use anyhow::{Context, Result, bail};
use futures_util::{SinkExt, StreamExt};
use hibiki_lib::{decode, encode, identity::Identity, protocol::*, random_id};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::{
    connect_async_tls_with_config,
    tungstenite::{Message, protocol::WebSocketConfig},
};
use tokio_util::sync::CancellationToken;

type Pending = Arc<Mutex<HashMap<String, oneshot::Sender<std::result::Result<Reply, WireError>>>>>;
struct PendingGuard {
    pending: Pending,
    id: String,
}
impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.pending.lock().unwrap().remove(&self.id);
    }
}
pub struct Connection {
    tx: mpsc::Sender<Message>,
    pending: Pending,
    pub closed: CancellationToken,
}
#[allow(clippy::large_enum_variant)] // Bounded internal event queue.
pub enum Event {
    Message(Envelope),
    Disconnected,
}

pub fn validate_url(value: &str, insecure: bool) -> Result<()> {
    let url = url::Url::parse(value)?;
    if url.scheme() != "wss" && !(url.scheme() == "ws" && insecure) {
        bail!("use wss://; plaintext ws:// requires explicit --allow-insecure for development");
    }
    if url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() {
        bail!("invalid WebSocket URL");
    }
    Ok(())
}
impl Connection {
    /// Placeholder for local service before the first relay connection succeeds.
    pub fn disconnected() -> Arc<Self> {
        let (tx, _) = mpsc::channel(1);
        let closed = CancellationToken::new();
        closed.cancel();
        Arc::new(Self {
            tx,
            pending: Default::default(),
            closed,
        })
    }

    pub async fn open(
        url: &str,
        insecure: bool,
        identity: &Identity,
    ) -> Result<(Arc<Self>, mpsc::Receiver<Event>)> {
        Self::open_with_tls_options(url, insecure, false, identity).await
    }
    pub async fn open_with_tls_options(
        url: &str,
        allow_plaintext: bool,
        skip_tls_certificate_validation: bool,
        identity: &Identity,
    ) -> Result<(Arc<Self>, mpsc::Receiver<Event>)> {
        validate_url(url, allow_plaintext)?;
        let connector = skip_tls_certificate_validation.then(crate::tls::connector);
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_WIRE))
            .max_frame_size(Some(MAX_WIRE));
        let (mut ws, _) = tokio::time::timeout(
            Duration::from_secs(10),
            // Assuan uses many small request/reply frames, including nested PIN
            // inquiries. Nagle plus delayed ACKs can exhaust their deadline.
            connect_async_tls_with_config(url, Some(config), true, connector),
        )
        .await??;
        let hello = tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await?
            .context("server closed connection")??;
        let Message::Binary(raw) = hello else {
            bail!("invalid server greeting");
        };
        let Envelope::Hello { version, nonce } = decode(&raw)? else {
            bail!("missing protocol greeting");
        };
        if version != VERSION || nonce.len() > 128 {
            bail!("unsupported server protocol; expected {VERSION}");
        }
        let signature =
            identity.sign("server-auth/v1", &(version, &nonce, &identity.device.id()))?;
        ws.send(Message::Binary(
            encode(&Envelope::Authenticate {
                device: identity.device.clone(),
                signature,
            })?
            .into(),
        ))
        .await?;
        let response = tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await?
            .context("authentication failed")??;
        let Message::Binary(raw) = response else {
            bail!("invalid authentication response");
        };
        if !matches!(decode::<Envelope>(&raw)?, Envelope::Authenticated) {
            bail!("authentication failed");
        }

        let (tx, mut rx) = mpsc::channel::<Message>(64);
        let (event_tx, event_rx) = mpsc::channel(128);
        let pending: Pending = Default::default();
        let closed = CancellationToken::new();
        let conn = Arc::new(Self {
            tx: tx.clone(),
            pending: pending.clone(),
            closed: closed.clone(),
        });
        let (mut writer, mut reader) = ws.split();
        let write_stop = closed.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = write_stop.cancelled() => break,
                    message = rx.recv() => match message {
                        Some(message) => if !matches!(tokio::time::timeout(Duration::from_secs(10), writer.send(message)).await, Ok(Ok(()))) { break; },
                        None => break,
                    }
                }
            }
            let _ = tokio::time::timeout(Duration::from_secs(2), writer.close()).await;
            write_stop.cancel();
        });
        tokio::spawn(async move {
            loop {
                let message = tokio::select! {
                    _ = closed.cancelled() => break,
                    message = tokio::time::timeout(Duration::from_secs(50), reader.next()) => match message {
                        Ok(Some(Ok(message))) => message,
                        _ => break,
                    }
                };
                match message {
                    Message::Ping(data) => {
                        if tx.try_send(Message::Pong(data)).is_err() {
                            break;
                        }
                    }
                    Message::Pong(_) => {}
                    Message::Binary(raw) => match decode::<Envelope>(&raw) {
                        Ok(Envelope::Response { id, result }) => {
                            if let Some(sender) = pending.lock().unwrap().remove(&id) {
                                let _ = sender.send(result);
                            }
                        }
                        Ok(message) => {
                            if event_tx.try_send(Event::Message(message)).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    },
                    Message::Close(_) => break,
                    _ => break,
                }
            }
            closed.cancel();
            let entries = std::mem::take(&mut *pending.lock().unwrap());
            for (_, sender) in entries {
                let _ = sender.send(Err(WireError::new(
                    "disconnected",
                    "server connection closed",
                )));
            }
            let _ = event_tx.try_send(Event::Disconnected);
        });
        Ok((conn, event_rx))
    }
    pub async fn send(&self, message: Envelope) -> Result<()> {
        if self.closed.is_cancelled() {
            bail!("server connection closed");
        }
        let bytes = encode(&message)?;
        if bytes.len() > MAX_WIRE {
            bail!("wire message too large");
        }
        tokio::time::timeout(
            Duration::from_secs(10),
            self.tx.send(Message::Binary(bytes.into())),
        )
        .await??;
        Ok(())
    }
    pub async fn request(&self, command: Control) -> Result<Reply> {
        let id = random_id();
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending.lock().unwrap();
            if pending.len() >= 128 {
                bail!("too many control requests");
            }
            pending.insert(id.clone(), tx);
        }
        let _guard = PendingGuard {
            pending: self.pending.clone(),
            id: id.clone(),
        };
        let result = async {
            self.send(Envelope::Request {
                id: id.clone(),
                command,
            })
            .await?;
            let reply = tokio::time::timeout(Duration::from_secs(15), rx).await???;
            Ok(reply)
        }
        .await;
        self.pending.lock().unwrap().remove(&id);
        result
    }
    pub fn close(&self) {
        self.closed.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn incompatible_hibiki_versions_are_rejected_before_authentication() {
        for version in ["hibiki/0", "hibiki/1", "hibiki/3", "Hibiki/1", "1"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}{WS_PATH}", listener.local_addr().unwrap());
            let peer = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
                ws.send(Message::Binary(
                    encode(&Envelope::Hello {
                        version: version.into(),
                        nonce: random_id(),
                    })
                    .unwrap()
                    .into(),
                ))
                .await
                .unwrap();
                // Rejection must not reveal an authentication signature to the peer.
                let next = tokio::time::timeout(Duration::from_secs(2), ws.next())
                    .await
                    .unwrap();
                assert!(!matches!(next, Some(Ok(Message::Binary(_)))));
            });
            let identity = Identity::generate("test".into()).unwrap();
            match Connection::open(&url, true, &identity).await {
                Err(error) => assert!(error.to_string().contains(&format!("expected {VERSION}"))),
                Ok(_) => panic!("accepted incompatible protocol"),
            }
            peer.await.unwrap();
        }
    }
}
