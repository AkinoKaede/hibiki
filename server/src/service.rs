use crate::db::Database;
use anyhow::{Context, Result, bail};
use axum::{
    Router,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
    routing::get,
};
use futures_util::{SinkExt, StreamExt};
use hibiki_lib::{decode, encode, identity::verify, protocol::*, random_id};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct Service {
    pub db: Database,
    pub allow_client_channel_creation: bool,
    executors: Arc<Mutex<HashMap<String, Executor>>>,
    // Serialize authority changes with routing to prevent a revoke/relay TOCTOU.
    authority: Arc<tokio::sync::Mutex<()>>,
}
#[derive(Clone)]
struct Executor {
    connection: String,
    channels: HashSet<String>,
    tx: mpsc::Sender<Envelope>,
    stop: CancellationToken,
}
struct Registration {
    service: Service,
    device: String,
    connection: String,
}
impl Drop for Registration {
    fn drop(&mut self) {
        let mut entries = self.service.executors.lock().unwrap();
        if entries
            .get(&self.device)
            .is_some_and(|e| e.connection == self.connection)
        {
            entries.remove(&self.device);
            for entry in entries.values() {
                if entry
                    .tx
                    .try_send(Envelope::PeerOffline {
                        peer: self.device.clone(),
                    })
                    .is_err()
                {
                    entry.stop.cancel();
                }
            }
        }
    }
}
impl Service {
    pub fn new(db: Database, allow_client_channel_creation: bool) -> Self {
        Self {
            db,
            allow_client_channel_creation,
            executors: Arc::new(Mutex::new(HashMap::new())),
            authority: Arc::new(tokio::sync::Mutex::new(())),
        }
    }
    async fn channel(&self, id: &str) -> Result<hibiki_lib::channel::MembershipProof> {
        self.db.get(id).await
    }
    pub async fn notify_deleted(&self) -> Result<()> {
        let _authority = self.authority.lock().await;
        let channels: HashSet<String> = self
            .executors
            .lock()
            .unwrap()
            .values()
            .flat_map(|e| e.channels.iter().cloned())
            .collect();
        for channel in channels {
            if !self.db.exists(&channel).await? {
                for executor in self.executors.lock().unwrap().values_mut() {
                    if executor.channels.remove(&channel)
                        && executor
                            .tx
                            .try_send(Envelope::ChannelChanged {
                                channel: channel.clone(),
                            })
                            .is_err()
                    {
                        executor.stop.cancel();
                    }
                }
            }
        }
        Ok(())
    }
    pub async fn watch_deleted(self, stop: CancellationToken) {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = stop.cancelled() => break,
                _ = tick.tick() => { if self.notify_deleted().await.is_err() { tracing::warn!("could not refresh channel deletions"); } }
            }
        }
    }
    pub fn router(self) -> Router {
        Router::new()
            .route("/healthz", get(|| async { "ok\n" }))
            .route(WS_PATH, get(upgrade))
            .with_state(self)
    }
    async fn control(
        &self,
        device: &str,
        connection: &str,
        tx: &mpsc::Sender<Envelope>,
        cmd: Control,
        stop: &CancellationToken,
    ) -> Result<Reply> {
        let _authority = self.authority.lock().await;
        match cmd {
            Control::Create { genesis, verifier } => {
                if !self.allow_client_channel_creation {
                    bail!(
                        "client channel creation is disabled; ask the server administrator for an initialization invitation"
                    );
                }
                Ok(Reply::Proof(
                    self.db.create(device, genesis, verifier).await?,
                ))
            }
            Control::Claim { genesis, psk } => {
                Ok(Reply::Proof(self.db.claim(device, genesis, psk).await?))
            }
            Control::GetChannel { channel } => Ok(Reply::Proof(self.channel(&channel).await?)),
            Control::ListChannels => Ok(Reply::Proofs(self.db.list(device).await?)),
            Control::Join { request, psk } => {
                self.channel(&request.body.channel_id).await?;
                self.db.join(device, request, psk).await?;
                Ok(Reply::Ok)
            }
            Control::Pending { channel } => {
                self.channel(&channel).await?;
                Ok(Reply::Requests(self.db.pending(device, &channel).await?))
            }
            Control::Append { event, verifier } => {
                let id = event.body.channel_id.clone();
                self.channel(&id).await?;
                let proof = self.db.append(device, event, verifier).await?;
                let state = proof.verify()?;
                let targets: Vec<_> = {
                    let mut executors = self.executors.lock().unwrap();
                    let mut targets = Vec::new();
                    for (peer, executor) in executors.iter_mut() {
                        if executor.channels.contains(&id) {
                            targets.push((executor.tx.clone(), executor.stop.clone()));
                            if state.member(peer).is_err() {
                                executor.channels.remove(&id);
                            }
                        }
                    }
                    targets
                };
                for (target, stop) in targets {
                    if target
                        .try_send(Envelope::ChannelChanged {
                            channel: id.clone(),
                        })
                        .is_err()
                    {
                        stop.cancel();
                    }
                }
                Ok(Reply::Proof(proof))
            }
            Control::Announce { channels } => {
                let mut authorized = HashSet::new();
                for channel in channels {
                    self.channel(&channel).await?.verify()?.member(device)?;
                    authorized.insert(channel);
                }
                let mut executors = self.executors.lock().unwrap();
                if executors
                    .get(device)
                    .is_some_and(|e| e.connection != connection)
                {
                    bail!("an executor for this device is already online");
                }
                executors.insert(
                    device.into(),
                    Executor {
                        connection: connection.into(),
                        channels: authorized,
                        tx: tx.clone(),
                        stop: stop.clone(),
                    },
                );
                Ok(Reply::Ok)
            }
            Control::Peers { channel } => {
                let state = self.channel(&channel).await?.verify()?;
                state.member(device)?;
                let executors = self.executors.lock().unwrap();
                let mut peers: Vec<_> = executors
                    .iter()
                    .filter(|(id, e)| {
                        id.as_str() != device
                            && e.channels.contains(&channel)
                            && state.member(id).is_ok()
                    })
                    .map(|(id, _)| id.clone())
                    .collect();
                peers.sort();
                Ok(Reply::Peers(peers))
            }
        }
    }
    async fn relay(
        &self,
        sender: &str,
        connection: &str,
        channel: String,
        peer: String,
        session: String,
        data: Vec<u8>,
    ) -> Result<()> {
        let _authority = self.authority.lock().await;
        if data.len() > 65535 || !hibiki_lib::channel::valid_id(&session) {
            bail!("invalid relay frame");
        }
        let state = self.channel(&channel).await?.verify()?;
        state.member(sender)?;
        state.member(&peer)?;
        let target = {
            let executors = self.executors.lock().unwrap();
            let source = executors.get(sender).context("sender is not an executor")?;
            if source.connection != connection || !source.channels.contains(&channel) {
                bail!("unauthorized source");
            }
            let target = executors.get(&peer).context("peer is offline")?;
            if !target.channels.contains(&channel) {
                bail!("peer is not subscribed to channel");
            }
            target.tx.clone()
        };
        target
            .try_send(Envelope::Relay {
                channel,
                peer: sender.into(),
                session,
                data,
            })
            .map_err(|_| anyhow::anyhow!("peer queue is full or closed"))?;
        Ok(())
    }
}
async fn upgrade(State(service): State<Service>, ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.max_message_size(MAX_WIRE)
        .max_frame_size(MAX_WIRE)
        .on_upgrade(move |socket| async move {
            if let Err(e) = session(service, socket).await {
                tracing::debug!(error=%e, "connection ended");
            }
        })
}
async fn session(service: Service, mut socket: WebSocket) -> Result<()> {
    let nonce = random_id();
    socket
        .send(Message::Binary(
            encode(&Envelope::Hello {
                version: VERSION.into(),
                nonce: nonce.clone(),
            })?
            .into(),
        ))
        .await?;
    let message = tokio::time::timeout(Duration::from_secs(10), socket.next())
        .await?
        .context("connection closed")??;
    let Message::Binary(bytes) = message else {
        bail!("binary authentication required");
    };
    let Envelope::Authenticate { device, signature } = decode(&bytes)? else {
        bail!("authentication required");
    };
    device.verify()?;
    let device_id = device.id();
    verify(
        &device.signing_key,
        "server-auth/v1",
        &(VERSION, &nonce, &device_id),
        &signature,
    )?;
    service.db.register(&device).await?;
    socket
        .send(Message::Binary(encode(&Envelope::Authenticated)?.into()))
        .await?;
    let connection = random_id();
    let stop = CancellationToken::new();
    let _registration = Registration {
        service: service.clone(),
        device: device_id.clone(),
        connection: connection.clone(),
    };
    let (tx, mut rx) = mpsc::channel::<Envelope>(64);
    let (mut writer, mut reader) = socket.split();
    let mut heartbeat = tokio::time::interval(Duration::from_secs(15));
    let mut last_seen = tokio::time::Instant::now();
    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            _ = heartbeat.tick() => {
                if last_seen.elapsed() > Duration::from_secs(45) { break; }
                if send_bounded(&mut writer, Message::Ping(vec![].into())).await.is_err() { break; }
            }
            Some(message) = rx.recv() => {
                if send_bounded(&mut writer, Message::Binary(encode(&message)?.into())).await.is_err() { break; }
            }
            incoming = reader.next() => {
                let Some(Ok(message)) = incoming else { break; };
                last_seen = tokio::time::Instant::now();
                match message {
                    Message::Ping(data) => { if send_bounded(&mut writer, Message::Pong(data)).await.is_err() { break; } }
                    Message::Pong(_) => {}
                    Message::Close(_) => break,
                    Message::Binary(bytes) => {
                        let envelope: Envelope = match decode(&bytes) { Ok(e) => e, Err(_) => break };
                        match envelope {
                            Envelope::Request { id, command } => {
                                let result = service.control(&device_id, &connection, &tx, command, &stop).await.map_err(|e| {
                                    let message = e.to_string();
                                    let code = if message.contains("CONFLICT") { "conflict" } else { "request_failed" };
                                    WireError::new(code, message)
                                });
                                if send_bounded(&mut writer, Message::Binary(encode(&Envelope::Response { id, result })?.into())).await.is_err() { break; }
                            }
                            Envelope::Relay { channel, peer, session, data } => {
                                if let Err(e) = service.relay(&device_id, &connection, channel, peer.clone(), session.clone(), data).await {
                                    let failure = Envelope::RelayFailure { session, peer, error: WireError::new("relay_failed", e.to_string()) };
                                    if send_bounded(&mut writer, Message::Binary(encode(&failure)?.into())).await.is_err() { break; }
                                }
                            }
                            _ => break,
                        }
                    }
                    _ => break,
                }
            }
        }
    }
    Ok(())
}

async fn send_bounded<S>(writer: &mut S, message: Message) -> Result<()>
where
    S: futures_util::Sink<Message> + Unpin,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    tokio::time::timeout(Duration::from_secs(10), writer.send(message)).await??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hibiki_lib::{channel::*, identity::Identity};

    #[tokio::test]
    async fn creation_switch_does_not_restrict_names_or_block_claim_and_members() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(&dir.path().join("db")).await.unwrap();
        let service = Service::new(db.clone(), false);
        let a = Identity::generate("a".into()).unwrap();
        let b = Identity::generate("b".into()).unwrap();
        let (tx, mut rx) = mpsc::channel(64);
        let stop = CancellationToken::new();
        let verifier = hash_psk("test-secret").unwrap();
        let genesis = ChannelGenesis::create(&a, "arbitrary-name".into(), &verifier).unwrap();
        assert!(
            service
                .control(
                    &a.device.id(),
                    "a",
                    &tx,
                    Control::Create {
                        genesis,
                        verifier: verifier.clone()
                    },
                    &stop
                )
                .await
                .is_err()
        );
        let invite = db
            .reserve(
                "ws://localhost/hibiki".into(),
                "arbitrary-name".into(),
                verifier.clone(),
            )
            .await
            .unwrap();
        let id = invite.id.clone();
        let Reply::Proof(proof) = service
            .control(
                &a.device.id(),
                "a",
                &tx,
                Control::Claim {
                    genesis: invite.founder_genesis(&a).unwrap(),
                    psk: "test-secret".into(),
                },
                &stop,
            )
            .await
            .unwrap()
        else {
            panic!()
        };
        let request = JoinRequest::create(&b, &proof.verify().unwrap()).unwrap();
        service
            .control(
                &b.device.id(),
                "b",
                &tx,
                Control::Join {
                    request: request.clone(),
                    psk: "test-secret".into(),
                },
                &stop,
            )
            .await
            .unwrap();
        assert!(
            service
                .control(
                    &b.device.id(),
                    "b",
                    &tx,
                    Control::Announce {
                        channels: vec![id.clone()]
                    },
                    &stop
                )
                .await
                .is_err()
        );
        assert!(
            service
                .relay(
                    &b.device.id(),
                    "b",
                    id.clone(),
                    a.device.id(),
                    random_id(),
                    vec![0; 32]
                )
                .await
                .is_err()
        );
        let event = MembershipEvent::create(
            &a,
            &proof.verify().unwrap(),
            MembershipAction::Admit(request),
        )
        .unwrap();
        service
            .control(
                &a.device.id(),
                "a",
                &tx,
                Control::Append {
                    event,
                    verifier: None,
                },
                &stop,
            )
            .await
            .unwrap();
        for (device, connection) in [(&a, "a"), (&b, "b")] {
            service
                .control(
                    &device.device.id(),
                    connection,
                    &tx,
                    Control::Announce {
                        channels: vec![id.clone()],
                    },
                    &stop,
                )
                .await
                .unwrap();
        }
        assert!(
            service
                .control(
                    &a.device.id(),
                    "duplicate",
                    &tx,
                    Control::Announce {
                        channels: vec![id.clone()]
                    },
                    &stop
                )
                .await
                .is_err()
        );
        service
            .control(
                &a.device.id(),
                "management",
                &tx,
                Control::Pending {
                    channel: id.clone(),
                },
                &stop,
            )
            .await
            .unwrap();
        service
            .relay(
                &a.device.id(),
                "a",
                id.clone(),
                b.device.id(),
                random_id(),
                vec![0; 32],
            )
            .await
            .unwrap();
        assert!(matches!(rx.recv().await.unwrap(), Envelope::Relay { .. }));
        db.delete("arbitrary-name").await.unwrap();
        assert!(
            service
                .relay(
                    &a.device.id(),
                    "a",
                    id.clone(),
                    b.device.id(),
                    random_id(),
                    vec![0; 32]
                )
                .await
                .is_err()
        );
        assert!(
            service
                .control(
                    &a.device.id(),
                    "a",
                    &tx,
                    Control::Peers {
                        channel: id.clone()
                    },
                    &stop
                )
                .await
                .is_err()
        );
        service.notify_deleted().await.unwrap();
        for _ in 0..2 {
            assert!(
                matches!(rx.recv().await.unwrap(), Envelope::ChannelChanged { channel } if channel == id)
            );
        }
        assert!(
            service
                .executors
                .lock()
                .unwrap()
                .values()
                .all(|e| !e.channels.contains(&id))
        );
        let open = Service::new(db, true);
        for name in ["Team", "team", "Other", "工作"] {
            let genesis = ChannelGenesis::create(&a, name.into(), &verifier).unwrap();
            open.control(
                &a.device.id(),
                "a",
                &tx,
                Control::Create {
                    genesis,
                    verifier: verifier.clone(),
                },
                &stop,
            )
            .await
            .unwrap();
        }
    }
}
