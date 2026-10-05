//! One-shot, bounded native requests. A dropped request invalidates its reply token.
use crate::types::NativeEvent;
use anyhow::{Result, bail};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
#[error("request canceled")]
pub struct RequestCancelled;

#[derive(Debug, thiserror::Error)]
#[error("operation canceled by user")]
pub struct OperationCancelled;

#[derive(Debug, thiserror::Error)]
#[error("card not present")]
pub struct CardNotPresent;

type Answer = Result<Zeroizing<Vec<u8>>>;
pub struct Broker {
    pub pin_cache: Arc<crate::pin_cache::PinCache>,
    tx: mpsc::Sender<NativeEvent>,
    rx: tokio::sync::Mutex<mpsc::Receiver<NativeEvent>>,
    pending: Mutex<HashMap<String, oneshot::Sender<Answer>>>,
}
impl Broker {
    pub fn new() -> Arc<Self> {
        let (tx, rx) = mpsc::channel(256);
        Arc::new(Self {
            pin_cache: Arc::default(),
            tx,
            rx: tokio::sync::Mutex::new(rx),
            pending: Mutex::new(HashMap::new()),
        })
    }
    pub fn emit(&self, event: NativeEvent) -> Result<()> {
        self.tx
            .try_send(event)
            .map_err(|_| anyhow::anyhow!("native event queue full"))
    }
    pub async fn next(&self) -> Option<NativeEvent> {
        self.rx.lock().await.recv().await
    }
    pub fn pending(&self, token: &str) -> bool {
        self.pending.lock().unwrap().contains_key(token)
    }
    pub fn respond(&self, token: &str, bytes: Vec<u8>, accepted: bool) -> Result<()> {
        let bytes = Zeroizing::new(bytes);
        self.answer(
            token,
            if accepted {
                Ok(bytes)
            } else {
                Err(RequestCancelled.into())
            },
        )
    }
    pub fn fail(&self, token: &str, message: String, canceled: bool) -> Result<()> {
        self.answer(
            token,
            Err(if canceled {
                RequestCancelled.into()
            } else {
                anyhow::anyhow!(message)
            }),
        )
    }
    pub fn card_not_present(&self, token: &str) -> Result<()> {
        self.answer(token, Err(CardNotPresent.into()))
    }
    pub fn cancel(&self, token: &str) -> Result<()> {
        self.answer(token, Err(OperationCancelled.into()))
    }
    fn answer(&self, token: &str, answer: Answer) -> Result<()> {
        let tx = self
            .pending
            .lock()
            .unwrap()
            .remove(token)
            .ok_or_else(|| anyhow::anyhow!("request expired or already answered"))?;
        tx.send(answer)
            .map_err(|_| anyhow::anyhow!("request expired"))
    }
    pub fn cancel_all(&self) {
        let pending = std::mem::take(&mut *self.pending.lock().unwrap());
        for (token, _) in pending {
            let _ = self.emit(NativeEvent::Cancelled { token });
        }
    }
    pub async fn request(
        self: &Arc<Self>,
        make: impl FnOnce(String) -> NativeEvent,
        stop: &CancellationToken,
        timeout: Duration,
    ) -> Result<Zeroizing<Vec<u8>>> {
        if stop.is_cancelled() {
            return Err(RequestCancelled.into());
        }
        let token = hibiki_lib::random_id();
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending.lock().unwrap();
            if pending.len() >= 128 {
                bail!("too many native requests");
            }
            pending.insert(token.clone(), tx);
        }
        let _guard = RequestGuard {
            broker: self.clone(),
            token: token.clone(),
        };
        self.emit(make(token))?;
        tokio::select! {
            biased;
            _ = stop.cancelled() => Err(RequestCancelled.into()),
            result = tokio::time::timeout(timeout, rx) => result??,
        }
    }
}
struct RequestGuard {
    broker: Arc<Broker>,
    token: String,
}
impl Drop for RequestGuard {
    fn drop(&mut self) {
        self.broker.pending.lock().unwrap().remove(&self.token);
        let _ = self.broker.emit(NativeEvent::Cancelled {
            token: self.token.clone(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn canceled_and_duplicate_replies_cannot_reach_another_request() {
        let broker = Broker::new();
        let stop = CancellationToken::new();
        let b = broker.clone();
        let s = stop.clone();
        let task = tokio::spawn(async move {
            b.request(
                |token| NativeEvent::Cancelled { token },
                &s,
                Duration::from_secs(30),
            )
            .await
        });
        let Some(NativeEvent::Cancelled { token }) = broker.next().await else {
            panic!()
        };
        stop.cancel();
        assert!(task.await.unwrap().is_err());
        assert!(broker.respond(&token, b"secret".to_vec(), true).is_err());
        assert!(!broker.pending(&token));
    }
}
