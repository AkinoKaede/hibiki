//! One persistent scdaemon candidate per eligible device and adapter session.
use crate::{
    daemon::Hub,
    frontend::LocalOpen,
    provider::LocalContext,
    proxy::{Inquiry, transaction},
};
use anyhow::{Context, Result, bail};
use hibiki_lib::{
    assuan::{AssuanResult, Line},
    protocol::{CardPreparation, CardTarget, ServiceKind},
    random_id,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;

struct Command {
    line: Line,
    preparation: Option<Vec<Line>>,
    operation: Option<String>,
    inquiries: Option<mpsc::Sender<Inquiry>>,
    reply: oneshot::Sender<Result<AssuanResult>>,
}
#[derive(Clone)]
struct Candidate {
    tx: mpsc::Sender<Command>,
    state: watch::Receiver<(Option<Target>, CardPreparation)>,
}
#[derive(Clone, PartialEq, Eq)]
struct Target {
    generation: u64,
    card: Option<CardTarget>,
}
pub struct Pool {
    candidates: Arc<Mutex<BTreeMap<String, Candidate>>>,
    target: watch::Sender<Target>,
    stop: CancellationToken,
    changed: Arc<tokio::sync::Notify>,
}
impl Drop for Pool {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}
impl Pool {
    pub fn start(hub: Arc<Hub>, open: LocalOpen, stop: CancellationToken) -> Self {
        let stop = stop.child_token();
        let (target, _) = watch::channel(Target {
            generation: 0,
            card: Some(CardTarget::default()),
        });
        let pool = Self {
            candidates: Arc::new(Mutex::new(BTreeMap::new())),
            target,
            stop,
            changed: Arc::new(tokio::sync::Notify::new()),
        };
        let candidates = pool.candidates.clone();
        let target = pool.target.clone();
        let stop = pool.stop.clone();
        let changed = pool.changed.clone();
        tokio::spawn(async move {
            loop {
                if let Ok(peers) = hub.eligible(&open.channel, ServiceKind::Scdaemon) {
                    for peer in peers {
                        let mut entries = candidates.lock().unwrap();
                        if entries.contains_key(&peer) {
                            continue;
                        }
                        let (tx, rx) = mpsc::channel(8);
                        let (state, status) = watch::channel((None, CardPreparation::Unavailable));
                        entries.insert(peer.clone(), Candidate { tx, state: status });
                        tokio::spawn(candidate(
                            hub.clone(),
                            open.clone(),
                            peer,
                            rx,
                            state,
                            target.subscribe(),
                            stop.child_token(),
                            changed.clone(),
                        ));
                    }
                }
                tokio::select! { _=stop.cancelled()=>break, _=tokio::time::sleep(Duration::from_secs(2))=>{}, _=hub.changed.notified()=>{} }
            }
        });
        pool
    }
    pub fn prepare(&self, target: CardTarget) {
        self.set_target(Some(target));
    }
    pub fn cancel_prompts(&self) {
        self.set_target(None);
    }
    fn set_target(&self, card: Option<CardTarget>) {
        self.target.send_if_modified(|target| {
            if target.card == card {
                return false;
            }
            target.generation += 1;
            target.card = card;
            true
        });
    }
    async fn send(&self, peer: &str, command: Command) -> Result<()> {
        let tx = self
            .candidates
            .lock()
            .unwrap()
            .get(peer)
            .context("candidate unavailable")?
            .tx
            .clone();
        tx.send(command).await?;
        Ok(())
    }
    pub async fn query_from(&self, peer: &str, line: Line) -> Result<AssuanResult> {
        tokio::select! {
            biased;
            _ = self.rejected() => Err(hibiki_core::provider::PreparationRejected.into()),
            result = self.query_from_candidate(peer, line) => result,
        }
    }
    async fn rejected(&self) {
        loop {
            let changed = self.changed.notified();
            if self.candidates.lock().unwrap().values().any(|candidate| {
                let state = candidate.state.borrow();
                state.0.as_ref() == Some(&*self.target.borrow())
                    && matches!(state.1, CardPreparation::Rejected)
            }) {
                return;
            }
            tokio::select! { _ = changed => {}, _ = tokio::time::sleep(Duration::from_millis(100)) => {} }
        }
    }
    async fn query_from_candidate(&self, peer: &str, line: Line) -> Result<AssuanResult> {
        let (reply, rx) = oneshot::channel();
        self.send(
            peer,
            Command {
                line,
                preparation: None,
                operation: None,
                inquiries: None,
                reply,
            },
        )
        .await?;
        rx.await?
    }
    pub async fn query(&self, line: Line) -> Result<(String, AssuanResult)> {
        tokio::select! {
            biased;
            _ = self.rejected() => Err(hibiki_core::provider::PreparationRejected.into()),
            result = self.query_candidates(line) => result,
        }
    }
    async fn query_candidates(&self, line: Line) -> Result<(String, AssuanResult)> {
        loop {
            let peers: Vec<_> = self.candidates.lock().unwrap().keys().cloned().collect();
            let mut queries = tokio::task::JoinSet::new();
            for peer in peers {
                let tx = self.candidates.lock().unwrap()[&peer].tx.clone();
                let line = line.clone();
                queries.spawn(async move {
                    loop {
                        let (reply, rx) = oneshot::channel();
                        tx.send(Command {
                            line: line.clone(),
                            preparation: None,
                            operation: None,
                            inquiries: None,
                            reply,
                        })
                        .await?;
                        // A candidate can reconnect while other cardless peers are
                        // still waiting. Keep discovery alive for that candidate;
                        // this retry path never carries private commands.
                        if let Ok(Ok(result)) = rx.await
                            && result.success()
                        {
                            return Ok::<_, anyhow::Error>((peer, result));
                        }
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                });
            }
            while let Some(result) = queries.join_next().await {
                if let Ok(Ok((peer, result))) = result
                    && result.success()
                {
                    return Ok((peer, result));
                }
            }
            tokio::select! { _=self.stop.cancelled()=>bail!("card pool closed"), _=tokio::time::sleep(Duration::from_millis(250))=>{} }
        }
    }
    pub async fn ready(&self) -> Result<String> {
        loop {
            let changed = self.changed.notified();
            {
                let candidates = self.candidates.lock().unwrap();
                let target = self.target.borrow();
                let mut ready = None;
                for (peer, candidate) in candidates.iter() {
                    let state = candidate.state.borrow();
                    if state.0.as_ref() != Some(&*target) {
                        continue;
                    }
                    match state.1 {
                        CardPreparation::Rejected => {
                            return Err(hibiki_core::provider::PreparationRejected.into());
                        }
                        CardPreparation::Ready { .. } if ready.is_none() => {
                            ready = Some(peer.clone())
                        }
                        _ => {}
                    }
                }
                if let Some(peer) = ready {
                    return Ok(peer);
                }
            }
            tokio::select! { _=self.stop.cancelled()=>bail!("card pool closed"), _=changed=>{}, _=tokio::time::sleep(Duration::from_millis(100))=>{} }
        }
    }
    pub async fn execute(
        &self,
        peer: &str,
        line: Line,
        preparation: Vec<Line>,
        operation: Option<String>,
        inquiries: mpsc::Sender<Inquiry>,
    ) -> Result<AssuanResult> {
        let (reply, rx) = oneshot::channel();
        self.send(
            peer,
            Command {
                line,
                preparation: Some(preparation),
                operation,
                inquiries: Some(inquiries),
                reply,
            },
        )
        .await?;
        rx.await?
    }
    pub async fn reset(&self, line: Line) {
        self.cancel_prompts();
        let entries: Vec<_> = self.candidates.lock().unwrap().values().cloned().collect();
        for entry in entries {
            let (reply, _rx) = oneshot::channel();
            let _ = entry.tx.try_send(Command {
                line: line.clone(),
                preparation: None,
                operation: None,
                inquiries: None,
                reply,
            });
        }
    }
}
#[allow(clippy::too_many_arguments)]
async fn candidate(
    hub: Arc<Hub>,
    open: LocalOpen,
    peer: String,
    mut commands: mpsc::Receiver<Command>,
    state: watch::Sender<(Option<Target>, CardPreparation)>,
    mut target: watch::Receiver<Target>,
    stop: CancellationToken,
    changed: Arc<tokio::sync::Notify>,
) {
    loop {
        let result = tokio::select! {
            _=stop.cancelled()=>return,
            result=hub.open(&open.channel, &peer, ServiceKind::Scdaemon, stop.child_token(), LocalContext { display: open.display.clone() })=>result,
        };
        if let Ok(Some(mut ep)) = result {
            let run = async {
                let mut id = random_id();
                let mut preparing = false;
                let mut current = target.borrow_and_update().clone();
                if let Some(value) = current.card.clone() {
                    ep.prepare(id.clone(), value).await?;
                    preparing = true;
                }
                loop {
                    tokio::select! {
                        biased;
                        _=stop.cancelled()=>break,
                        update=target.changed()=>{
                            if update.is_err() { break; }
                            ep.cancel_preparation(id.clone()).await?;
                            state.send_replace((None, CardPreparation::Waiting));
                            current = target.borrow_and_update().clone();
                            id = random_id();
                            preparing = current.card.is_some();
                            if let Some(value) = current.card.clone() { ep.prepare(id.clone(), value).await?; }
                        },
                        command=commands.recv()=>{
                            let Some(command) = command else { break; };
                            let reset = matches!(&*command.line, b"RESET" | b"RESTART");
                            ep.bind_operation(command.operation);
                            let result = if let Some(preparation) = command.preparation {
                                ep.execute(command.line, preparation).await?;
                                crate::proxy::collect(&mut ep, command.inquiries.as_ref()).await
                            } else { transaction(&mut ep, command.line, command.inquiries.as_ref()).await };
                            ep.bind_operation(None);
                            let failed = result.is_err();
                            let _ = command.reply.send(result);
                            if failed { bail!("candidate session ended"); }
                            if reset {
                                // A target update can overtake a queued RESET. Re-arm
                                // acquisition after the reset at its new command boundary.
                                state.send_replace((None, CardPreparation::Waiting));
                                current = target.borrow_and_update().clone();
                                id = random_id();
                                preparing = current.card.is_some();
                                if let Some(value) = current.card.clone() { ep.prepare(id.clone(), value).await?; }
                            }
                        },
                        result=ep.prepared(&id), if preparing=>{
                            let result = result?;
                            preparing = matches!(result, CardPreparation::Waiting);
                            state.send_replace((Some(current.clone()), result));
                            changed.notify_waiters();
                        },
                    }
                }
                Ok::<_, anyhow::Error>(())
            };
            tokio::select! { _=stop.cancelled()=>{}, _=run=>{} }
            ep.close().await;
        }
        state.send_replace((None, CardPreparation::Unavailable));
        changed.notify_waiters();
        tokio::select! { _=stop.cancelled()=>return, _=tokio::time::sleep(Duration::from_secs(2))=>{} }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn explicit_rejection_wins_over_ready_candidates_and_reset_invalidates_it() {
        let target = Target {
            generation: 0,
            card: Some(CardTarget::default()),
        };
        let (target_tx, _) = watch::channel(target.clone());
        let mut candidates = BTreeMap::new();
        let mut statuses = Vec::new();
        for (peer, status) in [
            (
                "first-ready",
                CardPreparation::Ready {
                    serial: "AABB".into(),
                },
            ),
            ("last-rejected", CardPreparation::Rejected),
        ] {
            let (tx, _rx) = mpsc::channel(1);
            let (state, rx) = watch::channel((Some(target.clone()), status));
            statuses.push(state);
            candidates.insert(peer.into(), Candidate { tx, state: rx });
        }
        let pool = Pool {
            candidates: Arc::new(Mutex::new(candidates)),
            target: target_tx,
            stop: CancellationToken::new(),
            changed: Arc::new(tokio::sync::Notify::new()),
        };
        assert!(
            pool.ready()
                .await
                .unwrap_err()
                .is::<hibiki_core::provider::PreparationRejected>()
        );
        assert!(
            pool.query("SERIALNO".into())
                .await
                .unwrap_err()
                .is::<hibiki_core::provider::PreparationRejected>()
        );
        assert!(
            pool.query_from("first-ready", "SERIALNO".into())
                .await
                .unwrap_err()
                .is::<hibiki_core::provider::PreparationRejected>()
        );
        pool.prepare(CardTarget::default());
        assert!(
            pool.ready()
                .await
                .unwrap_err()
                .is::<hibiki_core::provider::PreparationRejected>()
        );
        pool.reset("RESET".into()).await;
        pool.prepare(CardTarget::default());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), pool.ready())
                .await
                .is_err(),
            "reset reused a stale ready/rejected observation"
        );
        statuses[0].send_replace((
            Some(pool.target.borrow().clone()),
            CardPreparation::Ready {
                serial: "AABB".into(),
            },
        ));
        assert_eq!(pool.ready().await.unwrap(), "first-ready");
    }
}
