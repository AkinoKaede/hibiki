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
    state: watch::Receiver<(Option<CardTarget>, CardPreparation)>,
}
pub struct Pool {
    candidates: Arc<Mutex<BTreeMap<String, Candidate>>>,
    target: watch::Sender<Option<CardTarget>>,
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
        let (target, _) = watch::channel(Some(CardTarget::default()));
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
        self.target.send_replace(Some(target));
        // A new target invalidates every prior readiness observation.
    }
    pub fn cancel_prompts(&self) {
        self.target.send_replace(None);
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
                        let result = rx.await??;
                        if result.success() {
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
            if let Some((peer, _)) = self.candidates.lock().unwrap().iter().find(|(_, c)| {
                let state = c.state.borrow();
                state.0 == *self.target.borrow() && matches!(state.1, CardPreparation::Ready { .. })
            }) {
                return Ok(peer.clone());
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
    state: watch::Sender<(Option<CardTarget>, CardPreparation)>,
    mut target: watch::Receiver<Option<CardTarget>>,
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
                if let Some(value) = current.clone() {
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
                            preparing = current.is_some();
                            if let Some(value) = current.clone() { ep.prepare(id.clone(), value).await?; }
                        },
                        command=commands.recv()=>{
                            let Some(command) = command else { break; };
                            ep.bind_operation(command.operation);
                            let result = if let Some(preparation) = command.preparation {
                                ep.execute(command.line, preparation).await?;
                                crate::proxy::collect(&mut ep, command.inquiries.as_ref()).await
                            } else { transaction(&mut ep, command.line, command.inquiries.as_ref()).await };
                            ep.bind_operation(None);
                            let failed = result.is_err();
                            let _ = command.reply.send(result);
                            if failed { bail!("candidate session ended"); }
                        },
                        result=ep.prepared(&id), if preparing=>{
                            let result = result?;
                            preparing = matches!(result, CardPreparation::Waiting);
                            state.send_replace((current.clone(), result));
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
