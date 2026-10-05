/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

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
#[derive(Debug)]
struct CandidateUnavailable;
impl std::fmt::Display for CandidateUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("scdaemon candidate is offline or unavailable")
    }
}
impl std::error::Error for CandidateUnavailable {}
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
/// Keep native errors across the command deadline if an online peer stalls.
/// Offline/disabled peers finish their query immediately without an Assuan result.
#[derive(Default)]
pub(crate) struct QueryFailures(BTreeMap<String, AssuanResult>);
impl QueryFailures {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn take_first(&mut self) -> Option<(String, AssuanResult)> {
        self.0.pop_first()
    }
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
            // Discovery opens candidates without asking the user to insert a card.
            // Only an explicit private operation starts interactive preparation.
            card: None,
        });
        let pool = Self {
            candidates: Arc::new(Mutex::new(BTreeMap::new())),
            target,
            stop,
            changed: Arc::new(tokio::sync::Notify::new()),
        };
        // Populate before returning so a discovery snapshots every known member,
        // but never waits for new members or an offline member to reconnect.
        let candidates = pool.candidates.clone();
        let target = pool.target.clone();
        let stop = pool.stop.clone();
        let changed = pool.changed.clone();
        let add_candidates = {
            let hub = hub.clone();
            let stop = stop.clone();
            move || {
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
            }
        };
        add_candidates();
        tokio::spawn(async move {
            loop {
                tokio::select! { _=stop.cancelled()=>break, _=tokio::time::sleep(Duration::from_secs(2))=>{}, _=hub.changed.notified()=>{} }
                add_candidates();
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
    pub async fn query(
        &self,
        line: Line,
        failures: &mut QueryFailures,
    ) -> Result<(String, AssuanResult)> {
        tokio::select! {
            biased;
            _ = self.rejected() => Err(hibiki_core::provider::PreparationRejected.into()),
            result = self.query_candidates(line, failures) => result,
        }
    }
    async fn query_candidates(
        &self,
        line: Line,
        failures: &mut QueryFailures,
    ) -> Result<(String, AssuanResult)> {
        let mut queries = tokio::task::JoinSet::new();
        let peers: Vec<_> = self
            .candidates
            .lock()
            .unwrap()
            .iter()
            .map(|(peer, candidate)| (peer.clone(), candidate.tx.clone()))
            .collect();
        for (peer, tx) in peers {
            let line = line.clone();
            queries.spawn(async move {
                let (reply, rx) = oneshot::channel();
                let sent = tx
                    .send(Command {
                        line,
                        preparation: None,
                        operation: None,
                        inquiries: None,
                        reply,
                    })
                    .await;
                // A discovery performs one query per candidate. Native errors,
                // including no-card, belong to gpg-agent; connection failures
                // exclude only that device from this round.
                let result = if sent.is_ok() {
                    rx.await.ok().and_then(Result::ok)
                } else {
                    None
                };
                (peer, result)
            });
        }
        while !queries.is_empty() {
            tokio::select! {
                biased;
                _=self.stop.cancelled()=>bail!("card pool closed"),
                completed=queries.join_next()=>{
                    let (peer, result) = completed.context("query task missing")??;
                    let Some(result) = result else { continue; };
                    if result.success() || result.canceled() {
                        return Ok((peer, result));
                    }
                    failures.0.insert(peer, result);
                },
            }
        }
        failures
            .take_first()
            .context("no available scdaemon providers")
    }
    pub async fn ready(&self) -> Result<String> {
        loop {
            let changed = self.changed.notified();
            {
                let candidates = self.candidates.lock().unwrap();
                let target = self.target.borrow();
                let mut ready = None;
                let mut waiting = false;
                for (peer, candidate) in candidates.iter() {
                    let state = candidate.state.borrow();
                    if state.0.as_ref() != Some(&*target) {
                        waiting = true;
                        continue;
                    }
                    match state.1 {
                        CardPreparation::Rejected => {
                            return Err(hibiki_core::provider::PreparationRejected.into());
                        }
                        CardPreparation::Ready { .. } if ready.is_none() => {
                            ready = Some(peer.clone())
                        }
                        CardPreparation::Waiting => waiting = true,
                        _ => {}
                    }
                }
                if let Some(peer) = ready {
                    return Ok(peer);
                }
                if !waiting {
                    bail!("no available device can prepare the target card");
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
    let mut pending = None;
    loop {
        state.send_replace((None, CardPreparation::Waiting));
        changed.notify_waiters();
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
                        command=async {
                            if pending.is_some() { pending.take() } else { commands.recv().await }
                        }=>{
                            let Some(mut command) = command else { break; };
                            let reset = matches!(&*command.line, b"RESET" | b"RESTART");
                            if command.reply.is_closed() && !reset { continue; }
                            // Only targeted discovery can wait for mobile NFC consent.
                            // Ordinary queries finish their Assuan response and retain
                            // the native session, including its card authentication state.
                            let interactive = hibiki_lib::assuan::command(&command.line).is_ok_and(|(cmd, args)|
                                cmd == "SERIALNO" && args.split_ascii_whitespace().any(|a| a.starts_with("--demand=")));
                            ep.bind_operation(command.operation);
                            let work = async {
                                if let Some(preparation) = command.preparation {
                                    ep.execute(command.line, preparation).await?;
                                    crate::proxy::collect(&mut ep, command.inquiries.as_ref()).await
                                } else {
                                    transaction(&mut ep, command.line, command.inquiries.as_ref()).await
                                }
                            };
                            let result = tokio::select! {
                                biased;
                                _ = command.reply.closed(), if interactive => bail!("candidate query abandoned"),
                                result = work => result,
                            };
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
        if let Some(command) = pending.take() {
            let _ = command.reply.send(Err(CandidateUnavailable.into()));
        }
        state.send_replace((
            Some(target.borrow_and_update().clone()),
            CardPreparation::Unavailable,
        ));
        changed.notify_waiters();
        // Keep reconnecting for future queries and private preparation,
        // but do not park this discovery's reply behind an offline retry loop.
        let retry = tokio::time::sleep(Duration::from_secs(2));
        tokio::pin!(retry);
        loop {
            tokio::select! {
                _=stop.cancelled()=>return,
                _=&mut retry=>break,
                _=hub.changed.notified()=>break,
                update=target.changed()=>{
                    if update.is_err() { return; }
                    state.send_replace((Some(target.borrow_and_update().clone()), CardPreparation::Unavailable));
                    changed.notify_waiters();
                },
                command=commands.recv()=>{
                    let Some(command) = command else { return; };
                    // A new query gets one fresh connection attempt; a peer
                    // that just returned must not wait for the retry timer.
                    pending = Some(command);
                    break;
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query_pool(peers: &[&str]) -> (Pool, Vec<mpsc::Receiver<Command>>) {
        let (target, _) = watch::channel(Target {
            generation: 0,
            card: None,
        });
        let mut candidates = BTreeMap::new();
        let mut receivers = Vec::new();
        for peer in peers {
            let (tx, rx) = mpsc::channel(8);
            let (_, state) = watch::channel((None, CardPreparation::Unavailable));
            candidates.insert((*peer).to_owned(), Candidate { tx, state });
            receivers.push(rx);
        }
        (
            Pool {
                candidates: Arc::new(Mutex::new(candidates)),
                target,
                stop: CancellationToken::new(),
                changed: Arc::new(tokio::sync::Notify::new()),
            },
            receivers,
        )
    }

    #[tokio::test(start_paused = true)]
    async fn definitive_failures_finish_without_retry_and_preserve_the_first_peer_result() {
        let (pool, mut receivers) = query_pool(&["a", "b"]);
        let mut b = receivers.pop().unwrap();
        let mut a = receivers.pop().unwrap();
        let replies = tokio::spawn(async move {
            let ca = a.recv().await.unwrap();
            let cb = b.recv().await.unwrap();
            cb.reply
                .send(Ok(AssuanResult::error(27, "not found")))
                .unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            ca.reply
                .send(Ok(AssuanResult {
                    lines: vec!["S TEST diagnostic".into(), "ERR 100663313 No key".into()],
                }))
                .unwrap();
            (a, b)
        });
        let mut failures = QueryFailures::default();
        let (peer, result) = tokio::time::timeout(
            Duration::from_secs(1),
            pool.query("READKEY OPENPGP.1".into(), &mut failures),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(peer, "a");
        assert_eq!(&*result.lines[0], b"S TEST diagnostic");
        assert_eq!(&*result.lines[1], b"ERR 100663313 No key");
        let (mut a, mut b) = replies.await.unwrap();
        assert!(a.try_recv().is_err());
        assert!(b.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn slower_success_wins_over_a_definitive_failure() {
        for code in [17, 112] {
            let (pool, mut receivers) = query_pool(&["a", "b"]);
            let mut b = receivers.pop().unwrap();
            let mut a = receivers.pop().unwrap();
            let replies = tokio::spawn(async move {
                a.recv()
                    .await
                    .unwrap()
                    .reply
                    .send(Ok(AssuanResult::error(code, "No key or card")))
                    .unwrap();
                let command = b.recv().await.unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;
                command.reply.send(Ok(AssuanResult::ok())).unwrap();
                a
            });
            let (peer, result) = pool
                .query("READKEY OPENPGP.1".into(), &mut QueryFailures::default())
                .await
                .unwrap();
            assert_eq!(peer, "b");
            assert!(result.success());
            assert!(replies.await.unwrap().try_recv().is_err());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn offline_or_disabled_candidate_does_not_delay_a_native_error() {
        let (pool, mut receivers) = query_pool(&["disabled", "native"]);
        let mut native = receivers.pop().unwrap();
        let mut disabled = receivers.pop().unwrap();
        let replies = tokio::spawn(async move {
            disabled
                .recv()
                .await
                .unwrap()
                .reply
                .send(Err(CandidateUnavailable.into()))
                .unwrap();
            native
                .recv()
                .await
                .unwrap()
                .reply
                .send(Ok(AssuanResult::error(100663313, "No key")))
                .unwrap();
        });
        let (peer, result) = tokio::time::timeout(
            Duration::from_secs(1),
            pool.query("READKEY OPENPGP.1".into(), &mut QueryFailures::default()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(peer, "native");
        assert_eq!(&*result.lines[0], b"ERR 100663313 No key");
        replies.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_keeps_native_failure_while_an_online_candidate_stalls() {
        let (pool, mut receivers) = query_pool(&["a", "stalled"]);
        let mut stalled = receivers.pop().unwrap();
        let mut a = receivers.pop().unwrap();
        let replies = tokio::spawn(async move {
            a.recv()
                .await
                .unwrap()
                .reply
                .send(Ok(AssuanResult::error(100663313, "No key")))
                .unwrap();
            // An online peer accepted a command but never returned a response.
            (a, stalled.recv().await.unwrap())
        });
        let mut failures = QueryFailures::default();
        let started = tokio::time::Instant::now();
        assert!(
            tokio::time::timeout(
                Duration::from_secs(2),
                pool.query("READKEY OPENPGP.1".into(), &mut failures)
            )
            .await
            .is_err()
        );
        assert_eq!(started.elapsed(), Duration::from_secs(2));
        assert_eq!(
            &*failures.take_first().unwrap().1.lines[0],
            b"ERR 100663313 No key"
        );
        let (mut a, _pending) = replies.await.unwrap();
        assert!(a.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn absent_card_returns_native_error_and_new_discovery_can_succeed() {
        let (pool, mut receivers) = query_pool(&["a"]);
        let mut a = receivers.pop().unwrap();
        let result = AssuanResult::error(100663408, "Card not present");
        let response = AssuanResult {
            lines: result.lines.clone(),
        };
        let replies = tokio::spawn(async move {
            a.recv().await.unwrap().reply.send(Ok(response)).unwrap();
            a
        });
        let (_, actual) = tokio::time::timeout(
            Duration::from_secs(1),
            pool.query("SERIALNO".into(), &mut QueryFailures::default()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(actual.lines, result.lines);
        let mut a = replies.await.unwrap();
        assert!(
            a.try_recv().is_err(),
            "no-card response triggered an automatic query"
        );
        let replies = tokio::spawn(async move {
            a.recv()
                .await
                .unwrap()
                .reply
                .send(Ok(AssuanResult {
                    lines: vec!["S SERIALNO AABB".into(), "OK".into()],
                }))
                .unwrap();
        });
        let (_, result) = pool
            .query("SERIALNO".into(), &mut QueryFailures::default())
            .await
            .unwrap();
        assert!(result.success());
        replies.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn native_cancellation_takes_priority_over_saved_query_errors() {
        let (pool, mut receivers) = query_pool(&["a", "b"]);
        let mut b = receivers.pop().unwrap();
        let mut a = receivers.pop().unwrap();
        let replies = tokio::spawn(async move {
            a.recv()
                .await
                .unwrap()
                .reply
                .send(Ok(AssuanResult::error(17, "No key")))
                .unwrap();
            let command = b.recv().await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            command
                .reply
                .send(Ok(AssuanResult::error(100663395, "canceled")))
                .unwrap();
        });
        let (peer, result) = pool
            .query("READKEY OPENPGP.1".into(), &mut QueryFailures::default())
            .await
            .unwrap();
        assert_eq!(peer, "b");
        assert_eq!(&*result.lines[0], b"ERR 100663395 canceled");
        replies.await.unwrap();
    }

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
            pool.query("SERIALNO".into(), &mut QueryFailures::default())
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
        for status in &statuses {
            status.send_replace((
                Some(pool.target.borrow().clone()),
                CardPreparation::Unavailable,
            ));
        }
        assert!(
            pool.ready().await.is_err(),
            "all unavailable devices waited until timeout"
        );
        statuses[0].send_replace((Some(pool.target.borrow().clone()), CardPreparation::Waiting));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), pool.ready())
                .await
                .is_err(),
            "an unavailable device ended another device's preparation"
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
