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
            Control::Queue { operation } => {
                self.executor(device, connection)?;
                Ok(Reply::Operation(
                    self.db
                        .queue_operation(device, connection, operation)
                        .await?,
                ))
            }
            Control::ResumeOperation { id } => {
                self.executor(device, connection)?;
                Ok(Reply::Operation(
                    self.db.resume_operation(device, connection, &id).await?,
                ))
            }
            Control::OperationStatus { id } => {
                Ok(Reply::Operation(self.db.operation(device, &id).await?.0))
            }
            Control::ClaimOperation {
                id,
                initiator,
                channel,
                service,
            } => {
                self.executor(device, connection)?;
                let (mut op, owner_connection) = self.db.operation(device, &id).await?;
                let previous = op.clone();
                if op.state != OperationState::Pending
                    || op.initiator != initiator
                    || op.channel != channel
                    || op.service != service
                {
                    bail!("operation is terminal or does not match session");
                }
                self.executor(&op.initiator, &owner_connection)?;
                let target = op
                    .targets
                    .iter_mut()
                    .find(|t| t.device == device)
                    .context("not an operation target")?;
                if target.state != TargetState::Pending {
                    bail!("operation already executed or execution result unknown");
                }
                target.state = TargetState::Executing;
                self.db
                    .save_operation(&op, &owner_connection, &previous)
                    .await?;
                Ok(Reply::Operation(op))
            }
            Control::TargetDone { id, success } => {
                let (mut op, owner_connection) = self.db.operation(device, &id).await?;
                let previous = op.clone();
                let target = op
                    .targets
                    .iter_mut()
                    .find(|t| t.device == device)
                    .context("not an operation target")?;
                let terminal = if success {
                    TargetState::Succeeded
                } else {
                    TargetState::Failed
                };
                if target.state == terminal {
                    return Ok(Reply::Operation(op));
                }
                if target.state != TargetState::Executing {
                    bail!("operation target is not executing");
                }
                target.state = terminal;
                self.db
                    .save_operation(&op, &owner_connection, &previous)
                    .await?;
                Ok(Reply::Operation(op))
            }
            Control::AbandonTarget { id, peer } => {
                let (mut op, owner_connection) = self.db.operation(device, &id).await?;
                let previous = op.clone();
                if op.initiator != device {
                    bail!("only initiator can abandon a target");
                }
                let target = op
                    .targets
                    .iter_mut()
                    .find(|t| t.device == peer)
                    .context("not a target")?;
                if target.state == TargetState::Pending {
                    target.state = TargetState::Failed;
                }
                self.db
                    .save_operation(&op, &owner_connection, &previous)
                    .await?;
                Ok(Reply::Operation(op))
            }
            Control::EndOperation { id, completed } => {
                let (mut op, owner_connection) = self.db.operation(device, &id).await?;
                let previous = op.clone();
                if op.initiator != device {
                    bail!("only initiator can end operation");
                }
                if op.state == OperationState::Pending {
                    op.state = if completed {
                        OperationState::Completed
                    } else {
                        OperationState::Canceled
                    };
                    self.db
                        .save_operation(&op, &owner_connection, &previous)
                        .await?;
                    self.operation_changed(&op);
                }
                Ok(Reply::Operation(op))
            }
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
                {
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
                }
                self.notify_ready(device).await?;
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

    fn executor(&self, device: &str, connection: &str) -> Result<()> {
        if !self
            .executors
            .lock()
            .unwrap()
            .get(device)
            .is_some_and(|e| e.connection == connection && !e.stop.is_cancelled())
        {
            bail!("operation owner or target is offline; resume on current connection");
        }
        Ok(())
    }
    fn operation_changed(&self, operation: &Operation) {
        for (device, executor) in self.executors.lock().unwrap().iter() {
            if (operation.initiator == *device
                || operation.targets.iter().any(|t| t.device == *device))
                && executor
                    .tx
                    .try_send(Envelope::OperationChanged {
                        id: operation.id.clone(),
                    })
                    .is_err()
            {
                executor.stop.cancel();
            }
        }
    }
    async fn notify_ready(&self, device: &str) -> Result<()> {
        for (op, connection) in self.db.queued_for(device).await? {
            let executors = self.executors.lock().unwrap();
            if !executors
                .get(device)
                .is_some_and(|e| e.channels.contains(&op.channel))
            {
                continue;
            }
            if let Some(owner) = executors
                .get(&op.initiator)
                .filter(|e| e.connection == connection && e.channels.contains(&op.channel))
                && owner
                    .tx
                    .try_send(Envelope::OperationReady {
                        id: op.id,
                        peer: device.into(),
                    })
                    .is_err()
            {
                owner.stop.cancel();
            }
        }
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

    struct QueueFixture {
        dir: tempfile::TempDir,
        service: Service,
        a: Identity,
        b: Identity,
        channel: String,
        tx: mpsc::Sender<Envelope>,
        _rx: mpsc::Receiver<Envelope>,
        stop: CancellationToken,
    }
    impl QueueFixture {
        async fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let db = Database::open(&dir.path().join("db")).await.unwrap();
            let a = Identity::generate("caller".into()).unwrap();
            let b = Identity::generate("executor".into()).unwrap();
            db.register(&a.device).await.unwrap();
            db.register(&b.device).await.unwrap();
            let verifier = hash_psk("test-secret").unwrap();
            let genesis = ChannelGenesis::create(&a, "queue".into(), &verifier).unwrap();
            let proof = db.create(&a.device.id(), genesis, verifier).await.unwrap();
            let request = JoinRequest::create(&b, &proof.verify().unwrap()).unwrap();
            db.join(&b.device.id(), request.clone(), "test-secret".into())
                .await
                .unwrap();
            let event = MembershipEvent::create(
                &a,
                &proof.verify().unwrap(),
                MembershipAction::Admit(request),
            )
            .unwrap();
            db.append(&a.device.id(), event, None).await.unwrap();
            let (tx, rx) = mpsc::channel(64);
            let f = Self {
                dir,
                service: Service::new(db, true),
                a,
                b,
                channel: proof.genesis.body.id,
                tx,
                _rx: rx,
                stop: CancellationToken::new(),
            };
            f.announce(&f.a, "a").await;
            f.announce(&f.b, "b").await;
            f
        }
        async fn command(
            &self,
            caller: &Identity,
            connection: &str,
            command: Control,
        ) -> Result<Reply> {
            self.service
                .control(
                    &caller.device.id(),
                    connection,
                    &self.tx,
                    command,
                    &self.stop,
                )
                .await
        }
        async fn announce(&self, caller: &Identity, connection: &str) {
            self.command(
                caller,
                connection,
                Control::Announce {
                    channels: vec![self.channel.clone()],
                },
            )
            .await
            .unwrap();
        }
        fn operation(&self) -> Operation {
            Operation {
                id: random_id(),
                channel: self.channel.clone(),
                initiator: self.a.device.id(),
                service: ServiceKind::Pinentry,
                deadline: hibiki_lib::now() + 120,
                state: OperationState::Pending,
                targets: vec![OperationTarget {
                    device: self.b.device.id(),
                    state: TargetState::Pending,
                }],
            }
        }
        fn claim(&self, id: &str) -> Control {
            Control::ClaimOperation {
                id: id.into(),
                initiator: self.a.device.id(),
                channel: self.channel.clone(),
                service: ServiceKind::Pinentry,
            }
        }
    }

    #[tokio::test]
    async fn independent_database_writers_cannot_claim_the_same_target() {
        let f = QueueFixture::new().await;
        let op = f.operation();
        f.command(
            &f.a,
            "a",
            Control::Queue {
                operation: op.clone(),
            },
        )
        .await
        .unwrap();
        let other = Database::open(&f.dir.path().join("db")).await.unwrap();
        let mut claimed = op.clone();
        claimed.targets[0].state = TargetState::Executing;
        let (first, second) = tokio::join!(
            f.service.db.save_operation(&claimed, "a", &op),
            other.save_operation(&claimed, "a", &op)
        );
        assert_ne!(first.is_ok(), second.is_ok());
        assert_eq!(
            other
                .operation(&f.a.device.id(), &op.id)
                .await
                .unwrap()
                .0
                .targets[0]
                .state,
            TargetState::Executing
        );
    }

    #[tokio::test]
    async fn offline_ready_notification_stops_after_completion_and_queue_limits_hold() {
        let mut f = QueueFixture::new().await;
        f.service.executors.lock().unwrap().remove(&f.b.device.id());
        let op = f.operation();
        f.command(
            &f.a,
            "a",
            Control::Queue {
                operation: op.clone(),
            },
        )
        .await
        .unwrap();
        assert!(f._rx.try_recv().is_err());
        f.announce(&f.b, "b").await;
        assert!(
            matches!(f._rx.try_recv().unwrap(),Envelope::OperationReady {id,..} if id == op.id)
        );
        f.command(
            &f.a,
            "a",
            Control::EndOperation {
                id: op.id.clone(),
                completed: true,
            },
        )
        .await
        .unwrap();
        while f._rx.try_recv().is_ok() {}
        f.announce(&f.b, "b").await;
        assert!(f._rx.try_recv().is_err());
        for _ in 0..128 {
            f.command(
                &f.a,
                "a",
                Control::Queue {
                    operation: f.operation(),
                },
            )
            .await
            .unwrap();
        }
        assert!(
            f.command(
                &f.a,
                "a",
                Control::Queue {
                    operation: f.operation()
                }
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("queue full")
        );
        let mut same_target = f.operation();
        same_target.initiator = f.b.device.id();
        assert!(
            f.command(
                &f.b,
                "b",
                Control::Queue {
                    operation: same_target
                }
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("target operation queue full")
        );
    }

    #[tokio::test]
    async fn queued_claim_is_atomic_and_terminal_operations_cannot_replay() {
        let f = QueueFixture::new().await;
        let op = f.operation();
        f.command(
            &f.a,
            "a",
            Control::Queue {
                operation: op.clone(),
            },
        )
        .await
        .unwrap();
        let (first, duplicate) = tokio::join!(
            f.command(&f.b, "b", f.claim(&op.id)),
            f.command(&f.b, "b", f.claim(&op.id))
        );
        assert_ne!(first.is_ok(), duplicate.is_ok());
        assert!(f.command(&f.a, "a", f.claim(&op.id)).await.is_err());
        f.command(
            &f.b,
            "b",
            Control::TargetDone {
                id: op.id.clone(),
                success: true,
            },
        )
        .await
        .unwrap();
        f.command(
            &f.a,
            "a",
            Control::EndOperation {
                id: op.id.clone(),
                completed: true,
            },
        )
        .await
        .unwrap();
        assert!(f.command(&f.b, "b", f.claim(&op.id)).await.is_err());
        let Reply::Operation(saved) = f
            .command(
                &f.a,
                "a",
                Control::Queue {
                    operation: op.clone(),
                },
            )
            .await
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(saved.state, OperationState::Completed);
        assert_eq!(saved.targets[0].state, TargetState::Succeeded);
        let mut changed = op;
        changed.deadline += 10;
        assert!(
            f.command(&f.a, "a", Control::Queue { operation: changed })
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn restart_requires_live_owner_resume_and_preserves_unknown_execution() {
        let mut f = QueueFixture::new().await;
        let op = f.operation();
        f.command(
            &f.a,
            "a",
            Control::Queue {
                operation: op.clone(),
            },
        )
        .await
        .unwrap();
        f.service = Service::new(
            Database::open(&f.dir.path().join("db")).await.unwrap(),
            true,
        );
        f.announce(&f.a, "a-new").await;
        f.announce(&f.b, "b-new").await;
        assert!(f.command(&f.b, "b-new", f.claim(&op.id)).await.is_err());
        assert!(
            f.command(
                &f.b,
                "b-new",
                Control::ResumeOperation { id: op.id.clone() }
            )
            .await
            .is_err()
        );
        f.command(
            &f.a,
            "a-new",
            Control::ResumeOperation { id: op.id.clone() },
        )
        .await
        .unwrap();
        f.command(&f.b, "b-new", f.claim(&op.id)).await.unwrap();
        f.service = Service::new(
            Database::open(&f.dir.path().join("db")).await.unwrap(),
            true,
        );
        f.announce(&f.a, "a-third").await;
        f.announce(&f.b, "b-third").await;
        f.command(
            &f.a,
            "a-third",
            Control::ResumeOperation { id: op.id.clone() },
        )
        .await
        .unwrap();
        assert!(f.command(&f.b, "b-third", f.claim(&op.id)).await.is_err());
        assert_eq!(
            f.service
                .db
                .operation(&f.a.device.id(), &op.id)
                .await
                .unwrap()
                .0
                .targets[0]
                .state,
            TargetState::Executing
        );
    }

    #[tokio::test]
    async fn cancel_expiry_revocation_and_deletion_block_delivery() {
        let f = QueueFixture::new().await;
        let canceled = f.operation();
        f.command(
            &f.a,
            "a",
            Control::Queue {
                operation: canceled.clone(),
            },
        )
        .await
        .unwrap();
        f.command(
            &f.a,
            "a",
            Control::EndOperation {
                id: canceled.id.clone(),
                completed: false,
            },
        )
        .await
        .unwrap();
        assert!(f.command(&f.b, "b", f.claim(&canceled.id)).await.is_err());
        let mut expired = f.operation();
        f.command(
            &f.a,
            "a",
            Control::Queue {
                operation: expired.clone(),
            },
        )
        .await
        .unwrap();
        let previous = expired.clone();
        expired.deadline = hibiki_lib::now() - 1;
        f.service
            .db
            .save_operation(&expired, "a", &previous)
            .await
            .unwrap();
        assert!(f.command(&f.b, "b", f.claim(&expired.id)).await.is_err());
        assert_eq!(
            f.service
                .db
                .operation(&f.a.device.id(), &expired.id)
                .await
                .unwrap()
                .0
                .state,
            OperationState::Expired
        );
        let revoked = f.operation();
        f.command(
            &f.a,
            "a",
            Control::Queue {
                operation: revoked.clone(),
            },
        )
        .await
        .unwrap();
        let proof = f.service.db.get(&f.channel).await.unwrap();
        let event = MembershipEvent::create(
            &f.a,
            &proof.verify().unwrap(),
            MembershipAction::Revoke {
                device_id: f.b.device.id(),
            },
        )
        .unwrap();
        f.command(
            &f.a,
            "a",
            Control::Append {
                event,
                verifier: None,
            },
        )
        .await
        .unwrap();
        assert!(f.command(&f.b, "b", f.claim(&revoked.id)).await.is_err());
        f.service.db.delete("queue").await.unwrap();
        assert_eq!(
            f.service
                .db
                .operation(&f.a.device.id(), &revoked.id)
                .await
                .unwrap()
                .0
                .state,
            OperationState::Canceled
        );
    }

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
