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
use hibiki_lib::{
    identity::verify,
    protocol::*,
    random_id,
    wire::{self, decode, encode},
};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::sync::{
    OwnedMutexGuard, OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock, mpsc, oneshot,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct Service {
    pub db: Database,
    pub allow_client_channel_creation: bool,
    executors: Arc<Mutex<HashMap<String, Executor>>>,
    // Readers route concurrently; authority changes exclude readers only in
    // their own channel. Weak entries do not retain locks for arbitrary IDs.
    authority: Arc<Mutex<HashMap<String, Weak<RwLock<()>>>>>,
    operations: Arc<Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>>,
    // Queue limits span channels, so admission still needs a global guard.
    queue_admission: Arc<tokio::sync::Mutex<()>>,
}
// Keep owned guards alive until the command and its notifications complete.
#[derive(Default)]
struct AuthorityGuard {
    _reads: Vec<OwnedRwLockReadGuard<()>>,
    _write: Option<OwnedRwLockWriteGuard<()>>,
    _operation: Option<OwnedMutexGuard<()>>,
    channel: String,
}

fn shared_lock<T: Default>(locks: &Mutex<HashMap<String, Weak<T>>>, key: &str) -> Arc<T> {
    let mut locks = locks.lock().unwrap();
    if let Some(lock) = locks.get(key).and_then(Weak::upgrade) {
        return lock;
    }
    locks.retain(|_, lock| lock.strong_count() > 0);
    let lock = Arc::new(T::default());
    locks.insert(key.into(), Arc::downgrade(&lock));
    lock
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
            authority: Default::default(),
            operations: Default::default(),
            queue_admission: Default::default(),
        }
    }
    fn channel_authority(&self, channel: &str) -> Arc<RwLock<()>> {
        shared_lock(&self.authority, channel)
    }
    async fn control_authority(&self, device: &str, cmd: &Control) -> Result<AuthorityGuard> {
        let (channel, write) = match cmd {
            Control::Policy | Control::ListChannels => return Ok(AuthorityGuard::default()),
            Control::Announce { channels } => {
                // Always take multi-channel locks in the same order.
                let mut channels = channels.clone();
                channels.sort();
                channels.dedup();
                let mut guards = Vec::new();
                for channel in channels {
                    guards.push(self.channel_authority(&channel).read_owned().await);
                }
                return Ok(AuthorityGuard {
                    _reads: guards,
                    ..Default::default()
                });
            }
            Control::GetChannel { channel }
            | Control::ChannelSnapshot { channel }
            | Control::Peers { channel }
            | Control::Pending { channel }
            | Control::JoinStatus { channel, .. } => (channel.clone(), false),
            Control::RejectJoin { channel, .. }
            | Control::WithdrawJoin { channel, .. }
            | Control::WithdrawPending { channel } => (channel.clone(), false),
            Control::Queue { operation } => (operation.channel.clone(), false),
            Control::ResumeOperation { id }
            | Control::OperationStatus { id }
            | Control::ClaimOperation { id, .. }
            | Control::TargetDone { id, .. }
            | Control::AbandonTarget { id, .. }
            | Control::EndOperation { id, .. } => {
                // Resolve from immutable stored metadata, not an untrusted
                // ClaimOperation channel. Recheck the operation under the lock.
                (self.db.operation_channel(device, id).await?, false)
            }
            Control::Create { genesis, .. } | Control::Claim { genesis, .. } => {
                (genesis.body.id.clone(), true)
            }
            Control::Join { request, .. } => (request.body.channel_id.clone(), false),
            Control::Append { event, .. } => (event.body.channel_id.clone(), true),
        };
        let lock = self.channel_authority(&channel);
        let mut guard = if write {
            AuthorityGuard {
                _write: Some(lock.write_owned().await),
                channel,
                ..Default::default()
            }
        } else {
            AuthorityGuard {
                _reads: vec![lock.read_owned().await],
                channel,
                ..Default::default()
            }
        };
        let operation = match cmd {
            Control::Queue { operation } => Some(&operation.id),
            Control::ResumeOperation { id }
            | Control::OperationStatus { id }
            | Control::ClaimOperation { id, .. }
            | Control::TargetDone { id, .. }
            | Control::AbandonTarget { id, .. }
            | Control::EndOperation { id, .. } => Some(id),
            _ => None,
        };
        if let Some(id) = operation {
            guard._operation = Some(shared_lock(&self.operations, id).lock_owned().await);
        }
        Ok(guard)
    }
    async fn channel(&self, id: &str) -> Result<hibiki_lib::channel::MembershipProof> {
        self.db.get(id).await
    }
    pub async fn notify_deleted(&self) -> Result<()> {
        let channels: HashSet<String> = self
            .executors
            .lock()
            .unwrap()
            .values()
            .flat_map(|e| e.channels.iter().cloned())
            .collect();
        for channel in channels {
            let _authority = self.channel_authority(&channel).write_owned().await;
            let exists = self.db.exists(&channel).await?;
            let revoked = self.db.revoked(&channel).await?;
            if !exists || !revoked.is_empty() {
                for (id, executor) in self.executors.lock().unwrap().iter_mut() {
                    if revoked.contains(id) {
                        executor.stop.cancel();
                    }
                    if (!exists || revoked.contains(id))
                        && executor.channels.remove(&channel)
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
        // Wait for global admission before taking channel authority, so a queue
        // request waiting on another channel cannot delay its own revocation.
        let _admission = if matches!(&cmd, Control::Queue { .. }) {
            Some(self.queue_admission.lock().await)
        } else {
            None
        };
        let authority = self.control_authority(device, &cmd).await?;
        match cmd {
            Control::Policy => Ok(Reply::Policy {
                allow_client_channel_creation: self.allow_client_channel_creation,
            }),
            Control::RejectJoin { channel, request } => {
                self.db
                    .remove_pending(device, &channel, &request, false)
                    .await?;
                Ok(Reply::Ok)
            }
            Control::WithdrawJoin { channel, request } => {
                self.db
                    .remove_pending(device, &channel, &request, true)
                    .await?;
                Ok(Reply::Ok)
            }
            Control::WithdrawPending { channel } => Ok(Reply::Proof(
                self.db.withdraw_pending(device, &channel).await?,
            )),
            Control::JoinStatus { channel, request } => Ok(Reply::JoinStatus(
                self.db.join_status(device, &channel, &request).await?,
            )),
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
                let (op, saved_connection) = self
                    .db
                    .operation_in_channel(device, &id, &authority.channel)
                    .await?;
                if op.initiator != device {
                    bail!("only initiator can resume operation");
                }
                if saved_connection != connection {
                    self.db.save_operation(&op, connection, &op).await?;
                }
                Ok(Reply::Operation(op))
            }
            Control::OperationStatus { id } => Ok(Reply::Operation(
                self.db
                    .operation_in_channel(device, &id, &authority.channel)
                    .await?
                    .0,
            )),
            Control::ClaimOperation {
                id,
                initiator,
                channel,
                service,
            } => {
                self.executor(device, connection)?;
                let (mut op, owner_connection) = self
                    .db
                    .operation_in_channel(device, &id, &authority.channel)
                    .await?;
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
                let (mut op, owner_connection) = self
                    .db
                    .operation_in_channel(device, &id, &authority.channel)
                    .await?;
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
                let (mut op, owner_connection) = self
                    .db
                    .operation_in_channel(device, &id, &authority.channel)
                    .await?;
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
                let (mut op, owner_connection) = self
                    .db
                    .operation_in_channel(device, &id, &authority.channel)
                    .await?;
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
            Control::GetChannel { channel } => {
                self.db.require_access(&channel, device).await?;
                Ok(Reply::Proof(self.channel(&channel).await?))
            }
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
                    self.db.require_access(&channel, device).await?;
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
                for (id, executor) in self.executors.lock().unwrap().iter() {
                    if id != device {
                        let _ = executor.tx.try_send(Envelope::PeerOnline {
                            peer: device.into(),
                        });
                    }
                }
                self.notify_ready(device).await?;
                Ok(Reply::Ok)
            }
            Control::ChannelSnapshot { channel } => {
                let proof = self.channel(&channel).await?;
                let state = proof.verify()?;
                state.member(device)?;
                self.db.require_access(&channel, device).await?;
                let revoked = self.db.revoked(&channel).await?;
                let mut online: Vec<_> = self
                    .executors
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|(id, e)| {
                        e.channels.contains(&channel)
                            && state.member(id).is_ok()
                            && !revoked.contains(id)
                    })
                    .map(|(id, _)| id.clone())
                    .collect();
                online.sort();
                Ok(Reply::ChannelSnapshot {
                    proof,
                    online,
                    revoked,
                })
            }
            Control::Peers { channel } => {
                let state = self.channel(&channel).await?.verify()?;
                state.member(device)?;
                self.db.require_access(&channel, device).await?;
                let revoked = self.db.revoked(&channel).await?;
                let executors = self.executors.lock().unwrap();
                let mut peers: Vec<_> = executors
                    .iter()
                    .filter(|(id, e)| {
                        id.as_str() != device
                            && e.channels.contains(&channel)
                            && state.member(id).is_ok()
                            && !revoked.contains(id)
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
        let _authority = self.channel_authority(&channel).read_owned().await;
        if data.len() > 65535 || !hibiki_lib::channel::valid_id(&session) {
            bail!("invalid relay frame");
        }
        let state = self.channel(&channel).await?.verify()?;
        self.db.require_access(&channel, sender).await?;
        self.db.require_access(&channel, &peer).await?;
        state.member(sender)?;
        state.member(&peer)?;
        // Keep subscription validation and nonblocking enqueue atomic with
        // Announce and disconnect, which update this same executor registry.
        let executors = self.executors.lock().unwrap();
        let source = executors.get(sender).context("sender is not an executor")?;
        if source.connection != connection
            || !source.channels.contains(&channel)
            || source.stop.is_cancelled()
        {
            bail!("unauthorized source");
        }
        let target = executors.get(&peer).context("peer is offline")?;
        if !target.channels.contains(&channel) || target.stop.is_cancelled() {
            bail!("peer is not subscribed to channel");
        }
        target
            .tx
            .try_send(Envelope::Relay {
                channel,
                peer: sender.into(),
                session,
                data,
            })
            .map_err(|_| anyhow::anyhow!("peer queue is full or closed"))?;
        Ok(())
    }

    async fn process_envelope(
        &self,
        device: &str,
        connection: &str,
        tx: &mpsc::Sender<Envelope>,
        stop: &CancellationToken,
        envelope: Envelope,
    ) -> Result<()> {
        let response = match envelope {
            Envelope::Request { id, command } => {
                let result = self
                    .control(device, connection, tx, command, stop)
                    .await
                    .map_err(|e| {
                        let message = e.to_string();
                        let code = if message.contains("CONFLICT") {
                            "conflict"
                        } else {
                            "request_failed"
                        };
                        WireError::new(code, message)
                    });
                Some(Envelope::Response { id, result })
            }
            Envelope::Relay {
                channel,
                peer,
                session,
                data,
            } => {
                match self
                    .relay(
                        device,
                        connection,
                        channel,
                        peer.clone(),
                        session.clone(),
                        data,
                    )
                    .await
                {
                    Ok(()) => None,
                    Err(e) => Some(Envelope::RelayFailure {
                        session,
                        peer,
                        error: WireError::new("relay_failed", e.to_string()),
                    }),
                }
            }
            _ => bail!("unexpected envelope"),
        };
        if let Some(response) = response {
            tokio::time::timeout(Duration::from_secs(10), tx.send(response)).await??;
        }
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
    let server_capabilities = wire::supported_capabilities();
    socket
        .send(Message::Binary(
            encode(&Envelope::Hello {
                version: VERSION.into(),
                nonce: nonce.clone(),
                capabilities: server_capabilities.clone(),
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
    let Envelope::Authenticate {
        device,
        signature,
        capabilities: client_capabilities,
    } = decode(&bytes)?
    else {
        bail!("authentication required");
    };
    device.verify()?;
    let device_id = device.id();
    verify(
        &device.signing_key,
        "server-auth/v2",
        &wire::authentication_body(
            VERSION,
            &nonce,
            &device_id,
            &server_capabilities,
            &client_capabilities,
        )?,
        &signature,
    )?;
    let capabilities = wire::negotiate_capabilities(&server_capabilities, &client_capabilities)?;
    service.db.register(&device).await?;
    socket
        .send(Message::Binary(
            encode(&Envelope::Authenticated { capabilities })?.into(),
        ))
        .await?;
    let connection = random_id();
    let stop = CancellationToken::new();
    let _registration = Registration {
        service: service.clone(),
        device: device_id.clone(),
        connection: connection.clone(),
    };
    let (tx, mut rx) = mpsc::channel::<Envelope>(64);
    let (frames, mut frame_rx) = mpsc::channel::<Message>(16);
    let (mut writer, mut reader) = socket.split();
    let mut jobs = tokio::task::JoinSet::new();
    let mut order = RelayOrder::default();
    let bytes_in_flight = Arc::new(tokio::sync::Semaphore::new(MAX_WIRE * 2));
    let result = {
        // One writer owns the sink. Slow database work never prevents it from
        // sending queued relays, responses, pongs, or periodic heartbeats.
        let write = async {
            let mut heartbeat = tokio::time::interval(Duration::from_secs(15));
            loop {
                let message = tokio::select! {
                    _ = heartbeat.tick() => Message::Ping(vec![].into()),
                    Some(message) = frame_rx.recv() => message,
                    Some(envelope) = rx.recv() => Message::Binary(encode(&envelope)?.into()),
                };
                if let Err(error) = send_bounded(&mut writer, message).await {
                    break Err::<(), _>(error);
                }
            }
        };
        let read = async {
            let mut last_seen = tokio::time::Instant::now();
            loop {
                tokio::select! {
                    result = jobs.join_next(), if !jobs.is_empty() => { result.unwrap()??; }
                    incoming = tokio::time::timeout_at(last_seen + Duration::from_secs(45), reader.next()) => {
                        let Some(message) = incoming? else { break; };
                        last_seen = tokio::time::Instant::now();
                        match message? {
                            Message::Ping(data) => { frames.try_send(Message::Pong(data))?; }
                            Message::Pong(_) => {}
                            Message::Close(_) => break,
                            Message::Binary(bytes) => {
                                // Bound both task count and retained request bytes. Overload
                                // closes this connection instead of blocking heartbeat reads.
                                while let Some(result) = jobs.try_join_next() { result??; }
                                if jobs.len() >= 128 {
                                    bail!("too many in-flight messages");
                                }
                                let budget = bytes_in_flight.clone()
                                    .try_acquire_many_owned(bytes.len() as u32)?;
                                let envelope: Envelope = decode(&bytes)?;
                                let previous = order.enqueue(&envelope);
                                let service = service.clone();
                                let device = device_id.clone();
                                let connection = connection.clone();
                                let tx = tx.clone();
                                let stop = stop.clone();
                                jobs.spawn(async move {
                                    let _budget = budget;
                                    let _complete = if let Some((previous, complete)) = previous {
                                        if let Some(previous) = previous {
                                            let _ = previous.await;
                                        }
                                        Some(complete)
                                    } else {
                                        None
                                    };
                                    service.process_envelope(&device, &connection, &tx, &stop, envelope).await
                                });
                            }
                            _ => bail!("unexpected WebSocket message"),
                        }
                    }
                }
            }
            Ok::<_, anyhow::Error>(())
        };
        tokio::select! {
            _ = stop.cancelled() => Ok(()),
            result = write => result,
            result = read => result,
        }
    };
    stop.cancel();
    // Finish dropping every worker before unregistering the executor; a queued
    // Announce must not outlive disconnect and resurrect an abandoned connection.
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
    result
}

/// Chain only frames belonging to the same peer/channel/Noise session. Other
/// sessions and independent control requests can complete out of order.
#[derive(Default)]
struct RelayOrder {
    tails: HashMap<(String, String, String), oneshot::Receiver<()>>,
}
impl RelayOrder {
    fn enqueue(
        &mut self,
        envelope: &Envelope,
    ) -> Option<(Option<oneshot::Receiver<()>>, oneshot::Sender<()>)> {
        self.tails
            .retain(|_, tail| matches!(tail.try_recv(), Err(oneshot::error::TryRecvError::Empty)));
        let Envelope::Relay {
            channel,
            peer,
            session,
            ..
        } = envelope
        else {
            return None;
        };
        let (complete, tail) = oneshot::channel();
        let previous = self
            .tails
            .insert((channel.clone(), peer.clone(), session.clone()), tail);
        Some((previous, complete))
    }
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

    use tokio_tungstenite::tungstenite::Message as ClientMessage;

    struct TestSocket {
        ws: tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        server: tokio::task::JoinHandle<()>,
    }
    impl Drop for TestSocket {
        fn drop(&mut self) {
            self.server.abort();
        }
    }
    impl TestSocket {
        async fn new(service: Service, identity: &Identity) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}{WS_PATH}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                axum::serve(listener, service.router()).await.unwrap();
            });
            let (ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
            let mut socket = Self { ws, server };
            let Envelope::Hello {
                version,
                nonce,
                capabilities,
            } = socket.envelope().await
            else {
                panic!()
            };
            let client_caps = wire::supported_capabilities();
            let signature = identity
                .sign(
                    "server-auth/v2",
                    &wire::authentication_body(
                        &version,
                        &nonce,
                        &identity.device.id(),
                        &capabilities,
                        &client_caps,
                    )
                    .unwrap(),
                )
                .unwrap();
            socket
                .send(Envelope::Authenticate {
                    device: identity.device.clone(),
                    signature,
                    capabilities: client_caps,
                })
                .await;
            assert!(matches!(
                socket.envelope().await,
                Envelope::Authenticated { .. }
            ));
            socket
        }
        async fn send(&mut self, envelope: Envelope) {
            self.ws
                .send(ClientMessage::Binary(encode(&envelope).unwrap().into()))
                .await
                .unwrap();
        }
        async fn envelope(&mut self) -> Envelope {
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    match self.ws.next().await.unwrap().unwrap() {
                        ClientMessage::Binary(raw) => return decode(&raw).unwrap(),
                        ClientMessage::Ping(data) => {
                            self.ws.send(ClientMessage::Pong(data)).await.unwrap()
                        }
                        ClientMessage::Pong(_) => {}
                        message => panic!("unexpected frame: {message:?}"),
                    }
                }
            })
            .await
            .unwrap()
        }
        async fn announce(&mut self, channel: &str) {
            self.send(Envelope::Request {
                id: "announce".into(),
                command: Control::Announce {
                    channels: vec![channel.into()],
                },
            })
            .await;
            assert!(matches!(
                self.envelope().await,
                Envelope::Response {
                    result: Ok(Reply::Ok),
                    ..
                }
            ));
        }
    }

    #[tokio::test]
    async fn routing_shares_authority_but_revocation_is_exclusive_and_channel_scoped() {
        let f = QueueFixture::new().await;
        let proof = f.service.db.get(&f.channel).await.unwrap();
        let event = MembershipEvent::create(
            &f.a,
            &proof.verify().unwrap(),
            MembershipAction::Revoke {
                device_id: f.b.device.id(),
            },
        )
        .unwrap();
        let verifier = hash_psk("other-secret").unwrap();
        let genesis = ChannelGenesis::create(&f.a, "other".into(), &verifier).unwrap();
        let other = f
            .service
            .db
            .create(&f.a.device.id(), genesis, verifier)
            .await
            .unwrap();
        let lock = f.service.channel_authority(&f.channel);
        let reader = lock.clone().read_owned().await;
        // A reader already holding authority must not serialize another relay.
        tokio::time::timeout(
            Duration::from_secs(1),
            f.service.relay(
                &f.a.device.id(),
                "a",
                f.channel.clone(),
                f.b.device.id(),
                random_id(),
                vec![1],
            ),
        )
        .await
        .unwrap()
        .unwrap();
        let mut revoke = Box::pin(f.command(
            &f.a,
            "a",
            Control::Append {
                event,
                verifier: None,
            },
        ));
        // Poll once to enqueue the exclusive acquisition behind the held reader.
        tokio::select! {
            biased;
            result = &mut revoke => panic!("revocation bypassed reader: {result:?}"),
            _ = std::future::ready(()) => {}
        }
        // A queued writer on this channel must not block another channel.
        tokio::time::timeout(
            Duration::from_secs(1),
            f.command(
                &f.a,
                "a",
                Control::GetChannel {
                    channel: other.genesis.body.id,
                },
            ),
        )
        .await
        .unwrap()
        .unwrap();
        drop(reader);
        revoke.await.unwrap();
        assert!(
            f.service
                .relay(
                    &f.a.device.id(),
                    "a",
                    f.channel.clone(),
                    f.b.device.id(),
                    random_id(),
                    vec![2],
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn blocked_control_does_not_block_socket_io_or_other_requests() {
        let f = QueueFixture::new().await;
        f.service.executors.lock().unwrap().remove(&f.a.device.id());
        let mut socket = TestSocket::new(f.service.clone(), &f.a).await;
        socket.announce(&f.channel).await;
        let guard = f.service.channel_authority(&f.channel).write_owned().await;
        socket
            .send(Envelope::Request {
                id: "blocked".into(),
                command: Control::GetChannel {
                    channel: f.channel.clone(),
                },
            })
            .await;
        socket
            .send(Envelope::Request {
                id: "fast".into(),
                command: Control::Policy,
            })
            .await;
        assert!(matches!(socket.envelope().await,
            Envelope::Response { id, result: Ok(Reply::Policy { .. }) } if id == "fast"));
        // An outbound notification must be written while the request is blocked.
        f.service.executors.lock().unwrap()[&f.a.device.id()]
            .tx
            .try_send(Envelope::PeerOnline {
                peer: "notification".into(),
            })
            .unwrap();
        assert!(
            matches!(socket.envelope().await, Envelope::PeerOnline { peer } if peer == "notification")
        );
        socket
            .ws
            .send(ClientMessage::Ping(vec![1, 2, 3].into()))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match socket.ws.next().await.unwrap().unwrap() {
                    ClientMessage::Pong(data) if data.as_ref() == [1, 2, 3] => break,
                    ClientMessage::Ping(data) => {
                        socket.ws.send(ClientMessage::Pong(data)).await.unwrap()
                    }
                    _ => panic!("expected pong while control is blocked"),
                }
            }
        })
        .await
        .unwrap();
        drop(guard);
        assert!(matches!(socket.envelope().await,
            Envelope::Response { id, result: Ok(Reply::Proof(_)) } if id == "blocked"));
    }

    #[tokio::test]
    async fn socket_relays_preserve_session_order_without_blocking_other_channels() {
        let mut f = QueueFixture::new().await;
        f.service.executors.lock().unwrap().remove(&f.a.device.id());
        let mut socket = TestSocket::new(f.service.clone(), &f.a).await;
        socket.announce(&f.channel).await;
        // Subscribe the same executors to a second channel with the same members.
        let verifier = hash_psk("test-secret").unwrap();
        let genesis = ChannelGenesis::create(&f.a, "other".into(), &verifier).unwrap();
        let proof = f
            .service
            .db
            .create(&f.a.device.id(), genesis, verifier)
            .await
            .unwrap();
        let request = JoinRequest::create(&f.b, &proof.verify().unwrap()).unwrap();
        f.service
            .db
            .join(&f.b.device.id(), request.clone(), "test-secret".into())
            .await
            .unwrap();
        let event = MembershipEvent::create(
            &f.a,
            &proof.verify().unwrap(),
            MembershipAction::Admit(request),
        )
        .unwrap();
        f.service
            .db
            .append(&f.a.device.id(), event, None)
            .await
            .unwrap();
        let other = proof.genesis.body.id;
        for executor in f.service.executors.lock().unwrap().values_mut() {
            executor.channels.insert(other.clone());
        }
        while f._rx.try_recv().is_ok() {}
        let guard = f.service.channel_authority(&f.channel).write_owned().await;
        let session = random_id();
        for n in 0..16 {
            socket
                .send(Envelope::Relay {
                    channel: f.channel.clone(),
                    peer: f.b.device.id(),
                    session: session.clone(),
                    data: vec![n],
                })
                .await;
        }
        socket
            .send(Envelope::Relay {
                channel: f.channel.clone(),
                peer: f.b.device.id(),
                session: session.clone(),
                data: Vec::new(),
            })
            .await;
        socket
            .send(Envelope::Relay {
                channel: other.clone(),
                peer: f.b.device.id(),
                session: session.clone(),
                data: vec![99],
            })
            .await;
        let first = tokio::time::timeout(Duration::from_secs(2), f._rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(first, Envelope::Relay { channel, data, .. } if channel == other && data == [99])
        );
        drop(guard);
        for n in 0..16 {
            let next = tokio::time::timeout(Duration::from_secs(2), f._rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(matches!(next, Envelope::Relay { data, .. } if data == [n]));
        }
        // The empty close queued with the batch must follow every data frame.
        assert!(
            matches!(tokio::time::timeout(Duration::from_secs(2), f._rx.recv()).await.unwrap().unwrap(),
            Envelope::Relay { data, .. } if data.is_empty())
        );
    }

    #[tokio::test]
    async fn disconnect_cancels_waiting_announce_before_unregistering() {
        let f = QueueFixture::new().await;
        f.service.executors.lock().unwrap().remove(&f.a.device.id());
        let mut socket = TestSocket::new(f.service.clone(), &f.a).await;
        socket.announce(&f.channel).await;
        let guard = f.service.channel_authority(&f.channel).write_owned().await;
        socket
            .send(Envelope::Request {
                id: "waiting-announce".into(),
                command: Control::Announce {
                    channels: vec![f.channel.clone()],
                },
            })
            .await;
        socket
            .send(Envelope::Request {
                id: "barrier".into(),
                command: Control::Policy,
            })
            .await;
        assert!(
            matches!(socket.envelope().await, Envelope::Response { id, .. } if id == "barrier")
        );
        socket.ws.send(ClientMessage::Close(None)).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while f
                .service
                .executors
                .lock()
                .unwrap()
                .contains_key(&f.a.device.id())
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        drop(guard);
        assert_eq!(
            f.service.authority.lock().unwrap()[&f.channel].strong_count(),
            0
        );
        assert!(
            !f.service
                .executors
                .lock()
                .unwrap()
                .contains_key(&f.a.device.id())
        );
    }

    #[tokio::test]
    async fn blocked_operation_does_not_serialize_other_operations_or_relays() {
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
        let guard = shared_lock(&f.service.operations, &op.id)
            .lock_owned()
            .await;
        let mut claim = Box::pin(f.command(&f.b, "b", f.claim(&op.id)));
        tokio::select! {
            biased;
            result = &mut claim => panic!("claim bypassed operation lock: {result:?}"),
            _ = std::future::ready(()) => {}
        }
        tokio::time::timeout(
            Duration::from_secs(1),
            f.service.relay(
                &f.a.device.id(),
                "a",
                f.channel.clone(),
                f.b.device.id(),
                random_id(),
                vec![1],
            ),
        )
        .await
        .unwrap()
        .unwrap();
        tokio::time::timeout(
            Duration::from_secs(1),
            f.command(
                &f.a,
                "a",
                Control::Queue {
                    operation: f.operation(),
                },
            ),
        )
        .await
        .unwrap()
        .unwrap();
        drop(guard);
        claim.await.unwrap();
    }

    #[tokio::test]
    async fn full_control_burst_drains_through_bounded_output_queue() {
        let f = QueueFixture::new().await;
        let mut socket = TestSocket::new(f.service.clone(), &f.a).await;
        for n in 0..128 {
            socket
                .send(Envelope::Request {
                    id: n.to_string(),
                    command: Control::Policy,
                })
                .await;
        }
        let mut replies = HashSet::new();
        for _ in 0..128 {
            let Envelope::Response {
                id,
                result: Ok(Reply::Policy { .. }),
            } = socket.envelope().await
            else {
                panic!()
            };
            assert!(replies.insert(id));
        }
        assert_eq!(replies.len(), 128);
    }

    #[tokio::test]
    async fn socket_overload_closes_and_cleans_up_blocked_workers() {
        let f = QueueFixture::new().await;
        f.service.executors.lock().unwrap().remove(&f.a.device.id());
        let mut socket = TestSocket::new(f.service.clone(), &f.a).await;
        socket.announce(&f.channel).await;
        let guard = f.service.channel_authority(&f.channel).write_owned().await;
        for n in 0..129 {
            socket
                .send(Envelope::Request {
                    id: n.to_string(),
                    command: Control::GetChannel {
                        channel: f.channel.clone(),
                    },
                })
                .await;
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match socket.ws.next().await {
                    Some(Ok(ClientMessage::Ping(data))) => {
                        let _ = socket.ws.send(ClientMessage::Pong(data)).await;
                    }
                    None | Some(Err(_)) | Some(Ok(ClientMessage::Close(_))) => break,
                    frame => panic!("overloaded connection accepted another request: {frame:?}"),
                }
            }
        })
        .await
        .unwrap();
        assert!(
            !f.service
                .executors
                .lock()
                .unwrap()
                .contains_key(&f.a.device.id())
        );
        drop(guard);
        assert_eq!(
            f.service.authority.lock().unwrap()[&f.channel].strong_count(),
            0
        );
    }

    #[tokio::test]
    async fn local_admin_can_revoke_founder_and_cancels_queued_work() {
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
        let external = Database::open(&f.dir.path().join("db")).await.unwrap();
        let (_, affected) = external
            .admin_revoke(&f.channel[..6], &f.a.device.id()[..6], false)
            .await
            .unwrap();
        assert_eq!(affected, vec![f.a.device.id()]);
        assert!(
            external
                .require_access(&f.channel, &f.b.device.id())
                .await
                .is_ok()
        );
        assert!(f.command(&f.b, "b", f.claim(&op.id)).await.is_err());
        assert!(
            f.command(
                &f.a,
                "a",
                Control::Queue {
                    operation: f.operation()
                }
            )
            .await
            .is_err()
        );
        assert!(
            f.command(
                &f.a,
                "a",
                Control::Announce {
                    channels: vec![f.channel.clone()]
                }
            )
            .await
            .is_err()
        );
        assert!(
            f.service
                .relay(
                    &f.b.device.id(),
                    "b",
                    f.channel.clone(),
                    f.a.device.id(),
                    random_id(),
                    vec![1]
                )
                .await
                .is_err()
        );
        let (saved, _) = external.operation(&f.a.device.id(), &op.id).await.unwrap();
        assert_eq!(saved.state, OperationState::Canceled);
        let Reply::ChannelSnapshot { revoked, .. } = f
            .command(
                &f.b,
                "b",
                Control::ChannelSnapshot {
                    channel: f.channel.clone(),
                },
            )
            .await
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(revoked, vec![f.a.device.id()]);
        f.service.notify_deleted().await.unwrap();
        assert!(f.stop.is_cancelled());
        // Signed membership history is retained, not rewritten by the administrator.
        assert!(
            external
                .get(&f.channel)
                .await
                .unwrap()
                .verify()
                .unwrap()
                .member(&f.a.device.id())
                .is_ok()
        );
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
        while let Ok(event) = f._rx.try_recv() {
            assert!(matches!(event, Envelope::PeerOnline { .. }));
        }
        f.announce(&f.b, "b").await;
        assert!(
            matches!({ let mut event = f._rx.try_recv().unwrap(); while matches!(event, Envelope::PeerOnline { .. }) { event = f._rx.try_recv().unwrap(); } event },Envelope::OperationReady {id,..} if id == op.id)
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
        while let Ok(event) = f._rx.try_recv() {
            assert!(matches!(event, Envelope::PeerOnline { .. }));
        }
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
        let mut event = rx.recv().await.unwrap();
        while matches!(event, Envelope::PeerOnline { .. }) {
            event = rx.recv().await.unwrap();
        }
        assert!(matches!(event, Envelope::Relay { .. }));
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
    #[tokio::test]
    async fn future_client_authenticates_to_baseline_relay_but_tampered_capabilities_do_not() {
        use tokio_tungstenite::tungstenite::Message as ClientMessage;
        for tampered in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let db = Database::open(&dir.path().join("db")).await.unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}{WS_PATH}", listener.local_addr().unwrap());
            let router = Service::new(db, false).router();
            let server = tokio::spawn(async move {
                axum::serve(listener, router).await.unwrap();
            });
            let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
            let ClientMessage::Binary(raw) = ws.next().await.unwrap().unwrap() else {
                panic!()
            };
            let Envelope::Hello {
                version,
                nonce,
                capabilities: server_caps,
            } = decode(&raw).unwrap()
            else {
                panic!()
            };
            assert!(server_caps.is_empty());
            let identity = Identity::generate("future-client".into()).unwrap();
            let capabilities = vec!["future/query".to_owned()];
            let signature = identity
                .sign(
                    "server-auth/v2",
                    &wire::authentication_body(
                        &version,
                        &nonce,
                        &identity.device.id(),
                        &server_caps,
                        &capabilities,
                    )
                    .unwrap(),
                )
                .unwrap();
            let declared = if tampered {
                vec!["substituted".to_owned()]
            } else {
                capabilities
            };
            let mut auth = encode(&Envelope::Authenticate {
                device: identity.device.clone(),
                signature,
                capabilities: declared,
            })
            .unwrap();
            auth.extend_from_slice(&[0xa2, 0x06, 0x01, 42]);
            ws.send(ClientMessage::Binary(auth.into())).await.unwrap();
            let reply = tokio::time::timeout(Duration::from_secs(2), ws.next())
                .await
                .unwrap();
            if tampered {
                assert!(!matches!(reply, Some(Ok(ClientMessage::Binary(_)))));
            } else {
                let Some(Ok(ClientMessage::Binary(raw))) = reply else {
                    panic!()
                };
                let Envelope::Authenticated { capabilities } = decode(&raw).unwrap() else {
                    panic!()
                };
                assert!(capabilities.is_empty());
                let mut request = encode(&Envelope::Request {
                    id: "policy".into(),
                    command: Control::Policy,
                })
                .unwrap();
                request.extend_from_slice(&[0xa2, 0x06, 0x01, 42]);
                ws.send(ClientMessage::Binary(request.into()))
                    .await
                    .unwrap();
                // The server can emit a WebSocket heartbeat immediately after auth.
                let reply = tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        match ws.next().await.unwrap().unwrap() {
                            ClientMessage::Ping(data) => {
                                ws.send(ClientMessage::Pong(data)).await.unwrap()
                            }
                            ClientMessage::Binary(raw) => break decode::<Envelope>(&raw).unwrap(),
                            _ => panic!(),
                        }
                    }
                })
                .await
                .unwrap();
                assert!(matches!(
                    reply,
                    Envelope::Response {
                        result: Ok(Reply::Policy {
                            allow_client_channel_creation: false
                        }),
                        ..
                    }
                ));
                ws.close(None).await.unwrap();
            }
            server.abort();
            let _ = server.await;
        }
    }
}
