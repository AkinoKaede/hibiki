use crate::{
    endpoint::Endpoint,
    network::Connection,
    provider::{LocalContext, Provider, ProviderContext},
    storage::App,
};
use anyhow::{Context, Result, bail};
use hibiki_lib::{
    channel::MembershipProof,
    decode,
    e2ee::{Handshake, Transport},
    encode_secret,
    protocol::*,
    random_id,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

enum Packet {
    Data(Vec<u8>),
}
struct Entry {
    operation: Option<String>,
    channel: String,
    peer: String,
    tx: mpsc::Sender<Packet>,
    stop: CancellationToken,
}
pub struct Hub {
    pub app: Arc<App>,
    connection: RwLock<Arc<Connection>>,
    pub changed: tokio::sync::Notify,
    card_slot: Arc<tokio::sync::Semaphore>,
    provider: Arc<dyn Provider>,
    sessions: Mutex<HashMap<String, Entry>>,
    sessions_changed: tokio::sync::Notify,
}
pub struct PeerSession {
    hub: Arc<Hub>,
    connection: Arc<Connection>,
    channel: String,
    peer: String,
    id: String,
    rx: mpsc::Receiver<Packet>,
    pub stop: CancellationToken,
    sent_messages: std::sync::atomic::AtomicU64,
    opened_at: std::time::Instant,
}
impl Drop for PeerSession {
    fn drop(&mut self) {
        tracing::debug!(
            messages = self
                .sent_messages
                .load(std::sync::atomic::Ordering::Relaxed),
            elapsed_ms = self.opened_at.elapsed().as_millis(),
            "session closed"
        );
        self.hub.sessions.lock().unwrap().remove(&self.id);
        self.hub.sessions_changed.notify_waiters();
        // A canceled handshake may have already opened a remote child. An empty
        // authenticated relay frame closes only this exact peer/channel/session.
        if self.peer != self.hub.app.identity.device.id() && !self.connection.closed.is_cancelled()
        {
            let connection = self.connection.clone();
            let message = Envelope::Relay {
                channel: self.channel.clone(),
                peer: self.peer.clone(),
                session: self.id.clone(),
                data: Vec::new(),
            };
            tokio::spawn(async move {
                let _ = connection.send(message).await;
            });
        }
    }
}
impl PeerSession {
    async fn send(&self, data: Vec<u8>) -> Result<()> {
        self.connection
            .send(Envelope::Relay {
                channel: self.channel.clone(),
                peer: self.peer.clone(),
                session: self.id.clone(),
                data,
            })
            .await
    }
    async fn packet(&mut self) -> Result<Vec<u8>> {
        tokio::select! {
            _ = self.stop.cancelled() => bail!("session canceled"),
            _ = self.connection.closed.cancelled() => bail!("server disconnected"),
            packet = self.rx.recv() => match packet {
                Some(Packet::Data(b)) => Ok(b),
                None => bail!("session disconnected"),
            }
        }
    }
    async fn send_private(
        &self,
        transport: &mut Transport,
        message: &PrivateMessage,
    ) -> Result<()> {
        let kind = match message {
            PrivateMessage::Input(SessionInput::Command { .. }) => "query",
            PrivateMessage::Execute { .. } => "execute",
            PrivateMessage::Input(SessionInput::PrepareCard { .. }) => "prepare",
            PrivateMessage::Input(SessionInput::CancelPreparation { .. }) => "cancel_preparation",
            PrivateMessage::OutputBatch { .. } => "result",
            PrivateMessage::OpenService { .. } => "open",
            PrivateMessage::ServiceOpened { .. } => "opened",
            _ => "control",
        };
        let sequence = self
            .sent_messages
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        tracing::trace!(kind, sequence, "session message sent");
        let plain = encode_secret(message)?;
        for packet in transport.encrypt(&plain)? {
            self.send(packet).await?;
        }
        Ok(())
    }
    async fn receive_private(&mut self, transport: &mut Transport) -> Result<PrivateMessage> {
        loop {
            let packet = self.packet().await?;
            if let Some(plain) = transport.decrypt(&packet)? {
                let plain = zeroize::Zeroizing::new(plain);
                let message: PrivateMessage = decode(&plain)?;
                match &message {
                    PrivateMessage::Input(
                        SessionInput::Command { line, .. }
                        | SessionInput::InquiryReply { line, .. },
                    )
                    | PrivateMessage::Output(SessionOutput::Line { line, .. }) => {
                        hibiki_lib::assuan::framing(line)?
                    }
                    _ => {}
                }
                return Ok(message);
            }
        }
    }
}

impl Hub {
    pub fn connection(&self) -> Arc<Connection> {
        self.connection.read().unwrap().clone()
    }
    pub fn reconnect(&self, connection: Arc<Connection>) {
        *self.connection.write().unwrap() = connection;
        self.changed.notify_waiters();
    }

    pub fn new(
        app: Arc<App>,
        connection: Arc<Connection>,
        provider: Arc<dyn Provider>,
        card_slot: Arc<tokio::sync::Semaphore>,
    ) -> Arc<Self> {
        Arc::new(Self {
            app,
            connection: RwLock::new(connection),
            changed: tokio::sync::Notify::new(),
            provider,
            card_slot,
            sessions: Mutex::new(HashMap::new()),
            sessions_changed: tokio::sync::Notify::new(),
        })
    }

    fn register(
        self: &Arc<Self>,
        channel: String,
        peer: String,
        id: String,
    ) -> Result<PeerSession> {
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.len() >= 128 || sessions.contains_key(&id) {
            bail!("session capacity or duplicate ID");
        }
        let (tx, rx) = mpsc::channel(64);
        let connection = self.connection();
        let stop = if peer == self.app.identity.device.id() {
            CancellationToken::new()
        } else {
            connection.closed.child_token()
        };
        sessions.insert(
            id.clone(),
            Entry {
                operation: None,
                channel: channel.clone(),
                peer: peer.clone(),
                tx,
                stop: stop.clone(),
            },
        );
        Ok(PeerSession {
            hub: self.clone(),
            connection,
            channel,
            peer,
            id,
            rx,
            stop,
            sent_messages: std::sync::atomic::AtomicU64::new(0),
            opened_at: std::time::Instant::now(),
        })
    }
    pub async fn refresh(&self, channel: &str) -> Result<MembershipProof> {
        let Reply::Proof(proof) = self
            .connection()
            .request(Control::GetChannel {
                channel: channel.into(),
            })
            .await?
        else {
            bail!("invalid channel response");
        };
        if proof.genesis.body.id != channel {
            bail!("channel response identity mismatch");
        }
        let proof = self.app.merge(proof)?;
        let state = proof.verify()?;
        let sessions = self.sessions.lock().unwrap();
        for entry in sessions.values() {
            if entry.channel == channel
                && (state.member(&entry.peer).is_err()
                    || state.member(&self.app.identity.device.id()).is_err())
            {
                entry.stop.cancel();
            }
        }
        Ok(proof)
    }
    pub fn stop_channel(&self, channel: &str) {
        for entry in self.sessions.lock().unwrap().values() {
            if entry.channel == channel {
                entry.stop.cancel();
            }
        }
    }
    pub fn stop_all(&self) {
        for entry in self.sessions.lock().unwrap().values() {
            entry.stop.cancel();
        }
    }
    /// Call after the caller has stopped routing new sessions to this hub.
    /// Draining sessions prevents their trust/replay writes from racing a local reset.
    pub async fn shutdown(&self) {
        self.connection().close();
        self.stop_all();
        loop {
            let changed = self.sessions_changed.notified();
            if self.sessions.lock().unwrap().is_empty() {
                return;
            }
            changed.await;
        }
    }
    pub fn stop_session(&self, id: &str, peer: &str) {
        if let Some(entry) = self.sessions.lock().unwrap().get(id)
            && entry.peer == peer
        {
            entry.stop.cancel();
        }
    }
    pub fn stop_peer(&self, peer: &str) {
        for entry in self.sessions.lock().unwrap().values() {
            if entry.peer == peer {
                entry.stop.cancel();
            }
        }
    }
    pub fn stop_operation(&self, id: &str) {
        for entry in self.sessions.lock().unwrap().values() {
            if entry.operation.as_deref() == Some(id) {
                entry.stop.cancel();
            }
        }
        self.changed.notify_waiters();
    }
    fn bind_session(&self, session: &str, id: Option<String>) {
        if let Some(entry) = self.sessions.lock().unwrap().get_mut(session) {
            entry.operation = id;
        }
    }
    async fn claim(&self, session: &PeerSession, id: &str, service: ServiceKind) -> Result<()> {
        let Reply::Operation(op) = session
            .connection
            .request(Control::ClaimOperation {
                id: id.into(),
                initiator: session.peer.clone(),
                channel: session.channel.clone(),
                service,
            })
            .await?
        else {
            bail!("invalid operation claim");
        };
        if op.id != id
            || op.initiator != session.peer
            || op.channel != session.channel
            || op.service != service
            || op.state != OperationState::Pending
            || !op.targets.iter().any(|t| {
                t.device == self.app.identity.device.id() && t.state == TargetState::Executing
            })
        {
            bail!("operation claim identity mismatch");
        }
        crate::operation::record_execution(&self.app, &op)?;
        self.bind_session(&session.id, Some(id.into()));
        Ok(())
    }
    async fn check_command(
        &self,
        _session: &PeerSession,
        input: &SessionInput,
        operation: Option<&str>,
        service: ServiceKind,
    ) -> Result<()> {
        require_operation(input, operation)?;
        if !self.provider.enabled(service) {
            bail!("service disabled");
        }
        Ok(())
    }
    pub async fn peers(&self, channel: &str) -> Result<Vec<String>> {
        let Reply::ChannelSnapshot {
            proof,
            online: mut peers,
            revoked,
        } = self
            .connection()
            .request(Control::ChannelSnapshot {
                channel: channel.into(),
            })
            .await?
        else {
            bail!("invalid channel snapshot");
        };
        if proof.genesis.body.id != channel {
            bail!("snapshot channel mismatch");
        }
        let state = self.app.merge(proof)?.verify()?;
        state.member(&self.app.identity.device.id())?;
        peers.retain(|p| {
            state.member(p).is_ok() && !revoked.contains(p) && *p != self.app.identity.device.id()
        });
        Ok(peers)
    }

    pub fn track_local(self: &Arc<Self>, channel: &str) -> Result<PeerSession> {
        self.register(channel.into(), self.app.identity.device.id(), random_id())
    }
    pub fn authorized(&self, channel: &str, peer: &str) -> Result<()> {
        let state = self.app.proof(channel)?.verify()?;
        state.member(&self.app.identity.device.id())?;
        state.member(peer)?;
        Ok(())
    }
    pub async fn candidates(&self, channel: &str, service: ServiceKind) -> Vec<String> {
        let mut peers = self.peers(channel).await.unwrap_or_default();
        if self.provider.enabled(service)
            && self
                .authorized(channel, &self.app.identity.device.id())
                .is_ok()
        {
            peers.push(self.app.identity.device.id());
        }
        peers
    }
    pub fn eligible(&self, channel: &str, service: ServiceKind) -> Result<Vec<String>> {
        let state = self.app.proof(channel)?.verify()?;
        state.member(&self.app.identity.device.id())?;
        let mut peers: Vec<_> = state
            .members()
            .keys()
            .filter(|p| **p != self.app.identity.device.id() || self.provider.enabled(service))
            .cloned()
            .collect();
        peers.sort();
        Ok(peers)
    }
    /// Diagnostic session: no card lease, provider process, or password prompt.
    pub async fn ping(
        self: &Arc<Self>,
        channel: &str,
        peer: &str,
        count: u16,
    ) -> Result<PingReport> {
        if !(1..=20).contains(&count) {
            bail!("ping count must be 1..20");
        }
        let start = std::time::Instant::now();
        self.refresh(channel).await?;
        let state = self.app.proof(channel)?.verify()?;
        let full_id =
            hibiki_lib::selection::resolve_id(peer, state.members().keys().map(String::as_str))?;
        let peer = full_id.as_str();
        self.authorized(channel, peer)?;
        if peer == self.app.identity.device.id() {
            bail!("choose another device");
        }
        let mut session = self.register(channel.into(), peer.into(), random_id())?;
        let mut transport = tokio::time::timeout(Duration::from_secs(15), async {
            let proof = self.app.proof(channel)?;
            let expected = proof.verify()?.member(peer)?.noise_key;
            let mut hs = Handshake::new(
                &self.app.identity,
                channel,
                &self.app.identity.device.id(),
                peer,
                &session.id,
                expected,
                true,
            )?;
            session.send(hs.write()?).await?;
            hs.read(&session.packet().await?)?;
            session.send(hs.write()?).await?;
            let mut transport = hs.finish()?;
            session
                .send_private(&mut transport, &PrivateMessage::PingOpen { proof })
                .await?;
            let PrivateMessage::PingOpened { proof } =
                session.receive_private(&mut transport).await?
            else {
                bail!("ping handshake failed");
            };
            if proof.genesis.body.id != channel {
                bail!("ping channel mismatch");
            }
            self.app.merge(proof)?;
            self.authorized(channel, peer)?;
            Ok::<_, anyhow::Error>(transport)
        })
        .await
        .context("ping connection timed out")??;
        let mut report = PingReport {
            peer: peer.into(),
            setup_micros: start.elapsed().as_micros() as u64,
            round_trips_micros: Vec::new(),
        };
        for _ in 0..count {
            let nonce = random_id();
            let start = std::time::Instant::now();
            session
                .send_private(
                    &mut transport,
                    &PrivateMessage::Ping {
                        nonce: nonce.clone(),
                    },
                )
                .await?;
            let pong = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    match session.receive_private(&mut transport).await? {
                        PrivateMessage::Pong { nonce: received } if received == nonce => {
                            return Ok::<_, anyhow::Error>(());
                        }
                        PrivateMessage::Pong { .. } => {}
                        _ => bail!("unexpected ping response"),
                    }
                }
            })
            .await;
            match pong {
                Ok(result) => {
                    result?;
                    report
                        .round_trips_micros
                        .push(Some(start.elapsed().as_micros() as u64));
                }
                Err(_) => report.round_trips_micros.push(None),
            }
        }
        session
            .send_private(&mut transport, &PrivateMessage::Close)
            .await?;
        Ok(report)
    }
    pub async fn open(
        self: &Arc<Self>,
        channel: &str,
        peer: &str,
        service: ServiceKind,
        cancel: CancellationToken,
        local: LocalContext,
    ) -> Result<Option<Endpoint>> {
        self.authorized(channel, peer)?;
        if peer == self.app.identity.device.id() {
            let mut endpoint = self
                .provider
                .open(
                    self.app.clone(),
                    service,
                    self.card_slot.clone(),
                    cancel,
                    ProviderContext {
                        local: Some(local.clone()),
                        channel: channel.into(),
                        peer: peer.into(),
                        session: random_id(),
                    },
                )
                .await?;
            if service == ServiceKind::Scdaemon {
                endpoint = crate::preparation::wrap(
                    endpoint,
                    self.provider.clone(),
                    self.app.clone(),
                    ProviderContext {
                        local: Some(local),
                        channel: channel.into(),
                        peer: peer.into(),
                        session: random_id(),
                    },
                );
            }
            endpoint.peer = peer.into();
            return Ok(Some(endpoint));
        }
        let mut session = self.register(channel.into(), peer.into(), random_id())?;
        let setup = async {
            let proof = self.app.proof(channel)?;
            let expected = proof.verify()?.member(peer)?.noise_key;
            let mut hs = Handshake::new(
                &self.app.identity,
                channel,
                &self.app.identity.device.id(),
                peer,
                &session.id,
                expected,
                true,
            )?;
            session.send(hs.write()?).await?;
            hs.read(&session.packet().await?)?;
            session.send(hs.write()?).await?;
            let mut transport = hs.finish()?;
            session
                .send_private(
                    &mut transport,
                    &PrivateMessage::OpenService { proof, service },
                )
                .await?;
            let PrivateMessage::ServiceOpened { proof, enabled } =
                session.receive_private(&mut transport).await?
            else {
                bail!("service open response required");
            };
            if proof.genesis.body.id != channel {
                bail!("trust channel mismatch");
            }
            self.app.merge(proof)?;
            self.authorized(channel, peer)?;
            if !enabled {
                return Ok(None);
            }
            Ok::<_, anyhow::Error>(Some(transport))
        };
        let Some(mut transport) = (tokio::select! {
            _=cancel.cancelled()=>bail!("request canceled"),
            result=tokio::time::timeout(Duration::from_secs(20),setup)=>result??,
        }) else {
            return Ok(None);
        };
        let (tx, mut inputs) = mpsc::channel::<SessionInput>(16);
        let (outputs, rx) = mpsc::channel(32);
        let done = CancellationToken::new();
        let finished = done.clone();
        let stop = cancel.clone();
        let hub = self.clone();
        let mut endpoint = Endpoint::new(tx, rx, cancel, done);
        endpoint.peer = peer.into();
        let binding = endpoint.operation.clone();
        tokio::spawn(async move {
            let run = async {
                loop {
                    tokio::select! {
                        input=inputs.recv()=>match input {
                            Some(input)=>{
                                let operation = if matches!(input, SessionInput::Command { .. } | SessionInput::Execute { .. }) { binding.lock().unwrap().clone() } else { None };
                                if let Some(id) = operation {
                                    hub.bind_session(&session.id, Some(id.clone()));
                                    session.send_private(&mut transport, &PrivateMessage::Execute { id, input }).await?;
                                } else {
                                    session.send_private(&mut transport,&PrivateMessage::Input(input)).await?;
                                }
                            },
                            None=>break,
                        },
                        output=session.receive_private(&mut transport)=>match output? {
                            PrivateMessage::OutputBatch { request, lines } => {
                                hub.authorized(&session.channel,&session.peer)?;
                                if lines.len() > hibiki_lib::assuan::MAX_LINES || lines.iter().map(|l|l.len()).sum::<usize>() > hibiki_lib::assuan::MAX_DATA { bail!("response limit"); }
                                for line in lines {
                                    hibiki_lib::assuan::framing(&line)?;
                                    if matches!(hibiki_lib::assuan::parse_response(&line)?, hibiki_lib::assuan::Response::Ok | hibiki_lib::assuan::Response::Err(_)) { hub.bind_session(&session.id, None); }
                                    outputs.send(SessionOutput::Line { request, line }).await?;
                                }
                            },
                            PrivateMessage::Output(output)=>{
                                hub.authorized(&session.channel,&session.peer)?;
                                if let SessionOutput::Line { line, .. } = &output
                                    && matches!(hibiki_lib::assuan::parse_response(line)?, hibiki_lib::assuan::Response::Ok | hibiki_lib::assuan::Response::Err(_)) {
                                    hub.bind_session(&session.id, None);
                                }
                                outputs.send(output).await?;
                            },
                            _=>bail!("unexpected service frame"),
                        }
                    }
                }
                Ok::<_, anyhow::Error>(())
            };
            tokio::select! { _=stop.cancelled()=>{}, result=run=>{if result.is_err(){ let _=outputs.try_send(SessionOutput::Failure); }} }
            let _ = tokio::time::timeout(Duration::from_secs(2), async {
                session
                    .send_private(&mut transport, &PrivateMessage::Close)
                    .await?;
                loop {
                    if matches!(
                        session.receive_private(&mut transport).await?,
                        PrivateMessage::Closed
                    ) {
                        break;
                    }
                }
                Ok::<_, anyhow::Error>(())
            })
            .await;
            finished.cancel();
        });
        Ok(Some(endpoint))
    }
    async fn incoming(self: Arc<Self>, mut session: PeerSession) -> Result<()> {
        let setup = async {
            let proof = self.app.proof(&session.channel)?;
            self.authorized(&session.channel, &session.peer)?;
            let expected = proof.verify()?.member(&session.peer)?.noise_key;
            let mut hs = Handshake::new(
                &self.app.identity,
                &session.channel,
                &session.peer,
                &self.app.identity.device.id(),
                &session.id,
                expected,
                false,
            )?;
            hs.read(&session.packet().await?)?;
            session.send(hs.write()?).await?;
            hs.read(&session.packet().await?)?;
            let mut transport = hs.finish()?;
            let (proof, service) = match session.receive_private(&mut transport).await? {
                PrivateMessage::OpenService { proof, service } => (proof, Some(service)),
                PrivateMessage::PingOpen { proof } => (proof, None),
                _ => bail!("service or ping open required"),
            };
            if proof.genesis.body.id != session.channel {
                bail!("trust channel mismatch");
            }
            self.app.merge(proof)?;
            self.authorized(&session.channel, &session.peer)?;
            Ok::<_, anyhow::Error>((transport, service))
        };
        let (mut transport, service) =
            tokio::time::timeout(Duration::from_secs(25), setup).await??;
        let Some(service) = service else {
            session
                .send_private(
                    &mut transport,
                    &PrivateMessage::PingOpened {
                        proof: self.app.proof(&session.channel)?,
                    },
                )
                .await?;
            for _ in 0..21 {
                self.authorized(&session.channel, &session.peer)?;
                match tokio::time::timeout(
                    Duration::from_secs(10),
                    session.receive_private(&mut transport),
                )
                .await??
                {
                    PrivateMessage::Ping { nonce } if hibiki_lib::channel::valid_id(&nonce) => {
                        session
                            .send_private(&mut transport, &PrivateMessage::Pong { nonce })
                            .await?
                    }
                    PrivateMessage::Close => return Ok(()),
                    _ => bail!("invalid ping request"),
                }
            }
            return Ok(());
        };
        let enabled = self.provider.enabled(service);
        if !enabled {
            session
                .send_private(
                    &mut transport,
                    &PrivateMessage::ServiceOpened {
                        proof: self.app.proof(&session.channel)?,
                        enabled: false,
                    },
                )
                .await?;
            return Ok(());
        }
        let mut operation = None;
        let endpoint = self
            .provider
            .open(
                self.app.clone(),
                service,
                self.card_slot.clone(),
                session.stop.child_token(),
                ProviderContext {
                    local: None,
                    channel: session.channel.clone(),
                    peer: session.peer.clone(),
                    session: session.id.clone(),
                },
            )
            .await;
        let mut endpoint = match endpoint {
            Ok(e) => e,
            Err(_) => {
                session
                    .send_private(&mut transport, &PrivateMessage::Failure)
                    .await?;
                return Ok(());
            }
        };
        if service == ServiceKind::Scdaemon {
            endpoint = crate::preparation::wrap(
                endpoint,
                self.provider.clone(),
                self.app.clone(),
                ProviderContext {
                    local: None,
                    channel: session.channel.clone(),
                    peer: session.peer.clone(),
                    session: session.id.clone(),
                },
            );
        }
        session
            .send_private(
                &mut transport,
                &PrivateMessage::ServiceOpened {
                    proof: self.app.proof(&session.channel)?,
                    enabled: true,
                },
            )
            .await?;
        let (monitor_tx, mut monitor_rx) = tokio::sync::watch::channel::<Option<String>>(None);
        let monitor_stop = session.stop.child_token();
        let monitor_token = monitor_stop.clone();
        let connection = session.connection.clone();
        let session_cancel = session.stop.clone();
        let monitor = tokio::spawn(async move {
            loop {
                tokio::select! { _=monitor_token.cancelled()=>break, _=tokio::time::sleep(Duration::from_millis(500))=>{} }
                let id = monitor_rx.borrow_and_update().clone();
                if let Some(id) = id {
                    let result = tokio::select! {
                        _=monitor_token.cancelled()=>break,
                        _=monitor_rx.changed()=>continue,
                        result=connection.request(Control::OperationStatus { id: id.clone() })=>result,
                    };
                    if monitor_rx.borrow().as_ref() == Some(&id)
                        && !matches!(
                            result,
                            Ok(Reply::Operation(Operation {
                                state: OperationState::Pending,
                                ..
                            }))
                        )
                    {
                        session_cancel.cancel();
                        break;
                    }
                }
            }
        });
        let result=async {
            let mut collected = Vec::new();
            let session_stop=session.stop.clone();
            loop {
                tokio::select! {
                    _=session_stop.cancelled()=>bail!("operation canceled"),
                    message=session.receive_private(&mut transport)=>match message? {
                        PrivateMessage::Execute { id, input }=>{
                            if operation.is_some() || !matches!(input, SessionInput::Command { .. } | SessionInput::Execute { .. }) { bail!("invalid execution request"); }
                            self.authorized(&session.channel,&session.peer)?;
                            self.claim(&session, &id, service).await?;
                            operation=Some(id.clone());
                            monitor_tx.send_replace(Some(id));
                            self.check_command(&session, &input, operation.as_deref(), service).await?;
                            endpoint.tx.send(input).await?;
                        },
                        PrivateMessage::Input(input)=>{self.authorized(&session.channel,&session.peer)?; self.check_command(&session,&input,operation.as_deref(),service).await?; endpoint.tx.send(input).await?;},
                        PrivateMessage::Close=>return Ok::<_,anyhow::Error>(()),
                        _=>bail!("unexpected service input"),
                    },
                    output=endpoint.rx.recv()=>match output {
                        Some(output)=>{
                            self.authorized(&session.channel,&session.peer)?;
                            if let SessionOutput::Line { line, .. } = &output {
                                let response=hibiki_lib::assuan::parse_response(line)?;
                                if matches!(response, hibiki_lib::assuan::Response::Ok | hibiki_lib::assuan::Response::Err(_))
                                    && let Some(id)=operation.take() {
                                    monitor_tx.send_replace(None);
                                    session.connection.request(Control::TargetDone { id, success: matches!(response, hibiki_lib::assuan::Response::Ok) }).await?;
                                    self.bind_session(&session.id, None);
                                }
                            }
                            match output {
                                SessionOutput::Line { request, line } => {
                                    let response = hibiki_lib::assuan::parse_response(&line)?;
                                    let flush = matches!(response, hibiki_lib::assuan::Response::Ok | hibiki_lib::assuan::Response::Err(_) | hibiki_lib::assuan::Response::Inquire(_));
                                    collected.push(line);
                                    if collected.len() > hibiki_lib::assuan::MAX_LINES || collected.iter().map(|l|l.len()).sum::<usize>() > hibiki_lib::assuan::MAX_DATA { bail!("response limit"); }
                                    if flush { session.send_private(&mut transport, &PrivateMessage::OutputBatch { request, lines: std::mem::take(&mut collected) }).await?; }
                                },
                                output => session.send_private(&mut transport,&PrivateMessage::Output(output)).await?,
                            }
                        },
                        None=>bail!("native service ended"),
                    }
                }
            }
        }.await;
        monitor_stop.cancel();
        monitor.abort();
        endpoint.close().await;
        let _ = session
            .send_private(&mut transport, &PrivateMessage::Closed)
            .await;
        result
    }
    pub async fn route(
        self: &Arc<Self>,
        channel: String,
        peer: String,
        id: String,
        data: Vec<u8>,
    ) -> Result<()> {
        {
            let sessions = self.sessions.lock().unwrap();
            if let Some(entry) = sessions.get(&id) {
                if entry.peer != peer || entry.channel != channel {
                    bail!("session routing identity mismatch");
                }
                if data.is_empty() {
                    entry.stop.cancel();
                    return Ok(());
                }
                if entry.tx.try_send(Packet::Data(data)).is_err() {
                    entry.stop.cancel();
                    bail!("session queue full");
                }
                return Ok(());
            }
        }
        if data.len() != 32 {
            return Ok(());
        }
        let session = self.register(channel, peer, id.clone())?;
        self.sessions
            .lock()
            .unwrap()
            .get(&id)
            .unwrap()
            .tx
            .try_send(Packet::Data(data))?;
        let hub = self.clone();
        tokio::spawn(async move {
            let _ = hub.incoming(session).await;
        });
        Ok(())
    }
}

fn require_operation(input: &SessionInput, operation: Option<&str>) -> Result<()> {
    if let SessionInput::Command { line, .. } | SessionInput::Execute { line, .. } = input {
        let (cmd, _) = hibiki_lib::assuan::command(line)?;
        if matches!(
            cmd,
            "GETPIN" | "CONFIRM" | "MESSAGE" | "PKSIGN" | "PKDECRYPT"
        ) && operation.is_none()
        {
            bail!("private operation requires a queue claim");
        }
    }
    Ok(())
}

pub async fn announce(hub: &Arc<Hub>) -> Result<()> {
    let mut channels = Vec::new();
    for proof in hub.app.proofs()? {
        let id = proof.genesis.body.id;
        match hub.refresh(&id).await {
            Ok(proof)
                if proof
                    .verify()?
                    .member(&hub.app.identity.device.id())
                    .is_ok() =>
            {
                channels.push(id)
            }
            _ => hub.stop_channel(&id),
        }
    }
    hub.connection()
        .request(Control::Announce { channels })
        .await?;
    Ok(())
}
