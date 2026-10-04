use crate::{
    endpoint::Endpoint,
    network::Connection,
    provider::{LocalContext, Provider, ProviderContext},
    storage::App,
};
use anyhow::{Result, bail};
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
}
pub struct PeerSession {
    hub: Arc<Hub>,
    connection: Arc<Connection>,
    channel: String,
    peer: String,
    id: String,
    rx: mpsc::Receiver<Packet>,
    pub stop: CancellationToken,
}
impl Drop for PeerSession {
    fn drop(&mut self) {
        self.hub.sessions.lock().unwrap().remove(&self.id);
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
        session: &PeerSession,
        input: &SessionInput,
        operation: Option<&str>,
        service: ServiceKind,
    ) -> Result<()> {
        require_operation(input, operation)?;
        if !self.provider.enabled(service) {
            bail!("service disabled");
        }
        if matches!(input, SessionInput::Command { .. })
            && let Some(id) = operation
        {
            let Reply::Operation(op) = session
                .connection
                .request(Control::OperationStatus { id: id.into() })
                .await?
            else {
                bail!("invalid operation status");
            };
            if op.state != OperationState::Pending {
                bail!("operation ended before execution");
            }
        }
        Ok(())
    }
    pub async fn peers(&self, channel: &str) -> Result<Vec<String>> {
        let state = self.refresh(channel).await?.verify()?;
        state.member(&self.app.identity.device.id())?;
        let Reply::Peers(mut peers) = self
            .connection()
            .request(Control::Peers {
                channel: channel.into(),
            })
            .await?
        else {
            bail!("invalid peer response");
        };
        peers.retain(|p| state.member(p).is_ok() && *p != self.app.identity.device.id());
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
                        local: Some(local),
                        channel: channel.into(),
                        peer: peer.into(),
                        session: random_id(),
                    },
                )
                .await?;
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
                .send_private(&mut transport, &PrivateMessage::Trust(proof))
                .await?;
            let PrivateMessage::Trust(proof) = session.receive_private(&mut transport).await?
            else {
                bail!("trust proof required");
            };
            if proof.genesis.body.id != channel {
                bail!("trust channel mismatch");
            }
            let proof = self.app.merge(proof)?;
            self.authorized(channel, peer)?;
            session
                .send_private(&mut transport, &PrivateMessage::Trust(proof))
                .await?;
            session
                .send_private(&mut transport, &PrivateMessage::Discover)
                .await?;
            let PrivateMessage::Capabilities { scdaemon, pinentry } =
                session.receive_private(&mut transport).await?
            else {
                bail!("missing capabilities");
            };
            if !match service {
                ServiceKind::Scdaemon => scdaemon,
                ServiceKind::Pinentry => pinentry,
            } {
                session
                    .send_private(&mut transport, &PrivateMessage::Close)
                    .await?;
                return Ok(None);
            }
            session
                .send_private(&mut transport, &PrivateMessage::Open { service })
                .await?;
            if !matches!(
                session.receive_private(&mut transport).await?,
                PrivateMessage::Opened
            ) {
                bail!("service unavailable or busy");
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
                                if matches!(input, SessionInput::Command { .. }) {
                                    let operation = binding.lock().unwrap().clone();
                                    if let Some(id) = operation {
                                        hub.bind_session(&session.id, Some(id.clone()));
                                        session.send_private(&mut transport, &PrivateMessage::BeginOperation { id }).await?;
                                        if !matches!(session.receive_private(&mut transport).await?, PrivateMessage::OperationBegun) { bail!("operation claim rejected"); }
                                    }
                                }
                                session.send_private(&mut transport,&PrivateMessage::Input(input)).await?;
                            },
                            None=>break,
                        },
                        output=session.receive_private(&mut transport)=>match output? {
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
            let proof = self.refresh(&session.channel).await?;
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
            let PrivateMessage::Trust(proof) = session.receive_private(&mut transport).await?
            else {
                bail!("trust proof required");
            };
            if proof.genesis.body.id != session.channel {
                bail!("trust channel mismatch");
            }
            let proof = self.app.merge(proof)?;
            self.authorized(&session.channel, &session.peer)?;
            session
                .send_private(&mut transport, &PrivateMessage::Trust(proof))
                .await?;
            let PrivateMessage::Trust(proof) = session.receive_private(&mut transport).await?
            else {
                bail!("trust acknowledgement required");
            };
            if proof.genesis.body.id != session.channel {
                bail!("trust channel mismatch");
            }
            self.app.merge(proof)?;
            self.authorized(&session.channel, &session.peer)?;
            if !matches!(
                session.receive_private(&mut transport).await?,
                PrivateMessage::Discover
            ) {
                bail!("service discovery required");
            }
            session
                .send_private(
                    &mut transport,
                    &PrivateMessage::Capabilities {
                        scdaemon: self.provider.enabled(ServiceKind::Scdaemon),
                        pinentry: self.provider.enabled(ServiceKind::Pinentry),
                    },
                )
                .await?;
            let PrivateMessage::Open { service } = session.receive_private(&mut transport).await?
            else {
                bail!("service open required");
            };
            Ok::<_, anyhow::Error>((transport, service))
        };
        let (mut transport, service) =
            tokio::time::timeout(Duration::from_secs(25), setup).await??;
        if !self.provider.enabled(service) {
            session
                .send_private(&mut transport, &PrivateMessage::Failure)
                .await?;
            return Ok(());
        }
        session
            .send_private(&mut transport, &PrivateMessage::Opened)
            .await?;
        // Do not acquire a card or launch a UI for abandoned Open handshakes.
        let mut first = tokio::time::timeout(
            Duration::from_secs(20),
            session.receive_private(&mut transport),
        )
        .await??;
        let mut operation = None;
        if let PrivateMessage::BeginOperation { id } = first {
            self.claim(&session, &id, service).await?;
            operation = Some(id);
            session
                .send_private(&mut transport, &PrivateMessage::OperationBegun)
                .await?;
            first = session.receive_private(&mut transport).await?;
        }
        let PrivateMessage::Input(first @ SessionInput::Command { request: 1, .. }) = first else {
            session
                .send_private(&mut transport, &PrivateMessage::Closed)
                .await?;
            return Ok(());
        };
        self.authorized(&session.channel, &session.peer)?;
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
        let result=async {
            self.check_command(&session, &first, operation.as_deref(), service).await?;
            endpoint.tx.send(first).await?;
            let session_stop=session.stop.clone();
            let mut tick = tokio::time::interval(Duration::from_millis(500));
            loop {
                tokio::select! {
                    _=session_stop.cancelled()=>bail!("operation canceled"),
                    _=tick.tick(), if operation.is_some()=>{
                        if !self.provider.enabled(service) { bail!("service disabled"); }
                        let Reply::Operation(op)=session.connection.request(Control::OperationStatus { id: operation.clone().unwrap() }).await? else { bail!("invalid operation status"); };
                        if op.state != OperationState::Pending { bail!("operation ended"); }
                    },
                    message=session.receive_private(&mut transport)=>match message? {
                        PrivateMessage::BeginOperation { id }=>{
                            if operation.is_some() { bail!("operation already active"); }
                            self.claim(&session, &id, service).await?;
                            operation=Some(id);
                            session.send_private(&mut transport, &PrivateMessage::OperationBegun).await?;
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
                                    session.connection.request(Control::TargetDone { id, success: matches!(response, hibiki_lib::assuan::Response::Ok) }).await?;
                                    self.bind_session(&session.id, None);
                                }
                            }
                            session.send_private(&mut transport,&PrivateMessage::Output(output)).await?;
                        },
                        None=>bail!("native service ended"),
                    }
                }
            }
        }.await;
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
    if let SessionInput::Command { line, .. } = input {
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
