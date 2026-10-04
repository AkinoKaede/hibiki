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
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

enum Packet {
    Data(Vec<u8>),
}
struct Entry {
    channel: String,
    peer: String,
    tx: mpsc::Sender<Packet>,
    stop: CancellationToken,
}
pub struct Hub {
    pub app: Arc<App>,
    pub connection: Arc<Connection>,
    card_slot: Arc<tokio::sync::Semaphore>,
    provider: Arc<dyn Provider>,
    sessions: Mutex<HashMap<String, Entry>>,
}
pub struct PeerSession {
    hub: Arc<Hub>,
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
        self.hub
            .connection
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
            _ = self.hub.connection.closed.cancelled() => bail!("server disconnected"),
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
    pub fn new(
        app: Arc<App>,
        connection: Arc<Connection>,
        provider: Arc<dyn Provider>,
        card_slot: Arc<tokio::sync::Semaphore>,
    ) -> Arc<Self> {
        Arc::new(Self {
            app,
            connection,
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
        let stop = self.connection.closed.child_token();
        sessions.insert(
            id.clone(),
            Entry {
                channel: channel.clone(),
                peer: peer.clone(),
                tx,
                stop: stop.clone(),
            },
        );
        Ok(PeerSession {
            hub: self.clone(),
            channel,
            peer,
            id,
            rx,
            stop,
        })
    }
    pub async fn refresh(&self, channel: &str) -> Result<MembershipProof> {
        let Reply::Proof(proof) = self
            .connection
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
    pub async fn peers(&self, channel: &str) -> Result<Vec<String>> {
        let state = self.refresh(channel).await?.verify()?;
        state.member(&self.app.identity.device.id())?;
        let Reply::Peers(mut peers) = self
            .connection
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
            return self
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
                .await
                .map(Some);
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
        tokio::spawn(async move {
            let run = async {
                loop {
                    tokio::select! {
                        input=inputs.recv()=>match input {
                            Some(input)=>session.send_private(&mut transport,&PrivateMessage::Input(input)).await?,
                            None=>break,
                        },
                        output=session.receive_private(&mut transport)=>match output? {
                            PrivateMessage::Output(output)=>{
                                hub.authorized(&session.channel,&session.peer)?;
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
        Ok(Some(Endpoint::new(tx, rx, cancel, done)))
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
        let first = tokio::time::timeout(
            Duration::from_secs(20),
            session.receive_private(&mut transport),
        )
        .await??;
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
            endpoint.tx.send(first).await?;
            loop {
                tokio::select! {
                    message=session.receive_private(&mut transport)=>match message? {
                        PrivateMessage::Input(input)=>{self.authorized(&session.channel,&session.peer)?; endpoint.tx.send(input).await?;},
                        PrivateMessage::Close=>return Ok::<_,anyhow::Error>(()),
                        _=>bail!("unexpected service input"),
                    },
                    output=endpoint.rx.recv()=>match output {
                        Some(output)=>{self.authorized(&session.channel,&session.peer)?;session.send_private(&mut transport,&PrivateMessage::Output(output)).await?;},
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
    hub.connection
        .request(Control::Announce { channels })
        .await?;
    Ok(())
}
