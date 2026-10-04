//! iOS bridge. Cryptographic wire messages never cross into Swift.
mod broker;
mod card;
mod card_backend;
mod curves;
mod keycodec;
mod pinentry;
mod provider;
mod registry;
mod types;
pub use types::*;

use anyhow::{Context, Result, bail};
use broker::Broker;
use hibiki_core::{
    management,
    network::{Connection, Event},
    session::{Hub, announce},
    storage::{App, Config, atomic_write, private_dir, read_private},
};
use hibiki_lib::{
    channel::*,
    decode, encode,
    identity::Identity,
    paths::AppPaths,
    protocol::{Control, Envelope, Reply},
};
use provider::MobileProvider;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex, atomic::Ordering},
    time::Duration,
};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

#[uniffi::export]
pub fn create_identity(name: String) -> MobileResult<Vec<u8>> {
    (|| Ok(encode(&Identity::generate(name)?)?))().map_err(|e: anyhow::Error| e.into())
}

/// Check the relay protocol and authentication before committing onboarding state.
#[uniffi::export(async_runtime = "tokio")]
pub async fn check_relay(
    server: String,
    identity: Vec<u8>,
    skip_tls_certificate_validation: bool,
) -> MobileResult<()> {
    let result: Result<()> = async {
        let identity = Zeroizing::new(identity);
        let identity: Identity = decode(&identity)?;
        identity.validate()?;
        let (connection, _) = tokio::time::timeout(
            Duration::from_secs(15),
            Connection::open_with_tls_options(
                &server,
                true,
                skip_tls_certificate_validation,
                &identity,
            ),
        )
        .await
        .context("relay connection timed out")??;
        connection.close();
        Ok(())
    }
    .await;
    result.map_err(Into::into)
}
fn device_info(device: &hibiki_lib::identity::Device, online: bool) -> Result<DeviceInfo> {
    Ok(DeviceInfo {
        id: device.id(),
        name: device.name.clone(),
        words: device.public_key_words()?,
        online,
    })
}
#[derive(uniffi::Object)]
pub struct MobileClient {
    app: Arc<App>,
    skip_tls_certificate_validation: bool,
    broker: Arc<Broker>,
    provider: Arc<MobileProvider>,
    slots: Arc<Semaphore>,
    registry: Mutex<registry::Registry>,
    hub: Mutex<Option<Arc<Hub>>>,
    lifecycle: tokio::sync::Mutex<()>,
    stop: Mutex<CancellationToken>,
    job: Mutex<Option<tokio::task::JoinHandle<()>>>,
}
impl MobileClient {
    fn connected(&self) -> Result<Arc<Hub>> {
        self.hub
            .lock()
            .unwrap()
            .clone()
            .filter(|h| !h.connection().closed.is_cancelled())
            .context("relay is offline")
    }
    fn selected_path(&self) -> PathBuf {
        self.app.paths.data.join("cards.bin")
    }
    fn save_registry(&self, registry: registry::Registry) -> Result<()> {
        atomic_write(&self.selected_path(), &encode(&registry)?)?;
        self.provider.usb_enabled.store(
            registry.active().is_some_and(|c| c.usb_enabled),
            Ordering::Release,
        );
        *self.provider.card.lock().unwrap() = registry.provider_card();
        *self.registry.lock().unwrap() = registry;
        Ok(())
    }
    fn channel_info(&self, proof: MembershipProof, online: &[String]) -> Result<ChannelInfo> {
        let state = proof.verify()?;
        Ok(ChannelInfo {
            id: state.id.clone(),
            name: state.name.clone(),
            revision: state.sequence,
            active: state.member(&self.app.identity.device.id()).is_ok(),
            members: state
                .members()
                .values()
                .map(|d| device_info(d, online.contains(&d.id())))
                .collect::<Result<_>>()?,
        })
    }
    async fn run(self: Arc<Self>, stop: CancellationToken) {
        let mut delay = 1;
        loop {
            if stop.is_cancelled() {
                break;
            }
            let _ = self.broker.emit(NativeEvent::Connection {
                state: "connecting".into(),
            });
            let opened = tokio::select! {_=stop.cancelled()=>break,result=Connection::open_with_tls_options(&self.app.config.server,true,self.skip_tls_certificate_validation,&self.app.identity)=>result};
            if let Ok((connection, mut events)) = opened {
                let hub = Hub::new(
                    self.app.clone(),
                    connection.clone(),
                    self.provider.clone(),
                    self.slots.clone(),
                );
                let announced = tokio::select! {
                    _=stop.cancelled()=>{connection.close();break;},
                    result=announce(&hub)=>result,
                };
                if announced.is_ok() {
                    *self.hub.lock().unwrap() = Some(hub.clone());
                    delay = 1;
                    let _ = self.broker.emit(NativeEvent::Connection {
                        state: "online".into(),
                    });
                    let mut refresh = tokio::time::interval(Duration::from_secs(10));
                    let mut jobs = tokio::task::JoinSet::new();
                    loop {
                        tokio::select! {
                            biased;
                            _=stop.cancelled()=>break,
                            _=connection.closed.cancelled()=>break,
                            _=refresh.tick()=>{let h=hub.clone();jobs.spawn(async move{let _=announce(&h).await;});},
                            Some(_)=jobs.join_next(),if !jobs.is_empty()=>{},
                            event=events.recv()=>match event {
                                Some(Event::Message(Envelope::OperationReady {..}))=>hub.changed.notify_waiters(),
                                Some(Event::Message(Envelope::Relay{channel,peer,session,data}))=>{let _=hub.route(channel,peer,session,data).await;},
                                Some(Event::Message(Envelope::RelayFailure{session,peer,..}))=>hub.stop_session(&session,&peer),
                                Some(Event::Message(Envelope::OperationChanged{id}))=>hub.stop_operation(&id),
                                Some(Event::Message(Envelope::PeerOffline{peer}))=>hub.stop_peer(&peer),
                                Some(Event::Message(Envelope::ChannelChanged{channel}))=>{let h=hub.clone();jobs.spawn(async move{if h.refresh(&channel).await.is_err(){h.stop_channel(&channel);}});},
                                Some(Event::Disconnected)|None=>break,
                                _=>{},
                            }
                        }
                    }
                    // Finish cancellation before stop() permits local trust data to be reset.
                    jobs.shutdown().await;
                }
                connection.close();
                self.hub.lock().unwrap().take();
                self.broker.cancel_all();
                hub.shutdown().await;
            }
            let _ = self.broker.emit(NativeEvent::Connection {
                state: "offline".into(),
            });
            tokio::select! {_=stop.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(delay))=>{}}
            delay = (delay * 2).min(30);
        }
        let _ = self.broker.emit(NativeEvent::Connection {
            state: "offline".into(),
        });
    }
}
#[uniffi::export(async_runtime = "tokio")]
impl MobileClient {
    #[uniffi::constructor]
    pub fn new(
        directory: String,
        server: String,
        identity: Vec<u8>,
        skip_tls_certificate_validation: bool,
    ) -> MobileResult<Arc<Self>> {
        (|| {
            hibiki_core::network::validate_url(&server, true)?;
            let identity = Zeroizing::new(identity);
            let identity: Identity = decode(&identity)?;
            identity.validate()?;
            let root = PathBuf::from(directory);
            if !root.is_absolute() {
                bail!("absolute storage directory required");
            }
            private_dir(&root)?;
            let paths = AppPaths {
                config: root.join("config"),
                data: root.join("data"),
                state: root.join("state"),
                cache: root.join("cache"),
                runtime: root.join("runtime"),
                runtime_base: None,
                config_dirs: vec![],
            };
            for path in [&paths.config, &paths.data, &paths.state, &paths.runtime] {
                private_dir(path)?;
            }
            let config = Config {
                server,
                allow_insecure: true,
                ..Config::default()
            };
            let app = Arc::new(App {
                config_file: paths.config.join("client.toml"),
                paths,
                config,
                identity: Arc::new(identity),
            });
            let path = app.paths.data.join("cards.bin");
            let registry = if path.exists() {
                decode::<registry::Registry>(&read_private(&path)?)?
            } else {
                registry::Registry::default()
            };
            let broker = Broker::new();
            let provider = MobileProvider::new(broker.clone(), registry.provider_card());
            provider.usb_enabled.store(
                registry.active().is_some_and(|c| c.usb_enabled),
                Ordering::Release,
            );
            Ok(Arc::new(Self {
                app,
                skip_tls_certificate_validation,
                broker,
                provider,
                slots: Arc::new(Semaphore::new(1)),
                registry: Mutex::new(registry),
                hub: Mutex::new(None),
                lifecycle: tokio::sync::Mutex::new(()),
                stop: Mutex::new(CancellationToken::new()),
                job: Mutex::new(None),
            }))
        })()
        .map_err(|e: anyhow::Error| e.into())
    }
    pub fn device(&self) -> MobileResult<DeviceInfo> {
        device_info(&self.app.identity.device, false).map_err(Into::into)
    }
    pub async fn start(self: Arc<Self>) -> MobileResult<()> {
        let _lock = self.lifecycle.lock().await;
        if self
            .job
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|job| !job.is_finished())
        {
            return Ok(());
        }
        let stop = CancellationToken::new();
        *self.stop.lock().unwrap() = stop.clone();
        let client = self.clone();
        *self.job.lock().unwrap() = Some(tokio::spawn(async move {
            client.run(stop).await;
        }));
        Ok(())
    }
    pub async fn stop(&self) {
        let _lock = self.lifecycle.lock().await;
        self.stop.lock().unwrap().cancel();
        if let Some(hub) = self.hub.lock().unwrap().take() {
            hub.connection().close();
        }
        self.broker.cancel_all();
        let job = self.job.lock().unwrap().take();
        if let Some(job) = job {
            let _ = job.await;
        }
    }
    pub async fn next_event(&self) -> Option<NativeEvent> {
        self.broker.next().await
    }
    pub fn request_is_pending(&self, token: String) -> bool {
        self.broker.pending(&token)
    }
    pub fn respond(&self, token: String, data: Vec<u8>, accepted: bool) -> MobileResult<()> {
        self.broker
            .respond(&token, data, accepted)
            .map_err(Into::into)
    }
    pub fn set_services(&self, pinentry: bool, card: bool) {
        let old_pin = self.provider.pin_enabled.swap(pinentry, Ordering::AcqRel);
        let old_card = self.provider.card_enabled.swap(card, Ordering::AcqRel);
        if ((old_pin && !pinentry) || (old_card && !card))
            && let Some(hub) = self.hub.lock().unwrap().as_ref()
        {
            hub.stop_all();
        }
    }
    pub fn usb_present(&self, present: bool) {
        let was_present = self.provider.usb_present.swap(present, Ordering::AcqRel);
        if was_present
            && !present
            && let Some(hub) = self.hub.lock().unwrap().as_ref()
        {
            hub.stop_all();
        }
    }
    pub fn selected_card(&self) -> Option<CardInfo> {
        self.provider.card.lock().unwrap().clone()
    }
    pub async fn register_card(
        &self,
        transport: CardTransport,
        name: String,
        usb_supported: bool,
        nfc_supported: bool,
    ) -> MobileResult<CardInfo> {
        let result = async {
            if !usb_supported && !nfc_supported {
                bail!("select at least one supported connection");
            }
            let _permit = self
                .slots
                .clone()
                .try_acquire_owned()
                .context("card is in use")?;
            let stop = self.stop.lock().unwrap().child_token();
            let broker = self.broker.clone();
            let _guard = provider::CancelOnDrop(stop.clone());
            let info = tokio::task::spawn_blocking(move || card::inspect(broker, stop, transport))
                .await??;
            let mut registry = self.registry.lock().unwrap().clone();
            registry.upsert(info.clone(), name, usb_supported, nfc_supported);
            self.save_registry(registry)?;
            let _ = self
                .broker
                .emit(NativeEvent::CardChanged { card: info.clone() });
            if let Ok(hub) = self.connected() {
                let _ = announce(&hub).await;
            }
            Ok(info)
        }
        .await;
        result.map_err(|e: anyhow::Error| e.into())
    }
    pub fn registered_cards(&self) -> Vec<RegisteredCard> {
        self.registry.lock().unwrap().cards.clone()
    }
    pub async fn select_card(&self, serial: String) -> MobileResult<()> {
        let _permit = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| MobileError::Failed {
                message: "card is in use".into(),
            })?;
        let mut registry = self.registry.lock().unwrap().clone();
        registry.select(&serial).map_err(MobileError::from)?;
        self.save_registry(registry).map_err(MobileError::from)?;
        if let Ok(hub) = self.connected() {
            let _ = announce(&hub).await;
        }
        Ok(())
    }
    pub async fn remove_card(&self, serial: String) -> MobileResult<()> {
        let _permit = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| MobileError::Failed {
                message: "card is in use".into(),
            })?;
        let mut registry = self.registry.lock().unwrap().clone();
        registry.remove(&serial);
        self.save_registry(registry).map_err(MobileError::from)?;
        if let Ok(hub) = self.connected() {
            let _ = announce(&hub).await;
        }
        Ok(())
    }
    pub async fn channels(&self) -> MobileResult<Vec<ChannelInfo>> {
        let result = async {
            let hub = self.connected().ok();
            let mut out = Vec::new();
            for proof in self.app.proofs()? {
                let id = proof.genesis.body.id.clone();
                let current = if let Some(h) = &hub {
                    h.refresh(&id).await.unwrap_or(proof)
                } else {
                    proof
                };
                let mut peers = if let Some(h) = &hub {
                    h.peers(&id).await.unwrap_or_default()
                } else {
                    vec![]
                };
                if hub.is_some() {
                    peers.push(self.app.identity.device.id());
                }
                out.push(self.channel_info(current, &peers)?);
            }
            Ok(out)
        }
        .await;
        result.map_err(|e: anyhow::Error| e.into())
    }
    pub async fn create_channel(&self, name: String) -> MobileResult<Invitation> {
        let result = async {
            let hub = self.connected()?;
            let psk = Zeroizing::new(make_psk());
            let verifier = hash_psk(&psk)?;
            let genesis = ChannelGenesis::create(&self.app.identity, name, &verifier)?;
            let expected = genesis.clone();
            let Reply::Proof(proof) = hub
                .connection()
                .request(Control::Create { genesis, verifier })
                .await?
            else {
                bail!("invalid creation response")
            };
            if proof.genesis != expected || !proof.events.is_empty() {
                bail!("server altered genesis");
            }
            let proof = self.app.bootstrap(proof, None)?;
            let state = proof.verify()?;
            let invite = Invite {
                version: 1,
                server: self.app.config.server.clone(),
                genesis: proof.genesis,
                checkpoint: state.checkpoint(),
            }
            .export()?;
            announce(&hub).await?;
            Ok(Invitation {
                channel: state.id,
                invite,
                psk: psk.to_string(),
            })
        }
        .await;
        result.map_err(|e: anyhow::Error| e.into())
    }
    pub async fn invitation(&self, channel: String) -> MobileResult<String> {
        let result = async {
            let hub = self.connected()?;
            let proof = hub.refresh(&channel).await?;
            let state = proof.verify()?;
            state.member(&self.app.identity.device.id())?;
            Ok(Invite {
                version: 1,
                server: self.app.config.server.clone(),
                genesis: proof.genesis,
                checkpoint: state.checkpoint(),
            }
            .export()?)
        }
        .await;
        result.map_err(|e: anyhow::Error| e.into())
    }
    pub async fn join(&self, invitation: String, psk: String) -> MobileResult<JoinInfo> {
        let result = async {
            let psk = Zeroizing::new(psk);
            let hub = self.connected()?;
            if invitation.starts_with("hibiki-init-v1:") {
                let invite = EmptyChannelInvite::import(&invitation)?;
                if invite.server != self.app.config.server {
                    bail!("invitation relay differs from configured relay");
                }
                let genesis = invite.founder_genesis(&self.app.identity)?;
                let existing = hub
                    .connection()
                    .request(Control::GetChannel {
                        channel: invite.id.clone(),
                    })
                    .await;
                let proof = if let Ok(Reply::Proof(proof)) = existing {
                    proof
                } else {
                    let Reply::Proof(proof) = hub
                        .connection()
                        .request(Control::Claim {
                            genesis: genesis.clone(),
                            psk: psk.to_string(),
                        })
                        .await?
                    else {
                        bail!("invalid claim response")
                    };
                    proof
                };
                if proof.genesis != genesis {
                    bail!("initialization invite already claimed or altered");
                }
                proof.verify()?.member(&self.app.identity.device.id())?;
                self.app.bootstrap(proof, None)?;
                announce(&hub).await?;
                return Ok(JoinInfo {
                    channel: invite.id,
                    request: String::new(),
                });
            }
            let invite = Invite::import(&invitation)?;
            if invite.server != self.app.config.server {
                bail!("invitation relay differs from configured relay");
            }
            let id = invite.genesis.body.id.clone();
            let Reply::Proof(proof) = hub
                .connection()
                .request(Control::GetChannel {
                    channel: id.clone(),
                })
                .await?
            else {
                bail!("invalid channel response")
            };
            let state = self.app.bootstrap(proof, Some(&invite))?.verify()?;
            let request = JoinRequest::create(&self.app.identity, &state)?;
            let result = JoinInfo {
                channel: id,
                request: request.id()?,
            };
            hub.connection()
                .request(Control::Join {
                    request,
                    psk: psk.to_string(),
                })
                .await?;
            Ok(result)
        }
        .await;
        result.map_err(|e: anyhow::Error| e.into())
    }
    pub async fn allows_channel_creation(&self) -> MobileResult<bool> {
        let result: Result<bool> = async {
            let Reply::Policy {
                allow_client_channel_creation,
            } = self
                .connected()?
                .connection()
                .request(Control::Policy)
                .await?
            else {
                bail!("invalid relay policy response");
            };
            Ok(allow_client_channel_creation)
        }
        .await;
        result.map_err(Into::into)
    }
    pub async fn reject_join(&self, channel: String, request_id: String) -> MobileResult<()> {
        let result: Result<()> = async {
            let hub = self.connected()?;
            hub.refresh(&channel)
                .await?
                .verify()?
                .member(&self.app.identity.device.id())?;
            let Reply::Ok = hub
                .connection()
                .request(Control::RejectJoin {
                    channel,
                    request: request_id,
                })
                .await?
            else {
                bail!("invalid rejection response");
            };
            Ok(())
        }
        .await;
        result.map_err(Into::into)
    }
    pub async fn withdraw_join(&self, channel: String, request_id: String) -> MobileResult<()> {
        let result: Result<()> = async {
            let Reply::Ok = self
                .connected()?
                .connection()
                .request(Control::WithdrawJoin {
                    channel,
                    request: request_id,
                })
                .await?
            else {
                bail!("invalid withdrawal response");
            };
            Ok(())
        }
        .await;
        result.map_err(Into::into)
    }
    pub async fn pairing_status(
        &self,
        channel: String,
        request_id: String,
    ) -> MobileResult<PairingState> {
        let result: Result<PairingState> = async {
            let hub = self.connected()?;
            let Reply::JoinStatus(state) = hub
                .connection()
                .request(Control::JoinStatus {
                    channel: channel.clone(),
                    request: request_id,
                })
                .await?
            else {
                bail!("invalid join status response");
            };
            Ok(match state {
                hibiki_lib::protocol::JoinState::Pending => PairingState::Pending,
                hibiki_lib::protocol::JoinState::Absent => PairingState::Absent,
                hibiki_lib::protocol::JoinState::Member => {
                    hub.refresh(&channel)
                        .await?
                        .verify()?
                        .member(&self.app.identity.device.id())?;
                    PairingState::Member
                }
            })
        }
        .await;
        result.map_err(Into::into)
    }
    pub async fn pending(&self, channel: String) -> MobileResult<Vec<PendingInfo>> {
        let result = async {
            let hub = self.connected()?;
            let state = hub.refresh(&channel).await?.verify()?;
            state.member(&self.app.identity.device.id())?;
            let Reply::Requests(requests) = hub
                .connection()
                .request(Control::Pending {
                    channel: channel.clone(),
                })
                .await?
            else {
                bail!("invalid pending response")
            };
            requests
                .into_iter()
                .map(|r| {
                    management::validate_pending(&r, &state)?;
                    Ok(PendingInfo {
                        id: r.id()?,
                        channel: channel.clone(),
                        device: device_info(&r.body.device, false)?,
                    })
                })
                .collect::<Result<Vec<_>>>()
        }
        .await;
        result.map_err(|e: anyhow::Error| e.into())
    }
    pub async fn approve(&self, channel: String, request_id: String) -> MobileResult<()> {
        let result = async {
            let hub = self.connected()?;
            let state = hub.refresh(&channel).await?.verify()?;
            state.member(&self.app.identity.device.id())?;
            let Reply::Requests(requests) = hub
                .connection()
                .request(Control::Pending {
                    channel: channel.clone(),
                })
                .await?
            else {
                bail!("invalid pending response")
            };
            let request = requests
                .into_iter()
                .find(|r| r.id().ok().as_ref() == Some(&request_id))
                .context("request not pending")?;
            management::validate_pending(&request, &state)?;
            management::append(
                &self.app,
                &hub.connection(),
                &channel,
                MembershipAction::Admit(request),
                None,
            )
            .await
        }
        .await;
        result.map_err(Into::into)
    }
    pub async fn revoke(&self, channel: String, device: String) -> MobileResult<()> {
        let result = async {
            let hub = self.connected()?;
            management::append(
                &self.app,
                &hub.connection(),
                &channel,
                MembershipAction::Revoke { device_id: device },
                None,
            )
            .await?;
            hub.refresh(&channel).await?;
            Ok(())
        }
        .await;
        result.map_err(|e: anyhow::Error| e.into())
    }
    pub async fn leave(&self, channel: String) -> MobileResult<()> {
        let result = async {
            let hub = self.connected()?;
            management::append(
                &self.app,
                &hub.connection(),
                &channel,
                MembershipAction::Leave,
                None,
            )
            .await?;
            hub.stop_channel(&channel);
            announce(&hub).await
        }
        .await;
        result.map_err(Into::into)
    }
    pub async fn rotate_psk(&self, channel: String) -> MobileResult<String> {
        let result = async {
            let hub = self.connected()?;
            let psk = Zeroizing::new(make_psk());
            let verifier = hash_psk(&psk)?;
            management::append(
                &self.app,
                &hub.connection(),
                &channel,
                MembershipAction::ChangePsk {
                    verifier_commitment: hibiki_lib::digest(verifier.as_bytes()),
                },
                Some(verifier),
            )
            .await?;
            Ok(psk.to_string())
        }
        .await;
        result.map_err(|e: anyhow::Error| e.into())
    }
}
