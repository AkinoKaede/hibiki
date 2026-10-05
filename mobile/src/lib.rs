//! iOS bridge. Cryptographic wire messages never cross into Swift.
mod broker;
mod card;
mod card_backend;
mod curves;
#[cfg(test)]
mod inspection_tests;
mod keycodec;
mod pin_cache;
mod pinentry;
mod provider;
mod provider_cards;
mod types;
use hibiki_lib::invitation::OneTimeInvitation;
pub use types::*;

use anyhow::{Context, Result, bail};
use broker::Broker;
use hibiki_core::{
    management,
    network::{Connection, Event},
    session::{Hub, announce},
    storage::{App, Config, private_dir},
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

#[derive(uniffi::Record)]
pub struct DevicePingReport {
    pub setup_micros: u64,
    pub round_trips_micros: Vec<Option<u64>>,
}

/// UniFFI does not forward Swift task cancellation; explicitly close the ping session.
#[derive(uniffi::Object, Default)]
pub struct PingCancellation {
    stop: CancellationToken,
}
#[uniffi::export]
impl PingCancellation {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn cancel(&self) {
        self.stop.cancel();
    }
}

/// Stops scan approval before any subsequent network step after the scanner closes.
#[derive(uniffi::Object, Default)]
pub struct PairingCancellation {
    stop: CancellationToken,
}
#[uniffi::export]
impl PairingCancellation {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn cancel(&self) {
        self.stop.cancel();
    }
}

/// A request-scoped handle because Swift task cancellation is not forwarded by UniFFI.
#[derive(uniffi::Object, Default)]
pub struct CardReadCancellation {
    stop: CancellationToken,
}
#[uniffi::export]
impl CardReadCancellation {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn cancel(&self) {
        self.stop.cancel();
    }
}

/// Identify supported GnuPG insertion descriptions after Assuan unescaping.
#[uniffi::export]
pub fn card_insertion_number(description: String) -> Option<String> {
    hibiki_lib::card_prompt::insertion_number(&description)
}

/// Use the same human-readable card number as insertion requests.
#[uniffi::export]
pub fn format_card_number(serial: String) -> String {
    hibiki_lib::card_prompt::card_number(&serial)
}

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
        .context("server connection timed out")??;
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
        approved_by: None,
        approver_name: None,
        can_revoke: false,
        revoked_by_server: false,
        reverse_revoke_available_at: None,
        revocation_subtree: vec![],
    })
}
#[derive(uniffi::Object)]
pub struct MobileClient {
    app: Arc<App>,
    skip_tls_certificate_validation: bool,
    broker: Arc<Broker>,
    provider: Arc<MobileProvider>,
    slots: Arc<Semaphore>,
    nfc_record_stop: Mutex<CancellationToken>,
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
            .context("server is offline")
    }
    async fn read_recorded_card(
        &self,
        expected: Option<String>,
        confirm_token: Option<&str>,
        cancellation: Arc<CardReadCancellation>,
    ) -> Result<CardInfo> {
        let permit = self
            .slots
            .clone()
            .try_acquire_owned()
            .context("card is in use")?;
        let stop = cancellation.stop.child_token();
        let _guard = provider::CancelOnDrop(stop.clone());
        let lifecycle_stop = self.stop.lock().unwrap().clone();
        let record_stop = self.nfc_record_stop.lock().unwrap().child_token();
        if stop.is_cancelled() || lifecycle_stop.is_cancelled() || record_stop.is_cancelled() {
            return Err(broker::RequestCancelled.into());
        }
        // Acquire the reader before acknowledging; following card queries wait for it.
        // Native prompt completion must not cancel this independent public read.
        if let Some(token) = confirm_token {
            self.broker.respond(token, vec![], true)?;
        }
        let broker = self.broker.clone();
        let read_stop = stop.clone();
        let usb = confirm_token.is_some() && self.provider.usb_present.load(Ordering::Acquire);
        let nfc = self.provider.nfc_available.load(Ordering::Acquire);
        let mut read = tokio::task::spawn_blocking(move || {
            let info = if usb {
                match card::inspect(broker.clone(), read_stop.clone(), CardTransport::Usb) {
                    Ok(info) => Some(info),
                    Err(error) if error.is::<broker::CardNotPresent>() => None,
                    Err(error) => return Err(error),
                }
            } else {
                None
            };
            let info = match info {
                Some(info) => info,
                None => {
                    if !nfc {
                        bail!("NFC reading is unavailable on this device");
                    }
                    card::inspect(broker, read_stop, CardTransport::Nfc)?
                }
            };
            if let Some(expected) = expected
                && !hibiki_lib::card_prompt::card_number(&info.serial)
                    .eq_ignore_ascii_case(&expected)
                && !info.serial.eq_ignore_ascii_case(&expected)
            {
                bail!("The security key does not match the requested card.");
            }
            Ok((info, permit))
        });
        let (info, _permit) = tokio::select! {
            biased;
            _ = lifecycle_stop.cancelled() => { stop.cancel(); let _ = read.await; return Err(broker::RequestCancelled.into()); },
            _ = record_stop.cancelled() => { stop.cancel(); let _ = read.await; return Err(broker::RequestCancelled.into()); },
            result = &mut read => result??,
        };
        let _record_guard = self.nfc_record_stop.lock().unwrap();
        if stop.is_cancelled() || lifecycle_stop.is_cancelled() || record_stop.is_cancelled() {
            return Err(broker::RequestCancelled.into());
        }
        if matches!(info.transport, CardTransport::Nfc) {
            *self.provider.nfc_card.lock().unwrap() = Some(info.clone());
            let _ = self
                .broker
                .emit(NativeEvent::CardChanged { card: info.clone() });
        }
        Ok(info)
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
                .map(|d| {
                    let mut info = device_info(d, online.contains(&d.id()))?;
                    info.approved_by = state.approved_by(&info.id).map(|d| d.id());
                    info.approver_name = state.approved_by(&info.id).map(|d| d.name.clone());
                    info.reverse_revoke_available_at =
                        state.reverse_revoke_available_at(&self.app.identity.device.id(), &info.id);
                    info.can_revoke = state.can_revoke(&self.app.identity.device.id(), &info.id);
                    if state.can_revoke_subtree(&self.app.identity.device.id(), &info.id) {
                        info.revocation_subtree = state.revocation_subtree(&info.id);
                    }
                    Ok(info)
                })
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
                        Some(Event::Message(Envelope::PeerOnline { .. }))=>hub.changed.notify_waiters(),
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
            // Retire both historical public-key registries, without decoding them.
            for name in ["nfc-cards.bin", "cards.bin"] {
                match std::fs::remove_file(app.paths.data.join(name)) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            let broker = Broker::new();
            let provider = MobileProvider::new(broker.clone());
            Ok(Arc::new(Self {
                app,
                skip_tls_certificate_validation,
                broker,
                nfc_record_stop: Mutex::new(CancellationToken::new()),
                slots: provider.slots.clone(),
                provider,
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
        // A synchronous background-expiration stop may still be unwinding.
        // Join it before replacing its token or publishing another connection.
        if self.stop.lock().unwrap().is_cancelled() {
            let job = self.job.lock().unwrap().take();
            if let Some(job) = job {
                let _ = job.await;
            }
        }
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
    /// Synchronous cancellation for host background-expiration callbacks.
    /// `stop` or the next `start` joins the canceled connection task.
    pub fn request_stop(&self) {
        self.stop.lock().unwrap().cancel();
        if let Some(hub) = self.hub.lock().unwrap().take() {
            hub.connection().close();
        }
        self.broker.cancel_all();
    }
    pub async fn stop(&self) {
        let _lock = self.lifecycle.lock().await;
        self.request_stop();
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
    pub fn cancel_request(&self, token: String) -> MobileResult<()> {
        self.broker.cancel(&token).map_err(Into::into)
    }
    pub fn fail_native_request(
        &self,
        token: String,
        message: String,
        canceled: bool,
    ) -> MobileResult<()> {
        self.broker
            .fail(&token, message, canceled)
            .map_err(Into::into)
    }
    pub fn set_services(&self, pinentry: bool, card: bool) {
        let old_pin = self.provider.pin_enabled.swap(pinentry, Ordering::AcqRel);
        let old_card = self.provider.card_enabled.swap(card, Ordering::AcqRel);
        if old_card && !card {
            self.provider.pin_cache.clear_all();
        }
        if ((old_pin && !pinentry) || (old_card && !card))
            && let Some(hub) = self.hub.lock().unwrap().as_ref()
        {
            hub.stop_all();
        }
    }
    /// A live reader probe found no physical card; distinct from cancellation or I/O failure.
    pub fn card_not_present(&self, token: String) -> MobileResult<()> {
        self.broker.card_not_present(&token).map_err(Into::into)
    }
    pub fn usb_present(&self, present: bool) {
        self.provider.usb_present.store(present, Ordering::Release);
    }
    /// Host capability, separate from the process-local NFC snapshot.
    pub fn set_nfc_available(&self, available: bool) {
        let was_available = self
            .provider
            .nfc_available
            .swap(available, Ordering::AcqRel);
        if !available {
            self.clear_nfc_card();
        }
        if was_available
            && !available
            && let Some(hub) = self.hub.lock().unwrap().as_ref()
        {
            hub.stop_all();
        }
    }
    /// Read public information without changing the process-local NFC record.
    pub async fn inspect_card(
        &self,
        transport: CardTransport,
        cancellation: Arc<CardReadCancellation>,
    ) -> MobileResult<CardInfo> {
        let result: Result<CardInfo> = async {
            if cancellation.stop.is_cancelled() {
                return Err(broker::RequestCancelled.into());
            }
            if transport == CardTransport::Nfc
                && !self.provider.nfc_available.load(Ordering::Acquire)
            {
                bail!("NFC reading is unavailable on this device");
            }
            let permit = self
                .slots
                .clone()
                .try_acquire_owned()
                .context("card is in use")?;
            let stop = cancellation.stop.child_token();
            let _guard = provider::CancelOnDrop(stop.clone());
            let lifecycle_stop = self.stop.lock().unwrap().clone();
            let broker = self.broker.clone();
            let read_stop = stop.clone();
            let mut read = tokio::task::spawn_blocking(move || {
                // Keep the hardware slot until the blocking reader has actually unwound.
                let _permit = permit;
                card::inspect(broker, read_stop, transport)
            });
            let result = tokio::select! {
                result = &mut read => result?,
                _ = lifecycle_stop.cancelled() => {
                    stop.cancel();
                    read.await?
                }
            };
            if stop.is_cancelled() || lifecycle_stop.is_cancelled() {
                Err(broker::RequestCancelled.into())
            } else {
                result
            }
        }
        .await;
        result.map_err(Into::into)
    }
    /// Read and remember one public NFC snapshot for this process only.
    pub async fn record_nfc_card(
        &self,
        expected_number: Option<String>,
        cancellation: Arc<CardReadCancellation>,
    ) -> MobileResult<CardInfo> {
        self.read_recorded_card(expected_number, None, cancellation)
            .await
            .map_err(Into::into)
    }
    pub fn nfc_card(&self) -> Option<CardInfo> {
        self.provider.nfc_card.lock().unwrap().clone()
    }
    pub fn clear_nfc_card(&self) {
        let mut stop = self.nfc_record_stop.lock().unwrap();
        stop.cancel();
        *stop = CancellationToken::new();
        *self.provider.nfc_card.lock().unwrap() = None;
        self.provider.cancel_nfc_sessions();
    }
    /// Only a recognized two-button CONFIRM may use the insertion workflow.
    /// The caller refreshes native USB presence immediately before calling.
    pub async fn continue_card_insertion(
        &self,
        prompt: PinPrompt,
        cancellation: Arc<CardReadCancellation>,
    ) -> MobileResult<()> {
        let result = async {
            if !matches!(prompt.kind, PromptKind::Confirm) {
                bail!("not a card insertion confirmation");
            }
            let expected = hibiki_lib::card_prompt::insertion_number(&prompt.description)
                .context("not a card insertion confirmation")?;
            if !self.provider.nfc_available.load(Ordering::Acquire) {
                return self.broker.respond(&prompt.token, vec![], true);
            }
            self.read_recorded_card(Some(expected), Some(&prompt.token), cancellation)
                .await?;
            Ok(())
        }
        .await;
        result.map_err(Into::into)
    }
    pub async fn channels(&self) -> MobileResult<Vec<ChannelInfo>> {
        let result = async {
            let hub = self.connected().ok();
            let mut out = Vec::new();
            for proof in self.app.proofs()? {
                let id = proof.genesis.body.id.clone();
                let mut denied = false;
                let current = if let Some(h) = &hub {
                    match h.refresh(&id).await {
                        Ok(proof) => proof,
                        Err(e) => {
                            denied = e
                                .downcast_ref::<hibiki_lib::protocol::WireError>()
                                .is_some_and(|e| e.code == "access_revoked");
                            proof
                        }
                    }
                } else {
                    proof
                };
                let (peers, revoked) = if let Some(h) = &hub {
                    match h
                        .connection()
                        .request(Control::ChannelSnapshot {
                            channel: id.clone(),
                        })
                        .await
                    {
                        Ok(Reply::ChannelSnapshot {
                            proof,
                            online,
                            revoked,
                        }) => {
                            if proof.genesis.body.id != id {
                                bail!("snapshot channel mismatch");
                            }
                            self.app.merge(proof)?;
                            (online, revoked)
                        }
                        _ => (vec![], vec![]),
                    }
                } else {
                    (vec![], vec![])
                };
                let mut info = self.channel_info(self.app.proof(&id).unwrap_or(current), &peers)?;
                info.active &= !denied;
                for device in &mut info.members {
                    device.revoked_by_server = revoked.contains(&device.id);
                    if device.revoked_by_server {
                        device.can_revoke = false;
                        device.revocation_subtree.clear();
                    }
                }
                out.push(info);
            }
            Ok(out)
        }
        .await;
        result.map_err(|e: anyhow::Error| e.into())
    }
    pub async fn ping_device(
        &self,
        channel: String,
        device: String,
        count: u16,
        cancellation: Arc<PingCancellation>,
    ) -> MobileResult<DevicePingReport> {
        let result: Result<DevicePingReport> = async {
            let hub = self.connected()?;
            let report = tokio::select! {
                biased;
                _ = cancellation.stop.cancelled() => bail!("ping canceled"),
                report = async {
                    // Admission may have completed before the periodic announcement.
                    announce(&hub).await?;
                    hub.ping(&channel, &device, count).await
                } => report?,
            };
            Ok(DevicePingReport {
                setup_micros: report.setup_micros,
                round_trips_micros: report.round_trips_micros,
            })
        }
        .await;
        result.map_err(Into::into)
    }
    pub async fn rename_device(&self, name: String) -> MobileResult<Vec<u8>> {
        let result: Result<Vec<u8>> = async {
            let hub = self.connected()?;
            let identity = management::rename(&self.app, &hub.connection(), name).await?;
            Ok(encode(&identity)?)
        }
        .await;
        result.map_err(Into::into)
    }
    pub async fn create_channel(&self, name: String) -> MobileResult<Invitation> {
        let result: Result<Invitation> = async {
            let hub = self.connected()?;
            let value = management::create_channel(&self.app, &hub.connection(), name).await?;
            announce(&hub).await?;
            Ok(Invitation {
                channel: value.metadata.channel.clone(),
                invite: value.export()?.to_string(),
                expires_at: value.metadata.expires_at,
            })
        }
        .await;
        result.map_err(Into::into)
    }
    pub async fn invitation(&self, channel: String) -> MobileResult<Invitation> {
        let result: Result<Invitation> = async {
            let value =
                management::invitation(&self.app, &self.connected()?.connection(), &channel)
                    .await?;
            Ok(Invitation {
                channel,
                invite: value.export()?.to_string(),
                expires_at: value.metadata.expires_at,
            })
        }
        .await;
        result.map_err(Into::into)
    }
    pub fn invitation_preview(&self, text: String) -> MobileResult<InvitationPreview> {
        let value = OneTimeInvitation::import(&text).map_err(anyhow::Error::from)?;
        if value.metadata.expires_at <= hibiki_lib::now() {
            return Err(anyhow::anyhow!("invitation expired; obtain a new invitation").into());
        }
        if value.metadata.server != self.app.config.server {
            return Err(anyhow::anyhow!("invitation server differs from configured server").into());
        }
        Ok(InvitationPreview {
            server: value.metadata.server.clone(),
            channel: value.metadata.channel.clone(),
            name: value.metadata.name.clone(),
            expires_at: value.metadata.expires_at,
        })
    }
    pub async fn join(&self, invitation: String) -> MobileResult<JoinInfo> {
        let result: Result<JoinInfo> = async {
            let hub = self.connected()?;
            let invitation = Zeroizing::new(invitation);
            let result = management::join(&self.app, &hub.connection(), &invitation).await?;
            if result.request.is_none() {
                announce(&hub).await?;
            }
            Ok(JoinInfo {
                channel: result.channel,
                request: result.request.unwrap_or_default(),
                verification: result.verification,
            })
        }
        .await;
        result.map_err(Into::into)
    }
    pub async fn approve_verification(
        &self,
        channel: String,
        request_id: String,
        code: String,
        cancellation: Arc<PairingCancellation>,
    ) -> MobileResult<()> {
        let hub = self.connected().map_err(MobileError::from)?;
        let stop = self.stop.lock().unwrap().clone();
        let connection = hub.connection();
        tokio::select! {
            biased;
            _ = cancellation.stop.cancelled() => Err(MobileError::Cancelled),
            _ = stop.cancelled() => Err(MobileError::Cancelled),
            result = management::approve_verification(&self.app, &connection, &channel, &request_id, &code) => result.map_err(Into::into),
        }
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
                bail!("invalid server policy response");
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
                MembershipAction::Accept(request),
            )
            .await
        }
        .await;
        result.map_err(Into::into)
    }
    pub async fn revoke(&self, channel: String, device: String) -> MobileResult<()> {
        let hub = self.connected().map_err(MobileError::from)?;
        let state = hub
            .refresh(&channel)
            .await
            .map_err(MobileError::from)?
            .verify()
            .map_err(anyhow::Error::from)?;
        self.revoke_selected(channel, device, false, state.sequence)
            .await
    }
    pub async fn revoke_selected(
        &self,
        channel: String,
        device: String,
        subtree: bool,
        revision: u64,
    ) -> MobileResult<()> {
        let result = async {
            let hub = self.connected()?;
            management::revoke(
                &self.app,
                &hub.connection(),
                &channel,
                &device,
                subtree,
                revision,
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
            )
            .await?;
            hub.stop_channel(&channel);
            announce(&hub).await
        }
        .await;
        result.map_err(Into::into)
    }
}
