use crate::{
    broker::Broker,
    card,
    pin_cache::{PinCache, Scope},
    pinentry::Pinentry,
    provider_cards::{CardSetSession, matches_target},
    types::{CardInfo, CardTransport, NativeEvent, PinPrompt, PromptKind},
};
use anyhow::{Context, Result, bail};
use hibiki_core::{
    endpoint::Endpoint,
    provider::{OpenFuture, Provider, ProviderContext},
    storage::App,
};
use hibiki_lib::{
    assuan::{self, AssuanResult, Line},
    protocol::{ServiceKind, SessionInput, SessionOutput},
};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

#[derive(Default)]
struct SessionCards {
    prepared: Option<CardInfo>,
    usb: Option<CardInfo>,
    nfc_used: bool,
    stop: CancellationToken,
}

pub struct MobileProvider {
    pub broker: Arc<Broker>,
    pub pin_cache: Arc<PinCache>,
    pub nfc_card: Arc<Mutex<Option<CardInfo>>>,
    pub card_enabled: AtomicBool,
    pub pin_enabled: AtomicBool,
    pub usb_present: Arc<AtomicBool>,
    pub nfc_available: Arc<AtomicBool>,
    pub slots: Arc<Semaphore>,
    sessions: Mutex<HashMap<String, Weak<Mutex<SessionCards>>>>,
}
impl MobileProvider {
    pub fn cancel_nfc_sessions(&self) {
        for session in self
            .sessions
            .lock()
            .unwrap()
            .values()
            .filter_map(Weak::upgrade)
        {
            let state = session.lock().unwrap();
            if state.nfc_used {
                state.stop.cancel();
            }
        }
    }
    pub fn new(broker: Arc<Broker>) -> Arc<Self> {
        Arc::new(Self {
            broker,
            pin_cache: Arc::new(PinCache::default()),
            nfc_card: Arc::new(Mutex::new(None)),
            card_enabled: AtomicBool::new(true),
            pin_enabled: AtomicBool::new(true),
            usb_present: Arc::new(AtomicBool::new(false)),
            nfc_available: Arc::new(AtomicBool::new(false)),
            slots: Arc::new(Semaphore::new(1)),
            sessions: Mutex::new(HashMap::new()),
        })
    }
}
// Mobile preparation does not borrow the native Assuan endpoint. Keep its
// complete future (including broker reply tokens and NFC/USB state) across
// public queries, polling it again when the controller resumes acquisition.
struct MobilePreparation(
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send>>,
);
impl hibiki_core::provider::Preparation for MobilePreparation {
    fn poll<'a>(
        &'a mut self,
        _endpoint: &'a mut Endpoint,
        pause: CancellationToken,
    ) -> hibiki_core::provider::PrepareFuture<'a> {
        Box::pin(async move {
            tokio::select! {
                biased;
                _ = pause.cancelled() => Ok(None),
                result = &mut self.0 => result.map(Some),
            }
        })
    }
}

impl Provider for MobileProvider {
    fn enabled(&self, kind: ServiceKind) -> bool {
        match kind {
            ServiceKind::Pinentry => self.pin_enabled.load(Ordering::Acquire),
            ServiceKind::Scdaemon => self.card_enabled.load(Ordering::Acquire),
        }
    }
    fn prepare(
        &self,
        app: Arc<App>,
        target: hibiki_lib::protocol::CardTarget,
        context: ProviderContext,
    ) -> Result<Box<dyn hibiki_core::provider::Preparation>> {
        let slots = self.slots.clone();
        let cards = self.nfc_card.clone();
        let broker = self.broker.clone();
        let nfc_available = self.nfc_available.clone();
        let usb_present = self.usb_present.clone();
        let prepared = self
            .sessions
            .lock()
            .unwrap()
            .get(&context.session)
            .and_then(Weak::upgrade)
            .context("card session is closed")?;
        Ok(Box::new(MobilePreparation(Box::pin(async move {
            let stop = CancellationToken::new();
            target.validate()?;
            prepared.lock().unwrap().prepared = None;
            if nfc_available.load(Ordering::Acquire)
                && let Some(info) = cards
                    .lock()
                    .unwrap()
                    .clone()
                    .filter(|c| matches_target(c, &target))
            {
                let serial = info.serial.clone();
                let mut state = prepared.lock().unwrap();
                state.prepared = Some(info);
                state.nfc_used = true;
                return Ok(serial);
            }
            let known_usb = prepared
                .lock()
                .unwrap()
                .usb
                .clone()
                .filter(|c| matches_target(c, &target));
            // A previously discovered USB identity can proceed to PIN entry even
            // after removal: the final reader is chosen only once the PIN arrives.
            if nfc_available.load(Ordering::Acquire)
                && let Some(info) = known_usb.clone()
            {
                let serial = info.serial.clone();
                prepared.lock().unwrap().prepared = Some(info);
                return Ok(serial);
            }
            let prompt_stop = stop.child_token();
            let _guard = CancelOnDrop(stop.clone());
            let make_prompt = || async {
                let serial = target
                    .serial
                    .as_deref()
                    .or_else(|| known_usb.as_ref().map(|c| c.serial.as_str()))
                    .context("card serial number is required for insertion prompt")?;
                confirm_card(&app, &context, &broker, &prompt_stop, serial, false).await
            };
            let mut prompt = Box::pin(make_prompt());
            let mut prompt_started = false;
            loop {
                if stop.is_cancelled() {
                    bail!("card preparation canceled");
                }
                // Once shown, keep polling the prompt while USB detection is in flight.
                // A ready card must not overtake an already submitted cancellation.
                prompt_started |= !usb_present.load(Ordering::Acquire);
                let probe = async {
                    if nfc_available.load(Ordering::Acquire)
                        && let Some(info) = cards
                            .lock()
                            .unwrap()
                            .clone()
                            .filter(|c| matches_target(c, &target))
                    {
                        let serial = info.serial.clone();
                        let mut state = prepared.lock().unwrap();
                        state.prepared = Some(info);
                        state.nfc_used = true;
                        return Ok(Some(serial));
                    }
                    if usb_present.load(Ordering::Acquire) {
                        let Ok(_permit) = slots.clone().try_acquire_owned() else {
                            tokio::time::sleep(Duration::from_millis(300)).await;
                            return Ok(None);
                        };
                        match inspect_usb(&broker, &stop, Some(Arc::new(_permit))).await {
                            Ok(Some(info)) if matches_target(&info, &target) => {
                                let serial = info.serial.clone();
                                let mut state = prepared.lock().unwrap();
                                state.usb = Some(info.clone());
                                state.prepared = Some(info);
                                return Ok(Some(serial));
                            }
                            Err(error) => return Err(error),
                            _ => {}
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    Ok(None)
                };
                tokio::pin!(probe);
                loop {
                    tokio::select! {
                        biased;
                        _=stop.cancelled()=>bail!("card preparation canceled"),
                        result=&mut prompt, if prompt_started=>{
                            if let Err(error) = result {
                                if error.is::<crate::broker::OperationCancelled>()
                                    || error.is::<crate::broker::RequestCancelled>()
                                {
                                    return Err(hibiki_core::provider::PreparationRejected.into());
                                }
                                return Err(error);
                            }
                            prompt = Box::pin(make_prompt());
                        },
                        serial=&mut probe=>{
                            if let Some(serial) = serial? { return Ok(serial); }
                            prompt_started = true;
                            break;
                        },
                    }
                }
            }
        }))))
    }
    fn open(
        &self,
        app: Arc<App>,
        kind: ServiceKind,
        slots: Arc<Semaphore>,
        stop: CancellationToken,
        context: ProviderContext,
    ) -> OpenFuture<'_> {
        Box::pin(async move {
            if !self.enabled(kind) {
                bail!("service disabled");
            }
            let nfc_card = self.nfc_card.clone();
            let mut card_set = CardSetSession::new();
            let broker = self.broker.clone();
            let pin_cache = self.pin_cache.clone();
            let usb_present = self.usb_present.clone();
            let nfc_available = self.nfc_available.clone();
            let prepared = Arc::new(Mutex::new(SessionCards {
                stop: stop.clone(),
                ..SessionCards::default()
            }));
            if kind == ServiceKind::Scdaemon {
                let mut sessions = self.sessions.lock().unwrap();
                sessions.retain(|_, value| value.strong_count() > 0);
                sessions.insert(context.session.clone(), Arc::downgrade(&prepared));
            }
            let (tx, mut inputs) = mpsc::channel(16);
            let (outputs, rx) = mpsc::channel(32);
            let done = CancellationToken::new();
            let finished = done.clone();
            let cancel = stop.clone();
            tokio::spawn(async move {
                let mut pinentry = Pinentry::default();
                let run = async {
                    let mut last = 0;
                    while let Some(input) = inputs.recv().await {
                        let SessionInput::Command { request, line } = input else {
                            bail!("unsolicited inquiry reply")
                        };
                        if request != last + 1 {
                            bail!("out of order command");
                        }
                        last = request;
                        let command_stop = cancel.child_token();
                        let _guard = CancelOnDrop(command_stop.clone());
                        let _permit = if kind == ServiceKind::Scdaemon {
                            Some(Arc::new(
                                slots
                                    .clone()
                                    .acquire_owned()
                                    .await
                                    .context("card is in use")?,
                            ))
                        } else {
                            None
                        };
                        let result = if assuan::validate_command(kind, &line).is_err() {
                            AssuanResult::error(
                                assuan::NOT_SUPPORTED,
                                "unsupported service command",
                            )
                        } else {
                            let work = async {
                                if kind == ServiceKind::Scdaemon {
                                    let (cmd, args) = assuan::command(&line)?;
                                    if matches!(cmd, "PKSIGN" | "PKDECRYPT") {
                                        card_set.prepare_execution(
                                            prepared.lock().unwrap().prepared.take(),
                                        )?;
                                        let card = &mut card_set.card;
                                        let key = card.private_key(cmd, args)?;
                                        let info = card.info.clone();
                                        let data = card.take_data();
                                        let signing = cmd == "PKSIGN";
                                        let hash = args
                                            .split_ascii_whitespace()
                                            .find_map(|a| a.strip_prefix("--hash="))
                                            .unwrap_or("sha1")
                                            .to_owned();
                                        private_with_cache(
                                            &pin_cache,
                                            &app.identity.device.id(),
                                            &context,
                                            &outputs,
                                            &mut inputs,
                                            request,
                                            broker.clone(),
                                            command_stop.clone(),
                                            info,
                                            key,
                                            signing,
                                            hash,
                                            data,
                                            nfc_available.load(Ordering::Acquire),
                                            _permit.clone(),
                                        )
                                        .await
                                    } else if cmd == "SERIALNO" {
                                        let card = {
                                            let card = nfc_card.lock().unwrap();
                                            if card.is_some() {
                                                prepared.lock().unwrap().nfc_used = true;
                                            }
                                            card.clone()
                                        };
                                        let query = SerialQuery {
                                            card: card.as_ref(),
                                            permit: _permit.clone(),
                                            broker: &broker,
                                            usb_present: usb_present.load(Ordering::Acquire),
                                            nfc_available: nfc_available.load(Ordering::Acquire),
                                        };
                                        match query.run(args, &app, &context, &command_stop).await?
                                        {
                                            Some(info) => {
                                                if info.transport == CardTransport::Usb {
                                                    prepared.lock().unwrap().usb =
                                                        Some(info.clone());
                                                }
                                                if info.transport == CardTransport::Nfc {
                                                    prepared.lock().unwrap().nfc_used = true;
                                                }
                                                card_set.bind(info);
                                                card_set.card.command(&line)
                                            }
                                            None => Ok(AssuanResult::error(
                                                assuan::CARD_NOT_PRESENT,
                                                "Card not present",
                                            )),
                                        }
                                    } else {
                                        if cmd == "RESET" {
                                            for status in pin_cache.clear_context(&context) {
                                                send(&outputs, request, status).await?;
                                            }
                                        }
                                        if matches!(cmd, "RESET" | "RESTART") {
                                            *prepared.lock().unwrap() = SessionCards {
                                                stop: cancel.clone(),
                                                ..SessionCards::default()
                                            };
                                        }
                                        let mut cards: Vec<CardInfo> =
                                            if nfc_available.load(Ordering::Acquire) {
                                                {
                                                    let card = nfc_card.lock().unwrap();
                                                    if card.is_some() {
                                                        prepared.lock().unwrap().nfc_used = true;
                                                    }
                                                    card.iter().cloned().collect()
                                                }
                                            } else {
                                                vec![]
                                            };
                                        let public_card_query = matches!(
                                            cmd,
                                            "LEARN"
                                                | "READKEY"
                                                | "KEYINFO"
                                                | "GETATTR"
                                                | "SWITCHCARD"
                                        ) || (cmd == "GETINFO"
                                            && matches!(
                                                args,
                                                "card_list" | "all_active_apps" | "status"
                                            ));
                                        if public_card_query && usb_present.load(Ordering::Acquire)
                                        {
                                            let cached = prepared.lock().unwrap().usb.clone();
                                            let info = if cached.is_some() {
                                                cached
                                            } else {
                                                inspect_usb(&broker, &command_stop, _permit.clone())
                                                    .await?
                                            };
                                            if let Some(info) = info {
                                                prepared.lock().unwrap().usb = Some(info.clone());
                                                cards.retain(|c| c.serial != info.serial);
                                                cards.insert(0, info);
                                            }
                                        }
                                        card_set.bind_if_unbound(
                                            prepared.lock().unwrap().prepared.clone(),
                                        );
                                        card_set.command(&cards, &line)
                                    }
                                } else {
                                    pinentry
                                        .command(
                                            &line,
                                            request,
                                            &app,
                                            &context,
                                            &broker,
                                            &command_stop,
                                        )
                                        .await
                                }
                            };
                            match tokio::time::timeout(
                                Duration::from_secs(app.config.operation_timeout_seconds),
                                work,
                            )
                            .await
                            {
                                Ok(Ok(result)) => result,
                                Ok(Err(_)) if command_stop.is_cancelled() => {
                                    card::operation_error(&crate::broker::RequestCancelled.into())
                                }
                                Ok(Err(error)) => card::operation_error(&error),
                                Err(_) => {
                                    command_stop.cancel();
                                    AssuanResult::error(assuan::CANCELED, "operation timed out")
                                }
                            }
                        };
                        for line in result.lines {
                            send(&outputs, request, line).await?;
                        }
                        if &*line == b"BYE" {
                            break;
                        }
                    }
                    Ok::<_, anyhow::Error>(())
                };
                tokio::select! {
                    biased;
                    _=cancel.cancelled()=>{},
                    result=run=>{if result.is_err(){let _=outputs.try_send(SessionOutput::Failure);}},
                }
                cancel.cancel();
                finished.cancel();
            });
            Ok(Endpoint::new(tx, rx, stop, done))
        })
    }
}
// NFC discovery uses only this process's explicitly recorded snapshot.
struct SerialQuery<'a> {
    card: Option<&'a CardInfo>,
    permit: Option<Arc<OwnedSemaphorePermit>>,
    broker: &'a Arc<Broker>,
    usb_present: bool,
    nfc_available: bool,
}
impl SerialQuery<'_> {
    async fn run(
        &self,
        args: &str,
        _app: &App,
        _context: &ProviderContext,
        stop: &CancellationToken,
    ) -> Result<Option<CardInfo>> {
        let serial = args
            .split_ascii_whitespace()
            .find_map(|a| a.strip_prefix("--demand="));
        if self.usb_present
            && let Some(info) = inspect_usb(self.broker, stop, self.permit.clone()).await?
            && serial.is_none_or(|s| s.eq_ignore_ascii_case(&info.serial))
        {
            return Ok(Some(info));
        }
        Ok(self
            .card
            .filter(|c| {
                self.nfc_available && serial.is_none_or(|s| s.eq_ignore_ascii_case(&c.serial))
            })
            .cloned())
    }
}

async fn inspect_usb(
    broker: &Arc<Broker>,
    stop: &CancellationToken,
    permit: Option<Arc<OwnedSemaphorePermit>>,
) -> Result<Option<CardInfo>> {
    let broker = broker.clone();
    let probe_stop = stop.child_token();
    let _guard = CancelOnDrop(probe_stop.clone());
    match tokio::task::spawn_blocking(move || {
        // Cancellation can drop the async future before the blocking APDU reader unwinds.
        let _permit = permit;
        card::inspect(broker, probe_stop, CardTransport::Usb)
    })
    .await?
    {
        Ok(info) => Ok(Some(info)),
        Err(error) if error.is::<crate::broker::CardNotPresent>() => Ok(None),
        Err(error) => Err(error),
    }
}

async fn confirm_card(
    app: &App,
    context: &ProviderContext,
    broker: &Arc<Broker>,
    stop: &CancellationToken,
    serial: &str,
    nfc: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    let state = app.proof(&context.channel)?.verify()?;
    let device = state.member(&context.peer)?;
    broker
        .request(
            |token| NativeEvent::Prompt {
                prompt: PinPrompt {
                    token,
                    session: context.session.clone(),
                    request: 0,
                    channel: state.name.clone(),
                    device_name: device.name.clone(),
                    device_id: context.peer.clone(),
                    kind: if nfc {
                        PromptKind::CardNfc
                    } else {
                        PromptKind::CardUsb
                    },
                    title: String::new(),
                    description: hibiki_lib::card_prompt::description(serial, ""),
                    label: String::new(),
                    error: String::new(),
                    repeat: String::new(),
                    repeat_error: String::new(),
                    ok: String::new(),
                    cancel: String::new(),
                    not_ok: String::new(),
                    timeout_seconds: app.config.operation_timeout_seconds as u32,
                },
            },
            stop,
            Duration::from_secs(app.config.operation_timeout_seconds),
        )
        .await
}

async fn send(outputs: &mpsc::Sender<SessionOutput>, request: u64, line: Line) -> Result<()> {
    outputs.send(SessionOutput::Line { request, line }).await?;
    Ok(())
}
#[allow(clippy::too_many_arguments)] // One bounded private command and its Assuan channel.
async fn private_with_cache(
    cache: &Arc<PinCache>,
    provider: &str,
    context: &ProviderContext,
    outputs: &mpsc::Sender<SessionOutput>,
    inputs: &mut mpsc::Receiver<SessionInput>,
    request: u64,
    broker: Arc<Broker>,
    stop: CancellationToken,
    info: CardInfo,
    key: crate::types::CardKey,
    signing: bool,
    hash: String,
    mut data: Zeroizing<Vec<u8>>,
    nfc: bool,
    permit: Option<Arc<OwnedSemaphorePermit>>,
) -> Result<AssuanResult> {
    let scope = Scope::new(provider, context, &info, &key);
    let mut ticket = cache.begin(scope.clone());
    let mut cached = None;
    if cache.contains(&ticket) {
        send(
            outputs,
            request,
            format!("INQUIRE PINCACHE_GET {}", scope.id).as_str().into(),
        )
        .await?;
        // GnuPG uses CAN for an unsupported cache inquiry. This is distinct
        // from cancellation of the operation/session, which still wins below.
        if let Some(value) = read_inquiry(inputs, request, 512).await? {
            cached = cache.decrypt(&ticket, &value);
        }
    }
    loop {
        if stop.is_cancelled() {
            return Err(crate::broker::RequestCancelled.into());
        }
        let using_cache = cached.is_some();
        let pin = if let Some(pin) = cached.take() {
            pin
        } else {
            let description = card::pin_description(&info)
                .replace('%', "%25")
                .replace('\r', "%0D")
                .replace('\n', "%0A");
            send(
                outputs,
                request,
                format!("INQUIRE NEEDPIN ||{description}").as_str().into(),
            )
            .await?;
            read_pin(inputs, request).await?
        };
        if stop.is_cancelled() {
            return Err(crate::broker::RequestCancelled.into());
        }
        let work_broker = broker.clone();
        let work_stop = stop.clone();
        let work_info = info.clone();
        let work_key = key.clone();
        let work_hash = hash.clone();
        let work_permit = permit.clone();
        let work_cache = cache.clone();
        let work_scope = scope.clone();
        let (outcome, invalidations) = tokio::task::spawn_blocking(move || {
            let _permit = work_permit;
            let outcome = card::private_operation(
                work_broker,
                work_stop,
                work_info,
                work_key,
                signing,
                work_hash,
                data,
                pin,
                nfc,
                using_cache,
            );
            // Invalidate even if timeout/cancellation has dropped the async waiter.
            let invalidations = if outcome.as_ref().err().is_some_and(card::bad_pin) {
                work_cache.clear_card(&work_scope)
            } else {
                Vec::new()
            };
            (outcome, invalidations)
        })
        .await?;
        if stop.is_cancelled() {
            return Err(crate::broker::RequestCancelled.into());
        }
        for status in invalidations {
            send(outputs, request, status).await?;
        }
        match outcome {
            Ok(card::PrivateResult::NeedFreshPin(input)) => {
                for status in cache.clear_entry(&scope) {
                    send(outputs, request, status).await?;
                }
                ticket = cache.begin(scope.clone());
                data = input;
                // The blocking task has dropped its reader. Prompt before reopening.
            }
            Ok(card::PrivateResult::Complete { result, cache_pin }) => {
                if let Some(pin) = cache_pin {
                    // Cache failures must never turn a completed private operation
                    // into an error (and thereby invite a duplicate signature).
                    let _ = cache.publish(ticket, &pin, |line| {
                        if stop.is_cancelled() {
                            return Err(crate::broker::RequestCancelled.into());
                        }
                        outputs.try_send(SessionOutput::Line { request, line })?;
                        Ok(())
                    });
                } else {
                    for status in cache.clear_entry(&scope) {
                        send(outputs, request, status).await?;
                    }
                }
                return Ok(result);
            }
            Err(error) => return Err(error),
        }
    }
}

async fn read_pin(
    inputs: &mut mpsc::Receiver<SessionInput>,
    request: u64,
) -> Result<Zeroizing<Vec<u8>>> {
    read_inquiry(inputs, request, 128)
        .await?
        .ok_or_else(|| crate::broker::RequestCancelled.into())
}
async fn read_inquiry(
    inputs: &mut mpsc::Receiver<SessionInput>,
    request: u64,
    limit: usize,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(limit));
    let mut lines = 0;
    loop {
        let Some(SessionInput::InquiryReply { request: id, line }) = inputs.recv().await else {
            bail!("expected PIN inquiry reply")
        };
        if id != request {
            bail!("PIN inquiry ID mismatch");
        }
        lines += 1;
        if lines > 16 {
            bail!("PIN inquiry limit");
        }
        if &*line == b"END" {
            return Ok(Some(bytes));
        }
        if &*line == b"CAN" {
            return Ok(None);
        }
        let assuan::Response::Data(raw) = assuan::parse_response(&line)? else {
            bail!("invalid PIN inquiry response")
        };
        let decoded = Zeroizing::new(assuan::unescape(raw)?);
        if bytes.len() + decoded.len() > limit {
            bail!("PIN length limit");
        }
        bytes.extend_from_slice(&decoded);
    }
}
pub struct CancelOnDrop(pub CancellationToken);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn services_start_enabled_and_can_be_disabled_independently() {
        let provider = MobileProvider::new(Broker::new());
        assert!(provider.enabled(ServiceKind::Scdaemon));
        assert!(provider.enabled(ServiceKind::Pinentry));
        assert!(!provider.nfc_available.load(Ordering::Acquire));
        for card in [false, true] {
            for pin in [false, true] {
                provider.card_enabled.store(card, Ordering::Release);
                provider.pin_enabled.store(pin, Ordering::Release);
                assert_eq!(provider.enabled(ServiceKind::Scdaemon), card);
                assert_eq!(provider.enabled(ServiceKind::Pinentry), pin);
            }
        }
    }
    #[tokio::test]
    async fn pin_inquiry_rejects_cross_request_replies() {
        let (tx, mut rx) = mpsc::channel(4);
        tx.send(SessionInput::InquiryReply {
            request: 9,
            line: "D secret".into(),
        })
        .await
        .unwrap();
        assert!(read_pin(&mut rx, 8).await.is_err());
    }
    #[tokio::test]
    async fn inquiry_limits_and_cache_can_are_distinct_from_pin_cancel() {
        for (limit, size, valid) in [
            (128, 128, true),
            (128, 129, false),
            (512, 512, true),
            (512, 513, false),
        ] {
            let (tx, mut rx) = mpsc::channel(16);
            for line in assuan::data_lines(&vec![b'x'; size])
                .into_iter()
                .chain(["END".into()])
            {
                tx.send(SessionInput::InquiryReply { request: 1, line })
                    .await
                    .unwrap();
            }
            assert_eq!(read_inquiry(&mut rx, 1, limit).await.is_ok(), valid);
        }
        let (tx, mut rx) = mpsc::channel(4);
        tx.send(SessionInput::InquiryReply {
            request: 1,
            line: "CAN".into(),
        })
        .await
        .unwrap();
        assert!(read_inquiry(&mut rx, 1, 512).await.unwrap().is_none());
        tx.send(SessionInput::InquiryReply {
            request: 1,
            line: "CAN".into(),
        })
        .await
        .unwrap();
        assert!(
            read_pin(&mut rx, 1)
                .await
                .unwrap_err()
                .is::<crate::broker::RequestCancelled>()
        );
        drop(tx);
        assert!(read_inquiry(&mut rx, 1, 512).await.is_err());
    }
}

#[cfg(test)]
#[path = "cancellation_tests.rs"]
mod cancellation_tests;
