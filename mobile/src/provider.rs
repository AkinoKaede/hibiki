use crate::{
    broker::Broker,
    card,
    pinentry::Pinentry,
    provider_cards::{CardSetSession, matches_target, usable},
    types::{CardInfo, CardTransport, NativeEvent, PinPrompt, PromptKind, RegisteredCard},
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
use tokio::sync::{Semaphore, mpsc};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

pub struct MobileProvider {
    pub broker: Arc<Broker>,
    pub cards: Arc<Mutex<Vec<RegisteredCard>>>,
    pub card_enabled: AtomicBool,
    pub pin_enabled: AtomicBool,
    pub usb_present: Arc<AtomicBool>,
    pub nfc_available: Arc<AtomicBool>,
    pub selected_nfc: Arc<Mutex<Option<String>>>,
    sessions: Mutex<HashMap<String, Weak<Mutex<Option<CardInfo>>>>>,
}
impl MobileProvider {
    pub fn new(broker: Arc<Broker>, cards: Vec<RegisteredCard>) -> Arc<Self> {
        Arc::new(Self {
            broker,
            cards: Arc::new(Mutex::new(cards)),
            card_enabled: AtomicBool::new(true),
            pin_enabled: AtomicBool::new(true),
            usb_present: Arc::new(AtomicBool::new(false)),
            nfc_available: Arc::new(AtomicBool::new(false)),
            selected_nfc: Arc::new(Mutex::new(None)),
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
        let cards = self.cards.clone();
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
            *prepared.lock().unwrap() = None;
            let candidates: Vec<_> = usable(
                &cards.lock().unwrap(),
                nfc_available.load(Ordering::Acquire),
            )
            .into_iter()
            .filter(|c| matches_target(&c.card, &target))
            .collect();
            if candidates.is_empty() {
                bail!("no registered card matches this device's available transports");
            }
            let registered = (candidates.len() == 1).then(|| &candidates[0]);
            let nfc =
                registered.is_some_and(|c| c.nfc_enabled) && nfc_available.load(Ordering::Acquire);
            let prompt_stop = stop.child_token();
            let _guard = CancelOnDrop(stop.clone());
            let make_prompt = || async {
                let serial = target
                    .serial
                    .as_deref()
                    .or_else(|| registered.map(|c| c.card.serial.as_str()))
                    .context("card serial number is required for insertion prompt")?;
                confirm_card(&app, &context, &broker, &prompt_stop, serial, nfc).await
            };
            let mut prompt = Box::pin(make_prompt());
            let mut acknowledged = false;
            let mut prompt_started = false;
            loop {
                if stop.is_cancelled() {
                    bail!("card preparation canceled");
                }
                if nfc && !nfc_available.load(Ordering::Acquire) {
                    bail!("NFC reading is unavailable on this device");
                }
                if acknowledged && nfc {
                    let mut info = registered.unwrap().card.clone();
                    info.transport = CardTransport::Nfc;
                    let serial = info.serial.clone();
                    *prepared.lock().unwrap() = Some(info);
                    return Ok(serial);
                }
                // Once shown, keep polling the prompt while USB detection is in flight.
                // A ready card must not overtake an already submitted cancellation.
                prompt_started |= !usb_present.load(Ordering::Acquire);
                let probe = async {
                    if candidates.iter().any(|c| c.usb_enabled)
                        && usb_present.load(Ordering::Acquire)
                    {
                        let broker = broker.clone();
                        let token = stop.child_token();
                        let _probe_guard = CancelOnDrop(token.clone());
                        if let Ok(Ok(info)) = tokio::task::spawn_blocking(move || {
                            card::inspect(broker, token, CardTransport::Usb)
                        })
                        .await
                            && matches_target(&info, &target)
                            && candidates.iter().any(|c| {
                                c.usb_enabled
                                    && c.card.serial.eq_ignore_ascii_case(&info.serial)
                                    && c.card.keys.iter().all(|key| {
                                        info.keys.iter().any(|actual| {
                                            actual.slot == key.slot
                                                && actual.keygrip == key.keygrip
                                                && actual.fingerprint == key.fingerprint
                                        })
                                    })
                            })
                        {
                            let serial = info.serial.clone();
                            *prepared.lock().unwrap() = Some(info);
                            return Some(serial);
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    None
                };
                tokio::pin!(probe);
                loop {
                    tokio::select! {
                        biased;
                        _=stop.cancelled()=>bail!("card preparation canceled"),
                        result=&mut prompt, if !acknowledged && prompt_started && candidates.len() == 1=>{
                            if let Err(error) = result {
                                if error.is::<crate::broker::OperationCancelled>()
                                    || error.is::<crate::broker::RequestCancelled>()
                                {
                                    return Err(hibiki_core::provider::PreparationRejected.into());
                                }
                                return Err(error);
                            }
                            if nfc { acknowledged = true; break; } else { prompt = Box::pin(make_prompt()); }
                        },
                        serial=&mut probe=>{
                            if let Some(serial) = serial { return Ok(serial); }
                            prompt_started = true;
                            if candidates.len() > 1 {
                                bail!("specify a card serial number when multiple cards match");
                            }
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
            let permit = if kind == ServiceKind::Scdaemon {
                Some(slots.try_acquire_owned().context("card busy")?)
            } else {
                None
            };
            let registry = self.cards.clone();
            let selected_nfc = self.selected_nfc.clone();
            let mut card_set = CardSetSession::new();
            let broker = self.broker.clone();
            let usb_present = self.usb_present.clone();
            let nfc_available = self.nfc_available.clone();
            let prepared = Arc::new(Mutex::new(None));
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
                let _permit = permit;
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
                                            prepared.lock().unwrap().clone(),
                                            &registry.lock().unwrap(),
                                            nfc_available.load(Ordering::Acquire),
                                        )?;
                                        let card = &mut card_set.card;
                                        let key = card.private_key(cmd, args)?;
                                        let info = card.info.clone();
                                        if info.transport == CardTransport::Usb
                                            && !usb_present.load(Ordering::Acquire)
                                        {
                                            bail!("USB card must be connected");
                                        }
                                        let data = card.take_data();
                                        let description = {
                                            let broker = broker.clone();
                                            let stop = command_stop.clone();
                                            let info = info.clone();
                                            let key = key.clone();
                                            let signing = cmd == "PKSIGN";
                                            tokio::task::spawn_blocking(move || {
                                                card::pin_description(
                                                    broker, stop, &info, &key, signing,
                                                )
                                            })
                                            .await??
                                        };
                                        let description = description
                                            .replace('%', "%25")
                                            .replace('\r', "%0D")
                                            .replace('\n', "%0A");
                                        send(
                                            &outputs,
                                            request,
                                            format!("INQUIRE NEEDPIN ||{description}")
                                                .as_str()
                                                .into(),
                                        )
                                        .await?;
                                        let pin = read_pin(&mut inputs, request).await?;
                                        let broker = broker.clone();
                                        let stop = command_stop.clone();
                                        let signing = cmd == "PKSIGN";
                                        let hash = args
                                            .split_ascii_whitespace()
                                            .find_map(|a| a.strip_prefix("--hash="))
                                            .unwrap_or("sha1")
                                            .to_owned();
                                        tokio::task::spawn_blocking(move || {
                                            card::private_operation(
                                                broker, stop, info, key, signing, hash, data, pin,
                                            )
                                        })
                                        .await?
                                    } else if cmd == "SERIALNO" {
                                        let cards = registry.lock().unwrap().clone();
                                        let query = SerialQuery {
                                            cards: &cards,
                                            selected_nfc: selected_nfc.lock().unwrap().clone(),
                                            broker: &broker,
                                            usb_present: usb_present.load(Ordering::Acquire),
                                            nfc_available: nfc_available.load(Ordering::Acquire),
                                        };
                                        match query.run(args, &app, &context, &command_stop).await?
                                        {
                                            Some(info) => {
                                                card_set.bind(info);
                                                card_set.card.command(&line)
                                            }
                                            None => Ok(AssuanResult::error(
                                                assuan::CARD_NOT_PRESENT,
                                                "Card not present",
                                            )),
                                        }
                                    } else {
                                        if matches!(cmd, "RESET" | "RESTART") {
                                            *prepared.lock().unwrap() = None;
                                        }
                                        let cards = usable(
                                            &registry.lock().unwrap(),
                                            nfc_available.load(Ordering::Acquire),
                                        );
                                        card_set.bind_if_unbound(prepared.lock().unwrap().clone());
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
// Presence queries never infer USB readiness from a saved registration.
// An explicitly selected NFC key is advertised without asking; only a demand
// for another registered NFC key may open an availability prompt.
struct SerialQuery<'a> {
    cards: &'a [RegisteredCard],
    selected_nfc: Option<String>,
    broker: &'a Arc<Broker>,
    usb_present: bool,
    nfc_available: bool,
}
impl SerialQuery<'_> {
    async fn run(
        &self,
        args: &str,
        app: &App,
        context: &ProviderContext,
        stop: &CancellationToken,
    ) -> Result<Option<CardInfo>> {
        let serial = args
            .split_ascii_whitespace()
            .find_map(|a| a.strip_prefix("--demand="));
        if self.usb_present && self.cards.iter().any(|c| c.usb_enabled) {
            let broker = self.broker.clone();
            let probe_stop = stop.child_token();
            let _guard = CancelOnDrop(probe_stop.clone());
            match tokio::task::spawn_blocking(move || {
                card::inspect(broker, probe_stop, CardTransport::Usb)
            })
            .await?
            {
                Ok(info)
                    if serial.is_none_or(|s| s.eq_ignore_ascii_case(&info.serial))
                        && self.cards.iter().any(|c| {
                            c.usb_enabled && c.card.serial.eq_ignore_ascii_case(&info.serial)
                        }) =>
                {
                    return Ok(Some(info));
                }
                Err(error) if card::operation_error(&error).canceled() => return Err(error),
                _ => {}
            }
        }
        let selected = self.selected_nfc.as_deref().and_then(|selected| {
            self.cards.iter().find(|c| {
                self.nfc_available
                    && c.nfc_enabled
                    && c.card.serial.eq_ignore_ascii_case(selected)
                    && serial.is_none_or(|s| s.eq_ignore_ascii_case(&c.card.serial))
            })
        });
        if let Some(entry) = selected {
            let mut info = entry.card.clone();
            info.transport = CardTransport::Nfc;
            return Ok(Some(info));
        }
        let nfc = serial.and_then(|serial| {
            self.cards.iter().find(|c| {
                c.nfc_enabled && self.nfc_available && c.card.serial.eq_ignore_ascii_case(serial)
            })
        });
        if let Some(entry) = nfc {
            confirm_card(app, context, self.broker, stop, &entry.card.serial, true).await?;
            let mut info = entry.card.clone();
            info.transport = CardTransport::Nfc;
            return Ok(Some(info));
        }
        Ok(None)
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
async fn read_pin(
    inputs: &mut mpsc::Receiver<SessionInput>,
    request: u64,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(128));
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
            return Ok(bytes);
        }
        if &*line == b"CAN" {
            return Err(crate::broker::RequestCancelled.into());
        }
        let assuan::Response::Data(raw) = assuan::parse_response(&line)? else {
            bail!("invalid PIN inquiry response")
        };
        let decoded = assuan::unescape(raw)?;
        if bytes.len() + decoded.len() > 128 {
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
        let provider = MobileProvider::new(Broker::new(), vec![]);
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
}

#[cfg(test)]
#[path = "cancellation_tests.rs"]
mod cancellation_tests;
