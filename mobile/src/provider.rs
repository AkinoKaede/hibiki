use crate::{
    broker::Broker,
    card::{self, CardSession},
    pinentry::Pinentry,
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
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Semaphore, mpsc};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

pub struct MobileProvider {
    pub broker: Arc<Broker>,
    pub card: Arc<Mutex<Option<CardInfo>>>,
    pub card_enabled: AtomicBool,
    pub pin_enabled: AtomicBool,
    pub usb_present: Arc<AtomicBool>,
    pub usb_enabled: Arc<AtomicBool>,
    prepared_transport: Arc<Mutex<Option<CardTransport>>>,
}
impl MobileProvider {
    pub fn new(broker: Arc<Broker>, card: Option<CardInfo>) -> Arc<Self> {
        Arc::new(Self {
            broker,
            card: Arc::new(Mutex::new(card)),
            card_enabled: AtomicBool::new(false),
            pin_enabled: AtomicBool::new(false),
            usb_present: Arc::new(AtomicBool::new(false)),
            usb_enabled: Arc::new(AtomicBool::new(true)),
            prepared_transport: Arc::new(Mutex::new(None)),
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
    fn prepare<'a>(
        &'a self,
        app: Arc<App>,
        _endpoint: &'a mut Endpoint,
        target: hibiki_lib::protocol::CardTarget,
        stop: CancellationToken,
        context: ProviderContext,
    ) -> hibiki_core::provider::PrepareFuture<'a> {
        Box::pin(async move {
            target.validate()?;
            *self.prepared_transport.lock().unwrap() = None;
            let registered = self
                .card
                .lock()
                .unwrap()
                .clone()
                .filter(|info| matches_target(info, &target));
            let nfc = registered
                .as_ref()
                .is_some_and(|info| info.transport != CardTransport::Usb);
            let state = app.proof(&context.channel)?.verify()?;
            let device = state.member(&context.peer)?;
            let prompt_stop = stop.child_token();
            let _guard = CancelOnDrop(prompt_stop.clone());
            let make_prompt = || {
                self.broker.request(
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
                            description: hibiki_lib::card_prompt::description(
                                target
                                    .serial
                                    .as_deref()
                                    .or_else(|| registered.as_ref().map(|c| c.serial.as_str())),
                                None,
                            ),
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
                    &prompt_stop,
                    Duration::from_secs(app.config.operation_timeout_seconds),
                )
            };
            let mut prompt = Box::pin(make_prompt());
            let mut acknowledged = false;
            loop {
                if stop.is_cancelled() {
                    bail!("card preparation canceled");
                }
                if self.usb_enabled.load(Ordering::Acquire)
                    && self.usb_present.load(Ordering::Acquire)
                {
                    let broker = self.broker.clone();
                    let token = stop.child_token();
                    if let Ok(Ok(info)) = tokio::task::spawn_blocking(move || {
                        card::inspect(broker, token, CardTransport::Usb)
                    })
                    .await
                        && matches_target(&info, &target)
                    {
                        *self.prepared_transport.lock().unwrap() = Some(CardTransport::Usb);
                        return Ok(info.serial);
                    }
                }
                if acknowledged && nfc {
                    *self.prepared_transport.lock().unwrap() = Some(CardTransport::Nfc);
                    return Ok(registered.as_ref().unwrap().serial.clone());
                }
                tokio::select! {
                    _=stop.cancelled()=>bail!("card preparation canceled"),
                    result=&mut prompt, if !acknowledged=>{
                        result?;
                        if nfc { acknowledged = true; } else { prompt = Box::pin(make_prompt()); }
                    },
                    _=tokio::time::sleep(Duration::from_millis(300))=>{},
                }
            }
        })
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
            let registry = self.card.clone();
            let mut card = registry.lock().unwrap().clone().map(CardSession::new);
            let broker = self.broker.clone();
            let usb_present = self.usb_present.clone();
            let usb_enabled = self.usb_enabled.clone();
            let prepared_transport = self.prepared_transport.clone();
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
                                if kind == ServiceKind::Scdaemon && card.is_none() {
                                    card = registry.lock().unwrap().clone().map(CardSession::new);
                                }
                                if let Some(card) =
                                    card.as_mut().filter(|_| kind == ServiceKind::Scdaemon)
                                {
                                    let (cmd, args) = assuan::command(&line)?;
                                    if matches!(cmd, "PKSIGN" | "PKDECRYPT") {
                                        let key = card.private_key(cmd, args)?;
                                        let mut info = card.info.clone();
                                        let connected_usb = usb_enabled.load(Ordering::Acquire)
                                            && usb_present.load(Ordering::Acquire);
                                        if !connected_usb
                                            && card.info.transport == CardTransport::Usb
                                        {
                                            bail!("USB card must be connected");
                                        }
                                        let data = card.take_data();
                                        info.transport = prepared_transport
                                            .lock()
                                            .unwrap()
                                            .clone()
                                            .context("card preparation required")?;
                                        let description = {
                                            let broker = broker.clone();
                                            let stop = command_stop.child_token();
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
                                    } else {
                                        card.command(&line)
                                    }
                                } else if kind == ServiceKind::Scdaemon {
                                    Ok(AssuanResult::error(108, "card not present"))
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
            bail!("PIN inquiry canceled");
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

fn matches_target(info: &CardInfo, target: &hibiki_lib::protocol::CardTarget) -> bool {
    if target
        .serial
        .as_ref()
        .is_some_and(|s| !s.eq_ignore_ascii_case(&info.serial))
    {
        return false;
    }
    target.key.as_ref().is_none_or(|key| {
        CardSession::new(info.clone())
            .command(format!("READKEY {key}").as_bytes())
            .is_ok_and(|r| r.success())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CardTransport;
    #[test]
    fn registered_cards_advertise_only_when_service_enabled() {
        let provider = MobileProvider::new(
            Broker::new(),
            Some(CardInfo {
                serial: "test".into(),
                transport: CardTransport::Nfc,
                keys: vec![],
            }),
        );
        assert!(!provider.enabled(ServiceKind::Scdaemon));
        provider.card_enabled.store(true, Ordering::Release);

        assert!(provider.enabled(ServiceKind::Scdaemon));
        provider.card.lock().unwrap().as_mut().unwrap().transport = CardTransport::Usb;
        assert!(provider.enabled(ServiceKind::Scdaemon));
        provider.usb_present.store(true, Ordering::Release);
        assert!(provider.enabled(ServiceKind::Scdaemon));
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
