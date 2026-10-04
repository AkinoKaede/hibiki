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
    pub card: Mutex<Option<CardInfo>>,
    pub card_enabled: AtomicBool,
    pub pin_enabled: AtomicBool,
    pub usb_present: Arc<AtomicBool>,
    pub usb_enabled: Arc<AtomicBool>,
}
impl MobileProvider {
    pub fn new(broker: Arc<Broker>, card: Option<CardInfo>) -> Arc<Self> {
        Arc::new(Self {
            broker,
            card: Mutex::new(card),
            card_enabled: AtomicBool::new(false),
            pin_enabled: AtomicBool::new(false),
            usb_present: Arc::new(AtomicBool::new(false)),
            usb_enabled: Arc::new(AtomicBool::new(true)),
        })
    }
}
impl Provider for MobileProvider {
    fn enabled(&self, kind: ServiceKind) -> bool {
        match kind {
            ServiceKind::Pinentry => self.pin_enabled.load(Ordering::Acquire),
            ServiceKind::Scdaemon => {
                self.card_enabled.load(Ordering::Acquire) && self.card.lock().unwrap().is_some()
            }
        }
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
            let mut card = if kind == ServiceKind::Scdaemon {
                Some(CardSession::new(
                    self.card
                        .lock()
                        .unwrap()
                        .clone()
                        .context("no selected card")?,
                ))
            } else {
                None
            };
            let broker = self.broker.clone();
            let usb_present = self.usb_present.clone();
            let usb_enabled = self.usb_enabled.clone();
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
                                if let Some(card) = card.as_mut() {
                                    let (cmd, args) = assuan::command(&line)?;
                                    if matches!(cmd, "PKSIGN" | "PKDECRYPT") {
                                        let key = card.private_key(cmd, args)?;
                                        let mut info = card.info.clone();
                                        let connected_usb = usb_enabled.load(Ordering::Acquire)
                                            && usb_present.load(Ordering::Acquire);
                                        if !connected_usb {
                                            let state = app.proof(&context.channel)?.verify()?;
                                            let device = state.member(&context.peer)?;
                                            broker
                                                .request(
                                                    |token| NativeEvent::Prompt {
                                                        prompt: PinPrompt {
                                                            token,
                                                            session: context.session.clone(),
                                                            request,
                                                            channel: state.name.clone(),
                                                            device_name: device.name.clone(),
                                                            device_id: context.peer.clone(),
                                                            kind: if card.info.transport
                                                                == CardTransport::Usb
                                                            {
                                                                PromptKind::CardUsb
                                                            } else {
                                                                PromptKind::CardNfc
                                                            },
                                                            title: String::new(),
                                                            description: card.info.serial.clone(),
                                                            label: String::new(),
                                                            error: String::new(),
                                                            repeat: String::new(),
                                                            repeat_error: String::new(),
                                                            ok: String::new(),
                                                            cancel: String::new(),
                                                            not_ok: String::new(),
                                                            timeout_seconds: app
                                                                .config
                                                                .operation_timeout_seconds
                                                                as u32,
                                                        },
                                                    },
                                                    &command_stop,
                                                    Duration::from_secs(
                                                        app.config.operation_timeout_seconds,
                                                    ),
                                                )
                                                .await?;
                                        }
                                        let data = card.take_data();
                                        send(
                                            &outputs,
                                            request,
                                            "INQUIRE NEEDPIN ||Security key PIN".into(),
                                        )
                                        .await?;
                                        let pin = read_pin(&mut inputs, request).await?;
                                        // USB may have been inserted while confirming or entering the PIN.
                                        // Choose before opening the card; never switch after a failure.
                                        if usb_enabled.load(Ordering::Acquire)
                                            && usb_present.load(Ordering::Acquire)
                                        {
                                            info.transport = CardTransport::Usb;
                                        }
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
