use crate::{
    broker::Broker,
    types::{NativeEvent, PinPrompt, PromptKind},
};
use anyhow::Result;
use hibiki_core::{provider::ProviderContext, storage::App};
use hibiki_lib::assuan::{self, AssuanResult};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

#[derive(Default)]
pub struct Pinentry {
    settings: HashMap<String, String>,
    timeout: u32,
}
impl Pinentry {
    pub async fn command(
        &mut self,
        line: &[u8],
        request: u64,
        app: &App,
        context: &ProviderContext,
        broker: &Arc<Broker>,
        stop: &CancellationToken,
    ) -> Result<AssuanResult> {
        let (cmd, args) = assuan::command(line)?;
        match cmd {
            "RESET" => *self = Self::default(),
            "NOP" | "BYE" => {}
            "GETINFO" => {
                let value = match args {
                    "version" => "1.0",
                    "flavor" => "hibiki-ios",
                    _ => {
                        return Ok(AssuanResult::error(
                            assuan::NO_DATA,
                            "process-local information",
                        ));
                    }
                };
                let mut lines = assuan::data_lines(value.as_bytes());
                lines.push("OK".into());
                return Ok(AssuanResult { lines });
            }
            "SETTIMEOUT" => self.timeout = args.parse()?,
            "OPTION" => {
                let (name, value) = args.split_once('=').unwrap_or((args, ""));
                let key = match name {
                    "default-ok" => "SETOK",
                    "default-cancel" => "SETCANCEL",
                    "default-prompt" => "SETPROMPT",
                    "default-title" => "SETTITLE",
                    "grab"
                    | "no-grab"
                    | "default-pwmngr"
                    | "default-cf-visi"
                    | "default-tt-visi"
                    | "default-tt-hide"
                    | "default-capshint"
                    | "default-tt-save"
                    | "invisible-char"
                    | "formatted-passphrase"
                    | "formatted-passphrase-hint" => return Ok(AssuanResult::ok()),
                    _ => {
                        return Ok(AssuanResult::error(
                            assuan::NOT_SUPPORTED,
                            "unsupported pinentry option",
                        ));
                    }
                };
                self.settings.entry(key.into()).or_insert(value.into());
            }
            "GETPIN" | "CONFIRM" | "MESSAGE" => {
                let state = app.proof(&context.channel)?.verify()?;
                let device = state.member(&context.peer)?;
                let get = |key: &str| self.settings.get(key).cloned().unwrap_or_default();
                let timeout = if self.timeout == 0 {
                    app.config.operation_timeout_seconds as u32
                } else {
                    self.timeout
                        .min(app.config.operation_timeout_seconds as u32)
                };
                let mut prompt = PinPrompt {
                    token: String::new(),
                    session: context.session.clone(),
                    request,
                    channel: state.name.clone(),
                    device_name: device.name.clone(),
                    device_id: context.peer.clone(),
                    kind: match cmd {
                        "GETPIN" => PromptKind::Pin,
                        "CONFIRM" if args != "--one-button" => PromptKind::Confirm,
                        _ => PromptKind::Message,
                    },
                    title: get("SETTITLE"),
                    description: get("SETDESC"),
                    label: get("SETPROMPT"),
                    error: get("SETERROR"),
                    // Collect one value. The requesting agent owns any new-passphrase
                    // confirmation; do not claim PIN_REPEATED without comparing inputs.
                    repeat: String::new(),
                    repeat_error: String::new(),
                    ok: get("SETOK"),
                    cancel: get("SETCANCEL"),
                    not_ok: get("SETNOTOK"),
                    timeout_seconds: timeout,
                };
                let answer = broker
                    .request(
                        |token| {
                            prompt.token = token;
                            NativeEvent::Prompt { prompt }
                        },
                        stop,
                        Duration::from_secs(timeout.into()),
                    )
                    .await;
                return Ok(match answer {
                    Ok(bytes) => {
                        let mut lines = if cmd == "GETPIN" {
                            assuan::data_lines(&bytes)
                        } else {
                            vec![]
                        };
                        lines.push("OK".into());
                        AssuanResult { lines }
                    }
                    Err(error) if error.is::<crate::broker::OperationCancelled>() => {
                        AssuanResult::error(assuan::CANCELED, "operation canceled by user")
                    }
                    Err(error) if error.is::<crate::broker::CandidateWithdrawn>() => {
                        return Err(error);
                    }
                    Err(_) => AssuanResult::error(assuan::CANCELED, "input canceled or timed out"),
                });
            }
            "SETDESC" | "SETPROMPT" | "SETTITLE" | "SETOK" | "SETCANCEL" | "SETNOTOK"
            | "SETERROR" | "SETREPEAT" | "SETREPEATERROR" | "SETREPEATOK" | "SETKEYINFO"
            | "SETQUALITYBAR" | "SETQUALITYBAR_TT" | "SETGENPIN" | "SETGENPIN_TT" => {
                let decoded = assuan::unescape(args.as_bytes())?;
                self.settings
                    .insert(cmd.into(), String::from_utf8_lossy(&decoded).into_owned());
            }
            _ => {
                return Ok(AssuanResult::error(
                    assuan::NOT_SUPPORTED,
                    "unsupported pinentry command",
                ));
            }
        }
        Ok(AssuanResult::ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MobileClient, create_identity};
    use hibiki_core::provider::Provider;
    use hibiki_lib::{
        channel::{ChannelGenesis, MembershipProof},
        protocol::ServiceKind,
    };
    use tokio::sync::Semaphore;

    #[tokio::test]
    async fn native_pinentry_preserves_escapes_and_cancels_stale_prompts() {
        let root = tempfile::tempdir().unwrap();
        let client = MobileClient::new(
            root.path().join("mobile").to_string_lossy().into(),
            "wss://example.com/hibiki".into(),
            create_identity("phone".into()).unwrap(),
            false,
        )
        .unwrap();
        let genesis =
            ChannelGenesis::create(&client.app.identity, "test".into(), "verifier").unwrap();
        let channel = genesis.body.id.clone();
        client
            .app
            .bootstrap(
                MembershipProof {
                    genesis,
                    events: vec![],
                },
                None,
            )
            .unwrap();
        client.set_services(true, false);
        let stop = CancellationToken::new();
        let mut ep = client
            .provider
            .open(
                client.app.clone(),
                ServiceKind::Pinentry,
                Arc::new(Semaphore::new(1)),
                stop.clone(),
                ProviderContext {
                    local: None,
                    channel,
                    peer: client.app.identity.device.id(),
                    session: "native-test".into(),
                },
            )
            .await
            .unwrap();
        for cmd in [
            "SETDESC first%0Asecond%25",
            "OPTION default-ok=Allow",
            "SETREPEAT Repeat",
            "SETREPEATERROR Mismatch",
        ] {
            ep.command(cmd.into()).await.unwrap();
            assert_eq!(&*ep.next().await.unwrap(), b"OK");
        }
        ep.command("GETPIN".into()).await.unwrap();
        let Some(NativeEvent::Prompt { prompt }) = client.broker.next().await else {
            panic!()
        };
        assert_eq!(prompt.description, "first\nsecond%");
        assert_eq!(prompt.ok, "Allow");
        assert!(prompt.repeat.is_empty());
        assert!(prompt.repeat_error.is_empty());
        assert_eq!(prompt.device_id, client.app.identity.device.id());
        let secret = b"p%\na\rss";
        client
            .broker
            .respond(&prompt.token, secret.to_vec(), true)
            .unwrap();
        let line = ep.next().await.unwrap();
        let assuan::Response::Data(raw) = assuan::parse_response(&line).unwrap() else {
            panic!()
        };
        assert_eq!(&*assuan::unescape(raw).unwrap(), secret);
        assert_eq!(&*ep.next().await.unwrap(), b"OK");
        assert!(
            client
                .broker
                .respond(&prompt.token, b"again".to_vec(), true)
                .is_err()
        );
        for (inserted, explicit_cancel, expected) in [
            (false, false, None),
            (true, false, Some(assuan::CANCELED)),
            (false, true, Some(assuan::CANCELED)),
            (true, true, Some(assuan::CANCELED)),
        ] {
            client.usb_present(inserted);
            ep.command("GETPIN".into()).await.unwrap();
            let token = loop {
                if let Some(NativeEvent::Prompt { prompt }) = client.broker.next().await {
                    break prompt.token;
                }
            };
            if explicit_cancel {
                client.cancel_request(token.clone(), true).unwrap();
            } else {
                client.dismiss_request(token.clone()).unwrap();
            }
            if let Some(expected) = expected {
                assert!(
                    matches!(assuan::parse_response(&ep.next().await.unwrap()).unwrap(), assuan::Response::Err(code) if code == expected)
                );
            } else {
                assert!(
                    ep.next()
                        .await
                        .unwrap_err()
                        .is::<hibiki_core::endpoint::CandidateIgnored>()
                );
            }
            assert!(!client.broker.pending(&token));
            assert!(client.respond(token, b"late reply".to_vec(), true).is_err());
        }
        ep.command("GETPIN".into()).await.unwrap();
        let token = loop {
            if let Some(NativeEvent::Prompt { prompt }) = client.broker.next().await {
                break prompt.token;
            }
        };
        ep.close().await;
        assert!(!client.broker.pending(&token));
        assert!(
            client
                .broker
                .respond(&token, b"too late".to_vec(), true)
                .is_err()
        );
    }
    #[tokio::test]
    async fn pin_timeout_closes_request_and_returns_cancellation() {
        let broker = Broker::new();
        let stop = CancellationToken::new();
        let b = broker.clone();
        let task = tokio::spawn(async move {
            b.request(
                |token| NativeEvent::Cancelled { token },
                &stop,
                Duration::from_millis(20),
            )
            .await
        });
        let Some(NativeEvent::Cancelled { token }) = broker.next().await else {
            panic!()
        };
        assert!(task.await.unwrap().is_err());
        assert!(!broker.pending(&token));
    }
}
