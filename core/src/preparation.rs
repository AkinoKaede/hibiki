//! Card acquisition is distinct from both public metadata and private execution.
use crate::{
    endpoint::Endpoint,
    provider::{Provider, ProviderContext},
    storage::App,
};
use anyhow::{Context, Result, bail};
use hibiki_lib::{
    assuan::{self, AssuanResult, Line, Response},
    protocol::*,
};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Complete a public query even if preparation is canceled, so the connection
/// remains at an Assuan command boundary and can be reused safely.
pub async fn query(ep: &mut Endpoint, line: Line) -> Result<AssuanResult> {
    ep.command(line).await?;
    let mut result = AssuanResult::default();
    loop {
        let line = ep.next().await?;
        match assuan::parse_response(&line)? {
            Response::Inquire(args) if args.starts_with(b"KNOWNCARDP ") => {
                ep.answer("END".into()).await?
            }
            Response::Inquire(_) => bail!("unexpected card preparation inquiry"),
            Response::Ok | Response::Err(_) => {
                result.lines.push(line);
                return Ok(result);
            }
            _ => result.lines.push(line),
        }
    }
}
pub async fn probe(ep: &mut Endpoint, target: &CardTarget) -> Result<Option<String>> {
    target.validate()?;
    let command = target
        .serial
        .as_ref()
        .map(|s| format!("SERIALNO --demand={s} openpgp"))
        .unwrap_or_else(|| "SERIALNO openpgp".into());
    let result = query(ep, command.as_str().into()).await?;
    if !result.success() {
        return Ok(None);
    }
    let serial = result
        .lines
        .iter()
        .find_map(|l| {
            l.strip_prefix(b"S SERIALNO ")
                .and_then(|s| std::str::from_utf8(s).ok())
                .map(str::to_owned)
        })
        .context("missing card identity")?;
    if target
        .serial
        .as_ref()
        .is_some_and(|s| !s.eq_ignore_ascii_case(&serial))
    {
        return Ok(None);
    }
    if let Some(key) = &target.key
        && !query(ep, format!("READKEY {key}").as_str().into())
            .await?
            .success()
    {
        return Ok(None);
    }
    Ok(Some(serial))
}

/// Wrap a provider with a cancellable acquisition controller. The controller
/// owns the child for the entire session, including after another device wins.
pub fn wrap(
    mut native: Endpoint,
    provider: Arc<dyn Provider>,
    app: Arc<App>,
    context: ProviderContext,
) -> Endpoint {
    let stop = native.stop.clone();
    let cancel = stop.clone();
    let done = CancellationToken::new();
    let finished = done.clone();
    let (tx, mut inputs) = mpsc::channel::<SessionInput>(16);
    let (outputs, rx) = mpsc::channel(32);
    tokio::spawn(async move {
        let run = async {
            let mut deferred = None;
            let mut last = 0;
            let mut resume = None;
            let mut ready = false;
            loop {
                let input = match deferred.take() {
                    Some(input) => input,
                    None => match inputs.recv().await {
                        Some(i) => i,
                        None => break,
                    },
                };
                match input {
                    SessionInput::PrepareCard { id, target } => {
                        ready = false;
                        if !hibiki_lib::channel::valid_id(&id) {
                            bail!("invalid preparation ID");
                        }
                        target.validate()?;
                        outputs
                            .send(SessionOutput::CardStatus {
                                id: id.clone(),
                                state: CardPreparation::Waiting,
                            })
                            .await?;
                        let preparation_stop = cancel.child_token();
                        let preparation = provider.prepare(
                            app.clone(),
                            &mut native,
                            target.clone(),
                            preparation_stop.clone(),
                            context.clone(),
                        );
                        tokio::pin!(preparation);
                        let result = tokio::select! {
                            result = &mut preparation => Some(result),
                            input = inputs.recv() => {
                                preparation_stop.cancel();
                                // Finish a query already in flight; never leave stale responses.
                                let _ = preparation.await;
                                match input {
                                    Some(SessionInput::CancelPreparation { id: canceled }) if canceled == id => {},
                                    Some(input @ (SessionInput::Command { .. } | SessionInput::Execute { .. })) => {
                                        resume = Some(SessionInput::PrepareCard { id: id.clone(), target: target.clone() });
                                        deferred = Some(input);
                                    },
                                    other => deferred = other,
                                }
                                None
                            }
                        };
                        preparation_stop.cancel();
                        if resume.is_some() {
                            continue;
                        }
                        ready = matches!(result, Some(Ok(_)));
                        let state = match result {
                            Some(Ok(serial)) => CardPreparation::Ready { serial },
                            _ => CardPreparation::Unavailable,
                        };
                        outputs
                            .send(SessionOutput::CardStatus { id, state })
                            .await?;
                    }
                    SessionInput::CancelPreparation { .. } => {}
                    input => {
                        let (request, line, preparation) = match input {
                            SessionInput::Command { request, line } => (request, line, Vec::new()),
                            SessionInput::Execute {
                                request,
                                line,
                                preparation,
                            } => (request, line, preparation),
                            _ => bail!("unsolicited inquiry reply"),
                        };
                        if request != last + 1 {
                            bail!("out of order command");
                        }
                        last = request;
                        if preparation.len() > assuan::MAX_LINES
                            || preparation.iter().map(|l| l.len()).sum::<usize>() > assuan::MAX_DATA
                        {
                            bail!("preparation limit");
                        }
                        for setting in preparation {
                            assuan::validate_command(ServiceKind::Scdaemon, &setting)?;
                            if !matches!(assuan::command(&setting)?.0, "SETDATA" | "SWITCHAPP") {
                                bail!("invalid preparation command");
                            }
                            if !query(&mut native, setting).await?.success() {
                                bail!("preparation failed");
                            }
                        }
                        if matches!(assuan::command(&line)?.0, "PKSIGN" | "PKDECRYPT") && !ready {
                            bail!("card preparation required");
                        }
                        native.command(line).await?;
                        loop {
                            let line = native.next().await?;
                            let response = assuan::parse_response(&line)?;
                            let terminal = matches!(response, Response::Ok | Response::Err(_));
                            let inquiry = matches!(response, Response::Inquire(_));
                            outputs.send(SessionOutput::Line { request, line }).await?;
                            if inquiry {
                                loop {
                                    let Some(SessionInput::InquiryReply { request: id, line }) =
                                        inputs.recv().await
                                    else {
                                        bail!("inquiry reply required");
                                    };
                                    if id != request {
                                        bail!("inquiry ID mismatch");
                                    }
                                    let terminal = matches!(&*line, b"END" | b"CAN");
                                    native.answer(line).await?;
                                    if terminal {
                                        break;
                                    }
                                }
                            }
                            if terminal {
                                break;
                            }
                        }
                        deferred = resume.take();
                    }
                }
            }
            Ok::<_, anyhow::Error>(())
        };
        tokio::select! { _=cancel.cancelled()=>{}, result=run=>{ if result.is_err() { let _=outputs.try_send(SessionOutput::Failure); } } }
        native.close().await;
        finished.cancel();
    });
    Endpoint::new(tx, rx, stop, done)
}
