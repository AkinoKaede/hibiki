//! Card acquisition is distinct from both public metadata and private execution.
use crate::{
    endpoint::Endpoint,
    provider::{Preparation, PreparationDeclined, PreparationRejected, Provider, ProviderContext},
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

struct Acquisition {
    id: String,
    target: CardTarget,
    state: CardPreparation,
    preparation: Option<Box<dyn Preparation>>,
    retired: bool,
    withdrawn: bool,
}
impl Acquisition {
    async fn report(&mut self, outputs: &mpsc::Sender<SessionOutput>) -> Result<()> {
        outputs
            .send(SessionOutput::CardStatus {
                id: self.id.clone(),
                state: self.state.clone(),
            })
            .await?;
        Ok(())
    }
    async fn complete(
        &mut self,
        result: Result<Option<String>>,
        outputs: &mpsc::Sender<SessionOutput>,
    ) -> Result<()> {
        self.state = match result {
            Ok(None) => return Ok(()), // Paused for a query; preserve the prompt.
            Ok(Some(serial)) => CardPreparation::Ready { serial },
            Err(error) if error.is::<PreparationRejected>() => CardPreparation::Rejected,
            Err(error) if error.is::<PreparationDeclined>() => {
                self.withdrawn = true;
                CardPreparation::Unavailable
            }
            Err(_) => CardPreparation::Unavailable,
        };
        self.preparation = None;
        self.report(outputs).await
    }
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
            let mut last = 0;
            let mut acquisition: Option<Acquisition> = None;
            loop {
                let input = if let Some(current) = acquisition.as_mut()
                    && let Some(preparation) = current.preparation.as_mut()
                {
                    let pause = CancellationToken::new();
                    let (input, result) = {
                        let polling = preparation.poll(&mut native, pause.clone());
                        tokio::pin!(polling);
                        tokio::select! {
                            result = &mut polling => (None, result),
                            input = inputs.recv() => {
                                pause.cancel();
                                // Complete an in-flight Assuan query before borrowing the
                                // native endpoint. This does not cancel the prompt, and a
                                // concurrent terminal preparation result must not be lost.
                                (Some(input), polling.await)
                            }
                        }
                    };
                    current.complete(result, &outputs).await?;
                    match input {
                        None => continue,
                        Some(None) => break,
                        Some(Some(input)) => input,
                    }
                } else {
                    match inputs.recv().await {
                        Some(input) => input,
                        None => break,
                    }
                };
                match input {
                    SessionInput::PrepareCard { id, target } => {
                        if !hibiki_lib::channel::valid_id(&id) {
                            bail!("invalid preparation ID");
                        }
                        target.validate()?;
                        if let Some(current) = acquisition.as_mut()
                            && ((current.target == target && !current.retired)
                                || current.withdrawn
                                || matches!(current.state, CardPreparation::Rejected))
                        {
                            // Repeated notifications do not dismiss an unanswered prompt
                            // or resurrect a candidate the user already canceled.
                            current.id = id;
                            current.target = target;
                        } else {
                            drop(acquisition.take());
                            let preparation = provider
                                .prepare(app.clone(), target.clone(), context.clone())
                                .ok();
                            acquisition = Some(Acquisition {
                                id,
                                target,
                                state: if preparation.is_some() {
                                    CardPreparation::Waiting
                                } else {
                                    CardPreparation::Unavailable
                                },
                                preparation,
                                retired: false,
                                withdrawn: false,
                            });
                        }
                        acquisition.as_mut().unwrap().report(&outputs).await?;
                    }
                    SessionInput::CancelPreparation { id } => {
                        if let Some(current) = acquisition.as_mut()
                            && current.id == id
                        {
                            current.retired = true;
                            if current.preparation.take().is_some() {
                                current.state = CardPreparation::Unavailable;
                                current.report(&outputs).await?;
                            }
                        }
                        // A ready winner remains authorized to execute after the pool
                        // closes all insertion prompts with CancelPreparation.
                    }
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
                        let command = assuan::command(&line)?.0;
                        if matches!(command, "RESET" | "RESTART") {
                            drop(acquisition.take());
                        }
                        if matches!(command, "PKSIGN" | "PKDECRYPT")
                            && !acquisition.as_ref().is_some_and(|current| {
                                matches!(current.state, CardPreparation::Ready { .. })
                            })
                        {
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
