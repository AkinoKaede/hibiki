use crate::{
    assuan_io::{read_line, write_line, write_result},
    daemon::Hub,
    endpoint::Endpoint,
    frontend::LocalOpen,
    provider::LocalContext,
};
use anyhow::{Context, Result, bail};
use hibiki_core::operation::QueuedOperation;
use hibiki_lib::{
    assuan::{self, AssuanResult, Line, Response},
    protocol::{ServiceKind, TargetState},
};
use std::{collections::HashSet, sync::Arc, time::Duration};
use tokio::{
    net::{UnixStream, unix::OwnedWriteHalf},
    sync::{mpsc, oneshot},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Default)]
struct Settings(Vec<(String, Line)>);
impl Settings {
    fn insert(&mut self, key: String, line: Line) {
        self.0.retain(|(k, _)| k != &key);
        self.0.push((key, line));
    }
    fn remove(&mut self, key: &str) {
        self.0.retain(|(k, _)| k != key);
    }
    fn clear(&mut self) {
        self.0.clear();
    }
    fn len(&self) -> usize {
        self.0.len()
    }
    fn values(&self) -> impl Iterator<Item = &Line> {
        self.0.iter().map(|(_, l)| l)
    }
}

pub(crate) struct Inquiry {
    line: Line,
    reply: oneshot::Sender<Vec<Line>>,
}
pub(crate) async fn transaction(
    ep: &mut Endpoint,
    line: Line,
    inquiries: Option<&mpsc::Sender<Inquiry>>,
) -> Result<AssuanResult> {
    ep.command(line).await?;
    collect(ep, inquiries).await
}
pub(crate) async fn collect(
    ep: &mut Endpoint,
    inquiries: Option<&mpsc::Sender<Inquiry>>,
) -> Result<AssuanResult> {
    let mut result = AssuanResult::default();
    loop {
        let line = ep.next().await?;
        match assuan::parse_response(&line)? {
            Response::Inquire(args) => {
                if let Some(tx) = inquiries {
                    let (reply, rx) = oneshot::channel();
                    tx.send(Inquiry { line, reply }).await?;
                    for line in rx.await? {
                        ep.answer(line).await?;
                    }
                } else if args.starts_with(b"KNOWNCARDP ") {
                    ep.answer("END".into()).await?;
                } else {
                    bail!("unexpected inquiry during discovery or setup");
                }
            }
            Response::Ok | Response::Err(_) => {
                result.lines.push(line);
                result.validate()?;
                return Ok(result);
            }
            _ => result.lines.push(line),
        }
    }
}
async fn upstream_inquiry(
    inquiry: Inquiry,
    writer: &mut OwnedWriteHalf,
    inputs: &mut mpsc::Receiver<Line>,
) -> Result<()> {
    write_line(writer, &inquiry.line).await?;
    let mut reply = Vec::new();
    let mut size = 0;
    loop {
        let line = inputs
            .recv()
            .await
            .context("caller disconnected during inquiry")?;
        size += line.len();
        if size > assuan::MAX_DATA || reply.len() >= assuan::MAX_LINES {
            bail!("inquiry reply limit");
        }
        let end = &*line == b"END" || &*line == b"CAN";
        if !end {
            let Response::Data(d) = assuan::parse_response(&line)? else {
                bail!("invalid inquiry reply");
            };
            assuan::unescape(d)?;
        }
        reply.push(line);
        if end {
            break;
        }
    }
    let _ = inquiry.reply.send(reply);
    Ok(())
}
// The local candidate never awaits relay control traffic. Keep remote discovery,
// queue registration and completion in a separate task, including during reconnect.
async fn password_race(
    hub: Arc<Hub>,
    open: &LocalOpen,
    settings: &Settings,
    line: Line,
    stop: &CancellationToken,
    writer: &mut OwnedWriteHalf,
    inputs: &mut mpsc::Receiver<Line>,
) -> Result<AssuanResult> {
    let mut targets = hub.eligible(&open.channel, ServiceKind::Pinentry)?;
    let local = hub.app.identity.device.id();
    let mut tasks = JoinSet::new();
    let (tx, mut inquiries) = mpsc::channel(32);
    if targets.contains(&local) {
        targets.retain(|peer| peer != &local);
        let hub = hub.clone();
        let open = open.clone();
        let settings = settings.clone();
        let line = line.clone();
        let stop = stop.child_token();
        let tx = tx.clone();
        tasks.spawn(async move {
            let mut ep = hub
                .open(
                    &open.channel,
                    &local,
                    ServiceKind::Pinentry,
                    stop,
                    LocalContext {
                        display: open.display.clone(),
                    },
                )
                .await?
                .context("local pinentry disabled")?;
            for setting in settings.values() {
                let result = transaction(&mut ep, setting.clone(), None).await?;
                if !result.success() {
                    return Ok(Some(result));
                }
            }
            transaction(&mut ep, line, Some(&tx)).await.map(Some)
        });
    }
    if !targets.is_empty() {
        let open = open.clone();
        let settings = settings.clone();
        let stop = stop.child_token();
        tasks.spawn(async move {
            password_remote(hub, &open, &settings, line, &stop, tx, targets).await
        });
    }
    let mut canceled = None;
    let mut failed = None;
    loop {
        tokio::select! {
            Some(inquiry) = inquiries.recv() => upstream_inquiry(inquiry, writer, inputs).await?,
            result = tasks.join_next() => match result {
                Some(Ok(Ok(Some(result)))) if result.success() => return Ok(result),
                Some(Ok(Ok(Some(mut result)))) => {
                    // Failed candidates may have emitted partial password data.
                    // Preserve only the native terminal error, never that data.
                    let terminal = result.lines.pop().context("missing pinentry result")?;
                    result.lines.clear();
                    result.lines.push(terminal);
                    if result.fully_canceled() { return Ok(result); }
                    if result.canceled() { canceled = Some(result); }
                    else { failed = Some(result); }
                },
                Some(Ok(Ok(None))) => {},
                Some(_) => failed = Some(AssuanResult::error(assuan::GENERAL, "pinentry candidate failed")),
                None => return Ok(failed.or(canceled).unwrap_or_else(||
                    AssuanResult::error(assuan::GENERAL, "no pinentry providers"))),
            }
        }
    }
}

async fn password_remote(
    hub: Arc<Hub>,
    open: &LocalOpen,
    settings: &Settings,
    line: Line,
    stop: &CancellationToken,
    tx: mpsc::Sender<Inquiry>,
    targets: Vec<String>,
) -> Result<Option<AssuanResult>> {
    if targets.is_empty() {
        bail!("no pinentry providers");
    }
    let operation = Arc::new(
        QueuedOperation::new(hub.clone(), &open.channel, ServiceKind::Pinentry, targets).await?,
    );
    let mut tasks = JoinSet::new();
    let mut running = HashSet::new();
    let mut failures = 0;
    let mut canceled = None;
    let mut failed = None;
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    loop {
        tokio::select! {
            _=tick.tick()=>{
                let status=operation.status().await?;
                for peer in operation.ready().await? {
                    if !running.insert(peer.clone()) { continue; }
                    let hub=hub.clone(); let channel=open.channel.clone(); let stop=stop.child_token();
                    let settings=settings.clone(); let line=line.clone(); let tx=tx.clone();
                    let context=LocalContext { display: open.display.clone() };
                    let operation=operation.clone();
                    tasks.spawn(async move {
                        let result=async {
                            let Some(mut ep)=hub.open(&channel, &peer, ServiceKind::Pinentry, stop, context).await? else { return Ok(None); };
                            for setting in settings.values() {
                                let (cmd,args)=assuan::command(setting)?;
                                if cmd == "OPTION" && assuan::local_option(args) { continue; }
                                let result=transaction(&mut ep,setting.clone(),None).await?;
                                if !result.success() { return Ok(Some(result)); }
                            }
                            ep.bind_operation(Some(operation.value.id.clone()));
                            let watching=operation.watch(ep.stop.clone());
                            let result=transaction(&mut ep,line,Some(&tx)).await;
                            watching.abort();
                            drop(ep);
                            result.map(Some)
                        }.await;
                        (peer,result)
                    });
                }
                if tasks.is_empty() && status.targets.iter().all(|t| t.state != TargetState::Pending) {
                    operation.finish(false).await?;
                    if failures == 0 && canceled.is_none() { return Ok(None); }
                    return Ok(Some(AssuanResult { lines: vec![(if failures == 0 { canceled } else { failed }).unwrap_or_else(||assuan::error(assuan::GENERAL,"no pinentry candidate completed; execution result may be unknown"))] }));
                }
            },
            result=tasks.join_next(), if !tasks.is_empty()=>{
                if let Some(Ok((peer,result)))=result {
                    running.remove(&peer);
                    match result {
                        Ok(Some(result)) if result.success()=>{ operation.finish(true).await?; return Ok(Some(result)); },
                        Ok(Some(mut result)) if result.fully_canceled()=>{
                            let terminal=result.lines.pop().context("missing pinentry cancellation")?;
                            // Returning drops the remaining candidates immediately. Queue
                            // cleanup must not delay cancellation behind relay traffic.
                            let operation=operation.clone();
                            tokio::spawn(async move { let _=operation.finish(false).await; });
                            return Ok(Some(AssuanResult { lines: vec![terminal] }));
                        },
                        Ok(Some(mut result)) if result.canceled()=>canceled=result.lines.pop(),
                        Ok(Some(mut result))=>{failures+=1;failed=result.lines.pop();},
                        Ok(None)=>{},
                        Err(_)=>failures+=1,
                    }
                    if !hub.connection().closed.is_cancelled() {
                        let online=hub.peers(&open.channel).await.unwrap_or_default();
                        if online.contains(&peer) || peer == hub.app.identity.device.id() { operation.abandon(&peer).await?; }
                    }
                }
            }
        }
    }
}

fn local_info(service: ServiceKind, args: &str, pid: u32) -> AssuanResult {
    let value = match args {
        "pid" => pid.to_string(),
        "version" => if service == ServiceKind::Scdaemon {
            "2.4.0"
        } else {
            "1.3.0"
        }
        .into(),
        "flavor" if service == ServiceKind::Pinentry => "hibiki".into(),
        "ttyinfo" if service == ServiceKind::Pinentry => "- - -".into(),
        "socket_name" => return AssuanResult::error(assuan::NO_DATA, "stdio only"),
        "deny_admin" if service == ServiceKind::Scdaemon => return AssuanResult::ok(),
        _ => return AssuanResult::error(assuan::NOT_SUPPORTED, "unsupported capability"),
    };
    let mut lines = assuan::data_lines(value.as_bytes());
    lines.push("OK".into());
    AssuanResult { lines }
}

#[derive(Default)]
struct CardState {
    peer: String,
    public_source: String,
    serial: String,
    preparation: Vec<Line>,
}
impl CardState {
    fn observe_serial(&mut self, command: &str, result: &AssuanResult) {
        // Inventory responses may contain several cards. Enumerating them must
        // not silently bind the next private operation to the first one.
        if !matches!(command, "SERIALNO" | "SWITCHCARD" | "LEARN" | "GETATTR") {
            return;
        }
        if let Some(serial) = result.lines.iter().find_map(|line| {
            line.strip_prefix(b"S SERIALNO ")
                .and_then(|value| std::str::from_utf8(value).ok())
        }) {
            self.serial = serial.to_owned();
        }
    }
    fn remember(&mut self, line: &Line) -> Result<()> {
        let (cmd, args) = assuan::command(line)?;
        if cmd == "SETDATA" {
            if !args.starts_with("--append ") {
                self.preparation.retain(|l| !l.starts_with(b"SETDATA "));
            }
            self.preparation.push(line.clone());
        } else if cmd == "SWITCHAPP" {
            self.preparation.retain(|l| !l.starts_with(b"SWITCHAPP "));
            self.preparation.insert(0, line.clone());
        }
        if self.preparation.len() > assuan::MAX_LINES
            || self.preparation.iter().map(|l| l.len()).sum::<usize>() > assuan::MAX_DATA
        {
            bail!("card preparation limit");
        }
        Ok(())
    }
}

pub async fn serve(hub: Arc<Hub>, stream: UnixStream, open: LocalOpen) -> Result<()> {
    hub.authorized(&open.channel, &hub.app.identity.device.id())?;
    let lease = hub.track_local(&open.channel)?;
    let stop = lease.stop.clone();
    let (reader, mut writer) = stream.into_split();
    let (tx, mut inputs) = mpsc::channel(32);
    let reader_stop = stop.clone();
    let reader_task = tokio::spawn(async move {
        let mut reader = crate::assuan_io::SecretReader::new(reader);
        let reading = async {
            while let Some(line) = read_line(&mut reader).await? {
                tx.send(line).await?;
            }
            Ok::<_, anyhow::Error>(())
        };
        tokio::select! {_=reader_stop.cancelled()=>{},_=reading=>{}}
        reader_stop.cancel();
    });
    let result = async {
        write_line(&mut writer, b"OK HIbiki Assuan stdio service").await?;
        let pool = (open.service == ServiceKind::Scdaemon)
            .then(|| crate::card_pool::Pool::start(hub.clone(), open.clone(), stop.clone()));
        let mut card_state = CardState::default();
        let mut settings = Settings::default();
        let mut broken = false;
        while let Some(line) = inputs.recv().await {
            hub.authorized(&open.channel, &hub.app.identity.device.id())?;
            let (cmd, args) = match assuan::command(&line) {
                Ok(c) => c,
                Err(_) => {
                    write_line(
                        &mut writer,
                        &assuan::error(assuan::NOT_SUPPORTED, "invalid command"),
                    )
                    .await?;
                    continue;
                }
            };
            if matches!(cmd, "BYE" | "KILLSCD") {
                write_line(&mut writer, b"OK closing connection").await?;
                break;
            }
            if open.service == ServiceKind::Scdaemon && cmd == "OPTION" {
                write_line(
                    &mut writer,
                    &assuan::error(
                        assuan::NOT_SUPPORTED,
                        "stdio service does not use event signals",
                    ),
                )
                .await?;
                continue;
            }
            if assuan::validate_command(open.service, &line).is_err() {
                write_line(
                    &mut writer,
                    &assuan::error(assuan::NOT_SUPPORTED, "unsupported service command"),
                )
                .await?;
                continue;
            }
            let started = std::time::Instant::now();
            let operation = async {
                if cmd == "GETINFO"
                    && (open.service == ServiceKind::Pinentry
                        || matches!(args, "pid" | "version" | "socket_name" | "deny_admin")
                        || args.starts_with("cmd_has_option "))
                {
                    return Ok::<_, anyhow::Error>(local_info(open.service, args, open.pid));
                }
                if cmd == "NOP" {
                    return Ok(AssuanResult::ok());
                }
                if open.service == ServiceKind::Pinentry {
                    if cmd == "RESET" {
                        settings.clear();
                        return Ok(AssuanResult::ok());
                    }
                    if matches!(cmd, "GETPIN" | "CONFIRM" | "MESSAGE") {
                        let result = password_race(
                            hub.clone(),
                            &open,
                            &settings,
                            line.clone(),
                            &stop,
                            &mut writer,
                            &mut inputs,
                        )
                        .await;
                        // Native pinentry consumes SETERROR on each dialog, including canceled dialogs.
                        settings.remove("SETERROR");
                        return result;
                    }
                    if cmd == "OPTION"
                        && matches!(
                            args.split('=').next(),
                            Some(
                                "allow-external-password-cache"
                                    | "touch-file"
                                    | "allow-emacs-prompt"
                            )
                        )
                    {
                        return Ok(AssuanResult::ok());
                    }
                    let key = if cmd == "OPTION" {
                        format!("OPTION {}", args.split('=').next().unwrap_or(""))
                    } else {
                        cmd.into()
                    };
                    settings.insert(key, line.clone());
                    if settings.len() > 128 {
                        bail!("pinentry settings limit");
                    }
                    return Ok(AssuanResult::ok());
                }
                let pool = pool.as_ref().context("card pool missing")?;
                if matches!(cmd, "RESET" | "RESTART") {
                    pool.reset(line.clone()).await;
                    broken = false;
                    card_state = CardState::default();
                    return Ok(AssuanResult::ok());
                }
                if matches!(cmd, "SERIALNO" | "SWITCHCARD") {
                    broken = false;
                    card_state.peer.clear();
                    card_state.public_source.clear();
                    card_state.serial = args
                        .split_ascii_whitespace()
                        .find_map(|a| a.strip_prefix("--demand="))
                        .unwrap_or(if cmd == "SWITCHCARD" { args } else { "" })
                        .to_string();
                    pool.prepare(hibiki_lib::protocol::CardTarget {
                        serial: (!card_state.serial.is_empty()).then(|| card_state.serial.clone()),
                        key: None,
                    });
                }
                if broken {
                    bail!("card session failed; reset before a new operation");
                }
                if cmd == "SETDATA" {
                    card_state.remember(&line)?;
                    return Ok(AssuanResult::ok());
                }
                if matches!(cmd, "PKSIGN" | "PKDECRYPT") {
                    let key = args
                        .split_ascii_whitespace()
                        .rfind(|a| !a.starts_with("--"))
                        .map(str::to_owned);
                    pool.prepare(hibiki_lib::protocol::CardTarget {
                        serial: (!card_state.serial.is_empty()).then(|| card_state.serial.clone()),
                        key,
                    });
                    let peer = pool.ready().await?;
                    card_state.peer = peer.clone();
                    pool.cancel_prompts();
                    let operation = if peer == hub.app.identity.device.id() {
                        None
                    } else {
                        Some(
                            QueuedOperation::new(
                                hub.clone(),
                                &open.channel,
                                ServiceKind::Scdaemon,
                                vec![peer.clone()],
                            )
                            .await?,
                        )
                    };
                    let (tx, mut inquiries) = mpsc::channel(8);
                    let execute = pool.execute(
                        &peer,
                        line.clone(),
                        card_state.preparation.clone(),
                        operation.as_ref().map(|op| op.value.id.clone()),
                        tx,
                    );
                    tokio::pin!(execute);
                    let result = loop {
                        tokio::select! {
                            result=&mut execute=>break result,
                            Some(inquiry)=inquiries.recv()=>upstream_inquiry(inquiry,&mut writer,&mut inputs).await?,
                        }
                    };
                    card_state.preparation.clear();
                    let result = result.map_err(|_| {
                        anyhow::anyhow!(
                            "execution result unknown; private operation will not be repeated"
                        )
                    })?;
                    if let Some(operation) = operation {
                        let success = result.success();
                        tokio::spawn(async move {
                            let _ = operation.finish(success).await;
                        });
                    }
                    if !result.success() {
                        broken = true;
                    }
                    return Ok(result);
                }
                let result = if card_state.public_source.is_empty() {
                    let (peer, result) = pool.query(line.clone()).await?;
                    card_state.public_source = peer;
                    result
                } else {
                    pool.query_from(&card_state.public_source, line.clone())
                        .await?
                };
                card_state.observe_serial(cmd, &result);
                if result.success() {
                    card_state.remember(&line)?;
                }
                Ok(result)
            };
            let outcome = tokio::time::timeout(
                Duration::from_secs(hub.app.config.operation_timeout_seconds),
                operation,
            )
            .await;
            let unknown = matches!(&outcome, Ok(Err(error)) if error.to_string().contains("execution result unknown"));
            let rejected = matches!(&outcome, Ok(Err(error)) if error.is::<hibiki_core::provider::PreparationRejected>());
            let result = match outcome {
                Ok(Ok(result)) => result,
                _ => {
                    if let Some(pool) = &pool {
                        // The command deadline also ends its acquisition UI, even
                        // when no candidate has supplied public metadata yet.
                        pool.cancel_prompts();
                    }
                    if open.service == ServiceKind::Scdaemon
                        && (rejected
                            || !card_state.peer.is_empty()
                            || !card_state.public_source.is_empty())
                    {
                        broken = true;
                    }
                    AssuanResult::error(
                        if rejected {
                            assuan::CANCELED
                        } else {
                            assuan::GENERAL
                        },
                        if rejected {
                            "card operation rejected by user"
                        } else if unknown {
                            "execution result unknown; do not retry automatically"
                        } else {
                            "service unavailable, failed or timed out"
                        },
                    )
                }
            };
            tracing::debug!(service=?open.service,command=cmd,success=result.success(),elapsed_us=started.elapsed().as_micros(),"Assuan result");
            write_result(&mut writer, &result).await?;
        }
        Ok::<_, anyhow::Error>(())
    };
    let outcome = tokio::select! {_=stop.cancelled()=>Ok(()),result=result=>result};
    stop.cancel();
    reader_task.abort();
    outcome
}

#[cfg(test)]
mod card_state_tests {
    use super::*;
    #[test]
    fn enumeration_does_not_select_the_first_registered_card() {
        let mut state = CardState::default();
        let inventory = AssuanResult {
            lines: vec![
                "S SERIALNO first".into(),
                "S SERIALNO second".into(),
                "OK".into(),
            ],
        };
        state.observe_serial("GETINFO", &inventory);
        assert!(state.serial.is_empty());
        state.observe_serial(
            "SWITCHCARD",
            &AssuanResult {
                lines: vec!["S SERIALNO second".into(), "OK".into()],
            },
        );
        state.observe_serial("GETINFO", &inventory);
        assert_eq!(state.serial, "second");
    }
}
