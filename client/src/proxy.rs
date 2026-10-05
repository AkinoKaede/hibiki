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
    fn reset(&mut self) {
        // pinentry_reset preserves these process options, not every OPTION.
        // In particular, formatted-passphrase and its hint are dialog state.
        self.0.retain(|(key, _)| {
            matches!(
                key.as_str(),
                "SETTIMEOUT"
                    | "OPTION grab"
                    | "OPTION no-grab"
                    | "OPTION ttyname"
                    | "OPTION ttytype"
                    | "OPTION lc-ctype"
                    | "OPTION lc-messages"
                    | "OPTION display"
                    | "OPTION owner"
                    | "OPTION default-ok"
                    | "OPTION default-cancel"
                    | "OPTION default-prompt"
                    | "OPTION default-pwmngr"
                    | "OPTION default-cf-visi"
                    | "OPTION default-tt-visi"
                    | "OPTION default-tt-hide"
                    | "OPTION default-capshint"
                    | "OPTION constraints-enforce"
                    | "OPTION constraints-hint-short"
                    | "OPTION constraints-hint-long"
                    | "OPTION constraints-error-title"
                    | "OPTION invisible-char"
            )
        });
    }
    fn finish_dialog(&mut self, command: &str) {
        self.remove("SETERROR");
        self.remove("SETQUALITYBAR");
        if command == "GETPIN" {
            self.remove("SETREPEAT");
        }
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
                    if result.canceled() { return Ok(result); }
                    failed = Some(result);
                },
                Some(Ok(Ok(None))) => {},
                Some(Ok(Err(error))) if error.is::<hibiki_core::endpoint::CandidateIgnored>() => {},
                Some(_) => failed = Some(AssuanResult::error(assuan::GENERAL, "pinentry candidate failed")),
                None => return Ok(failed.unwrap_or_else(||
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
                    if failures == 0 { return Ok(None); }
                    return Ok(Some(AssuanResult { lines: vec![failed.unwrap_or_else(||assuan::error(assuan::GENERAL,"no pinentry candidate completed; execution result may be unknown"))] }));
                }
            },
            result=tasks.join_next(), if !tasks.is_empty()=>{
                if let Some(Ok((peer,result)))=result {
                    running.remove(&peer);
                    match result {
                        Ok(Some(result)) if result.success()=>{ operation.finish(true).await?; return Ok(Some(result)); },
                        Ok(Some(mut result)) if result.canceled()=>{
                            let terminal=result.lines.pop().context("missing pinentry cancellation")?;
                            // Returning drops the remaining candidates immediately. Queue
                            // cleanup must not delay cancellation behind relay traffic.
                            let operation=operation.clone();
                            tokio::spawn(async move { let _=operation.finish(false).await; });
                            return Ok(Some(AssuanResult { lines: vec![terminal] }));
                        },
                        Ok(Some(mut result))=>{failures+=1;failed=result.lines.pop();},
                        Ok(None)=>{},
                        Err(error) if error.is::<hibiki_core::endpoint::CandidateIgnored>()=>{},
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
    let mut words = args.split_ascii_whitespace();
    if service == ServiceKind::Scdaemon && words.next() == Some("cmd_has_option") {
        let (Some(command), Some(option)) = (words.next(), words.next()) else {
            return AssuanResult::error(assuan::MISSING_VALUE, "command and option required");
        };
        // GnuPG 2.4's capability table advertises only SERIALNO's all option.
        return if command == "SERIALNO" && option == "all" && words.next().is_none() {
            AssuanResult::ok()
        } else {
            AssuanResult::error(assuan::FALSE, "command option not advertised")
        };
    }
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
        if !result.success() || !matches!(command, "SERIALNO" | "SWITCHCARD" | "LEARN" | "GETATTR")
        {
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
                    &assuan::error(
                        if open.service == ServiceKind::Pinentry && cmd == "OPTION" {
                            assuan::UNKNOWN_OPTION
                        } else {
                            assuan::NOT_SUPPORTED
                        },
                        "unsupported service command",
                    ),
                )
                .await?;
                continue;
            }
            let started = std::time::Instant::now();
            let mut query_failures = crate::card_pool::QueryFailures::default();
            let operation = async {
                if cmd == "GETINFO"
                    && (open.service == ServiceKind::Pinentry
                        || matches!(args, "pid" | "version" | "socket_name" | "deny_admin")
                        || args.split_ascii_whitespace().next() == Some("cmd_has_option"))
                {
                    return Ok::<_, anyhow::Error>(local_info(open.service, args, open.pid));
                }
                if cmd == "NOP" {
                    return Ok(AssuanResult::ok());
                }
                if open.service == ServiceKind::Pinentry {
                    if cmd == "RESET" {
                        settings.reset();
                        return Ok(AssuanResult::ok());
                    }
                    if matches!(cmd, "GETPIN" | "CONFIRM" | "MESSAGE") {
                        return password_race(
                            hub.clone(),
                            &open,
                            &settings,
                            line.clone(),
                            &stop,
                            &mut writer,
                            &mut inputs,
                        )
                        .await;
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
                    let (peer, result) = pool.query(line.clone(), &mut query_failures).await?;
                    if result.success() {
                        card_state.public_source = peer;
                    }
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
            // Consume dialog state even when the outer deadline drops the race.
            if open.service == ServiceKind::Pinentry
                && matches!(cmd, "GETPIN" | "CONFIRM" | "MESSAGE")
            {
                settings.finish_dialog(cmd);
            }
            let unknown = matches!(&outcome, Ok(Err(error)) if error.to_string().contains("execution result unknown"));
            let rejected = matches!(&outcome, Ok(Err(error)) if error.is::<hibiki_core::provider::PreparationRejected>());
            let result = match outcome {
                Ok(Ok(result)) => result,
                Err(_) if !query_failures.is_empty() => {
                    if let Some(pool) = &pool {
                        pool.cancel_prompts();
                    }
                    // A definitive public-query error is a normal Assuan result,
                    // not a broken session or a generic transport timeout.
                    query_failures.take_first().unwrap().1
                }
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
    fn settings(lines: &[&str]) -> Settings {
        let mut settings = Settings::default();
        for line in lines {
            let (command, args) = assuan::command(line.as_bytes()).unwrap();
            let key = if command == "OPTION" {
                format!("OPTION {}", args.split('=').next().unwrap())
            } else {
                command.to_owned()
            };
            settings.insert(key, (*line).into());
        }
        settings
    }

    #[test]
    fn reset_preserves_native_process_options_but_clears_dialog_state() {
        let persistent = [
            "OPTION ttyname=/dev/tty",
            "OPTION ttytype=xterm",
            "OPTION display=:0",
            "OPTION lc-ctype=en_US.UTF-8",
            "OPTION lc-messages=en_US.UTF-8",
            "OPTION owner=1/1 host",
            "OPTION grab",
            "OPTION no-grab",
            "OPTION default-ok=Proceed",
            "OPTION default-cancel=Cancel",
            "OPTION default-prompt=PIN",
            "OPTION default-pwmngr=Save",
            "OPTION default-cf-visi=Show",
            "OPTION default-tt-visi=Show",
            "OPTION default-tt-hide=Hide",
            "OPTION default-capshint=Caps",
            "OPTION constraints-enforce",
            "OPTION constraints-hint-short=Short",
            "OPTION constraints-hint-long=Long",
            "OPTION constraints-error-title=Error",
            "OPTION invisible-char=*",
            "SETTIMEOUT 12",
        ];
        let temporary = [
            "SETDESC Description",
            "SETPROMPT Prompt",
            "SETTITLE Title",
            "SETOK OK",
            "SETCANCEL Cancel",
            "SETNOTOK No",
            "SETERROR Error",
            "SETREPEAT Again",
            "SETREPEATERROR Mismatch",
            "SETREPEATOK Match",
            "SETQUALITYBAR Quality",
            "SETQUALITYBAR_TT Hint",
            "SETGENPIN Generate",
            "SETGENPIN_TT Random",
            "SETKEYINFO key",
            "OPTION formatted-passphrase",
            "OPTION formatted-passphrase-hint=Format",
            "OPTION default-title=Title",
            "OPTION default-tt-save=Save",
        ];
        let mut settings = settings(&[persistent.as_slice(), temporary.as_slice()].concat());
        settings.reset();
        let actual: Vec<_> = settings.values().map(|line| &**line).collect();
        assert_eq!(actual, persistent.map(str::as_bytes));
    }

    #[test]
    fn dialogs_consume_only_their_native_one_shot_settings() {
        let mut settings = settings(&[
            "SETERROR Retry",
            "SETREPEAT Again",
            "SETQUALITYBAR Quality",
            "SETQUALITYBAR_TT Hint",
            "SETREPEATERROR Mismatch",
            "SETREPEATOK Match",
            "SETDESC Description",
        ]);
        for command in ["CONFIRM", "MESSAGE"] {
            let mut copy = settings.clone();
            copy.finish_dialog(command);
            assert!(copy.0.iter().any(|(key, _)| key == "SETREPEAT"));
            assert!(
                !copy
                    .0
                    .iter()
                    .any(|(key, _)| matches!(key.as_str(), "SETERROR" | "SETQUALITYBAR"))
            );
        }
        settings.finish_dialog("GETPIN");
        let keys: Vec<_> = settings.0.iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(
            keys,
            [
                "SETQUALITYBAR_TT",
                "SETREPEATERROR",
                "SETREPEATOK",
                "SETDESC"
            ]
        );
    }

    #[test]
    fn native_capability_query_reports_support_false_and_missing_values() {
        for (args, code) in [
            ("cmd_has_option SERIALNO all", None),
            ("cmd_has_option\tSERIALNO\tall", None),
            ("cmd_has_option", Some(128)),
            ("cmd_has_option SERIALNO", Some(128)),
            ("cmd_has_option SERIALNO unknown", Some(256)),
            ("cmd_has_option UNKNOWN all", Some(256)),
            ("cmd_has_option SERIALNO all extra", Some(256)),
        ] {
            let line = format!("GETINFO {args}");
            assuan::validate_command(ServiceKind::Scdaemon, line.as_bytes()).unwrap();
            let result = local_info(ServiceKind::Scdaemon, args, 1);
            assert_eq!(
                assuan::parse_response(result.lines.last().unwrap()).unwrap(),
                code.map(Response::Err).unwrap_or(Response::Ok)
            );
        }
    }

    #[test]
    fn failed_public_response_does_not_change_card_identity() {
        let mut state = CardState {
            serial: "original".into(),
            ..CardState::default()
        };
        state.observe_serial(
            "SERIALNO",
            &AssuanResult {
                lines: vec!["S SERIALNO other".into(), "ERR 17 No key".into()],
            },
        );
        assert_eq!(state.serial, "original");
    }

    #[tokio::test]
    async fn ignore_discards_partial_pin_and_does_not_become_an_assuan_result() {
        use hibiki_lib::protocol::SessionOutput;
        let (tx, _input) = mpsc::channel(8);
        let (out, rx) = mpsc::channel(8);
        let mut ep = Endpoint::new(tx, rx, CancellationToken::new(), CancellationToken::new());
        ep.command("GETPIN".into()).await.unwrap();
        out.send(SessionOutput::Line {
            request: 1,
            line: "D partial-secret".into(),
        })
        .await
        .unwrap();
        out.send(SessionOutput::Ignored { request: 1 })
            .await
            .unwrap();
        let error = collect(&mut ep, None).await.unwrap_err();
        assert!(error.is::<hibiki_core::endpoint::CandidateIgnored>());
        ep.command("GETPIN".into()).await.unwrap();
        out.send(SessionOutput::Line {
            request: 2,
            line: "OK".into(),
        })
        .await
        .unwrap();
        let result = collect(&mut ep, None).await.unwrap();
        assert_eq!(result.lines.len(), 1);
        assert_eq!(&*result.lines[0], b"OK");
    }

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
