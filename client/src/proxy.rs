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

struct Inquiry {
    line: Line,
    reply: oneshot::Sender<Vec<Line>>,
}
async fn transaction(
    ep: &mut Endpoint,
    line: Line,
    inquiries: Option<&mpsc::Sender<Inquiry>>,
) -> Result<AssuanResult> {
    ep.command(line).await?;
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
async fn interactive(
    ep: &mut Endpoint,
    line: Line,
    writer: &mut OwnedWriteHalf,
    inputs: &mut mpsc::Receiver<Line>,
) -> Result<AssuanResult> {
    let (tx, mut rx) = mpsc::channel(8);
    let operation = transaction(ep, line, Some(&tx));
    tokio::pin!(operation);
    loop {
        tokio::select! {
            result=&mut operation=>return result,
            Some(inquiry)=rx.recv()=>upstream_inquiry(inquiry,writer,inputs).await?,
        }
    }
}

async fn discover_round(
    hub: Arc<Hub>,
    open: &LocalOpen,
    line: Line,
    stop: &CancellationToken,
    peers: Vec<String>,
) -> Result<(Endpoint, AssuanResult)> {
    let mut tasks = JoinSet::new();
    for peer in peers {
        let hub = hub.clone();
        let channel = open.channel.clone();
        let stop = stop.child_token();
        let line = line.clone();
        tasks.spawn(async move {
            let mut ep = hub
                .open(
                    &channel,
                    &peer,
                    ServiceKind::Scdaemon,
                    stop,
                    LocalContext::default(),
                )
                .await?
                .context("service disabled")?;
            // Probe only the OpenPGP application; no PIN or private operation may run in discovery.
            let (cmd, args) = assuan::command(&line)?;
            let probe = if cmd == "SERIALNO" {
                if args.split_ascii_whitespace().any(|s| s == "openpgp") {
                    line.clone()
                } else {
                    format!("SERIALNO {args} openpgp").as_str().into()
                }
            } else {
                "SERIALNO openpgp".into()
            };
            let result = transaction(&mut ep, probe, None).await?;
            if !result.success() {
                ep.close().await;
                bail!("no matching OpenPGP card");
            }
            ep.card_serial = result.lines.iter().find_map(|line| {
                line.strip_prefix(b"S SERIALNO ")
                    .and_then(|v| std::str::from_utf8(v).ok())
                    .map(str::to_owned)
            });
            if ep.card_serial.is_none() {
                bail!("card did not return its serial number");
            }
            let result = if cmd == "SERIALNO" {
                result
            } else {
                transaction(&mut ep, line, None).await?
            };
            if !result.success() {
                ep.close().await;
                bail!("card does not match query");
            }
            Ok::<_, anyhow::Error>((ep, result))
        });
    }
    while let Some(result) = tasks.join_next().await {
        if let Ok(Ok(winner)) = result {
            return Ok(winner);
        }
    }
    bail!("no matching OpenPGP card available")
}

async fn discover(
    hub: Arc<Hub>,
    open: &LocalOpen,
    line: Line,
    stop: &CancellationToken,
) -> Result<(Endpoint, AssuanResult)> {
    let targets = hub.eligible(&open.channel, ServiceKind::Scdaemon)?;
    if targets.is_empty() {
        bail!("no card providers");
    }
    let operation =
        QueuedOperation::new(hub.clone(), &open.channel, ServiceKind::Scdaemon, targets).await?;
    loop {
        let peers = operation.ready().await?;
        if !peers.is_empty() {
            if let Ok(result) =
                discover_round(hub.clone(), open, line.clone(), stop, peers.clone()).await
            {
                operation.finish(true).await?;
                return Ok(result);
            }
            if !hub.connection().closed.is_cancelled() {
                let online = hub.peers(&open.channel).await.unwrap_or_default();
                for peer in peers {
                    if online.contains(&peer) || peer == hub.app.identity.device.id() {
                        operation.abandon(&peer).await?;
                    }
                }
            }
        }
        if operation
            .status()
            .await?
            .targets
            .iter()
            .all(|t| t.state != TargetState::Pending)
        {
            bail!("no matching OpenPGP card available");
        }
        operation.pause().await;
    }
}

async fn password_race(
    hub: Arc<Hub>,
    open: &LocalOpen,
    settings: &Settings,
    line: Line,
    stop: &CancellationToken,
    writer: &mut OwnedWriteHalf,
    inputs: &mut mpsc::Receiver<Line>,
) -> Result<AssuanResult> {
    let targets = hub.eligible(&open.channel, ServiceKind::Pinentry)?;
    if targets.is_empty() {
        bail!("no pinentry providers");
    }
    let operation = Arc::new(
        QueuedOperation::new(hub.clone(), &open.channel, ServiceKind::Pinentry, targets).await?,
    );
    let mut tasks = JoinSet::new();
    let (tx, mut inquiries) = mpsc::channel(32);
    let mut running = HashSet::new();
    let mut failures = 0;
    let mut canceled = None;
    let mut failed = None;
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    loop {
        tokio::select! {
            Some(inquiry)=inquiries.recv()=>upstream_inquiry(inquiry,writer,inputs).await?,
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
                            let local=peer == hub.app.identity.device.id();
                            let Some(mut ep)=hub.open(&channel, &peer, ServiceKind::Pinentry, stop, context).await? else { return Ok(None); };
                            for setting in settings.values() {
                                let (cmd,args)=assuan::command(setting)?;
                                if !local && cmd == "OPTION" && assuan::local_option(args) { continue; }
                                let result=transaction(&mut ep,setting.clone(),None).await?;
                                if !result.success() { return Ok(Some(result)); }
                            }
                            if local { operation.claim_local().await?; }
                            else { ep.bind_operation(Some(operation.value.id.clone())); }
                            let watching=operation.watch(ep.stop.clone());
                            let result=transaction(&mut ep,line,Some(&tx)).await;
                            watching.abort();
                            if local && let Ok(result)=&result {
                                operation.local_done(result.success()).await?;
                            }
                            drop(ep);
                            result.map(Some)
                        }.await;
                        (peer,result)
                    });
                }
                if tasks.is_empty() && status.targets.iter().all(|t| t.state != TargetState::Pending) {
                    operation.finish(false).await?;
                    return Ok(AssuanResult { lines: vec![(if failures == 0 { canceled } else { failed }).unwrap_or_else(||assuan::error(assuan::GENERAL,"no pinentry candidate completed; execution result may be unknown"))] });
                }
            },
            result=tasks.join_next(), if !tasks.is_empty()=>{
                if let Some(Ok((peer,result)))=result {
                    running.remove(&peer);
                    match result {
                        Ok(Some(result)) if result.success()=>{ operation.finish(true).await?; return Ok(result); },
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
    serial: String,
    preparation: Vec<Line>,
}
impl CardState {
    fn selected(&mut self, ep: &Endpoint) -> Result<()> {
        self.peer = ep.peer.clone();
        self.serial = ep
            .card_serial
            .clone()
            .context("card identity unavailable")?;
        self.preparation.clear();
        Ok(())
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

async fn restore_card(
    hub: Arc<Hub>,
    open: &LocalOpen,
    state: &CardState,
    stop: &CancellationToken,
    operation: &QueuedOperation,
) -> Result<Endpoint> {
    loop {
        let status = operation.status().await?;
        let target = status
            .targets
            .iter()
            .find(|t| t.device == state.peer)
            .context("card target missing")?;
        if target.state != TargetState::Pending {
            bail!("execution result unknown; private operation will not be repeated");
        }
        if operation.ready().await?.contains(&state.peer) {
            match hub
                .open(
                    &open.channel,
                    &state.peer,
                    ServiceKind::Scdaemon,
                    stop.child_token(),
                    LocalContext::default(),
                )
                .await
            {
                Ok(Some(mut ep)) => {
                    let preparation = async {
                        let result = transaction(
                            &mut ep,
                            format!("SERIALNO --demand={} openpgp", state.serial)
                                .as_str()
                                .into(),
                            None,
                        )
                        .await?;
                        if !result.success()
                            || !result
                                .lines
                                .iter()
                                .any(|l| &**l == format!("S SERIALNO {}", state.serial).as_bytes())
                        {
                            bail!("original card unavailable");
                        }
                        for line in &state.preparation {
                            if !transaction(&mut ep, line.clone(), None).await?.success() {
                                bail!("card preparation failed");
                            }
                        }
                        Ok::<_, anyhow::Error>(())
                    }
                    .await;
                    if preparation.is_ok() {
                        ep.card_serial = Some(state.serial.clone());
                        return Ok(ep);
                    }
                    if !hub.connection().closed.is_cancelled()
                        && hub
                            .peers(&open.channel)
                            .await
                            .unwrap_or_default()
                            .contains(&state.peer)
                    {
                        preparation?;
                    }
                }
                Ok(None) => bail!("card service disabled"),
                Err(_) => {}
            }
        }
        operation.pause().await;
    }
}

async fn card_transaction(
    hub: Arc<Hub>,
    open: &LocalOpen,
    selected: &mut Option<Endpoint>,
    state: &CardState,
    line: Line,
    stop: &CancellationToken,
    io: (&mut OwnedWriteHalf, &mut mpsc::Receiver<Line>),
) -> Result<AssuanResult> {
    let (cmd, _) = assuan::command(&line)?;
    let private = matches!(cmd, "PKSIGN" | "PKDECRYPT");
    let operation = QueuedOperation::new(
        hub.clone(),
        &open.channel,
        ServiceKind::Scdaemon,
        vec![state.peer.clone()],
    )
    .await?;
    loop {
        if selected
            .as_ref()
            .is_none_or(|ep| ep.done.is_cancelled() || ep.stop.is_cancelled())
        {
            if let Some(ep) = selected.take() {
                ep.close().await;
            }
            *selected = Some(restore_card(hub.clone(), open, state, stop, &operation).await?);
        }
        let ep = selected.as_mut().unwrap();
        let local = state.peer == hub.app.identity.device.id();
        if private {
            if local {
                operation.claim_local().await?;
            } else {
                ep.bind_operation(Some(operation.value.id.clone()));
            }
        }
        let watching = operation.watch(ep.stop.clone());
        let result = interactive(ep, line.clone(), io.0, io.1).await;
        watching.abort();
        ep.bind_operation(None);
        match result {
            Ok(result) => {
                if private && local {
                    operation.local_done(result.success()).await?;
                }
                operation.finish(result.success()).await?;
                return Ok(result);
            }
            Err(error) => {
                if let Some(ep) = selected.take() {
                    ep.close().await;
                }
                let status = operation.status().await?;
                if private
                    && status
                        .targets
                        .iter()
                        .any(|t| t.state != TargetState::Pending)
                {
                    bail!(
                        "execution result unknown; private operation will not be repeated: {error}"
                    );
                }
                *selected = Some(restore_card(hub.clone(), open, state, stop, &operation).await?);
            }
        }
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
        let mut selected: Option<Endpoint> = None;
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
                if let Some(ep) = selected.take() {
                    ep.close().await;
                }
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
                if matches!(cmd, "RESET" | "RESTART") {
                    let result = if let Some(mut ep) = selected.take() {
                        let result = transaction(&mut ep, line.clone(), None).await;
                        ep.close().await;
                        result?
                    } else {
                        AssuanResult::ok()
                    };
                    broken = false;
                    card_state = CardState::default();
                    return Ok(result);
                }
                if matches!(cmd, "SERIALNO" | "SWITCHCARD")
                    || (cmd == "LEARN" && args.contains("--demand="))
                {
                    if let Some(ep) = selected.take() {
                        ep.close().await;
                    }
                    broken = false;
                    card_state = CardState::default();
                }
                if broken {
                    bail!("card session failed; reset or select a card again");
                }
                if selected.is_some() {
                    let result = card_transaction(
                        hub.clone(),
                        &open,
                        &mut selected,
                        &card_state,
                        line.clone(),
                        &stop,
                        (&mut writer, &mut inputs),
                    )
                    .await?;
                    if result.success() {
                        card_state.remember(&line)?;
                    }
                    return Ok(result);
                }
                if matches!(cmd, "PKSIGN" | "PKDECRYPT") {
                    bail!("select a card and set data first");
                }
                let (ep, result) = if cmd == "SETDATA" {
                    let (mut ep, _) =
                        discover(hub.clone(), &open, "SERIALNO openpgp".into(), &stop).await?;
                    let result = transaction(&mut ep, line.clone(), None).await?;
                    (ep, result)
                } else {
                    discover(hub.clone(), &open, line.clone(), &stop).await?
                };
                card_state.selected(&ep)?;
                if result.success() {
                    card_state.remember(&line)?;
                }
                selected = Some(ep);
                Ok(result)
            };
            let outcome = tokio::time::timeout(
                Duration::from_secs(hub.app.config.operation_timeout_seconds),
                operation,
            )
            .await;
            let unknown = matches!(&outcome, Ok(Err(error)) if error.to_string().contains("execution result unknown"));
            let result = match outcome {
                Ok(Ok(result)) => result,
                _ => {
                    if open.service == ServiceKind::Scdaemon && !card_state.peer.is_empty() {
                        broken = true;
                    }
                    if let Some(ep) = selected.take() {
                        ep.close().await;
                        broken = true;
                    }
                    AssuanResult::error(
                        assuan::GENERAL,
                        if unknown {
                            "execution result unknown; do not retry automatically"
                        } else {
                            "service unavailable, failed or timed out"
                        },
                    )
                }
            };
            tracing::debug!(service=?open.service,command=cmd,success=result.success(),"Assuan result");
            write_result(&mut writer, &result).await?;
        }
        if let Some(ep) = selected.take() {
            ep.close().await;
        }
        Ok::<_, anyhow::Error>(())
    };
    let outcome = tokio::select! {_=stop.cancelled()=>Ok(()),result=result=>result};
    stop.cancel();
    reader_task.abort();
    outcome
}
