use crate::{
    assuan_io::{read_line, write_line, write_result},
    daemon::Hub,
    endpoint::Endpoint,
    frontend::LocalOpen,
    provider::LocalContext,
};
use anyhow::{Context, Result, bail};
use hibiki_lib::{
    assuan::{self, AssuanResult, Line, Response},
    decode,
    protocol::ServiceKind,
};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::AsyncReadExt,
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

async fn discover(
    hub: Arc<Hub>,
    open: &LocalOpen,
    line: Line,
    stop: &CancellationToken,
) -> Result<(Endpoint, AssuanResult)> {
    let mut tasks = JoinSet::new();
    let peers = hub.candidates(&open.channel, ServiceKind::Scdaemon).await;
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

async fn password_race(
    hub: Arc<Hub>,
    open: &LocalOpen,
    settings: &Settings,
    line: Line,
    stop: &CancellationToken,
    writer: &mut OwnedWriteHalf,
    inputs: &mut mpsc::Receiver<Line>,
) -> Result<AssuanResult> {
    let mut tasks = JoinSet::new();
    let (tx, mut inquiries) = mpsc::channel(32);
    let mut failures = 0;
    let mut canceled = None;
    let mut failed = None;
    for peer in hub.candidates(&open.channel, ServiceKind::Pinentry).await {
        let hub = hub.clone();
        let channel = open.channel.clone();
        let stop = stop.child_token();
        let settings = settings.clone();
        let line = line.clone();
        let tx = tx.clone();
        let local = peer == hub.app.identity.device.id();
        let context = LocalContext {
            display: open.display.clone(),
        };
        tasks.spawn(async move {
            let Some(mut ep) = hub
                .open(&channel, &peer, ServiceKind::Pinentry, stop, context)
                .await?
            else {
                return Ok(None);
            };
            for setting in settings.values() {
                let (cmd, args) = assuan::command(setting)?;
                if !local && cmd == "OPTION" && assuan::local_option(args) {
                    continue;
                }
                let result = transaction(&mut ep, setting.clone(), None).await?;
                if !result.success() {
                    ep.close().await;
                    return Ok(Some(result));
                }
            }
            let result = transaction(&mut ep, line, Some(&tx)).await;
            drop(ep);
            result.map(Some)
        });
    }
    drop(tx);
    loop {
        tokio::select! {
            Some(inquiry)=inquiries.recv()=>upstream_inquiry(inquiry,writer,inputs).await?,
            result=tasks.join_next()=>match result {
                Some(Ok(Ok(Some(result)))) if result.success()=>return Ok(result),
                Some(Ok(Ok(Some(mut result)))) if result.canceled()=>canceled=result.lines.pop(),
                Some(Ok(Ok(Some(mut result))))=>{failures+=1;failed=result.lines.pop();},
                // Disabled peers are not participants, including when every enabled window cancels.
                Some(Ok(Ok(None)))=>{},
                Some(_)=>failures+=1,
                None=>return Ok(AssuanResult { lines: vec![
                    (if failures == 0 { canceled } else { failed })
                        .unwrap_or_else(||assuan::error(assuan::GENERAL,"no pinentry candidate completed"))
                ] }),
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

pub async fn serve(hub: Arc<Hub>, mut stream: UnixStream) -> Result<()> {
    let open = tokio::time::timeout(Duration::from_secs(5), async {
        let length = stream.read_u32().await? as usize;
        if length > 8192 {
            bail!("IPC header limit");
        }
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes).await?;
        Ok::<LocalOpen, anyhow::Error>(decode(&bytes)?)
    })
    .await??;
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
                    return Ok(result);
                }
                if matches!(cmd, "SERIALNO" | "SWITCHCARD")
                    || (cmd == "LEARN" && args.contains("--demand="))
                {
                    if let Some(ep) = selected.take() {
                        ep.close().await;
                    }
                    broken = false;
                }
                if broken {
                    bail!("card session failed; reset or select a card again");
                }
                if let Some(ep) = selected.as_mut() {
                    return interactive(ep, line.clone(), &mut writer, &mut inputs).await;
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
                selected = Some(ep);
                Ok(result)
            };
            let outcome = tokio::time::timeout(
                Duration::from_secs(hub.app.config.operation_timeout_seconds),
                operation,
            )
            .await;
            let result = match outcome {
                Ok(Ok(result)) => result,
                _ => {
                    if let Some(ep) = selected.take() {
                        ep.close().await;
                        broken = true;
                    }
                    AssuanResult::error(assuan::GENERAL, "service unavailable, failed or timed out")
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
