//! Native stdio children. No agent socket or user-owned process is used.
use crate::{
    assuan_io::{read_line, write_line},
    endpoint::Endpoint,
    storage::{App, private_dir},
};
use anyhow::{Context, Result, bail};
use hibiki_lib::{
    assuan::{self, Response},
    protocol::{ServiceKind, SessionInput, SessionOutput},
};
use std::{path::PathBuf, process::Stdio, sync::Arc, time::Duration};
use tokio::{
    process::{Child, Command},
    sync::{Semaphore, mpsc},
};
use tokio_util::sync::CancellationToken;

#[derive(Default, Clone)]
pub struct LocalContext {
    pub display: Option<String>,
}

pub async fn program(app: &App, service: ServiceKind) -> Result<PathBuf> {
    let path = if let Some(p) = &app.config.service(service).program {
        p.clone()
    } else {
        let out = Command::new(&app.config.gpgconf_program)
            .arg("--list-components")
            .output()
            .await?;
        if !out.status.success() {
            bail!("gpgconf failed to locate native service");
        }
        let name = match service {
            ServiceKind::Scdaemon => "scdaemon",
            ServiceKind::Pinentry => "pinentry",
        };
        let record = out
            .stdout
            .split(|b| *b == b'\n')
            .find(|l| l.starts_with(format!("{name}:").as_bytes()))
            .context("native service is not installed")?;
        let raw = record
            .splitn(3, |b| *b == b':')
            .nth(2)
            .context("invalid gpgconf component")?;
        PathBuf::from(std::str::from_utf8(&assuan::unescape(raw)?)?)
    };
    let resolved = if path.is_absolute() {
        path.canonicalize()?
    } else {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|p| p.join(&path))
            .find(|p| p.is_file())
            .context("native program not found in PATH")?
            .canonicalize()?
    };
    if resolved
        .file_name()
        .is_some_and(|n| n.to_string_lossy().starts_with("hibiki"))
    {
        bail!("native program points to HIbiki");
    }
    if let Some(dir) = std::env::current_exe()?.parent() {
        for name in ["hibiki", "hibiki-scdaemon", "hibiki-pinentry"] {
            if let Ok(m) = std::fs::metadata(dir.join(name)) {
                use std::os::unix::fs::MetadataExt;
                let n = std::fs::metadata(&resolved)?;
                if n.dev() == m.dev() && n.ino() == m.ino() {
                    bail!("native program points to HIbiki");
                }
            }
        }
    }
    Ok(resolved)
}

pub async fn open(
    app: Arc<App>,
    service: ServiceKind,
    card_slot: Arc<Semaphore>,
    stop: CancellationToken,
    local: Option<LocalContext>,
) -> Result<Endpoint> {
    if !app.config.service(service).enabled {
        bail!("service disabled");
    }
    let permit = if service == ServiceKind::Scdaemon {
        Some(card_slot.try_acquire_owned().context("scdaemon is busy")?)
    } else {
        None
    };
    let mut cmd = Command::new(program(&app, service).await?);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    // Do not inherit debugging that could disclose Assuan payloads.
    cmd.env_remove("ASSUAN_DEBUG")
        .env_remove("ASSUAN_LOG_CAT")
        .env_remove("_assuan_connection_fd");
    if service == ServiceKind::Scdaemon {
        let home = app.paths.data.join("scdaemon");
        private_dir(&home)?;
        cmd.arg("--server")
            .arg("--homedir")
            .arg(home)
            .arg("--deny-admin");
    } else if let Some(display) = local.as_ref().and_then(|c| c.display.as_ref()) {
        cmd.arg("--display").arg(display);
    }
    let mut child = cmd.spawn().context("could not start native service")?;
    let mut reader =
        crate::assuan_io::SecretReader::new(child.stdout.take().context("child stdout")?);
    let mut writer = child.stdin.take().context("child stdin")?;
    let greeting = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let l = read_line(&mut reader)
                .await?
                .context("missing native greeting")?;
            match assuan::parse_response(&l)? {
                Response::Ok => return Ok::<_, anyhow::Error>(()),
                Response::Comment => {}
                _ => bail!("native service rejected connection"),
            }
        }
    })
    .await;
    if !matches!(greeting, Ok(Ok(()))) {
        let _ = child.kill().await;
        bail!("native service greeting failed");
    }
    // Remote TTY/display names never come from the requesting machine.
    if service == ServiceKind::Pinentry && local.is_none() {
        for (key, env) in [("ttyname", "GPG_TTY"), ("ttytype", "TERM")] {
            if let Ok(value) = std::env::var(env) {
                let line = format!("OPTION {key}={value}");
                if assuan::framing(line.as_bytes()).is_ok() {
                    write_line(&mut writer, line.as_bytes()).await?;
                    let _ = tokio::time::timeout(Duration::from_secs(2), read_line(&mut reader))
                        .await?;
                }
            }
        }
    }
    let (tx, mut inputs) = mpsc::channel::<SessionInput>(16);
    let (outputs, rx) = mpsc::channel(32);
    let done = CancellationToken::new();
    let finished = done.clone();
    let cancel = stop.clone();
    tokio::spawn(async move {
        let mut active = false;
        let run = async {
            let mut last = 0;
            let mut staged = 0;
            while let Some(input) = inputs.recv().await {
                let SessionInput::Command { request, line } = input else {
                    bail!("unsolicited inquiry reply");
                };
                if request != last + 1 {
                    bail!("out of order command");
                }
                last = request;
                if assuan::validate_command(service, &line).is_err()
                    || (local.is_none()
                        && line.starts_with(b"OPTION ")
                        && (assuan::local_option(std::str::from_utf8(&line[7..])?)
                            || matches!(
                                std::str::from_utf8(&line[7..])?.split('=').next(),
                                Some(
                                    "touch-file"
                                        | "allow-external-password-cache"
                                        | "allow-emacs-prompt"
                                )
                            )))
                {
                    outputs
                        .send(SessionOutput::Line {
                            request,
                            line: assuan::error(
                                assuan::NOT_SUPPORTED,
                                "unsupported service command",
                            ),
                        })
                        .await?;
                    continue;
                }
                if matches!(&*line, b"GETINFO pid" | b"GETINFO socket_name") {
                    outputs
                        .send(SessionOutput::Line {
                            request,
                            line: assuan::error(assuan::NO_DATA, "process-local information"),
                        })
                        .await?;
                    continue;
                }
                if service == ServiceKind::Scdaemon && line.starts_with(b"SETDATA ") {
                    let args = &line[8..];
                    staged = if let Some(hex) = args.strip_prefix(b"--append ") {
                        staged + hex.len() / 2
                    } else {
                        args.len() / 2
                    };
                    if staged > assuan::MAX_DATA {
                        bail!("SETDATA accumulation limit");
                    }
                }
                if matches!(&*line, b"RESET" | b"RESTART") {
                    staged = 0;
                }
                active = true;
                let transaction = async {
                    write_line(&mut writer, &line).await?;
                    let mut bytes = 0;
                    let mut count = 0;
                    loop {
                        let line = read_line(&mut reader)
                            .await?
                            .context("native service disconnected")?;
                        bytes += line.len();
                        count += 1;
                        if bytes > assuan::MAX_DATA || count > assuan::MAX_LINES {
                            bail!("native response limit");
                        }
                        let r = assuan::parse_response(&line)?;
                        let inquire = matches!(r, Response::Inquire(_));
                        let terminal = matches!(r, Response::Ok | Response::Err(_));
                        if let Response::Data(d) = r {
                            assuan::unescape(d)?;
                        }
                        outputs.send(SessionOutput::Line { request, line }).await?;
                        if inquire {
                            loop {
                                let Some(SessionInput::InquiryReply { request: id, line }) =
                                    inputs.recv().await
                                else {
                                    bail!("inquiry reply required");
                                };
                                if id != request {
                                    bail!("inquiry request mismatch");
                                }
                                bytes += line.len();
                                count += 1;
                                if bytes > assuan::MAX_DATA || count > assuan::MAX_LINES {
                                    bail!("inquiry limit");
                                }
                                let terminal = &*line == b"END" || &*line == b"CAN";
                                if !terminal {
                                    let Response::Data(d) = assuan::parse_response(&line)? else {
                                        bail!("invalid inquiry data");
                                    };
                                    assuan::unescape(d)?;
                                }
                                write_line(&mut writer, &line).await?;
                                if terminal {
                                    break;
                                }
                            }
                        }
                        if terminal {
                            return Ok::<_, anyhow::Error>(());
                        }
                    }
                };
                tokio::time::timeout(
                    Duration::from_secs(app.config.operation_timeout_seconds),
                    transaction,
                )
                .await??;
                active = false;
            }
            Ok::<_, anyhow::Error>(())
        };
        tokio::select! { _=cancel.cancelled()=>{}, result=run=> { if result.is_err() { let _=outputs.try_send(SessionOutput::Failure); } } }
        // A completed command permits graceful session cleanup. During an inquiry,
        // cancellation must kill the dedicated child instead of injecting a command.
        if !active {
            let _ = tokio::time::timeout(Duration::from_millis(500), async {
                write_line(
                    &mut writer,
                    if service == ServiceKind::Scdaemon {
                        b"RESTART"
                    } else {
                        b"RESET"
                    },
                )
                .await?;
                loop {
                    let line = read_line(&mut reader).await?.context("child closed")?;
                    if matches!(
                        assuan::parse_response(&line)?,
                        Response::Ok | Response::Err(_)
                    ) {
                        break;
                    }
                }
                write_line(&mut writer, b"BYE").await?;
                Ok::<_, anyhow::Error>(())
            })
            .await;
        }
        drop(writer);
        if active
            || tokio::time::timeout(Duration::from_millis(500), child.wait())
                .await
                .is_err()
        {
            reap(&mut child).await;
        }
        drop(permit);
        finished.cancel();
    });
    Ok(Endpoint::new(tx, rx, stop, done))
}
async fn reap(child: &mut Child) {
    let _ = child.start_kill();
    let _ = child.wait().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{Config, ServiceConfig};
    use hibiki_lib::{identity::Identity, paths::AppPaths};
    use std::{collections::BTreeMap, os::unix::fs::PermissionsExt};
    fn app(root: &std::path::Path) -> Arc<App> {
        let paths = AppPaths::resolve(&BTreeMap::new(), root, root, unsafe { libc::geteuid() });
        let script = root.join("native-test");
        std::fs::write(&script,b"#!/bin/sh\nprintf 'OK native\\n'\nwhile IFS= read -r line; do\ncase \"$line\" in\nPKSIGN*) printf 'INQUIRE NEEDPIN |A|Test PIN\\n';;\n*) printf 'OK\\n';;\nesac\ndone\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let service = ServiceConfig {
            enabled: true,
            program: Some(script),
        };
        Arc::new(App {
            config: Config {
                scdaemon: service.clone(),
                pinentry: service,
                ..Config::default()
            },
            config_file: root.join("client.toml"),
            paths,
            identity: Arc::new(Identity::generate("test".into()).unwrap()),
        })
    }
    #[tokio::test]
    async fn disabled_services_never_start_a_program() {
        for card in [false, true] {
            for pin in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let mut app = app(dir.path());
                let a = Arc::get_mut(&mut app).unwrap();
                a.config.scdaemon.enabled = card;
                a.config.pinentry.enabled = pin;
                let slot = Arc::new(Semaphore::new(1));
                for service in [ServiceKind::Scdaemon, ServiceKind::Pinentry] {
                    let result = open(
                        app.clone(),
                        service,
                        slot.clone(),
                        CancellationToken::new(),
                        None,
                    )
                    .await;
                    assert_eq!(result.is_ok(), app.config.service(service).enabled);
                    if let Ok(ep) = result {
                        ep.close().await;
                    }
                }
                assert_eq!(slot.available_permits(), 1);
            }
        }
    }
    #[tokio::test]
    async fn provider_rejects_admin_commands_inquiry_injection_and_releases_lease() {
        let dir = tempfile::tempdir().unwrap();
        let app = app(dir.path());
        let slot = Arc::new(Semaphore::new(1));
        let mut ep = open(
            app.clone(),
            ServiceKind::Scdaemon,
            slot.clone(),
            CancellationToken::new(),
            None,
        )
        .await
        .unwrap();
        assert!(
            open(
                app.clone(),
                ServiceKind::Scdaemon,
                slot.clone(),
                CancellationToken::new(),
                None
            )
            .await
            .is_err()
        );
        ep.command("GENKEY 1".into()).await.unwrap();
        assert!(matches!(
            assuan::parse_response(&ep.next().await.unwrap()).unwrap(),
            Response::Err(assuan::NOT_SUPPORTED)
        ));
        ep.command("PKSIGN OPENPGP.1".into()).await.unwrap();
        assert!(matches!(
            assuan::parse_response(&ep.next().await.unwrap()).unwrap(),
            Response::Inquire(_)
        ));
        // Bypass the frontend and submit an invalid peer frame directly.
        ep.tx
            .send(SessionInput::Command {
                request: 3,
                line: "NOP".into(),
            })
            .await
            .unwrap();
        assert!(matches!(ep.rx.recv().await, Some(SessionOutput::Failure)));
        ep.close().await;
        assert_eq!(slot.available_permits(), 1);
        let next = open(
            app,
            ServiceKind::Scdaemon,
            slot,
            CancellationToken::new(),
            None,
        )
        .await
        .unwrap();
        next.close().await;
    }
    #[tokio::test]
    async fn remote_display_and_file_options_are_not_executable() {
        let dir = tempfile::tempdir().unwrap();
        let app = app(dir.path());
        let mut ep = open(
            app,
            ServiceKind::Pinentry,
            Arc::new(Semaphore::new(1)),
            CancellationToken::new(),
            None,
        )
        .await
        .unwrap();
        for line in [
            "OPTION ttyname=/dev/elsewhere",
            "OPTION touch-file=/tmp/elsewhere",
            "OPTION allow-external-password-cache",
        ] {
            ep.command(line.into()).await.unwrap();
            assert!(matches!(
                assuan::parse_response(&ep.next().await.unwrap()).unwrap(),
                Response::Err(assuan::NOT_SUPPORTED)
            ));
        }
        ep.close().await;
    }
}
