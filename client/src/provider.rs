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

pub use hibiki_core::provider::LocalContext;
pub struct NativeProvider(pub crate::storage::Config);
impl hibiki_core::provider::Provider for NativeProvider {
    fn enabled(&self, service: ServiceKind) -> bool {
        self.0.service(service).enabled
    }
    fn prepare(
        &self,
        app: Arc<App>,
        target: hibiki_lib::protocol::CardTarget,
        context: hibiki_core::provider::ProviderContext,
    ) -> Result<Box<dyn hibiki_core::provider::Preparation>> {
        Ok(Box::new(NativePreparation {
            app,
            target,
            local: context.local,
            prompt_stop: PromptGuard(CancellationToken::new()),
            prompt: None,
        }))
    }
    fn open(
        &self,
        app: Arc<App>,
        service: ServiceKind,
        card_slot: Arc<Semaphore>,
        stop: CancellationToken,
        context: hibiki_core::provider::ProviderContext,
    ) -> hibiki_core::provider::OpenFuture<'_> {
        Box::pin(open(app, service, card_slot, stop, context.local))
    }
}

struct NativePreparation {
    app: Arc<App>,
    target: hibiki_lib::protocol::CardTarget,
    local: Option<LocalContext>,
    prompt_stop: PromptGuard,
    prompt: Option<tokio::task::JoinHandle<Result<bool>>>,
}
impl NativePreparation {
    fn prompt_result(
        &mut self,
        result: Result<Result<bool>, tokio::task::JoinError>,
    ) -> Result<()> {
        match result {
            Ok(Ok(true)) => self.prompt = None,
            Ok(Ok(false)) => return Err(hibiki_core::provider::PreparationRejected.into()),
            // A missing graphical pinentry must not prevent card detection.
            _ => {
                let token = self.prompt_stop.0.clone();
                self.prompt = Some(tokio::spawn(async move {
                    token.cancelled().await;
                    Ok(false)
                }));
            }
        }
        Ok(())
    }
}
impl hibiki_core::provider::Preparation for NativePreparation {
    fn poll<'a>(
        &'a mut self,
        endpoint: &'a mut Endpoint,
        pause: CancellationToken,
    ) -> hibiki_core::provider::PrepareFuture<'a> {
        Box::pin(async move {
            loop {
                if pause.is_cancelled() {
                    return Ok(None);
                }
                let serial = hibiki_core::preparation::probe(endpoint, &self.target).await?;
                // Drain the native query, then honor any cancellation that arrived
                // during it before publishing a ready card or pausing for a query.
                if self
                    .prompt
                    .as_ref()
                    .is_some_and(|prompt| prompt.is_finished())
                {
                    let result = self.prompt.take().unwrap().await;
                    self.prompt_result(result)?;
                }
                if let Some(serial) = serial {
                    return Ok(Some(serial));
                }
                // A query may have paused us while the probe was in flight.
                // Drain that response, but leave the existing UI untouched.
                if pause.is_cancelled() {
                    return Ok(None);
                }
                if self.prompt.is_none() {
                    let app = self.app.clone();
                    let target = self.target.clone();
                    let token = self.prompt_stop.0.child_token();
                    let local = self.local.clone();
                    self.prompt = Some(tokio::spawn(async move {
                        insertion_prompt(app, target, token, local).await
                    }));
                }
                tokio::select! {
                    _=pause.cancelled()=>return Ok(None),
                    result=self.prompt.as_mut().unwrap()=>{
                        self.prompt_result(result)?;
                    },
                    _=tokio::time::sleep(Duration::from_millis(250))=>{},
                }
            }
        })
    }
}

pub async fn program(app: &App, service: ServiceKind) -> Result<PathBuf> {
    let path = if let Some(p) = &app.config.service(service).program {
        p.clone()
    } else {
        let out = tokio::time::timeout(
            Duration::from_secs(5),
            Command::new(&app.config.gpgconf_program)
                .arg("--list-components")
                .kill_on_drop(true)
                .output(),
        )
        .await
        .context("gpgconf discovery timed out")?
        .with_context(|| {
            format!(
                "could not run {:?}; install GnuPG or set gpgconf_program",
                app.config.gpgconf_program
            )
        })?;
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
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(&resolved)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        bail!(
            "native program is not an executable file: {}",
            resolved.display()
        );
    }
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

/// Check enabled providers without opening a reader or displaying a PIN prompt.
pub async fn preflight(app: &App) -> Result<()> {
    for service in [ServiceKind::Scdaemon, ServiceKind::Pinentry] {
        if app.config.service(service).enabled {
            let path = program(app, service).await.with_context(|| {
                format!(
                    "{service:?} is enabled but unavailable; fix its program setting or disable it"
                )
            })?;
            eprintln!("{service:?}: {}", path.display());
        }
    }
    Ok(())
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
                        // Desktop Cancel always ends the whole input operation. Mobile
                        // dismissal keeps its distinct, device-local CANCELED semantics.
                        let line = if service == ServiceKind::Pinentry
                            && matches!(r, Response::Err(code) if code & 0xffff == assuan::CANCELED)
                        {
                            assuan::error(assuan::FULLY_CANCELED, "operation canceled by user")
                        } else {
                            line
                        };
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
    async fn preflight_rejects_missing_nonexecutable_and_adapter_programs() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app(dir.path());
        preflight(&app).await.unwrap();
        let config = &mut Arc::get_mut(&mut app).unwrap().config;
        config.pinentry.program = Some(dir.path().join("missing"));
        assert!(preflight(&app).await.is_err());
        let config = &mut Arc::get_mut(&mut app).unwrap().config;
        config.pinentry.enabled = false;
        preflight(&app).await.unwrap();
        let native = app.config.scdaemon.program.as_ref().unwrap();
        std::fs::set_permissions(native, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(preflight(&app).await.is_err());
        let adapter = dir.path().join("hibiki-pinentry");
        std::fs::write(&adapter, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&adapter, std::fs::Permissions::from_mode(0o700)).unwrap();
        Arc::get_mut(&mut app).unwrap().config.scdaemon.program = Some(adapter);
        assert!(preflight(&app).await.is_err());
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

struct PromptGuard(CancellationToken);
impl Drop for PromptGuard {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
async fn insertion_prompt(
    app: Arc<App>,
    target: hibiki_lib::protocol::CardTarget,
    stop: CancellationToken,
    local: Option<LocalContext>,
) -> Result<bool> {
    // This UI belongs to the card service, regardless of exported password service.
    let mut prompt_app = (*app).clone();
    prompt_app.config.pinentry.enabled = true;
    let mut ep = open(
        Arc::new(prompt_app),
        ServiceKind::Pinentry,
        Arc::new(Semaphore::new(1)),
        stop,
        local,
    )
    .await?;
    let description = hibiki_lib::card_prompt::description(target.serial.as_deref(), None)
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A");
    for command in [
        "SETTITLE GnuPG".to_owned(),
        format!("SETDESC {description}"),
        "SETOK _OK".into(),
        "SETCANCEL _Cancel".into(),
    ] {
        if !hibiki_core::preparation::query(&mut ep, command.as_str().into())
            .await?
            .success()
        {
            bail!("insertion prompt setup failed");
        }
    }
    let result = hibiki_core::preparation::query(&mut ep, "CONFIRM".into()).await?;
    ep.close().await;
    Ok(result.success())
}

#[cfg(test)]
mod preparation_tests {
    use super::*;
    use hibiki_core::provider::{Provider, ProviderContext};
    use hibiki_lib::{assuan::AssuanResult, protocol::CardPreparation, random_id};
    use hibiki_lib::{identity::Identity, paths::AppPaths, protocol::CardTarget};
    use std::{collections::BTreeMap, os::unix::fs::PermissionsExt};

    struct WaitingFixture {
        root: tempfile::TempDir,
        app: Arc<App>,
    }
    impl WaitingFixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let program = root.path().join("native");
            // Each CONFIRM blocks until the test acts as the user. Public queries
            // can be held separately to deliver a reply while preparation is paused.
            let script = format!(
                r#"#!/bin/sh
cd '{root}' || exit 1
printf 'OK\n'
while IFS= read -r line; do
 case "$line" in
 SERIALNO*)
   if [ -f block-probe ]; then
     touch probing
     while [ -f block-probe ]; do sleep 0.01; done
   fi
   if [ -f card ]; then printf 'S SERIALNO '; cat card; printf '\nOK\n'; else printf 'ERR 108 no-card\n'; fi ;;
 CONFIRM*)
   printf '%s\n' "$$" >> prompts
   while [ ! -f answer ]; do sleep 0.01; done
   answer=$(cat answer); rm answer
   printf '%s\n' "$answer" ;;
 'GETATTR BLOCK')
   touch querying
   while [ ! -f release ]; do sleep 0.01; done
   printf 'D public-result\nOK\n' ;;
 *) printf 'OK\n' ;;
 esac
done
"#,
                root = root.path().display()
            );
            std::fs::write(&program, script).unwrap();
            std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
            let service = crate::storage::ServiceConfig {
                enabled: true,
                program: Some(program),
            };
            let app = Arc::new(App {
                config: crate::storage::Config {
                    scdaemon: service.clone(),
                    pinentry: service,
                    ..Default::default()
                },
                config_file: root.path().join("client.toml"),
                paths: AppPaths::resolve(&BTreeMap::new(), root.path(), root.path(), unsafe {
                    libc::geteuid()
                }),
                identity: Arc::new(Identity::generate("prompt-test".into()).unwrap()),
            });
            Self { root, app }
        }
        fn write(&self, name: &str, value: &str) {
            std::fs::write(self.root.path().join(name), value).unwrap();
        }
        fn prompts(&self) -> Vec<i32> {
            std::fs::read_to_string(self.root.path().join("prompts"))
                .unwrap_or_default()
                .lines()
                .map(|line| line.parse().unwrap())
                .collect()
        }
        async fn endpoint(&self) -> Endpoint {
            let native = open(
                self.app.clone(),
                ServiceKind::Scdaemon,
                Arc::new(Semaphore::new(1)),
                CancellationToken::new(),
                None,
            )
            .await
            .unwrap();
            hibiki_core::preparation::wrap(
                native,
                Arc::new(NativeProvider(self.app.config.clone())),
                self.app.clone(),
                ProviderContext {
                    local: None,
                    channel: String::new(),
                    peer: String::new(),
                    session: String::new(),
                },
            )
        }
        async fn start(&self, ep: &mut Endpoint, target: CardTarget) -> String {
            let id = random_id();
            ep.prepare(id.clone(), target).await.unwrap();
            assert!(matches!(
                ep.prepared(&id).await.unwrap(),
                CardPreparation::Waiting
            ));
            id
        }
    }
    async fn until(mut predicate: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while !predicate() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("fixture condition timed out");
    }
    fn alive(pid: i32) -> bool {
        unsafe { libc::kill(pid, 0) == 0 }
    }
    async fn query(ep: &mut Endpoint, command: &str) -> AssuanResult {
        tokio::time::timeout(
            Duration::from_secs(3),
            hibiki_core::preparation::query(ep, command.into()),
        )
        .await
        .unwrap()
        .unwrap()
    }
    async fn prepared(ep: &mut Endpoint, id: &str) -> CardPreparation {
        tokio::time::timeout(Duration::from_secs(3), ep.prepared(id))
            .await
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn public_queries_and_duplicate_targets_preserve_unanswered_native_prompt() {
        let fixture = WaitingFixture::new();
        let mut ep = fixture.endpoint().await;
        let first = fixture.start(&mut ep, CardTarget::default()).await;
        until(|| fixture.prompts().len() == 1).await;
        let pid = fixture.prompts()[0];
        for _ in 0..12 {
            assert!(!query(&mut ep, "SERIALNO").await.success());
            assert!(alive(pid), "public query closed an unanswered prompt");
        }
        let id = fixture.start(&mut ep, CardTarget::default()).await;
        ep.cancel_preparation(first).await.unwrap(); // Stale cancellation must not affect the new ID.
        assert!(!query(&mut ep, "SERIALNO").await.success());
        assert!(alive(pid));
        assert_eq!(fixture.prompts(), vec![pid]);
        fixture.write("card", "AABB");
        assert!(
            matches!(prepared(&mut ep, &id).await, CardPreparation::Ready { serial } if serial == "AABB")
        );
        until(|| !alive(pid)).await;
        assert_eq!(fixture.prompts(), vec![pid]);
        ep.close().await;
    }

    #[tokio::test]
    async fn inserted_card_is_recognized_after_confirmation_even_during_public_query() {
        for public_query in [false, true] {
            let fixture = WaitingFixture::new();
            let mut ep = fixture.endpoint().await;
            let id = fixture
                .start(
                    &mut ep,
                    CardTarget {
                        serial: Some("AABB".into()),
                        key: None,
                    },
                )
                .await;
            until(|| fixture.prompts().len() == 1).await;
            let pid = fixture.prompts()[0];
            if public_query {
                ep.command("GETATTR BLOCK".into()).await.unwrap();
                until(|| fixture.root.path().join("querying").exists()).await;
            } else {
                fixture.write("block-probe", "");
                until(|| fixture.root.path().join("probing").exists()).await;
            }
            // Insert first, then confirm the existing prompt while probing is paused.
            fixture.write("card", "AABB");
            fixture.write("answer", "OK");
            until(|| !alive(pid)).await;
            if public_query {
                fixture.write("release", "");
                let result = crate::proxy::collect(&mut ep, None).await.unwrap();
                assert_eq!(
                    result.lines.iter().map(|line| &**line).collect::<Vec<_>>(),
                    [b"D public-result".as_slice(), b"OK"]
                );
            } else {
                std::fs::remove_file(fixture.root.path().join("block-probe")).unwrap();
            }
            assert!(
                matches!(prepared(&mut ep, &id).await, CardPreparation::Ready { serial } if serial == "AABB")
            );
            assert_eq!(
                fixture.prompts().len(),
                1,
                "confirmation reopened the prompt"
            );
            ep.close().await;
        }
    }

    #[tokio::test]
    async fn insertion_cancel_wins_over_card_arriving_during_probe() {
        let fixture = WaitingFixture::new();
        let mut ep = fixture.endpoint().await;
        let id = fixture.start(&mut ep, CardTarget::default()).await;
        until(|| fixture.prompts().len() == 1).await;
        let pid = fixture.prompts()[0];
        fixture.write("block-probe", "");
        until(|| fixture.root.path().join("probing").exists()).await;
        fixture.write("answer", "ERR 99 canceled");
        until(|| !alive(pid)).await;
        fixture.write("card", "AABB");
        std::fs::remove_file(fixture.root.path().join("block-probe")).unwrap();
        assert!(matches!(
            prepared(&mut ep, &id).await,
            CardPreparation::Rejected
        ));
        assert_eq!(fixture.prompts().len(), 1);
        ep.close().await;
    }

    #[tokio::test]
    async fn confirmation_and_cancellation_during_public_query_are_retained() {
        for accepted in [true, false] {
            let fixture = WaitingFixture::new();
            let mut ep = fixture.endpoint().await;
            let id = fixture.start(&mut ep, CardTarget::default()).await;
            until(|| fixture.prompts().len() == 1).await;
            let pid = fixture.prompts()[0];
            ep.command("GETATTR BLOCK".into()).await.unwrap();
            until(|| fixture.root.path().join("querying").exists()).await;
            assert!(alive(pid));
            fixture.write("answer", if accepted { "OK" } else { "ERR 99 canceled" });
            until(|| !alive(pid)).await;
            fixture.write("release", "");
            let result = crate::proxy::collect(&mut ep, None).await.unwrap();
            assert!(result.success());
            assert!(
                result
                    .lines
                    .iter()
                    .any(|line| &**line == b"D public-result")
            );
            if accepted {
                until(|| fixture.prompts().len() == 2).await;
                assert!(!query(&mut ep, "SERIALNO").await.success());
                assert_eq!(
                    fixture.prompts().len(),
                    2,
                    "confirmation should create exactly one next dialog"
                );
            } else {
                assert!(matches!(
                    prepared(&mut ep, &id).await,
                    CardPreparation::Rejected
                ));
                let repeated = random_id();
                ep.prepare(repeated.clone(), CardTarget::default())
                    .await
                    .unwrap();
                assert!(matches!(
                    prepared(&mut ep, &repeated).await,
                    CardPreparation::Rejected
                ));
                for _ in 0..4 {
                    assert!(!query(&mut ep, "SERIALNO").await.success());
                }
                assert_eq!(
                    fixture.prompts().len(),
                    1,
                    "queries resurrected a canceled prompt"
                );
                let refined = random_id();
                ep.prepare(
                    refined.clone(),
                    CardTarget {
                        serial: Some("AABB".into()),
                        key: Some("OPENPGP.1".into()),
                    },
                )
                .await
                .unwrap();
                assert!(matches!(
                    prepared(&mut ep, &refined).await,
                    CardPreparation::Rejected
                ));
                assert_eq!(
                    fixture.prompts().len(),
                    1,
                    "target refinement resurrected a dismissed candidate"
                );
            }
            let pids = fixture.prompts();
            ep.close().await;
            until(|| pids.iter().all(|pid| !alive(*pid))).await;
        }
    }

    #[tokio::test]
    async fn paused_probe_retains_readiness_and_drains_native_response() {
        let fixture = WaitingFixture::new();
        fixture.write("block-probe", "");
        let mut ep = fixture.endpoint().await;
        let id = fixture.start(&mut ep, CardTarget::default()).await;
        until(|| fixture.root.path().join("probing").exists()).await;
        ep.command("GETATTR BLOCK".into()).await.unwrap();
        fixture.write("card", "AABB");
        fixture.write("release", "");
        std::fs::remove_file(fixture.root.path().join("block-probe")).unwrap();
        let result = crate::proxy::collect(&mut ep, None).await.unwrap();
        assert_eq!(
            result.lines.iter().map(|line| &**line).collect::<Vec<_>>(),
            [b"D public-result".as_slice(), b"OK"]
        );
        assert!(
            matches!(prepared(&mut ep, &id).await, CardPreparation::Ready { serial } if serial == "AABB")
        );
        assert!(fixture.prompts().is_empty());
        ep.close().await;
    }

    #[tokio::test]
    async fn target_changes_reset_and_session_exit_close_only_the_current_prompt() {
        let fixture = WaitingFixture::new();
        let mut ep = fixture.endpoint().await;
        let first = fixture.start(&mut ep, CardTarget::default()).await;
        until(|| fixture.prompts().len() == 1).await;
        let old = fixture.prompts()[0];
        let target = CardTarget {
            serial: Some("AABB".into()),
            key: None,
        };
        let second = fixture.start(&mut ep, target.clone()).await;
        until(|| fixture.prompts().len() == 2 && !alive(old)).await;
        ep.cancel_preparation(first).await.unwrap();
        assert!(!query(&mut ep, "SERIALNO").await.success());
        assert!(alive(fixture.prompts()[1]));
        ep.cancel_preparation(second.clone()).await.unwrap();
        assert!(matches!(
            prepared(&mut ep, &second).await,
            CardPreparation::Unavailable
        ));
        until(|| fixture.prompts().iter().all(|pid| !alive(*pid))).await;
        fixture.start(&mut ep, target.clone()).await;
        until(|| fixture.prompts().len() == 3).await;
        assert!(query(&mut ep, "RESET").await.success());
        until(|| fixture.prompts().iter().all(|pid| !alive(*pid))).await;
        fixture.start(&mut ep, target).await;
        until(|| fixture.prompts().len() == 4).await;
        ep.close().await;
        until(|| fixture.prompts().iter().all(|pid| !alive(*pid))).await;
    }

    #[tokio::test]
    async fn insertion_prompt_works_with_password_service_disabled_and_requires_matching_card() {
        let root = tempfile::tempdir().unwrap();
        let program = root.path().join("test-native");
        let card = root.path().join("inserted");
        let prompt = root.path().join("prompted");
        let script = format!(
            r#"#!/bin/sh
printf 'OK\n'
while IFS= read -r line; do
 case "$line" in
 SERIALNO*) if [ -f '{card}' ]; then printf 'S SERIALNO '; cat '{card}'; printf '\nOK\n'; else printf 'ERR 108 no-card\n'; fi ;;
 CONFIRM*) printf 'confirmed\n' >> '{prompt}'; printf 'OK\n' ;;
 *) printf 'OK\n' ;;
 esac
done
"#,
            card = card.display(),
            prompt = prompt.display()
        );
        std::fs::write(&program, script).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let app = Arc::new(App {
            config: crate::storage::Config {
                scdaemon: crate::storage::ServiceConfig {
                    enabled: true,
                    program: Some(program.clone()),
                },
                pinentry: crate::storage::ServiceConfig {
                    enabled: false,
                    program: Some(program),
                },
                ..Default::default()
            },
            config_file: root.path().join("client.toml"),
            paths: AppPaths::resolve(&BTreeMap::new(), root.path(), root.path(), unsafe {
                libc::geteuid()
            }),
            identity: Arc::new(Identity::generate("test".into()).unwrap()),
        });
        let provider = NativeProvider(app.config.clone());
        let mut ep = open(
            app.clone(),
            ServiceKind::Scdaemon,
            Arc::new(Semaphore::new(1)),
            CancellationToken::new(),
            None,
        )
        .await
        .unwrap();
        let stop = CancellationToken::new();
        let context = ProviderContext {
            local: None,
            channel: String::new(),
            peer: String::new(),
            session: String::new(),
        };
        let mut preparation = provider
            .prepare(
                app,
                CardTarget {
                    serial: Some("AABB".into()),
                    key: None,
                },
                context,
            )
            .unwrap();
        let prepare = preparation.poll(&mut ep, stop);
        tokio::pin!(prepare);
        tokio::select! { result=&mut prepare=>panic!("confirmation won without a card: {result:?}"), _=tokio::time::sleep(Duration::from_millis(150))=>{} }
        assert!(prompt.exists());
        assert!(std::fs::read_to_string(&prompt).unwrap().lines().count() > 1);
        std::fs::write(&card, "CCDD").unwrap();
        tokio::select! { result=&mut prepare=>panic!("wrong card won: {result:?}"), _=tokio::time::sleep(Duration::from_millis(150))=>{} }
        std::fs::write(&card, "AABB").unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), &mut prepare)
                .await
                .unwrap()
                .unwrap(),
            Some("AABB".into())
        );
    }
}
