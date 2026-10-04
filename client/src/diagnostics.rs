use crate::{
    frontend::{DaemonStatus, LocalRequest},
    network::Connection,
    storage::App,
};
use anyhow::{Context, Result, bail};
use hibiki_lib::{
    decode, encode,
    protocol::{Control, Reply, ServiceKind},
};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

pub async fn daemon_status(app: &App) -> Result<DaemonStatus> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut stream = UnixStream::connect(app.paths.ipc_socket())
            .await
            .context("daemon unavailable; run hibiki daemon or start the user service")?;
        let request = encode(&LocalRequest::Status)?;
        stream.write_u32(request.len() as u32).await?;
        stream.write_all(&request).await?;
        let length = stream.read_u32().await? as usize;
        if length > 65536 {
            bail!("invalid daemon status length");
        }
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes).await?;
        let status: DaemonStatus = decode(&bytes)?;
        if status.device != app.identity.device.id() {
            bail!("daemon identity mismatch");
        }
        Ok(status)
    })
    .await
    .context("daemon status timed out; check the daemon logs and restart it")?
}

pub fn setup(app: &App) {
    eprintln!("\nNext steps (show again with hibiki setup):");
    eprintln!("1. Join an administrator/member invitation: hibiki channel join 'INVITATION'");
    eprintln!("   Obtain the PSK separately; compare verification words for member approval.");
    eprintln!("2. On requesting devices, select the joined channel: hibiki use NAME");
    eprintln!(
        "3. Edit {:?}: enable scdaemon and/or pinentry only on providers.",
        app.config_file
    );
    eprintln!("   Omit program for gpgconf discovery; background input needs a GUI Pinentry.");
    eprintln!("4. Run hibiki daemon on every device; check hibiki doctor in another terminal.");
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        eprintln!("5. Add the needed lines to the requesting device's gpg-agent.conf:");
        eprintln!(
            "   scdaemon-program {}",
            dir.join("hibiki-scdaemon").display()
        );
        eprintln!(
            "   pinentry-program {}",
            dir.join("hibiki-pinentry").display()
        );
    }
    eprintln!("   Restart that GnuPG home's agent with gpgconf --kill gpg-agent.");
    #[cfg(target_os = "linux")]
    {
        eprintln!(
            "6. For background startup, install systemd/hibiki.service from the client package"
        );
        eprintln!("   into ~/.config/systemd/user/; then systemctl --user daemon-reload");
        eprintln!("   and systemctl --user enable --now hibiki.service (binaries: ~/.local/bin).");
        eprintln!(
            "   Stop a manually started daemon first; import your GUI session environment for Pinentry."
        );
    }
    #[cfg(not(target_os = "linux"))]
    eprintln!(
        "6. macOS: run hibiki daemon in a terminal, or configure a per-user launchd job with the same paths and GUI environment."
    );
    eprintln!("Use the same --config / HIBIKI_CONFIG and XDG paths for every command and adapter.");
}

pub async fn inspect(app: &App, doctor: bool) -> Result<()> {
    println!(
        "device: {} {:?}",
        app.identity.device.id(),
        app.identity.device.name
    );
    println!("configuration: {:?}", app.config_file);
    println!("relay: {:?}", app.config.server);
    println!("IPC: {:?}", app.paths.ipc_socket());
    let mut failures = 0;
    match daemon_status(app).await {
        Ok(status) => {
            println!(
                "daemon: running; relay: {}",
                if status.relay_connected {
                    "connected"
                } else {
                    "reconnecting"
                }
            );
            println!(
                "active providers: scdaemon={} pinentry={}",
                status.config.scdaemon.enabled, status.config.pinentry.enabled
            );
            if !status.relay_connected {
                failures += 1;
            }
            if status.config != app.config {
                // Channel selection is read by each adapter; other settings need a restart.
                let mut active = status.config;
                active.default_channel = app.config.default_channel.clone();
                if active != app.config {
                    println!("FAIL: daemon configuration differs from disk; restart hibiki daemon");
                    failures += 1;
                }
            }
        }
        Err(error) => {
            println!("FAIL: {error:#}");
            failures += 1;
        }
    }
    match &app.config.default_channel {
        Some(id) => match app.proof(id).and_then(|p| {
            let state = p.verify()?;
            state.member(&app.identity.device.id())?;
            Ok(state.name)
        }) {
            Ok(name) => println!("selected channel: {name:?} ({id})"),
            Err(error) => {
                println!(
                    "FAIL: selected channel: {error:#}; run hibiki channel list and hibiki use NAME"
                );
                failures += 1;
            }
        },
        None => println!("selected channel: none; requesting devices must run hibiki use NAME"),
    }
    if doctor {
        for service in [ServiceKind::Scdaemon, ServiceKind::Pinentry] {
            if !app.config.service(service).enabled {
                println!("{service:?}: disabled (remote requests remain available)");
                continue;
            }
            match crate::provider::program(app, service).await {
                Ok(path) => println!("{service:?}: executable {}", path.display()),
                Err(error) => {
                    println!(
                        "FAIL: {service:?}: {error:#}; set its program or disable this provider"
                    );
                    failures += 1;
                }
            }
        }
        let relay = tokio::time::timeout(Duration::from_secs(15), async {
            let (connection, _) =
                Connection::open(&app.config.server, app.config.allow_insecure, &app.identity)
                    .await?;
            let _guard = connection.closed.clone().drop_guard();
            let result = connection.request(Control::Policy).await;
            connection.close();
            let Reply::Policy {
                allow_client_channel_creation,
            } = result?
            else {
                bail!("invalid policy response");
            };
            Ok::<_, anyhow::Error>(allow_client_channel_creation)
        })
        .await;
        match relay {
            Ok(Ok(allowed)) => {
                println!("relay authentication: OK; client channel creation: {allowed}")
            }
            Ok(Err(error)) => {
                println!("FAIL: relay authentication: {error:#}");
                failures += 1;
            }
            Err(_) => {
                println!("FAIL: relay authentication timed out");
                failures += 1;
            }
        }
        println!(
            "Provider checks do not open a card or PIN dialog. Verify reader access and GUI/TTY availability locally."
        );
        println!("For GPG integration and background startup instructions, run hibiki setup.");
    }
    if failures > 0 {
        bail!("{failures} check(s) need attention");
    }
    Ok(())
}
