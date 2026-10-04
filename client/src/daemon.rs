use crate::{
    network::{Connection, Event},
    storage::{App, ensure_runtime},
};
use anyhow::{Context, Result, bail};
pub use hibiki_core::session::Hub;
use hibiki_core::session::announce;
use hibiki_lib::protocol::*;
use std::{sync::Arc, time::Duration};
async fn local_connection(
    app: Arc<App>,
    mut available: tokio::sync::watch::Receiver<Option<Arc<Hub>>>,
    mut stream: tokio::net::UnixStream,
) -> Result<()> {
    use crate::frontend::{DaemonStatus, LocalRequest};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let deadline =
        tokio::time::Instant::now() + Duration::from_secs(app.config.operation_timeout_seconds);
    let request = tokio::time::timeout_at(
        deadline.min(tokio::time::Instant::now() + Duration::from_secs(5)),
        async {
            let length = stream.read_u32().await? as usize;
            if length > 8192 {
                bail!("IPC header limit");
            }
            let mut bytes = vec![0; length];
            stream.read_exact(&mut bytes).await?;
            Ok::<LocalRequest, anyhow::Error>(hibiki_lib::decode(&bytes)?)
        },
    )
    .await??;
    let open = match request {
        LocalRequest::Status => {
            let status = DaemonStatus {
                device: app.identity.device.id(),
                relay_connected: available
                    .borrow()
                    .as_ref()
                    .is_some_and(|hub| !hub.connection().closed.is_cancelled()),
                config: app.config.clone(),
            };
            let bytes = hibiki_lib::encode(&status)?;
            tokio::time::timeout(Duration::from_secs(2), async {
                stream.write_u32(bytes.len() as u32).await?;
                stream.write_all(&bytes).await
            })
            .await??;
            return Ok(());
        }
        LocalRequest::Open(open) => open,
    };
    let ready = tokio::time::timeout_at(deadline, async {
        loop {
            if let Some(hub) = available.borrow().clone() {
                return Ok::<_, anyhow::Error>(hub);
            }
            available.changed().await?;
        }
    })
    .await;
    match ready {
        Ok(Ok(hub)) => crate::proxy::serve(hub, stream, open).await,
        _ => {
            tokio::time::timeout(
                Duration::from_secs(2),
                crate::assuan_io::write_line(
                    &mut stream,
                    &hibiki_lib::assuan::error(
                        hibiki_lib::assuan::GENERAL,
                        "relay unavailable; startup wait timed out; run hibiki status",
                    ),
                ),
            )
            .await??;
            Ok(())
        }
    }
}

pub async fn run(app: App) -> Result<()> {
    crate::provider::preflight(&app).await?;
    use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
    ensure_runtime(&app.paths)?;
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(
            app.paths
                .runtime
                .join(format!("d-{}.lock", &app.identity.device.id()[..16])),
        )?;
    fs2::FileExt::try_lock_exclusive(&lock).context("HIbiki daemon already running")?;
    let socket = app.paths.ipc_socket();
    if socket.as_os_str().len() >= 104 {
        bail!("XDG runtime path too long");
    }
    if let Ok(m) = std::fs::symlink_metadata(&socket) {
        if !m.file_type().is_socket() || tokio::net::UnixStream::connect(&socket).await.is_ok() {
            bail!("IPC path is already in use");
        }
        std::fs::remove_file(&socket)?;
    }
    let listener = tokio::net::UnixListener::bind(&socket)?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
    struct SocketGuard(std::path::PathBuf);
    impl Drop for SocketGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _guard = SocketGuard(socket);
    let app = Arc::new(app);
    let card_slot = Arc::new(tokio::sync::Semaphore::new(1));
    let local_slots = Arc::new(tokio::sync::Semaphore::new(128));
    let mut delay = 1;
    let mut stable_hub: Option<Arc<Hub>> = None;
    let (available, available_rx) = tokio::sync::watch::channel::<Option<Arc<Hub>>>(None);
    let listener_stop = tokio_util::sync::CancellationToken::new();
    let accept_stop = listener_stop.clone();
    let listener_app = app.clone();
    let listener_job = tokio::spawn(async move {
        let mut local_jobs = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _=accept_stop.cancelled()=>break,
                Some(_)=local_jobs.join_next(), if !local_jobs.is_empty()=>{},
                accepted=listener.accept()=>{
                    let Ok((stream,_))=accepted else { break; };
                    if let Ok(permit)=local_slots.clone().try_acquire_owned() {
                        let app = listener_app.clone();
                        let available = available_rx.clone();
                        local_jobs.spawn(async move {
                            let _permit = permit;
                            let _ = local_connection(app, available, stream).await;
                        });
                    }
                }
            }
        }
        local_jobs.abort_all();
    });
    loop {
        let opened = tokio::select! {
            _=tokio::signal::ctrl_c()=>break,
            result=Connection::open(&app.config.server,app.config.allow_insecure,&app.identity)=>result,
        };
        let (connection, mut events) = match opened {
            Ok(v) => v,
            Err(_) => {
                eprintln!("relay unavailable; reconnecting");
                tokio::select! {_=tokio::signal::ctrl_c()=>break,_=tokio::time::sleep(Duration::from_secs(delay))=>{}}
                delay = (delay * 2).min(30);
                continue;
            }
        };
        let hub = match &stable_hub {
            Some(hub) => {
                hub.reconnect(connection.clone());
                hub.clone()
            }
            None => {
                let hub = Hub::new(
                    app.clone(),
                    connection.clone(),
                    Arc::new(crate::provider::NativeProvider(app.config.clone())),
                    card_slot.clone(),
                );
                stable_hub = Some(hub.clone());
                hub
            }
        };
        if announce(&hub).await.is_err() {
            connection.close();
            continue;
        }
        available.send_replace(Some(hub.clone()));
        hub.changed.notify_waiters();
        eprintln!("HIbiki daemon connected");
        delay = 1;
        let mut refresh = tokio::time::interval(Duration::from_secs(10));
        let mut jobs = tokio::task::JoinSet::new();
        let interrupted = loop {
            tokio::select! {
                _=tokio::signal::ctrl_c()=>break true,
                _=connection.closed.cancelled()=>break false,
                _=refresh.tick()=>{let h=hub.clone();jobs.spawn(async move {let _=announce(&h).await;});},
                Some(_)=jobs.join_next(),if !jobs.is_empty()=>{},
                event=events.recv()=>match event {
                    Some(Event::Message(Envelope::OperationReady {..}))=>hub.changed.notify_waiters(),
                    Some(Event::Message(Envelope::Relay {channel,peer,session,data}))=>{let _=hub.route(channel,peer,session,data).await;},
                    Some(Event::Message(Envelope::RelayFailure {session,peer,..}))=>{
                        hub.stop_session(&session, &peer);
                    },
                    Some(Event::Message(Envelope::OperationChanged {id}))=>hub.stop_operation(&id),
                    Some(Event::Message(Envelope::PeerOffline {peer}))=>hub.stop_peer(&peer),
                    Some(Event::Message(Envelope::ChannelChanged {channel}))=>{
                        let h=hub.clone();jobs.spawn(async move {if h.refresh(&channel).await.is_err(){h.stop_channel(&channel);}});
                    },
                    Some(Event::Disconnected)|None=>break false,
                    _=>{},
                }
            }
        };
        connection.close();
        let _ = tokio::time::timeout(Duration::from_secs(3), async {
            while jobs.join_next().await.is_some() {}
        })
        .await;
        jobs.abort_all();
        if interrupted {
            break;
        }
    }
    if let Some(hub) = stable_hub {
        hub.stop_all();
    }
    listener_stop.cancel();
    let _ = listener_job.await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::{DaemonStatus, LocalOpen, LocalRequest};
    use hibiki_lib::{decode, encode, identity::Identity, paths::AppPaths};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test(start_paused = true)]
    async fn offline_startup_expires_without_blocking_status() {
        let dir = tempfile::tempdir().unwrap();
        let app = Arc::new(App {
            config: crate::storage::Config {
                operation_timeout_seconds: 2,
                ..Default::default()
            },
            config_file: dir.path().join("client.toml"),
            paths: AppPaths::resolve(&Default::default(), dir.path(), dir.path(), unsafe {
                libc::geteuid()
            }),
            identity: Arc::new(Identity::generate("test".into()).unwrap()),
        });
        let (_sender, available) = tokio::sync::watch::channel(None);
        let (mut caller, accepted) = tokio::net::UnixStream::pair().unwrap();
        let task = tokio::spawn(local_connection(app.clone(), available.clone(), accepted));
        let request = encode(&LocalRequest::Open(LocalOpen {
            channel: "test".into(),
            service: ServiceKind::Pinentry,
            pid: 1,
            display: None,
        }))
        .unwrap();
        caller.write_u32(request.len() as u32).await.unwrap();
        caller.write_all(&request).await.unwrap();
        tokio::task::yield_now().await;
        let (mut status_client, status_stream) = tokio::net::UnixStream::pair().unwrap();
        let status_task = tokio::spawn(local_connection(app, available, status_stream));
        let request = encode(&LocalRequest::Status).unwrap();
        status_client.write_u32(request.len() as u32).await.unwrap();
        status_client.write_all(&request).await.unwrap();
        let size = status_client.read_u32().await.unwrap();
        let mut bytes = vec![0; size as usize];
        status_client.read_exact(&mut bytes).await.unwrap();
        assert!(!decode::<DaemonStatus>(&bytes).unwrap().relay_connected);
        status_task.await.unwrap().unwrap();
        tokio::time::advance(Duration::from_secs(3)).await;
        let mut output = String::new();
        caller.read_to_string(&mut output).await.unwrap();
        assert!(output.starts_with("ERR "), "{output}");
        assert!(output.contains("startup wait timed out"));
        task.await.unwrap().unwrap();
    }
}
