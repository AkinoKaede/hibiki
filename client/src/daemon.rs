use crate::{
    network::{Connection, Event},
    storage::{App, ensure_runtime},
};
use anyhow::{Context, Result, bail};
pub use hibiki_core::session::Hub;
use hibiki_core::session::announce;
use hibiki_lib::protocol::*;
use std::{sync::Arc, time::Duration};
pub async fn run(app: App) -> Result<()> {
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
    let (available, mut available_rx) = tokio::sync::watch::channel::<Option<Arc<Hub>>>(None);
    let listener_stop = tokio_util::sync::CancellationToken::new();
    let accept_stop = listener_stop.clone();
    let listener_job = tokio::spawn(async move {
        let mut local_jobs = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _=accept_stop.cancelled()=>break,
                Some(_)=local_jobs.join_next(), if !local_jobs.is_empty()=>{},
                accepted=listener.accept()=>{
                    let Ok((stream,_))=accepted else { break; };
                    if let Ok(permit)=local_slots.clone().try_acquire_owned() {
                        while available_rx.borrow().is_none() {
                            tokio::select! { _=accept_stop.cancelled()=>return, _=available_rx.changed()=>{} }
                        }
                        let hub=available_rx.borrow().as_ref().unwrap().clone();
                        local_jobs.spawn(async move { let _permit=permit; let _=crate::proxy::serve(hub,stream).await; });
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
