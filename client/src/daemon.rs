use crate::{
    network::{Connection, Event},
    storage::{App, ensure_runtime},
    terminal::{SUCCESS, WARNING},
};
use anstream::eprintln;
use anyhow::{Context, Result, bail};
pub use hibiki_core::session::Hub;
use hibiki_core::session::announce;
use hibiki_lib::protocol::*;
use std::{sync::Arc, time::Duration};
async fn local_connection(
    app: Arc<App>,
    hub: Arc<Hub>,
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
                relay_connected: !hub.connection().closed.is_cancelled(),
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
        LocalRequest::Ping {
            channel,
            peer,
            count,
        } => {
            let result = hub
                .ping(&channel, &peer, count)
                .await
                .map_err(|e| e.to_string());
            let bytes = hibiki_lib::encode(&result)?;
            stream.write_u32(bytes.len() as u32).await?;
            stream.write_all(&bytes).await?;
            return Ok(());
        }
        LocalRequest::Open(open) => open,
    };
    crate::proxy::serve(hub, stream, open).await
}

pub async fn run(app: App) -> Result<()> {
    run_until_shutdown(app, tokio::signal::ctrl_c()).await
}

async fn run_until_shutdown(
    app: App,
    shutdown: impl std::future::Future<Output = std::io::Result<()>>,
) -> Result<()> {
    // Reuse one listener throughout the lifecycle. Recreating ctrl_c() in each
    // select drops its signal receiver when another event wins, losing SIGINTs
    // delivered between that receiver's cancellation and its replacement.
    tokio::pin!(shutdown);
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
    let hub = Hub::new(
        app.clone(),
        Connection::disconnected(),
        Arc::new(crate::provider::NativeProvider(app.config.clone())),
        card_slot,
    );
    let listener_stop = tokio_util::sync::CancellationToken::new();
    let accept_stop = listener_stop.clone();
    let listener_app = app.clone();
    let listener_hub = hub.clone();
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
                        let hub = listener_hub.clone();
                        local_jobs.spawn(async move {
                            let _permit = permit;
                            let _ = local_connection(app, hub, stream).await;
                        });
                    }
                }
            }
        }
        local_jobs.abort_all();
    });
    loop {
        let opened = tokio::select! {
            _=&mut shutdown=>break,
            result=Connection::open(&app.config.server,app.config.allow_insecure,&app.identity)=>result,
        };
        let (connection, mut events) = match opened {
            Ok(v) => v,
            Err(_) => {
                eprintln!("{WARNING}relay unavailable; reconnecting{WARNING:#}");
                tokio::select! {_=&mut shutdown=>break,_=tokio::time::sleep(Duration::from_secs(delay))=>{}}
                delay = (delay * 2).min(30);
                continue;
            }
        };
        hub.reconnect(connection.clone());
        let announced = tokio::select! {
            _=&mut shutdown=>{connection.close();break;},
            result=announce(&hub)=>result,
        };
        if announced.is_err() {
            connection.close();
            continue;
        }
        hub.changed.notify_waiters();
        eprintln!("{SUCCESS}HIbiki daemon connected{SUCCESS:#}");
        delay = 1;
        let mut refresh = tokio::time::interval(Duration::from_secs(10));
        let mut jobs = tokio::task::JoinSet::new();
        let interrupted = loop {
            tokio::select! {
                _=&mut shutdown=>break true,
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
                    Some(Event::Message(Envelope::PeerOnline { .. }))=>hub.changed.notify_waiters(),
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
    hub.stop_all();
    listener_stop.cancel();
    let _ = listener_job.await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::{DaemonStatus, LocalOpen, LocalRequest};
    use hibiki_lib::{
        channel::{ChannelGenesis, MembershipProof},
        decode, encode,
        identity::Identity,
        paths::AppPaths,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn shutdown_with_relay_activity(answer_announce: bool) {
        use futures_util::{SinkExt, StreamExt};
        use hibiki_lib::wire;
        use tokio_tungstenite::tungstenite::Message;

        let dir = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let app = App {
            config: crate::storage::Config {
                server: format!("ws://{}{WS_PATH}", listener.local_addr().unwrap()),
                allow_insecure: true,
                ..Default::default()
            },
            config_file: dir.path().join("client.toml"),
            paths: AppPaths::resolve(&Default::default(), dir.path(), dir.path(), unsafe {
                libc::geteuid()
            }),
            identity: Arc::new(Identity::generate("shutdown-test".into()).unwrap()),
        };
        let socket = app.paths.ipc_socket();
        let (ready, waiting) = tokio::sync::oneshot::channel();
        let relay = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            ws.send(Message::Binary(
                wire::encode(&Envelope::Hello {
                    version: VERSION.into(),
                    nonce: hibiki_lib::random_id(),
                    capabilities: wire::supported_capabilities(),
                })
                .unwrap()
                .into(),
            ))
            .await
            .unwrap();
            let Message::Binary(raw) = ws.next().await.unwrap().unwrap() else {
                panic!()
            };
            assert!(matches!(
                wire::decode::<Envelope>(&raw).unwrap(),
                Envelope::Authenticate { .. }
            ));
            ws.send(Message::Binary(
                wire::encode(&Envelope::Authenticated {
                    capabilities: wire::supported_capabilities(),
                })
                .unwrap()
                .into(),
            ))
            .await
            .unwrap();
            let mut ready = Some(ready);
            let mut announced = false;
            let mut messages = 0;
            let mut tick = tokio::time::interval(Duration::from_millis(1));
            loop {
                tokio::select! {
                    incoming = ws.next() => match incoming {
                        Some(Ok(Message::Binary(raw))) => {
                            let Envelope::Request { id, command: Control::Announce { .. } } =
                                wire::decode(&raw).unwrap() else { panic!() };
                            if answer_announce {
                                ws.send(Message::Binary(wire::encode(&Envelope::Response {
                                    id, result: Ok(Reply::Ok),
                                }).unwrap().into())).await.unwrap();
                                announced = true;
                            } else if let Some(ready) = ready.take() {
                                ready.send(()).unwrap();
                            }
                        }
                        None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break,
                        _ => {}
                    },
                    _ = tick.tick(), if announced => {
                        if ws.send(Message::Binary(wire::encode(&Envelope::PeerOnline {
                            peer: "busy-peer".into(),
                        }).unwrap().into())).await.is_err() { break; }
                        messages += 1;
                        if messages == 32 {
                            ready.take().unwrap().send(()).unwrap();
                        }
                    }
                }
            }
        });
        let stop = tokio_util::sync::CancellationToken::new();
        let shutdown = stop.clone();
        let daemon = tokio::spawn(run_until_shutdown(app, async move {
            shutdown.cancelled().await;
            Ok(())
        }));
        tokio::time::timeout(Duration::from_secs(2), waiting)
            .await
            .unwrap()
            .unwrap();
        assert!(socket.exists());
        stop.cancel();
        tokio::time::timeout(Duration::from_secs(1), daemon)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(!socket.exists(), "daemon did not clean up its listener");
        tokio::time::timeout(Duration::from_secs(3), relay)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn shutdown_interrupts_initial_announce_without_waiting_for_request_timeout() {
        shutdown_with_relay_activity(false).await;
    }

    #[tokio::test]
    async fn shutdown_remains_ready_while_relay_events_keep_arriving() {
        shutdown_with_relay_activity(true).await;
    }

    #[tokio::test(start_paused = true)]
    async fn offline_status_and_local_requests_do_not_wait_for_relay() {
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
        let proof = MembershipProof {
            genesis: ChannelGenesis::create(&app.identity, "test".into(), "verifier").unwrap(),
            events: vec![],
        };
        let channel = proof.genesis.body.id.clone();
        app.bootstrap(proof, None).unwrap();
        let hub = Hub::new(
            app.clone(),
            Connection::disconnected(),
            Arc::new(crate::provider::NativeProvider(app.config.clone())),
            Arc::new(tokio::sync::Semaphore::new(1)),
        );
        let (mut caller, accepted) = tokio::net::UnixStream::pair().unwrap();
        let task = tokio::spawn(local_connection(app.clone(), hub.clone(), accepted));
        let request = encode(&LocalRequest::Open(LocalOpen {
            channel,
            service: ServiceKind::Pinentry,
            pid: 1,
            display: None,
        }))
        .unwrap();
        caller.write_u32(request.len() as u32).await.unwrap();
        caller.write_all(&request).await.unwrap();
        tokio::task::yield_now().await;
        let (mut status_client, status_stream) = tokio::net::UnixStream::pair().unwrap();
        let status_task = tokio::spawn(local_connection(app, hub, status_stream));
        let request = encode(&LocalRequest::Status).unwrap();
        status_client.write_u32(request.len() as u32).await.unwrap();
        status_client.write_all(&request).await.unwrap();
        let size = status_client.read_u32().await.unwrap();
        let mut bytes = vec![0; size as usize];
        status_client.read_exact(&mut bytes).await.unwrap();
        assert!(!decode::<DaemonStatus>(&bytes).unwrap().relay_connected);
        status_task.await.unwrap().unwrap();
        // The adapter can open and close using saved trust before the first
        // relay connection, without consuming the command timeout.
        caller.write_all(b"BYE\n").await.unwrap();
        tokio::time::timeout(Duration::from_millis(100), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let mut output = String::new();
        caller.read_to_string(&mut output).await.unwrap();
        assert!(output.starts_with("OK HIbiki Assuan"), "{output}");
        assert!(output.contains("OK closing connection"));
    }
}
