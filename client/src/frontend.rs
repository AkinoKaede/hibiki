use crate::{
    assuan_io::{read_line, write_line},
    storage::App,
};
use anyhow::{Context, Result, bail};
use hibiki_lib::{assuan, encode, protocol::ServiceKind};
use serde::{Deserialize, Serialize};
use std::{os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::Mutex,
    task::JoinSet,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct LocalOpen {
    pub channel: String,
    pub service: ServiceKind,
    pub pid: u32,
    pub display: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub enum LocalRequest {
    Open(LocalOpen),
    Status,
}

#[derive(Serialize, Deserialize)]
pub struct DaemonStatus {
    pub device: String,
    pub relay_connected: bool,
    pub config: crate::storage::Config,
}

pub async fn run(service: ServiceKind) -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut display = std::env::var("DISPLAY").ok();
    let mut multi_server = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--server" => {}
            "--multi-server" => multi_server = service == ServiceKind::Scdaemon,
            "--homedir" => {
                args.next().context("missing homedir")?;
            }
            "--display" => display = Some(args.next().context("missing display")?),
            "--version" => {
                println!("Hibiki {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--help" => {
                println!(
                    "Hibiki Assuan stdio adapter. Configure HIBIKI_CONFIG and run hibiki daemon."
                );
                return Ok(());
            }
            _ => bail!("unsupported adapter argument"),
        }
    }
    let path = std::env::var_os("HIBIKI_CONFIG").map(std::path::PathBuf::from);
    let app = App::load(path.as_deref())?;
    let channel = app
        .config
        .default_channel
        .clone()
        .context("select a channel with hibiki use NAME")?;
    app.proof(&channel)?
        .verify()?
        .member(&app.identity.device.id())?;
    let header = encode(&LocalRequest::Open(LocalOpen {
        channel,
        service,
        pid: std::process::id(),
        display,
    }))?;
    // gpg-agent keeps the primary pipe for one client and uses this socket for
    // other clients. Accepting --multi-server without advertising a socket
    // makes GnuPG report "No SmartCard daemon" whenever the pipe is occupied.
    let directory = if multi_server {
        crate::storage::ensure_runtime(&app.paths)?;
        Some(
            tempfile::Builder::new()
                .prefix("scd-")
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir_in(&app.paths.runtime)?,
        )
    } else {
        None
    };
    let socket_name = directory.as_ref().map(|dir| dir.path().join("S"));
    let listener = if let Some(path) = &socket_name {
        let listener = UnixListener::bind(path).context("create adapter socket")?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Some(listener)
    } else {
        None
    };
    let adapter = Arc::new(Adapter {
        ipc_socket: app.paths.ipc_socket(),
        header,
        socket_name,
    });
    let primary = adapter.relay(crate::stdio::Stdio::new(0)?, crate::stdio::Stdio::new(1)?);
    let mut sessions = JoinSet::new();
    let accepting = async {
        let Some(listener) = listener else {
            return std::future::pending::<Result<()>>().await;
        };
        loop {
            tokio::select! {
                Some(_) = sessions.join_next(), if !sessions.is_empty() => {},
                accepted = listener.accept(), if sessions.len() < 128 => {
                    let (stream, _) = accepted?;
                    let adapter = adapter.clone();
                    sessions.spawn(async move {
                        let (reader, writer) = stream.into_split();
                        adapter.relay(reader, writer).await
                    });
                }
            }
        }
    };
    let result = tokio::select! {r = primary => r, r = accepting => r};
    // The primary pipe owns the adapter lifetime, including all secondary IPC
    // sessions. Drop the private socket directory only after they are closed.
    sessions.abort_all();
    while sessions.join_next().await.is_some() {}
    drop(directory);
    result
}

struct Adapter {
    ipc_socket: PathBuf,
    header: Vec<u8>,
    socket_name: Option<PathBuf>,
}

impl Adapter {
    async fn relay<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        input: R,
        output: W,
    ) -> Result<()> {
        let mut stream = UnixStream::connect(&self.ipc_socket)
            .await
            .context("run hibiki daemon first")?;
        stream.write_u32(self.header.len().try_into()?).await?;
        stream.write_all(&self.header).await?;
        let (reader, mut writer) = stream.into_split();
        let mut reader = crate::assuan_io::SecretReader::new(reader);
        let mut input = crate::assuan_io::SecretReader::new(input);
        let output = Mutex::new(output);
        // Reserve the first output for the daemon greeting, while still
        // observing caller EOF if the daemon is waiting for its relay.
        let mut greeting_output = output.lock().await;
        let upstream = async {
            while let Some(line) = read_line(&mut input).await? {
                if let Some(path) = &self.socket_name
                    && assuan::command(&line).ok() == Some(("GETINFO", "socket_name"))
                {
                    let mut output = output.lock().await;
                    for data in assuan::data_lines(path.as_os_str().as_encoded_bytes()) {
                        write_line(&mut *output, &data).await?;
                    }
                    write_line(&mut *output, b"OK").await?;
                } else {
                    write_line(&mut writer, &line).await?;
                }
            }
            Ok::<_, anyhow::Error>(())
        };
        let downstream = async {
            let greeting = read_line(&mut reader)
                .await?
                .context("missing daemon greeting")?;
            write_line(&mut *greeting_output, &greeting).await?;
            drop(greeting_output);
            while let Some(line) = read_line(&mut reader).await? {
                write_line(&mut *output.lock().await, &line).await?;
            }
            Ok::<_, anyhow::Error>(())
        };
        // Keep each read loop alive across partial lines; read_line itself is
        // not cancel-safe and must not be recreated on each select iteration.
        tokio::select! {r = upstream => r, r = downstream => r}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn caller_exit_cancels_a_pending_greeting() {
        let dir = tempfile::tempdir().unwrap();
        let ipc_socket = dir.path().join("ipc");
        let listener = UnixListener::bind(&ipc_socket).unwrap();
        let adapter = Adapter {
            ipc_socket,
            header: vec![1],
            socket_name: None,
        };
        let (caller, connection) = tokio::io::duplex(128);
        let task = tokio::spawn(async move {
            let (input, output) = tokio::io::split(connection);
            adapter.relay(input, output).await
        });
        let (mut daemon, _) = listener.accept().await.unwrap();
        assert_eq!(daemon.read_u32().await.unwrap(), 1);
        assert_eq!(daemon.read_u8().await.unwrap(), 1);
        // Model a daemon waiting for its relay without sending a greeting.
        drop(caller);
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(daemon.read(&mut [0]).await.unwrap(), 0);
    }
}
