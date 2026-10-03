use crate::{
    assuan_io::{read_line, write_line},
    storage::App,
};
use anyhow::{Context, Result, bail};
use hibiki_lib::{encode, protocol::ServiceKind};
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncWriteExt, net::UnixStream};

#[derive(Serialize, Deserialize)]
pub struct LocalOpen {
    pub channel: String,
    pub service: ServiceKind,
    pub pid: u32,
    pub display: Option<String>,
}

pub async fn run(service: ServiceKind) -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut display = std::env::var("DISPLAY").ok();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--server" | "--multi-server" => {}
            "--homedir" => {
                args.next().context("missing homedir")?;
            }
            "--display" => display = Some(args.next().context("missing display")?),
            "--version" => {
                println!("HIbiki {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--help" => {
                println!(
                    "HIbiki Assuan stdio adapter. Configure HIBIKI_CONFIG and run hibiki daemon."
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
    let mut stream = UnixStream::connect(app.paths.ipc_socket())
        .await
        .context("run hibiki daemon first")?;
    let header = encode(&LocalOpen {
        channel,
        service,
        pid: std::process::id(),
        display,
    })?;
    stream.write_u32(header.len().try_into()?).await?;
    stream.write_all(&header).await?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = crate::assuan_io::SecretReader::new(reader);
    let mut stdin = crate::assuan_io::SecretReader::new(crate::stdio::Stdio::new(0)?);
    let mut stdout = crate::stdio::Stdio::new(1)?;
    let upstream = async {
        while let Some(line) = read_line(&mut stdin).await? {
            write_line(&mut writer, &line).await?;
        }
        Ok::<_, anyhow::Error>(())
    };
    let downstream = async {
        while let Some(line) = read_line(&mut reader).await? {
            write_line(&mut stdout, &line).await?;
        }
        Ok::<_, anyhow::Error>(())
    };
    tokio::select! {r=upstream=>r,r=downstream=>r}
}
