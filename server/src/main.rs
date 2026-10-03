mod db;
mod entities;
mod service;
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use hibiki_lib::{
    channel::{hash_psk, make_psk},
    paths::AppPaths,
};
use serde::Deserialize;
use std::{
    fs::{self, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(
    version,
    about = "Hibiki relay for end-to-end encrypted GPG operations"
)]
struct Args {
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}
#[derive(Subcommand)]
enum Command {
    Channel {
        #[command(subcommand)]
        command: ChannelCommand,
    },
}
#[derive(Subcommand)]
enum ChannelCommand {
    /// Reserve a channel without any member; print a single-use initialization invitation.
    Create {
        name: String,
        #[arg(long)]
        server: String,
        #[arg(long)]
        psk_file: Option<PathBuf>,
        #[arg(long, conflicts_with = "psk_file")]
        prompt_psk: bool,
    },
    /// Permanently delete channel records and stop routing (local administrator only).
    Delete {
        name: String,
    },
    List,
}
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Config {
    listen: String,
    database: Option<PathBuf>,
    allow_client_channel_creation: bool,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:7749".into(),
            database: None,
            allow_client_channel_creation: true,
        }
    }
}
fn private_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
    }
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
        bail!(
            "directory must be owned by current user and mode 0700: {}",
            path.display()
        );
    }
    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();
    let paths = AppPaths::discover()?;
    let candidate = paths
        .config_candidates(args.config.as_deref(), "server.toml")
        .into_iter()
        .find(|p| p.is_file());
    if args.config.is_some() && candidate.is_none() {
        bail!("configuration file not found");
    }
    let config: Config = if let Some(path) = &candidate {
        toml::from_str(&fs::read_to_string(path)?)?
    } else {
        Config::default()
    };
    let database = match config.database {
        Some(p) if p.is_absolute() => p,
        Some(p) => candidate
            .as_ref()
            .and_then(|c| c.parent())
            .unwrap_or(Path::new("."))
            .join(p),
        None => paths.data.join("server").join("hibiki.sqlite3"),
    };
    private_dir(database.parent().context("database directory")?)?;
    if !database.exists() {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&database)?;
    }
    let m = fs::symlink_metadata(&database)?;
    if !m.is_file() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
        bail!("database must be a private regular file");
    }
    let db = db::Database::open(&database).await?;
    if let Some(Command::Channel { command }) = args.command {
        match command {
            ChannelCommand::Create {
                name,
                server,
                psk_file,
                prompt_psk,
            } => {
                let url = url::Url::parse(&server)?;
                if !matches!(url.scheme(), "ws" | "wss")
                    || url.host_str().is_none()
                    || !url.username().is_empty()
                    || url.password().is_some()
                {
                    bail!("expected ws:// or wss:// server URL without credentials");
                }
                let (secret, generated) = if let Some(path) = psk_file {
                    (
                        fs::read_to_string(path)?
                            .trim_end_matches(['\r', '\n'])
                            .to_owned(),
                        false,
                    )
                } else if prompt_psk {
                    (rpassword::prompt_password("Channel PSK: ")?, false)
                } else {
                    (make_psk(), true)
                };
                let invite = db.reserve(server, name, hash_psk(&secret)?).await?;
                println!("channel {}", invite.id);
                println!("invite {}", invite.export()?);
                if generated {
                    println!("PSK {secret}");
                }
            }
            ChannelCommand::Delete { name } => {
                let id = db.delete(&name).await?;
                println!("deleted {name} {id}");
            }
            ChannelCommand::List => {
                for (id, name, empty) in db.admin_list().await? {
                    println!("{id} {} {name}", if empty { "empty" } else { "active" });
                }
            }
        }
        return Ok(());
    }
    let service = service::Service::new(db, config.allow_client_channel_creation);
    let stop = tokio_util::sync::CancellationToken::new();
    let _guard = stop.clone().drop_guard();
    tokio::spawn(service.clone().watch_deleted(stop));
    let listener = tokio::net::TcpListener::bind(&config.listen).await?;
    eprintln!("hibiki-server listening on {}", listener.local_addr()?);
    axum::serve(listener, service.router())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests;
