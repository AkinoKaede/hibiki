mod db;
mod entities;
mod health;
mod operations;
mod service;
use anyhow::{Context, Result, bail};
use axum::serve::ListenerExt;
use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::{
    fs::{self, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const CONFIG_PATHS: [&str; 2] = [
    "/etc/hibiki/server.toml",
    "/usr/local/etc/hibiki/server.toml",
];

#[derive(Parser)]
#[command(
    version,
    about = "Hibiki relay for end-to-end encrypted GPG operations"
)]
struct Args {
    /// Configuration file (otherwise search /etc/hibiki, then /usr/local/etc/hibiki).
    #[arg(long, global = true, env = "HIBIKI_SERVER_CONFIG")]
    config: Option<PathBuf>,
    /// Override the listen address from the configuration file.
    #[arg(long, global = true, env = "HIBIKI_SERVER_LISTEN")]
    listen: Option<String>,
    /// Override the database path (relative paths use the configuration directory).
    #[arg(long, global = true, env = "HIBIKI_SERVER_DATABASE")]
    database: Option<PathBuf>,
    /// Override whether authenticated clients may create channels.
    #[arg(
        long,
        global = true,
        env = "HIBIKI_SERVER_ALLOW_CLIENT_CHANNEL_CREATION"
    )]
    allow_client_channel_creation: Option<bool>,
    #[command(subcommand)]
    command: Option<Command>,
}
#[derive(Subcommand)]
enum Command {
    /// Check the running relay's /healthz endpoint (exit 0 if healthy, 1 otherwise).
    Health,
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
    },
    /// Generate a fresh initialization invitation for an unclaimed channel.
    Invite {
        name: String,
        #[arg(long)]
        server: String,
    },
    /// Permanently delete channel records and stop routing (local administrator only).
    Delete { name: String },
    /// Revoke relay access to any device, independently of member approval authority.
    Revoke {
        name: String,
        device_id: String,
        #[arg(long)]
        subtree: bool,
    },
    List {
        #[arg(long)]
        json: bool,
    },
}
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Config {
    listen: String,
    database: PathBuf,
    allow_client_channel_creation: bool,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:7749".into(),
            database: "/var/lib/hibiki/hibiki.sqlite3".into(),
            allow_client_channel_creation: false,
        }
    }
}

fn load_config(explicit: Option<&Path>, defaults: &[&Path]) -> Result<(Config, Option<PathBuf>)> {
    let explicit_paths = explicit.map(|path| [path]);
    let candidates = explicit_paths.as_ref().map_or(defaults, |paths| &paths[..]);
    for path in candidates {
        match fs::read_to_string(path) {
            Ok(contents) => {
                let config = toml::from_str(&contents)
                    .with_context(|| format!("invalid configuration: {}", path.display()))?;
                return Ok((config, Some(path.to_path_buf())));
            }
            Err(error) if explicit.is_none() && error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("could not read configuration: {}", path.display()));
            }
        }
    }
    Ok((Config::default(), None))
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
    let (mut config, candidate) =
        load_config(args.config.as_deref(), &CONFIG_PATHS.map(Path::new))?;
    if let Some(listen) = args.listen {
        config.listen = listen;
    }
    if let Some(database) = args.database {
        config.database = database;
    }
    if let Some(allowed) = args.allow_client_channel_creation {
        config.allow_client_channel_creation = allowed;
    }
    if matches!(args.command, Some(Command::Health)) {
        health::check(&config.listen).await?;
        println!("ok");
        return Ok(());
    }
    let database = if config.database.is_absolute() {
        config.database
    } else {
        candidate
            .as_ref()
            .and_then(|c| c.parent())
            .unwrap_or(Path::new("."))
            .join(config.database)
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
            ChannelCommand::Create { name, server } => {
                let url = url::Url::parse(&server)?;
                if !matches!(url.scheme(), "ws" | "wss")
                    || url.host_str().is_none()
                    || !url.username().is_empty()
                    || url.password().is_some()
                {
                    bail!("expected ws:// or wss:// server URL without credentials");
                }
                let invite = db.reserve(server, name).await?;
                println!("channel {}", invite.metadata.channel);
                println!("invite {}", *invite.export()?);
            }
            ChannelCommand::Invite { name, server } => {
                let invite = db.reserve_invitation(server, &name).await?;
                println!("invite {}", *invite.export()?);
            }
            ChannelCommand::Delete { name } => {
                let id = db.delete(&name).await?;
                println!("deleted {name} {id}");
            }
            ChannelCommand::Revoke {
                name,
                device_id,
                subtree,
            } => {
                let (id, affected) = db.admin_revoke(&name, &device_id, subtree).await?;
                println!(
                    "Server revoked {} device(s) in channel {id}:\n{}",
                    affected.len(),
                    affected.join("\n")
                );
            }
            ChannelCommand::List { json } => {
                let rows = db.admin_list().await?;
                if json {
                    let rows: Vec<_> = rows.into_iter().map(|(id,name,empty)|serde_json::json!({"id":id,"name":name,"state":if empty {"awaiting_founder"} else {"active"}})).collect();
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &serde_json::json!({"schema_version":1,"channels":rows})
                        )?
                    );
                } else {
                    println!("CHANNEL / CHANNEL ID                     STATE");
                    for (id, name, empty) in rows {
                        println!(
                            "{name:?} — {}\n  Channel ID: {id}",
                            if empty {
                                "Awaiting first member"
                            } else {
                                "Active"
                            }
                        );
                    }
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
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    // Relay frames are latency-sensitive, especially during nested PIN inquiries.
    let listener = listener.tap_io(|stream| {
        if let Err(error) = stream.set_nodelay(true) {
            tracing::warn!(%error, "could not disable TCP Nagle algorithm");
        }
    });
    axum::serve(listener, service.router())
        .with_graceful_shutdown(async move {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = terminate.recv() => {},
            }
            tracing::info!("relay shutting down");
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests;
