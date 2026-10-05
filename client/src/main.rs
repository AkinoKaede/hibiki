use anstream::{eprintln, println};
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use hibiki::{
    network::Connection,
    pairing,
    storage::App,
    terminal::{ERROR, HEADING, SUCCESS, WARNING},
};
use hibiki_lib::protocol::{Control, JoinState, Reply};
use std::{io::Write, path::PathBuf, time::Duration};

#[derive(Parser)]
#[command(version, about = "Manage Hibiki devices and Assuan services")]
struct Args {
    #[arg(long, global = true, env = "HIBIKI_CONFIG")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    Init {
        #[arg(long)]
        server: String,
        /// Device display name; defaults to the operating system hostname.
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        allow_insecure: bool,
    },
    Channel {
        #[command(subcommand)]
        command: ChannelCommand,
    },
    Device {
        #[command(subcommand)]
        command: DeviceCommand,
    },
    Use {
        name: String,
    },
    Daemon,
    /// Measure encrypted round trips to another device through the server.
    Ping {
        device_id: String,
        #[arg(long)]
        channel: Option<String>,
        #[arg(long, default_value_t = 4)]
        count: u16,
        #[arg(long)]
        json: bool,
    },

    /// Interactive device, channel, request and service management.
    Tui,
    /// Show live daemon, server and selected-channel status.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Diagnose daemon, server authentication and enabled native providers.
    Doctor {
        #[arg(long)]
        json: bool,
    },
    /// Show setup steps and GPG adapter paths without modifying configuration.
    Setup,
}
#[derive(Subcommand)]
enum DeviceCommand {
    /// Measure encrypted round trips to another device through the server.
    Ping {
        device_id: String,
        #[arg(long)]
        channel: Option<String>,
        #[arg(long, default_value_t = 4)]
        count: u16,
        #[arg(long)]
        json: bool,
    },
    /// Rename this device without changing its keys, ID or verification words.
    Rename { name: String },
    List {
        #[arg(long)]
        json: bool,
    },
}
#[derive(Subcommand)]
enum ChannelCommand {
    Create {
        name: String,
        #[command(flatten)]
        qr: QrOptions,
    },
    Invite {
        name: String,
        #[command(flatten)]
        qr: QrOptions,
    },
    Join {
        invite: String,
        #[arg(long)]
        no_wait: bool,
        #[command(flatten)]
        qr: QrOptions,
    },
    Pending {
        name: String,
        #[arg(long)]
        json: bool,
    },
    Approve {
        name: String,
        /// Omit to choose a pending request interactively. Always asks for y/N confirmation.
        request_id: Option<String>,
    },
    /// Reject one pending request; the device may submit a new request.
    Reject { name: String, request_id: String },
    /// Leave a channel or withdraw this device's pending join requests.
    Leave { name: String },
    Revoke {
        name: String,
        device_id: String,
        /// Also revoke all descendants in this approval branch.
        #[arg(long)]
        subtree: bool,
    },
    List {
        #[arg(long)]
        json: bool,
    },
}
#[derive(clap::Args)]
struct QrOptions {
    /// Display a scannable QR code on the terminal (stderr).
    #[arg(long)]
    qr: bool,
    /// Export the QR code as a private PNG file; never overwrite an existing file.
    #[arg(long)]
    qr_output: Option<PathBuf>,
}
impl QrOptions {
    fn show(&self, text: &str) -> Result<()> {
        if self.qr {
            for line in hibiki_lib::qr::terminal(text)?.lines() {
                eprintln!("\x1b[30;47m{line}\x1b[0m");
            }
        }
        if let Some(path) = &self.qr_output {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(&hibiki_lib::qr::png(text)?)?;
        }
        Ok(())
    }
}
use hibiki_core::management::refresh;

fn hostname() -> Result<String> {
    let mut info = std::mem::MaybeUninit::<libc::utsname>::uninit();
    // uname initializes the structure on success, with a NUL-terminated nodename.
    if unsafe { libc::uname(info.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let info = unsafe { info.assume_init() };
    let name = unsafe { std::ffi::CStr::from_ptr(info.nodename.as_ptr()) }.to_str()?;
    if name.is_empty() || name.len() > 128 {
        bail!("hostname must be 1 to 128 bytes");
    }
    Ok(name.to_owned())
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{ERROR}Error:{ERROR:#} {error:?}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let args = Args::parse();
    if matches!(args.command, Commands::Tui) {
        return hibiki::tui::run(args.config).await;
    }
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_ansi(anstream::AutoStream::choice(&std::io::stderr()) != anstream::ColorChoice::Never)
        .with_writer(std::io::stderr)
        .init();
    if let Commands::Init {
        server,
        name,
        allow_insecure,
    } = args.command
    {
        if args.config.is_some() {
            bail!(
                "init writes the XDG user configuration; use XDG_CONFIG_HOME to choose its location"
            );
        }
        let name = match name {
            Some(name) => name,
            None => hostname().context("could not use hostname as device name; specify --name")?,
        };
        let app = App::initialize(server, name, allow_insecure)?;
        println!("{HEADING}device{HEADING:#} {}", app.identity.device.id());
        hibiki::diagnostics::setup(&app);
        return Ok(());
    }
    let mut app = App::load(args.config.as_deref())?;
    match args.command {
        Commands::Status { json } => {
            return hibiki::diagnostics::inspect_format(&app, false, json).await;
        }
        Commands::Doctor { json } => {
            return hibiki::diagnostics::inspect_format(&app, true, json).await;
        }
        Commands::Setup => {
            hibiki::diagnostics::setup(&app);
            return Ok(());
        }
        _ => {}
    }
    if let Commands::Daemon = args.command {
        return hibiki::daemon::run(app).await;
    }
    if let Commands::Use { name } = args.command {
        let id = app.resolve_channel(&name)?;
        app.proof(&id)?
            .verify()?
            .member(&app.identity.device.id())?;
        app.config.default_channel = Some(id);
        app.save_config()?;
        println!("{SUCCESS}default channel:{SUCCESS:#} {name}");
        eprintln!(
            "Run hibiki doctor to check readiness; hibiki setup shows GPG and background-service steps."
        );
        return Ok(());
    }
    if let Commands::Device {
        command:
            DeviceCommand::Ping {
                ref device_id,
                ref channel,
                count,
                json,
            },
    }
    | Commands::Ping {
        ref device_id,
        ref channel,
        count,
        json,
    } = args.command
    {
        let channel = channel
            .clone()
            .or_else(|| app.config.default_channel.clone())
            .context("select a channel or pass --channel NAME")?;
        let report = hibiki::diagnostics::ping(
            &app,
            app.resolve_channel(&channel)?,
            device_id.clone(),
            count,
        )
        .await?;
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"schema_version":1,"ping":report})
                )?
            );
        } else {
            print!("{}", hibiki::diagnostics::ping_text(&report));
        }
        return Ok(());
    }
    if let Commands::Device {
        command: DeviceCommand::Rename { ref name },
    } = args.command
    {
        let mut manager = hibiki::management::Manager::connect(app.clone()).await?;
        manager.rename(name.clone()).await?;
        println!(
            "Renamed this device to {}\nDevice ID: {}",
            hibiki::presentation::safe(name),
            app.identity.device.id()
        );
        eprintln!(
            "Keys and verification words are unchanged. Restart the daemon to refresh its local name."
        );
        return Ok(());
    }
    if let Commands::Device {
        command: DeviceCommand::List { json },
    } = args.command
    {
        let snapshot = match hibiki::management::Manager::connect(app.clone()).await {
            Ok(manager) => manager.snapshot().await?,
            Err(_) => hibiki::management::local_snapshot(&app).await?,
        };
        if json {
            println!("{}", serde_json::to_string_pretty(&snapshot)?);
        } else {
            print!(
                "{}",
                hibiki::presentation::devices(&snapshot.local_device, &snapshot.channels)
            );
        }
        return Ok(());
    }
    let Commands::Channel { command } = args.command else {
        unreachable!()
    };
    let (conn, _events) =
        Connection::open(&app.config.server, app.config.allow_insecure, &app.identity).await?;
    let mut manager = hibiki::management::Manager {
        app: app.clone(),
        connection: conn.clone(),
    };
    match command {
        ChannelCommand::Create { name, qr } => {
            let invite = manager.create(name).await?;
            let parsed = hibiki_lib::invitation::OneTimeInvitation::import(&invite)?;
            println!("channel {}", parsed.metadata.channel);
            println!("invite {}", &*invite);
            qr.show(&invite)?;
            eprintln!("Invitation expires in 24 hours and can be used once.");
        }
        ChannelCommand::Invite { name, qr } => {
            let id = app.resolve_channel(&name)?;
            let invite = manager.invitation(&id).await?;
            println!("{}", &*invite);
            qr.show(&invite)?;
        }
        ChannelCommand::Join {
            invite,
            no_wait,
            qr,
        } => {
            pairing::show_device(&mut std::io::stderr().lock(), &app.identity.device)?;
            let result = manager.join(invite).await?;
            if let Some(request_id) = &result.request {
                // Flush before waiting: scripts and the approving terminal need this ID.
                println!("request {request_id}");
                println!("verification {}", result.verification);
                qr.show(&result.verification)?;
                std::io::stdout().flush()?;
                eprintln!(
                    "Channel: {}\nChannel ID: {}\nRequest ID: {request_id}\nStatus: Awaiting approval",
                    hibiki::presentation::safe(&result.name),
                    result.channel
                );
                eprintln!(
                    "Compare all 24 words with the approving device. Approve with: hibiki channel approve {}\nWithdraw with: hibiki channel leave {}",
                    hibiki::presentation::quote(&result.channel),
                    hibiki::presentation::quote(&result.channel)
                );
                if !no_wait {
                    loop {
                        match manager.join_status(&result.channel, request_id).await? {
                            JoinState::Member => {
                                refresh(&app, &conn, &result.channel).await?;
                                break;
                            }
                            JoinState::Absent => bail!(
                                "request was rejected, withdrawn or invalidated; obtain a current invitation"
                            ),
                            JoinState::Pending => {}
                        }
                        tokio::select! { _=tokio::signal::ctrl_c()=>bail!("stopped waiting; request remains pending"), _=tokio::time::sleep(Duration::from_secs(1))=>{} }
                    }
                } else {
                    return Ok(());
                }
            }
            println!(
                "Joined channel: {}\nChannel ID: {}",
                hibiki::presentation::safe(&result.name),
                result.channel
            );
            eprintln!(
                "Next: hibiki use {}",
                hibiki::presentation::quote(&result.channel)
            );
        }
        ChannelCommand::Pending { name, json } => {
            let id = app.resolve_channel(&name)?;
            let row = manager.channel(&id).await?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({"schema_version":1,"channel":{"id":row.id,"name":row.name},"requests":row.pending})
                    )?
                );
            } else {
                print!(
                    "{}",
                    hibiki::presentation::pending(&row.name, &row.id, &row.pending)
                );
            }
        }
        ChannelCommand::Approve { name, request_id } => {
            let id = app.resolve_channel(&name)?;
            let state = refresh(&app, &conn, &id).await?.verify()?;
            state.member(&app.identity.device.id())?;
            let Reply::Requests(requests) = conn
                .request(Control::Pending {
                    channel: id.clone(),
                })
                .await?
            else {
                bail!("invalid pending response");
            };
            let request = pairing::choose_approval(
                requests,
                &state,
                request_id.as_deref(),
                &mut std::io::stdin().lock(),
                &mut std::io::stderr().lock(),
            )?;
            if let Some(request) = request {
                let request_id = request.id()?;
                manager.approve(&id, &request_id).await?;
                println!(
                    "{SUCCESS}Approved request:{SUCCESS:#} {request_id}\nChannel: {}\nDevice: {}\nDevice ID: {}",
                    hibiki::presentation::safe(&name),
                    hibiki::presentation::safe(&request.body.device.name),
                    request.body.device.id()
                );
            } else {
                println!("{WARNING}not approved{WARNING:#}");
            }
        }
        ChannelCommand::Reject { name, request_id } => {
            let id = app.resolve_channel(&name)?;
            let request_id = manager.resolve_request(&id, &request_id).await?;
            manager.reject(&id, &request_id).await?;
            println!(
                "Rejected request: {request_id}\nChannel: {} ({id})",
                hibiki::presentation::safe(&name)
            );
            eprintln!(
                "Next: hibiki channel pending {}",
                hibiki::presentation::quote(&id)
            );
        }
        ChannelCommand::Leave { name } => {
            let id = app.resolve_channel(&name)?;
            manager.leave(&id).await?;
            println!(
                "Left channel: {}\nChannel ID: {id}",
                hibiki::presentation::safe(&name)
            );
            eprintln!("Next: hibiki channel list");
            if app.proof(&id)?.verify()?.members().is_empty() {
                eprintln!(
                    "{WARNING}No members remain;{WARNING:#} ask the server administrator to recreate the channel if needed."
                );
            }
        }
        ChannelCommand::Revoke {
            name,
            device_id,
            subtree,
        } => {
            let id = app.resolve_channel(&name)?;
            let device_id = manager.resolve_device(&id, &device_id).await?;
            let revision = manager.channel(&id).await?.revision;
            let affected = manager.revoke(&id, &device_id, subtree, revision).await?;
            println!(
                "Revoked {} device(s):\n{}",
                affected.len(),
                affected.join("\n")
            );
            println!(
                "Revoked device: {device_id}\nChannel: {} ({id})",
                hibiki::presentation::safe(&name)
            );
            eprintln!("Next: hibiki device list");
        }
        ChannelCommand::List { json } => {
            let snapshot = manager.snapshot().await?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({"schema_version":1,"channels":snapshot.channels})
                    )?
                );
            } else {
                print!("{}", hibiki::presentation::channels(&snapshot.channels));
            }
        }
    }
    conn.close();
    Ok(())
}
