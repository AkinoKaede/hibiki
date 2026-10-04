use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use hibiki::{network::Connection, pairing, storage::App};
use hibiki_lib::{
    channel::*,
    digest,
    protocol::{Control, JoinState, Reply},
};
use std::{io::Write, path::PathBuf, time::Duration};

#[derive(Parser)]
#[command(version, about = "Manage HIbiki devices and Assuan services")]
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
    /// Show live daemon, relay and selected-channel status.
    Status,
    /// Diagnose daemon, relay authentication and enabled native providers.
    Doctor,
    /// Show setup steps and GPG adapter paths without modifying configuration.
    Setup,
}
#[derive(Subcommand)]
enum DeviceCommand {
    List,
}
#[derive(Subcommand)]
enum ChannelCommand {
    Create {
        name: String,
        #[arg(long)]
        psk_file: Option<PathBuf>,
        #[arg(long, conflicts_with = "psk_file")]
        prompt_psk: bool,
    },
    Invite {
        name: String,
    },
    Join {
        invite: String,
        #[arg(long)]
        psk_file: Option<PathBuf>,
        #[arg(long)]
        no_wait: bool,
    },
    Pending {
        name: String,
    },
    Approve {
        name: String,
        /// Omit to choose a pending request interactively. Always asks for y/N confirmation.
        request_id: Option<String>,
    },
    /// Reject one pending request; the device may submit a new request.
    Reject {
        name: String,
        request_id: String,
    },
    /// Withdraw this device's own pending request.
    Withdraw {
        name: String,
        request_id: String,
    },
    RotatePsk {
        name: String,
        #[arg(long)]
        psk_file: Option<PathBuf>,
        #[arg(long, conflicts_with = "psk_file")]
        prompt_psk: bool,
    },
    /// Leave a channel using this device's signed membership record.
    Leave {
        name: String,
    },
    Revoke {
        name: String,
        device_id: String,
    },
    List,
}
fn psk(file: Option<PathBuf>, generate: bool) -> Result<(String, bool)> {
    if let Some(path) = file {
        let data = std::fs::read_to_string(path)?;
        return Ok((data.trim_end_matches(['\r', '\n']).to_owned(), false));
    }
    if generate {
        Ok((make_psk(), true))
    } else {
        Ok((rpassword::prompt_password("Channel PSK: ")?, false))
    }
}
use hibiki_core::management::{append, refresh};

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
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();
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
        println!("device {}", app.identity.device.id());
        hibiki::diagnostics::setup(&app);
        return Ok(());
    }
    let mut app = App::load(args.config.as_deref())?;
    match args.command {
        Commands::Status => return hibiki::diagnostics::inspect(&app, false).await,
        Commands::Doctor => return hibiki::diagnostics::inspect(&app, true).await,
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
        println!("default channel: {name}");
        eprintln!(
            "Run hibiki doctor to check readiness; hibiki setup shows GPG and background-service steps."
        );
        return Ok(());
    }
    if let Commands::Device {
        command: DeviceCommand::List,
    } = args.command
    {
        println!(
            "local {} {}",
            app.identity.device.id(),
            app.identity.device.name
        );
        for proof in app.proofs()? {
            let state = proof.verify()?;
            for (id, device) in state.members() {
                println!("{} {} {}", state.name, id, device.name);
            }
        }
        return Ok(());
    }
    let Commands::Channel { command } = args.command else {
        unreachable!()
    };
    let (conn, _events) =
        Connection::open(&app.config.server, app.config.allow_insecure, &app.identity).await?;
    match command {
        ChannelCommand::Create {
            name,
            psk_file,
            prompt_psk,
        } => {
            let (secret, generated) = psk(psk_file, !prompt_psk)?;
            let verifier = hash_psk(&secret)?;
            let genesis = ChannelGenesis::create(&app.identity, name, &verifier)?;
            let expected = genesis.clone();
            let Reply::Proof(proof) = conn.request(Control::Create { genesis, verifier }).await?
            else {
                bail!("invalid creation response");
            };
            if proof.genesis != expected || !proof.events.is_empty() {
                bail!("server altered channel genesis");
            }
            let proof = app.bootstrap(proof, None)?;
            println!("channel {}", proof.genesis.body.id);
            eprintln!("Next: hibiki channel invite NAME; on requesting devices, hibiki use NAME.");
            if generated {
                println!("PSK {secret}");
            }
        }
        ChannelCommand::Invite { name } => {
            let id = app.resolve_channel(&name)?;
            let proof = refresh(&app, &conn, &id).await?;
            let state = proof.verify()?;
            state.member(&app.identity.device.id())?;
            let invite = Invite {
                version: 1,
                server: app.config.server.clone(),
                genesis: proof.genesis,
                checkpoint: state.checkpoint(),
            };
            println!("{}", invite.export()?);
        }
        ChannelCommand::Join {
            invite,
            psk_file,
            no_wait,
        } => {
            pairing::show_device(&mut std::io::stderr().lock(), &app.identity.device)?;
            if invite.starts_with("hibiki-init-v1:") {
                let invite = EmptyChannelInvite::import(&invite)?;
                if invite.server != app.config.server {
                    bail!("initialization invitation server mismatch");
                }
                let genesis = invite.founder_genesis(&app.identity)?;
                // Recovery after a lost Claim reply is allowed only for this exact founder.
                let existing = conn
                    .request(Control::GetChannel {
                        channel: invite.id.clone(),
                    })
                    .await;
                let proof = if let Ok(Reply::Proof(proof)) = existing {
                    proof
                } else {
                    let (secret, _) = psk(psk_file, false)?;
                    let Reply::Proof(proof) = conn
                        .request(Control::Claim {
                            genesis: genesis.clone(),
                            psk: secret,
                        })
                        .await?
                    else {
                        bail!("invalid claim response");
                    };
                    proof
                };
                if proof.genesis != genesis {
                    bail!(
                        "initialization invitation already claimed by another identity or altered; obtain a member invitation"
                    );
                }
                proof.verify()?.member(&app.identity.device.id())?;
                app.bootstrap(proof, None)?;
                println!("joined {} {}", invite.name, invite.id);
                eprintln!(
                    "Next on requesting devices: hibiki use {:?}; then hibiki doctor.",
                    invite.name
                );
                conn.close();
                return Ok(());
            }
            let invite = Invite::import(&invite)?;
            if invite.server != app.config.server {
                bail!("invite server does not match configured server");
            }
            let id = invite.genesis.body.id.clone();
            let Reply::Proof(proof) = conn
                .request(Control::GetChannel {
                    channel: id.clone(),
                })
                .await?
            else {
                bail!("invalid channel response");
            };
            let proof = app.bootstrap(proof, Some(&invite))?;
            let state = proof.verify()?;
            let (secret, _) = psk(psk_file, false)?;
            let request = JoinRequest::create(&app.identity, &state)?;
            let request_id = request.id()?;
            conn.request(Control::Join {
                request,
                psk: secret,
            })
            .await?;
            println!("request {request_id}");
            std::io::stdout().flush()?;
            eprintln!(
                "Ask a trusted member to run hibiki channel approve {:?} and compare all 24 public-key words and request ID {request_id} before answering y.",
                state.name
            );
            eprintln!(
                "To withdraw: hibiki channel withdraw {:?} {request_id}",
                state.name
            );
            if !no_wait {
                loop {
                    let Reply::JoinStatus(status) = conn
                        .request(Control::JoinStatus {
                            channel: id.clone(),
                            request: request_id.clone(),
                        })
                        .await?
                    else {
                        bail!("invalid join status response");
                    };
                    match status {
                        JoinState::Member => {
                            refresh(&app, &conn, &id)
                                .await?
                                .verify()?
                                .member(&app.identity.device.id())?;
                            println!("joined {} {}", state.name, id);
                            eprintln!(
                                "Next on requesting devices: hibiki use {:?}; then hibiki doctor.",
                                state.name
                            );
                            break;
                        }
                        JoinState::Absent => bail!(
                            "request was rejected, withdrawn or invalidated; obtain a current invitation and submit a new request"
                        ),
                        JoinState::Pending => {}
                    }
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => bail!("stopped waiting; request remains pending"),
                        _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                    }
                }
            }
        }
        ChannelCommand::Pending { name } => {
            let id = app.resolve_channel(&name)?;
            refresh(&app, &conn, &id).await?;
            let Reply::Requests(requests) = conn.request(Control::Pending { channel: id }).await?
            else {
                bail!("invalid pending response");
            };
            for request in requests {
                request.verify()?;
                println!(
                    "{} {} {}",
                    request.id()?,
                    request.body.device.id(),
                    request.body.device.name
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
                append(&app, &conn, &id, MembershipAction::Admit(request), None).await?;
                println!("approved {request_id}");
            } else {
                println!("not approved");
            }
        }
        ChannelCommand::Reject { name, request_id } => {
            let id = app.resolve_channel(&name)?;
            refresh(&app, &conn, &id)
                .await?
                .verify()?
                .member(&app.identity.device.id())?;
            let Reply::Ok = conn
                .request(Control::RejectJoin {
                    channel: id,
                    request: request_id.clone(),
                })
                .await?
            else {
                bail!("invalid rejection response");
            };
            println!("rejected {request_id}");
        }
        ChannelCommand::Withdraw { name, request_id } => {
            let id = app.resolve_channel(&name)?;
            let Reply::Ok = conn
                .request(Control::WithdrawJoin {
                    channel: id,
                    request: request_id.clone(),
                })
                .await?
            else {
                bail!("invalid withdrawal response");
            };
            println!("withdrawn {request_id}");
        }
        ChannelCommand::RotatePsk {
            name,
            psk_file,
            prompt_psk,
        } => {
            let id = app.resolve_channel(&name)?;
            let (secret, generated) = psk(psk_file, !prompt_psk)?;
            let verifier = hash_psk(&secret)?;
            let action = MembershipAction::ChangePsk {
                verifier_commitment: digest(verifier.as_bytes()),
            };
            append(&app, &conn, &id, action, Some(verifier)).await?;
            println!("PSK updated; existing members retained");
            if generated {
                println!("PSK {secret}");
            }
        }
        ChannelCommand::Leave { name } => {
            let id = app.resolve_channel(&name)?;
            append(&app, &conn, &id, MembershipAction::Leave, None).await?;
            if app.config.default_channel.as_ref() == Some(&id) {
                app.config.default_channel = None;
                app.save_config()?;
            }
            println!("left {name} {id}");
            if app.proof(&id)?.verify()?.members().is_empty() {
                eprintln!(
                    "No members remain; the server administrator must delete and recreate the channel to use it again."
                );
            }
        }
        ChannelCommand::Revoke { name, device_id } => {
            let id = app.resolve_channel(&name)?;
            append(
                &app,
                &conn,
                &id,
                MembershipAction::Revoke {
                    device_id: device_id.clone(),
                },
                None,
            )
            .await?;
            println!("revoked {device_id}");
        }
        ChannelCommand::List => {
            for proof in app.proofs()? {
                let proof = match refresh(&app, &conn, &proof.genesis.body.id).await {
                    Ok(current) => current,
                    Err(_) => {
                        println!(
                            "{} {} unavailable",
                            proof.genesis.body.id, proof.genesis.body.name
                        );
                        continue;
                    }
                };
                let state = proof.verify()?;
                println!(
                    "{} {} revision={} active={}",
                    state.id,
                    state.name,
                    state.sequence,
                    state.member(&app.identity.device.id()).is_ok()
                );
            }
        }
    }
    conn.close();
    Ok(())
}
