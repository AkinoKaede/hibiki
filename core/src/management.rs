//! Shared signed channel management. Presentation and approval UI live in clients.
use crate::{network::Connection, storage::App};
use anyhow::{Result, bail};
use hibiki_lib::invitation::{AdmissionRequest, OneTimeInvitation, VerificationCode};
use hibiki_lib::{
    channel::*,
    protocol::{Control, Reply, WireError},
};
pub async fn refresh(app: &App, conn: &Connection, id: &str) -> Result<MembershipProof> {
    let Reply::Proof(proof) = conn
        .request(Control::GetChannel { channel: id.into() })
        .await?
    else {
        bail!("invalid channel response");
    };
    if proof.genesis.body.id != id {
        bail!("channel response identity mismatch");
    }
    app.merge(proof)
}
pub async fn append(
    app: &App,
    conn: &Connection,
    id: &str,
    action: MembershipAction,
) -> Result<()> {
    for _ in 0..3 {
        let proof = refresh(app, conn, id).await?;
        let state = proof.verify()?;
        state.member(&app.identity.device.id())?;
        if matches!(action, MembershipAction::EnableInvitations) && state.invitations_enabled {
            return Ok(());
        }
        let event = MembershipEvent::create(&app.identity, &state, action.clone())?;
        match conn.request(Control::Append { event }).await {
            Ok(Reply::Proof(proof)) => {
                app.merge(proof)?;
                return Ok(());
            }
            Err(e)
                if e.downcast_ref::<WireError>()
                    .is_some_and(|e| e.code == "conflict") =>
            {
                continue;
            }
            Err(e) => return Err(e),
            _ => bail!("invalid append response"),
        }
    }
    bail!("channel changed concurrently; retry the command")
}

/// Cancel pending admissions, then sign a departure if already admitted.
pub async fn leave(app: &App, conn: &Connection, id: &str) -> Result<()> {
    for _ in 0..3 {
        match conn
            .request(Control::WithdrawPending { channel: id.into() })
            .await
        {
            Ok(Reply::Proof(proof)) => {
                if proof.genesis.body.id != id {
                    bail!("channel response identity mismatch");
                }
                let state = app.merge(proof)?.verify()?;
                if state.member(&app.identity.device.id()).is_ok() {
                    match append(app, conn, id, MembershipAction::Leave).await {
                        // Administrator denial does not rewrite signed history.
                        // The withdrawal committed, and this device already lacks access.
                        Err(error)
                            if error
                                .downcast_ref::<WireError>()
                                .is_some_and(|e| e.code == "access_revoked") => {}
                        result => result?,
                    }
                }
                return Ok(());
            }
            Err(e)
                if e.downcast_ref::<WireError>()
                    .is_some_and(|e| e.code == "conflict") =>
            {
                continue;
            }
            Err(e) => return Err(e),
            _ => bail!("invalid withdrawal response"),
        }
    }
    bail!("channel changed concurrently; retry the command")
}

pub fn validate_pending(request: &AdmissionRequest, state: &VerifiedChannelState) -> Result<()> {
    state.validate_admission(request)?;
    let b = &request.body;
    if b.channel_id != state.id
        || b.genesis_hash != state.genesis_hash
        || b.created_at > hibiki_lib::now() + 30
    {
        bail!("pending request does not match channel");
    }
    Ok(())
}

/// Publish a self-signed name in each active channel. Rerunning is idempotent
/// when a connection drops partway through a multi-channel update.
pub async fn rename(
    app: &App,
    conn: &Connection,
    name: String,
) -> Result<hibiki_lib::identity::Identity> {
    let identity = app.identity.renamed(name)?;
    for proof in app.proofs()? {
        let id = proof.genesis.body.id;
        let state = refresh(app, conn, &id).await?.verify()?;
        if let Ok(member) = state.member(&identity.device.id())
            && member != &identity.device
        {
            append(
                app,
                conn,
                &id,
                MembershipAction::Rename {
                    device: identity.device.clone(),
                },
            )
            .await?;
        }
    }
    Ok(identity)
}

/// Revocation never retries across a changed approval tree after UI confirmation.
pub async fn revoke(
    app: &App,
    conn: &Connection,
    id: &str,
    device: &str,
    subtree: bool,
    revision: u64,
) -> Result<Vec<String>> {
    let mut proof = refresh(app, conn, id).await?;
    let state = proof.verify()?;
    if state.sequence != revision {
        bail!("channel changed; refresh and review revocation again");
    }
    let action = if subtree {
        MembershipAction::RevokeSubtree {
            device_id: device.into(),
        }
    } else {
        MembershipAction::Revoke {
            device_id: device.into(),
        }
    };
    let affected = if subtree {
        state.revocation_subtree(device)
    } else {
        vec![device.into()]
    };
    let event = MembershipEvent::create(&app.identity, &state, action)?;
    proof.events.push(event.clone());
    proof.verify()?;
    match conn.request(Control::Append { event }).await? {
        Reply::Proof(proof) => {
            app.merge(proof)?;
            Ok(affected)
        }
        _ => bail!("invalid revocation response"),
    }
}

pub async fn invitation(app: &App, conn: &Connection, id: &str) -> Result<OneTimeInvitation> {
    let mut proof = refresh(app, conn, id).await?;
    if !proof.verify()?.invitations_enabled {
        append(app, conn, id, MembershipAction::EnableInvitations).await?;
        proof = refresh(app, conn, id).await?;
    }
    let state = proof.verify()?;
    state.member(&app.identity.device.id())?;
    let invitation = OneTimeInvitation::new(
        app.config.server.clone(),
        id.into(),
        state.name.clone(),
        Some((&state, &app.identity.device.id())),
    )?;
    let Reply::Ok = conn
        .request(Control::RegisterInvitation {
            metadata: invitation.metadata.clone(),
        })
        .await?
    else {
        bail!("invalid invitation registration response");
    };
    Ok(invitation)
}

pub async fn create_channel(
    app: &App,
    conn: &Connection,
    name: String,
) -> Result<OneTimeInvitation> {
    let genesis = ChannelGenesis::without_psk(&app.identity, hibiki_lib::random_id(), name)?;
    let Reply::Proof(proof) = conn
        .request(Control::Create {
            genesis: genesis.clone(),
        })
        .await?
    else {
        bail!("invalid channel creation response");
    };
    if proof.genesis != genesis || !proof.events.is_empty() {
        bail!("server altered genesis");
    }
    app.bootstrap(proof, None)?;
    invitation(app, conn, &genesis.body.id).await
}

pub struct AdmissionResult {
    pub channel: String,
    pub name: String,
    pub request: Option<String>,
    pub verification: String,
}

pub async fn join(app: &App, conn: &Connection, text: &str) -> Result<AdmissionResult> {
    let invitation = OneTimeInvitation::import(text)?;
    let meta = &invitation.metadata;
    if meta.server != app.config.server {
        bail!("invitation relay differs from configured relay");
    }
    if meta.genesis_hash.is_none() {
        let genesis =
            ChannelGenesis::without_psk(&app.identity, meta.channel.clone(), meta.name.clone())?;
        let Reply::Proof(proof) = conn
            .request(Control::Claim {
                genesis: genesis.clone(),
                invitation: invitation.clone(),
            })
            .await?
        else {
            bail!("invalid claim response");
        };
        if proof.genesis != genesis {
            bail!("initialization invitation already claimed or altered");
        }
        app.bootstrap(proof, None)?;
        return Ok(AdmissionResult {
            channel: meta.channel.clone(),
            name: meta.name.clone(),
            request: None,
            verification: String::new(),
        });
    }
    let saved = app
        .paths
        .channel_dir(&meta.channel)?
        .join("join-request-v3.bin");
    let previous: Option<AdmissionRequest> = if saved.exists() {
        Some(hibiki_lib::decode(&crate::storage::read_private(&saved)?)?)
    } else {
        None
    };
    // The public signed request is persisted before sending. A retry never invents a new nonce.
    let previous = previous.filter(|r| {
        r.body.invitation_id == meta.id && r.body.device.id() == app.identity.device.id()
    });
    if let Some(request) = &previous {
        request.verify()?;
        if let Ok(Reply::JoinStatus(hibiki_lib::protocol::JoinState::Member)) = conn
            .request(Control::JoinStatus {
                channel: meta.channel.clone(),
                request: request.id()?,
            })
            .await
        {
            refresh(app, conn, &meta.channel).await?;
            return Ok(AdmissionResult {
                channel: meta.channel.clone(),
                name: meta.name.clone(),
                request: None,
                verification: String::new(),
            });
        }
    }
    let Reply::InvitationProof {
        proof,
        access_revision,
    } = conn
        .request(Control::ResolveInvitation {
            invitation: invitation.clone(),
        })
        .await?
    else {
        bail!("invalid invitation resolution response");
    };
    if proof.genesis.body.id != meta.channel {
        bail!("invitation channel mismatch");
    }
    proof.verify_from(&meta.genesis_hash.unwrap(), &meta.checkpoint)?;
    let trust = Invite {
        version: 1,
        server: meta.server.clone(),
        genesis: proof.genesis.clone(),
        checkpoint: meta.checkpoint.clone(),
    };
    let state = app.bootstrap(proof, Some(&trust))?.verify()?;
    let request = match previous {
        Some(request) => request,
        None => AdmissionRequest::create(&app.identity, &state, meta.id.clone(), access_revision)?,
    };
    let id = request.id()?;
    crate::storage::atomic_write(&saved, &hibiki_lib::encode(&request)?)?;
    let verification = VerificationCode::new(app.config.server.clone(), &request)?.export()?;
    let channel = meta.channel.clone();
    let name = meta.name.clone();
    let Reply::Ok = conn
        .request(Control::Join {
            request,
            invitation,
        })
        .await?
    else {
        bail!("invalid admission response");
    };
    Ok(AdmissionResult {
        channel,
        name,
        request: Some(id),
        verification,
    })
}

pub async fn approve_verification(
    app: &App,
    conn: &Connection,
    channel: &str,
    request_id: &str,
    code: &str,
) -> Result<()> {
    let code = VerificationCode::import(code)?;
    if code.channel != channel || code.request != request_id {
        bail!("verification code does not match this pending request");
    }
    let state = refresh(app, conn, channel).await?.verify()?;
    let Reply::Requests(requests) = conn
        .request(Control::Pending {
            channel: channel.into(),
        })
        .await?
    else {
        bail!("invalid pending response");
    };
    let request = requests
        .into_iter()
        .find(|r| r.id().is_ok_and(|id| id == request_id))
        .ok_or_else(|| anyhow::anyhow!("request no longer pending"))?;
    validate_pending(&request, &state)?;
    code.matches(&app.config.server, &request)?;
    append(app, conn, channel, MembershipAction::Accept(request)).await
}
