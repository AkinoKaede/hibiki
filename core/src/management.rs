//! Shared signed channel management. Presentation and approval UI live in clients.
use crate::{network::Connection, storage::App};
use anyhow::{Result, bail};
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
    verifier: Option<String>,
) -> Result<()> {
    for _ in 0..3 {
        let proof = refresh(app, conn, id).await?;
        let state = proof.verify()?;
        state.member(&app.identity.device.id())?;
        let event = MembershipEvent::create(&app.identity, &state, action.clone())?;
        match conn
            .request(Control::Append {
                event,
                verifier: verifier.clone(),
            })
            .await
        {
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
                    append(app, conn, id, MembershipAction::Leave, None).await?;
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

pub fn validate_pending(request: &JoinRequest, state: &VerifiedChannelState) -> Result<()> {
    request.verify()?;
    let b = &request.body;
    if b.channel_id != state.id
        || b.genesis_hash != state.genesis_hash
        || b.psk_epoch != state.psk_epoch
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
                None,
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
    match conn
        .request(Control::Append {
            event,
            verifier: None,
        })
        .await?
    {
        Reply::Proof(proof) => {
            app.merge(proof)?;
            Ok(affected)
        }
        _ => bail!("invalid revocation response"),
    }
}
