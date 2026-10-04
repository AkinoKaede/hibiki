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
