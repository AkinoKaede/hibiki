/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

//! Versioned one-use invitations and request-bound public verification codes.
use crate::{
    channel::*,
    identity::{Device, Identity, verify},
    *,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const INVITATION_TTL: u64 = 24 * 60 * 60;
const INVITE_PREFIX: &str = "hibiki-invite-v2:";
const VERIFY_PREFIX: &str = "hibiki-verify-v1:";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvitationMetadata {
    pub id: String,
    pub server: String,
    pub channel: String,
    pub name: String,
    /// None only for an unclaimed, administrator-reserved channel.
    pub genesis_hash: Option<[u8; 32]>,
    pub checkpoint: TrustCheckpoint,
    pub issuer_admission: String,
    pub expires_at: u64,
    pub key_hash: [u8; 32],
}
impl InvitationMetadata {
    pub fn validate(&self) -> Result<()> {
        if !valid_id(&self.id)
            || !valid_id(&self.channel)
            || self.server.len() > 512
            || !(self.server.starts_with("wss://") || self.server.starts_with("ws://"))
            || self.name.trim().is_empty()
            || self.name.len() > 128
            || (self.genesis_hash.is_some() && !valid_digest(&self.issuer_admission))
        {
            return Err(Error::Invalid("invalid invitation metadata".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct OneTimeInvitation {
    #[zeroize(skip)]
    pub metadata: InvitationMetadata,
    pub key: [u8; 32],
}
impl std::fmt::Debug for OneTimeInvitation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[invitation redacted]")
    }
}
impl OneTimeInvitation {
    pub fn new(
        server: String,
        channel: String,
        name: String,
        state: Option<(&VerifiedChannelState, &str)>,
    ) -> Result<Self> {
        let mut key = [0; 32];
        getrandom::fill(&mut key)
            .map_err(|_| Error::Invalid("random source unavailable".into()))?;
        let metadata = InvitationMetadata {
            id: random_id(),
            server,
            channel,
            name,
            genesis_hash: state.map(|(s, _)| s.genesis_hash),
            checkpoint: state
                .map(|(s, _)| s.checkpoint())
                .unwrap_or(TrustCheckpoint {
                    sequence: 0,
                    hash: [0; 32],
                }),
            issuer_admission: state
                .and_then(|(s, id)| s.admission_id(id))
                .unwrap_or_default()
                .to_owned(),
            expires_at: now().saturating_add(INVITATION_TTL),
            key_hash: digest(&key),
        };
        metadata.validate()?;
        Ok(Self { metadata, key })
    }
    pub fn export(&self) -> Result<Zeroizing<String>> {
        self.metadata.validate()?;
        Ok(Zeroizing::new(format!(
            "{INVITE_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(&*encode_secret(self)?)
        )))
    }
    pub fn import(text: &str) -> Result<Self> {
        let raw = text.trim().strip_prefix(INVITE_PREFIX).ok_or_else(|| {
            Error::Unsupported(
                "old or unsupported invitation; obtain a new one-use invitation".into(),
            )
        })?;
        if raw.len() > 4096 {
            return Err(Error::Invalid("invitation too large".into()));
        }
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(raw)
                .map_err(|_| Error::Invalid("invitation encoding".into()))?,
        );
        let value: Self = decode(&bytes)?;
        value.metadata.validate()?;
        if digest(&value.key) != value.metadata.key_hash {
            return Err(Error::Invalid("invitation key mismatch".into()));
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdmissionBody {
    pub channel_id: String,
    pub genesis_hash: [u8; 32],
    pub device: Device,
    pub nonce: String,
    pub invitation_id: String,
    pub checkpoint: TrustCheckpoint,
    pub previous_admission: Option<String>,
    pub access_revision: u64,
    pub created_at: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdmissionRequest {
    pub body: AdmissionBody,
    pub signature: Vec<u8>,
}
impl AdmissionRequest {
    pub fn create(
        identity: &Identity,
        state: &VerifiedChannelState,
        invitation_id: String,
        access_revision: u64,
    ) -> Result<Self> {
        let body = AdmissionBody {
            channel_id: state.id.clone(),
            genesis_hash: state.genesis_hash,
            device: identity.device.clone(),
            nonce: random_id(),
            invitation_id,
            checkpoint: state.checkpoint(),
            previous_admission: state.admission_id(&identity.device.id()).map(str::to_owned),
            access_revision,
            created_at: now(),
        };
        Ok(Self {
            signature: identity.sign("join/v4", &body)?,
            body,
        })
    }
    pub fn id(&self) -> Result<String> {
        Ok(hex::encode(digest(&encode(self)?)))
    }
    pub fn verify(&self) -> Result<()> {
        self.body.device.verify()?;
        if !valid_id(&self.body.nonce)
            || !valid_id(&self.body.invitation_id)
            || !valid_id(&self.body.channel_id)
            || self
                .body
                .previous_admission
                .as_ref()
                .is_some_and(|id| !valid_digest(id))
        {
            return Err(Error::Invalid("invalid admission request".into()));
        }
        verify(
            &self.body.device.signing_key,
            "join/v4",
            &self.body,
            &self.signature,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationCode {
    pub server: String,
    pub channel: String,
    pub genesis_hash: [u8; 32],
    pub request: String,
    pub device: String,
}
impl VerificationCode {
    pub fn new(server: String, request: &AdmissionRequest) -> Result<Self> {
        request.verify()?;
        Ok(Self {
            server,
            channel: request.body.channel_id.clone(),
            genesis_hash: request.body.genesis_hash,
            request: request.id()?,
            device: request.body.device.id(),
        })
    }
    pub fn export(&self) -> Result<String> {
        Ok(format!(
            "{VERIFY_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(encode(self)?)
        ))
    }
    pub fn import(text: &str) -> Result<Self> {
        let raw = text.trim().strip_prefix(VERIFY_PREFIX).ok_or_else(|| {
            Error::Invalid("expected a request verification QR code, not an invitation".into())
        })?;
        if raw.len() > 2048 {
            return Err(Error::Invalid("verification code too large".into()));
        }
        let value: Self = decode(
            &URL_SAFE_NO_PAD
                .decode(raw)
                .map_err(|_| Error::Invalid("verification code encoding".into()))?,
        )?;
        if value.server.len() > 512
            || !valid_id(&value.channel)
            || !valid_digest(&value.request)
            || !valid_digest(&value.device)
        {
            return Err(Error::Invalid("invalid verification code".into()));
        }
        Ok(value)
    }
    pub fn matches(&self, server: &str, request: &AdmissionRequest) -> Result<()> {
        if self != &Self::new(server.into(), request)? {
            return Err(Error::Invalid(
                "verification code does not match this pending request".into(),
            ));
        }
        Ok(())
    }
}
fn valid_digest(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
