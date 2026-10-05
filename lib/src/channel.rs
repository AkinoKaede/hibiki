use crate::{
    Error, Result, decode, digest, encode,
    identity::{Device, Identity, verify},
    now, random_id,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenesisBody {
    pub version: u16,
    pub id: String,
    pub name: String,
    pub founder: Device,
    pub psk_commitment: [u8; 32],
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelGenesis {
    pub body: GenesisBody,
    pub signature: Vec<u8>,
}

impl ChannelGenesis {
    pub fn create(identity: &Identity, name: String, verifier: &str) -> Result<Self> {
        Self::for_reserved(identity, random_id(), name, digest(verifier.as_bytes()))
    }
    pub fn for_reserved(
        identity: &Identity,
        id: String,
        name: String,
        psk_commitment: [u8; 32],
    ) -> Result<Self> {
        let body = GenesisBody {
            version: 1,
            id,
            name,
            founder: identity.device.clone(),
            psk_commitment,
        };
        let value = Self {
            signature: identity.sign("genesis/v1", &body)?,
            body,
        };
        value.verify()?;
        Ok(value)
    }
    pub fn verify(&self) -> Result<()> {
        let b = &self.body;
        if b.version != 1 || !valid_id(&b.id) || b.name.trim().is_empty() || b.name.len() > 128 {
            return Err(Error::Invalid("channel identity/name".into()));
        }
        b.founder.verify()?;
        verify(&b.founder.signing_key, "genesis/v1", b, &self.signature)
    }
    pub fn hash(&self) -> Result<[u8; 32]> {
        Ok(digest(&encode(self)?))
    }
}

pub fn valid_id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct JoinBody {
    pub channel_id: String,
    pub genesis_hash: [u8; 32],
    pub device: Device,
    pub nonce: String,
    pub psk_epoch: u64,
    pub created_at: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct JoinRequest {
    pub body: JoinBody,
    pub signature: Vec<u8>,
}

impl JoinRequest {
    pub fn create(identity: &Identity, state: &VerifiedChannelState) -> Result<Self> {
        let body = JoinBody {
            channel_id: state.id.clone(),
            genesis_hash: state.genesis_hash,
            device: identity.device.clone(),
            nonce: random_id(),
            psk_epoch: state.psk_epoch,
            created_at: now(),
        };
        Ok(Self {
            signature: identity.sign("join/v1", &body)?,
            body,
        })
    }
    pub fn id(&self) -> Result<String> {
        Ok(hex::encode(digest(&encode(self)?)))
    }
    pub fn verify(&self) -> Result<()> {
        self.body.device.verify()?;
        if !valid_id(&self.body.nonce) {
            return Err(Error::Invalid("join request nonce".into()));
        }
        verify(
            &self.body.device.signing_key,
            "join/v1",
            &self.body,
            &self.signature,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // Bounded, serialized wire value.
pub enum MembershipAction {
    Admit(JoinRequest),
    Revoke {
        device_id: String,
    },
    ChangePsk {
        verifier_commitment: [u8; 32],
    },
    /// A member leaves voluntarily; readmission requires a fresh signed request.
    Leave,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventBody {
    pub channel_id: String,
    pub sequence: u64,
    pub previous_event_hash: [u8; 32],
    pub action: MembershipAction,
    pub issuer_device_id: String,
    pub issued_at: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MembershipEvent {
    pub body: EventBody,
    pub signature: Vec<u8>,
}

impl MembershipEvent {
    pub fn create(
        identity: &Identity,
        state: &VerifiedChannelState,
        action: MembershipAction,
    ) -> Result<Self> {
        let body = EventBody {
            channel_id: state.id.clone(),
            sequence: state.sequence + 1,
            previous_event_hash: state.head,
            action,
            issuer_device_id: identity.device.id(),
            issued_at: now(),
        };
        Ok(Self {
            signature: identity.sign("membership/v1", &body)?,
            body,
        })
    }
    pub fn hash(&self) -> Result<[u8; 32]> {
        Ok(digest(&encode(self)?))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MembershipProof {
    pub genesis: ChannelGenesis,
    pub events: Vec<MembershipEvent>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustCheckpoint {
    pub sequence: u64,
    pub hash: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct VerifiedChannelState {
    pub id: String,
    pub name: String,
    pub genesis_hash: [u8; 32],
    pub sequence: u64,
    pub head: [u8; 32],
    pub psk_epoch: u64,
    pub psk_commitment: [u8; 32],
    members: BTreeMap<String, Device>,
    seen: BTreeSet<String>,
    known: BTreeMap<String, Device>,
    admissions: BTreeSet<String>,
}
impl VerifiedChannelState {
    pub fn members(&self) -> &BTreeMap<String, Device> {
        &self.members
    }
    pub fn member(&self, id: &str) -> Result<&Device> {
        self.members.get(id).ok_or(Error::NotMember)
    }
    pub fn checkpoint(&self) -> TrustCheckpoint {
        TrustCheckpoint {
            sequence: self.sequence,
            hash: self.head,
        }
    }
}

impl MembershipProof {
    pub fn verify(&self) -> Result<VerifiedChannelState> {
        self.genesis.verify()?;
        if self.events.len() > 10000 {
            return Err(Error::Invalid("membership log too long".into()));
        }
        let g = &self.genesis.body;
        let gh = self.genesis.hash()?;
        let mut state = VerifiedChannelState {
            id: g.id.clone(),
            name: g.name.clone(),
            genesis_hash: gh,
            sequence: 0,
            head: gh,
            psk_epoch: 0,
            psk_commitment: g.psk_commitment,
            members: BTreeMap::from([(g.founder.id(), g.founder.clone())]),
            seen: BTreeSet::from([g.founder.id()]),
            known: BTreeMap::from([(g.founder.id(), g.founder.clone())]),
            admissions: BTreeSet::new(),
        };
        for event in &self.events {
            let b = &event.body;
            if b.channel_id != state.id
                || b.sequence != state.sequence + 1
                || b.previous_event_hash != state.head
            {
                return Err(Error::Fork);
            }
            let issuer = state.member(&b.issuer_device_id)?;
            verify(&issuer.signing_key, "membership/v1", b, &event.signature)?;
            match &b.action {
                MembershipAction::Admit(request) => {
                    request.verify()?;
                    let r = &request.body;
                    if r.channel_id != state.id
                        || r.genesis_hash != gh
                        || r.psk_epoch != state.psk_epoch
                        || b.issued_at < r.created_at
                        || !state.seen.insert(r.device.id())
                        || !state.admissions.insert(request.id()?)
                        || state
                            .known
                            .get(&r.device.id())
                            .is_some_and(|old| old != &r.device)
                    {
                        return Err(Error::Invalid("invalid or reused admission".into()));
                    }
                    state.known.insert(r.device.id(), r.device.clone());
                    state.members.insert(r.device.id(), r.device.clone());
                }
                MembershipAction::Leave => {
                    state
                        .members
                        .remove(&b.issuer_device_id)
                        .ok_or(Error::NotMember)?;
                    state.seen.remove(&b.issuer_device_id);
                }
                MembershipAction::Revoke { device_id } => {
                    if state.members.remove(device_id).is_none() {
                        return Err(Error::NotMember);
                    }
                }
                MembershipAction::ChangePsk {
                    verifier_commitment,
                } => {
                    state.psk_epoch += 1;
                    state.psk_commitment = *verifier_commitment;
                }
            }
            state.sequence = b.sequence;
            state.head = event.hash()?;
        }
        Ok(state)
    }

    pub fn verify_from(
        &self,
        root: &[u8; 32],
        checkpoint: &TrustCheckpoint,
    ) -> Result<VerifiedChannelState> {
        let state = self.verify()?;
        if &state.genesis_hash != root || self.hash_at(checkpoint.sequence)? != checkpoint.hash {
            return Err(Error::Fork);
        }
        Ok(state)
    }

    pub fn hash_at(&self, sequence: u64) -> Result<[u8; 32]> {
        if sequence == 0 {
            return self.genesis.hash();
        }
        self.events
            .get((sequence - 1) as usize)
            .ok_or(Error::Fork)?
            .hash()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invite {
    pub version: u16,
    pub server: String,
    pub genesis: ChannelGenesis,
    pub checkpoint: TrustCheckpoint,
}
impl Invite {
    pub fn export(&self) -> Result<String> {
        Ok(format!(
            "hibiki-v1:{}",
            URL_SAFE_NO_PAD.encode(encode(self)?)
        ))
    }
    pub fn import(text: &str) -> Result<Self> {
        let raw = text
            .strip_prefix("hibiki-v1:")
            .ok_or_else(|| Error::Invalid("invite prefix".into()))?;
        if raw.len() > 32768 {
            return Err(Error::Invalid("invite too large".into()));
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(raw)
            .map_err(|_| Error::Invalid("invite encoding".into()))?;
        let invite: Self = decode(&bytes)?;
        if invite.version != 1 {
            return Err(Error::Unsupported("invite version".into()));
        }
        invite.genesis.verify()?;
        Ok(invite)
    }
}

pub fn make_psk() -> String {
    let mut b = [0; 32];
    getrandom::fill(&mut b).expect("operating-system random source unavailable");
    URL_SAFE_NO_PAD.encode(b)
}
pub fn hash_psk(psk: &str) -> Result<String> {
    use argon2::{Argon2, PasswordHasher};
    if psk.len() < 8 || psk.len() > 1024 {
        return Err(Error::Invalid("PSK must have 8..1024 bytes".into()));
    }
    Argon2::default()
        .hash_password(psk.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| Error::Crypto(e.to_string()))
}
pub fn check_psk(psk: &str, verifier: &str) -> bool {
    use argon2::{Argon2, PasswordHash, PasswordVerifier};
    if psk.len() > 1024 {
        return false;
    }
    PasswordHash::new(verifier).is_ok_and(|h| {
        Argon2::default()
            .verify_password(psk.as_bytes(), &h)
            .is_ok()
    })
}

/// Public, single-use initialization invitation. No device trust root exists yet.
/// Only its recipient who creates the exact founder genesis may bootstrap from it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmptyChannelInvite {
    pub version: u16,
    pub server: String,
    pub id: String,
    pub name: String,
    pub psk_commitment: [u8; 32],
}
impl EmptyChannelInvite {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1
            || !valid_id(&self.id)
            || self.name.trim().is_empty()
            || self.name.len() > 128
        {
            return Err(Error::Invalid("empty channel invitation".into()));
        }
        Ok(())
    }
    pub fn export(&self) -> Result<String> {
        self.validate()?;
        Ok(format!(
            "hibiki-init-v1:{}",
            URL_SAFE_NO_PAD.encode(encode(self)?)
        ))
    }
    pub fn import(text: &str) -> Result<Self> {
        let raw = text
            .strip_prefix("hibiki-init-v1:")
            .ok_or_else(|| Error::Invalid("initialization invitation prefix".into()))?;
        if raw.len() > 32768 {
            return Err(Error::Invalid("initialization invitation length".into()));
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(raw)
            .map_err(|_| Error::Invalid("initialization invitation encoding".into()))?;
        let invite: Self = decode(&bytes)?;
        invite.validate()?;
        Ok(invite)
    }
    pub fn founder_genesis(&self, identity: &Identity) -> Result<ChannelGenesis> {
        self.validate()?;
        ChannelGenesis::for_reserved(
            identity,
            self.id.clone(),
            self.name.clone(),
            self.psk_commitment,
        )
    }
}

/// Invitation kind is public; credentials are kept in the separate secret envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum InvitationKind {
    Member(Invite),
    Initialization(EmptyChannelInvite),
}
impl InvitationKind {
    pub fn import(text: &str) -> Result<Self> {
        if text.starts_with("hibiki-init-v1:") {
            Ok(Self::Initialization(EmptyChannelInvite::import(text)?))
        } else {
            Ok(Self::Member(Invite::import(text)?))
        }
    }
    pub fn export(&self) -> Result<String> {
        match self {
            Self::Member(value) => value.export(),
            Self::Initialization(value) => value.export(),
        }
    }
    pub fn server(&self) -> &str {
        match self {
            Self::Member(v) => &v.server,
            Self::Initialization(v) => &v.server,
        }
    }
}

#[derive(Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct CredentialInvitation {
    version: u16,
    #[zeroize(skip)]
    invitation: InvitationKind,
    psk: String,
}
impl std::fmt::Debug for CredentialInvitation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[credential invitation redacted]")
    }
}

pub struct ParsedInvitation {
    pub invitation: InvitationKind,
    pub psk: Option<zeroize::Zeroizing<String>>,
}
impl std::fmt::Debug for ParsedInvitation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[invitation redacted]")
    }
}
impl ParsedInvitation {
    pub fn import(text: &str) -> Result<Self> {
        let text = text.trim();
        let Some(raw) = text.strip_prefix("hibiki-psk-v1:") else {
            return Ok(Self {
                invitation: InvitationKind::import(text)?,
                psk: None,
            });
        };
        if raw.len() > 32768 {
            return Err(Error::Invalid("invite too large".into()));
        }
        let bytes = zeroize::Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(raw)
                .map_err(|_| Error::Invalid("invite encoding".into()))?,
        );
        let mut value: CredentialInvitation =
            decode(&bytes).map_err(|_| Error::Invalid("credential invitation encoding".into()))?;
        if value.version != 1 {
            return Err(Error::Unsupported("credential invitation version".into()));
        }
        validate_invitation_psk(&value.psk)?;
        // Reuse the original signature/version validation without accepting nesting.
        InvitationKind::import(&value.invitation.export()?)?;
        Ok(Self {
            invitation: value.invitation.clone(),
            psk: Some(zeroize::Zeroizing::new(std::mem::take(&mut value.psk))),
        })
    }
    pub fn secret(
        self,
        external: Option<String>,
    ) -> Result<(InvitationKind, Option<zeroize::Zeroizing<String>>)> {
        let external = external.map(zeroize::Zeroizing::new);
        if self.psk.is_some() && external.is_some() {
            return Err(Error::Invalid(
                "invitation already contains a PSK; do not supply another PSK".into(),
            ));
        }
        Ok((self.invitation, self.psk.or(external)))
    }
}
fn validate_invitation_psk(psk: &str) -> Result<()> {
    if !(8..=1024).contains(&psk.len()) {
        return Err(Error::Invalid("PSK must have 8..1024 bytes".into()));
    }
    Ok(())
}
pub fn invitation_with_psk(invitation: InvitationKind, psk: String) -> Result<String> {
    let value = CredentialInvitation {
        version: 1,
        invitation,
        psk,
    };
    validate_invitation_psk(&value.psk)?;
    InvitationKind::import(&value.invitation.export()?)?;
    let bytes = crate::encode_secret(&value)?;
    let raw = URL_SAFE_NO_PAD.encode(&*bytes);
    if raw.len() > 32768 {
        return Err(Error::Invalid("invite too large".into()));
    }
    Ok(format!("hibiki-psk-v1:{raw}"))
}
