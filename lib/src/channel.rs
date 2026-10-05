use crate::{
    Error, Result, digest, encode,
    identity::{Device, Identity, verify},
    now, random_id,
};
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
    pub fn without_psk(identity: &Identity, id: String, name: String) -> Result<Self> {
        let body = GenesisBody {
            version: 2,
            id,
            name,
            founder: identity.device.clone(),
            psk_commitment: [0; 32],
        };
        let value = Self {
            signature: identity.sign("genesis/v2", &body)?,
            body,
        };
        value.verify()?;
        Ok(value)
    }
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
        if !matches!(b.version, 1 | 2)
            || (b.version == 2 && b.psk_commitment != [0; 32])
            || !valid_id(&b.id)
            || b.name.trim().is_empty()
            || b.name.len() > 128
        {
            return Err(Error::Invalid("channel identity/name".into()));
        }
        b.founder.verify()?;
        verify(
            &b.founder.signing_key,
            if b.version == 1 {
                "genesis/v1"
            } else {
                "genesis/v2"
            },
            b,
            &self.signature,
        )
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
    Rename {
        device: Device,
    },
    /// Explicit cascading removal; ordinary Revoke remains target-only.
    RevokeSubtree {
        device_id: String,
    },
    // Append only: these discriminants preserve every historical signing preimage.
    EnableInvitations,
    Accept(crate::invitation::AdmissionRequest),
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
            signature: identity.sign(
                if state.invitations_enabled
                    || matches!(body.action, MembershipAction::EnableInvitations)
                {
                    "membership/v3"
                } else {
                    "membership/v1"
                },
                &body,
            )?,
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
    pub invitations_enabled: bool,
    pub psk_epoch: u64,
    pub psk_commitment: [u8; 32],
    members: BTreeMap<String, Device>,
    seen: BTreeSet<String>,
    known: BTreeMap<String, Device>,
    admissions: BTreeSet<String>,
    // Keep departed intermediaries so ancestor authority does not disappear.
    approved_by: BTreeMap<String, String>,
    admitted_at: BTreeMap<String, u64>,
    current_admission: BTreeMap<String, String>,
    round_parents: BTreeMap<String, String>,
    removed_at: BTreeMap<String, u64>,
    checkpoints: Vec<[u8; 32]>,
    used_invitations: BTreeSet<String>,
}
impl VerifiedChannelState {
    pub fn members(&self) -> &BTreeMap<String, Device> {
        &self.members
    }
    pub fn member(&self, id: &str) -> Result<&Device> {
        self.members.get(id).ok_or(Error::NotMember)
    }
    pub fn approved_by(&self, id: &str) -> Option<&Device> {
        self.approved_by
            .get(id)
            .and_then(|parent| self.known.get(parent))
    }
    pub fn admission_id(&self, device: &str) -> Option<&str> {
        self.current_admission.get(device).map(String::as_str)
    }
    fn seed_admissions(&mut self) {
        for id in self.known.keys() {
            self.current_admission.insert(
                id.clone(),
                hex::encode(digest(
                    format!("admission/v3:{}:{id}", hex::encode(self.head)).as_bytes(),
                )),
            );
        }
        for (child, parent) in &self.approved_by {
            self.round_parents.insert(
                self.current_admission[child].clone(),
                self.current_admission[parent].clone(),
            );
        }
    }
    pub fn validate_admission(&self, request: &crate::invitation::AdmissionRequest) -> Result<()> {
        request.verify()?;
        let r = &request.body;
        let id = r.device.id();
        if !self.invitations_enabled
            || r.channel_id != self.id
            || r.genesis_hash != self.genesis_hash
            || self.checkpoints.get(r.checkpoint.sequence as usize) != Some(&r.checkpoint.hash)
            || r.checkpoint.sequence < *self.removed_at.get(&id).unwrap_or(&0)
            || r.previous_admission.as_deref() != self.admission_id(&id)
            || self.admissions.contains(&request.id()?)
            || self.used_invitations.contains(&r.invitation_id)
            || self.known.get(&id).is_some_and(|old| {
                old.signing_key != r.device.signing_key || old.noise_key != r.device.noise_key
            })
        {
            return Err(Error::Invalid("stale, reused or invalid admission".into()));
        }
        Ok(())
    }
    fn descends_from(&self, target: &str, ancestor: &str) -> bool {
        if self.invitations_enabled {
            let (Some(mut current), Some(ancestor)) =
                (self.admission_id(target), self.admission_id(ancestor))
            else {
                return false;
            };
            for _ in 0..self.round_parents.len() {
                let Some(parent) = self.round_parents.get(current) else {
                    return false;
                };
                if parent == ancestor {
                    return true;
                }
                current = parent;
            }
            return false;
        }
        let mut current = target;
        for _ in 0..self.approved_by.len() {
            let Some(parent) = self.approved_by.get(current) else {
                return false;
            };
            if parent == ancestor {
                return true;
            }
            current = parent;
        }
        false
    }
    pub fn can_revoke(&self, issuer: &str, target: &str) -> bool {
        self.can_revoke_at(issuer, target, now())
    }
    pub fn can_revoke_at(&self, issuer: &str, target: &str, at: u64) -> bool {
        issuer != target
            && self.members.contains_key(issuer)
            && self.members.contains_key(target)
            && (self.descends_from(target, issuer)
                || (self.descends_from(issuer, target)
                    && self
                        .admitted_at
                        .get(issuer)
                        .is_some_and(|joined| at >= joined.saturating_add(30 * 24 * 60 * 60))))
    }
    pub fn reverse_revoke_available_at(&self, issuer: &str, target: &str) -> Option<u64> {
        (issuer != target
            && self.members.contains_key(issuer)
            && self.members.contains_key(target)
            && self.descends_from(issuer, target))
        .then(|| {
            self.admitted_at
                .get(issuer)
                .map(|joined| joined.saturating_add(30 * 24 * 60 * 60))
        })
        .flatten()
    }
    pub fn can_revoke_subtree(&self, issuer: &str, target: &str) -> bool {
        issuer != target
            && self.members.contains_key(issuer)
            && self.members.contains_key(target)
            && self.descends_from(target, issuer)
    }
    pub fn revocation_subtree(&self, target: &str) -> Vec<String> {
        self.members
            .keys()
            .filter(|id| id.as_str() == target || self.descends_from(id, target))
            .cloned()
            .collect()
    }
    pub fn is_revoked(&self, id: &str) -> bool {
        self.seen.contains(id) && !self.members.contains_key(id)
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
            invitations_enabled: g.version == 2,
            psk_epoch: 0,
            psk_commitment: g.psk_commitment,
            members: BTreeMap::from([(g.founder.id(), g.founder.clone())]),
            seen: BTreeSet::from([g.founder.id()]),
            known: BTreeMap::from([(g.founder.id(), g.founder.clone())]),
            admissions: BTreeSet::new(),
            approved_by: BTreeMap::new(),
            admitted_at: BTreeMap::new(),
            current_admission: BTreeMap::new(),
            round_parents: BTreeMap::new(),
            removed_at: BTreeMap::new(),
            checkpoints: vec![gh],
            used_invitations: BTreeSet::new(),
        };
        if state.invitations_enabled {
            state.seed_admissions();
        }
        for event in &self.events {
            let b = &event.body;
            if b.channel_id != state.id
                || b.sequence != state.sequence + 1
                || b.previous_event_hash != state.head
            {
                return Err(Error::Fork);
            }
            let issuer = state.member(&b.issuer_device_id)?;
            verify(
                &issuer.signing_key,
                if state.invitations_enabled
                    || matches!(b.action, MembershipAction::EnableInvitations)
                {
                    "membership/v3"
                } else {
                    "membership/v1"
                },
                b,
                &event.signature,
            )?;
            match &b.action {
                MembershipAction::EnableInvitations => {
                    if state.invitations_enabled {
                        return Err(Error::Invalid("channel already upgraded".into()));
                    }
                    state.seed_admissions();
                    state.invitations_enabled = true;
                }
                MembershipAction::Accept(request) => {
                    state.validate_admission(request)?;
                    let r = &request.body;
                    let id = r.device.id();
                    if id == b.issuer_device_id || b.issued_at < r.created_at {
                        return Err(Error::Invalid("invalid admission approver or time".into()));
                    }
                    let admission = request.id()?;
                    state.round_parents.insert(
                        admission.clone(),
                        state.current_admission[&b.issuer_device_id].clone(),
                    );
                    state
                        .current_admission
                        .insert(id.clone(), admission.clone());
                    state.admissions.insert(admission);
                    state.used_invitations.insert(r.invitation_id.clone());
                    state
                        .approved_by
                        .insert(id.clone(), b.issuer_device_id.clone());
                    state.admitted_at.insert(id.clone(), b.issued_at);
                    state.known.insert(id.clone(), r.device.clone());
                    state.seen.insert(id.clone());
                    state.members.insert(id, r.device.clone());
                }
                MembershipAction::Admit(request) => {
                    if state.invitations_enabled {
                        return Err(Error::Unsupported("legacy admission after upgrade".into()));
                    }
                    request.verify()?;
                    let r = &request.body;
                    if r.device.id() == g.founder.id()
                        || state.descends_from(&b.issuer_device_id, &r.device.id())
                    {
                        return Err(Error::Invalid(
                            "admission would reverse the approval chain".into(),
                        ));
                    }
                    if r.channel_id != state.id
                        || r.genesis_hash != gh
                        || r.psk_epoch != state.psk_epoch
                        || b.issued_at < r.created_at
                        || !state.seen.insert(r.device.id())
                        || !state.admissions.insert(request.id()?)
                        || state.known.get(&r.device.id()).is_some_and(|old| {
                            old.signing_key != r.device.signing_key
                                || old.noise_key != r.device.noise_key
                        })
                    {
                        return Err(Error::Invalid("invalid or reused admission".into()));
                    }
                    state.known.insert(r.device.id(), r.device.clone());
                    state
                        .approved_by
                        .insert(r.device.id(), b.issuer_device_id.clone());
                    state.admitted_at.insert(r.device.id(), b.issued_at);
                    state.members.insert(r.device.id(), r.device.clone());
                }
                MembershipAction::Rename { device } => {
                    device.verify()?;
                    if device.id() != b.issuer_device_id
                        || device.signing_key != issuer.signing_key
                        || device.noise_key != issuer.noise_key
                    {
                        return Err(Error::Invalid(
                            "rename must preserve the issuer identity".into(),
                        ));
                    }
                    state.known.insert(device.id(), device.clone());
                    state.members.insert(device.id(), device.clone());
                }
                MembershipAction::Leave => {
                    state
                        .members
                        .remove(&b.issuer_device_id)
                        .ok_or(Error::NotMember)?;
                    state.seen.remove(&b.issuer_device_id);
                    state
                        .removed_at
                        .insert(b.issuer_device_id.clone(), b.sequence);
                }
                MembershipAction::Revoke { device_id } => {
                    if !state.can_revoke_at(&b.issuer_device_id, device_id, b.issued_at) {
                        return Err(Error::Invalid("revocation requires a descendant target, or an ancestor target after 30 days of current membership; use Leave to remove yourself".into()));
                    }
                    state.removed_at.insert(device_id.clone(), b.sequence);
                    if state.members.remove(device_id).is_none() {
                        return Err(Error::NotMember);
                    }
                }
                MembershipAction::RevokeSubtree { device_id } => {
                    if !state.can_revoke_subtree(&b.issuer_device_id, device_id) {
                        return Err(Error::Invalid(
                            "subtree revocation requires a descendant target".into(),
                        ));
                    }
                    // Mark departed intermediaries as removed too. After the upgrade,
                    // returning devices need a request pinned after this removal.
                    let removed: Vec<_> = state
                        .known
                        .keys()
                        .filter(|id| id.as_str() == device_id || state.descends_from(id, device_id))
                        .cloned()
                        .collect();
                    for id in removed {
                        state.members.remove(&id);
                        state.removed_at.insert(id.clone(), b.sequence);
                        state.seen.insert(id);
                    }
                }
                MembershipAction::ChangePsk {
                    verifier_commitment,
                } => {
                    if state.invitations_enabled {
                        return Err(Error::Unsupported("PSK rotation after upgrade".into()));
                    }
                    state.psk_epoch += 1;
                    state.psk_commitment = *verifier_commitment;
                }
            }
            state.sequence = b.sequence;
            state.head = event.hash()?;
            state.checkpoints.push(state.head);
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
