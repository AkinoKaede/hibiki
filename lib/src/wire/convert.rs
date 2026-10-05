/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

//! Typed hibiki/4 conversions. Persistent and signed formats use the separate Postcard codec.
use super::{Wire, array32, invalid, pb, required, signature64};
use crate::e2ee::Fragment;
use crate::invitation::{AdmissionRequest, InvitationMetadata, OneTimeInvitation};
use crate::{Result, assuan::Line, channel::*, identity::Device, protocol::*};

impl Wire for JoinState {
    type Proto = i32;
    fn to_proto(&self) -> i32 {
        match self {
            Self::Pending => 1,
            Self::Member => 2,
            Self::Absent => 3,
        }
    }
    fn from_proto(value: &i32) -> Result<Self> {
        match *value {
            1 => Ok(Self::Pending),
            2 => Ok(Self::Member),
            3 => Ok(Self::Absent),
            _ => Err(invalid("unknown or unspecified JoinState")),
        }
    }
}

impl Wire for ServiceKind {
    type Proto = i32;
    fn to_proto(&self) -> i32 {
        match self {
            Self::Scdaemon => 1,
            Self::Pinentry => 2,
        }
    }
    fn from_proto(value: &i32) -> Result<Self> {
        match *value {
            1 => Ok(Self::Scdaemon),
            2 => Ok(Self::Pinentry),
            _ => Err(invalid("unknown or unspecified ServiceKind")),
        }
    }
}

impl Wire for OperationState {
    type Proto = i32;
    fn to_proto(&self) -> i32 {
        match self {
            Self::Pending => 1,
            Self::Completed => 2,
            Self::Canceled => 3,
            Self::Expired => 4,
        }
    }
    fn from_proto(value: &i32) -> Result<Self> {
        match *value {
            1 => Ok(Self::Pending),
            2 => Ok(Self::Completed),
            3 => Ok(Self::Canceled),
            4 => Ok(Self::Expired),
            _ => Err(invalid("unknown or unspecified OperationState")),
        }
    }
}

impl Wire for TargetState {
    type Proto = i32;
    fn to_proto(&self) -> i32 {
        match self {
            Self::Pending => 1,
            Self::Executing => 2,
            Self::Succeeded => 3,
            Self::Failed => 4,
        }
    }
    fn from_proto(value: &i32) -> Result<Self> {
        match *value {
            1 => Ok(Self::Pending),
            2 => Ok(Self::Executing),
            3 => Ok(Self::Succeeded),
            4 => Ok(Self::Failed),
            _ => Err(invalid("unknown or unspecified TargetState")),
        }
    }
}

impl Wire for WireError {
    type Proto = pb::WireError;
    const NAME: &'static str = "WireError";
    fn to_proto(&self) -> Self::Proto {
        pb::WireError {
            code: self.code.clone(),
            message: self.message.clone(),
        }
    }
    fn from_proto(value: &Self::Proto) -> Result<Self> {
        let result = Self {
            code: value.code.clone(),
            message: value.message.clone(),
        };
        Ok(result)
    }
}

impl Wire for OperationTarget {
    type Proto = pb::OperationTarget;
    const NAME: &'static str = "OperationTarget";
    fn to_proto(&self) -> Self::Proto {
        pb::OperationTarget {
            device: self.device.clone(),
            state: self.state.to_proto(),
        }
    }
    fn from_proto(value: &Self::Proto) -> Result<Self> {
        let result = Self {
            device: value.device.clone(),
            state: TargetState::from_proto(&value.state)?,
        };
        Ok(result)
    }
}

impl Wire for Operation {
    type Proto = pb::Operation;
    const NAME: &'static str = "Operation";
    fn to_proto(&self) -> Self::Proto {
        pb::Operation {
            id: self.id.clone(),
            channel: self.channel.clone(),
            initiator: self.initiator.clone(),
            service: self.service.to_proto(),
            deadline: self.deadline,
            state: self.state.to_proto(),
            targets: self.targets.iter().map(|value| value.to_proto()).collect(),
        }
    }
    fn from_proto(value: &Self::Proto) -> Result<Self> {
        let result = Self {
            id: value.id.clone(),
            channel: value.channel.clone(),
            initiator: value.initiator.clone(),
            service: ServiceKind::from_proto(&value.service)?,
            deadline: value.deadline,
            state: OperationState::from_proto(&value.state)?,
            targets: value
                .targets
                .iter()
                .map(OperationTarget::from_proto)
                .collect::<Result<_>>()?,
        };
        Ok(result)
    }
}

impl Wire for CardTarget {
    type Proto = pb::CardTarget;
    const NAME: &'static str = "CardTarget";
    fn to_proto(&self) -> Self::Proto {
        pb::CardTarget {
            serial: self.serial.clone(),
            key: self.key.clone(),
        }
    }
    fn from_proto(value: &Self::Proto) -> Result<Self> {
        let result = Self {
            serial: value
                .serial
                .as_ref()
                .map(|value| Ok(value.clone()))
                .transpose()?,
            key: value
                .key
                .as_ref()
                .map(|value| Ok(value.clone()))
                .transpose()?,
        };
        result.validate()?;
        Ok(result)
    }
}

impl Wire for Device {
    type Proto = pb::Device;
    const NAME: &'static str = "Device";
    fn to_proto(&self) -> Self::Proto {
        pb::Device {
            name: self.name.clone(),
            signing_key: self.signing_key.to_vec(),
            noise_key: self.noise_key.to_vec(),
            binding: self.binding.clone(),
        }
    }
    fn from_proto(value: &Self::Proto) -> Result<Self> {
        let result = Self {
            name: value.name.clone(),
            signing_key: array32(&value.signing_key)?,
            noise_key: array32(&value.noise_key)?,
            binding: value.binding.clone(),
        };
        signature64(&result.binding)?;
        Ok(result)
    }
}

impl Wire for GenesisBody {
    type Proto = pb::GenesisBody;
    const NAME: &'static str = "GenesisBody";
    fn to_proto(&self) -> Self::Proto {
        pb::GenesisBody {
            id: self.id.clone(),
            name: self.name.clone(),
            founder: Some(self.founder.to_proto()),
        }
    }
    fn from_proto(value: &Self::Proto) -> Result<Self> {
        let result = Self {
            id: value.id.clone(),
            name: value.name.clone(),
            founder: Device::from_proto(required(&value.founder)?)?,
        };
        Ok(result)
    }
}

impl Wire for ChannelGenesis {
    type Proto = pb::ChannelGenesis;
    const NAME: &'static str = "ChannelGenesis";
    fn to_proto(&self) -> Self::Proto {
        pb::ChannelGenesis {
            body: Some(self.body.to_proto()),
            signature: self.signature.clone(),
        }
    }
    fn from_proto(value: &Self::Proto) -> Result<Self> {
        signature64(&value.signature)?;
        let result = Self {
            body: GenesisBody::from_proto(required(&value.body)?)?,
            signature: value.signature.clone(),
        };
        Ok(result)
    }
}

impl Wire for EventBody {
    type Proto = pb::EventBody;
    const NAME: &'static str = "EventBody";
    fn to_proto(&self) -> Self::Proto {
        pb::EventBody {
            channel_id: self.channel_id.clone(),
            sequence: self.sequence,
            previous_event_hash: self.previous_event_hash.to_vec(),
            action: Some(self.action.to_proto()),
            issuer_device_id: self.issuer_device_id.clone(),
            issued_at: self.issued_at,
        }
    }
    fn from_proto(value: &Self::Proto) -> Result<Self> {
        let result = Self {
            channel_id: value.channel_id.clone(),
            sequence: value.sequence,
            previous_event_hash: array32(&value.previous_event_hash)?,
            action: MembershipAction::from_proto(required(&value.action)?)?,
            issuer_device_id: value.issuer_device_id.clone(),
            issued_at: value.issued_at,
        };
        Ok(result)
    }
}

impl Wire for MembershipEvent {
    type Proto = pb::MembershipEvent;
    const NAME: &'static str = "MembershipEvent";
    fn to_proto(&self) -> Self::Proto {
        pb::MembershipEvent {
            body: Some(self.body.to_proto()),
            signature: self.signature.clone(),
        }
    }
    fn from_proto(value: &Self::Proto) -> Result<Self> {
        signature64(&value.signature)?;
        let result = Self {
            body: EventBody::from_proto(required(&value.body)?)?,
            signature: value.signature.clone(),
        };
        Ok(result)
    }
}

impl Wire for MembershipProof {
    type Proto = pb::MembershipProof;
    const NAME: &'static str = "MembershipProof";
    fn to_proto(&self) -> Self::Proto {
        pb::MembershipProof {
            genesis: Some(self.genesis.to_proto()),
            events: self.events.iter().map(|value| value.to_proto()).collect(),
        }
    }
    fn from_proto(value: &Self::Proto) -> Result<Self> {
        let result = Self {
            genesis: ChannelGenesis::from_proto(required(&value.genesis)?)?,
            events: value
                .events
                .iter()
                .map(MembershipEvent::from_proto)
                .collect::<Result<_>>()?,
        };
        Ok(result)
    }
}

impl Wire for Fragment {
    const LIMIT: usize = crate::e2ee::CHUNK + 16;
    fn validate_wire(&self) -> Result<()> {
        super::validate_fragment(self)
    }
    type Proto = pb::Fragment;
    const NAME: &'static str = "Fragment";
    fn to_proto(&self) -> Self::Proto {
        pb::Fragment {
            last: self.last,
            bytes: self.bytes.clone(),
        }
    }
    fn from_proto(value: &Self::Proto) -> Result<Self> {
        let result = Self {
            last: value.last,
            bytes: value.bytes.clone(),
        };
        Ok(result)
    }
}

impl Wire for Control {
    type Proto = pb::Control;
    const NAME: &'static str = "Control";
    fn to_proto(&self) -> Self::Proto {
        use pb::control::Kind;
        let kind = match self {
            Self::Queue { operation } => Kind::Queue(pb::ControlQueue {
                operation: Some(operation.to_proto()),
            }),
            Self::ResumeOperation { id } => {
                Kind::ResumeOperation(pb::ControlResumeOperation { id: id.clone() })
            }
            Self::OperationStatus { id } => {
                Kind::OperationStatus(pb::ControlOperationStatus { id: id.clone() })
            }
            Self::ClaimOperation {
                id,
                initiator,
                channel,
                service,
            } => Kind::ClaimOperation(pb::ControlClaimOperation {
                id: id.clone(),
                initiator: initiator.clone(),
                channel: channel.clone(),
                service: service.to_proto(),
            }),
            Self::TargetDone { id, success } => Kind::TargetDone(pb::ControlTargetDone {
                id: id.clone(),
                success: *success,
            }),
            Self::AbandonTarget { id, peer } => Kind::AbandonTarget(pb::ControlAbandonTarget {
                id: id.clone(),
                peer: peer.clone(),
            }),
            Self::EndOperation { id, completed } => Kind::EndOperation(pb::ControlEndOperation {
                id: id.clone(),
                completed: *completed,
            }),
            Self::Create { genesis } => Kind::Create(pb::ControlCreate {
                genesis: Some(genesis.to_proto()),
            }),
            Self::GetChannel { channel } => Kind::GetChannel(pb::ControlGetChannel {
                channel: channel.clone(),
            }),
            Self::ListChannels => Kind::ListChannels(pb::ControlListChannels {}),
            Self::ChannelSnapshot { channel } => {
                Kind::ChannelSnapshot(pb::ControlChannelSnapshot {
                    channel: channel.clone(),
                })
            }
            Self::Join {
                request,
                invitation,
            } => Kind::Join(pb::ControlJoin {
                request: Some(request.to_proto()),
                invitation: Some(invitation.to_proto()),
            }),
            Self::Pending { channel } => Kind::Pending(pb::ControlPending {
                channel: channel.clone(),
            }),
            Self::Append { event } => Kind::Append(pb::ControlAppend {
                event: Some(event.to_proto()),
            }),
            Self::Announce { channels } => Kind::Announce(pb::ControlAnnounce {
                channels: channels.to_vec(),
            }),
            Self::Peers { channel } => Kind::Peers(pb::ControlPeers {
                channel: channel.clone(),
            }),
            Self::Claim {
                genesis,
                invitation,
            } => Kind::Claim(pb::ControlClaim {
                genesis: Some(genesis.to_proto()),
                invitation: Some(invitation.to_proto()),
            }),
            Self::RegisterInvitation { metadata } => {
                Kind::RegisterInvitation(pb::ControlRegisterInvitation {
                    metadata: Some(metadata.to_proto()),
                })
            }
            Self::ResolveInvitation { invitation } => {
                Kind::ResolveInvitation(pb::ControlResolveInvitation {
                    invitation: Some(invitation.to_proto()),
                })
            }
            Self::Policy => Kind::Policy(pb::ControlPolicy {}),
            Self::RejectJoin { channel, request } => Kind::RejectJoin(pb::ControlRejectJoin {
                channel: channel.clone(),
                request: request.clone(),
            }),
            Self::WithdrawJoin { channel, request } => {
                Kind::WithdrawJoin(pb::ControlWithdrawJoin {
                    channel: channel.clone(),
                    request: request.clone(),
                })
            }
            Self::JoinStatus { channel, request } => Kind::JoinStatus(pb::ControlJoinStatus {
                channel: channel.clone(),
                request: request.clone(),
            }),
            Self::WithdrawPending { channel } => {
                Kind::WithdrawPending(pb::ControlWithdrawPending {
                    channel: channel.clone(),
                })
            }
        };
        pb::Control { kind: Some(kind) }
    }
    fn from_proto(value: &Self::Proto) -> Result<Self> {
        use pb::control::Kind;
        Ok(match required(&value.kind)? {
            Kind::Queue(value) => Self::Queue {
                operation: Operation::from_proto(required(&value.operation)?)?,
            },
            Kind::ResumeOperation(value) => Self::ResumeOperation {
                id: value.id.clone(),
            },
            Kind::OperationStatus(value) => Self::OperationStatus {
                id: value.id.clone(),
            },
            Kind::ClaimOperation(value) => Self::ClaimOperation {
                id: value.id.clone(),
                initiator: value.initiator.clone(),
                channel: value.channel.clone(),
                service: ServiceKind::from_proto(&value.service)?,
            },
            Kind::TargetDone(value) => Self::TargetDone {
                id: value.id.clone(),
                success: value.success,
            },
            Kind::AbandonTarget(value) => Self::AbandonTarget {
                id: value.id.clone(),
                peer: value.peer.clone(),
            },
            Kind::EndOperation(value) => Self::EndOperation {
                id: value.id.clone(),
                completed: value.completed,
            },
            Kind::Create(value) => Self::Create {
                genesis: ChannelGenesis::from_proto(required(&value.genesis)?)?,
            },
            Kind::GetChannel(value) => Self::GetChannel {
                channel: value.channel.clone(),
            },
            Kind::ListChannels(_) => Self::ListChannels,
            Kind::ChannelSnapshot(value) => Self::ChannelSnapshot {
                channel: value.channel.clone(),
            },
            Kind::Join(value) => Self::Join {
                request: AdmissionRequest::from_proto(required(&value.request)?)?,
                invitation: OneTimeInvitation::from_proto(required(&value.invitation)?)?,
            },
            Kind::Pending(value) => Self::Pending {
                channel: value.channel.clone(),
            },
            Kind::Append(value) => Self::Append {
                event: MembershipEvent::from_proto(required(&value.event)?)?,
            },
            Kind::Announce(value) => Self::Announce {
                channels: value
                    .channels
                    .iter()
                    .map(|value| Ok(value.clone()))
                    .collect::<Result<_>>()?,
            },
            Kind::Peers(value) => Self::Peers {
                channel: value.channel.clone(),
            },
            Kind::Claim(value) => Self::Claim {
                genesis: ChannelGenesis::from_proto(required(&value.genesis)?)?,
                invitation: OneTimeInvitation::from_proto(required(&value.invitation)?)?,
            },
            Kind::RegisterInvitation(v) => Self::RegisterInvitation {
                metadata: InvitationMetadata::from_proto(required(&v.metadata)?)?,
            },
            Kind::ResolveInvitation(v) => Self::ResolveInvitation {
                invitation: OneTimeInvitation::from_proto(required(&v.invitation)?)?,
            },
            Kind::Policy(_) => Self::Policy,
            Kind::RejectJoin(value) => Self::RejectJoin {
                channel: value.channel.clone(),
                request: value.request.clone(),
            },
            Kind::WithdrawJoin(value) => Self::WithdrawJoin {
                channel: value.channel.clone(),
                request: value.request.clone(),
            },
            Kind::JoinStatus(value) => Self::JoinStatus {
                channel: value.channel.clone(),
                request: value.request.clone(),
            },
            Kind::WithdrawPending(value) => Self::WithdrawPending {
                channel: value.channel.clone(),
            },
        })
    }
}

impl Wire for Reply {
    type Proto = pb::Reply;
    const NAME: &'static str = "Reply";
    fn to_proto(&self) -> Self::Proto {
        use pb::reply::Kind;
        let kind = match self {
            Self::Operation(value) => Kind::Operation(pb::ReplyOperation {
                value: Some(value.to_proto()),
            }),
            Self::Ok => Kind::Ok(pb::ReplyOk {}),
            Self::Proof(value) => Kind::Proof(pb::ReplyProof {
                value: Some(value.to_proto()),
            }),
            Self::Proofs(value) => Kind::Proofs(pb::ReplyProofs {
                value: value.iter().map(|value| value.to_proto()).collect(),
            }),
            Self::ChannelSnapshot {
                proof,
                online,
                revoked,
            } => Kind::ChannelSnapshot(pb::ReplyChannelSnapshot {
                proof: Some(proof.to_proto()),
                online: online.to_vec(),
                revoked: revoked.to_vec(),
            }),
            Self::InvitationProof {
                proof,
                access_revision,
            } => Kind::InvitationProof(pb::ReplyInvitationProof {
                proof: Some(proof.to_proto()),
                access_revision: *access_revision,
            }),
            Self::Requests(value) => Kind::Requests(pb::ReplyRequests {
                value: value.iter().map(|value| value.to_proto()).collect(),
            }),
            Self::Peers(value) => Kind::Peers(pb::ReplyPeers {
                value: value.to_vec(),
            }),
            Self::Policy {
                allow_client_channel_creation,
            } => Kind::Policy(pb::ReplyPolicy {
                allow_client_channel_creation: *allow_client_channel_creation,
            }),
            Self::JoinStatus(value) => Kind::JoinStatus(pb::ReplyJoinStatus {
                value: value.to_proto(),
            }),
        };
        pb::Reply { kind: Some(kind) }
    }
    fn from_proto(value: &Self::Proto) -> Result<Self> {
        use pb::reply::Kind;
        Ok(match required(&value.kind)? {
            Kind::Operation(value) => {
                Self::Operation(Operation::from_proto(required(&value.value)?)?)
            }
            Kind::Ok(_) => Self::Ok,
            Kind::Proof(value) => {
                Self::Proof(MembershipProof::from_proto(required(&value.value)?)?)
            }
            Kind::Proofs(value) => Self::Proofs(
                value
                    .value
                    .iter()
                    .map(MembershipProof::from_proto)
                    .collect::<Result<_>>()?,
            ),
            Kind::ChannelSnapshot(value) => Self::ChannelSnapshot {
                proof: MembershipProof::from_proto(required(&value.proof)?)?,
                online: value
                    .online
                    .iter()
                    .map(|value| Ok(value.clone()))
                    .collect::<Result<_>>()?,
                revoked: value
                    .revoked
                    .iter()
                    .map(|value| Ok(value.clone()))
                    .collect::<Result<_>>()?,
            },
            Kind::InvitationProof(v) => Self::InvitationProof {
                proof: MembershipProof::from_proto(required(&v.proof)?)?,
                access_revision: v.access_revision,
            },
            Kind::Requests(value) => Self::Requests(
                value
                    .value
                    .iter()
                    .map(AdmissionRequest::from_proto)
                    .collect::<Result<_>>()?,
            ),
            Kind::Peers(value) => Self::Peers(
                value
                    .value
                    .iter()
                    .map(|value| Ok(value.clone()))
                    .collect::<Result<_>>()?,
            ),
            Kind::Policy(value) => Self::Policy {
                allow_client_channel_creation: value.allow_client_channel_creation,
            },
            Kind::JoinStatus(value) => Self::JoinStatus(JoinState::from_proto(&value.value)?),
        })
    }
}

impl Wire for Envelope {
    const LIMIT: usize = MAX_WIRE;
    fn validate_wire(&self) -> Result<()> {
        super::validate_envelope(self)
    }
    type Proto = pb::Envelope;
    const NAME: &'static str = "Envelope";
    fn to_proto(&self) -> Self::Proto {
        use pb::envelope::Kind;
        let kind = match self {
            Self::OperationReady { id, peer } => Kind::OperationReady(pb::EnvelopeOperationReady {
                id: id.clone(),
                peer: peer.clone(),
            }),
            Self::OperationChanged { id } => {
                Kind::OperationChanged(pb::EnvelopeOperationChanged { id: id.clone() })
            }
            Self::Hello {
                version,
                nonce,
                capabilities,
            } => Kind::Hello(pb::EnvelopeHello {
                version: version.clone(),
                nonce: nonce.clone(),
                capabilities: capabilities.to_vec(),
            }),
            Self::Authenticate {
                device,
                signature,
                capabilities,
            } => Kind::Authenticate(pb::EnvelopeAuthenticate {
                device: Some(device.to_proto()),
                signature: signature.clone(),
                capabilities: capabilities.to_vec(),
            }),
            Self::Authenticated { capabilities } => {
                Kind::Authenticated(pb::EnvelopeAuthenticated {
                    capabilities: capabilities.to_vec(),
                })
            }
            Self::Request { id, command } => Kind::Request(pb::EnvelopeRequest {
                id: id.clone(),
                command: Some(command.to_proto()),
            }),
            Self::Response { id, result } => Kind::Response(pb::EnvelopeResponse {
                id: id.clone(),
                result: Some(encode_result(result)),
            }),
            Self::Relay {
                channel,
                peer,
                session,
                data,
            } => Kind::Relay(pb::EnvelopeRelay {
                channel: channel.clone(),
                peer: peer.clone(),
                session: session.clone(),
                data: data.clone(),
            }),
            Self::RelayFailure {
                session,
                peer,
                error,
            } => Kind::RelayFailure(pb::EnvelopeRelayFailure {
                session: session.clone(),
                peer: peer.clone(),
                error: Some(error.to_proto()),
            }),
            Self::ChannelChanged { channel } => Kind::ChannelChanged(pb::EnvelopeChannelChanged {
                channel: channel.clone(),
            }),
            Self::PeerOnline { peer } => {
                Kind::PeerOnline(pb::EnvelopePeerOnline { peer: peer.clone() })
            }
            Self::PeerOffline { peer } => {
                Kind::PeerOffline(pb::EnvelopePeerOffline { peer: peer.clone() })
            }
        };
        pb::Envelope { kind: Some(kind) }
    }
    fn from_proto(value: &Self::Proto) -> Result<Self> {
        use pb::envelope::Kind;
        Ok(match required(&value.kind)? {
            Kind::OperationReady(value) => Self::OperationReady {
                id: value.id.clone(),
                peer: value.peer.clone(),
            },
            Kind::OperationChanged(value) => Self::OperationChanged {
                id: value.id.clone(),
            },
            Kind::Hello(value) => Self::Hello {
                version: value.version.clone(),
                nonce: value.nonce.clone(),
                capabilities: value
                    .capabilities
                    .iter()
                    .map(|value| Ok(value.clone()))
                    .collect::<Result<_>>()?,
            },
            Kind::Authenticate(value) => Self::Authenticate {
                device: Device::from_proto(required(&value.device)?)?,
                signature: value.signature.clone(),
                capabilities: value
                    .capabilities
                    .iter()
                    .map(|value| Ok(value.clone()))
                    .collect::<Result<_>>()?,
            },
            Kind::Authenticated(value) => Self::Authenticated {
                capabilities: value
                    .capabilities
                    .iter()
                    .map(|value| Ok(value.clone()))
                    .collect::<Result<_>>()?,
            },
            Kind::Request(value) => Self::Request {
                id: value.id.clone(),
                command: Control::from_proto(required(&value.command)?)?,
            },
            Kind::Response(value) => Self::Response {
                id: value.id.clone(),
                result: decode_result(required(&value.result)?)?,
            },
            Kind::Relay(value) => Self::Relay {
                channel: value.channel.clone(),
                peer: value.peer.clone(),
                session: value.session.clone(),
                data: value.data.clone(),
            },
            Kind::RelayFailure(value) => Self::RelayFailure {
                session: value.session.clone(),
                peer: value.peer.clone(),
                error: WireError::from_proto(required(&value.error)?)?,
            },
            Kind::ChannelChanged(value) => Self::ChannelChanged {
                channel: value.channel.clone(),
            },
            Kind::PeerOnline(value) => Self::PeerOnline {
                peer: value.peer.clone(),
            },
            Kind::PeerOffline(value) => Self::PeerOffline {
                peer: value.peer.clone(),
            },
        })
    }
}

impl Wire for SessionInput {
    type Proto = pb::SessionInput;
    const NAME: &'static str = "SessionInput";
    fn to_proto(&self) -> Self::Proto {
        use pb::session_input::Kind;
        let kind = match self {
            Self::PrepareCard { id, target } => Kind::PrepareCard(pb::SessionInputPrepareCard {
                id: id.clone(),
                target: Some(target.to_proto()),
            }),
            Self::CancelPreparation { id } => {
                Kind::CancelPreparation(pb::SessionInputCancelPreparation { id: id.clone() })
            }
            Self::Execute {
                request,
                preparation,
                line,
            } => Kind::Execute(pb::SessionInputExecute {
                request: *request,
                preparation: preparation.iter().map(|value| value.0.clone()).collect(),
                line: line.0.clone(),
            }),
            Self::Command { request, line } => Kind::Command(pb::SessionInputCommand {
                request: *request,
                line: line.0.clone(),
            }),
            Self::InquiryReply { request, line } => {
                Kind::InquiryReply(pb::SessionInputInquiryReply {
                    request: *request,
                    line: line.0.clone(),
                })
            }
        };
        pb::SessionInput { kind: Some(kind) }
    }
    fn from_proto(value: &Self::Proto) -> Result<Self> {
        use pb::session_input::Kind;
        Ok(match required(&value.kind)? {
            Kind::PrepareCard(value) => Self::PrepareCard {
                id: value.id.clone(),
                target: CardTarget::from_proto(required(&value.target)?)?,
            },
            Kind::CancelPreparation(value) => Self::CancelPreparation {
                id: value.id.clone(),
            },
            Kind::Execute(value) => Self::Execute {
                request: value.request,
                preparation: value
                    .preparation
                    .iter()
                    .map(|value| Ok(Line(value.clone())))
                    .collect::<Result<_>>()?,
                line: Line(value.line.clone()),
            },
            Kind::Command(value) => Self::Command {
                request: value.request,
                line: Line(value.line.clone()),
            },
            Kind::InquiryReply(value) => Self::InquiryReply {
                request: value.request,
                line: Line(value.line.clone()),
            },
        })
    }
}

impl Wire for SessionOutput {
    type Proto = pb::SessionOutput;
    const NAME: &'static str = "SessionOutput";
    fn to_proto(&self) -> Self::Proto {
        use pb::session_output::Kind;
        let kind = match self {
            Self::CardStatus { id, state } => Kind::CardStatus(pb::SessionOutputCardStatus {
                id: id.clone(),
                state: Some(state.to_proto()),
            }),
            Self::Line { request, line } => Kind::Line(pb::SessionOutputLine {
                request: *request,
                line: line.0.clone(),
            }),
            Self::Failure => Kind::Failure(pb::SessionOutputFailure {}),
        };
        pb::SessionOutput { kind: Some(kind) }
    }
    fn from_proto(value: &Self::Proto) -> Result<Self> {
        use pb::session_output::Kind;
        Ok(match required(&value.kind)? {
            Kind::CardStatus(value) => Self::CardStatus {
                id: value.id.clone(),
                state: CardPreparation::from_proto(required(&value.state)?)?,
            },
            Kind::Line(value) => Self::Line {
                request: value.request,
                line: Line(value.line.clone()),
            },
            Kind::Failure(_) => Self::Failure,
        })
    }
}

impl Wire for PrivateMessage {
    const LIMIT: usize = crate::e2ee::MAX_PAYLOAD;
    fn validate_wire(&self) -> Result<()> {
        super::validate_private(self)
    }
    type Proto = pb::PrivateMessage;
    const NAME: &'static str = "PrivateMessage";
    fn to_proto(&self) -> Self::Proto {
        use pb::private_message::Kind;
        let kind = match self {
            Self::PingOpen {
                proof,
                capabilities,
            } => Kind::PingOpen(pb::PrivateMessagePingOpen {
                proof: Some(proof.to_proto()),
                capabilities: capabilities.to_vec(),
            }),
            Self::PingOpened {
                proof,
                capabilities,
            } => Kind::PingOpened(pb::PrivateMessagePingOpened {
                proof: Some(proof.to_proto()),
                capabilities: capabilities.to_vec(),
            }),
            Self::Ping { nonce } => Kind::Ping(pb::PrivateMessagePing {
                nonce: nonce.clone(),
            }),
            Self::Pong { nonce } => Kind::Pong(pb::PrivateMessagePong {
                nonce: nonce.clone(),
            }),
            Self::OpenService {
                proof,
                service,
                capabilities,
            } => Kind::OpenService(pb::PrivateMessageOpenService {
                proof: Some(proof.to_proto()),
                service: service.to_proto(),
                capabilities: capabilities.to_vec(),
            }),
            Self::ServiceOpened {
                proof,
                enabled,
                capabilities,
            } => Kind::ServiceOpened(pb::PrivateMessageServiceOpened {
                proof: Some(proof.to_proto()),
                enabled: *enabled,
                capabilities: capabilities.to_vec(),
            }),
            Self::Execute { id, input } => Kind::Execute(pb::PrivateMessageExecute {
                id: id.clone(),
                input: Some(input.to_proto()),
            }),
            Self::Input(value) => Kind::Input(pb::PrivateMessageInput {
                value: Some(value.to_proto()),
            }),
            Self::Output(value) => Kind::Output(pb::PrivateMessageOutput {
                value: Some(value.to_proto()),
            }),
            Self::OutputBatch { request, lines } => {
                Kind::OutputBatch(pb::PrivateMessageOutputBatch {
                    request: *request,
                    lines: lines.iter().map(|value| value.0.clone()).collect(),
                })
            }
            Self::Close => Kind::Close(pb::PrivateMessageClose {}),
            Self::Closed => Kind::Closed(pb::PrivateMessageClosed {}),
            Self::Failure => Kind::Failure(pb::PrivateMessageFailure {}),
        };
        pb::PrivateMessage { kind: Some(kind) }
    }
    fn from_proto(value: &Self::Proto) -> Result<Self> {
        use pb::private_message::Kind;
        Ok(match required(&value.kind)? {
            Kind::PingOpen(value) => Self::PingOpen {
                proof: MembershipProof::from_proto(required(&value.proof)?)?,
                capabilities: value
                    .capabilities
                    .iter()
                    .map(|value| Ok(value.clone()))
                    .collect::<Result<_>>()?,
            },
            Kind::PingOpened(value) => Self::PingOpened {
                proof: MembershipProof::from_proto(required(&value.proof)?)?,
                capabilities: value
                    .capabilities
                    .iter()
                    .map(|value| Ok(value.clone()))
                    .collect::<Result<_>>()?,
            },
            Kind::Ping(value) => Self::Ping {
                nonce: value.nonce.clone(),
            },
            Kind::Pong(value) => Self::Pong {
                nonce: value.nonce.clone(),
            },
            Kind::OpenService(value) => Self::OpenService {
                proof: MembershipProof::from_proto(required(&value.proof)?)?,
                service: ServiceKind::from_proto(&value.service)?,
                capabilities: value
                    .capabilities
                    .iter()
                    .map(|value| Ok(value.clone()))
                    .collect::<Result<_>>()?,
            },
            Kind::ServiceOpened(value) => Self::ServiceOpened {
                proof: MembershipProof::from_proto(required(&value.proof)?)?,
                enabled: value.enabled,
                capabilities: value
                    .capabilities
                    .iter()
                    .map(|value| Ok(value.clone()))
                    .collect::<Result<_>>()?,
            },
            Kind::Execute(value) => Self::Execute {
                id: value.id.clone(),
                input: SessionInput::from_proto(required(&value.input)?)?,
            },
            Kind::Input(value) => Self::Input(SessionInput::from_proto(required(&value.value)?)?),
            Kind::Output(value) => {
                Self::Output(SessionOutput::from_proto(required(&value.value)?)?)
            }
            Kind::OutputBatch(value) => Self::OutputBatch {
                request: value.request,
                lines: value
                    .lines
                    .iter()
                    .map(|value| Ok(Line(value.clone())))
                    .collect::<Result<_>>()?,
            },
            Kind::Close(_) => Self::Close,
            Kind::Closed(_) => Self::Closed,
            Kind::Failure(_) => Self::Failure,
        })
    }
}

impl Wire for CardPreparation {
    type Proto = pb::CardPreparation;
    const NAME: &'static str = "CardPreparation";
    fn to_proto(&self) -> Self::Proto {
        use pb::card_preparation::Kind;
        let kind = match self {
            Self::Waiting => Kind::Waiting(pb::CardPreparationWaiting {}),
            Self::Ready { serial } => Kind::Ready(pb::CardPreparationReady {
                serial: serial.clone(),
            }),
            Self::Unavailable => {
                Kind::Unavailable(pb::CardPreparationUnavailable { rejected: false })
            }
            Self::Rejected => Kind::Unavailable(pb::CardPreparationUnavailable { rejected: true }),
        };
        pb::CardPreparation { kind: Some(kind) }
    }
    fn from_proto(value: &Self::Proto) -> Result<Self> {
        use pb::card_preparation::Kind;
        Ok(match required(&value.kind)? {
            Kind::Waiting(_) => Self::Waiting,
            Kind::Ready(value) => Self::Ready {
                serial: value.serial.clone(),
            },
            Kind::Unavailable(value) if value.rejected => Self::Rejected,
            Kind::Unavailable(_) => Self::Unavailable,
        })
    }
}

impl Wire for MembershipAction {
    type Proto = pb::MembershipAction;
    const NAME: &'static str = "MembershipAction";
    fn to_proto(&self) -> Self::Proto {
        use pb::membership_action::Kind;
        let kind = match self {
            Self::Revoke { device_id } => Kind::Revoke(pb::MembershipActionRevoke {
                device_id: device_id.clone(),
            }),
            Self::Leave => Kind::Leave(pb::MembershipActionLeave {}),
            Self::Rename { device } => Kind::Rename(pb::MembershipActionRename {
                device: Some(device.to_proto()),
            }),
            Self::Accept(request) => Kind::Accept(request.to_proto()),
            Self::RevokeSubtree { device_id } => {
                Kind::RevokeSubtree(pb::MembershipActionRevokeSubtree {
                    device_id: device_id.clone(),
                })
            }
        };
        pb::MembershipAction { kind: Some(kind) }
    }
    fn from_proto(value: &Self::Proto) -> Result<Self> {
        use pb::membership_action::Kind;
        Ok(match required(&value.kind)? {
            Kind::Revoke(value) => Self::Revoke {
                device_id: value.device_id.clone(),
            },
            Kind::Leave(_) => Self::Leave,
            Kind::Rename(value) => Self::Rename {
                device: Device::from_proto(required(&value.device)?)?,
            },
            Kind::Accept(v) => Self::Accept(AdmissionRequest::from_proto(v)?),
            Kind::RevokeSubtree(value) => Self::RevokeSubtree {
                device_id: value.device_id.clone(),
            },
        })
    }
}

fn encode_result(value: &std::result::Result<Reply, WireError>) -> pb::ResponseResult {
    use pb::response_result::Kind;
    pb::ResponseResult {
        kind: Some(match value {
            Ok(value) => Kind::Ok(value.to_proto()),
            Err(value) => Kind::Error(value.to_proto()),
        }),
    }
}
fn decode_result(value: &pb::ResponseResult) -> Result<std::result::Result<Reply, WireError>> {
    use pb::response_result::Kind;
    Ok(match required(&value.kind)? {
        Kind::Ok(value) => Ok(Reply::from_proto(value)?),
        Kind::Error(value) => Err(WireError::from_proto(value)?),
    })
}

impl Wire for AdmissionRequest {
    type Proto = pb::AdmissionRequest;
    const NAME: &'static str = "AdmissionRequest";
    fn to_proto(&self) -> Self::Proto {
        pb::AdmissionRequest {
            canonical: crate::encode(self).expect("bounded signed request"),
        }
    }
    fn from_proto(v: &Self::Proto) -> Result<Self> {
        if v.canonical.len() > 4096 {
            return Err(invalid("admission request too large"));
        }
        let value: Self = crate::decode(&v.canonical)?;
        value.verify()?;
        Ok(value)
    }
}
impl Wire for InvitationMetadata {
    type Proto = pb::InvitationMetadata;
    const NAME: &'static str = "InvitationMetadata";
    fn to_proto(&self) -> Self::Proto {
        pb::InvitationMetadata {
            canonical: crate::encode(self).expect("bounded invitation metadata"),
        }
    }
    fn from_proto(v: &Self::Proto) -> Result<Self> {
        if v.canonical.len() > 2048 {
            return Err(invalid("invitation metadata too large"));
        }
        let value: Self = crate::decode(&v.canonical)?;
        value.validate()?;
        Ok(value)
    }
}
impl Wire for OneTimeInvitation {
    type Proto = pb::OneTimeInvitation;
    const NAME: &'static str = "OneTimeInvitation";
    fn to_proto(&self) -> Self::Proto {
        pb::OneTimeInvitation {
            metadata: Some(self.metadata.to_proto()),
            key: self.key.to_vec(),
        }
    }
    fn from_proto(v: &Self::Proto) -> Result<Self> {
        Ok(Self {
            metadata: InvitationMetadata::from_proto(required(&v.metadata)?)?,
            key: array32(&v.key)?,
        })
    }
}
