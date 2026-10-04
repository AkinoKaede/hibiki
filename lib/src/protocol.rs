use crate::{assuan::Line, channel::*, identity::Device};
use serde::{Deserialize, Serialize};

/// Hibiki wire protocol identifier, authenticated by the device and bound into Noise.
pub const VERSION: &str = "hibiki/1";
pub const WS_PATH: &str = "/hibiki";
pub const MAX_WIRE: usize = 4 * 1024 * 1024;
/// An hour of caller time plus less than a second of wire timestamp rounding.
pub const MAX_OPERATION_TTL: u64 = 3601;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireError {
    pub code: String,
    pub message: String,
}
impl WireError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}
impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for WireError {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Control {
    Queue {
        operation: Operation,
    },
    ResumeOperation {
        id: String,
    },
    OperationStatus {
        id: String,
    },
    ClaimOperation {
        id: String,
        initiator: String,
        channel: String,
        service: ServiceKind,
    },
    TargetDone {
        id: String,
        success: bool,
    },
    AbandonTarget {
        id: String,
        peer: String,
    },
    EndOperation {
        id: String,
        completed: bool,
    },
    Create {
        genesis: ChannelGenesis,
        verifier: String,
    },
    GetChannel {
        channel: String,
    },
    ListChannels,
    Join {
        request: JoinRequest,
        psk: String,
    },
    Pending {
        channel: String,
    },
    Append {
        event: MembershipEvent,
        verifier: Option<String>,
    },
    Announce {
        channels: Vec<String>,
    },
    Peers {
        channel: String,
    },
    Claim {
        genesis: ChannelGenesis,
        psk: String,
    },
    Policy,
    RejectJoin {
        channel: String,
        request: String,
    },
    WithdrawJoin {
        channel: String,
        request: String,
    },
    JoinStatus {
        channel: String,
        request: String,
    },
    /// Withdraw all of the caller's pending requests and return the current proof.
    WithdrawPending {
        channel: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)] // Bounded, serialized wire value.
pub enum Reply {
    Operation(Operation),
    Ok,
    Proof(MembershipProof),
    Proofs(Vec<MembershipProof>),
    Requests(Vec<JoinRequest>),
    Peers(Vec<String>),
    Policy { allow_client_channel_creation: bool },
    JoinStatus(JoinState),
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum JoinState {
    Pending,
    Member,
    Absent,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Envelope {
    OperationReady {
        id: String,
        peer: String,
    },
    OperationChanged {
        id: String,
    },
    Hello {
        version: String,
        nonce: String,
    },
    Authenticate {
        device: Device,
        signature: Vec<u8>,
    },
    Authenticated,
    Request {
        id: String,
        command: Control,
    },
    Response {
        id: String,
        result: std::result::Result<Reply, WireError>,
    },
    Relay {
        channel: String,
        peer: String,
        session: String,
        data: Vec<u8>,
    },
    RelayFailure {
        session: String,
        peer: String,
        error: WireError,
    },
    ChannelChanged {
        channel: String,
    },
    PeerOffline {
        peer: String,
    },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ServiceKind {
    Scdaemon,
    Pinentry,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SessionInput {
    Command { request: u64, line: Line },
    InquiryReply { request: u64, line: Line },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SessionOutput {
    Line { request: u64, line: Line },
    Failure,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)] // The trust proof is bounded and exchanged only at setup.
pub enum PrivateMessage {
    BeginOperation { id: String },
    OperationBegun,
    Trust(MembershipProof),
    Discover,
    Capabilities { scdaemon: bool, pinentry: bool },
    Open { service: ServiceKind },
    Opened,
    Input(SessionInput),
    Output(SessionOutput),
    Close,
    Closed,
    Failure,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum OperationState {
    Pending,
    Completed,
    Canceled,
    Expired,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TargetState {
    Pending,
    Executing,
    Succeeded,
    Failed,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperationTarget {
    pub device: String,
    pub state: TargetState,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Operation {
    pub id: String,
    pub channel: String,
    pub initiator: String,
    pub service: ServiceKind,
    pub deadline: u64,
    pub state: OperationState,
    pub targets: Vec<OperationTarget>,
}
