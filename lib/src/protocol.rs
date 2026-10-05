use crate::{assuan::Line, channel::*, identity::Device};
use serde::{Deserialize, Serialize};

/// Hibiki wire protocol identifier, authenticated by the device and bound into Noise.
pub const VERSION: &str = "hibiki/2";
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
    ChannelSnapshot {
        channel: String,
    },
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
    ChannelSnapshot {
        proof: MembershipProof,
        online: Vec<String>,
        revoked: Vec<String>,
    },
    Requests(Vec<JoinRequest>),
    Peers(Vec<String>),
    Policy {
        allow_client_channel_creation: bool,
    },
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
        capabilities: Vec<String>,
    },
    Authenticate {
        device: Device,
        signature: Vec<u8>,
        capabilities: Vec<String>,
    },
    Authenticated {
        capabilities: Vec<String>,
    },
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
    PeerOnline {
        peer: String,
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
    PrepareCard {
        id: String,
        target: CardTarget,
    },
    CancelPreparation {
        id: String,
    },
    Execute {
        request: u64,
        preparation: Vec<Line>,
        line: Line,
    },
    Command {
        request: u64,
        line: Line,
    },
    InquiryReply {
        request: u64,
        line: Line,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SessionOutput {
    CardStatus { id: String, state: CardPreparation },
    Line { request: u64, line: Line },
    Failure,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)] // The trust proof is bounded and exchanged only at setup.
pub enum PrivateMessage {
    PingOpen {
        proof: MembershipProof,
        capabilities: Vec<String>,
    },
    PingOpened {
        proof: MembershipProof,
        capabilities: Vec<String>,
    },
    Ping {
        nonce: String,
    },
    Pong {
        nonce: String,
    },
    OpenService {
        proof: MembershipProof,
        service: ServiceKind,
        capabilities: Vec<String>,
    },
    ServiceOpened {
        proof: MembershipProof,
        enabled: bool,
        capabilities: Vec<String>,
    },
    Execute {
        id: String,
        input: SessionInput,
    },
    Input(SessionInput),
    Output(SessionOutput),
    OutputBatch {
        request: u64,
        lines: Vec<Line>,
    },
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

/// Selection identity, never private command data or a PIN.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CardTarget {
    pub serial: Option<String>,
    pub key: Option<String>,
}
impl CardTarget {
    pub fn validate(&self) -> crate::Result<()> {
        for value in [&self.serial, &self.key].into_iter().flatten() {
            if value.is_empty()
                || value.len() > 256
                || !value
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"./".contains(&c))
            {
                return Err(crate::Error::Invalid("invalid card identity".into()));
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CardPreparation {
    Waiting,
    Ready { serial: String },
    Unavailable,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PingReport {
    pub peer: String,
    pub setup_micros: u64,
    pub round_trips_micros: Vec<Option<u64>>,
}
