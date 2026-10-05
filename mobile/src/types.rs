use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MobileError {
    #[error("request canceled")]
    Cancelled,
    #[error("{message}")]
    Failed { message: String },
}
impl From<anyhow::Error> for MobileError {
    fn from(value: anyhow::Error) -> Self {
        if value.is::<crate::broker::RequestCancelled>() {
            return Self::Cancelled;
        }
        Self::Failed {
            message: value.to_string(),
        }
    }
}
pub type MobileResult<T> = Result<T, MobileError>;

#[derive(Clone, Debug, uniffi::Record)]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    pub words: String,
    pub online: bool,
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct ChannelInfo {
    pub id: String,
    pub name: String,
    pub active: bool,
    pub revision: u64,
    pub members: Vec<DeviceInfo>,
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct PendingInfo {
    pub id: String,
    pub channel: String,
    pub device: DeviceInfo,
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct Invitation {
    pub channel: String,
    pub invite: String,
    pub psk: String,
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct JoinInfo {
    pub channel: String,
    pub request: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PairingState {
    Pending,
    Member,
    Absent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, uniffi::Enum)]
pub enum CardTransport {
    Usb,
    Nfc,
}
#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct CardKey {
    pub slot: u8,
    pub algorithm: String,
    pub fingerprint: String,
    pub keygrip: String,
    pub public_key: Vec<u8>,
    pub created_at: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct CardInfo {
    pub serial: String,
    pub transport: CardTransport,
    pub keys: Vec<CardKey>,
}
#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct RegisteredCard {
    pub card: CardInfo,
    pub name: String,
    pub usb_enabled: bool,
    pub nfc_enabled: bool,
}
#[derive(Clone, Debug, uniffi::Enum)]
pub enum PromptKind {
    Pin,
    Confirm,
    Message,
    CardUsb,
    CardNfc,
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct PinPrompt {
    pub token: String,
    pub session: String,
    pub request: u64,
    pub channel: String,
    pub device_name: String,
    pub device_id: String,
    pub kind: PromptKind,
    pub title: String,
    pub description: String,
    pub label: String,
    pub error: String,
    pub repeat: String,
    pub repeat_error: String,
    pub ok: String,
    pub cancel: String,
    pub not_ok: String,
    pub timeout_seconds: u32,
}
#[derive(Clone, uniffi::Enum)]
#[allow(clippy::large_enum_variant)] // Bounded typed FFI event; UniFFI records are passed by value.
pub enum NativeEvent {
    Connection {
        state: String,
    },
    Prompt {
        prompt: PinPrompt,
    },
    Cancelled {
        token: String,
    },
    CardOpen {
        token: String,
        connection: String,
        transport: CardTransport,
    },
    CardTransmit {
        token: String,
        connection: String,
        command: Vec<u8>,
    },
    CardClose {
        connection: String,
    },
    CardChanged {
        card: CardInfo,
    },
}
