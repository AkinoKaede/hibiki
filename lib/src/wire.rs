//! Protobuf network codec. Do not use these bytes as a signing or hash preimage.
//! Postcard storage, invitations and v1 signed objects remain independently stable.
use crate::{Error, Result, assuan, e2ee, protocol::*};
use prost::Message;
use zeroize::{Zeroize, Zeroizing};

#[doc(hidden)]
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/hibiki.v2.rs"));
}
mod convert;
mod preflight;

/// Conversion between business values and the independently versioned wire schema.
pub trait Wire: Sized {
    type Proto;
    const LIMIT: usize = MAX_WIRE;
    const NAME: &'static str = "";
    fn to_proto(&self) -> Self::Proto;
    fn from_proto(value: &Self::Proto) -> Result<Self>;
    fn validate_wire(&self) -> Result<()> {
        Ok(())
    }
}

pub fn encode<T: Wire>(value: &T) -> Result<Vec<u8>>
where
    T::Proto: Message + Zeroize,
{
    Ok(encode_secret(value)?.to_vec())
}

/// Every temporary protobuf allocation and the exactly sized output are cleared.
pub fn encode_secret<T: Wire>(value: &T) -> Result<Zeroizing<Vec<u8>>>
where
    T::Proto: Message + Zeroize,
{
    value.validate_wire()?;
    let message = Zeroizing::new(value.to_proto());
    let size = message.encoded_len();
    if size > T::LIMIT {
        return Err(invalid("wire message too large"));
    }
    let mut output = Zeroizing::new(vec![0; size]);
    message
        .encode(&mut &mut output[..])
        .map_err(|e| invalid(e.to_string()))?;
    Ok(output)
}

pub fn decode<T: Wire>(bytes: &[u8]) -> Result<T>
where
    T::Proto: Message + Default + Zeroize,
{
    if bytes.len() > T::LIMIT {
        return Err(invalid("wire message too large"));
    }
    preflight::check(bytes, T::NAME)?;
    // merge into a guard: even a failed partial decode must clear secrets.
    let mut message = Zeroizing::new(T::Proto::default());
    message.merge(bytes).map_err(|e| invalid(e.to_string()))?;
    let value = T::from_proto(&message)?;
    value.validate_wire()?;
    Ok(value)
}

fn invalid(message: impl Into<String>) -> Error {
    Error::Invalid(message.into())
}
fn required<T>(value: &Option<T>) -> Result<&T> {
    value
        .as_ref()
        .ok_or_else(|| invalid("missing or unknown required message"))
}
fn array32(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| invalid("expected 32-byte key or digest"))
}
fn signature64(bytes: &[u8]) -> Result<()> {
    if bytes.len() != 64 {
        return Err(invalid("expected 64-byte signature"));
    }
    Ok(())
}
fn lines(values: &[assuan::Line]) -> Result<()> {
    if values.len() > assuan::MAX_LINES
        || values.iter().map(|line| line.len()).sum::<usize>() > assuan::MAX_DATA
    {
        return Err(invalid("Assuan batch limit"));
    }
    for line in values {
        assuan::framing(line)?;
    }
    Ok(())
}
fn input(value: &SessionInput) -> Result<()> {
    match value {
        SessionInput::PrepareCard { target, .. } => target.validate(),
        SessionInput::CancelPreparation { .. } => Ok(()),
        SessionInput::Execute {
            preparation, line, ..
        } => {
            lines(preparation)?;
            assuan::framing(line)
        }
        SessionInput::Command { line, .. } | SessionInput::InquiryReply { line, .. } => {
            assuan::framing(line)
        }
    }
}
fn validate_envelope(value: &Envelope) -> Result<()> {
    match value {
        Envelope::Hello { capabilities, .. }
        | Envelope::Authenticate { capabilities, .. }
        | Envelope::Authenticated { capabilities } => {
            normalize_capabilities(capabilities)?;
        }
        _ => {}
    }
    if let Envelope::Authenticate { signature, .. } = value {
        signature64(signature)?;
    }
    Ok(())
}
fn validate_private(value: &PrivateMessage) -> Result<()> {
    match value {
        PrivateMessage::PingOpen { capabilities, .. }
        | PrivateMessage::PingOpened { capabilities, .. }
        | PrivateMessage::OpenService { capabilities, .. }
        | PrivateMessage::ServiceOpened { capabilities, .. } => {
            normalize_capabilities(capabilities)?;
            Ok(())
        }
        PrivateMessage::Input(value) | PrivateMessage::Execute { input: value, .. } => input(value),
        PrivateMessage::Output(SessionOutput::Line { line, .. }) => assuan::framing(line),
        PrivateMessage::OutputBatch { lines: value, .. } => lines(value),
        _ => Ok(()),
    }
}
fn validate_fragment(value: &e2ee::Fragment) -> Result<()> {
    if value.bytes.is_empty() || value.bytes.len() > e2ee::CHUNK {
        return Err(invalid("fragment length"));
    }
    Ok(())
}

/// Baseline hibiki/2 needs no extension capabilities. Add names only with gated uses.
pub const PINENTRY_IGNORE: &str = "pinentry-ignore-v1";
pub const CAPABILITIES: &[&str] = &[];

/// Peer-only features are negotiated inside Noise, not by the relay.
pub fn supported_peer_capabilities() -> Vec<String> {
    vec![PINENTRY_IGNORE.into()]
}

/// Enforce peer extensions on both send and receive, independently of the relay.
pub fn validate_private_capabilities(
    message: &PrivateMessage,
    capabilities: &[String],
) -> Result<()> {
    if matches!(
        message,
        PrivateMessage::Output(SessionOutput::Ignored { .. })
    ) && !capabilities.iter().any(|value| value == PINENTRY_IGNORE)
    {
        return Err(invalid("pinentry ignore capability required"));
    }
    Ok(())
}
pub fn supported_capabilities() -> Vec<String> {
    CAPABILITIES
        .iter()
        .map(|value| (*value).to_owned())
        .collect()
}
pub fn normalize_capabilities(values: &[String]) -> Result<Vec<String>> {
    if values.len() > 64
        || values.iter().any(|value| {
            value.is_empty()
                || value.len() > 128
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
        })
    {
        return Err(invalid("invalid capability list"));
    }
    let mut values = values.to_vec();
    values.sort();
    values.dedup();
    Ok(values)
}
pub fn negotiate_capabilities(local: &[String], remote: &[String]) -> Result<Vec<String>> {
    let local = normalize_capabilities(local)?;
    let remote = normalize_capabilities(remote)?;
    Ok(local
        .into_iter()
        .filter(|value| remote.binary_search(value).is_ok())
        .collect())
}
pub fn validate_negotiated(offered: &[String], selected: &[String]) -> Result<Vec<String>> {
    let selected = normalize_capabilities(selected)?;
    if negotiate_capabilities(offered, &selected)? != selected {
        return Err(invalid("unoffered capability selected"));
    }
    Ok(selected)
}
/// The original authentication context plus both normalized capability declarations.
pub type AuthenticationBody = (String, String, String, Vec<String>, Vec<String>);

pub fn authentication_body(
    version: &str,
    nonce: &str,
    device: &str,
    server: &[String],
    client: &[String],
) -> Result<AuthenticationBody> {
    Ok((
        version.into(),
        nonce.into(),
        device.into(),
        normalize_capabilities(server)?,
        normalize_capabilities(client)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fragments_enforce_chunk_limits_and_clear_their_generated_payload() {
        for size in [1, e2ee::CHUNK - 1, e2ee::CHUNK] {
            let value = e2ee::Fragment {
                last: true,
                bytes: vec![7; size],
            };
            let bytes = encode_secret(&value).unwrap();
            let decoded: e2ee::Fragment = decode(&bytes).unwrap();
            assert!(decoded.last);
            assert_eq!(decoded.bytes, value.bytes);
        }
        for size in [0, e2ee::CHUNK + 1] {
            let value = e2ee::Fragment {
                last: true,
                bytes: vec![7; size],
            };
            assert!(encode_secret(&value).is_err());
            assert!(decode::<e2ee::Fragment>(&value.to_proto().encode_to_vec()).is_err());
        }
    }
}
