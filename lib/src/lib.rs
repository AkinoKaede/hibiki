//! Shared wire formats and pure verification logic. No sockets, processes or databases.
pub mod assuan;
pub mod channel;
pub mod e2ee;
pub mod identity;
pub mod invitation;
pub mod paths;
pub mod protocol;
pub mod qr;
pub mod selection;
pub mod wire;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid data: {0}")]
    Invalid(String),
    #[error("cryptographic verification failed: {0}")]
    Crypto(String),
    #[error("trust rollback or fork detected")]
    Fork,
    #[error("not an active member")]
    NotMember,
    #[error("unsupported operation: {0}")]
    Unsupported(String),
}

pub fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    postcard::to_allocvec(value).map_err(|e| Error::Invalid(e.to_string()))
}

/// Serialize private frames without reallocating a buffer containing secrets.
pub fn encode_secret<T: serde::Serialize>(value: &T) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let size = postcard::experimental::serialized_size(value)
        .map_err(|e| Error::Invalid(e.to_string()))?;
    let mut bytes = zeroize::Zeroizing::new(vec![0; size]);
    postcard::to_slice(value, &mut bytes).map_err(|e| Error::Invalid(e.to_string()))?;
    Ok(bytes)
}

pub fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let (value, rest) =
        postcard::take_from_bytes(bytes).map_err(|e| Error::Invalid(e.to_string()))?;
    if !rest.is_empty() {
        return Err(Error::Invalid("trailing bytes".into()));
    }
    Ok(value)
}

pub fn digest(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).into()
}

pub fn random_id() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("operating-system random source unavailable");
    hex::encode(b)
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub mod card_prompt;
