/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

use crate::{Error, Result, encode, identity::Identity, protocol::VERSION, wire};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
pub const CHUNK: usize = 48 * 1024;
pub const MAX_PAYLOAD: usize = 2 * 1024 * 1024;

pub struct Handshake {
    inner: snow::HandshakeState,
    expected: [u8; 32],
}
impl Handshake {
    pub fn new(
        identity: &Identity,
        channel: &str,
        initiator_id: &str,
        responder_id: &str,
        session: &str,
        expected: [u8; 32],
        initiator: bool,
    ) -> Result<Self> {
        let prologue = encode(&(
            VERSION,
            "e2ee",
            channel,
            initiator_id,
            responder_id,
            session,
        ))?;
        let builder = snow::Builder::new(PARAMS.parse().unwrap())
            .local_private_key(identity.noise_secret())
            .map_err(|e| Error::Crypto(e.to_string()))?
            .prologue(&prologue)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let inner = if initiator {
            builder.build_initiator()
        } else {
            builder.build_responder()
        }
        .map_err(|e| Error::Crypto(e.to_string()))?;
        Ok(Self { inner, expected })
    }
    pub fn write(&mut self) -> Result<Vec<u8>> {
        let mut out = vec![0; 65535];
        let n = self
            .inner
            .write_message(&[], &mut out)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        out.truncate(n);
        Ok(out)
    }
    pub fn read(&mut self, bytes: &[u8]) -> Result<()> {
        let mut out = vec![0; 65535];
        let n = self
            .inner
            .read_message(bytes, &mut out)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        if n != 0 {
            return Err(Error::Invalid("unexpected handshake payload".into()));
        }
        if let Some(key) = self.inner.get_remote_static()
            && key != self.expected
        {
            return Err(Error::Crypto(
                "Noise key does not match the membership certificate".into(),
            ));
        }
        Ok(())
    }
    pub fn finish(self) -> Result<Transport> {
        if self.inner.get_remote_static() != Some(self.expected.as_slice()) {
            return Err(Error::Crypto("missing peer identity".into()));
        }
        Ok(Transport {
            inner: self
                .inner
                .into_transport_mode()
                .map_err(|e| Error::Crypto(e.to_string()))?,
            pending: Vec::new(),
        })
    }
}
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct Fragment {
    pub(crate) last: bool,
    pub(crate) bytes: Vec<u8>,
}

pub struct Transport {
    inner: snow::TransportState,
    pending: Vec<u8>,
}
impl Transport {
    pub fn encrypt(&mut self, payload: &[u8]) -> Result<Vec<Vec<u8>>> {
        if payload.is_empty() || payload.len() > MAX_PAYLOAD {
            return Err(Error::Invalid("encrypted payload length".into()));
        }
        let count = payload.len().div_ceil(CHUNK);
        payload
            .chunks(CHUNK)
            .enumerate()
            .map(|(i, chunk)| {
                let input = wire::encode_secret(&Fragment {
                    last: i + 1 == count,
                    bytes: chunk.to_vec(),
                })?;
                let mut out = vec![0; input.len() + 16];
                let n = self
                    .inner
                    .write_message(&input, &mut out)
                    .map_err(|e| Error::Crypto(e.to_string()))?;
                out.truncate(n);
                Ok(out)
            })
            .collect()
    }
    pub fn decrypt(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>> {
        if packet.len() > 65535 {
            return Err(Error::Invalid("Noise packet too large".into()));
        }
        let mut out = Zeroizing::new(vec![0; packet.len()]);
        let n = self
            .inner
            .read_message(packet, &mut out)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let part: Fragment = wire::decode(&out[..n])?;
        if part.bytes.len() > CHUNK || self.pending.len() + part.bytes.len() > MAX_PAYLOAD {
            return Err(Error::Invalid("reassembly limit".into()));
        }
        if self.pending.len() + part.bytes.len() > self.pending.capacity() {
            let mut grown =
                Vec::with_capacity((self.pending.len() + part.bytes.len()).next_power_of_two());
            grown.extend_from_slice(&self.pending);
            self.pending.zeroize();
            self.pending = grown;
        }
        self.pending.extend_from_slice(&part.bytes);
        Ok(part.last.then(|| std::mem::take(&mut self.pending)))
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        self.pending.zeroize();
    }
}
