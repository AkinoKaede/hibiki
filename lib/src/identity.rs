/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

use crate::{Error, Result, digest, encode};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Device {
    pub name: String,
    pub signing_key: [u8; 32],
    pub noise_key: [u8; 32],
    pub binding: Vec<u8>,
}

impl Device {
    pub fn id(&self) -> String {
        hex::encode(digest(&self.signing_key))
    }

    /// Lossless BIP39 encoding of the public Ed25519 key, not a private seed.
    pub fn public_key_words(&self) -> Result<String> {
        self.verify()?;
        bip39::Mnemonic::from_entropy_in(bip39::Language::English, &self.signing_key)
            .map(|words| words.to_string())
            .map_err(|e| Error::Invalid(e.to_string()))
    }

    pub fn verify(&self) -> Result<()> {
        if self.name.is_empty() || self.name.len() > 128 {
            return Err(Error::Invalid("device name length".into()));
        }
        verify(
            &self.signing_key,
            "device/v1",
            &(&self.name, self.signing_key, self.noise_key),
            &self.binding,
        )
    }
}

#[derive(Serialize, Deserialize)]
pub struct Identity {
    signing_secret: [u8; 32],
    noise_secret: [u8; 32],
    pub device: Device,
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.signing_secret.zeroize();
        self.noise_secret.zeroize();
    }
}

impl Identity {
    pub fn generate(name: String) -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| Error::Crypto(e.to_string()))?;
        let signing = SigningKey::from_bytes(&seed);
        seed.zeroize();
        let keys = snow::Builder::new(crate::e2ee::PARAMS.parse().unwrap())
            .generate_keypair()
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let mut device = Device {
            name,
            signing_key: signing.verifying_key().to_bytes(),
            noise_key: keys
                .public
                .try_into()
                .map_err(|_| Error::Invalid("Noise key length".into()))?,
            binding: vec![],
        };
        device.binding = sign(
            &signing,
            "device/v1",
            &(&device.name, device.signing_key, device.noise_key),
        )?;
        device.verify()?;
        Ok(Self {
            signing_secret: signing.to_bytes(),
            noise_secret: keys
                .private
                .try_into()
                .map_err(|_| Error::Invalid("Noise key length".into()))?,
            device,
        })
    }

    /// Re-sign the display name without changing either key or the stable ID.
    pub fn renamed(&self, name: String) -> Result<Self> {
        let mut device = self.device.clone();
        device.name = name;
        device.binding = self.sign(
            "device/v1",
            &(&device.name, device.signing_key, device.noise_key),
        )?;
        device.verify()?;
        Ok(Self {
            signing_secret: self.signing_secret,
            noise_secret: self.noise_secret,
            device,
        })
    }
    pub fn validate(&self) -> Result<()> {
        self.device.verify()?;
        if SigningKey::from_bytes(&self.signing_secret)
            .verifying_key()
            .to_bytes()
            != self.device.signing_key
        {
            return Err(Error::Crypto("identity secret/public mismatch".into()));
        }
        // Noise also checks static key possession during the handshake.
        Ok(())
    }

    pub fn sign<T: Serialize>(&self, domain: &str, body: &T) -> Result<Vec<u8>> {
        sign(&SigningKey::from_bytes(&self.signing_secret), domain, body)
    }

    pub fn noise_secret(&self) -> &[u8; 32] {
        &self.noise_secret
    }
}

fn signed_bytes<T: Serialize>(domain: &str, body: &T) -> Result<Vec<u8>> {
    encode(&("hibiki", 1u16, domain, body))
}

fn sign<T: Serialize>(key: &SigningKey, domain: &str, body: &T) -> Result<Vec<u8>> {
    Ok(key.sign(&signed_bytes(domain, body)?).to_bytes().to_vec())
}

pub fn verify<T: Serialize>(
    key: &[u8; 32],
    domain: &str,
    body: &T,
    signature: &[u8],
) -> Result<()> {
    let key = VerifyingKey::from_bytes(key).map_err(|e| Error::Crypto(e.to_string()))?;
    let signature = Signature::from_slice(signature).map_err(|e| Error::Crypto(e.to_string()))?;
    key.verify_strict(&signed_bytes(domain, body)?, &signature)
        .map_err(|_| Error::Crypto("invalid signature".into()))
}
