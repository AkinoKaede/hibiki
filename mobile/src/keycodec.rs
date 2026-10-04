//! GnuPG canonical public-key expressions and libgcrypt-compatible SHA-1 keygrips.
use crate::types::CardKey;
use anyhow::{Result, bail};
use openpgp_card::ocard::{
    algorithm::{AlgorithmAttributes, Curve},
    crypto::PublicKeyMaterial,
};
use sha1::{Digest, Sha1};

fn atom(value: &[u8]) -> Vec<u8> {
    let mut out = format!("{}:", value.len()).into_bytes();
    out.extend(value);
    out
}
fn field(name: &str, value: &[u8]) -> Vec<u8> {
    let mut out = vec![b'('];
    out.extend(atom(name.as_bytes()));
    out.extend(atom(value));
    out.push(b')');
    out
}
fn mpi(bytes: &[u8]) -> Vec<u8> {
    let bytes = &bytes[bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len().saturating_sub(1))..];
    let mut out = Vec::new();
    if bytes.first().is_some_and(|b| b & 128 != 0) {
        out.push(0);
    }
    out.extend(bytes);
    out
}
pub fn encode(
    material: PublicKeyMaterial,
    slot: u8,
    fingerprint: String,
    created_at: u32,
) -> Result<CardKey> {
    let mut expression = b"(10:public-key(".to_vec();
    let (algorithm, grip) = match material {
        PublicKeyMaterial::R(rsa) => {
            if !matches!(rsa.n().len(), 256 | 384 | 512) || rsa.v().is_empty() {
                bail!("unsupported RSA key size");
            }
            let n = mpi(rsa.n());
            let e = mpi(rsa.v());
            expression.extend(b"3:rsa");
            expression.extend(field("n", &n));
            expression.extend(field("e", &e));
            (
                format!("rsa{}", rsa.n().len() * 8),
                Sha1::digest(&n).to_vec(),
            )
        }
        PublicKeyMaterial::E(ecc) => {
            let AlgorithmAttributes::Ecc(attrs) = ecc.algo() else {
                bail!("invalid ECC attributes");
            };
            let (name, algorithm, width) = match attrs.curve() {
                Curve::Ed25519 => ("Ed25519", "ed25519", 32),
                Curve::Curve25519 => ("Curve25519", "cv25519", 32),
                Curve::NistP256r1 => ("NIST P-256", "nistp256", 32),
                Curve::NistP384r1 => ("NIST P-384", "nistp384", 48),
                Curve::NistP521r1 => ("NIST P-521", "nistp521", 66),
                _ => bail!("unsupported card curve"),
            };
            let compact = name == "Ed25519" || name == "Curve25519";
            let raw = ecc.data();
            let q = if compact {
                let raw = if raw.len() == 33 && raw[0] == 0x40 {
                    &raw[1..]
                } else {
                    raw
                };
                if raw.len() != 32 {
                    bail!("invalid Curve25519 public key");
                }
                [vec![0x40], raw.to_vec()].concat()
            } else {
                if raw.len() != 1 + 2 * width || raw[0] != 4 {
                    bail!("invalid uncompressed public point");
                }
                raw.to_vec()
            };
            expression.extend(b"3:ecc");
            expression.extend(field("curve", name.as_bytes()));
            if compact {
                expression.extend(field(
                    "flags",
                    if name == "Ed25519" {
                        b"eddsa"
                    } else {
                        b"djb-tweak"
                    },
                ));
            }
            expression.extend(field("q", &q));
            let mut hash = Sha1::new();
            for (label, value) in ["p", "a", "b", "g", "n"]
                .iter()
                .zip(crate::curves::parameters(name).unwrap())
            {
                hash.update(field(label, &hex::decode(value)?));
            }
            hash.update(field("q", if compact { &q[1..] } else { &q }));
            (algorithm.into(), hash.finalize().to_vec())
        }
    };
    expression.extend(b"))");
    Ok(CardKey {
        slot,
        algorithm,
        fingerprint,
        keygrip: hex::encode_upper(grip),
        public_key: expression,
        created_at,
    })
}

/// GnuPG sends DigestInfo for RSA and may send it for ECC too. Strip only a verified prefix.
pub fn signing_data(algorithm: &str, hash: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    let (prefix, size) = match hash {
        "sha1" => ("3021300906052b0e03021a05000414", 20),
        "rmd160" => ("3021300906052b2403020105000414", 20),
        "sha224" => ("302d300d06096086480165030402040500041c", 28),
        "sha256" => ("3031300d060960864801650304020105000420", 32),
        "sha384" => ("3041300d060960864801650304020205000430", 48),
        "sha512" => ("3051300d060960864801650304020305000440", 64),
        _ => bail!("unsupported digest algorithm"),
    };
    let prefix = hex::decode(prefix)?;
    let digest = if bytes.len() == size {
        bytes
    } else if bytes.len() == prefix.len() + size && bytes.starts_with(&prefix) {
        &bytes[prefix.len()..]
    } else {
        bail!("digest size or prefix mismatch");
    };
    if algorithm.starts_with("rsa") {
        Ok([prefix, digest.to_vec()].concat())
    } else {
        Ok(digest.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openpgp_card::ocard::{
        algorithm::EccAttributes,
        crypto::{EccPub, EccType, RSAPub},
    };
    #[test]
    fn all_supported_algorithms_match_independent_libgcrypt_keygrips() {
        let vectors: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("../tests/fixtures/keygrips.json")).unwrap();
        for v in vectors {
            let name = v["algorithm"].as_str().unwrap();
            let key = if name.starts_with("rsa") {
                PublicKeyMaterial::R(RSAPub::new(
                    hex::decode(v["n"].as_str().unwrap()).unwrap(),
                    hex::decode(v["e"].as_str().unwrap()).unwrap(),
                ))
            } else {
                let curve = match name {
                    "ed25519" => Curve::Ed25519,
                    "cv25519" => Curve::Curve25519,
                    "nistp256" => Curve::NistP256r1,
                    "nistp384" => Curve::NistP384r1,
                    _ => Curve::NistP521r1,
                };
                let kind = if name == "ed25519" {
                    EccType::EdDSA
                } else if name == "cv25519" {
                    EccType::ECDH
                } else {
                    EccType::ECDSA
                };
                PublicKeyMaterial::E(EccPub::new(
                    hex::decode(v["q"].as_str().unwrap()).unwrap(),
                    AlgorithmAttributes::Ecc(EccAttributes::new(kind, curve, None)),
                ))
            };
            let result = encode(key, 1, String::new(), 0).unwrap();
            assert_eq!(result.keygrip, v["keygrip"].as_str().unwrap(), "{name}");
            assert_eq!(result.algorithm, name);
        }
    }
    #[test]
    fn digest_info_is_validated_not_blindly_stripped() {
        let digest = vec![42; 32];
        let encoded = signing_data("rsa2048", "sha256", &digest).unwrap();
        assert_eq!(
            signing_data("nistp256", "sha256", &encoded).unwrap(),
            digest
        );
        assert!(signing_data("rsa2048", "sha512", &digest).is_err());
        let mut corrupt = encoded;
        corrupt[2] ^= 1;
        assert!(signing_data("ed25519", "sha256", &corrupt).is_err());
    }
}
