use crate::{
    broker::Broker,
    card_backend::NativeCard,
    keycodec,
    types::{CardInfo, CardKey, CardTransport},
};
use anyhow::{Context, Result, bail};
use hibiki_lib::assuan::{self, AssuanResult};
use openpgp_card::ocard::{KeyType, OpenPGP, Transaction, crypto::Cryptogram};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

pub fn snapshot(tx: &mut Transaction<'_>, transport: CardTransport) -> Result<CardInfo> {
    let data = tx.application_related_data()?;
    let aid = data.application_id()?;
    let serial = format!(
        "D276000124{:02X}{:04X}{:04X}{:08X}0000",
        aid.application(),
        aid.version(),
        aid.manufacturer(),
        aid.serial()
    );
    let prints = data.fingerprints()?;
    let times = data.key_generation_times()?;
    let mut keys = Vec::new();
    for (slot, kind, print, time) in [
        (1, KeyType::Signing, prints.signature(), times.signature()),
        (
            2,
            KeyType::Decryption,
            prints.decryption(),
            times.decryption(),
        ),
        (
            3,
            KeyType::Authentication,
            prints.authentication(),
            times.authentication(),
        ),
    ] {
        if let Some(print) = print {
            keys.push(keycodec::encode(
                tx.public_key(kind)?,
                slot,
                print.to_hex().to_uppercase(),
                time.map(|t| t.get()).unwrap_or(0),
            )?);
        }
    }
    Ok(CardInfo {
        serial,
        transport,
        keys,
    })
}
pub fn inspect(
    broker: Arc<Broker>,
    stop: CancellationToken,
    transport: CardTransport,
) -> Result<CardInfo> {
    let backend = NativeCard::open(broker, stop, transport.clone())?;
    let mut card =
        OpenPGP::new(Box::new(backend) as Box<dyn card_backend::CardBackend + Send + Sync>)?;
    snapshot(&mut card.transaction()?, transport)
}
fn ok_data(data: &[u8]) -> AssuanResult {
    let mut lines = assuan::data_lines(data);
    lines.push("OK".into());
    AssuanResult { lines }
}
fn ok_status(lines: impl IntoIterator<Item = String>) -> AssuanResult {
    let mut lines: Vec<_> = lines
        .into_iter()
        .map(|s| format!("S {s}").as_str().into())
        .collect();
    lines.push("OK".into());
    AssuanResult { lines }
}
fn algorithm_number(key: &CardKey) -> u8 {
    if key.algorithm.starts_with("rsa") {
        1
    } else if key.algorithm == "ed25519" {
        22
    } else if key.slot == 2 {
        18
    } else {
        19
    }
}
pub struct CardSession {
    pub info: CardInfo,
    data: Zeroizing<Vec<u8>>,
}
impl CardSession {
    pub fn new(info: CardInfo) -> Self {
        Self {
            info,
            data: Zeroizing::new(Vec::new()),
        }
    }
    fn key(&self, selector: &str) -> Result<CardKey> {
        self.info
            .keys
            .iter()
            .find(|k| {
                selector.eq_ignore_ascii_case(&k.keygrip)
                    || selector == format!("OPENPGP.{}", k.slot)
                    || (selector.starts_with(&self.info.serial)
                        && selector
                            .strip_prefix(&self.info.serial)
                            .is_some_and(|suffix| suffix == format!("/{}", k.fingerprint)))
            })
            .cloned()
            .context("card key not found")
    }
    fn attributes(&self) -> Vec<String> {
        let mut out = vec![
            format!("SERIALNO {}", self.info.serial),
            "APPTYPE OPENPGP".into(),
            "EXTCAP ki=1 aac=1".into(),
        ];
        for key in &self.info.keys {
            let usage = match key.slot {
                1 => "s",
                2 => "e",
                _ => "a",
            };
            out.extend([
                format!(
                    "KEYPAIRINFO {} OPENPGP.{} {usage} {} {}",
                    key.keygrip, key.slot, key.created_at, key.algorithm
                ),
                format!("KEY-FPR {} {}", key.slot, key.fingerprint),
                format!("KEY-TIME {} {}", key.slot, key.created_at),
                format!(
                    "KEY-ATTR {} {} {}",
                    key.slot,
                    algorithm_number(key),
                    key.algorithm
                ),
            ]);
        }
        out
    }
    pub fn command(&mut self, line: &[u8]) -> Result<AssuanResult> {
        let (cmd, args) = assuan::command(line)?;
        match cmd {
            "RESET" | "RESTART" => {
                self.data.zeroize();
                Ok(AssuanResult::ok())
            }
            "NOP" | "BYE" | "SWITCHAPP" => Ok(AssuanResult::ok()),
            "SETDATA" => {
                let (append, data) = args
                    .strip_prefix("--append ")
                    .map(|v| (true, v))
                    .unwrap_or((false, args));
                let mut decoded = Zeroizing::new(hex::decode(data)?);
                if !append {
                    self.data.zeroize();
                }
                if self.data.len() + decoded.len() > assuan::MAX_DATA {
                    bail!("SETDATA limit");
                }
                // Reserve the full bounded buffer once to avoid reallocating secrets.
                if self.data.capacity() < assuan::MAX_DATA {
                    self.data = Zeroizing::new(Vec::with_capacity(assuan::MAX_DATA));
                }
                self.data.append(&mut decoded);
                Ok(AssuanResult::ok())
            }
            "SERIALNO" | "SWITCHCARD" => {
                let demand = args
                    .split_ascii_whitespace()
                    .find_map(|a| a.strip_prefix("--demand="))
                    .or_else(|| {
                        if cmd == "SWITCHCARD" && !args.is_empty() {
                            Some(args)
                        } else {
                            None
                        }
                    });
                if demand.is_some_and(|s| !s.eq_ignore_ascii_case(&self.info.serial)) {
                    return Ok(AssuanResult::error(108, "card not present"));
                }
                Ok(ok_status([format!("SERIALNO {}", self.info.serial)]))
            }
            "LEARN" => {
                if args.split_ascii_whitespace().any(|a| {
                    a.strip_prefix("--demand=")
                        .is_some_and(|s| !s.eq_ignore_ascii_case(&self.info.serial))
                        || (a.len() == 40 && self.key(a).is_err())
                }) {
                    return Ok(AssuanResult::error(108, "card does not match"));
                }
                Ok(ok_status(self.attributes()))
            }
            "GETATTR" => {
                let prefix = format!("{args} ");
                let fields: Vec<_> = self
                    .attributes()
                    .into_iter()
                    .filter(|s| s.starts_with(&prefix))
                    .collect();
                if fields.is_empty() {
                    Ok(AssuanResult::error(
                        assuan::NO_DATA,
                        "attribute not available in public snapshot",
                    ))
                } else {
                    Ok(ok_status(fields))
                }
            }
            "READKEY" => {
                let key = self.key(args.split_ascii_whitespace().last().unwrap_or_default())?;
                let mut result = if args.split_ascii_whitespace().any(|s| s == "--info-only") {
                    AssuanResult::ok()
                } else {
                    ok_data(&key.public_key)
                };
                if args
                    .split_ascii_whitespace()
                    .any(|s| matches!(s, "--info" | "--info-only"))
                {
                    result.lines.insert(
                        0,
                        format!("S KEYPAIRINFO {} OPENPGP.{}", key.keygrip, key.slot)
                            .as_str()
                            .into(),
                    );
                }
                if args.contains("advanced") {
                    return Ok(AssuanResult::error(
                        assuan::NOT_SUPPORTED,
                        "use canonical public-key format",
                    ));
                }
                Ok(result)
            }
            "KEYINFO" => {
                let keys = if args.contains("--list") {
                    self.info.keys.clone()
                } else {
                    vec![self.key(args.split_ascii_whitespace().last().unwrap_or_default())?]
                };
                let filter = if args.contains("--list=auth") {
                    Some(3)
                } else if args.contains("--list=encr") {
                    Some(2)
                } else if args.contains("--list=sign") {
                    Some(1)
                } else {
                    None
                };
                let records: Vec<_> = keys
                    .iter()
                    .filter(|k| filter.is_none_or(|slot| slot == k.slot))
                    .map(|k| {
                        format!(
                            "{} T {} OPENPGP.{} {}",
                            k.keygrip,
                            self.info.serial,
                            k.slot,
                            match k.slot {
                                1 => "s",
                                2 => "e",
                                _ => "a",
                            }
                        )
                    })
                    .collect();
                if args.contains("--data") {
                    Ok(ok_data(format!("{}\n", records.join("\n")).as_bytes()))
                } else {
                    Ok(ok_status(
                        records.into_iter().map(|s| format!("KEYINFO {s}")),
                    ))
                }
            }
            "GETINFO" => Ok(match args {
                "version" => ok_data(b"2.4.0"),
                "app_list" => ok_data(b"openpgp:\n"),
                "reader_list" => ok_data(b"HIbiki iOS\n"),
                "deny_admin" => AssuanResult::ok(),
                "card_list" => ok_status([format!("SERIALNO {}", self.info.serial)]),
                "status" => ok_data(b"u"),
                "active_apps" | "all_active_apps" => ok_status([
                    format!("SERIALNO {}", self.info.serial),
                    "APPTYPE OPENPGP".into(),
                ]),
                _ => AssuanResult::error(assuan::NO_DATA, "information unavailable"),
            }),
            _ => Ok(AssuanResult::error(
                assuan::NOT_SUPPORTED,
                "unsupported card command",
            )),
        }
    }
    pub fn private_key(&self, cmd: &str, args: &str) -> Result<CardKey> {
        let selector = args
            .split_ascii_whitespace()
            .last()
            .context("missing key")?;
        let key = if selector == self.info.serial {
            self.info
                .keys
                .iter()
                .find(|k| k.slot == if cmd == "PKDECRYPT" { 2 } else { 1 })
                .cloned()
                .context("missing key")?
        } else {
            self.key(selector)?
        };
        if (cmd == "PKDECRYPT" && key.slot != 2) || (cmd == "PKSIGN" && key.slot == 2) {
            bail!("wrong card key usage");
        }
        if self.data.is_empty() {
            bail!("no operation data");
        }
        Ok(key)
    }
    pub fn take_data(&mut self) -> Zeroizing<Vec<u8>> {
        std::mem::replace(&mut self.data, Zeroizing::new(Vec::new()))
    }
}

#[allow(clippy::too_many_arguments)] // One immutable, bounded card operation across the blocking boundary.
pub fn private_operation(
    broker: Arc<Broker>,
    stop: CancellationToken,
    info: CardInfo,
    key: CardKey,
    signing: bool,
    hash: String,
    mut input: Zeroizing<Vec<u8>>,
    mut pin: Zeroizing<Vec<u8>>,
) -> Result<AssuanResult> {
    let backend = NativeCard::open(broker, stop, info.transport.clone())?;
    let mut card =
        OpenPGP::new(Box::new(backend) as Box<dyn card_backend::CardBackend + Send + Sync>)?;
    let mut tx = card.transaction()?;
    let current = snapshot(&mut tx, info.transport)?;
    if current.serial != info.serial
        || !current.keys.iter().any(|k| {
            k.slot == key.slot && k.keygrip == key.keygrip && k.fingerprint == key.fingerprint
        })
    {
        bail!("different card or key; operation canceled");
    }
    // gpg-agent sends a fixed-size NUL-padded inquiry buffer, not just a terminator.
    if let Some(end) = pin.iter().position(|b| *b == 0) {
        if pin[end..].iter().any(|b| *b != 0) {
            bail!("invalid PIN framing");
        }
        pin.truncate(end);
    }
    if pin.is_empty() || pin.contains(&0) || pin.len() > 127 {
        bail!("invalid PIN length");
    }
    if tx.extended_capabilities()?.kdf_do() {
        let kdf = tx.kdf_do()?;
        if kdf.kdf_algo() != 0 {
            if kdf.kdf_algo() != 3 {
                bail!("unsupported card PIN derivation");
            }
            let salt = kdf.salt_pw1().context("missing PIN salt")?;
            let count = kdf.iter_count().context("missing PIN iteration count")? as usize;
            if salt.len() != 8 || count > 64 * 1024 * 1024 {
                bail!("unsupported PIN derivation parameters");
            }
            use sha2::{Digest, Sha256, Sha512};
            let material = Zeroizing::new([salt, &pin].concat());
            fn derive<D: Digest>(material: &[u8], count: usize) -> Vec<u8> {
                let mut h = D::new();
                let mut left = count.max(material.len());
                while left > 0 {
                    let n = left.min(material.len());
                    h.update(&material[..n]);
                    left -= n;
                }
                h.finalize().to_vec()
            }
            pin = Zeroizing::new(match kdf.hash_algo() {
                Some(8) => derive::<Sha256>(&material, count),
                Some(10) => derive::<Sha512>(&material, count),
                _ => bail!("unsupported PIN derivation hash"),
            });
        }
    }
    let pin = secrecy::SecretBox::new(std::mem::take(&mut *pin).into_boxed_slice());
    if signing && key.slot == 1 {
        tx.verify_pw1_sign(pin)?;
    } else {
        tx.verify_pw1_user(pin)?;
    }
    let output = if signing {
        let bytes = keycodec::signing_data(&key.algorithm, &hash, &input)?;
        if key.slot == 3 {
            tx.internal_authenticate(bytes)?
        } else {
            tx.pso_compute_digital_signature(bytes)?
        }
    } else if key.algorithm.starts_with("rsa") {
        let width: usize = key.algorithm[3..].parse::<usize>()? / 8;
        if input.len() == width + 1 && input[0] == 0 {
            input.remove(0);
        }
        if input.len() > width || input.len() + 16 < width {
            bail!("RSA ciphertext length");
        }
        let mut padded = Zeroizing::new(vec![0; width]);
        padded[width - input.len()..].copy_from_slice(&input);
        tx.decipher(Cryptogram::RSA(&padded))?
    } else {
        if key.algorithm == "cv25519" {
            if input.len() == 33 && matches!(input[0], 0 | 0x40) {
                input.remove(0);
            }
            if input.len() != 32 {
                bail!("X25519 public point length");
            }
        } else {
            let width = match key.algorithm.as_str() {
                "nistp256" => 32,
                "nistp384" => 48,
                "nistp521" => 66,
                _ => bail!("unsupported decryption curve"),
            };
            if input.len() != 1 + width * 2 || input[0] != 4 {
                bail!("ECDH public point length");
            }
        }
        let result = Zeroizing::new(tx.decipher(Cryptogram::ECDH(&input))?);
        let prefix = if key.algorithm == "cv25519" {
            Some(0x40)
        } else if result.len() % 2 == 0 {
            Some(0x41)
        } else {
            None
        };
        let mut out = Vec::with_capacity(result.len() + 1);
        if let Some(p) = prefix {
            out.push(p);
        }
        out.extend_from_slice(&result);
        out
    };
    let output = Zeroizing::new(output);
    let mut result = ok_data(&output);
    if !signing {
        result.lines.insert(0, "S PADDING 0".into());
    }
    Ok(result)
}
pub fn operation_error(error: &anyhow::Error) -> AssuanResult {
    use openpgp_card::{Error, ocard::StatusBytes};
    match error.downcast_ref::<Error>() {
        Some(Error::CardStatus(StatusBytes::PasswordNotChecked(left))) => {
            AssuanResult::error(87, &format!("Bad PIN; {left} attempts remaining"))
        }
        Some(Error::CardStatus(StatusBytes::AuthenticationMethodBlocked)) => {
            AssuanResult::error(130, "PIN blocked")
        }
        _ => AssuanResult::error(assuan::GENERAL, "card operation failed or canceled"),
    }
}
