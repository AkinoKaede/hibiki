//! Per-session routing over public registrations. No persistent active card.
use crate::{CardInfo, CardTransport, RegisteredCard, card::CardSession};
use anyhow::{Context, Result, bail};
use hibiki_lib::{
    assuan::{self, AssuanResult},
    protocol::CardTarget,
};

pub fn usable(cards: &[RegisteredCard], nfc_available: bool) -> Vec<RegisteredCard> {
    cards
        .iter()
        .filter(|c| c.usb_enabled || (c.nfc_enabled && nfc_available))
        .cloned()
        .collect()
}

pub fn matches_target(info: &CardInfo, target: &CardTarget) -> bool {
    if target
        .serial
        .as_ref()
        .is_some_and(|s| !s.eq_ignore_ascii_case(&info.serial))
    {
        return false;
    }
    target.key.as_ref().is_none_or(|key| {
        key.eq_ignore_ascii_case(&info.serial)
            || CardSession::new(info.clone())
                .command(format!("READKEY {key}").as_bytes())
                .is_ok_and(|r| r.success())
    })
}

pub struct CardSetSession {
    // SETDATA can arrive before a card is bound. Replacing info preserves that buffer.
    pub card: CardSession,
    bound: bool,
}
impl CardSetSession {
    pub fn new() -> Self {
        Self {
            card: CardSession::new(CardInfo {
                serial: String::new(),
                transport: CardTransport::Usb,
                keys: vec![],
            }),
            bound: false,
        }
    }
    pub fn bind(&mut self, info: CardInfo) {
        self.card.info = info;
        self.bound = true;
    }
    pub fn bind_if_unbound(&mut self, info: Option<CardInfo>) {
        if !self.bound
            && let Some(info) = info
        {
            self.bind(info);
        }
    }
    pub fn command(&mut self, cards: &[RegisteredCard], line: &[u8]) -> Result<AssuanResult> {
        let (cmd, args) = assuan::command(line)?;
        if matches!(cmd, "RESET" | "RESTART") {
            self.bound = false;
            return self.card.command(line);
        }
        if matches!(cmd, "SETDATA" | "NOP" | "BYE" | "SWITCHAPP") {
            return self.card.command(line);
        }
        let aggregate = (cmd == "GETINFO" && matches!(args, "card_list" | "all_active_apps"))
            || (cmd == "KEYINFO"
                && args
                    .split_ascii_whitespace()
                    .any(|a| a.starts_with("--list")));
        if aggregate {
            if cards.is_empty() {
                return Ok(AssuanResult::error(108, "card not present"));
            }
            let mut result = AssuanResult::ok();
            result.lines.clear();
            for entry in cards {
                let mut part = CardSession::new(entry.card.clone()).command(line)?;
                if !part.success() {
                    return Ok(part);
                }
                part.lines.pop(); // A single final OK follows the combined records.
                result.lines.extend(part.lines);
            }
            result.lines.extend(AssuanResult::ok().lines);
            return Ok(result);
        }
        if cmd == "GETINFO" && matches!(args, "version" | "app_list" | "reader_list" | "deny_admin")
        {
            return self.card.command(line);
        }
        let serial = args
            .split_ascii_whitespace()
            .find_map(|a| a.strip_prefix("--demand="))
            .or_else(|| (cmd == "SWITCHCARD" && !args.is_empty()).then_some(args));
        let key = if matches!(cmd, "READKEY" | "KEYINFO") {
            args.split_ascii_whitespace()
                .rfind(|a| !a.starts_with("--"))
        } else if cmd == "LEARN" {
            args.split_ascii_whitespace()
                .find(|a| a.len() == 40 && a.bytes().all(|b| b.is_ascii_hexdigit()))
        } else {
            None
        };
        let target = CardTarget {
            serial: serial.map(str::to_owned),
            key: key.map(str::to_owned),
        };
        let candidates: Vec<_> = cards
            .iter()
            .filter(|c| matches_target(&c.card, &target))
            .collect();
        let existing = self
            .bound
            .then(|| {
                candidates
                    .iter()
                    .find(|c| c.card.serial == self.card.info.serial)
            })
            .flatten();
        let entry = if let Some(serial) = serial {
            candidates
                .iter()
                .find(|c| c.card.serial.eq_ignore_ascii_case(serial))
                .copied()
        } else if let Some(existing) = existing {
            Some(*existing)
        } else if candidates.len() == 1 {
            Some(candidates[0])
        } else {
            None
        };
        let Some(entry) = entry else {
            if candidates.is_empty() {
                bail!("card does not match");
            }
            bail!("specify a card serial number when multiple cards match");
        };
        self.bind(entry.card.clone());
        self.card.command(line)
    }

    pub fn prepare_execution(
        &mut self,
        info: Option<CardInfo>,
        cards: &[RegisteredCard],
        nfc_available: bool,
    ) -> Result<()> {
        let info = info.context("card preparation required")?;
        let entry = cards
            .iter()
            .find(|c| c.card.serial == info.serial)
            .context("card is no longer registered")?;
        match info.transport {
            CardTransport::Usb if !entry.usb_enabled => bail!("USB disabled for this card"),
            CardTransport::Nfc if !entry.nfc_enabled || !nfc_available => {
                bail!("NFC reading is unavailable on this device")
            }
            _ => {}
        }
        self.bind(info);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CardKey;

    fn entry(serial: &str, grip: &str, usb: bool, nfc: bool) -> RegisteredCard {
        RegisteredCard {
            card: CardInfo {
                serial: serial.into(),
                transport: CardTransport::Nfc,
                keys: vec![CardKey {
                    slot: 1,
                    keygrip: grip.into(),
                    fingerprint: grip.into(),
                    algorithm: "rsa2048".into(),
                    public_key: b"public".to_vec(),
                    created_at: 0,
                }],
            },
            name: serial.into(),
            usb_enabled: usb,
            nfc_enabled: nfc,
        }
    }

    #[test]
    fn capability_filters_without_changing_saved_configuration() {
        let cards = vec![
            entry("usb", "A", true, false),
            entry("nfc", "B", false, true),
            entry("both", "C", true, true),
        ];
        assert_eq!(
            usable(&cards, false)
                .iter()
                .map(|c| c.card.serial.as_str())
                .collect::<Vec<_>>(),
            ["usb", "both"]
        );
        assert_eq!(usable(&cards, true).len(), 3);
        assert!(cards[1].nfc_enabled);
    }

    #[test]
    fn inventory_includes_all_cards_and_targeted_queries_do_not_pick_the_first() {
        let cards = vec![entry("one", "A", true, true), entry("two", "B", true, true)];
        let mut session = CardSetSession::new();
        let list = session.command(&cards, b"GETINFO card_list").unwrap();
        assert_eq!(list.lines.len(), 3);
        assert_eq!(&*list.lines[0], b"S SERIALNO one");
        assert_eq!(&*list.lines[1], b"S SERIALNO two");
        assert!(session.command(&cards, b"SERIALNO").is_err());
        assert!(session.command(&cards, b"READKEY OPENPGP.1").is_err());
        assert!(session.command(&cards, b"READKEY B").unwrap().success());
        assert_eq!(session.card.info.serial, "two");
        assert!(
            session
                .command(&cards, b"READKEY OPENPGP.1")
                .unwrap()
                .success()
        );
        assert!(
            session
                .command(&cards, b"SWITCHCARD one")
                .unwrap()
                .success()
        );
        assert_eq!(session.card.info.serial, "one");
        assert!(
            session
                .command(&cards, b"SERIALNO --demand=missing")
                .is_err()
        );
        assert_eq!(
            session
                .command(&cards, b"KEYINFO --list")
                .unwrap()
                .lines
                .len(),
            3
        );
    }

    #[test]
    fn execution_uses_prepared_identity_preserves_data_and_checks_capability() {
        let cards = vec![entry("one", "A", true, true), entry("two", "B", true, true)];
        let mut session = CardSetSession::new();
        session.command(&cards, b"SETDATA 010203").unwrap();
        session.command(&cards, b"READKEY A").unwrap();
        assert!(session.prepare_execution(None, &cards, true).is_err());
        assert!(
            session
                .prepare_execution(Some(cards[1].card.clone()), &cards, false)
                .is_err()
        );
        session
            .prepare_execution(Some(cards[1].card.clone()), &cards, true)
            .unwrap();
        assert_eq!(session.card.info.serial, "two");
        assert_eq!(&*session.card.take_data(), &[1, 2, 3]);
        let mut other = CardSetSession::new();
        assert!(other.command(&cards, b"READKEY OPENPGP.1").is_err());
        assert!(
            session
                .prepare_execution(Some(cards[1].card.clone()), &cards[..1], true)
                .is_err()
        );
    }

    #[test]
    fn duplicate_keys_require_a_serial_or_a_bound_session() {
        let cards = vec![
            entry("one", "same", true, true),
            entry("two", "same", true, true),
        ];
        let mut session = CardSetSession::new();
        assert!(session.command(&cards, b"READKEY same").is_err());
        session.command(&cards, b"SWITCHCARD two").unwrap();
        assert!(session.command(&cards, b"READKEY same").unwrap().success());
        session.command(&cards, b"RESET").unwrap();
        assert!(session.command(&cards, b"READKEY same").is_err());
    }
}
