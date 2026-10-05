//! Saved NFC public snapshots. USB cards are discovered live and never registered.
use crate::{CardInfo, CardTransport, RegisteredCard};
use anyhow::{Context, Result, ensure};
use hibiki_core::storage::{atomic_write, read_private};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Registry {
    pub cards: Vec<RegisteredCard>,
}
impl Registry {
    pub fn load(directory: &Path) -> Result<Self> {
        let path = directory.join("nfc-cards.bin");
        if path.exists() {
            return Ok(hibiki_lib::decode(&read_private(&path)?)?);
        }
        let legacy = directory.join("cards.bin");
        if !legacy.exists() {
            return Ok(Self::default());
        }
        // One-time migration: keep NFC snapshots regardless of the reader used
        // to enroll them; discard obsolete USB permissions and saved selection.
        #[derive(Deserialize)]
        struct LegacyCard {
            card: CardInfo,
            name: String,
            _usb_enabled: bool,
            nfc_enabled: bool,
        }
        #[derive(Deserialize)]
        struct LegacyRegistry {
            cards: Vec<LegacyCard>,
            _selected: Option<String>,
        }
        let old: LegacyRegistry = hibiki_lib::decode(&read_private(&legacy)?)?;
        let mut registry = Self::default();
        for entry in old.cards.into_iter().filter(|c| c.nfc_enabled) {
            registry.upsert(entry.card, entry.name);
        }
        atomic_write(&path, &hibiki_lib::encode(&registry)?)?;
        std::fs::remove_file(legacy)?;
        Ok(registry)
    }
    pub fn upsert(&mut self, mut card: CardInfo, name: String) {
        card.transport = CardTransport::Nfc;
        let entry = RegisteredCard {
            card,
            name: if name.trim().is_empty() {
                "Security Key".into()
            } else {
                name.trim().into()
            },
        };
        if let Some(existing) = self
            .cards
            .iter_mut()
            .find(|c| c.card.serial == entry.card.serial)
        {
            *existing = entry;
        } else {
            self.cards.push(entry);
        }
    }
    pub fn update(&mut self, serial: &str, name: String) -> Result<()> {
        let name = name.trim();
        ensure!(!name.is_empty(), "enter a security key name");
        self.cards
            .iter_mut()
            .find(|c| c.card.serial == serial)
            .context("card not registered")?
            .name = name.into();
        Ok(())
    }
    pub fn remove(&mut self, serial: &str) {
        self.cards.retain(|c| c.card.serial != serial);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn migrates_only_nfc_records_and_keeps_names_without_selection() {
        #[derive(Serialize)]
        struct OldCard {
            card: CardInfo,
            name: String,
            usb_enabled: bool,
            nfc_enabled: bool,
        }
        #[derive(Serialize)]
        struct OldRegistry {
            cards: Vec<OldCard>,
            selected: Option<String>,
        }
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("registry");
        hibiki_core::storage::private_dir(&root).unwrap();
        let old = OldRegistry {
            cards: [("usb", false), ("dual", true), ("nfc", true)]
                .into_iter()
                .map(|(serial, nfc_enabled)| OldCard {
                    card: CardInfo {
                        serial: serial.into(),
                        transport: CardTransport::Usb,
                        keys: vec![],
                    },
                    name: serial.into(),
                    usb_enabled: true,
                    nfc_enabled,
                })
                .collect(),
            selected: Some("dual".into()),
        };
        atomic_write(&root.join("cards.bin"), &hibiki_lib::encode(&old).unwrap()).unwrap();
        let mut registry = Registry::load(&root).unwrap();
        assert_eq!(
            registry
                .cards
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>(),
            ["dual", "nfc"]
        );
        assert!(
            registry
                .cards
                .iter()
                .all(|c| c.card.transport == CardTransport::Nfc)
        );
        assert!(!root.join("cards.bin").exists());
        registry.update("dual", "Renamed".into()).unwrap();
        registry.remove("nfc");
        atomic_write(
            &root.join("nfc-cards.bin"),
            &hibiki_lib::encode(&registry).unwrap(),
        )
        .unwrap();
        let reopened = Registry::load(&root).unwrap();
        assert_eq!(reopened.cards.len(), 1);
        assert_eq!(reopened.cards[0].name, "Renamed");
    }
}
