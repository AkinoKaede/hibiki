//! Public card registrations, committed atomically as one snapshot.
use crate::{CardInfo, CardTransport, RegisteredCard};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Registry {
    pub cards: Vec<RegisteredCard>,
    pub selected: Option<String>,
}
impl Registry {
    pub fn upsert(
        &mut self,
        card: CardInfo,
        name: String,
        usb_supported: bool,
        nfc_supported: bool,
    ) {
        let entry = RegisteredCard {
            usb_enabled: usb_supported,
            nfc_enabled: nfc_supported,
            name: if name.trim().is_empty() {
                "Security Key".into()
            } else {
                name.trim().into()
            },
            card,
        };
        self.selected = Some(entry.card.serial.clone());
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
    pub fn select(&mut self, serial: &str) -> Result<()> {
        self.cards
            .iter()
            .find(|c| c.card.serial == serial)
            .context("card not registered")?;
        self.selected = Some(serial.into());
        Ok(())
    }
    pub fn remove(&mut self, serial: &str) {
        self.cards.retain(|c| c.card.serial != serial);
        // Removing the current key never silently selects a different key.
        if self.selected.as_deref() == Some(serial) {
            self.selected = None;
        }
    }
    pub fn active(&self) -> Option<&RegisteredCard> {
        self.cards
            .iter()
            .find(|c| Some(&c.card.serial) == self.selected.as_ref())
    }
    pub fn provider_card(&self) -> Option<CardInfo> {
        self.active().map(|c| {
            let mut info = c.card.clone();
            // With both modes enabled, disconnected USB falls back to an NFC confirmation.
            info.transport = if c.nfc_enabled {
                CardTransport::Nfc
            } else {
                CardTransport::Usb
            };
            info
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn card(serial: &str, transport: CardTransport) -> CardInfo {
        CardInfo {
            serial: serial.into(),
            transport,
            keys: vec![],
        }
    }
    #[test]
    fn merges_transports_preserves_other_cards_and_never_switches_on_remove() {
        let mut registry = Registry::default();
        registry.upsert(card("one", CardTransport::Usb), "First".into(), true, true);
        assert!(registry.active().unwrap().nfc_enabled);
        registry.upsert(
            card("two", CardTransport::Nfc),
            "Second".into(),
            false,
            true,
        );
        assert!(!registry.active().unwrap().usb_enabled);
        registry.upsert(
            card("one", CardTransport::Nfc),
            "Updated".into(),
            true,
            true,
        );
        assert_eq!(registry.cards.len(), 2);
        registry.select("two").unwrap();
        registry.remove("two");
        assert!(registry.active().is_none());
        assert_eq!(registry.cards.len(), 1);
        assert!(registry.select("missing").is_err());
        let bytes = hibiki_lib::encode(&registry).unwrap();
        let reopened: Registry = hibiki_lib::decode(&bytes).unwrap();
        assert!(reopened.selected.is_none());
        assert_eq!(reopened.cards[0].name, "Updated");
    }
}

#[cfg(test)]
mod persistence_tests {
    use super::*;
    use crate::{MobileClient, create_identity};
    use hibiki_core::storage::atomic_write;
    #[tokio::test]
    async fn registry_and_removal_survive_reopening() {
        let root =
            std::env::temp_dir().join(format!("hibiki-registry-{}", hibiki_lib::random_id()));
        let identity = create_identity("registry test".into()).unwrap();
        let open = || {
            MobileClient::new(
                root.to_string_lossy().into_owned(),
                "wss://example.com/hibiki".into(),
                identity.clone(),
                false,
            )
            .unwrap()
        };
        let first = open();
        let card = CardInfo {
            serial: "one".into(),
            transport: CardTransport::Nfc,
            keys: vec![],
        };
        let mut registry = Registry::default();
        registry.upsert(card, "Security Key".into(), true, true);
        atomic_write(
            &root.join("data/cards.bin"),
            &hibiki_lib::encode(&registry).unwrap(),
        )
        .unwrap();
        drop(first);
        let registered = open();
        assert_eq!(registered.registered_cards().len(), 1);
        assert_eq!(registered.selected_card().unwrap().serial, "one");
        registered.remove_card("one".into()).await.unwrap();
        drop(registered);
        let reopened = open();
        assert!(reopened.registered_cards().is_empty());
        assert!(reopened.selected_card().is_none());
        assert!(reopened.select_card("one".into()).await.is_err());
        drop(reopened);
        std::fs::remove_dir_all(root).unwrap();
    }
}
