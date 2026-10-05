//! Public card registrations, committed atomically as one snapshot.
#[cfg(test)]
use crate::CardTransport;
use crate::{CardInfo, RegisteredCard};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Registry {
    pub cards: Vec<RegisteredCard>,
    // Retained in the Postcard layout for existing cards.bin snapshots; never used.
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
        self.selected = None;
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
    pub fn update(&mut self, serial: &str, name: String, usb: bool, nfc: bool) -> Result<()> {
        let name = name.trim();
        ensure!(!name.is_empty(), "enter a security key name");
        ensure!(usb || nfc, "select at least one supported connection");
        let entry = self
            .cards
            .iter_mut()
            .find(|c| c.card.serial == serial)
            .context("card not registered")?;
        entry.name = name.into();
        entry.usb_enabled = usb;
        entry.nfc_enabled = nfc;
        Ok(())
    }
    pub fn remove(&mut self, serial: &str) {
        self.cards.retain(|c| c.card.serial != serial);
        self.selected = None;
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
        assert!(registry.cards[0].nfc_enabled);
        registry.upsert(
            card("two", CardTransport::Nfc),
            "Second".into(),
            false,
            true,
        );
        assert!(!registry.cards[1].usb_enabled);
        registry.upsert(
            card("one", CardTransport::Nfc),
            "Updated".into(),
            true,
            true,
        );
        assert_eq!(registry.cards.len(), 2);
        registry.remove("two");
        assert_eq!(registry.cards.len(), 1);
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
        // An old snapshot may contain a selected card. Loading retains all cards,
        // but the next write clears that obsolete field without changing layout.
        registry.selected = Some("one".into());
        atomic_write(
            &root.join("data/cards.bin"),
            &hibiki_lib::encode(&registry).unwrap(),
        )
        .unwrap();
        drop(first);
        let registered = open();
        assert_eq!(registered.registered_cards().len(), 1);
        assert_eq!(registered.registered_cards()[0].card.serial, "one");
        registered
            .update_card("one".into(), "Renamed".into(), true, true)
            .await
            .unwrap();
        let saved: Registry =
            hibiki_lib::decode(&std::fs::read(root.join("data/cards.bin")).unwrap()).unwrap();
        assert!(saved.selected.is_none());
        registered.remove_card("one".into()).await.unwrap();
        drop(registered);
        let reopened = open();
        assert!(reopened.registered_cards().is_empty());
        drop(reopened);
        std::fs::remove_dir_all(root).unwrap();
    }
}
