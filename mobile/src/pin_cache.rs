/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

//! The agent owns the ciphertext. Only wrapping keys and validity live here.
use crate::types::{CardInfo, CardKey};
use anyhow::{Context, Result, bail};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hibiki_core::provider::ProviderContext;
use hibiki_lib::assuan::Line;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, Weak},
};
use zeroize::Zeroizing;

const VERSION: u8 = 1;
const MAX_ENTRIES: usize = 256;

#[derive(Clone)]
pub struct Scope {
    channel: String,
    peer: String,
    serial: String,
    pub id: String,
}

impl Scope {
    pub fn new(provider: &str, context: &ProviderContext, info: &CardInfo, key: &CardKey) -> Self {
        let serial = info.serial.to_ascii_uppercase();
        let identity = hibiki_lib::encode(&(
            provider,
            &context.channel,
            &context.peer,
            &serial,
            key.slot,
            key.keygrip.to_ascii_uppercase(),
            key.fingerprint.to_ascii_uppercase(),
        ))
        .expect("bounded card cache identity");
        Self {
            channel: context.channel.clone(),
            peer: context.peer.clone(),
            serial,
            id: format!("0/hibiki-ios-v1/{}", hex::encode(Sha256::digest(identity))),
        }
    }
}

struct Entry {
    scope: Scope,
    key: Zeroizing<[u8; 32]>,
}
#[derive(Default)]
struct State {
    epoch: u64,
    entries: BTreeMap<String, Entry>,
    cards: BTreeMap<String, Weak<()>>,
    usb: BTreeMap<String, BTreeSet<String>>,
}
#[derive(Default)]
pub struct PinCache(Mutex<State>);

#[derive(Clone)]
pub struct Ticket {
    epoch: u64,
    card: Arc<()>,
    pub scope: Scope,
}
impl PinCache {
    pub fn begin(&self, scope: Scope) -> Ticket {
        let mut state = self.0.lock().unwrap();
        state.cards.retain(|_, version| version.strong_count() > 0);
        let version = state.cards.entry(scope.serial.clone()).or_default();
        let card = version.upgrade().unwrap_or_else(|| Arc::new(()));
        *version = Arc::downgrade(&card);
        Ticket {
            epoch: state.epoch,
            card,
            scope,
        }
    }
    pub fn is_valid(&self, ticket: &Ticket) -> bool {
        Self::valid(&self.0.lock().unwrap(), ticket)
    }
    pub fn contains(&self, ticket: &Ticket) -> bool {
        let state = self.0.lock().unwrap();
        Self::valid(&state, ticket) && state.entries.contains_key(&ticket.scope.id)
    }
    pub fn decrypt(&self, ticket: &Ticket, value: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let state = self.0.lock().unwrap();
        if !Self::valid(&state, ticket) || value.len() > 512 {
            return None;
        }
        let entry = state.entries.get(&ticket.scope.id)?;
        let wrapped = Zeroizing::new(hex::decode(value).ok()?);
        // Fixed-size plaintext: one length byte and 127 PIN/padding bytes.
        if wrapped.len() != 1 + 24 + 128 + 16 || wrapped[0] != VERSION {
            return None;
        }
        let cipher = XChaCha20Poly1305::new_from_slice(entry.key.as_ref()).ok()?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&wrapped[1..25]),
                    Payload {
                        msg: &wrapped[25..],
                        aad: ticket.scope.id.as_bytes(),
                    },
                )
                .ok()?,
        );
        let len = usize::from(plaintext[0]);
        if !(1..=127).contains(&len)
            || plaintext[1..=len].contains(&0)
            || plaintext[len + 1..].iter().any(|b| *b != 0)
        {
            return None;
        }
        Some(Zeroizing::new(plaintext[1..=len].to_vec()))
    }
    /// Publish under the validity lock: RESET/disable cannot race a stale PUT.
    /// The callback must synchronously enqueue a single line, without blocking.
    pub fn publish(
        &self,
        ticket: Ticket,
        pin: &[u8],
        emit: impl FnOnce(Line) -> Result<()>,
    ) -> Result<()> {
        let mut state = self.0.lock().unwrap();
        if !Self::valid(&state, &ticket) {
            return Ok(());
        }
        if pin.is_empty() || pin.len() > 127 || pin.contains(&0) {
            bail!("invalid cache PIN");
        }
        let mut key = Zeroizing::new([0u8; 32]);
        let mut nonce = [0u8; 24];
        getrandom::fill(key.as_mut()).context("PIN cache randomness unavailable")?;
        getrandom::fill(&mut nonce).context("PIN cache randomness unavailable")?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).expect("key length");
        let mut plaintext = Zeroizing::new([0u8; 128]);
        plaintext[0] = pin.len() as u8;
        plaintext[1..=pin.len()].copy_from_slice(pin);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_ref(),
                    aad: ticket.scope.id.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("PIN cache encryption failed"))?;
        let mut wrapped = vec![VERSION];
        wrapped.extend_from_slice(&nonce);
        wrapped.extend_from_slice(&ciphertext);
        emit(
            format!(
                "S PINCACHE_PUT {} {}",
                ticket.scope.id,
                hex::encode(wrapped)
            )
            .as_str()
            .into(),
        )?;
        if state.entries.len() >= MAX_ENTRIES && !state.entries.contains_key(&ticket.scope.id) {
            // Eviction only destroys a wrapping key; the old agent blob is unusable.
            state.entries.pop_first();
        }
        state.entries.insert(
            ticket.scope.id.clone(),
            Entry {
                scope: ticket.scope,
                key,
            },
        );
        Ok(())
    }
    fn valid(state: &State, ticket: &Ticket) -> bool {
        state.epoch == ticket.epoch
            && state
                .cards
                .get(&ticket.scope.serial)
                .and_then(Weak::upgrade)
                .is_some_and(|version| Arc::ptr_eq(&version, &ticket.card))
    }
    /// A physical card's lifecycle spans all requesters, channels and transports.
    pub fn clear_serial(&self, serial: &str) {
        Self::invalidate_serial(&mut self.0.lock().unwrap(), &serial.to_ascii_uppercase());
    }
    fn invalidate_serial(state: &mut State, serial: &str) {
        state.cards.remove(serial);
        state
            .entries
            .retain(|_, entry| entry.scope.serial != serial);
    }
    /// Connection IDs are opaque native insertion identities, not reader names.
    pub fn usb_connections(&self, connections: Vec<String>) {
        let mut state = self.0.lock().unwrap();
        let current: BTreeSet<_> = connections.into_iter().collect();
        let removed: BTreeSet<_> = state
            .usb
            .iter()
            .filter(|(id, _)| !current.contains(*id))
            .flat_map(|(_, serials)| serials.iter().cloned())
            .collect();
        for serial in removed {
            Self::invalidate_serial(&mut state, &serial);
        }
        state.usb.retain(|id, _| current.contains(id));
        for id in current {
            state.usb.entry(id).or_default();
        }
    }
    /// Reject late public reads from a removed/replaced insertion.
    pub fn observe_usb(&self, connection: &str, serial: &str) -> Result<()> {
        let mut state = self.0.lock().unwrap();
        let serial = serial.to_ascii_uppercase();
        let Some(serials) = state.usb.get_mut(connection) else {
            // The reader may finish identifying the removed card after its event.
            // Invalidate its old cache, but never reattach it to a new insertion.
            Self::invalidate_serial(&mut state, &serial);
            bail!("USB card was removed during identification");
        };
        serials.insert(serial);
        Ok(())
    }
    pub fn clear_all(&self) {
        let mut state = self.0.lock().unwrap();
        state.epoch += 1;
        state.entries.clear();
    }
    pub fn clear_context(&self, context: &ProviderContext) -> Vec<Line> {
        self.clear(|scope| scope.channel == context.channel && scope.peer == context.peer)
    }
    pub fn clear_card(&self, scope: &Scope) -> Vec<Line> {
        self.clear(|other| {
            other.channel == scope.channel
                && other.peer == scope.peer
                && other.serial == scope.serial
        })
    }
    pub fn clear_entry(&self, scope: &Scope) -> Vec<Line> {
        self.clear(|other| other.id == scope.id)
    }
    fn clear(&self, matches: impl Fn(&Scope) -> bool) -> Vec<Line> {
        let mut state = self.0.lock().unwrap();
        state.epoch += 1;
        let mut lines = Vec::new();
        state.entries.retain(|id, entry| {
            if matches(&entry.scope) {
                lines.push(format!("S PINCACHE_PUT {id}").as_str().into());
                false
            } else {
                true
            }
        });
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CardTransport;

    fn fixture() -> (ProviderContext, CardInfo, CardKey) {
        let key = CardKey {
            slot: 1,
            algorithm: "rsa2048".into(),
            fingerprint: "A".repeat(40),
            keygrip: "B".repeat(40),
            public_key: vec![],
            created_at: 0,
        };
        (
            ProviderContext {
                local: None,
                channel: "channel".into(),
                peer: "peer".into(),
                session: "one".into(),
            },
            CardInfo {
                serial: "ABCD".into(),
                transport: CardTransport::Usb,
                keys: vec![key.clone()],
            },
            key,
        )
    }
    fn put(cache: &PinCache, scope: Scope) -> Vec<u8> {
        let mut value = Vec::new();
        cache
            .publish(cache.begin(scope), b"123456", |line| {
                value = line.rsplit(|b| *b == b' ').next().unwrap().to_vec();
                Ok(())
            })
            .unwrap();
        value
    }
    #[test]
    fn authenticated_roundtrip_and_isolation() {
        let cache = PinCache::default();
        let (mut context, mut info, mut key) = fixture();
        let scope = Scope::new("provider", &context, &info, &key);
        let blob = put(&cache, scope.clone());
        assert_ne!(blob, b"123456");
        assert_eq!(
            &*cache.decrypt(&cache.begin(scope.clone()), &blob).unwrap(),
            b"123456"
        );
        context.session = "two".into();
        info.transport = CardTransport::Nfc;
        assert_eq!(scope.id, Scope::new("provider", &context, &info, &key).id);
        let mut variants = vec![Scope::new("other-provider", &context, &info, &key)];
        context.peer = "other-peer".into();
        variants.push(Scope::new("provider", &context, &info, &key));
        context.peer = "peer".into();
        context.channel = "other-channel".into();
        variants.push(Scope::new("provider", &context, &info, &key));
        context.channel = "channel".into();
        info.serial = "FFFF".into();
        variants.push(Scope::new("provider", &context, &info, &key));
        info.serial = "ABCD".into();
        key.slot = 2;
        variants.push(Scope::new("provider", &context, &info, &key));
        key.slot = 1;
        key.fingerprint = "C".repeat(40);
        variants.push(Scope::new("provider", &context, &info, &key));
        for other in variants {
            put(&cache, other.clone());
            assert!(cache.decrypt(&cache.begin(other), &blob).is_none());
        }
        let mut tampered = blob.clone();
        tampered[80] = if tampered[80] == b'0' { b'1' } else { b'0' };
        for invalid in [tampered, b"garbage".to_vec(), vec![], vec![b'A'; 514]] {
            assert!(
                cache
                    .decrypt(&cache.begin(scope.clone()), &invalid)
                    .is_none()
            );
        }
        let fresh = put(&cache, scope.clone());
        assert!(cache.decrypt(&cache.begin(scope.clone()), &blob).is_none());
        assert!(cache.decrypt(&cache.begin(scope.clone()), &fresh).is_some());
        assert!(
            PinCache::default()
                .decrypt(&cache.begin(scope), &fresh)
                .is_none()
        );
    }
    #[test]
    fn physical_removal_clears_all_card_scopes_and_only_fences_that_card() {
        let cache = PinCache::default();
        let (mut context, mut info, mut key) = fixture();
        let first = Scope::new("provider", &context, &info, &key);
        put(&cache, first.clone());
        let stale = cache.begin(first.clone());
        context.channel = "other-channel".into();
        context.peer = "other-peer".into();
        key.slot = 2;
        info.transport = CardTransport::Nfc;
        let second = Scope::new("provider", &context, &info, &key);
        put(&cache, second.clone());
        info.serial = "EEEE".into();
        let unrelated = Scope::new("provider", &context, &info, &key);
        let blob = put(&cache, unrelated.clone());
        let unaffected = cache.begin(unrelated.clone());
        cache.usb_connections(vec!["insertion-1".into(), "other-reader".into()]);
        cache.observe_usb("insertion-1", "abcd").unwrap();
        cache.observe_usb("other-reader", "EEEE").unwrap();
        // Reinsertion of the same physical card has a fresh native identity.
        cache.usb_connections(vec!["insertion-2".into(), "other-reader".into()]);
        assert!(!cache.contains(&cache.begin(first.clone())));
        assert!(!cache.contains(&cache.begin(second)));
        assert!(cache.decrypt(&unaffected, &blob).is_some());
        cache
            .publish(stale, b"123456", |_| panic!("stale PUT after removal"))
            .unwrap();
        assert!(cache.observe_usb("insertion-1", "ABCD").is_err());
        cache.observe_usb("insertion-2", "ABCD").unwrap();
        put(&cache, first.clone());
        // Duplicate state snapshots do not invalidate a new insertion's cache.
        cache.usb_connections(vec!["insertion-2".into(), "other-reader".into()]);
        assert!(cache.contains(&cache.begin(first)));
        let mut published = false;
        cache
            .publish(unaffected, b"123456", |_| {
                published = true;
                Ok(())
            })
            .unwrap();
        assert!(published);
    }

    #[test]
    fn forgetting_a_card_fences_an_unpublished_ticket_without_affecting_other_cards() {
        let cache = PinCache::default();
        let (context, info, key) = fixture();
        let scope = Scope::new("provider", &context, &info, &key);
        let stale = cache.begin(scope.clone());
        cache.clear_serial("abcd");
        cache
            .publish(stale, b"123456", |_| panic!("late first PUT"))
            .unwrap();
        assert!(!cache.contains(&cache.begin(scope.clone())));
        put(&cache, scope.clone());
        assert!(cache.contains(&cache.begin(scope)));
    }

    #[test]
    fn reset_bad_pin_and_disable_fence_inflight_writes() {
        let cache = PinCache::default();
        let (context, info, mut key) = fixture();
        let scope = Scope::new("provider", &context, &info, &key);
        let blob = put(&cache, scope.clone());
        key.slot = 2;
        let second = Scope::new("provider", &context, &info, &key);
        put(&cache, second.clone());
        let mut other_context = context.clone();
        other_context.peer = "unrelated".into();
        let other = Scope::new("provider", &other_context, &info, &key);
        let other_blob = put(&cache, other.clone());
        let stale = cache.begin(scope.clone());
        let deleted = cache.clear_context(&context);
        assert_eq!(deleted.len(), 2);
        assert!(cache.decrypt(&cache.begin(other), &other_blob).is_some());
        assert!(
            deleted
                .iter()
                .all(|l| l.starts_with(b"S PINCACHE_PUT 0/hibiki-ios-v1/"))
        );
        cache
            .publish(stale, b"123456", |_| panic!("stale PUT after RESET"))
            .unwrap();
        assert!(cache.decrypt(&cache.begin(scope.clone()), &blob).is_none());
        put(&cache, scope.clone());
        put(&cache, second.clone());
        assert_eq!(cache.clear_card(&scope).len(), 2);
        put(&cache, scope.clone());
        let stale = cache.begin(scope.clone());
        cache.clear_all();
        cache
            .publish(stale, b"123456", |_| panic!("stale PUT after disable"))
            .unwrap();
        assert!(!cache.contains(&cache.begin(scope)));
    }
}
