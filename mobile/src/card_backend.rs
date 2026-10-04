//! Synchronous OpenPGP-card backend running only on Tokio's blocking pool.
use crate::{
    broker::Broker,
    types::{CardTransport, NativeEvent},
};
use anyhow::Result;
use card_backend::{CardBackend, CardCaps, CardTransaction, PinType, SmartcardError};
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

pub struct NativeCard {
    broker: Arc<Broker>,
    stop: CancellationToken,
    connection: String,
    runtime: tokio::runtime::Handle,
}
impl NativeCard {
    pub fn open(
        broker: Arc<Broker>,
        stop: CancellationToken,
        transport: CardTransport,
    ) -> Result<Self> {
        let card = Self {
            broker,
            stop,
            connection: hibiki_lib::random_id(),
            runtime: tokio::runtime::Handle::current(),
        };
        card.runtime.block_on(card.broker.request(
            |token| NativeEvent::CardOpen {
                token,
                connection: card.connection.clone(),
                transport,
            },
            &card.stop,
            Duration::from_secs(90),
        ))?;
        Ok(card)
    }
    pub fn exchange(&self, bytes: &[u8]) -> Result<Vec<u8>, SmartcardError> {
        if bytes.len() > 65544 {
            return Err(SmartcardError::Error("APDU limit".into()));
        }
        let response = self
            .runtime
            .block_on(self.broker.request(
                |token| NativeEvent::CardTransmit {
                    token,
                    connection: self.connection.clone(),
                    command: bytes.to_vec(),
                },
                &self.stop,
                Duration::from_secs(120),
            ))
            .map_err(|_| SmartcardError::Error("card exchange canceled or failed".into()))?;
        if response.len() < 2 || response.len() > 65538 {
            return Err(SmartcardError::Error("invalid card response size".into()));
        }
        Ok(response.to_vec())
    }
}
impl Drop for NativeCard {
    fn drop(&mut self) {
        let _ = self.broker.emit(NativeEvent::CardClose {
            connection: self.connection.clone(),
        });
    }
}
impl CardBackend for NativeCard {
    fn limit_card_caps(&self, caps: CardCaps) -> CardCaps {
        caps
    }
    fn transaction(
        &mut self,
        _: Option<&[u8]>,
    ) -> Result<Box<dyn CardTransaction + Send + Sync + '_>, SmartcardError> {
        Ok(Box::new(NativeTransaction(self)))
    }
}
struct NativeTransaction<'a>(&'a NativeCard);
impl CardTransaction for NativeTransaction<'_> {
    fn transmit(&mut self, cmd: &[u8], _: usize) -> Result<Vec<u8>, SmartcardError> {
        self.0.exchange(cmd)
    }
    fn feature_pinpad_verify(&self) -> bool {
        false
    }
    fn feature_pinpad_modify(&self) -> bool {
        false
    }
    fn pinpad_verify(
        &mut self,
        _: PinType,
        _: &Option<CardCaps>,
    ) -> Result<Vec<u8>, SmartcardError> {
        Err(SmartcardError::Error("no pinpad".into()))
    }
    fn pinpad_modify(
        &mut self,
        _: PinType,
        _: &Option<CardCaps>,
    ) -> Result<Vec<u8>, SmartcardError> {
        Err(SmartcardError::Error("unsupported".into()))
    }
    fn was_reset(&self) -> bool {
        false
    }
}
