use crate::{endpoint::Endpoint, storage::App};
use anyhow::Result;
use hibiki_lib::protocol::{CardTarget, ServiceKind};
use std::{future::Future, pin::Pin, sync::Arc};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

#[derive(Default, Clone)]
pub struct LocalContext {
    pub display: Option<String>,
}

#[derive(Clone)]
pub struct ProviderContext {
    pub local: Option<LocalContext>,
    pub channel: String,
    pub peer: String,
    pub session: String,
}
pub type OpenFuture<'a> = Pin<Box<dyn Future<Output = Result<Endpoint>> + Send + 'a>>;

pub type PrepareFuture<'a> = Pin<Box<dyn Future<Output = Result<Option<String>>> + Send + 'a>>;

/// A user explicitly canceled the entire card acquisition.
/// This is terminal, unlike an unavailable device.
#[derive(Debug)]
pub struct PreparationRejected;
impl std::fmt::Display for PreparationRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("card operation rejected by user")
    }
}
impl std::error::Error for PreparationRejected {}

/// One acquisition, including its UI, survives pauses for public queries.
/// Dropping it must close its prompt. A pause must drain any native transaction
/// before returning None; success and user cancellation remain terminal results.
pub trait Preparation: Send {
    fn poll<'a>(
        &'a mut self,
        endpoint: &'a mut Endpoint,
        pause: CancellationToken,
    ) -> PrepareFuture<'a>;
}

pub trait Provider: Send + Sync {
    fn prepare(
        &self,
        app: Arc<App>,
        target: CardTarget,
        context: ProviderContext,
    ) -> Result<Box<dyn Preparation>>;

    fn enabled(&self, service: ServiceKind) -> bool;
    fn open(
        &self,
        app: Arc<App>,
        service: ServiceKind,
        card_slot: Arc<Semaphore>,
        stop: CancellationToken,
        context: ProviderContext,
    ) -> OpenFuture<'_>;
}
