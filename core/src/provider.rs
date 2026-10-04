use crate::{endpoint::Endpoint, storage::App};
use anyhow::Result;
use hibiki_lib::protocol::ServiceKind;
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

pub trait Provider: Send + Sync {
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
