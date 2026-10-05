/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

//! Operation identities survive a transport reconnect, never a vanished caller.
use crate::{
    session::Hub,
    storage::{App, atomic_write, private_dir, read_private},
};
use anyhow::{Result, bail};
use hibiki_lib::{decode, encode, now, protocol::*, random_id};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio_util::sync::CancellationToken;

pub struct QueuedOperation {
    pub value: Operation,
    pub hub: Arc<Hub>,
    finished: AtomicBool,
}
impl QueuedOperation {
    pub async fn new(
        hub: Arc<Hub>,
        channel: &str,
        service: ServiceKind,
        targets: Vec<String>,
    ) -> Result<Self> {
        let deadline = deadline_after(
            SystemTime::now().duration_since(UNIX_EPOCH)?,
            hub.app.config.operation_timeout_seconds,
        );
        let op = Self {
            value: Operation {
                id: random_id(),
                channel: channel.into(),
                initiator: hub.app.identity.device.id(),
                service,
                deadline,
                state: OperationState::Pending,
                targets: targets
                    .into_iter()
                    .map(|device| OperationTarget {
                        device,
                        state: TargetState::Pending,
                    })
                    .collect(),
            },
            hub,
            finished: AtomicBool::new(false),
        };
        op.control(Control::Queue {
            operation: op.value.clone(),
        })
        .await?;
        Ok(op)
    }
    async fn control(&self, command: Control) -> Result<Operation> {
        loop {
            let connection = self.hub.connection();
            if !connection.closed.is_cancelled() {
                match connection.request(command.clone()).await {
                    Ok(Reply::Operation(op)) => {
                        if op.id != self.value.id
                            || op.channel != self.value.channel
                            || op.initiator != self.value.initiator
                            || op.service != self.value.service
                            || op.deadline != self.value.deadline
                            || op.targets.iter().map(|t| &t.device).collect::<Vec<_>>()
                                != self
                                    .value
                                    .targets
                                    .iter()
                                    .map(|t| &t.device)
                                    .collect::<Vec<_>>()
                        {
                            bail!("operation response identity mismatch");
                        }
                        return Ok(op);
                    }
                    Ok(_) => bail!("invalid operation reply"),
                    Err(error)
                        if !connection.closed.is_cancelled()
                            && !error.to_string().contains("resume on current connection")
                            && !error.to_string().contains("CONFLICT") =>
                    {
                        return Err(error);
                    }
                    Err(_) => {}
                }
            }
            if now() >= self.value.deadline {
                bail!("operation timed out");
            }
            self.pause().await;
        }
    }
    pub async fn status(&self) -> Result<Operation> {
        let op = self
            .control(Control::ResumeOperation {
                id: self.value.id.clone(),
            })
            .await?;
        if op.state != OperationState::Pending {
            bail!("operation has ended");
        }
        Ok(op)
    }
    pub async fn pause(&self) {
        tokio::select! { _=self.hub.changed.notified()=>{}, _=tokio::time::sleep(Duration::from_millis(250))=>{} }
    }
    pub async fn finish(&self, completed: bool) -> Result<()> {
        let op = self
            .control(Control::EndOperation {
                id: self.value.id.clone(),
                completed,
            })
            .await?;
        self.finished.store(true, Ordering::Release);
        if completed && op.state != OperationState::Completed {
            bail!("operation ended before result was accepted");
        }
        Ok(())
    }
    pub async fn abandon(&self, peer: &str) -> Result<()> {
        self.control(Control::AbandonTarget {
            id: self.value.id.clone(),
            peer: peer.into(),
        })
        .await?;
        Ok(())
    }
    pub async fn ready(&self) -> Result<Vec<String>> {
        loop {
            let op = self.status().await?;
            self.hub.authorized(&op.channel, &op.initiator)?;
            let connection = self.hub.connection();
            match self.hub.peers(&op.channel).await {
                Ok(online) => {
                    return Ok(op
                        .targets
                        .iter()
                        .filter(|t| {
                            t.state == TargetState::Pending
                                && (online.contains(&t.device) || t.device == op.initiator)
                        })
                        .map(|t| t.device.clone())
                        .collect());
                }
                Err(_) if connection.closed.is_cancelled() => self.pause().await,
                Err(error) => return Err(error),
            }
        }
    }
    pub fn watch(&self, stop: CancellationToken) -> tokio::task::JoinHandle<()> {
        let hub = self.hub.clone();
        let id = self.value.id.clone();
        let deadline = self.value.deadline;
        tokio::spawn(async move {
            loop {
                tokio::select! { _=stop.cancelled()=>break, _=tokio::time::sleep(Duration::from_millis(500))=>{} }
                if now() >= deadline {
                    stop.cancel();
                    break;
                }
                let connection = hub.connection();
                if connection.closed.is_cancelled() {
                    continue;
                }
                if !matches!(
                    connection
                        .request(Control::OperationStatus { id: id.clone() })
                        .await,
                    Ok(Reply::Operation(Operation {
                        state: OperationState::Pending,
                        ..
                    }))
                ) {
                    stop.cancel();
                    break;
                }
            }
        })
    }
}
impl Drop for QueuedOperation {
    fn drop(&mut self) {
        if self.finished.load(Ordering::Acquire) {
            return;
        }
        let hub = self.hub.clone();
        let id = self.value.id.clone();
        let deadline = self.value.deadline;
        tokio::spawn(async move {
            loop {
                let connection = hub.connection();
                if matches!(
                    connection
                        .request(Control::EndOperation {
                            id: id.clone(),
                            completed: false
                        })
                        .await,
                    Ok(Reply::Operation(_))
                ) {
                    break;
                }
                if now() >= deadline {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        });
    }
}

/// Write before executing. A crash between claim and completion is deliberately
/// an unknown result, never permission to repeat a private operation.
pub fn record_execution(app: &App, op: &Operation) -> Result<()> {
    if !hibiki_lib::channel::valid_id(&op.id)
        || op.deadline <= now()
        || op.deadline > now() + MAX_OPERATION_TTL
    {
        bail!("invalid execution identity or deadline");
    }
    let directory = app.paths.data.join("operations");
    private_dir(&directory)?;
    for entry in std::fs::read_dir(&directory)? {
        let path = entry?.path();
        if let Ok(bytes) = read_private(&path)
            && let Ok(deadline) = decode::<u64>(&bytes)
            && deadline.saturating_add(30) < now()
        {
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    let path = directory.join(&op.id);
    if path.exists() {
        bail!("operation already executed or execution result unknown");
    }
    atomic_write(&path, &encode(&op.deadline)?)
}

// Round the absolute wire timestamp up. Rounding down would cut up to a second
// from a command's configured wait. The caller's monotonic timeout remains exact.
fn deadline_after(timestamp: Duration, timeout_seconds: u64) -> u64 {
    let end = timestamp + Duration::from_secs(timeout_seconds);
    end.as_secs() + u64::from(end.subsec_nanos() != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fractional_wall_clock_does_not_shorten_operation_timeout() {
        for fraction in [0, 1, 250, 750, 999] {
            for timeout in [1, 120, 3600] {
                let timestamp = Duration::from_secs(1000) + Duration::from_millis(fraction);
                let remaining = Duration::from_secs(deadline_after(timestamp, timeout)) - timestamp;
                assert!(remaining >= Duration::from_secs(timeout));
                assert!(remaining < Duration::from_secs(timeout + 1));
                assert!(
                    deadline_after(timestamp, timeout) <= timestamp.as_secs() + MAX_OPERATION_TTL
                );
            }
        }
    }
    #[test]
    fn execution_record_survives_reopening_and_rejects_invalid_paths() {
        let dir = tempfile::tempdir().unwrap();
        let app = App {
            paths: hibiki_lib::paths::AppPaths::resolve(
                &Default::default(),
                dir.path(),
                dir.path(),
                unsafe { libc::geteuid() },
            ),
            config: crate::storage::Config::default(),
            config_file: dir.path().join("client.toml"),
            identity: Arc::new(
                hibiki_lib::identity::Identity::generate("executor".into()).unwrap(),
            ),
        };
        let mut op = Operation {
            id: random_id(),
            channel: random_id(),
            initiator: app.identity.device.id(),
            service: ServiceKind::Pinentry,
            deadline: now() + 120,
            state: OperationState::Pending,
            targets: Vec::new(),
        };
        record_execution(&app, &op).unwrap();
        let reopened = app.clone();
        assert!(
            record_execution(&reopened, &op)
                .unwrap_err()
                .to_string()
                .contains("already executed")
        );
        assert_eq!(
            decode::<u64>(&read_private(&app.paths.data.join("operations").join(&op.id)).unwrap())
                .unwrap(),
            op.deadline
        );
        op.id = "../identity.bin".into();
        assert!(record_execution(&app, &op).is_err());
        assert!(!app.paths.data.join("identity.bin").exists());
        op.id = random_id();
        op.deadline = now() - 1;
        assert!(record_execution(&app, &op).is_err());
    }
}
