/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

//! Typed management shared by the CLI and TUI. Never registers as an executor.
use crate::{
    diagnostics,
    network::Connection,
    storage::{App, Config},
};
use anyhow::{Context, Result, bail};
use hibiki_core::management::{append, leave, refresh, validate_pending};
use hibiki_lib::invitation::{AdmissionRequest, VerificationCode};
use hibiki_lib::{
    channel::*,
    now,
    protocol::{Control, JoinState, Reply},
};
use serde::Serialize;
use zeroize::Zeroizing;

#[derive(Clone, Serialize)]
pub struct DeviceRow {
    pub id: String,
    pub name: String,
    pub local: bool,
    pub online: Option<bool>,
    pub verification_words: String,
    pub approved_by: Option<String>,
    pub approver_name: Option<String>,
    pub can_revoke: bool,
    pub revoked_by_server: bool,
    pub reverse_revoke_available_at: Option<u64>,
}
#[derive(Clone, Serialize)]
pub struct PendingRow {
    pub id: String,
    pub verification: String,
    pub channel: String,
    pub channel_name: String,
    pub device: DeviceRow,
    pub created_at: u64,
    pub own: bool,
}
#[derive(Clone, Serialize)]
pub struct ChannelRow {
    pub id: String,
    pub name: String,
    pub selected: bool,
    pub member: bool,
    pub revision: u64,
    pub available: bool,
    pub devices: Vec<DeviceRow>,
    pub pending: Vec<PendingRow>,
    pub error: Option<String>,
}
#[derive(Clone, Serialize)]
pub struct Snapshot {
    pub schema_version: u16,
    pub captured_at: u64,
    pub relay_connected: bool,
    pub local_device: DeviceRow,
    pub channels: Vec<ChannelRow>,
    pub config: Config,
    #[serde(skip)]
    pub config_source: Vec<u8>,
    pub running_config: Option<Config>,
    pub daemon_running: bool,
    pub daemon_relay_connected: bool,
    pub allow_channel_creation: bool,
}
#[derive(Clone, Serialize)]
pub struct JoinResult {
    pub verification: String,
    pub channel: String,
    pub name: String,
    pub request: Option<String>,
}

pub struct Manager {
    pub app: App,
    pub connection: std::sync::Arc<Connection>,
}
impl Drop for Manager {
    fn drop(&mut self) {
        self.connection.close();
    }
}
impl Manager {
    pub async fn connect(app: App) -> Result<Self> {
        let (connection, mut events) =
            Connection::open(&app.config.server, app.config.allow_insecure, &app.identity).await?;
        // This connection only manages membership. Announce would replace/interfere with the daemon.
        tokio::spawn(async move { while events.recv().await.is_some() {} });
        Ok(Self { app, connection })
    }
    pub async fn rename(&mut self, name: String) -> Result<()> {
        let identity = hibiki_core::management::rename(&self.app, &self.connection, name).await?;
        let bytes = hibiki_lib::encode_secret(&identity)?;
        crate::storage::atomic_write(&self.app.paths.data.join("identity.bin"), &bytes)?;
        self.app.identity = std::sync::Arc::new(identity);
        Ok(())
    }
    pub async fn pending(&self, channel: &str) -> Result<Vec<AdmissionRequest>> {
        let state = refresh(&self.app, &self.connection, channel)
            .await?
            .verify()?;
        let Reply::Requests(mut requests) = self
            .connection
            .request(Control::Pending {
                channel: channel.into(),
            })
            .await?
        else {
            bail!("invalid pending response")
        };
        for request in &requests {
            validate_pending(request, &state)?;
        }
        requests.sort_by_key(|r| (r.body.created_at, r.id().unwrap_or_default()));
        Ok(requests)
    }
    pub async fn snapshot(&self) -> Result<Snapshot> {
        let mut snapshot = local_snapshot(&self.app).await?;
        if self.connection.closed.is_cancelled() {
            bail!("server disconnected");
        }
        let Reply::Policy {
            allow_client_channel_creation,
        } = self.connection.request(Control::Policy).await?
        else {
            bail!("invalid server policy")
        };
        snapshot.relay_connected = true;
        snapshot.allow_channel_creation = allow_client_channel_creation;
        for row in &mut snapshot.channels {
            match self.channel(&row.id).await {
                Ok(current) => *row = current,
                Err(error) => {
                    row.available = false;
                    row.error = Some(format!("{error:#}"));
                }
            }
        }
        Ok(snapshot)
    }
    pub async fn channel(&self, id: &str) -> Result<ChannelRow> {
        let (proof, denied) = match refresh(&self.app, &self.connection, id).await {
            Ok(proof) => (proof, false),
            Err(e)
                if e.downcast_ref::<hibiki_lib::protocol::WireError>()
                    .is_some_and(|e| e.code == "access_revoked") =>
            {
                (self.app.proof(id)?, true)
            }
            Err(e) => return Err(e),
        };
        let state = proof.verify()?;
        let mut row = channel_row(&self.app, &state)?;
        row.member &= !denied;
        row.available = true;
        if row.member {
            let Reply::ChannelSnapshot {
                proof,
                online,
                revoked,
            } = self
                .connection
                .request(Control::ChannelSnapshot { channel: id.into() })
                .await?
            else {
                bail!("invalid peer response")
            };
            if proof.genesis.body.id != id {
                bail!("snapshot channel mismatch");
            }
            let current = self.app.merge(proof)?.verify()?;
            row = channel_row(&self.app, &current)?;
            row.available = true;
            for device in &mut row.devices {
                device.online = Some(online.contains(&device.id));
                device.revoked_by_server = revoked.contains(&device.id);
                if device.revoked_by_server {
                    device.can_revoke = false;
                }
            }
        }
        // The relay exposes all requests to members, and only one's own to applicants.
        let Reply::Requests(requests) = self
            .connection
            .request(Control::Pending { channel: id.into() })
            .await?
        else {
            bail!("invalid pending response")
        };
        for request in requests {
            validate_pending(&request, &state)?;
            row.pending.push(pending_row(&self.app, &state, &request)?);
        }
        row.pending.sort_by_key(|r| (r.created_at, r.id.clone()));
        Ok(row)
    }
    pub async fn resolve_request(&self, channel: &str, prefix: &str) -> Result<String> {
        let ids = self
            .pending(channel)
            .await?
            .iter()
            .map(|r| r.id())
            .collect::<hibiki_lib::Result<Vec<_>>>()?;
        Ok(hibiki_lib::selection::resolve_id(
            prefix,
            ids.iter().map(String::as_str),
        )?)
    }
    pub async fn resolve_device(&self, channel: &str, prefix: &str) -> Result<String> {
        let state = refresh(&self.app, &self.connection, channel)
            .await?
            .verify()?;
        Ok(hibiki_lib::selection::resolve_id(
            prefix,
            state.members().keys().map(String::as_str),
        )?)
    }
    pub async fn approve(&self, channel: &str, request_id: &str) -> Result<()> {
        let request = self
            .pending(channel)
            .await?
            .into_iter()
            .find(|r| r.id().is_ok_and(|id| id == request_id))
            .context("request no longer pending; refresh and compare the identity again")?;
        append(
            &self.app,
            &self.connection,
            channel,
            MembershipAction::Accept(request),
        )
        .await
    }
    pub async fn reject(&self, channel: &str, request: &str) -> Result<()> {
        let state = refresh(&self.app, &self.connection, channel)
            .await?
            .verify()?;
        state.member(&self.app.identity.device.id())?;
        let Reply::Ok = self
            .connection
            .request(Control::RejectJoin {
                channel: channel.into(),
                request: request.into(),
            })
            .await?
        else {
            bail!("invalid rejection response")
        };
        Ok(())
    }
    pub async fn revoke(&self, channel: &str, device: &str, revision: u64) -> Result<Vec<String>> {
        hibiki_core::management::revoke(&self.app, &self.connection, channel, device, revision)
            .await
    }
    pub async fn leave(&mut self, channel: &str) -> Result<()> {
        leave(&self.app, &self.connection, channel).await?;
        let mut latest = App::load(Some(&self.app.config_file))?;
        if latest.config.default_channel.as_deref() == Some(channel) {
            latest.config.default_channel = None;
            latest.save_config()?;
        }
        self.app = latest;
        Ok(())
    }
    pub fn select(&mut self, channel: &str) -> Result<()> {
        self.app = select_channel(&self.app, channel)?;
        Ok(())
    }

    pub async fn invitation(&self, channel: &str) -> Result<Zeroizing<String>> {
        hibiki_core::management::invitation(&self.app, &self.connection, channel)
            .await?
            .export()
            .map_err(Into::into)
    }
    pub async fn create(&self, name: String) -> Result<Zeroizing<String>> {
        hibiki_core::management::create_channel(&self.app, &self.connection, name)
            .await?
            .export()
            .map_err(Into::into)
    }
    pub async fn join(&self, text: String) -> Result<JoinResult> {
        let text = Zeroizing::new(text);
        let result = hibiki_core::management::join(&self.app, &self.connection, &text).await?;
        Ok(JoinResult {
            channel: result.channel,
            name: result.name,
            request: result.request,
            verification: result.verification,
        })
    }
    pub async fn join_status(&self, channel: &str, request: &str) -> Result<JoinState> {
        let Reply::JoinStatus(status) = self
            .connection
            .request(Control::JoinStatus {
                channel: channel.into(),
                request: request.into(),
            })
            .await?
        else {
            bail!("invalid join status")
        };
        Ok(status)
    }
}
pub fn pending_row(
    app: &App,
    state: &VerifiedChannelState,
    request: &AdmissionRequest,
) -> Result<PendingRow> {
    validate_pending(request, state)?;
    Ok(PendingRow {
        id: request.id()?,
        verification: VerificationCode::new(app.config.server.clone(), request)?.export()?,
        channel: state.id.clone(),
        channel_name: state.name.clone(),
        device: device_row(app, &request.body.device)?,
        created_at: request.body.created_at,
        own: request.body.device.id() == app.identity.device.id(),
    })
}
fn device_row(app: &App, device: &hibiki_lib::identity::Device) -> Result<DeviceRow> {
    Ok(DeviceRow {
        id: device.id(),
        name: device.name.clone(),
        local: device.id() == app.identity.device.id(),
        online: None,
        verification_words: device.public_key_words()?,
        approved_by: None,
        approver_name: None,
        can_revoke: false,
        revoked_by_server: false,
        reverse_revoke_available_at: None,
    })
}
fn channel_row(app: &App, state: &VerifiedChannelState) -> Result<ChannelRow> {
    Ok(ChannelRow {
        id: state.id.clone(),
        name: state.name.clone(),
        selected: app.config.default_channel.as_deref() == Some(&state.id),
        member: state.member(&app.identity.device.id()).is_ok(),
        revision: state.sequence,
        available: false,
        devices: state
            .members()
            .values()
            .map(|d| {
                let mut row = device_row(app, d)?;
                row.approved_by = state.approved_by(&row.id).map(|d| d.id());
                row.approver_name = state.approved_by(&row.id).map(|d| d.name.clone());
                row.reverse_revoke_available_at =
                    state.reverse_revoke_available_at(&app.identity.device.id(), &row.id);
                row.can_revoke = state.can_revoke(&app.identity.device.id(), &row.id);
                Ok(row)
            })
            .collect::<Result<_>>()?,
        pending: Vec::new(),
        error: None,
    })
}
pub async fn local_snapshot(app: &App) -> Result<Snapshot> {
    let daemon = diagnostics::daemon_status(app).await.ok();
    Ok(Snapshot {
        schema_version: 1,
        captured_at: now(),
        relay_connected: false,
        local_device: device_row(app, &app.identity.device)?,
        channels: app
            .proofs()?
            .iter()
            .map(|p| channel_row(app, &p.verify()?))
            .collect::<Result<_>>()?,
        config: app.config.clone(),
        config_source: std::fs::read(&app.config_file)?,
        daemon_running: daemon.is_some(),
        daemon_relay_connected: daemon.as_ref().is_some_and(|d| d.relay_connected),
        running_config: daemon.map(|d| d.config),
        allow_channel_creation: false,
    })
}

pub fn select_channel(app: &App, channel: &str) -> Result<App> {
    app.proof(channel)?
        .verify()?
        .member(&app.identity.device.id())?;
    let mut latest = App::load(Some(&app.config_file))?;
    latest.config.default_channel = Some(channel.into());
    latest.save_config()?;
    Ok(latest)
}

pub async fn save_settings(
    app: &App,
    expected: &Config,
    source: &[u8],
    edited: &Config,
) -> Result<App> {
    let mut latest = App::load(Some(&app.config_file))?;
    if &latest.config != expected || std::fs::read(&app.config_file)? != source {
        bail!("configuration changed outside this screen; reload before saving");
    }
    if !(1..=3600).contains(&edited.operation_timeout_seconds) {
        bail!("timeout must be 1..3600 seconds");
    }
    // Only settings this screen owns may be changed; preserve relay, identity and default channel.
    latest.config.scdaemon = edited.scdaemon.clone();
    latest.config.pinentry = edited.pinentry.clone();
    latest.config.operation_timeout_seconds = edited.operation_timeout_seconds;
    for service in [
        hibiki_lib::protocol::ServiceKind::Scdaemon,
        hibiki_lib::protocol::ServiceKind::Pinentry,
    ] {
        if latest.config.service(service).enabled {
            crate::provider::program(&latest, service).await?;
        }
    }
    // Validation can await a subprocess; detect edits made while it was running too.
    if &App::load(Some(&app.config_file))?.config != expected
        || std::fs::read(&app.config_file)? != source
    {
        bail!("configuration changed while validating; reload before saving");
    }
    latest.save_config()?;
    Ok(latest)
}
