use crate::entities::{channel, deleted, device, empty, invitation, pending, registry, revoked};
use anyhow::{Context, Result, bail};
use hibiki_lib::invitation::{
    AdmissionRequest, INVITATION_TTL, InvitationMetadata, OneTimeInvitation,
};
use hibiki_lib::{channel::*, decode, digest, encode, identity::Device, now, random_id};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, ConnectionTrait, DatabaseConnection,
    EntityTrait, QueryFilter, QueryOrder, Schema, Set, TransactionTrait,
    sea_query::{Expr, OnConflict},
};
use std::{collections::HashSet, path::Path, time::Duration};

#[derive(Clone)]
pub struct Database {
    pub(crate) connection: DatabaseConnection,
}
impl Database {
    pub async fn open(path: &Path) -> Result<Self> {
        let path = path.to_owned();
        let mut options = ConnectOptions::new("sqlite:");
        options
            .max_connections(5)
            .sqlx_logging(false)
            .map_sqlx_sqlite_opts(move |opts| {
                opts.filename(&path)
                    .create_if_missing(true)
                    .pragma("journal_mode", "WAL")
                    .busy_timeout(Duration::from_secs(5))
                    .foreign_keys(true)
            });
        let connection = sea_orm::Database::connect(options).await?;
        let db = Self { connection };
        db.initialize_schema().await?;
        Ok(db)
    }
    async fn initialize_schema(&self) -> Result<()> {
        let tx = self.connection.begin().await?;
        let schema = Schema::new(self.connection.get_database_backend());
        for mut statement in [
            schema.create_table_from_entity(invitation::Entity),
            schema.create_table_from_entity(device::Entity),
            schema.create_table_from_entity(channel::Entity),
            schema.create_table_from_entity(pending::Entity),
            schema.create_table_from_entity(registry::Entity),
            schema.create_table_from_entity(empty::Entity),
            schema.create_table_from_entity(deleted::Entity),
            schema.create_table_from_entity(revoked::Entity),
            schema.create_table_from_entity(crate::entities::operation::Entity),
        ] {
            tx.execute(statement.if_not_exists()).await?;
        }
        let version = tx
            .query_one_raw(sea_orm::Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                "PRAGMA user_version",
            ))
            .await?
            .context("database version unavailable")?
            .try_get_by_index::<i64>(0)?;
        if version < 3 {
            pending::Entity::delete_many().exec(&tx).await?;
            channel::Entity::update_many()
                .col_expr(channel::Column::Verifier, Expr::value(""))
                .exec(&tx)
                .await?;
            empty::Entity::update_many()
                .col_expr(empty::Column::Verifier, Expr::value(""))
                .exec(&tx)
                .await?;
            tx.execute_unprepared("PRAGMA user_version = 3").await?;
        }
        tx.commit().await?;
        Ok(())
    }
    pub async fn reserve(&self, server: String, name: String) -> Result<OneTimeInvitation> {
        let invite = OneTimeInvitation::new(server, random_id(), name, None)?;
        let tx = self.connection.begin().await?;
        registry::ActiveModel {
            id: Set(invite.metadata.channel.clone()),
            name: Set(invite.metadata.name.clone()),
        }
        .insert(&tx)
        .await
        .context("channel name already exists")?;
        empty::ActiveModel {
            id: Set(invite.metadata.channel.clone()),
            invitation: Set(Vec::new()),
            verifier: Set(String::new()),
        }
        .insert(&tx)
        .await?;
        insert_invitation(&tx, "", &invite.metadata).await?;
        tx.commit().await?;
        Ok(invite)
    }
    pub async fn reserve_invitation(
        &self,
        server: String,
        name: &str,
    ) -> Result<OneTimeInvitation> {
        let tx = self.connection.begin().await?;
        registry::Entity::update_many()
            .col_expr(registry::Column::Name, Expr::col(registry::Column::Name))
            .exec(&tx)
            .await?;
        let row = registry::Entity::find()
            .all(&tx)
            .await?
            .into_iter()
            .find(|r| r.id == name || r.name == name)
            .context("channel not found")?;
        if empty::Entity::find_by_id(&row.id).one(&tx).await?.is_none() {
            bail!("channel already has members; obtain an invitation from a member");
        }
        let invite = OneTimeInvitation::new(server, row.id, row.name, None)?;
        insert_invitation(&tx, "", &invite.metadata).await?;
        tx.commit().await?;
        Ok(invite)
    }
    pub async fn claim(
        &self,
        caller: &str,
        genesis: ChannelGenesis,
        invite: OneTimeInvitation,
    ) -> Result<MembershipProof> {
        genesis.verify()?;
        if genesis.body.version != 2
            || genesis.body.founder.id() != caller
            || genesis.body.id != invite.metadata.channel
            || genesis.body.name != invite.metadata.name
            || invite.metadata.genesis_hash.is_some()
        {
            bail!("invalid initialization claim");
        }
        let tx = self.connection.begin().await?;
        lock_channel(&tx, &genesis.body.id).await?;
        let row = check_invitation(&tx, &invite, None).await?;
        if let Some(existing) = channel::Entity::find_by_id(&genesis.body.id)
            .one(&tx)
            .await?
        {
            let proof: MembershipProof = decode(&existing.proof)?;
            if row.consumed_request.as_deref() == Some(caller)
                && proof.genesis == genesis
                && proof.verify()?.member(caller).is_ok()
                && access_revision(&tx, &genesis.body.id, caller).await? == 0
            {
                return Ok(proof);
            }
            bail!("initialization invitation already claimed");
        }
        if row.consumed_request.is_some()
            || empty::Entity::delete_by_id(&genesis.body.id)
                .exec(&tx)
                .await?
                .rows_affected
                != 1
        {
            bail!("channel already claimed or deleted");
        }
        let proof = MembershipProof {
            genesis,
            events: Vec::new(),
        };
        channel_model(&proof)?.insert(&tx).await?;
        invitation::Entity::update_many()
            .col_expr(invitation::Column::ConsumedRequest, Expr::value(caller))
            .filter(invitation::Column::Id.eq(&row.id))
            .exec(&tx)
            .await?;
        tx.commit().await?;
        Ok(proof)
    }
    pub async fn register_invitation(
        &self,
        caller: &str,
        metadata: InvitationMetadata,
    ) -> Result<()> {
        metadata.validate()?;
        let tx = self.connection.begin().await?;
        lock_channel(&tx, &metadata.channel).await?;
        require_access_tx(&tx, &metadata.channel, caller).await?;
        let proof = proof_tx(&tx, &metadata.channel).await?;
        let state = proof.verify()?;
        state.member(caller)?;
        if !state.invitations_enabled
            || metadata.genesis_hash != Some(state.genesis_hash)
            || metadata.issuer_admission != state.admission_id(caller).unwrap_or_default()
            || metadata.name != state.name
            || metadata.expires_at <= now()
            || metadata.expires_at > now().saturating_add(INVITATION_TTL + 30)
        {
            bail!("invalid invitation authority or expiry");
        }
        proof.verify_from(&state.genesis_hash, &metadata.checkpoint)?;
        if let Some(existing) = invitation::Entity::find_by_id(&metadata.id)
            .one(&tx)
            .await?
        {
            if existing.issuer != caller || existing.metadata != encode(&metadata)? {
                bail!("invitation ID already exists");
            }
        } else {
            insert_invitation(&tx, caller, &metadata).await?;
        }
        tx.commit().await?;
        Ok(())
    }
    pub async fn resolve_invitation(
        &self,
        caller: &str,
        invite: OneTimeInvitation,
    ) -> Result<(MembershipProof, u64)> {
        let tx = self.connection.begin().await?;
        lock_channel(&tx, &invite.metadata.channel).await?;
        let proof = proof_tx(&tx, &invite.metadata.channel).await?;
        let state = proof.verify()?;
        let row = check_invitation(&tx, &invite, Some(&state)).await?;
        if let Some(id) = row.consumed_request {
            let pending = pending::Entity::find_by_id(id)
                .one(&tx)
                .await?
                .context("invitation already used")?;
            let request: AdmissionRequest = decode(&pending.request)?;
            if request.body.device.id() != caller {
                bail!("invitation already used");
            }
        }
        let revision = access_revision(&tx, &state.id, caller).await?;
        Ok((proof, revision))
    }
    pub async fn admin_list(&self) -> Result<Vec<(String, String, bool)>> {
        let tx = self.connection.begin().await?;
        let empty_ids: HashSet<_> = empty::Entity::find()
            .all(&tx)
            .await?
            .into_iter()
            .map(|row| row.id)
            .collect();
        let result = registry::Entity::find()
            .order_by_asc(registry::Column::Name)
            .all(&tx)
            .await?
            .into_iter()
            .map(|row| {
                let vacant = empty_ids.contains(&row.id);
                (row.id, row.name, vacant)
            })
            .collect();
        tx.commit().await?;
        Ok(result)
    }
    pub async fn delete(&self, name: &str) -> Result<String> {
        let tx = self.connection.begin().await?;
        // Acquire the write lock before selecting so claim/delete cannot interleave.
        registry::Entity::update_many()
            .col_expr(registry::Column::Name, Expr::col(registry::Column::Name))
            .filter(registry::Column::Name.eq(name))
            .exec(&tx)
            .await?;
        let rows = registry::Entity::find().all(&tx).await?;
        let id = if let Some(row) = rows
            .iter()
            .find(|r| r.id == name)
            .or_else(|| rows.iter().find(|r| r.name == name))
        {
            row.id.clone()
        } else {
            hibiki_lib::selection::resolve_id(name, rows.iter().map(|r| r.id.as_str()))?
        };
        deleted::ActiveModel {
            id: Set(id.clone()),
            deleted_at: Set(now() as i64),
        }
        .insert(&tx)
        .await?;
        pending::Entity::delete_many()
            .filter(pending::Column::Channel.eq(&id))
            .exec(&tx)
            .await?;
        invitation::Entity::delete_many()
            .filter(invitation::Column::Channel.eq(&id))
            .exec(&tx)
            .await?;
        channel::Entity::delete_by_id(&id).exec(&tx).await?;
        empty::Entity::delete_by_id(&id).exec(&tx).await?;
        registry::Entity::delete_by_id(&id).exec(&tx).await?;
        tx.commit().await?;
        Ok(id)
    }
    pub async fn revoked(&self, channel: &str) -> Result<Vec<String>> {
        Ok(revoked::Entity::find()
            .filter(revoked::Column::Channel.eq(channel))
            .all(&self.connection)
            .await?
            .into_iter()
            .map(|r| r.device)
            .collect())
    }
    pub async fn require_access(&self, channel: &str, device: &str) -> Result<()> {
        if revoked::Entity::find_by_id((channel.to_owned(), device.to_owned()))
            .one(&self.connection)
            .await?
            .is_some()
        {
            return Err(hibiki_lib::protocol::WireError::new(
                "access_revoked",
                "device access revoked by server administrator",
            )
            .into());
        }
        Ok(())
    }
    /// Local administrator access revocation. Does not forge member-signed history.
    pub async fn admin_revoke(
        &self,
        name: &str,
        device: &str,
        subtree: bool,
    ) -> Result<(String, Vec<String>)> {
        use crate::entities::operation;
        use hibiki_lib::protocol::{Operation, OperationState};
        let tx = self.connection.begin().await?;
        registry::Entity::update_many()
            .col_expr(registry::Column::Name, Expr::col(registry::Column::Name))
            .exec(&tx)
            .await?;
        let rows = registry::Entity::find().all(&tx).await?;
        let id = rows
            .iter()
            .find(|r| r.id == name)
            .or_else(|| rows.iter().find(|r| r.name == name))
            .map(|r| r.id.clone())
            .map(Ok)
            .unwrap_or_else(|| {
                hibiki_lib::selection::resolve_id(name, rows.iter().map(|r| r.id.as_str()))
            })?;
        let row = channel::Entity::find_by_id(&id)
            .one(&tx)
            .await?
            .context("channel has no members")?;
        let proof: MembershipProof = decode(&row.proof)?;
        let state = proof.verify()?;
        let target =
            hibiki_lib::selection::resolve_id(device, state.members().keys().map(String::as_str))?;
        let affected = if subtree {
            state.revocation_subtree(&target)
        } else {
            vec![target]
        };
        for device in &affected {
            revoked::Entity::insert(revoked::ActiveModel {
                channel: Set(id.clone()),
                device: Set(device.clone()),
                revoked_at: Set(
                    (now() as i64).max(access_revision(&tx, &id, device).await? as i64 + 1)
                ),
            })
            .on_conflict(
                OnConflict::columns([revoked::Column::Channel, revoked::Column::Device])
                    .update_column(revoked::Column::RevokedAt)
                    .to_owned(),
            )
            .try_insert()
            .exec(&tx)
            .await?;
        }
        invalidate_invitations(&tx, &state).await?;
        for row in pending::Entity::find()
            .filter(pending::Column::Channel.eq(&id))
            .all(&tx)
            .await?
        {
            let request: AdmissionRequest = decode(&row.request)?;
            if affected.contains(&request.body.device.id()) {
                pending::Entity::delete_by_id(row.id).exec(&tx).await?;
            }
        }
        for row in operation::Entity::find()
            .filter(operation::Column::Channel.eq(&id))
            .filter(operation::Column::Active.eq(true))
            .all(&tx)
            .await?
        {
            let mut op: Operation = decode(&row.data)?;
            if affected.contains(&op.initiator)
                || op.targets.iter().any(|t| affected.contains(&t.device))
            {
                op.state = OperationState::Canceled;
                operation::Entity::update_many()
                    .col_expr(operation::Column::Active, Expr::value(false))
                    .col_expr(operation::Column::Data, Expr::value(encode(&op)?))
                    .filter(operation::Column::Id.eq(row.id))
                    .exec(&tx)
                    .await?;
            }
        }
        tx.commit().await?;
        Ok((id, affected))
    }
    pub async fn exists(&self, id: &str) -> Result<bool> {
        Ok(channel::Entity::find_by_id(id)
            .one(&self.connection)
            .await?
            .is_some())
    }
    pub async fn register(&self, device: &Device) -> Result<()> {
        device.verify()?;
        let bytes = encode(device)?;
        device::Entity::insert(device::ActiveModel {
            id: Set(device.id()),
            bundle: Set(bytes.clone()),
        })
        .on_conflict(
            OnConflict::column(device::Column::Id)
                .do_nothing()
                .to_owned(),
        )
        .try_insert()
        .exec(&self.connection)
        .await?;
        let existing = device::Entity::find_by_id(device.id())
            .one(&self.connection)
            .await?
            .context("device not found")?;
        let old: Device = hibiki_lib::decode(&existing.bundle)?;
        if old.signing_key != device.signing_key || old.noise_key != device.noise_key {
            bail!("device key binding changed; create a new identity");
        }
        Ok(())
    }
    pub async fn get(&self, id: &str) -> Result<MembershipProof> {
        let row = channel::Entity::find_by_id(id)
            .one(&self.connection)
            .await?
            .context("channel not found")?;
        let proof: MembershipProof = decode(&row.proof)?;
        proof.verify()?;
        Ok(proof)
    }
    pub async fn list(&self, device: &str) -> Result<Vec<MembershipProof>> {
        let rows = channel::Entity::find()
            .order_by_asc(channel::Column::Name)
            .all(&self.connection)
            .await?;
        let mut result = Vec::new();
        for row in rows {
            let proof: MembershipProof = decode(&row.proof)?;
            if proof.verify()?.member(device).is_ok() {
                result.push(proof);
            }
        }
        Ok(result)
    }
    pub async fn create(&self, caller: &str, genesis: ChannelGenesis) -> Result<MembershipProof> {
        genesis.verify()?;
        if genesis.body.version != 2 || genesis.body.founder.id() != caller {
            bail!("invalid channel creation authority");
        }
        let proof = MembershipProof {
            genesis,
            events: vec![],
        };
        let tx = self.connection.begin().await?;
        registry::ActiveModel {
            id: Set(proof.genesis.body.id.clone()),
            name: Set(proof.genesis.body.name.clone()),
        }
        .insert(&tx)
        .await
        .context("channel name or ID already exists")?;
        if deleted::Entity::find_by_id(&proof.genesis.body.id)
            .one(&tx)
            .await?
            .is_some()
        {
            bail!("deleted channel ID cannot be reused");
        }
        channel_model(&proof)?.insert(&tx).await?;
        tx.commit().await?;
        Ok(proof)
    }
    pub async fn join(
        &self,
        caller: &str,
        request: AdmissionRequest,
        invite: OneTimeInvitation,
    ) -> Result<()> {
        request.verify()?;
        let body = &request.body;
        if body.device.id() != caller
            || body.invitation_id != invite.metadata.id
            || body.channel_id != invite.metadata.channel
            || body.created_at > now() + 30
        {
            bail!("invalid admission request");
        }
        let tx = self.connection.begin().await?;
        lock_channel(&tx, &body.channel_id).await?;
        let state = proof_tx(&tx, &body.channel_id).await?.verify()?;
        let request_id = request.id()?;
        // A committed admission remains retryable if its inviter later departs.
        // This acknowledges the existing round only; it cannot restore lost access.
        if state.admission_id(caller) == Some(request_id.as_str())
            && state.member(caller).is_ok()
            && access_revision(&tx, &state.id, caller).await? == 0
        {
            let row = invitation::Entity::find_by_id(&body.invitation_id)
                .one(&tx)
                .await?
                .context("invitation not found")?;
            if row.consumed_request.as_deref() == Some(request_id.as_str())
                && row.metadata == encode(&invite.metadata)?
                && digest(&invite.key) == invite.metadata.key_hash
            {
                return Ok(());
            }
            bail!("invalid invitation");
        }
        let row = check_invitation(&tx, &invite, Some(&state)).await?;
        if let Some(used) = &row.consumed_request {
            if used == &request_id && pending::Entity::find_by_id(used).one(&tx).await?.is_some() {
                return Ok(());
            }
            bail!("invitation already used; obtain a new invitation");
        }
        state.validate_admission(&request)?;
        let revision = access_revision(&tx, &state.id, caller).await?;
        if revision != body.access_revision || (state.member(caller).is_ok() && revision == 0) {
            bail!("already a member or access changed; retry with a fresh request");
        }
        invitation::Entity::update_many()
            .col_expr(
                invitation::Column::ConsumedRequest,
                Expr::value(&request_id),
            )
            .filter(invitation::Column::Id.eq(&row.id))
            .exec(&tx)
            .await?;
        pending::ActiveModel {
            id: Set(request_id),
            channel: Set(state.id),
            request: Set(encode(&request)?),
            epoch: Set(0),
        }
        .insert(&tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn pending(&self, caller: &str, id: &str) -> Result<Vec<AdmissionRequest>> {
        let state = self.get(id).await?.verify()?;
        let member = state.member(caller).is_ok() && self.require_access(id, caller).await.is_ok();
        let rows = pending::Entity::find()
            .filter(pending::Column::Channel.eq(id))
            .order_by_asc(pending::Column::Id)
            .all(&self.connection)
            .await?;
        let requests: Vec<AdmissionRequest> = rows
            .into_iter()
            .map(|row| decode(&row.request).map_err(anyhow::Error::from))
            .collect::<Result<_>>()?;
        Ok(requests
            .into_iter()
            .filter(|request| member || request.body.device.id() == caller)
            .collect())
    }
    /// Remove exactly one request. The channel write lock serializes this with
    /// approval, revocation and deletion, including other database connections.
    pub async fn remove_pending(
        &self,
        caller: &str,
        id: &str,
        request_id: &str,
        withdraw: bool,
    ) -> Result<()> {
        let tx = self.connection.begin().await?;
        lock_channel(&tx, id).await?;
        let state = proof_tx(&tx, id).await?.verify()?;
        if !withdraw {
            require_access_tx(&tx, id, caller).await?;
            state.member(caller)?;
        }
        let row = pending::Entity::find_by_id(request_id)
            .filter(pending::Column::Channel.eq(id))
            .one(&tx)
            .await?
            .context("request is no longer pending")?;
        let request: AdmissionRequest = decode(&row.request)?;
        if withdraw && request.body.device.id() != caller {
            bail!("only the requesting device may withdraw its request");
        }
        pending::Entity::delete_by_id(row.id).exec(&tx).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Cancel all of this device's requests atomically with approval. Return the
    /// locked membership snapshot so a caller admitted first can sign its leave.
    pub async fn withdraw_pending(&self, caller: &str, id: &str) -> Result<MembershipProof> {
        let tx = self.connection.begin().await?;
        lock_channel(&tx, id).await?;
        let proof = proof_tx(&tx, id).await?;
        let rows = pending::Entity::find()
            .filter(pending::Column::Channel.eq(id))
            .all(&tx)
            .await?;
        for row in rows {
            let request: AdmissionRequest = decode(&row.request)?;
            if request.body.device.id() == caller {
                pending::Entity::delete_by_id(row.id).exec(&tx).await?;
            }
        }
        tx.commit().await?;
        Ok(proof)
    }

    pub async fn join_status(
        &self,
        caller: &str,
        id: &str,
        request_id: &str,
    ) -> Result<hibiki_lib::protocol::JoinState> {
        use hibiki_lib::protocol::JoinState;
        let tx = self.connection.begin().await?;
        let Some(channel) = channel::Entity::find_by_id(id).one(&tx).await? else {
            return Ok(JoinState::Absent);
        };
        let proof: MembershipProof = decode(&channel.proof)?;
        let state = proof.verify()?;
        if state.admission_id(caller) == Some(request_id)
            && state.member(caller).is_ok()
            && access_revision(&tx, id, caller).await? == 0
        {
            return Ok(JoinState::Member);
        }
        let row = pending::Entity::find_by_id(request_id)
            .filter(pending::Column::Channel.eq(id))
            .one(&tx)
            .await?;
        let Some(row) = row else {
            return Ok(JoinState::Absent);
        };
        let request: AdmissionRequest = decode(&row.request)?;
        if request.body.device.id() != caller {
            bail!("request belongs to another device");
        }
        Ok(JoinState::Pending)
    }

    pub async fn append(&self, caller: &str, event: MembershipEvent) -> Result<MembershipProof> {
        if event.body.issuer_device_id != caller || event.body.issued_at > now() + 30 {
            bail!("invalid issuer or timestamp");
        }
        if matches!(
            event.body.action,
            MembershipAction::Admit(_) | MembershipAction::ChangePsk { .. }
        ) {
            bail!("PSK admission is no longer supported");
        }
        let tx = self.connection.begin().await?;
        let id = &event.body.channel_id;
        lock_channel(&tx, id).await?;
        require_access_tx(&tx, id, caller).await?;
        let mut proof = proof_tx(&tx, id).await?;
        let old = proof.verify()?;
        old.member(caller)?;
        if event.body.previous_event_hash != old.head {
            bail!("CONFLICT: channel head changed");
        }
        if let MembershipAction::Revoke { device_id } = &event.body.action
            && !old.can_revoke_at(caller, device_id, now())
        {
            bail!("revocation is not yet permitted");
        }
        if let MembershipAction::Accept(request) = &event.body.action {
            if event.body.issued_at < now().saturating_sub(30) {
                bail!("admission timestamp must be current");
            }
            let row = pending::Entity::find_by_id(request.id()?)
                .filter(pending::Column::Channel.eq(id))
                .one(&tx)
                .await?
                .context("admission not pending")?;
            if row.request != encode(request)? {
                bail!("admission altered");
            }
            let grant = invitation::Entity::find_by_id(&request.body.invitation_id)
                .one(&tx)
                .await?
                .context("invitation missing")?;
            validate_issuer(&tx, &grant, &old).await?;
            let target = request.body.device.id();
            let revision = access_revision(&tx, id, &target).await?;
            if revision != request.body.access_revision
                || (old.member(&target).is_ok() && revision == 0)
            {
                bail!("membership changed since request");
            }
            pending::Entity::delete_by_id(row.id).exec(&tx).await?;
            revoked::Entity::delete_by_id((id.clone(), target))
                .exec(&tx)
                .await?;
        }
        proof.events.push(event.clone());
        let state = proof.verify()?;
        let encoded = encode(&proof)?;
        if encoded.len() > 1024 * 1024 {
            bail!("membership proof size limit");
        }
        channel::Entity::update_many()
            .col_expr(channel::Column::Proof, Expr::value(encoded))
            .col_expr(channel::Column::Head, Expr::value(state.head.to_vec()))
            .filter(channel::Column::Id.eq(id))
            .exec(&tx)
            .await?;
        invalidate_invitations(&tx, &state).await?;
        for row in pending::Entity::find()
            .filter(pending::Column::Channel.eq(id))
            .all(&tx)
            .await?
        {
            let request: AdmissionRequest = decode(&row.request)?;
            if state.validate_admission(&request).is_err() {
                pending::Entity::delete_by_id(row.id).exec(&tx).await?;
            }
        }
        tx.commit().await?;
        Ok(proof)
    }
}

fn channel_model(proof: &MembershipProof) -> Result<channel::ActiveModel> {
    let state = proof.verify()?;
    Ok(channel::ActiveModel {
        id: Set(state.id),
        name: Set(state.name),
        proof: Set(encode(proof)?),
        head: Set(state.head.to_vec()),
        verifier: Set(String::new()),
    })
}
async fn lock_channel(tx: &sea_orm::DatabaseTransaction, id: &str) -> Result<()> {
    let locked = registry::Entity::update_many()
        .col_expr(registry::Column::Name, Expr::col(registry::Column::Name))
        .filter(registry::Column::Id.eq(id))
        .exec(tx)
        .await?;
    if locked.rows_affected != 1 {
        bail!("channel not found or deleted");
    }
    Ok(())
}
async fn proof_tx(tx: &sea_orm::DatabaseTransaction, id: &str) -> Result<MembershipProof> {
    let row = channel::Entity::find_by_id(id)
        .one(tx)
        .await?
        .context("channel not found")?;
    let proof: MembershipProof = decode(&row.proof)?;
    proof.verify()?;
    Ok(proof)
}
async fn access_revision(
    tx: &sea_orm::DatabaseTransaction,
    channel: &str,
    device: &str,
) -> Result<u64> {
    Ok(
        revoked::Entity::find_by_id((channel.to_owned(), device.to_owned()))
            .one(tx)
            .await?
            .map(|r| r.revoked_at as u64)
            .unwrap_or(0),
    )
}
async fn require_access_tx(
    tx: &sea_orm::DatabaseTransaction,
    channel: &str,
    device: &str,
) -> Result<()> {
    if access_revision(tx, channel, device).await? != 0 {
        return Err(hibiki_lib::protocol::WireError::new(
            "access_revoked",
            "device access revoked by server administrator",
        )
        .into());
    }
    Ok(())
}
async fn insert_invitation(
    tx: &sea_orm::DatabaseTransaction,
    issuer: &str,
    metadata: &InvitationMetadata,
) -> Result<()> {
    invitation::ActiveModel {
        id: Set(metadata.id.clone()),
        channel: Set(metadata.channel.clone()),
        issuer: Set(issuer.into()),
        metadata: Set(encode(metadata)?),
        consumed_request: Set(None),
        invalidated: Set(false),
    }
    .insert(tx)
    .await?;
    Ok(())
}
async fn validate_issuer(
    tx: &sea_orm::DatabaseTransaction,
    row: &invitation::Model,
    state: &VerifiedChannelState,
) -> Result<()> {
    let metadata: InvitationMetadata = decode(&row.metadata)?;
    if row.invalidated
        || state.member(&row.issuer).is_err()
        || state.admission_id(&row.issuer) != Some(metadata.issuer_admission.as_str())
    {
        bail!("invitation issuer is no longer a member");
    }
    require_access_tx(tx, &state.id, &row.issuer).await
}
async fn check_invitation(
    tx: &sea_orm::DatabaseTransaction,
    invite: &OneTimeInvitation,
    state: Option<&VerifiedChannelState>,
) -> Result<invitation::Model> {
    invite.metadata.validate()?;
    let row = invitation::Entity::find_by_id(&invite.metadata.id)
        .one(tx)
        .await?
        .context("invitation not found")?;
    if row.metadata != encode(&invite.metadata)?
        || row.invalidated
        || digest(&invite.key) != invite.metadata.key_hash
    {
        bail!("invalid invitation");
    }
    if row.consumed_request.is_none() && now() >= invite.metadata.expires_at {
        bail!("invitation expired; obtain a new invitation");
    }
    if let Some(state) = state {
        if invite.metadata.genesis_hash != Some(state.genesis_hash) {
            bail!("invitation channel mismatch");
        }
        validate_issuer(tx, &row, state).await?;
    }
    Ok(row)
}
async fn invalidate_invitations(
    tx: &sea_orm::DatabaseTransaction,
    state: &VerifiedChannelState,
) -> Result<()> {
    for row in invitation::Entity::find()
        .filter(invitation::Column::Channel.eq(&state.id))
        .filter(invitation::Column::Invalidated.eq(false))
        .all(tx)
        .await?
    {
        if row.issuer.is_empty() {
            continue;
        }
        if validate_issuer(tx, &row, state).await.is_err() {
            invitation::Entity::update_many()
                .col_expr(invitation::Column::Invalidated, Expr::value(true))
                .filter(invitation::Column::Id.eq(&row.id))
                .exec(tx)
                .await?;
            if let Some(request) = row.consumed_request {
                pending::Entity::delete_by_id(request).exec(tx).await?;
            }
        }
    }
    Ok(())
}
