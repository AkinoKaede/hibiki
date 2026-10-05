use crate::entities::{channel, deleted, device, empty, pending, registry, revoked};
use anyhow::{Context, Result, bail};
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
        tx.commit().await?;
        Ok(())
    }
    pub async fn reserve(
        &self,
        server: String,
        name: String,
        verifier: String,
    ) -> Result<EmptyChannelInvite> {
        validate_verifier(&verifier)?;
        let invite = EmptyChannelInvite {
            version: 1,
            server,
            id: random_id(),
            name,
            psk_commitment: digest(verifier.as_bytes()),
        };
        invite.validate()?;
        let tx = self.connection.begin().await?;
        registry::ActiveModel {
            id: Set(invite.id.clone()),
            name: Set(invite.name.clone()),
        }
        .insert(&tx)
        .await
        .context("channel name already exists")?;
        empty::ActiveModel {
            id: Set(invite.id.clone()),
            invitation: Set(encode(&invite)?),
            verifier: Set(verifier),
        }
        .insert(&tx)
        .await?;
        tx.commit().await?;
        Ok(invite)
    }
    pub async fn claim(
        &self,
        caller: &str,
        genesis: ChannelGenesis,
        psk: String,
    ) -> Result<MembershipProof> {
        genesis.verify()?;
        if genesis.body.founder.id() != caller {
            bail!("invalid founder identity");
        }
        let row = empty::Entity::find_by_id(&genesis.body.id)
            .one(&self.connection)
            .await?
            .context("channel is not empty or was deleted")?;
        let invite: EmptyChannelInvite = decode(&row.invitation)?;
        invite.validate()?;
        if genesis.body.name != invite.name
            || genesis.body.psk_commitment != invite.psk_commitment
            || digest(row.verifier.as_bytes()) != invite.psk_commitment
        {
            bail!("initialization invitation mismatch");
        }
        let verifier_copy = row.verifier.clone();
        if !tokio::task::spawn_blocking(move || check_psk(&psk, &verifier_copy)).await? {
            bail!("incorrect PSK");
        }
        let proof = MembershipProof {
            genesis,
            events: vec![],
        };
        let tx = self.connection.begin().await?;
        let consumed = empty::Entity::delete_many()
            .filter(empty::Column::Id.eq(&invite.id))
            .filter(empty::Column::Invitation.eq(row.invitation))
            .filter(empty::Column::Verifier.eq(&row.verifier))
            .exec(&tx)
            .await?;
        if consumed.rows_affected != 1 {
            bail!("channel already claimed or deleted");
        }
        channel_model(&proof, row.verifier)?.insert(&tx).await?;
        tx.commit().await?;
        Ok(proof)
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
            bail!("device access revoked by server administrator");
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
                revoked_at: Set(now() as i64),
            })
            .on_conflict(
                OnConflict::columns([revoked::Column::Channel, revoked::Column::Device])
                    .do_nothing()
                    .to_owned(),
            )
            .try_insert()
            .exec(&tx)
            .await?;
        }
        for row in pending::Entity::find()
            .filter(pending::Column::Channel.eq(&id))
            .all(&tx)
            .await?
        {
            let request: JoinRequest = decode(&row.request)?;
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
    pub async fn create(
        &self,
        caller: &str,
        genesis: ChannelGenesis,
        verifier: String,
    ) -> Result<MembershipProof> {
        genesis.verify()?;
        if genesis.body.founder.id() != caller
            || digest(verifier.as_bytes()) != genesis.body.psk_commitment
        {
            bail!("invalid channel creation authority or verifier commitment");
        }
        validate_verifier(&verifier)?;
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
        channel_model(&proof, verifier)?.insert(&tx).await?;
        tx.commit().await?;
        Ok(proof)
    }
    pub async fn join(&self, caller: &str, request: JoinRequest, psk: String) -> Result<()> {
        request.verify()?;
        self.require_access(&request.body.channel_id, caller)
            .await?;
        let body = &request.body;
        let state = self.get(&body.channel_id).await?.verify()?;
        if body.device.id() != caller
            || body.genesis_hash != state.genesis_hash
            || body.psk_epoch != state.psk_epoch
            || body.created_at > now() + 30
            || state.member(caller).is_ok()
            || state.is_revoked(caller)
        {
            bail!("invalid admission request");
        }
        let row = channel::Entity::find_by_id(&state.id)
            .one(&self.connection)
            .await?
            .context("channel not found")?;
        if digest(row.verifier.as_bytes()) != state.psk_commitment {
            bail!("verifier commitment mismatch");
        }
        if !tokio::task::spawn_blocking(move || check_psk(&psk, &row.verifier)).await? {
            bail!("incorrect PSK");
        }
        let tx = self.connection.begin().await?;
        let unchanged = channel::Entity::update_many()
            .col_expr(channel::Column::Head, Expr::col(channel::Column::Head))
            .filter(channel::Column::Id.eq(&state.id))
            .filter(channel::Column::Head.eq(state.head.to_vec()))
            .exec(&tx)
            .await?;
        if unchanged.rows_affected != 1 {
            bail!("CONFLICT: channel changed; retry admission");
        }
        if revoked::Entity::find_by_id((state.id.clone(), caller.to_owned()))
            .one(&tx)
            .await?
            .is_some()
        {
            bail!("device access revoked by server administrator");
        }
        pending::Entity::insert(pending::ActiveModel {
            id: Set(request.id()?),
            channel: Set(state.id),
            request: Set(encode(&request)?),
            epoch: Set(body.psk_epoch as i64),
        })
        .on_conflict(
            OnConflict::column(pending::Column::Id)
                .do_nothing()
                .to_owned(),
        )
        .try_insert()
        .exec(&tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn pending(&self, caller: &str, id: &str) -> Result<Vec<JoinRequest>> {
        self.require_access(id, caller).await?;
        let state = self.get(id).await?.verify()?;
        let member = state.member(caller).is_ok();
        let rows = pending::Entity::find()
            .filter(pending::Column::Channel.eq(id))
            .filter(pending::Column::Epoch.eq(state.psk_epoch as i64))
            .order_by_asc(pending::Column::Id)
            .all(&self.connection)
            .await?;
        let requests: Vec<JoinRequest> = rows
            .into_iter()
            .map(|row| decode(&row.request).map_err(anyhow::Error::from))
            .collect::<Result<_>>()?;
        Ok(requests
            .into_iter()
            .filter(|request| member || request.body.device.id() == caller)
            .collect())
    }
    /// Remove exactly one request. The channel CAS serializes this with approval,
    /// rotation, revocation and deletion, including other database connections.
    pub async fn remove_pending(
        &self,
        caller: &str,
        id: &str,
        request_id: &str,
        withdraw: bool,
    ) -> Result<()> {
        let state = self.get(id).await?.verify()?;
        if !withdraw {
            self.require_access(id, caller).await?;
            state.member(caller)?;
        }
        let tx = self.connection.begin().await?;
        let locked = channel::Entity::update_many()
            .col_expr(channel::Column::Head, Expr::col(channel::Column::Head))
            .filter(channel::Column::Id.eq(id))
            .filter(channel::Column::Head.eq(state.head.to_vec()))
            .exec(&tx)
            .await?;
        if locked.rows_affected != 1 {
            bail!("CONFLICT: channel changed; retry");
        }
        let row = pending::Entity::find_by_id(request_id)
            .filter(pending::Column::Channel.eq(id))
            .filter(pending::Column::Epoch.eq(state.psk_epoch as i64))
            .one(&tx)
            .await?
            .context("request is no longer pending")?;
        let request: JoinRequest = decode(&row.request)?;
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
        let proof = self.get(id).await?;
        let state = proof.verify()?;
        let tx = self.connection.begin().await?;
        let locked = channel::Entity::update_many()
            .col_expr(channel::Column::Head, Expr::col(channel::Column::Head))
            .filter(channel::Column::Id.eq(id))
            .filter(channel::Column::Head.eq(state.head.to_vec()))
            .exec(&tx)
            .await?;
        if locked.rows_affected != 1 {
            bail!("CONFLICT: channel changed; retry");
        }
        let rows = pending::Entity::find()
            .filter(pending::Column::Channel.eq(id))
            .all(&tx)
            .await?;
        for row in rows {
            let request: JoinRequest = decode(&row.request)?;
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
        if revoked::Entity::find_by_id((id.to_owned(), caller.to_owned()))
            .one(&tx)
            .await?
            .is_some()
        {
            return Ok(JoinState::Absent);
        }
        if state.member(caller).is_ok() {
            return Ok(JoinState::Member);
        }
        let row = pending::Entity::find_by_id(request_id)
            .filter(pending::Column::Channel.eq(id))
            .filter(pending::Column::Epoch.eq(state.psk_epoch as i64))
            .one(&tx)
            .await?;
        let Some(row) = row else {
            return Ok(JoinState::Absent);
        };
        let request: JoinRequest = decode(&row.request)?;
        if request.body.device.id() != caller {
            bail!("request belongs to another device");
        }
        Ok(JoinState::Pending)
    }

    pub async fn append(
        &self,
        caller: &str,
        event: MembershipEvent,
        new_verifier: Option<String>,
    ) -> Result<MembershipProof> {
        if event.body.issuer_device_id != caller || event.body.issued_at > now() + 30 {
            bail!("invalid issuer or timestamp");
        }
        self.require_access(&event.body.channel_id, caller).await?;
        if matches!(event.body.action, MembershipAction::Admit(_))
            && event.body.issued_at < now().saturating_sub(30)
        {
            bail!("admission timestamp must be current");
        }
        if let MembershipAction::Admit(request) = &event.body.action {
            self.require_access(&event.body.channel_id, &request.body.device.id())
                .await?;
        }
        let mut proof = self.get(&event.body.channel_id).await?;
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
        proof.events.push(event.clone());
        let state = proof.verify()?;
        let encoded = encode(&proof)?;
        if encoded.len() > 1024 * 1024 {
            bail!("membership proof size limit");
        }
        let tx = self.connection.begin().await?;
        // CAS first acquires the SQLite write lock. Any validation failure below rolls it back.
        let mut update = channel::Entity::update_many()
            .col_expr(channel::Column::Proof, Expr::value(encoded))
            .col_expr(channel::Column::Head, Expr::value(state.head.to_vec()))
            .filter(channel::Column::Id.eq(&state.id))
            .filter(channel::Column::Head.eq(old.head.to_vec()));
        if let Some(verifier) = &new_verifier {
            update = update.col_expr(channel::Column::Verifier, Expr::value(verifier.clone()));
        }
        if update.exec(&tx).await?.rows_affected != 1 {
            bail!("CONFLICT: channel head changed");
        }
        if revoked::Entity::find_by_id((state.id.clone(), caller.to_owned()))
            .one(&tx)
            .await?
            .is_some()
        {
            bail!("device access revoked by server administrator");
        }
        if let MembershipAction::Admit(request) = &event.body.action
            && revoked::Entity::find_by_id((state.id.clone(), request.body.device.id()))
                .one(&tx)
                .await?
                .is_some()
        {
            bail!("device access revoked by server administrator");
        }
        match &event.body.action {
            MembershipAction::Admit(request) => {
                let row = pending::Entity::find_by_id(request.id()?)
                    .filter(pending::Column::Channel.eq(&state.id))
                    .one(&tx)
                    .await?
                    .context("admission not pending")?;
                if row.request != encode(request)? || row.epoch != old.psk_epoch as i64 {
                    bail!("admission altered");
                }
                if new_verifier.is_some() {
                    bail!("unexpected PSK verifier");
                }
                pending::Entity::delete_by_id(row.id).exec(&tx).await?;
            }
            MembershipAction::ChangePsk {
                verifier_commitment,
            } => {
                let verifier = new_verifier.as_ref().context("missing PSK verifier")?;
                validate_verifier(verifier)?;
                if &digest(verifier.as_bytes()) != verifier_commitment {
                    bail!("PSK commitment mismatch");
                }
                pending::Entity::delete_many()
                    .filter(pending::Column::Channel.eq(&state.id))
                    .exec(&tx)
                    .await?;
            }
            MembershipAction::Revoke { .. }
            | MembershipAction::RevokeSubtree { .. }
            | MembershipAction::Leave
            | MembershipAction::Rename { .. } => {
                if new_verifier.is_some() {
                    bail!("unexpected PSK verifier");
                }
            }
        }
        for row in pending::Entity::find()
            .filter(pending::Column::Channel.eq(&state.id))
            .all(&tx)
            .await?
        {
            let request: JoinRequest = decode(&row.request)?;
            // Subtree revocation also invalidates requests from departed identities in that branch.
            if matches!(
                event.body.action,
                MembershipAction::Revoke { .. } | MembershipAction::RevokeSubtree { .. }
            ) && state.is_revoked(&request.body.device.id())
            {
                pending::Entity::delete_by_id(row.id).exec(&tx).await?;
            }
        }
        tx.commit().await?;
        Ok(proof)
    }
}
fn channel_model(proof: &MembershipProof, verifier: String) -> Result<channel::ActiveModel> {
    let state = proof.verify()?;
    Ok(channel::ActiveModel {
        id: Set(state.id),
        name: Set(state.name),
        proof: Set(encode(proof)?),
        head: Set(state.head.to_vec()),
        verifier: Set(verifier),
    })
}
fn validate_verifier(value: &str) -> Result<()> {
    if value.len() > 256 || !value.starts_with("$argon2id$v=19$m=19456,t=2,p=1$") {
        bail!("PSK verifier must use the application Argon2id parameters");
    }
    Ok(())
}
