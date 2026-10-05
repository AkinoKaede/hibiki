//! Durable metadata only. Service's channel authority locks exclude membership
//! changes during execution claims, operation locks serialize state transitions,
//! and its admission lock protects global queue limits. No Assuan plaintext is stored.
use crate::{db::Database, entities::operation};
use anyhow::{Context, Result, bail};
use hibiki_lib::{channel::valid_id, decode, encode, now, protocol::*};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, Set, TransactionTrait,
};

impl Database {
    /// Read immutable routing metadata without expiring or canceling an operation.
    /// The service must load and validate the full operation again under authority.
    pub async fn operation_channel(&self, caller: &str, id: &str) -> Result<String> {
        let row = operation::Entity::find_by_id(id)
            .one(&self.connection)
            .await?
            .context("operation not found")?;
        let op: Operation = decode(&row.data)?;
        if op.initiator != caller && !op.targets.iter().any(|t| t.device == caller) {
            bail!("unauthorized operation");
        }
        Ok(op.channel)
    }
    pub async fn queued_for(&self, device: &str) -> Result<Vec<(Operation, String)>> {
        let rows = operation::Entity::find()
            .filter(operation::Column::Active.eq(true))
            .filter(operation::Column::Deadline.gt(now() as i64))
            .all(&self.connection)
            .await?;
        let mut result = Vec::new();
        for row in rows {
            let op: Operation = decode(&row.data)?;
            if op
                .targets
                .iter()
                .any(|t| t.device == device && t.state == TargetState::Pending)
            {
                result.push((op, row.connection));
            }
        }
        Ok(result)
    }
    pub async fn queue_operation(
        &self,
        caller: &str,
        connection: &str,
        op: Operation,
    ) -> Result<Operation> {
        if !valid_id(&op.id)
            || op.initiator != caller
            || op.deadline <= now()
            || op.deadline > now() + MAX_OPERATION_TTL
            || op.state != OperationState::Pending
            || op.targets.is_empty()
            || op.targets.len() > 128
            || op.targets.iter().any(|t| t.state != TargetState::Pending)
        {
            bail!("invalid queued operation");
        }
        let state = self.get(&op.channel).await?.verify()?;
        state.member(caller)?;
        self.require_access(&op.channel, caller).await?;
        let mut devices = std::collections::HashSet::new();
        for target in &op.targets {
            state.member(&target.device)?;
            self.require_access(&op.channel, &target.device).await?;
            if !devices.insert(&target.device) {
                bail!("duplicate operation target");
            }
        }
        if let Some(row) = operation::Entity::find_by_id(&op.id)
            .one(&self.connection)
            .await?
        {
            let saved: Operation = decode(&row.data)?;
            if saved.initiator != caller
                || saved.channel != op.channel
                || saved.deadline != op.deadline
                || saved.service != op.service
                || saved.targets.iter().map(|t| &t.device).collect::<Vec<_>>()
                    != op.targets.iter().map(|t| &t.device).collect::<Vec<_>>()
            {
                bail!("operation identity conflict");
            }
            return self.resume_operation(caller, connection, &op.id).await;
        }
        operation::Entity::delete_many()
            .filter(operation::Column::Deadline.lt(now().saturating_sub(30) as i64))
            .exec(&self.connection)
            .await?;
        let live = operation::Entity::find()
            .filter(operation::Column::Active.eq(true))
            .filter(operation::Column::Deadline.gt(now() as i64));
        if live.clone().count(&self.connection).await? >= 4096
            || live
                .clone()
                .filter(operation::Column::Initiator.eq(caller))
                .count(&self.connection)
                .await?
                >= 128
        {
            bail!("operation queue full");
        }
        let rows = live.all(&self.connection).await?;
        for target in &op.targets {
            let mut count = 0;
            for row in &rows {
                let other: Operation = decode(&row.data)?;
                if other.targets.iter().any(|t| t.device == target.device) {
                    count += 1;
                }
            }
            if count >= 128 {
                bail!("target operation queue full");
            }
        }
        let tx = self.connection.begin().await?;
        // Serialize with local administrator revocation in another process.
        crate::entities::channel::Entity::update_many()
            .col_expr(
                crate::entities::channel::Column::Head,
                sea_orm::sea_query::Expr::col(crate::entities::channel::Column::Head),
            )
            .filter(crate::entities::channel::Column::Id.eq(&op.channel))
            .exec(&tx)
            .await?;
        for device in std::iter::once(&op.initiator).chain(op.targets.iter().map(|t| &t.device)) {
            if crate::entities::revoked::Entity::find_by_id((op.channel.clone(), device.clone()))
                .one(&tx)
                .await?
                .is_some()
            {
                bail!("device access revoked by server administrator");
            }
        }
        operation::ActiveModel {
            id: Set(op.id.clone()),
            initiator: Set(caller.into()),
            channel: Set(op.channel.clone()),
            deadline: Set(op.deadline as i64),
            active: Set(true),
            connection: Set(connection.into()),
            data: Set(encode(&op)?),
        }
        .insert(&tx)
        .await?;
        tx.commit().await?;
        Ok(op)
    }
    pub async fn operation(&self, caller: &str, id: &str) -> Result<(Operation, String)> {
        self.operation_scoped(caller, id, None).await
    }
    pub async fn operation_in_channel(
        &self,
        caller: &str,
        id: &str,
        channel: &str,
    ) -> Result<(Operation, String)> {
        self.operation_scoped(caller, id, Some(channel)).await
    }
    async fn operation_scoped(
        &self,
        caller: &str,
        id: &str,
        channel: Option<&str>,
    ) -> Result<(Operation, String)> {
        let row = operation::Entity::find_by_id(id)
            .one(&self.connection)
            .await?
            .context("operation not found")?;
        let mut op: Operation = decode(&row.data)?;
        // Expired IDs may be purged and reused. Never mutate a replacement
        // operation under the authority lock of its former channel.
        if channel.is_some_and(|channel| channel != op.channel) {
            bail!("CONFLICT: operation channel changed; retry status");
        }
        if op.initiator != caller && !op.targets.iter().any(|t| t.device == caller) {
            bail!("unauthorized operation");
        }
        let authorized = if self.exists(&op.channel).await? {
            let state = self.get(&op.channel).await?.verify()?;
            state.member(caller).is_ok()
                && state.member(&op.initiator).is_ok()
                && self.require_access(&op.channel, caller).await.is_ok()
                && self
                    .require_access(&op.channel, &op.initiator)
                    .await
                    .is_ok()
        } else {
            false
        };
        let previous = op.clone();
        if op.state == OperationState::Pending {
            if op.deadline <= now() {
                op.state = OperationState::Expired;
            } else if !authorized {
                op.state = OperationState::Canceled;
            }
            if op.state != OperationState::Pending {
                self.save_operation(&op, &row.connection, &previous).await?;
            }
        }
        if !authorized && op.initiator != caller {
            bail!("operation membership removed");
        }
        Ok((op, row.connection))
    }
    /// Compare the complete previous state in the UPDATE so independent database
    /// writers cannot both claim a pending target or overwrite a terminal state.
    pub async fn save_operation(
        &self,
        op: &Operation,
        connection: &str,
        previous: &Operation,
    ) -> Result<()> {
        use sea_orm::sea_query::Expr;
        let result = operation::Entity::update_many()
            .col_expr(
                operation::Column::Active,
                Expr::value(op.state == OperationState::Pending),
            )
            .col_expr(
                operation::Column::Connection,
                Expr::value(connection.to_owned()),
            )
            .col_expr(operation::Column::Data, Expr::value(encode(op)?))
            .filter(operation::Column::Id.eq(&op.id))
            .filter(operation::Column::Data.eq(encode(previous)?))
            .exec(&self.connection)
            .await?;
        if result.rows_affected != 1 {
            bail!("CONFLICT: operation changed; retry status");
        }
        Ok(())
    }
    pub async fn resume_operation(
        &self,
        caller: &str,
        connection: &str,
        id: &str,
    ) -> Result<Operation> {
        let (op, saved_connection) = self.operation(caller, id).await?;
        if op.initiator != caller {
            bail!("only initiator can resume operation");
        }
        if saved_connection != connection {
            self.save_operation(&op, connection, &op).await?;
        }
        Ok(op)
    }
}
