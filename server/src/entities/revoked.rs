/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

use sea_orm::entity::prelude::*;
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "admin_revocations")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub channel: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub device: String,
    pub revoked_at: i64,
}
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}
