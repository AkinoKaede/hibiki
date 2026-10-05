/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    hibiki::frontend::run(hibiki_lib::protocol::ServiceKind::Pinentry).await
}
