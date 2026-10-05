/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

//! Shared desktop and mobile transport, trust storage, and service sessions.
pub mod endpoint;
pub mod management;
pub mod network;
pub mod operation;
pub mod provider;
pub mod session;
pub mod storage;
mod tls;

pub mod preparation;
