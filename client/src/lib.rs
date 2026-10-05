/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

pub mod assuan_io;
pub mod daemon;
pub mod diagnostics;
pub mod endpoint;
pub mod frontend;
pub mod network;
pub mod pairing;
pub mod provider;
pub mod proxy;
pub mod stdio;
pub mod storage;
pub mod terminal;

pub mod management;
pub mod presentation;
pub mod tui;

mod card_pool;
