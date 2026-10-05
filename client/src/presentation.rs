/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

//! Terminal text is a presentation of typed management data, never a machine API.
use crate::management::{ChannelRow, DeviceRow, PendingRow};
use chrono::{Local, TimeZone};
use std::fmt::Write;

pub fn safe(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| {
            if c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}
pub fn quote(value: &str) -> String {
    format!("'{}'", safe(value).replace('\'', "'\\''"))
}
pub fn words(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .chunks(6)
        .map(|row| row.join(" "))
        .collect::<Vec<_>>()
        .join("\n")
}
pub fn timestamp(value: u64) -> String {
    let time = i64::try_from(value)
        .ok()
        .and_then(|v| Local.timestamp_opt(v, 0).single());
    let age = hibiki_lib::now().saturating_sub(value);
    let relative = if value > hibiki_lib::now() {
        "future timestamp".into()
    } else if age < 60 {
        format!("{age}s ago")
    } else if age < 3600 {
        format!("{}m ago", age / 60)
    } else {
        format!("{}h ago", age / 3600)
    };
    format!(
        "{} ({relative})",
        time.map(|t| t.format("%Y-%m-%d %H:%M:%S %:z").to_string())
            .unwrap_or_else(|| "Invalid timestamp".into())
    )
}
pub fn device_details(device: &DeviceRow) -> String {
    let approval = device
        .approved_by
        .as_ref()
        .map(|id| {
            format!(
                "\nApproved by: {}\nApprover ID: {}\nMay revoke: {}",
                safe(device.approver_name.as_deref().unwrap_or("Unknown")),
                id,
                if device.can_revoke { "Yes" } else { "No" }
            )
        })
        .unwrap_or_default();
    let approval = format!(
        "{approval}{}",
        device
            .reverse_revoke_available_at
            .map(|t| format!("\nAncestor revocation available: {}", timestamp(t)))
            .unwrap_or_default()
    );
    format!(
        "Device: {}{}\nDevice ID: {}\nOnline: {}{approval}\n\nVerification words:\n{}",
        safe(&device.name),
        if device.local { " (this device)" } else { "" },
        device.id,
        match device.online {
            _ if device.revoked_by_server => "Revoked by server",
            Some(true) => "Yes",
            Some(false) => "No",
            None => "Unknown (cached)",
        },
        words(&device.verification_words)
    )
}
pub fn pending_details(row: &PendingRow) -> String {
    format!(
        "Channel: {}\nChannel ID: {}\nRequest ID: {}\nStatus: Awaiting approval\nRequested: {}\n\n{}",
        safe(&row.channel_name),
        row.channel,
        row.id,
        timestamp(row.created_at),
        device_details(&row.device)
    )
}
pub fn pending(name: &str, channel: &str, rows: &[PendingRow]) -> String {
    let mut out = format!(
        "Pending requests · {}\nChannel ID: {channel}\nRequests: {}\n",
        safe(name),
        rows.len()
    );
    if rows.is_empty() {
        out.push_str("\nNo pending requests.\n");
        return out;
    }
    for (i, row) in rows.iter().enumerate() {
        let _ = writeln!(
            out,
            "\n{}. {}\n   Status:     Awaiting approval\n   Request ID: {}\n   Device ID:  {}\n   Requested:  {}",
            i + 1,
            safe(&row.device.name),
            row.id,
            row.device.id,
            timestamp(row.created_at)
        );
    }
    let _ = writeln!(
        out,
        "\nReview and approve:\n  hibiki channel approve {}\nReject a request:\n  hibiki channel reject {} <REQUEST_ID>",
        quote(channel),
        quote(channel)
    );
    out
}
fn table(headers: &[&str], rows: &[Vec<String>], limit: usize) -> String {
    use unicode_width::UnicodeWidthStr;
    let rows: Vec<Vec<String>> = rows
        .iter()
        .map(|row| row.iter().map(|v| safe(v)).collect())
        .collect();
    let widths: Vec<usize> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| {
            rows.iter()
                .map(|r| r[i].width())
                .max()
                .unwrap_or(0)
                .max(h.width())
        })
        .collect();
    let mut out = String::new();
    if widths.iter().sum::<usize>() + (headers.len() - 1) * 2 > limit {
        // Keep full IDs on narrow terminals and let the terminal wrap values.
        for row in &rows {
            for (header, value) in headers.iter().zip(row) {
                let _ = writeln!(out, "{header}: {value}");
            }
            out.push('\n');
        }
    } else {
        for row in
            std::iter::once(headers.iter().map(|h| h.to_string()).collect::<Vec<_>>()).chain(rows)
        {
            for (i, value) in row.iter().enumerate() {
                out.push_str(value);
                if i + 1 < row.len() {
                    out.push_str(&" ".repeat(widths[i] - value.width() + 2));
                }
            }
            out.push('\n');
        }
    }
    out
}
fn terminal_width() -> usize {
    use std::io::IsTerminal;
    if std::io::stdout().is_terminal() {
        crossterm::terminal::size()
            .map(|(w, _)| w as usize)
            .unwrap_or(80)
    } else {
        usize::MAX
    }
}
pub fn channels(rows: &[ChannelRow]) -> String {
    if rows.is_empty() {
        return "No channels. Join with: hibiki channel join 'INVITATION'\n".into();
    }
    let mut out = table(
        &[
            "DEFAULT",
            "CHANNEL",
            "MEMBERSHIP",
            "MEMBERS",
            "REVISION",
            "SOURCE",
            "CHANNEL ID",
        ],
        &rows
            .iter()
            .map(|row| {
                vec![
                    if row.selected { "*" } else { "" }.into(),
                    row.name.clone(),
                    if row.member { "Member" } else { "Not a member" }.into(),
                    row.devices.len().to_string(),
                    row.revision.to_string(),
                    if row.available { "Live" } else { "Cached" }.into(),
                    row.id.clone(),
                ]
            })
            .collect::<Vec<_>>(),
        terminal_width(),
    );
    for row in rows {
        if let Some(error) = &row.error {
            let _ = writeln!(out, "{}: {}", safe(&row.name), safe(error));
        }
    }
    out.push_str("\n* Default channel for new adapter sessions.\n");
    out
}
pub fn devices(local: &DeviceRow, channels: &[ChannelRow]) -> String {
    let mut out = format!(
        "This device: {}\nDevice ID: {}\n",
        safe(&local.name),
        local.id
    );
    if channels.is_empty() {
        out.push_str("\nNo channels or member devices.\n");
    }
    for channel in channels {
        let _ = writeln!(out, "\nChannel: {} ({})", safe(&channel.name), channel.id);
        out.push_str(&table(
            &[
                "DEVICE",
                "LOCAL",
                "MEMBERSHIP",
                "CONNECTION",
                "DEVICE ID",
                "APPROVED BY",
                "APPROVER ID",
                "CAN REVOKE",
            ],
            &channel
                .devices
                .iter()
                .map(|device| {
                    vec![
                        device.name.clone(),
                        if device.local { "This device" } else { "" }.into(),
                        if device.revoked_by_server {
                            "Revoked by server"
                        } else {
                            "Member"
                        }
                        .into(),
                        match device.online {
                            _ if device.revoked_by_server => "Revoked by server",
                            Some(true) => "Online",
                            Some(false) => "Offline",
                            None => "Unknown (cached)",
                        }
                        .into(),
                        device.id.clone(),
                        device
                            .approver_name
                            .clone()
                            .unwrap_or_else(|| "Channel founder".into()),
                        device.approved_by.clone().unwrap_or_else(|| "—".into()),
                        if device.can_revoke { "Yes" } else { "No" }.into(),
                    ]
                })
                .collect::<Vec<_>>(),
            terminal_width(),
        ));
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn names_cannot_change_terminal_state_or_shell_commands() {
        assert_eq!(safe("你好\x1b[2J\n"), "你好\\u{1b}[2J\\n");
        assert_eq!(quote("Bob's"), "'Bob'\\''s'");
        assert!(safe("x\u{202e}y").contains("\\u{202e}"));
    }
    #[test]
    fn tables_preserve_unicode_full_ids_and_escape_controls() {
        let rows = vec![
            vec!["同名设备".into(), "a".repeat(64)],
            vec!["同名设备\x1b[2J".into(), "b".repeat(64)],
        ];
        for width in [20, 200] {
            let rendered = table(&["DEVICE", "ID"], &rows, width);
            assert!(rendered.contains(&"a".repeat(64)) && rendered.contains(&"b".repeat(64)));
            assert!(rendered.contains("同名设备") && !rendered.contains('\x1b'));
        }
    }
    #[test]
    fn verification_words_are_complete() {
        let input = (1..=24)
            .map(|i| format!("word{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(words(&input).lines().count(), 4);
        assert_eq!(
            words(&input).split_whitespace().collect::<Vec<_>>(),
            input.split_whitespace().collect::<Vec<_>>()
        );
        assert!(pending("channel", "id", &[]).contains("No pending requests"));
    }
}
