/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

//! Bounded Assuan framing shared by both stdio services. Payloads are never logged.
use crate::{Error, Result, protocol::ServiceKind};
use serde::{Deserialize, Serialize};
use std::ops::Deref;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MAX_LINE: usize = 1000;
pub const MAX_DATA: usize = 1024 * 1024;
pub const MAX_LINES: usize = 8192;
/// Audited GnuPG baseline for Hibiki's supported scdaemon commands, not full emulation.
pub const SCDAEMON_VERSION: &str = "2.5.24";
/// Pinentry reports our implementation version; GnuPG uses it for diagnostics only.
pub const PINENTRY_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const CANCELED: u32 = 99;
pub const CARD_NOT_PRESENT: u32 = 112;
pub const FULLY_CANCELED: u32 = 198;
pub const GENERAL: u32 = 1;
pub const NOT_SUPPORTED: u32 = 60;
pub const UNKNOWN_OPTION: u32 = 174;
pub const MISSING_VALUE: u32 = 128;
pub const FALSE: u32 = 256;
pub const NO_DATA: u32 = 58;

#[derive(Clone, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct Line(pub Vec<u8>);
impl std::fmt::Debug for Line {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[Assuan payload redacted]")
    }
}
impl Deref for Line {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}
impl From<Vec<u8>> for Line {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}
impl From<&[u8]> for Line {
    fn from(v: &[u8]) -> Self {
        Self(v.to_vec())
    }
}
impl From<&str> for Line {
    fn from(v: &str) -> Self {
        Self(v.as_bytes().to_vec())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Response<'a> {
    Ok,
    Err(u32),
    Data(&'a [u8]),
    Status(&'a [u8]),
    Inquire(&'a [u8]),
    Comment,
}
pub fn framing(raw: &[u8]) -> Result<()> {
    if raw.len() + 1 > MAX_LINE || raw.iter().any(|b| matches!(b, b'\n' | b'\r')) {
        return Err(Error::Invalid("Assuan line framing".into()));
    }
    Ok(())
}
pub fn parse_response(line: &[u8]) -> Result<Response<'_>> {
    framing(line)?;
    if line == b"OK" || line.starts_with(b"OK ") {
        return Ok(Response::Ok);
    }
    if let Some(s) = line.strip_prefix(b"ERR ") {
        return std::str::from_utf8(s.split(|b| *b == b' ').next().unwrap_or_default())
            .ok()
            .and_then(|s| s.parse().ok())
            .map(Response::Err)
            .ok_or_else(|| Error::Invalid("Assuan error code".into()));
    }
    if line == b"D" {
        return Ok(Response::Data(b""));
    }
    if let Some(s) = line.strip_prefix(b"D ") {
        return Ok(Response::Data(s));
    }
    if let Some(s) = line.strip_prefix(b"S ") {
        return Ok(Response::Status(s));
    }
    if let Some(s) = line.strip_prefix(b"INQUIRE ") {
        if s.is_empty() {
            return Err(Error::Invalid("empty inquiry".into()));
        }
        return Ok(Response::Inquire(s));
    }
    if line.starts_with(b"#") || line.is_empty() {
        return Ok(Response::Comment);
    }
    Err(Error::Invalid("invalid Assuan response".into()))
}
pub fn escape(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for b in bytes {
        match b {
            b'%' => out.extend_from_slice(b"%25"),
            b'\r' => out.extend_from_slice(b"%0D"),
            b'\n' => out.extend_from_slice(b"%0A"),
            _ => out.push(*b),
        }
    }
    out
}
pub fn unescape(bytes: &[u8]) -> Result<Line> {
    // Decoding can only shrink data. Reserve once so a realloc cannot leave a
    // copy of a partially decoded PIN in a freed allocation.
    let mut out = Line(Vec::with_capacity(bytes.len()));
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes
                .get(i + 1..i + 3)
                .ok_or_else(|| Error::Invalid("truncated escape".into()))?;
            let s = std::str::from_utf8(hex).map_err(|_| Error::Invalid("escape".into()))?;
            out.0
                .push(u8::from_str_radix(s, 16).map_err(|_| Error::Invalid("escape".into()))?);
            i += 3;
        } else {
            out.0.push(bytes[i]);
            i += 1;
        }
    }
    Ok(out)
}
pub fn data_lines(bytes: &[u8]) -> Vec<Line> {
    bytes
        .chunks(300)
        .map(|b| {
            let mut l = b"D ".to_vec();
            l.extend(escape(b));
            Line(l)
        })
        .collect()
}
pub fn error(code: u32, text: &str) -> Line {
    let safe: String = text
        .chars()
        .filter(|c| c.is_ascii() && !c.is_control())
        .take(150)
        .collect();
    format!("ERR {code} {safe}").as_str().into()
}
#[derive(Debug, Default)]
pub struct AssuanResult {
    pub lines: Vec<Line>,
}
impl AssuanResult {
    pub fn error(code: u32, text: &str) -> Self {
        Self {
            lines: vec![error(code, text)],
        }
    }
    pub fn ok() -> Self {
        Self {
            lines: vec!["OK".into()],
        }
    }
    pub fn success(&self) -> bool {
        self.lines
            .last()
            .is_some_and(|l| matches!(parse_response(l), Ok(Response::Ok)))
    }
    pub fn canceled(&self) -> bool {
        self.lines.last().is_some_and(|l| matches!(parse_response(l), Ok(Response::Err(n)) if matches!(n & 0xffff, CANCELED | FULLY_CANCELED)))
    }
    pub fn validate(&self) -> Result<()> {
        if self.lines.is_empty()
            || self.lines.len() > MAX_LINES
            || self.lines.iter().map(|l| l.len()).sum::<usize>() > MAX_DATA
        {
            return Err(Error::Invalid("Assuan result length".into()));
        }
        for (i, l) in self.lines.iter().enumerate() {
            let r = parse_response(l)?;
            if matches!(r, Response::Inquire(_))
                || matches!(r, Response::Ok | Response::Err(_)) != (i + 1 == self.lines.len())
            {
                return Err(Error::Invalid("Assuan result framing".into()));
            }
            if let Response::Data(d) = r {
                unescape(d)?;
            }
        }
        Ok(())
    }
}

pub fn command(line: &[u8]) -> Result<(&str, &str)> {
    framing(line)?;
    if line.contains(&0) {
        return Err(Error::Invalid("NUL in command".into()));
    }
    let s = std::str::from_utf8(line).map_err(|_| Error::Invalid("command encoding".into()))?;
    let (cmd, args) = s.split_once(' ').unwrap_or((s, ""));
    if cmd.is_empty() {
        return Err(Error::Invalid("empty command".into()));
    }
    Ok((cmd, args.trim()))
}
pub fn local_option(args: &str) -> bool {
    matches!(
        args.split('=').next().unwrap_or(""),
        "ttyname" | "ttytype" | "display" | "xauthority" | "lc-ctype" | "lc-messages" | "owner"
    )
}
/// Both the requester and the provider enforce the service boundary.
pub fn validate_command(service: ServiceKind, line: &[u8]) -> Result<()> {
    let (cmd, args) = command(line)?;
    let supported = match service {
        ServiceKind::Scdaemon => match cmd {
            "RESET" | "RESTART" | "NOP" | "BYE" => args.is_empty(),
            "SERIALNO" => args
                .split_ascii_whitespace()
                .all(|a| a == "openpgp" || a == "--all" || hex_arg(a, "--demand=")),
            "SWITCHCARD" => args.is_empty() || args.bytes().all(|c| c.is_ascii_hexdigit()),
            "SWITCHAPP" => args == "openpgp",
            "LEARN" => args.split_ascii_whitespace().all(|a| {
                matches!(a, "--force" | "--keypairinfo" | "--multi" | "--reread")
                    || hex_arg(a, "--demand=")
                    || (a.len() == 40 && a.bytes().all(|c| c.is_ascii_hexdigit()))
            }),
            "SETDATA" => {
                let a = args.strip_prefix("--append ").unwrap_or(args);
                !a.is_empty() && a.len() % 2 == 0 && a.bytes().all(|c| c.is_ascii_hexdigit())
            }
            "PKSIGN" => {
                args.split_ascii_whitespace().all(|a| {
                    !a.starts_with("--")
                        || matches!(
                            a,
                            "--hash=sha1"
                                | "--hash=sha224"
                                | "--hash=sha256"
                                | "--hash=sha384"
                                | "--hash=sha512"
                                | "--hash=rmd160"
                        )
                }) && !args.is_empty()
            }
            "PKDECRYPT" | "READCERT" => !args.is_empty() && !args.starts_with("--"),
            "READKEY" => {
                !args.is_empty()
                    && args.split_ascii_whitespace().all(|a| {
                        !a.starts_with("--")
                            || matches!(
                                a,
                                "--" | "--info"
                                    | "--info-only"
                                    | "--advanced"
                                    | "--format=advanced"
                            )
                    })
            }
            "GETATTR" => !args.is_empty(),
            "KEYINFO" => {
                !args.is_empty()
                    && args.split_ascii_whitespace().all(|a| {
                        matches!(
                            a,
                            "--list" | "--list=auth" | "--list=encr" | "--list=sign" | "--data"
                        ) || (a.len() == 40 && a.bytes().all(|c| c.is_ascii_hexdigit()))
                    })
            }
            "GETINFO" => {
                matches!(
                    args,
                    "version"
                        | "pid"
                        | "socket_name"
                        | "status"
                        | "reader_list"
                        | "app_list"
                        | "card_list"
                        | "deny_admin"
                        | "active_apps"
                        | "all_active_apps"
                ) || args.split_ascii_whitespace().next() == Some("cmd_has_option")
                    || args.starts_with("manufacturer ")
            }
            _ => false,
        },
        ServiceKind::Pinentry => match cmd {
            "RESET" | "NOP" | "BYE" | "GETPIN" | "MESSAGE" => args.is_empty(),
            "CONFIRM" => args.is_empty() || args == "--one-button",
            "SETDESC" | "SETPROMPT" | "SETTITLE" | "SETOK" | "SETCANCEL" | "SETNOTOK"
            | "SETERROR" | "SETREPEAT" | "SETREPEATERROR" | "SETREPEATOK" | "SETQUALITYBAR"
            | "SETQUALITYBAR_TT" | "SETGENPIN" | "SETGENPIN_TT" | "SETKEYINFO" => true,
            "SETTIMEOUT" => args.parse::<u32>().is_ok(),
            "GETINFO" => matches!(args, "version" | "pid" | "flavor" | "ttyinfo"),
            "OPTION" => {
                let k = args.split('=').next().unwrap_or("");
                local_option(args)
                    || matches!(
                        k,
                        "grab"
                            | "no-grab"
                            | "allow-external-password-cache"
                            | "allow-emacs-prompt"
                            | "default-ok"
                            | "default-cancel"
                            | "default-prompt"
                            | "default-pwmngr"
                            | "default-cf-visi"
                            | "default-tt-visi"
                            | "default-tt-hide"
                            | "default-capshint"
                            | "default-tt-save"
                            | "default-title"
                            | "touch-file"
                            | "formatted-passphrase"
                            | "formatted-passphrase-hint"
                            | "constraints-enforce"
                            | "constraints-hint-short"
                            | "constraints-hint-long"
                            | "constraints-error-title"
                            | "invisible-char"
                    )
            }
            _ => false,
        },
    };
    if supported {
        Ok(())
    } else {
        Err(Error::Unsupported("Assuan command or option".into()))
    }
}
fn hex_arg(s: &str, prefix: &str) -> bool {
    s.strip_prefix(prefix)
        .is_some_and(|s| !s.is_empty() && s.bytes().all(|c| c.is_ascii_hexdigit()))
}
