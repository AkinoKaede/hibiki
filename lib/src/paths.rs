/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

use crate::{Error, Result, digest};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug)]
pub struct AppPaths {
    pub config: PathBuf,
    pub data: PathBuf,
    pub state: PathBuf,
    pub cache: PathBuf,
    pub runtime: PathBuf,
    pub runtime_base: Option<PathBuf>,
    pub config_dirs: Vec<PathBuf>,
}
impl AppPaths {
    pub fn discover() -> Result<Self> {
        let vars: BTreeMap<_, _> = std::env::vars_os().collect();
        let home = vars
            .get(&OsString::from("HOME"))
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .ok_or_else(|| Error::Invalid("HOME must be absolute".into()))?;
        // Read-only UID query; no environment or filesystem changes.
        let uid = unsafe { libc::geteuid() };
        Ok(Self::resolve(&vars, &home, &std::env::temp_dir(), uid))
    }
    pub fn resolve(
        vars: &BTreeMap<OsString, OsString>,
        home: &Path,
        temp: &Path,
        uid: u32,
    ) -> Self {
        let value = |key: &str| {
            vars.get(&OsString::from(key))
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
        };
        let directory = |key: &str, fallback: &str| {
            value(key)
                .unwrap_or_else(|| home.join(fallback))
                .join("hibiki")
        };
        let runtime_base = value("XDG_RUNTIME_DIR");
        let runtime = runtime_base
            .as_ref()
            .map(|p| p.join("hibiki"))
            .unwrap_or_else(|| temp.join(format!("hibiki-{uid}")));
        let config_dirs = vars
            .get(&OsString::from("XDG_CONFIG_DIRS"))
            .filter(|v| !v.is_empty())
            .map(|v| {
                std::env::split_paths(v)
                    .filter(|p| p.is_absolute())
                    .map(|p| p.join("hibiki"))
                    .collect()
            })
            .unwrap_or_else(|| vec![PathBuf::from("/etc/xdg/hibiki")]);
        Self {
            config: directory("XDG_CONFIG_HOME", ".config"),
            data: directory("XDG_DATA_HOME", ".local/share"),
            state: directory("XDG_STATE_HOME", ".local/state"),
            cache: directory("XDG_CACHE_HOME", ".cache"),
            runtime,
            runtime_base,
            config_dirs,
        }
    }
    pub fn config_candidates(&self, explicit: Option<&Path>, file: &str) -> Vec<PathBuf> {
        if let Some(p) = explicit {
            return vec![p.to_owned()];
        }
        std::iter::once(self.config.join(file))
            .chain(self.config_dirs.iter().map(|p| p.join(file)))
            .collect()
    }
    pub fn channel_dir(&self, id: &str) -> Result<PathBuf> {
        if !crate::channel::valid_id(id) {
            return Err(Error::Invalid("channel ID".into()));
        }
        Ok(self.data.join("channels").join(id))
    }
    pub fn ipc_socket(&self) -> PathBuf {
        self.runtime.join(format!(
            "h-{}.sock",
            &hex::encode(digest(self.data.as_os_str().as_encoded_bytes()))[..16]
        ))
    }
}

/// Create (mode 0700) or validate a directory owned by the current user.
pub fn private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    if !path.exists() {
        // DirBuilder applies the mode to every newly created component.
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
    }
    let m = std::fs::symlink_metadata(path)?;
    // Read-only UID query; no environment or filesystem changes.
    if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "expected current-user directory with mode 0700: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}
