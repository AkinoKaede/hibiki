use anyhow::{Context, Result, bail};
use fs2::FileExt;
use hibiki_lib::{
    channel::{Invite, MembershipProof},
    decode, encode,
    identity::Identity,
    paths::AppPaths,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub server: String,
    pub allow_insecure: bool,
    pub default_channel: Option<String>,
    pub gpgconf_program: PathBuf,
    pub scdaemon: ServiceConfig,
    pub pinentry: ServiceConfig,
    pub operation_timeout_seconds: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            server: String::new(),
            allow_insecure: false,
            default_channel: None,
            gpgconf_program: "gpgconf".into(),
            scdaemon: ServiceConfig::default(),
            pinentry: ServiceConfig::default(),
            operation_timeout_seconds: 120,
        }
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServiceConfig {
    pub enabled: bool,
    pub program: Option<PathBuf>,
}
impl Config {
    pub fn service(&self, kind: hibiki_lib::protocol::ServiceKind) -> &ServiceConfig {
        match kind {
            hibiki_lib::protocol::ServiceKind::Scdaemon => &self.scdaemon,
            hibiki_lib::protocol::ServiceKind::Pinentry => &self.pinentry,
        }
    }
}
#[derive(Clone)]
pub struct App {
    pub paths: AppPaths,
    pub config: Config,
    pub config_file: PathBuf,
    pub identity: Arc<Identity>,
}

pub fn private_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        // DirBuilder applies the mode to every newly created component.
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
    }
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
        bail!(
            "expected current-user directory with mode 0700: {}",
            path.display()
        );
    }
    Ok(())
}
pub fn read_private(path: &Path) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
        bail!("expected private regular file: {}", path.display());
    }
    if m.len() > 4 * 1024 * 1024 {
        bail!("private file too large");
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 4 * 1024 * 1024 {
        bail!("private file too large");
    }
    Ok(bytes)
}

/// Match NSFileProtectionComplete for every newly created iOS file, including
/// atomic replacements. The simulator's host filesystem has no Data Protection.
fn protect_file(file: &File) -> Result<()> {
    #[cfg(all(target_os = "ios", not(target_abi = "sim")))]
    {
        use std::os::fd::AsRawFd;
        const F_SETPROTECTIONCLASS: libc::c_int = 64;
        const PROTECTION_CLASS_A: libc::c_int = 1;
        if unsafe { libc::fcntl(file.as_raw_fd(), F_SETPROTECTIONCLASS, PROTECTION_CLASS_A) } == -1
        {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    #[cfg(not(all(target_os = "ios", not(target_abi = "sim"))))]
    let _ = file;
    Ok(())
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("file parent")?;
    private_dir(parent)?;
    if path.symlink_metadata().is_ok() {
        read_private(path)?;
    }
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    protect_file(file.as_file())?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
pub fn ensure_runtime(paths: &AppPaths) -> Result<()> {
    if let Some(base) = &paths.runtime_base {
        private_dir(base)?;
    }
    private_dir(&paths.runtime)
}
pub fn lock_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
        bail!("unsafe lock file");
    }
    protect_file(&file)?;
    file.lock_exclusive()?;
    Ok(file)
}

impl App {
    pub fn load(explicit: Option<&Path>) -> Result<Self> {
        let paths = AppPaths::discover()?;
        let config_file = paths
            .config_candidates(explicit, "client.toml")
            .into_iter()
            .find(|p| p.is_file())
            .context("client is not initialized; run hibiki init")?;
        let config: Config = toml::from_str(&fs::read_to_string(&config_file)?)?;
        if config.operation_timeout_seconds == 0 || config.operation_timeout_seconds > 3600 {
            bail!("operation_timeout_seconds must be 1..3600");
        }
        let identity: Identity = decode(&read_private(&paths.data.join("identity.bin"))?)?;
        identity.validate()?;
        Ok(Self {
            paths,
            config,
            config_file,
            identity: Arc::new(identity),
        })
    }
    pub fn initialize(server: String, name: String, allow_insecure: bool) -> Result<Self> {
        let paths = AppPaths::discover()?;
        private_dir(&paths.config)?;
        private_dir(&paths.data)?;
        let config_file = paths.config.join("client.toml");
        if config_file.exists() || paths.data.join("identity.bin").exists() {
            bail!("device already initialized");
        }
        crate::network::validate_url(&server, allow_insecure)?;
        let identity = Identity::generate(name)?;
        let config = Config {
            server,
            allow_insecure,
            ..Config::default()
        };
        atomic_write(&paths.data.join("identity.bin"), &encode(&identity)?)?;
        atomic_write(&config_file, toml::to_string_pretty(&config)?.as_bytes())?;
        Ok(Self {
            paths,
            config,
            config_file,
            identity: Arc::new(identity),
        })
    }
    pub fn save_config(&self) -> Result<()> {
        // Never write to a configuration found in XDG_CONFIG_DIRS.
        let target = if self
            .paths
            .config_dirs
            .iter()
            .any(|dir| self.config_file.starts_with(dir))
        {
            self.paths.config.join("client.toml")
        } else {
            self.config_file.clone()
        };
        atomic_write(&target, toml::to_string_pretty(&self.config)?.as_bytes())
    }
    pub fn proof(&self, channel: &str) -> Result<MembershipProof> {
        let directory = self.paths.channel_dir(channel)?;
        if directory.join("FORKED").exists() {
            bail!("channel trust fork detected; restore from a trusted backup");
        }
        let proof: MembershipProof = decode(&read_private(&directory.join("trust.bin"))?)?;
        proof.verify()?;
        Ok(proof)
    }
    pub fn proofs(&self) -> Result<Vec<MembershipProof>> {
        let directory = self.paths.data.join("channels");
        if !directory.exists() {
            return Ok(vec![]);
        }
        let mut proofs = Vec::new();
        for item in fs::read_dir(directory)? {
            let item = item?;
            let name = item.file_name();
            let Some(id) = name.to_str() else { continue };
            if hibiki_lib::channel::valid_id(id) {
                match self.proof(id) {
                    Ok(proof) => proofs.push(proof),
                    Err(e) => tracing::warn!(channel=id, error=%e, "channel unavailable"),
                }
            }
        }
        proofs.sort_by(|a, b| a.genesis.body.name.cmp(&b.genesis.body.name));
        Ok(proofs)
    }
    pub fn resolve_channel(&self, name: &str) -> Result<String> {
        if hibiki_lib::channel::valid_id(name) && self.proof(name).is_ok() {
            return Ok(name.into());
        }
        let matches: Vec<_> = self
            .proofs()?
            .into_iter()
            .filter(|p| p.genesis.body.name == name)
            .collect();
        if matches.len() > 1 {
            bail!("multiple trusted channels have this name; use the immutable channel ID");
        }
        matches
            .into_iter()
            .next()
            .map(|p| p.genesis.body.id)
            .context("channel not present in this device's trust store")
    }
    pub fn bootstrap(
        &self,
        proof: MembershipProof,
        invite: Option<&Invite>,
    ) -> Result<MembershipProof> {
        let state = proof.verify()?;
        if let Some(invite) = invite {
            if invite.server != self.config.server {
                bail!("invite server differs from configured server");
            }
            proof.verify_from(&invite.genesis.hash()?, &invite.checkpoint)?;
        } else if proof.genesis.body.founder.id() != self.identity.device.id() {
            bail!("an authenticated invite is required for a new trust root");
        }
        let path = self.paths.channel_dir(&state.id)?.join("trust.bin");
        ensure_runtime(&self.paths)?;
        let _lock = lock_file(&self.paths.runtime.join(format!("t-{}.lock", state.id)))?;
        if path.exists() {
            drop(_lock);
            return self.merge(proof);
        }
        atomic_write(&path, &encode(&proof)?)?;
        Ok(proof)
    }
    /// Accept extensions, retain a newer local prefix, and permanently quarantine actual forks.
    pub fn merge(&self, proof: MembershipProof) -> Result<MembershipProof> {
        let new = proof.verify()?;
        ensure_runtime(&self.paths)?;
        let _lock = lock_file(&self.paths.runtime.join(format!("t-{}.lock", new.id)))?;
        let old_proof = self.proof(&new.id)?;
        let old = old_proof.verify()?;
        let agrees = if old.sequence <= new.sequence {
            proof
                .verify_from(&old.genesis_hash, &old.checkpoint())
                .is_ok()
        } else {
            old_proof
                .verify_from(&new.genesis_hash, &new.checkpoint())
                .is_ok()
        };
        if !agrees {
            atomic_write(
                &self.paths.channel_dir(&new.id)?.join("FORKED"),
                b"membership log fork\n",
            )?;
            bail!("channel trust fork detected");
        }
        if old.sequence >= new.sequence {
            return Ok(old_proof);
        }
        atomic_write(
            &self.paths.channel_dir(&new.id)?.join("trust.bin"),
            &encode(&proof)?,
        )?;
        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hibiki_lib::channel::*;
    use std::collections::BTreeMap;
    fn app(root: &Path) -> App {
        let paths = AppPaths::resolve(&BTreeMap::new(), root, root, unsafe { libc::geteuid() });
        App {
            config_file: root.join("custom.toml"),
            paths,
            config: Config::default(),
            identity: Arc::new(Identity::generate("test".into()).unwrap()),
        }
    }
    #[test]
    fn trust_retains_newer_checkpoint_and_quarantines_forks() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let app = app(dir.path());
        let genesis =
            ChannelGenesis::create(&app.identity, "test".into(), "test-verifier").unwrap();
        let original = MembershipProof {
            genesis,
            events: vec![],
        };
        app.bootstrap(original.clone(), None).unwrap();
        let event = MembershipEvent::create(
            &app.identity,
            &original.verify().unwrap(),
            MembershipAction::ChangePsk {
                verifier_commitment: [1; 32],
            },
        )
        .unwrap();
        let mut newer = original.clone();
        newer.events.push(event);
        app.merge(newer.clone()).unwrap();
        assert_eq!(app.merge(original.clone()).unwrap(), newer);
        let mut fork = original.clone();
        fork.events.push(
            MembershipEvent::create(
                &app.identity,
                &original.verify().unwrap(),
                MembershipAction::ChangePsk {
                    verifier_commitment: [2; 32],
                },
            )
            .unwrap(),
        );
        assert!(app.merge(fork).is_err());
        assert!(app.proof(&original.genesis.body.id).is_err());
    }
    #[test]
    fn recreated_names_require_explicit_channel_id() {
        let dir = tempfile::tempdir().unwrap();
        let app = app(dir.path());
        let original = MembershipProof {
            genesis: ChannelGenesis::create(&app.identity, "same".into(), "verifier").unwrap(),
            events: vec![],
        };
        let replacement = MembershipProof {
            genesis: ChannelGenesis::create(&app.identity, "same".into(), "verifier").unwrap(),
            events: vec![],
        };
        app.bootstrap(original.clone(), None).unwrap();
        app.bootstrap(replacement.clone(), None).unwrap();
        assert!(app.resolve_channel("same").is_err());
        assert_eq!(
            app.resolve_channel(&replacement.genesis.body.id).unwrap(),
            replacement.genesis.body.id
        );
        assert_eq!(app.proof(&original.genesis.body.id).unwrap(), original);
    }
    #[test]
    fn private_files_reject_symlinks_and_public_permissions() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let file = dir.path().join("secret");
        atomic_write(&file, b"secret").unwrap();
        assert_eq!(file.metadata().unwrap().mode() & 0o777, 0o600);
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(read_private(&link).is_err());
        assert!(atomic_write(&link, b"replacement").is_err());
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private(&file).is_err());
    }
    #[test]
    fn explicit_config_is_updated_and_system_config_is_not() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut app = app(dir.path());
        app.save_config().unwrap();
        assert!(app.config_file.is_file());
        let system = dir.path().join("system");
        private_dir(&system).unwrap();
        app.paths.config_dirs = vec![system.clone()];
        app.config_file = system.join("client.toml");
        atomic_write(&app.config_file, b"system sentinel").unwrap();
        app.save_config().unwrap();
        assert_eq!(fs::read(&app.config_file).unwrap(), b"system sentinel");
        assert!(app.paths.config.join("client.toml").is_file());
    }
}
