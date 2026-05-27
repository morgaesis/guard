//! Secret broker for managing sensitive credentials across multiple backends.
//!
//! Secrets are stored per-UID: each caller has its own private namespace
//! keyed by key name. Two users can reuse the same key name (e.g.
//! `OPNSENSE_API_KEY`) without collision, and one user cannot read, list,
//! overwrite, or delete another user's secrets. The daemon UID has a
//! separate admin-only `list_all` entry point that returns the full
//! (uid, key) set for observability; it still cannot read another user's
//! values through the normal `get` path (which requires the owning UID).

use anyhow::{bail, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::process::Command as AsyncCommand;
use tokio::sync::RwLock;

/// Directory within pass where secrets are stored. Entries live at
/// `guard/u<uid>/<key>` so one user's secrets cannot collide with
/// another's.
const PASS_PREFIX: &str = "guard/";

/// Prefix for environment variable secrets. Full form is
/// `GUARD_SECRET_U<uid>_<KEY>`.
const ENV_PREFIX: &str = "GUARD_SECRET_";

/// Filename for the local encrypted secrets file.
const SECRETS_FILE: &str = "secrets.yaml";
pub const LEGACY_UID_SENTINEL: u32 = u32::MAX;
type NamespacedSecretKey = (u32, String);
type PassStoreEntries = (Vec<NamespacedSecretKey>, Vec<String>);

fn uid_segment(uid: u32) -> String {
    format!("u{}", uid)
}

/// Trait for secret storage backends.
///
/// Implementors must be safe to share across threads (Send + Sync).
#[async_trait]
pub trait SecretBackend: Send + Sync {
    /// Returns the backend name for logging/debugging.
    fn name(&self) -> &str;

    /// Retrieve a secret by (uid, key).
    async fn get(&self, uid: u32, key: &str) -> Result<Option<String>>;

    /// List secret keys owned by `uid`.
    async fn list(&self, uid: u32) -> Result<Vec<String>>;

    /// Admin view: list every (uid, key) pair in the store. The daemon
    /// uses this for its aggregate `secrets list`. Backends that cannot
    /// enumerate by UID (env backend) should still return everything
    /// they can recover.
    async fn list_all(&self) -> Result<Vec<(u32, String)>>;

    /// Store a secret under `uid`.
    async fn set(&self, uid: u32, key: &str, value: &str) -> Result<()>;

    /// Delete a secret owned by `uid`.
    async fn delete(&self, uid: u32, key: &str) -> Result<()>;
}

// ---------------------------------------------------------------------------
// PassBackend
// ---------------------------------------------------------------------------

/// Secret backend backed by the unix `pass` password manager.
#[derive(Debug, Clone)]
pub struct PassBackend {
    store_dir: Option<PathBuf>,
}

impl PassBackend {
    /// Create a new PassBackend.
    ///
    pub fn new() -> Self {
        Self {
            store_dir: password_store_dir(),
        }
    }

    fn pass_path(&self, uid: u32, key: &str) -> String {
        format!("{}{}/{}", PASS_PREFIX, uid_segment(uid), key)
    }

    fn legacy_pass_path(&self, key: &str) -> String {
        format!("{}{}", PASS_PREFIX, key)
    }

    fn store_dir(&self) -> Option<&Path> {
        self.store_dir.as_deref()
    }

    async fn get_entry(&self, path: &str) -> Result<Option<String>> {
        let mut cmd = AsyncCommand::new("pass");
        cmd.arg("show").arg(path);
        if let Some(store_dir) = self.store_dir() {
            cmd.env("PASSWORD_STORE_DIR", store_dir);
        }
        let output = cmd.output().await?;

        if !output.status.success() {
            if output.status.code() == Some(1) {
                return Ok(None);
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("pass show {} failed: {}", path, stderr.trim());
        }

        Ok(Some(
            String::from_utf8_lossy(&output.stdout).trim().to_string(),
        ))
    }

    async fn run_pass<I, S>(&self, args: I) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut cmd = AsyncCommand::new("pass");
        cmd.args(args);
        if let Some(store_dir) = self.store_dir() {
            cmd.env("PASSWORD_STORE_DIR", store_dir);
        }

        let output = cmd.output().await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("pass command failed: {}", stderr.trim());
        }

        Ok(())
    }
}

fn password_store_dir() -> Option<PathBuf> {
    env::var_os("PASSWORD_STORE_DIR")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|home| home.join(".password-store")))
}

fn pass_store_initialized() -> bool {
    password_store_dir()
        .map(|dir| dir.join(".gpg-id").is_file())
        .unwrap_or(false)
}

fn collect_pass_entries(
    namespace_root: &Path,
    dir: &Path,
    namespaced: &mut Vec<NamespacedSecretKey>,
    legacy: &mut Vec<String>,
) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_pass_entries(namespace_root, &path, namespaced, legacy)?;
            continue;
        }
        if !file_type.is_file() || path.extension() != Some(OsStr::new("gpg")) {
            continue;
        }

        let rel = match path.strip_prefix(namespace_root) {
            Ok(rel) => rel,
            Err(_) => continue,
        };
        let components: Vec<String> = rel
            .iter()
            .map(|part| part.to_string_lossy().to_string())
            .collect();
        let mut key_parts = components.clone();
        let Some(last) = key_parts.last_mut() else {
            continue;
        };
        if let Some(stem) = last.strip_suffix(".gpg") {
            *last = stem.to_string();
        }
        if let Some(uid_str) = components[0].strip_prefix('u') {
            if let Ok(uid) = uid_str.parse::<u32>() {
                let key = key_parts[1..].join("/");
                if !key.is_empty() {
                    namespaced.push((uid, key));
                }
                continue;
            }
        }
        let key = key_parts.join("/");
        if !key.is_empty() {
            legacy.push(key);
        }
    }
    Ok(())
}

fn list_pass_store_entries(store_dir: &Path) -> Result<PassStoreEntries> {
    let namespace_root = store_dir.join(PASS_PREFIX.trim_end_matches('/'));
    if !namespace_root.exists() {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut namespaced = Vec::new();
    let mut legacy = Vec::new();
    collect_pass_entries(
        &namespace_root,
        &namespace_root,
        &mut namespaced,
        &mut legacy,
    )?;
    namespaced.sort();
    namespaced.dedup();
    legacy.sort();
    legacy.dedup();
    Ok((namespaced, legacy))
}

#[async_trait]
impl SecretBackend for PassBackend {
    fn name(&self) -> &str {
        "pass"
    }

    async fn get(&self, uid: u32, key: &str) -> Result<Option<String>> {
        self.get_entry(&self.pass_path(uid, key)).await
    }

    async fn list(&self, uid: u32) -> Result<Vec<String>> {
        let Some(store_dir) = self.store_dir() else {
            return Ok(Vec::new());
        };
        let (namespaced, _) = list_pass_store_entries(store_dir)?;
        let mut keys: Vec<String> = namespaced
            .into_iter()
            .filter_map(|(entry_uid, key)| if entry_uid == uid { Some(key) } else { None })
            .collect();
        keys.sort();
        keys.dedup();
        Ok(keys)
    }

    async fn list_all(&self) -> Result<Vec<(u32, String)>> {
        let Some(store_dir) = self.store_dir() else {
            return Ok(Vec::new());
        };
        let (mut namespaced, legacy) = list_pass_store_entries(store_dir)?;
        namespaced.extend(legacy.into_iter().map(|key| (LEGACY_UID_SENTINEL, key)));
        namespaced.sort();
        namespaced.dedup();
        Ok(namespaced)
    }

    async fn set(&self, uid: u32, key: &str, value: &str) -> Result<()> {
        let path = self.pass_path(uid, key);

        let mut cmd = AsyncCommand::new("pass");
        cmd.args(["insert", "--force", "--multiline", &path]);
        if let Some(store_dir) = self.store_dir() {
            cmd.env("PASSWORD_STORE_DIR", store_dir);
        }

        cmd.stdin(std::process::Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(value.as_bytes()).await?;
        }

        let output = child.wait_with_output().await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("pass insert {} failed: {}", path, stderr.trim());
        }

        Ok(())
    }

    async fn delete(&self, uid: u32, key: &str) -> Result<()> {
        let path = self.pass_path(uid, key);
        let mut cmd = AsyncCommand::new("pass");
        cmd.args(["rm", "-f", &path]);
        if let Some(store_dir) = self.store_dir() {
            cmd.env("PASSWORD_STORE_DIR", store_dir);
        }

        let output = cmd.output().await?;

        if !output.status.success() && output.status.code() != Some(1) {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("pass rm {} failed: {}", path, stderr.trim());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// EnvBackend
// ---------------------------------------------------------------------------

/// Secret backend backed by environment variables. Layout is
/// `GUARD_SECRET_U<uid>_<KEY>`.
#[derive(Debug, Clone)]
pub struct EnvBackend {
    _priv: (),
}

impl EnvBackend {
    pub fn new() -> Self {
        Self { _priv: () }
    }

    fn env_key(uid: u32, secret_key: &str) -> String {
        format!("{}U{}_{}", ENV_PREFIX, uid, secret_key)
    }

    fn legacy_env_key(secret_key: &str) -> String {
        format!("{}{}", ENV_PREFIX, secret_key)
    }

    fn user_prefix(uid: u32) -> String {
        format!("{}U{}_", ENV_PREFIX, uid)
    }
}

impl Default for EnvBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecretBackend for EnvBackend {
    fn name(&self) -> &str {
        "env"
    }

    async fn get(&self, uid: u32, key: &str) -> Result<Option<String>> {
        Ok(env::var(Self::env_key(uid, key)).ok())
    }

    async fn list(&self, uid: u32) -> Result<Vec<String>> {
        let prefix = Self::user_prefix(uid);
        let mut keys = Vec::new();
        for (env_key, _) in env::vars() {
            if let Some(key) = env_key.strip_prefix(&prefix) {
                keys.push(key.to_string());
            }
        }
        keys.sort();
        keys.dedup();
        Ok(keys)
    }

    async fn list_all(&self) -> Result<Vec<(u32, String)>> {
        let mut out = Vec::new();
        for (env_key, _) in env::vars() {
            if let Some(rest) = env_key.strip_prefix(ENV_PREFIX) {
                if let Some(after_u) = rest.strip_prefix('U') {
                    if let Some((uid_str, key)) = after_u.split_once('_') {
                        if let Ok(uid) = uid_str.parse::<u32>() {
                            if !key.is_empty() {
                                out.push((uid, key.to_string()));
                            }
                        }
                    }
                } else if !rest.is_empty() {
                    out.push((LEGACY_UID_SENTINEL, rest.to_string()));
                }
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    async fn set(&self, uid: u32, key: &str, value: &str) -> Result<()> {
        env::set_var(Self::env_key(uid, key), value);
        Ok(())
    }

    async fn delete(&self, uid: u32, key: &str) -> Result<()> {
        env::remove_var(Self::env_key(uid, key));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// LocalBackend
// ---------------------------------------------------------------------------

/// Secret backend backed by an encrypted YAML file.
/// The on-disk shape is `{ <uid>: { <key>: <value> } }`.
#[derive(Debug, Clone)]
pub struct LocalBackend {
    path: PathBuf,
    gpg_recipient: Option<String>,
}

type LocalStore = HashMap<u32, HashMap<String, String>>;
type LegacyLocalStore = HashMap<String, String>;

enum LocalStoreVariant {
    Namespaced(LocalStore),
    Legacy(LegacyLocalStore),
}

impl LocalBackend {
    pub fn new() -> Result<Self> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| anyhow::anyhow!("could not determine config directory"))?;
        let guard_dir = config_dir.join("guard");

        Ok(Self {
            path: guard_dir.join(SECRETS_FILE),
            gpg_recipient: None,
        })
    }

    pub fn with_path(path: PathBuf) -> Self {
        Self {
            path,
            gpg_recipient: None,
        }
    }

    pub fn with_gpg_recipient(mut self, recipient: String) -> Self {
        self.gpg_recipient = Some(recipient);
        self
    }

    fn encrypted_path(&self) -> PathBuf {
        PathBuf::from(format!("{}.gpg", self.path.display()))
    }

    async fn load_store_variant(&self) -> Result<LocalStoreVariant> {
        let encrypted = self.encrypted_path();

        if !encrypted.exists() {
            return Ok(LocalStoreVariant::Namespaced(HashMap::new()));
        }

        let output = if let Some(ref recipient) = self.gpg_recipient {
            AsyncCommand::new("gpg")
                .args(["--decrypt", "--recipient", recipient, "--quiet"])
                .arg(&encrypted)
                .output()
                .await?
        } else {
            AsyncCommand::new("gpg")
                .args(["--decrypt", "--quiet"])
                .arg(&encrypted)
                .output()
                .await?
        };

        if !output.status.success() {
            tracing::debug!("could not decrypt secrets file: {:?}", output.status);
            return Ok(LocalStoreVariant::Namespaced(HashMap::new()));
        }

        let content = String::from_utf8_lossy(&output.stdout);
        if let Ok(store) = serde_yaml::from_str::<LocalStore>(&content) {
            return Ok(LocalStoreVariant::Namespaced(store));
        }
        if let Ok(store) = serde_yaml::from_str::<LegacyLocalStore>(&content) {
            return Ok(LocalStoreVariant::Legacy(store));
        }
        bail!("failed to parse secrets file {}", encrypted.display())
    }

    async fn save_store_variant(&self, secrets: &LocalStoreVariant) -> Result<()> {
        let parent = self.path.parent();
        if let Some(parent) = parent {
            fs::create_dir_all(parent)?;
        }

        let content = match secrets {
            LocalStoreVariant::Namespaced(store) => serde_yaml::to_string(store)?,
            LocalStoreVariant::Legacy(store) => serde_yaml::to_string(store)?,
        };

        if let Some(ref recipient) = self.gpg_recipient {
            let mut child = AsyncCommand::new("gpg")
                .args(["--encrypt", "--recipient", recipient, "--quiet", "-o"])
                .arg(self.encrypted_path())
                .stdin(Stdio::piped())
                .spawn()?;

            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(content.as_bytes()).await?;
                drop(stdin);
            }

            let status = child.wait().await?;
            if !status.success() {
                bail!("gpg encryption failed");
            }
        } else {
            let mut child = AsyncCommand::new("gpg")
                .args(["--symmetric", "--cipher-algo", "AES256", "--quiet", "-o"])
                .arg(self.encrypted_path())
                .stdin(Stdio::piped())
                .spawn()?;

            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(content.as_bytes()).await?;
                drop(stdin);
            }

            let status = child.wait().await?;
            if !status.success() {
                bail!("gpg symmetric encryption failed");
            }
        }

        Ok(())
    }
}

impl Default for LocalBackend {
    fn default() -> Self {
        Self::new().expect("could not create default LocalBackend")
    }
}

#[async_trait]
impl SecretBackend for LocalBackend {
    fn name(&self) -> &str {
        "local"
    }

    async fn get(&self, uid: u32, key: &str) -> Result<Option<String>> {
        match self.load_store_variant().await? {
            LocalStoreVariant::Namespaced(store) => {
                Ok(store.get(&uid).and_then(|m| m.get(key)).cloned())
            }
            LocalStoreVariant::Legacy(_) => Ok(None),
        }
    }

    async fn list(&self, uid: u32) -> Result<Vec<String>> {
        let mut keys: Vec<String> = match self.load_store_variant().await? {
            LocalStoreVariant::Namespaced(store) => store
                .get(&uid)
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default(),
            LocalStoreVariant::Legacy(_) => Vec::new(),
        };
        keys.sort();
        keys.dedup();
        Ok(keys)
    }

    async fn list_all(&self) -> Result<Vec<(u32, String)>> {
        let mut out: Vec<(u32, String)> = match self.load_store_variant().await? {
            LocalStoreVariant::Namespaced(store) => store
                .iter()
                .flat_map(|(uid, m)| m.keys().map(move |k| (*uid, k.clone())))
                .collect(),
            LocalStoreVariant::Legacy(store) => store
                .keys()
                .cloned()
                .map(|k| (LEGACY_UID_SENTINEL, k))
                .collect(),
        };
        out.sort();
        out.dedup();
        Ok(out)
    }

    async fn set(&self, uid: u32, key: &str, value: &str) -> Result<()> {
        match self.load_store_variant().await? {
            LocalStoreVariant::Namespaced(mut store) => {
                store
                    .entry(uid)
                    .or_default()
                    .insert(key.to_string(), value.to_string());
                self.save_store_variant(&LocalStoreVariant::Namespaced(store))
                    .await
            }
            LocalStoreVariant::Legacy(_) => bail!(
                "legacy flat local secret store detected; daemon migration is required before user-scoped writes"
            ),
        }
    }

    async fn delete(&self, uid: u32, key: &str) -> Result<()> {
        match self.load_store_variant().await? {
            LocalStoreVariant::Namespaced(mut store) => {
                if let Some(m) = store.get_mut(&uid) {
                    m.remove(key);
                    if m.is_empty() {
                        store.remove(&uid);
                    }
                }
                self.save_store_variant(&LocalStoreVariant::Namespaced(store))
                    .await
            }
            LocalStoreVariant::Legacy(_) => bail!(
                "legacy flat local secret store detected; daemon migration is required before user-scoped deletes"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// SecretFd
// ---------------------------------------------------------------------------

/// File-descriptor wrapper for secret injection. The secret is written to
/// a temporary file with 0600 permissions and cleaned up on drop.
#[derive(Debug)]
pub struct SecretFd {
    pub path: PathBuf,
    temp_dir: tempfile::TempDir,
}

impl SecretFd {
    fn new(secret: &str) -> Result<Self> {
        let temp_dir = tempfile::TempDir::new_in("/tmp")?;
        let path = temp_dir.path().join("secret");

        fs::write(&path, secret)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;

        Ok(Self { path, temp_dir })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for SecretFd {
    fn drop(&mut self) {
        if self.path.exists() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

// ---------------------------------------------------------------------------
// SecretManager
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
struct CacheKey {
    uid: u32,
    key: String,
}

/// Manager for secret operations with a configurable backend.
#[derive(Clone)]
pub struct SecretManager {
    backend: Arc<dyn SecretBackend>,
    cache: Arc<RwLock<HashMap<CacheKey, String>>>,
}

impl std::fmt::Debug for SecretManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretManager")
            .field("backend_name", &self.backend.name())
            .finish()
    }
}

impl SecretManager {
    pub fn new(backend: Arc<dyn SecretBackend>) -> Self {
        Self {
            backend,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn with_backend<B: SecretBackend + 'static>(backend: B) -> Self {
        Self::new(Arc::new(backend))
    }

    pub fn backend_name(&self) -> &str {
        self.backend.name()
    }

    pub async fn get(&self, uid: u32, key: &str) -> Result<Option<String>> {
        let ck = CacheKey {
            uid,
            key: key.to_string(),
        };
        {
            let cache = self.cache.read().await;
            if let Some(value) = cache.get(&ck) {
                return Ok(Some(value.clone()));
            }
        }

        let value = self.backend.get(uid, key).await?;

        if let Some(ref v) = value {
            let mut cache = self.cache.write().await;
            cache.insert(ck, v.clone());
        }

        Ok(value)
    }

    pub async fn list(&self, uid: u32) -> Result<Vec<String>> {
        self.backend.list(uid).await
    }

    pub async fn list_all(&self) -> Result<Vec<(u32, String)>> {
        self.backend.list_all().await
    }

    pub async fn set(&self, uid: u32, key: &str, value: &str) -> Result<()> {
        self.backend.set(uid, key, value).await?;
        let mut cache = self.cache.write().await;
        cache.insert(
            CacheKey {
                uid,
                key: key.to_string(),
            },
            value.to_string(),
        );
        Ok(())
    }

    pub async fn delete(&self, uid: u32, key: &str) -> Result<()> {
        self.backend.delete(uid, key).await?;
        let mut cache = self.cache.write().await;
        cache.remove(&CacheKey {
            uid,
            key: key.to_string(),
        });
        Ok(())
    }

    pub async fn inject_fd(&self, uid: u32, key: &str) -> Result<SecretFd> {
        let secret = match self.get(uid, key).await? {
            Some(s) => s,
            None => anyhow::bail!("secret not found: {}", key),
        };

        SecretFd::new(&secret)
    }

    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }
}

// ---------------------------------------------------------------------------
// Backend selection
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendType {
    Pass,
    Env,
    Local,
}

impl BackendType {
    pub fn as_str(&self) -> &'static str {
        match self {
            BackendType::Pass => "pass",
            BackendType::Env => "env",
            BackendType::Local => "local",
        }
    }

    pub fn build(&self) -> Result<Arc<dyn SecretBackend>> {
        match self {
            BackendType::Pass => Ok(Arc::new(PassBackend::new())),
            BackendType::Env => Ok(Arc::new(EnvBackend::new())),
            BackendType::Local => {
                let mut backend = LocalBackend::new()?;
                if let Ok(recipient) = env::var("SSH_GUARD_GPG_RECIPIENT") {
                    backend = backend.with_gpg_recipient(recipient);
                }
                Ok(Arc::new(backend))
            }
        }
    }
}

impl std::str::FromStr for BackendType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pass" => Ok(BackendType::Pass),
            "env" => Ok(BackendType::Env),
            "local" => Ok(BackendType::Local),
            other => Err(format!(
                "unknown backend '{}'. Use: pass, env, local",
                other
            )),
        }
    }
}

pub fn detect_backend() -> BackendType {
    if let Ok(backend_str) = env::var("SSH_GUARD_BACKEND") {
        if let Ok(backend) = backend_str.parse::<BackendType>() {
            return backend;
        }
    }

    if pass_store_initialized() {
        return BackendType::Pass;
    }

    BackendType::Env
}

/// Resolve a UID to a user name via nsswitch; returns None when the UID
/// has no entry. Used only for display (audit lines, `secrets list`).
pub fn uid_to_name(uid: u32) -> Option<String> {
    uzers::get_user_by_uid(uid).and_then(|u| u.name().to_str().map(|s| s.to_string()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct MockBackend {
        store: Mutex<HashMap<(u32, String), String>>,
    }

    impl MockBackend {
        fn new() -> Self {
            Self {
                store: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl SecretBackend for MockBackend {
        fn name(&self) -> &str {
            "mock"
        }

        async fn get(&self, uid: u32, key: &str) -> Result<Option<String>> {
            let store = self.store.lock().unwrap();
            Ok(store.get(&(uid, key.to_string())).cloned())
        }

        async fn list(&self, uid: u32) -> Result<Vec<String>> {
            let store = self.store.lock().unwrap();
            Ok(store
                .keys()
                .filter(|(u, _)| *u == uid)
                .map(|(_, k)| k.clone())
                .collect())
        }

        async fn list_all(&self) -> Result<Vec<(u32, String)>> {
            let store = self.store.lock().unwrap();
            Ok(store.keys().cloned().collect())
        }

        async fn set(&self, uid: u32, key: &str, value: &str) -> Result<()> {
            let mut store = self.store.lock().unwrap();
            store.insert((uid, key.to_string()), value.to_string());
            Ok(())
        }

        async fn delete(&self, uid: u32, key: &str) -> Result<()> {
            let mut store = self.store.lock().unwrap();
            store.remove(&(uid, key.to_string()));
            Ok(())
        }
    }

    #[tokio::test]
    async fn secret_manager_per_user_basic() {
        let backend = Arc::new(MockBackend::new());
        let manager = SecretManager::new(backend);

        manager.set(1000, "api_key", "alice-key").await.unwrap();
        manager.set(1001, "api_key", "bob-key").await.unwrap();

        assert_eq!(
            manager.get(1000, "api_key").await.unwrap(),
            Some("alice-key".to_string())
        );
        assert_eq!(
            manager.get(1001, "api_key").await.unwrap(),
            Some("bob-key".to_string())
        );
        assert_eq!(manager.get(1002, "api_key").await.unwrap(), None);

        let alice_keys = manager.list(1000).await.unwrap();
        assert_eq!(alice_keys, vec!["api_key".to_string()]);

        let all = manager.list_all().await.unwrap();
        assert_eq!(all.len(), 2);

        manager.delete(1000, "api_key").await.unwrap();
        assert_eq!(manager.get(1000, "api_key").await.unwrap(), None);
        // Bob's still there.
        assert_eq!(
            manager.get(1001, "api_key").await.unwrap(),
            Some("bob-key".to_string())
        );
    }

    #[tokio::test]
    async fn secret_manager_cache_is_uid_keyed() {
        let backend = Arc::new(MockBackend::new());
        let manager = SecretManager::new(backend);

        manager.set(1000, "k", "alice").await.unwrap();
        manager.set(1001, "k", "bob").await.unwrap();

        // Populate cache
        let _ = manager.get(1000, "k").await;
        let _ = manager.get(1001, "k").await;

        let cache = manager.cache.read().await;
        let alice_ck = CacheKey {
            uid: 1000,
            key: "k".into(),
        };
        let bob_ck = CacheKey {
            uid: 1001,
            key: "k".into(),
        };
        assert_eq!(cache.get(&alice_ck).map(String::as_str), Some("alice"));
        assert_eq!(cache.get(&bob_ck).map(String::as_str), Some("bob"));
    }

    #[tokio::test]
    async fn secret_fd_creation() {
        let secret = "test_secret_content";
        let fd = SecretFd::new(secret).unwrap();

        assert!(fd.path.exists());
        let content = fs::read_to_string(fd.path()).unwrap();
        assert_eq!(content, secret);

        let metadata = fs::metadata(fd.path()).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[tokio::test]
    async fn env_backend_namespaces_by_uid() {
        let backend = EnvBackend::new();
        env::set_var("GUARD_SECRET_U2000_EB_KEY", "v2000");
        env::set_var("GUARD_SECRET_U2001_EB_KEY", "v2001");

        assert_eq!(
            backend.get(2000, "EB_KEY").await.unwrap(),
            Some("v2000".to_string())
        );
        assert_eq!(
            backend.get(2001, "EB_KEY").await.unwrap(),
            Some("v2001".to_string())
        );

        let keys = backend.list(2000).await.unwrap();
        assert!(keys.contains(&"EB_KEY".to_string()));

        let all = backend.list_all().await.unwrap();
        assert!(all.contains(&(2000u32, "EB_KEY".to_string())));
        assert!(all.contains(&(2001u32, "EB_KEY".to_string())));

        env::remove_var("GUARD_SECRET_U2000_EB_KEY");
        env::remove_var("GUARD_SECRET_U2001_EB_KEY");
    }

    #[tokio::test]
    async fn env_backend_surfaces_legacy_flat_keys_only_via_admin_view() {
        let backend = EnvBackend::new();
        env::set_var("GUARD_SECRET_LEGACY_KEY", "legacy");

        assert_eq!(backend.get(2000, "LEGACY_KEY").await.unwrap(), None);
        assert!(!backend
            .list(2000)
            .await
            .unwrap()
            .contains(&"LEGACY_KEY".to_string()));
        assert!(backend
            .list_all()
            .await
            .unwrap()
            .contains(&(LEGACY_UID_SENTINEL, "LEGACY_KEY".to_string())));

        env::remove_var("GUARD_SECRET_LEGACY_KEY");
    }

    #[tokio::test]
    async fn backend_type_parsing() {
        assert_eq!("pass".parse::<BackendType>().unwrap(), BackendType::Pass);
        assert_eq!("env".parse::<BackendType>().unwrap(), BackendType::Env);
        assert_eq!("local".parse::<BackendType>().unwrap(), BackendType::Local);
        assert_eq!("PASS".parse::<BackendType>().unwrap(), BackendType::Pass);
        assert!("invalid".parse::<BackendType>().is_err());
    }

    #[test]
    fn pass_store_listing_walks_uid_namespaces() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(".cache")
            .join(format!("pass-store-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("guard/u1000")).unwrap();
        fs::create_dir_all(root.join("guard/u1001/nested")).unwrap();
        fs::write(root.join("guard/u1000/OPNSENSE_API_KEY.gpg"), b"x").unwrap();
        fs::write(root.join("guard/u1001/nested/token.gpg"), b"y").unwrap();
        fs::write(root.join("guard/LEGACY.gpg"), b"z").unwrap();
        fs::write(root.join("guard/.gpg-id"), b"test").unwrap();

        let (all, legacy) = list_pass_store_entries(&root).unwrap();
        assert_eq!(
            all,
            vec![
                (1000u32, "OPNSENSE_API_KEY".to_string()),
                (1001u32, "nested/token".to_string())
            ]
        );
        assert_eq!(legacy, vec!["LEGACY".to_string()]);

        let _ = fs::remove_dir_all(&root);
    }
}
