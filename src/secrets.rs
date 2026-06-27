//! Secret broker for managing sensitive credentials across multiple backends.
//!
//! Secrets are stored per-principal: each caller has its own private namespace
//! keyed by key name. Two users can reuse the same key name (e.g.
//! `OPNSENSE_API_KEY`) without collision, and one user cannot read, list,
//! overwrite, or delete another user's secrets. The daemon principal has a
//! separate admin-only `list_all` entry point that returns the full
//! (principal, key) set for observability; it still cannot read another user's
//! values through the normal `get` path (which requires the owning principal).
//!
//! A principal is a [`PrincipalKey`]: a Unix uid string on Unix, a SID on
//! Windows. The per-principal storage segment is `PrincipalKey::segment()`,
//! which yields `u<uid>` for a uid (preserving the existing on-disk
//! `pass guard/u<uid>/...` and `secrets.yaml` `{<uid>: ...}` layout with no
//! migration) and a filesystem/env-safe form for SIDs.

use anyhow::{bail, Result};
use async_trait::async_trait;
use guard::principal::PrincipalKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::ffi::OsStr;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::process::Command as AsyncCommand;
use tokio::sync::RwLock;

/// Directory within pass where secrets are stored. Entries live at
/// `guard/<segment>/<key>` (e.g. `guard/u<uid>/<key>`) so one user's secrets
/// cannot collide with another's.
const PASS_PREFIX: &str = "guard/";

/// Prefix for environment variable secrets. Full form is
/// `GUARD_SECRET_<segment>_<KEY>` (e.g. `GUARD_SECRET_U<uid>_<KEY>`).
const ENV_PREFIX: &str = "GUARD_SECRET_";

/// Filename for the local encrypted secrets file.
const SECRETS_FILE: &str = "secrets.yaml";

/// Reserved principal used to tag entries recovered from the pre-namespacing
/// flat layout (`pass guard/<key>`, bare `GUARD_SECRET_<KEY>`, or a legacy flat
/// `secrets.yaml`). It is a non-colliding sentinel string: no real uid or SID
/// produces it, so it cannot be addressed as a normal namespace.
pub fn legacy_sentinel() -> PrincipalKey {
    PrincipalKey::from_raw("__legacy__")
}

type NamespacedSecretKey = (PrincipalKey, String);
type PassStoreEntries = (Vec<NamespacedSecretKey>, Vec<String>);

/// Trait for secret storage backends.
///
/// Implementors must be safe to share across threads (Send + Sync).
#[async_trait]
pub trait SecretBackend: Send + Sync {
    /// Returns the backend name for logging/debugging.
    fn name(&self) -> &str;

    /// Retrieve a secret by (principal, key).
    async fn get(&self, principal: &PrincipalKey, key: &str) -> Result<Option<String>>;

    /// List secret keys owned by `principal`.
    async fn list(&self, principal: &PrincipalKey) -> Result<Vec<String>>;

    /// Admin view: list every (principal, key) pair in the store. The daemon
    /// uses this for its aggregate `secrets list`. Backends that cannot
    /// enumerate by principal (env backend) should still return everything
    /// they can recover.
    async fn list_all(&self) -> Result<Vec<(PrincipalKey, String)>>;

    /// Store a secret under `principal`.
    async fn set(&self, principal: &PrincipalKey, key: &str, value: &str) -> Result<()>;

    /// Delete a secret owned by `principal`.
    async fn delete(&self, principal: &PrincipalKey, key: &str) -> Result<()>;
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

    fn pass_path(&self, principal: &PrincipalKey, key: &str) -> String {
        format!("{}{}/{}", PASS_PREFIX, principal.segment(), key)
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

/// Recover the owning principal from a stored namespace segment. A `u<digits>`
/// segment is a Unix uid and round-trips exactly to `PrincipalKey::from_uid`.
/// Any other segment is a SID-derived segment (non-alphanumerics already
/// collapsed to `_`); it is wrapped verbatim as the principal. SID segments are
/// not perfectly invertible to the original SID, so the recovered principal is
/// a stable display/grouping label for the admin aggregate view; per-caller
/// `list`/`get`/`set`/`delete` never round-trip through this — they address the
/// store by the live caller's `segment()`, which is exact.
fn principal_from_segment(segment: &str) -> PrincipalKey {
    if let Some(uid_str) = segment.strip_prefix('u') {
        if !uid_str.is_empty() && uid_str.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(uid) = uid_str.parse::<u32>() {
                return PrincipalKey::from_uid(uid);
            }
        }
    }
    PrincipalKey::from_raw(segment)
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
        // A namespaced entry lives under a per-principal segment directory
        // (`guard/<segment>/<key...>`, two-plus components). A bare file
        // directly under `guard/` is a pre-namespacing flat entry.
        if components.len() >= 2 {
            let principal = principal_from_segment(&components[0]);
            let key = key_parts[1..].join("/");
            if !key.is_empty() {
                namespaced.push((principal, key));
            }
            continue;
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

    async fn get(&self, principal: &PrincipalKey, key: &str) -> Result<Option<String>> {
        self.get_entry(&self.pass_path(principal, key)).await
    }

    async fn list(&self, principal: &PrincipalKey) -> Result<Vec<String>> {
        let Some(store_dir) = self.store_dir() else {
            return Ok(Vec::new());
        };
        // Filter by storage segment, which is exact for the live caller even
        // when the recovered-from-disk principal is only a display label.
        let want = principal.segment();
        let (namespaced, _) = list_pass_store_entries(store_dir)?;
        let mut keys: Vec<String> = namespaced
            .into_iter()
            .filter_map(|(entry_principal, key)| {
                if entry_principal.segment() == want {
                    Some(key)
                } else {
                    None
                }
            })
            .collect();
        keys.sort();
        keys.dedup();
        Ok(keys)
    }

    async fn list_all(&self) -> Result<Vec<(PrincipalKey, String)>> {
        let Some(store_dir) = self.store_dir() else {
            return Ok(Vec::new());
        };
        let (mut namespaced, legacy) = list_pass_store_entries(store_dir)?;
        namespaced.extend(legacy.into_iter().map(|key| (legacy_sentinel(), key)));
        namespaced.sort();
        namespaced.dedup();
        Ok(namespaced)
    }

    async fn set(&self, principal: &PrincipalKey, key: &str, value: &str) -> Result<()> {
        let path = self.pass_path(principal, key);

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

    async fn delete(&self, principal: &PrincipalKey, key: &str) -> Result<()> {
        let path = self.pass_path(principal, key);
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
/// `GUARD_SECRET_<SEGMENT>_<KEY>`; for a Unix uid the segment is `U<uid>`,
/// preserving the existing `GUARD_SECRET_U<uid>_<KEY>` form with no migration.
#[derive(Debug, Clone)]
pub struct EnvBackend {
    _priv: (),
}

impl EnvBackend {
    pub fn new() -> Self {
        Self { _priv: () }
    }

    /// The per-principal env segment. `PrincipalKey::segment()` yields `u<uid>`
    /// for a uid and an alphanumeric/`_` form for a SID; environment variable
    /// names are conventionally uppercase and case-sensitive, so the segment is
    /// uppercased. For a uid this is `U<uid>`, exactly the legacy layout.
    fn env_segment(principal: &PrincipalKey) -> String {
        principal.segment().to_ascii_uppercase()
    }

    fn env_key(principal: &PrincipalKey, secret_key: &str) -> String {
        format!(
            "{}{}_{}",
            ENV_PREFIX,
            Self::env_segment(principal),
            secret_key
        )
    }

    fn user_prefix(principal: &PrincipalKey) -> String {
        format!("{}{}_", ENV_PREFIX, Self::env_segment(principal))
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

    async fn get(&self, principal: &PrincipalKey, key: &str) -> Result<Option<String>> {
        Ok(env::var(Self::env_key(principal, key)).ok())
    }

    async fn list(&self, principal: &PrincipalKey) -> Result<Vec<String>> {
        let prefix = Self::user_prefix(principal);
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

    async fn list_all(&self) -> Result<Vec<(PrincipalKey, String)>> {
        // The env layout has no unambiguous delimiter between a SID segment and
        // the key (both contain `_`), so the aggregate view recovers the uid
        // namespace (`U<digits>_<key>`) exactly and tags everything else as a
        // pre-namespacing flat entry. Per-caller `list`/`get` are unaffected:
        // they match the full `user_prefix`, which is exact for any principal.
        let mut out = Vec::new();
        for (env_key, _) in env::vars() {
            if let Some(rest) = env_key.strip_prefix(ENV_PREFIX) {
                if let Some(after_u) = rest.strip_prefix('U') {
                    if let Some((uid_str, key)) = after_u.split_once('_') {
                        if !uid_str.is_empty()
                            && uid_str.bytes().all(|b| b.is_ascii_digit())
                            && !key.is_empty()
                        {
                            if let Ok(uid) = uid_str.parse::<u32>() {
                                out.push((PrincipalKey::from_uid(uid), key.to_string()));
                                continue;
                            }
                        }
                    }
                }
                if !rest.is_empty() {
                    out.push((legacy_sentinel(), rest.to_string()));
                }
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    async fn set(&self, principal: &PrincipalKey, key: &str, value: &str) -> Result<()> {
        env::set_var(Self::env_key(principal, key), value);
        Ok(())
    }

    async fn delete(&self, principal: &PrincipalKey, key: &str) -> Result<()> {
        env::remove_var(Self::env_key(principal, key));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// LocalBackend
// ---------------------------------------------------------------------------

/// Secret backend backed by an encrypted YAML file.
/// The on-disk shape is `{ <principal>: { <key>: <value> } }`. For a Unix uid
/// the principal key is the bare decimal uid (`{ 1000: { ... } }`), exactly the
/// pre-principal layout, so existing files read with no migration; a Windows SID
/// principal is the SID string.
#[derive(Debug, Clone)]
pub struct LocalBackend {
    path: PathBuf,
    gpg_recipient: Option<String>,
}

/// In-memory namespaced store, keyed by the principal's raw string. A Unix uid
/// principal is its decimal string (`"1000"`); the on-disk YAML key is the bare
/// scalar `1000`, and an integer YAML key is normalized to this string form on
/// load, so legacy uid-keyed files round-trip.
type LocalStore = HashMap<String, HashMap<String, String>>;
type LegacyLocalStore = HashMap<String, String>;

enum LocalStoreVariant {
    Namespaced(LocalStore),
    Legacy(LegacyLocalStore),
}

/// Normalize a YAML mapping key (which may be an integer for legacy uid-keyed
/// files, or a string) to the principal's raw string form.
fn yaml_key_to_principal_string(value: &serde_yaml::Value) -> Option<String> {
    match value {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
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
        // The namespaced shape is `{ <principal>: { <key>: <value> } }`. Parse
        // through `Value` so a legacy integer uid key (`1000:`) and a string
        // key (`"1000":` or a SID) both normalize to the principal raw string.
        if let Ok(serde_yaml::Value::Mapping(map)) =
            serde_yaml::from_str::<serde_yaml::Value>(&content)
        {
            let mut namespaced: LocalStore = HashMap::new();
            let mut all_namespaced = true;
            for (k, v) in &map {
                let (Some(principal), Ok(inner)) = (
                    yaml_key_to_principal_string(k),
                    serde_yaml::from_value::<HashMap<String, String>>(v.clone()),
                ) else {
                    all_namespaced = false;
                    break;
                };
                namespaced.insert(principal, inner);
            }
            if all_namespaced {
                return Ok(LocalStoreVariant::Namespaced(namespaced));
            }
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

    async fn get(&self, principal: &PrincipalKey, key: &str) -> Result<Option<String>> {
        let ns = principal.as_str();
        match self.load_store_variant().await? {
            LocalStoreVariant::Namespaced(store) => {
                Ok(store.get(ns).and_then(|m| m.get(key)).cloned())
            }
            LocalStoreVariant::Legacy(_) => Ok(None),
        }
    }

    async fn list(&self, principal: &PrincipalKey) -> Result<Vec<String>> {
        let ns = principal.as_str();
        let mut keys: Vec<String> = match self.load_store_variant().await? {
            LocalStoreVariant::Namespaced(store) => store
                .get(ns)
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default(),
            LocalStoreVariant::Legacy(_) => Vec::new(),
        };
        keys.sort();
        keys.dedup();
        Ok(keys)
    }

    async fn list_all(&self) -> Result<Vec<(PrincipalKey, String)>> {
        let mut out: Vec<(PrincipalKey, String)> = match self.load_store_variant().await? {
            LocalStoreVariant::Namespaced(store) => store
                .iter()
                .flat_map(|(ns, m)| {
                    let principal = PrincipalKey::from_raw(ns.clone());
                    m.keys().map(move |k| (principal.clone(), k.clone()))
                })
                .collect(),
            LocalStoreVariant::Legacy(store) => store
                .keys()
                .cloned()
                .map(|k| (legacy_sentinel(), k))
                .collect(),
        };
        out.sort();
        out.dedup();
        Ok(out)
    }

    async fn set(&self, principal: &PrincipalKey, key: &str, value: &str) -> Result<()> {
        let ns = principal.as_str().to_string();
        match self.load_store_variant().await? {
            LocalStoreVariant::Namespaced(mut store) => {
                store
                    .entry(ns)
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

    async fn delete(&self, principal: &PrincipalKey, key: &str) -> Result<()> {
        let ns = principal.as_str();
        match self.load_store_variant().await? {
            LocalStoreVariant::Namespaced(mut store) => {
                if let Some(m) = store.get_mut(ns) {
                    m.remove(key);
                    if m.is_empty() {
                        store.remove(ns);
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

/// File-descriptor wrapper for secret injection. The secret is written to a
/// temporary file readable only by the owner, and cleaned up on drop.
///
/// Owner-only access is enforced differently per platform:
/// - Unix: an explicit `0600` mode on the file.
/// - Windows: the temp dir is created under the daemon service account's
///   `%TEMP%`, which inherits that account's owner-scoped default ACL; no
///   other account (including the unrelated agent account) can read it.
#[derive(Debug)]
pub struct SecretFd {
    pub path: PathBuf,
    temp_dir: tempfile::TempDir,
}

impl SecretFd {
    fn new(secret: &str) -> Result<Self> {
        #[cfg(unix)]
        let temp_dir = tempfile::TempDir::new_in("/tmp")?;
        #[cfg(windows)]
        let temp_dir = tempfile::TempDir::new()?;
        let path = temp_dir.path().join("secret");

        fs::write(&path, secret)?;
        // Restrict to the owner. On Unix this is the 0600 mode bit; on Windows
        // the file inherits the owner-scoped default ACL of the service
        // account's per-user temp directory (see the type-level docs).
        #[cfg(unix)]
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
    principal: PrincipalKey,
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

    pub async fn get(&self, principal: &PrincipalKey, key: &str) -> Result<Option<String>> {
        let ck = CacheKey {
            principal: principal.clone(),
            key: key.to_string(),
        };
        {
            let cache = self.cache.read().await;
            if let Some(value) = cache.get(&ck) {
                return Ok(Some(value.clone()));
            }
        }

        let value = self.backend.get(principal, key).await?;

        if let Some(ref v) = value {
            let mut cache = self.cache.write().await;
            cache.insert(ck, v.clone());
        }

        Ok(value)
    }

    pub async fn list(&self, principal: &PrincipalKey) -> Result<Vec<String>> {
        self.backend.list(principal).await
    }

    pub async fn list_all(&self) -> Result<Vec<(PrincipalKey, String)>> {
        self.backend.list_all().await
    }

    pub async fn set(&self, principal: &PrincipalKey, key: &str, value: &str) -> Result<()> {
        self.backend.set(principal, key, value).await?;
        let mut cache = self.cache.write().await;
        cache.insert(
            CacheKey {
                principal: principal.clone(),
                key: key.to_string(),
            },
            value.to_string(),
        );
        Ok(())
    }

    pub async fn delete(&self, principal: &PrincipalKey, key: &str) -> Result<()> {
        self.backend.delete(principal, key).await?;
        let mut cache = self.cache.write().await;
        cache.remove(&CacheKey {
            principal: principal.clone(),
            key: key.to_string(),
        });
        Ok(())
    }

    pub async fn inject_fd(&self, principal: &PrincipalKey, key: &str) -> Result<SecretFd> {
        let secret = match self.get(principal, key).await? {
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
                if let Some(recipient) = guard::env::guard_env("GPG_RECIPIENT") {
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
    if let Some(backend_str) = guard::env::guard_env("BACKEND") {
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
#[cfg(unix)]
pub fn uid_to_name(uid: u32) -> Option<String> {
    uzers::get_user_by_uid(uid).and_then(|u| u.name().to_str().map(|s| s.to_string()))
}

/// No passwd database on Windows; secret namespaces are keyed by SID string and
/// this display-only helper has no numeric-UID source.
#[cfg(windows)]
pub fn uid_to_name(_uid: u32) -> Option<String> {
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::Mutex;

    fn p(uid: u32) -> PrincipalKey {
        PrincipalKey::from_uid(uid)
    }

    #[derive(Debug, Default)]
    struct MockBackend {
        store: Mutex<HashMap<(PrincipalKey, String), String>>,
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

        async fn get(&self, principal: &PrincipalKey, key: &str) -> Result<Option<String>> {
            let store = self.store.lock().unwrap();
            Ok(store.get(&(principal.clone(), key.to_string())).cloned())
        }

        async fn list(&self, principal: &PrincipalKey) -> Result<Vec<String>> {
            let store = self.store.lock().unwrap();
            Ok(store
                .keys()
                .filter(|(u, _)| u == principal)
                .map(|(_, k)| k.clone())
                .collect())
        }

        async fn list_all(&self) -> Result<Vec<(PrincipalKey, String)>> {
            let store = self.store.lock().unwrap();
            Ok(store.keys().cloned().collect())
        }

        async fn set(&self, principal: &PrincipalKey, key: &str, value: &str) -> Result<()> {
            let mut store = self.store.lock().unwrap();
            store.insert((principal.clone(), key.to_string()), value.to_string());
            Ok(())
        }

        async fn delete(&self, principal: &PrincipalKey, key: &str) -> Result<()> {
            let mut store = self.store.lock().unwrap();
            store.remove(&(principal.clone(), key.to_string()));
            Ok(())
        }
    }

    #[tokio::test]
    async fn secret_manager_per_user_basic() {
        let backend = Arc::new(MockBackend::new());
        let manager = SecretManager::new(backend);

        manager.set(&p(1000), "api_key", "alice-key").await.unwrap();
        manager.set(&p(1001), "api_key", "bob-key").await.unwrap();

        assert_eq!(
            manager.get(&p(1000), "api_key").await.unwrap(),
            Some("alice-key".to_string())
        );
        assert_eq!(
            manager.get(&p(1001), "api_key").await.unwrap(),
            Some("bob-key".to_string())
        );
        assert_eq!(manager.get(&p(1002), "api_key").await.unwrap(), None);

        let alice_keys = manager.list(&p(1000)).await.unwrap();
        assert_eq!(alice_keys, vec!["api_key".to_string()]);

        let all = manager.list_all().await.unwrap();
        assert_eq!(all.len(), 2);

        manager.delete(&p(1000), "api_key").await.unwrap();
        assert_eq!(manager.get(&p(1000), "api_key").await.unwrap(), None);
        // Bob's still there.
        assert_eq!(
            manager.get(&p(1001), "api_key").await.unwrap(),
            Some("bob-key".to_string())
        );
    }

    #[tokio::test]
    async fn secret_manager_per_principal_isolates_sid_from_uid() {
        // A Windows SID principal and a Unix uid principal are distinct
        // namespaces even when a key name collides.
        let backend = Arc::new(MockBackend::new());
        let manager = SecretManager::new(backend);

        let sid = PrincipalKey::from_sid("S-1-5-21-1-2-3-1001");
        manager.set(&p(1000), "api_key", "unix-val").await.unwrap();
        manager.set(&sid, "api_key", "win-val").await.unwrap();

        assert_eq!(
            manager.get(&sid, "api_key").await.unwrap(),
            Some("win-val".to_string())
        );
        assert_eq!(
            manager.get(&p(1000), "api_key").await.unwrap(),
            Some("unix-val".to_string())
        );
        // The uid principal cannot see the SID's value and vice versa.
        assert_eq!(manager.list(&sid).await.unwrap(), vec!["api_key"]);
    }

    #[tokio::test]
    async fn secret_manager_cache_is_principal_keyed() {
        let backend = Arc::new(MockBackend::new());
        let manager = SecretManager::new(backend);

        manager.set(&p(1000), "k", "alice").await.unwrap();
        manager.set(&p(1001), "k", "bob").await.unwrap();

        // Populate cache
        let _ = manager.get(&p(1000), "k").await;
        let _ = manager.get(&p(1001), "k").await;

        let cache = manager.cache.read().await;
        let alice_ck = CacheKey {
            principal: p(1000),
            key: "k".into(),
        };
        let bob_ck = CacheKey {
            principal: p(1001),
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

        // 0600 is a Unix permission semantic; on Windows the temp dir's default
        // ACL provides owner-only access and there is no mode bit to assert.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(fd.path()).unwrap();
            let mode = metadata.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[tokio::test]
    async fn env_backend_namespaces_by_uid() {
        let backend = EnvBackend::new();
        // The on-disk env layout is the uppercase `U<uid>` segment; a uid
        // principal's `segment()` (`u<uid>`) is uppercased to match it, so
        // existing `GUARD_SECRET_U<uid>_<KEY>` vars are read with no migration.
        env::set_var("GUARD_SECRET_U2000_EB_KEY", "v2000");
        env::set_var("GUARD_SECRET_U2001_EB_KEY", "v2001");

        assert_eq!(
            backend.get(&p(2000), "EB_KEY").await.unwrap(),
            Some("v2000".to_string())
        );
        assert_eq!(
            backend.get(&p(2001), "EB_KEY").await.unwrap(),
            Some("v2001".to_string())
        );

        let keys = backend.list(&p(2000)).await.unwrap();
        assert!(keys.contains(&"EB_KEY".to_string()));

        let all = backend.list_all().await.unwrap();
        assert!(all.contains(&(p(2000), "EB_KEY".to_string())));
        assert!(all.contains(&(p(2001), "EB_KEY".to_string())));

        env::remove_var("GUARD_SECRET_U2000_EB_KEY");
        env::remove_var("GUARD_SECRET_U2001_EB_KEY");
    }

    #[tokio::test]
    async fn env_backend_set_uses_legacy_uppercase_uid_layout() {
        // Writing through the principal API must produce exactly the historical
        // `GUARD_SECRET_U<uid>_<KEY>` variable so a uid namespace is wire- and
        // disk-compatible across the retype.
        let backend = EnvBackend::new();
        let key = format!("SETFMT_{}", std::process::id());
        backend.set(&p(4242), &key, "v").await.unwrap();
        let expected = format!("GUARD_SECRET_U4242_{key}");
        assert_eq!(env::var(&expected).ok(), Some("v".to_string()));
        backend.delete(&p(4242), &key).await.unwrap();
        assert!(env::var(&expected).is_err());
    }

    #[tokio::test]
    async fn env_backend_surfaces_legacy_flat_keys_only_via_admin_view() {
        let backend = EnvBackend::new();
        env::set_var("GUARD_SECRET_LEGACY_KEY", "legacy");

        assert_eq!(backend.get(&p(2000), "LEGACY_KEY").await.unwrap(), None);
        assert!(!backend
            .list(&p(2000))
            .await
            .unwrap()
            .contains(&"LEGACY_KEY".to_string()));
        assert!(backend
            .list_all()
            .await
            .unwrap()
            .contains(&(legacy_sentinel(), "LEGACY_KEY".to_string())));

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
    fn pass_store_listing_walks_principal_namespaces() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(".cache")
            .join(format!("pass-store-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("guard/u1000")).unwrap();
        fs::create_dir_all(root.join("guard/u1001/nested")).unwrap();
        // A SID-derived segment (the form `PrincipalKey::segment()` emits).
        fs::create_dir_all(root.join("guard/S_1_5_21_1_2_3_1001")).unwrap();
        fs::write(root.join("guard/u1000/OPNSENSE_API_KEY.gpg"), b"x").unwrap();
        fs::write(root.join("guard/u1001/nested/token.gpg"), b"y").unwrap();
        fs::write(root.join("guard/S_1_5_21_1_2_3_1001/WIN_KEY.gpg"), b"w").unwrap();
        fs::write(root.join("guard/LEGACY.gpg"), b"z").unwrap();
        fs::write(root.join("guard/.gpg-id"), b"test").unwrap();

        let (all, legacy) = list_pass_store_entries(&root).unwrap();
        // Entries are sorted lexically by principal string: the decimal uids
        // sort ahead of the `S`-prefixed SID segment.
        assert_eq!(
            all,
            vec![
                (PrincipalKey::from_uid(1000), "OPNSENSE_API_KEY".to_string()),
                (PrincipalKey::from_uid(1001), "nested/token".to_string()),
                (
                    PrincipalKey::from_raw("S_1_5_21_1_2_3_1001"),
                    "WIN_KEY".to_string()
                ),
            ]
        );
        assert_eq!(legacy, vec!["LEGACY".to_string()]);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn local_store_yaml_key_normalizes_integer_uid_to_principal_string() {
        // A pre-principal `secrets.yaml` stores the bare integer uid as the
        // mapping key (`1000: { ... }`). The load path normalizes that integer
        // key to the uid principal's raw string, so the matching uid principal
        // reads its own namespace with no migration. A string SID key is
        // preserved verbatim.
        let legacy_int: serde_yaml::Value =
            serde_yaml::from_str("1000:\n  OPNSENSE_API_KEY: v\n").unwrap();
        let serde_yaml::Value::Mapping(map) = legacy_int else {
            panic!("expected mapping");
        };
        let (int_key, inner) = map.iter().next().unwrap();
        assert_eq!(
            yaml_key_to_principal_string(int_key).as_deref(),
            Some(PrincipalKey::from_uid(1000).as_str())
        );
        // The inner map deserializes as the per-key value store.
        let inner: HashMap<String, String> = serde_yaml::from_value(inner.clone()).unwrap();
        assert_eq!(inner.get("OPNSENSE_API_KEY").map(String::as_str), Some("v"));

        let sid_keyed: serde_yaml::Value =
            serde_yaml::from_str("S-1-5-21-1-2-3-1001:\n  WIN_KEY: v\n").unwrap();
        let serde_yaml::Value::Mapping(map) = sid_keyed else {
            panic!("expected mapping");
        };
        let (sid_key, _) = map.iter().next().unwrap();
        assert_eq!(
            yaml_key_to_principal_string(sid_key).as_deref(),
            Some(PrincipalKey::from_sid("S-1-5-21-1-2-3-1001").as_str())
        );
    }
}
