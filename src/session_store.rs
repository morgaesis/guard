use crate::grant_profile::{EvaluationMode, GrantRequest, SavedGrant};
use crate::session::{
    session_grant_revision_key, CredentialReference, HistoricalGrant, HistoricalStatus,
    IssuedGrantScope, SessionDecisionSource, SessionExactRule, SessionExecStatus, SessionGrant,
    SessionInteraction, SessionOwner, SessionRegistry,
};
use anyhow::{Context, Result};
use guard::gating::approval::{Approval, ApprovalStatus};
use guard::gating::provisional::{Provisional, ProvisionalStatus, REVERT_BODY_CLEANUP_PREFIX};
use guard::gating::read_grant::ReadGrant;
use guard::redact::{redact_output_text, SENSITIVE_ARGV_REPLAY_GUIDANCE};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

/// Version 6 sanitizes persisted command-derived text (recorded argv, deny
/// reasons, prompts, learned exact rules) with credential redaction; see
/// `sanitize_persisted_credentials`.
///
/// Version 7 binds every live and historical session to the authenticated
/// principal that created it (`owner_json` on `session_grants` and
/// `session_history`). Rows carried forward from v6 default to the `Unowned`
/// sentinel, which is refused for any authority use until the session is
/// reissued.
///
/// Version 8 adds access-managed session scope and per-request bounded-use
/// accounting.
///
/// Version 9 adds a durable registry generation. Every full registry rewrite
/// compares and advances that generation in the same SQLite transaction, so
/// independently running daemons cannot consume the same bounded use or
/// restore an older authority snapshot. Older binaries reject schema 9 instead
/// of writing without that concurrency boundary.
///
/// Version 10 removes literal-sensitive argv from durable approval and
/// provisional rows. Version 11 removes literal-sensitive session exact
/// authority instead of redacting it into a different matcher, clears legacy
/// approval parameter maps, and preserves every terminal provisional status.
///
/// Version 12 sanitizes nested decision traces and persisted explanatory prose,
/// storing malformed non-authoritative traces as `NULL`. Version 13
/// canonicalizes the full generated-access proposal envelope. Version 14 adds
/// the inert pre-handoff provisional state and classifies ambiguous v13 API
/// dispatch rows before older binaries can interpret their rollback authority.
const SCHEMA_VERSION: i64 = 14;
const VACUUM_MIN_PAGES: u64 = 512;
const VACUUM_MIN_FREE_PAGES: u64 = 128;
const REGISTRY_GENERATION_KEY: &str = "registry_generation";

#[derive(Debug)]
struct SessionRevisionUpdate {
    token: String,
    old_revision: String,
    new_revision: String,
    token_fingerprint: String,
}

fn access_session_token_fingerprint(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    format!(
        "sha256:{}",
        digest[..16]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

#[derive(Debug)]
struct RegistryGenerationConflict {
    expected: u64,
    found: u64,
}

impl std::fmt::Display for RegistryGenerationConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "session registry changed in another daemon (expected generation {}, found {}); reload before retrying",
            self.expected, self.found
        )
    }
}

impl std::error::Error for RegistryGenerationConflict {}

#[derive(Debug, Default)]
struct RegistryWriteState {
    database_generation: u64,
    last_written_revision: u64,
}

#[derive(Debug, Clone, Copy)]
struct RegistryCommitOptions {
    fail_before_commit: bool,
    expected_generation: u64,
}

#[derive(Clone, Copy)]
enum StaleRegistryWrite {
    Ignore,
    Reject(&'static str),
}

#[cfg(test)]
pub(crate) type RegistryCommitHook = (
    std::sync::Arc<tokio::sync::Semaphore>,
    std::sync::Arc<tokio::sync::Semaphore>,
);

#[cfg(test)]
fn registry_commit_hooks(
) -> &'static std::sync::Mutex<std::collections::BTreeMap<(usize, &'static str), RegistryCommitHook>>
{
    static HOOKS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::BTreeMap<(usize, &'static str), RegistryCommitHook>>,
    > = std::sync::OnceLock::new();
    HOOKS.get_or_init(|| std::sync::Mutex::new(std::collections::BTreeMap::new()))
}

#[cfg(test)]
fn registry_commit_hook(gate: usize, task: &'static str) -> RegistryCommitHook {
    let committed = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    let release = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    registry_commit_hooks()
        .lock()
        .expect("registry commit hook lock")
        .insert((gate, task), (committed.clone(), release.clone()));
    (committed, release)
}

#[cfg(test)]
type RegistryWriteAttemptHooks = std::sync::Mutex<
    std::collections::BTreeMap<(usize, &'static str), std::sync::Arc<tokio::sync::Semaphore>>,
>;

#[cfg(test)]
fn registry_write_attempt_hooks() -> &'static std::sync::Mutex<
    std::collections::BTreeMap<(usize, &'static str), std::sync::Arc<tokio::sync::Semaphore>>,
> {
    static HOOKS: std::sync::OnceLock<RegistryWriteAttemptHooks> = std::sync::OnceLock::new();
    HOOKS.get_or_init(|| std::sync::Mutex::new(std::collections::BTreeMap::new()))
}

#[cfg(test)]
fn registry_write_attempt_hook(
    gate: usize,
    task: &'static str,
) -> std::sync::Arc<tokio::sync::Semaphore> {
    let signal = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    registry_write_attempt_hooks()
        .lock()
        .expect("registry write attempt hook lock")
        .insert((gate, task), signal.clone());
    signal
}

#[cfg(test)]
fn signal_registry_write_attempt(gate: usize, task: &'static str) {
    if let Some(signal) = registry_write_attempt_hooks()
        .lock()
        .expect("registry write attempt hook lock")
        .remove(&(gate, task))
    {
        signal.add_permits(1);
    }
}

#[cfg(test)]
async fn pause_registry_write_after_commit(gate: usize, task: &'static str) {
    let hook = registry_commit_hooks()
        .lock()
        .expect("registry commit hook lock")
        .remove(&(gate, task));
    if let Some((committed, release)) = hook {
        committed.add_permits(1);
        release
            .acquire()
            .await
            .expect("registry commit hook remains open")
            .forget();
    }
}

#[derive(Debug, Clone)]
pub struct SessionStore {
    path: PathBuf,
    history_retention_secs: u64,
    /// Held by daemon-opened stores from before SQLite initialization until
    /// every clone of the running daemon's store has been dropped.
    daemon_lease: Option<std::sync::Arc<StateDatabaseLease>>,
    /// Serializes writes from this process and carries the durable generation
    /// expected by its next full registry rewrite. SQLite compares that
    /// generation inside the rewrite transaction, extending stale-snapshot
    /// protection across independently opened stores and daemon processes.
    registry_write_gate: std::sync::Arc<tokio::sync::Mutex<RegistryWriteState>>,
    #[cfg(test)]
    fail_next_write: std::sync::Arc<std::sync::atomic::AtomicBool>,
    #[cfg(test)]
    fail_next_approval: std::sync::Arc<std::sync::atomic::AtomicBool>,
    #[cfg(test)]
    fail_next_provisional_delete: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// Process-lifetime ownership of one state database. The operating system
/// releases the advisory lock if the daemon exits or crashes. The lock file is
/// intentionally retained so a new inode cannot bypass a live lock.
#[derive(Debug)]
pub struct StateDatabaseLease {
    _file: File,
}

impl SessionStore {
    #[cfg(test)]
    pub(crate) fn pause_registry_commit_for_test(&self, task: &'static str) -> RegistryCommitHook {
        registry_commit_hook(
            std::sync::Arc::as_ptr(&self.registry_write_gate) as usize,
            task,
        )
    }

    #[cfg(test)]
    pub(crate) fn observe_registry_write_attempt_for_test(
        &self,
        task: &'static str,
    ) -> std::sync::Arc<tokio::sync::Semaphore> {
        registry_write_attempt_hook(
            std::sync::Arc::as_ptr(&self.registry_write_gate) as usize,
            task,
        )
    }

    async fn run_registry_write<F>(
        &self,
        task: &'static str,
        revision: u64,
        stale: StaleRegistryWrite,
        operation: F,
    ) -> Result<()>
    where
        F: FnOnce(u64) -> Result<u64> + Send + 'static,
    {
        let gate = self.registry_write_gate.clone();
        #[cfg(test)]
        let gate_identity = std::sync::Arc::as_ptr(&gate) as usize;
        tokio::spawn(async move {
            #[cfg(test)]
            signal_registry_write_attempt(gate_identity, task);
            let mut state = gate.lock().await;
            if revision < state.last_written_revision {
                return match stale {
                    StaleRegistryWrite::Ignore => Ok(()),
                    StaleRegistryWrite::Reject(message) => anyhow::bail!(message),
                };
            }
            let expected_generation = state.database_generation;
            let generation = tokio::task::spawn_blocking(move || operation(expected_generation))
                .await
                .with_context(|| format!("{task} task failed"))??;
            #[cfg(test)]
            pause_registry_write_after_commit(gate_identity, task).await;
            state.database_generation = generation;
            state.last_written_revision = revision;
            Ok(())
        })
        .await
        .with_context(|| format!("{task} coordination task failed"))?
    }

    pub(crate) fn is_registry_generation_conflict(error: &anyhow::Error) -> bool {
        error.downcast_ref::<RegistryGenerationConflict>().is_some()
    }

    pub(crate) fn has_daemon_lease(&self) -> bool {
        self.daemon_lease.is_some()
    }

    #[cfg(test)]
    pub async fn open(path: PathBuf, history_retention_secs: u64) -> Result<Self> {
        let path_for_open = path.clone();
        tokio::task::spawn_blocking(move || {
            Self::open_sync(path_for_open, history_retention_secs, None)
        })
        .await
        .context("session store open task failed")?
    }

    /// Open the state database for a daemon. The path lease is acquired before
    /// SQLite can initialize, migrate, sanitize, or repair any durable row.
    pub async fn open_for_daemon(path: PathBuf, history_retention_secs: u64) -> Result<Self> {
        tokio::task::spawn_blocking(move || {
            let path = Self::normalize_daemon_database_path(&path)?;
            Self::ensure_single_link_database(&path)?;
            let lease = std::sync::Arc::new(Self::acquire_daemon_lease_sync(&path)?);
            Self::ensure_single_link_database(&path)?;
            let store = Self::open_sync(path.clone(), history_retention_secs, Some(lease))?;
            Self::ensure_single_link_database(&path)?;
            Ok(store)
        })
        .await
        .context("daemon session store open task failed")?
    }

    fn normalize_daemon_database_path(path: &Path) -> Result<PathBuf> {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .context("resolve current directory for state database")?
                .join(path)
        };
        let file_name = absolute
            .file_name()
            .context("state database path must name a file")?
            .to_os_string();
        let parent = absolute
            .parent()
            .context("state database path must have a parent directory")?;

        #[cfg(unix)]
        {
            create_parent_without_symlinks(parent)?;
            secure_state_parent(parent)?;
        }
        #[cfg(windows)]
        {
            Self::ensure_windows_path_has_no_reparse_points(&absolute)?;
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create state database parent {}", parent.display()))?;
            if !crate::server::secure_fs::harden_existing_state_path(parent, true) {
                anyhow::bail!(
                    "state database parent {} is not protected from ordinary local users",
                    parent.display()
                );
            }
            Self::ensure_windows_path_has_no_reparse_points(&absolute)?;
        }
        #[cfg(not(any(unix, windows)))]
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create state database parent {}", parent.display()))?;

        let canonical_parent = std::fs::canonicalize(parent)
            .with_context(|| format!("canonicalize state database parent {}", parent.display()))?;
        let canonical = canonical_parent.join(file_name);
        #[cfg(windows)]
        Self::ensure_windows_path_has_no_reparse_points(&canonical)?;
        Ok(canonical)
    }

    #[cfg(windows)]
    fn ensure_windows_path_has_no_reparse_points(path: &Path) -> Result<()> {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

        let mut ancestors = path.ancestors().collect::<Vec<_>>();
        ancestors.reverse();
        for ancestor in ancestors {
            if ancestor.as_os_str().is_empty() {
                continue;
            }
            match std::fs::symlink_metadata(ancestor) {
                Ok(metadata) if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 => {
                    anyhow::bail!(
                        "state database path {} contains reparse point {}",
                        path.display(),
                        ancestor.display()
                    );
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "inspect state database path component {}",
                            ancestor.display()
                        )
                    });
                }
            }
        }
        Ok(())
    }

    pub async fn load_registry(&self) -> Result<SessionRegistry> {
        let path = self.path.clone();
        let retention = self.history_retention_secs;
        let gate = self.registry_write_gate.clone();
        #[cfg(test)]
        let gate_identity = std::sync::Arc::as_ptr(&gate) as usize;
        tokio::spawn(async move {
            let mut write_state = gate.lock().await;
            let (registry, generation) =
                tokio::task::spawn_blocking(move || Self::load_registry_sync(&path, retention))
                    .await
                    .context("session store load task failed")??;
            #[cfg(test)]
            pause_registry_write_after_commit(gate_identity, "session store load").await;
            write_state.database_generation = generation;
            write_state.last_written_revision = registry.revision();
            Ok(registry)
        })
        .await
        .context("session store load coordination task failed")?
    }

    /// Acquire the single-daemon lease for this state database. Daemon startup
    /// must hold this lease before loading or recovering consequence state, so
    /// a live `Reverting` claim is never reclassified by a second process.
    #[cfg(test)]
    pub async fn acquire_daemon_lease(&self) -> Result<StateDatabaseLease> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || Self::acquire_daemon_lease_sync(&path))
            .await
            .context("state database lease task failed")?
    }

    fn acquire_daemon_lease_sync(path: &Path) -> Result<StateDatabaseLease> {
        let mut lock_name = path.as_os_str().to_os_string();
        lock_name.push(".daemon.lock");
        let lock_path = PathBuf::from(lock_name);
        prepare_state_path(&lock_path)?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
            Self::ensure_windows_path_has_no_reparse_points(&lock_path)?;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let file = options
            .open(&lock_path)
            .with_context(|| format!("open daemon lease {}", lock_path.display()))?;
        #[cfg(windows)]
        Self::validate_windows_state_handle(&file, &lock_path)?;
        file.try_lock().map_err(|error| {
            anyhow::anyhow!(
                "state database {} already has an active daemon: {}",
                path.display(),
                error
            )
        })?;
        Ok(StateDatabaseLease { _file: file })
    }

    fn ensure_single_link_database(path: &Path) -> Result<()> {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(error).with_context(|| format!("inspect state db {}", path.display()))
            }
        };
        #[cfg(unix)]
        let links = metadata.nlink();
        #[cfg(windows)]
        let links = {
            if metadata.file_type().is_symlink() {
                anyhow::bail!(
                    "state database {} is a symbolic link; daemon state requires an unaliased path",
                    path.display()
                );
            }
            Self::windows_link_count(path)?
        };
        #[cfg(not(any(unix, windows)))]
        let links = 1;
        if links != 1 {
            anyhow::bail!(
                "state database {} has {links} hard links; daemon state requires one unaliased path",
                path.display()
            );
        }
        Ok(())
    }

    #[cfg(windows)]
    fn windows_link_count(path: &Path) -> Result<u64> {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .with_context(|| format!("open state db {} for identity check", path.display()))?;
        Self::validate_windows_state_handle(&file, path)
    }

    #[cfg(windows)]
    fn validate_windows_state_handle(file: &File, path: &Path) -> Result<u64> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, GetFinalPathNameByHandleW, BY_HANDLE_FILE_INFORMATION,
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_NAME_NORMALIZED, VOLUME_NAME_DOS,
        };

        let handle = file.as_raw_handle() as _;
        let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        let result = unsafe { GetFileInformationByHandle(handle, &mut information) };
        if result == 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("inspect state db identity {}", path.display()));
        }
        if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            anyhow::bail!("state database path {} is a reparse point", path.display());
        }
        if information.nNumberOfLinks != 1 {
            anyhow::bail!(
                "state database path {} has {} hard links",
                path.display(),
                information.nNumberOfLinks
            );
        }
        let length = unsafe {
            GetFinalPathNameByHandleW(
                handle,
                std::ptr::null_mut(),
                0,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        };
        if length == 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("resolve opened state path {}", path.display()));
        }
        let mut final_path = vec![0_u16; length as usize + 1];
        let written = unsafe {
            GetFinalPathNameByHandleW(
                handle,
                final_path.as_mut_ptr(),
                final_path.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        };
        if written == 0 || written as usize >= final_path.len() {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("resolve opened state path {}", path.display()));
        }
        final_path.truncate(written as usize);
        let final_path = String::from_utf16(&final_path)
            .context("opened state path is not valid UTF-16")?
            .trim_start_matches(r"\\?\")
            .to_ascii_lowercase();
        let expected = std::fs::canonicalize(path)
            .with_context(|| format!("canonicalize opened state path {}", path.display()))?
            .to_string_lossy()
            .trim_start_matches(r"\\?\")
            .to_ascii_lowercase();
        if final_path != expected {
            anyhow::bail!(
                "opened state path {} resolves to a different filesystem object",
                path.display()
            );
        }
        Ok(u64::from(information.nNumberOfLinks))
    }

    pub async fn persist_registry(&self, registry: &SessionRegistry) -> Result<()> {
        self.persist_registry_with_stale_policy(registry, StaleRegistryWrite::Ignore)
            .await
    }

    pub(crate) async fn persist_registry_strict(&self, registry: &SessionRegistry) -> Result<()> {
        self.persist_registry_with_stale_policy(
            registry,
            StaleRegistryWrite::Reject("session amendment snapshot is stale"),
        )
        .await
    }

    async fn persist_registry_with_stale_policy(
        &self,
        registry: &SessionRegistry,
        stale: StaleRegistryWrite,
    ) -> Result<()> {
        #[cfg(test)]
        if self
            .fail_next_write
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            anyhow::bail!("simulated session-store write failure");
        }
        let path = self.path.clone();
        let retention = self.history_retention_secs;
        let mut snapshot = registry.clone().with_history_retention(retention);
        snapshot.purge_expired();
        let revision = snapshot.revision();
        self.run_registry_write(
            "session store persist",
            revision,
            stale,
            move |expected_generation| {
                Self::persist_registry_sync(&path, retention, &snapshot, expected_generation)
            },
        )
        .await
    }

    fn open_sync(
        path: PathBuf,
        history_retention_secs: u64,
        daemon_lease: Option<std::sync::Arc<StateDatabaseLease>>,
    ) -> Result<Self> {
        let (registry, generation) = Self::load_registry_sync(&path, history_retention_secs)?;
        let store = Self {
            path,
            history_retention_secs,
            daemon_lease,
            registry_write_gate: std::sync::Arc::new(tokio::sync::Mutex::new(RegistryWriteState {
                database_generation: generation,
                last_written_revision: registry.revision(),
            })),
            #[cfg(test)]
            fail_next_write: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            #[cfg(test)]
            fail_next_approval: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            #[cfg(test)]
            fail_next_provisional_delete: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
                false,
            )),
        };
        Ok(store)
    }

    fn load_registry_sync(
        path: &Path,
        history_retention_secs: u64,
    ) -> Result<(SessionRegistry, u64)> {
        Self::load_registry_sync_with_hook(path, history_retention_secs, || {})
    }

    fn rebase_pending_session_dependents(
        conn: &Connection,
        updates: &[SessionRevisionUpdate],
    ) -> Result<()> {
        if updates.is_empty() {
            return Ok(());
        }

        let pending_requests = {
            let mut stmt = conn.prepare(
                "SELECT handle, json FROM grant_requests WHERE status = 'pending' ORDER BY handle",
            )?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        for (handle, json) in pending_requests {
            let mut request: GrantRequest = serde_json::from_str(&json)
                .with_context(|| format!("decode pending access request {handle}"))?;
            let Some(update) = updates.iter().find(|update| {
                request.session_token == update.token
                    && request.issued_session_revision.as_deref()
                        == Some(update.old_revision.as_str())
            }) else {
                continue;
            };
            request.issued_session_revision = Some(update.new_revision.clone());
            if request.has_access_projection() {
                request.request_key = request
                    .canonical_access_key()
                    .context("rebase pending access request key")?;
            }
            validate_persisted_access_request(&request)?;
            conn.execute(
                "UPDATE grant_requests SET json = ?1 WHERE handle = ?2",
                params![
                    serde_json::to_string(&request).context("encode rebased access request")?,
                    handle
                ],
            )?;
        }

        let pending_approvals = {
            let mut stmt = conn.prepare(
                "SELECT handle, json FROM gating_approval WHERE status = 'pending' ORDER BY handle",
            )?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        for (handle, json) in pending_approvals {
            let mut approval: Approval = serde_json::from_str(&json)
                .with_context(|| format!("decode pending approval {handle}"))?;
            let Some(update) = updates.iter().find(|update| {
                approval.snapshot.session_revision.as_deref() == Some(update.old_revision.as_str())
                    && approval.snapshot.session_fingerprint.as_deref()
                        == Some(update.token_fingerprint.as_str())
            }) else {
                continue;
            };
            approval.snapshot.session_revision = Some(update.new_revision.clone());
            validate_persisted_approval(&approval)?;
            conn.execute(
                "UPDATE gating_approval SET json = ?1 WHERE handle = ?2",
                params![
                    serde_json::to_string(&approval).context("encode rebased approval")?,
                    handle
                ],
            )?;
        }
        Ok(())
    }

    fn load_registry_sync_with_hook<F>(
        path: &Path,
        history_retention_secs: u64,
        after_grants: F,
    ) -> Result<(SessionRegistry, u64)>
    where
        F: FnOnce(),
    {
        let mut conn = Self::open_connection(path)?;
        Self::init_schema(&conn)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Deferred)?;

        let mut grants = HashMap::new();
        let mut active_exact_updates = Vec::new();
        let mut additive_access_updates = Vec::new();
        let mut retired_active = Vec::new();
        {
            let mut stmt = tx.prepare(
                "SELECT token, allow_json, deny_json, allow_exact_json, deny_exact_json, activated_verbs_json, override_markers_json, scope_json, expires_at, prompt_append, generated_notes_json, granted_at, static_only, auto_amend, owner_json
                 FROM session_grants",
            )?;
            let rows = stmt.query_map([], |row| {
                let token: String = row.get(0)?;
                let allow_json: String = row.get(1)?;
                let deny_json: String = row.get(2)?;
                let allow_exact_json: String = row.get(3)?;
                let deny_exact_json: String = row.get(4)?;
                Ok((
                    token,
                    SessionGrant {
                        allow: decode_vec(&allow_json)?,
                        deny: decode_vec(&deny_json)?,
                        allow_exact: decode_exact_vec(&allow_exact_json)?,
                        deny_exact: decode_exact_vec(&deny_exact_json)?,
                        activated_verbs: decode_vec(&row.get::<_, String>(5)?)?,
                        override_markers: decode_vec(&row.get::<_, String>(6)?)?,
                        scope: decode_scope(&row.get::<_, String>(7)?)?,
                        expires_at: decode_optional_u64(row.get(8)?)?,
                        prompt_append: row.get(9)?,
                        generated_notes: decode_vec(&row.get::<_, String>(10)?)?,
                        granted_at: decode_u64(row.get(11)?)?,
                        static_only: decode_bool(row.get(12)?)?,
                        auto_amend: decode_bool(row.get(13)?)?,
                        owner: decode_owner(&row.get::<_, String>(14)?)?,
                    },
                ))
            })?;
            for row in rows {
                let (token, mut grant) = row?;
                let additive_access_old_revision = if grant.scope.access_managed
                    && grant.static_only
                    && grant.scope.evaluation_mode != EvaluationMode::PolicyOnly
                {
                    // Access-managed sessions issued before additive access
                    // semantics persisted this legacy flag. Preserve an
                    // explicit policy-only mode, but otherwise normalize and
                    // durably rewrite the session during startup.
                    let old_revision = session_grant_revision_key(&grant)
                        .context("compute legacy access session revision")?;
                    grant.static_only = false;
                    Some(old_revision)
                } else {
                    None
                };
                let allow_changed = purge_sensitive_exact_rules(&mut grant.allow_exact);
                let deny_changed = purge_sensitive_exact_rules(&mut grant.deny_exact);
                let exact_metadata = serialized_contains_registered_exact_literals(&grant)?;
                if deny_changed || exact_metadata {
                    let mut retired =
                        revoked_history_from_grant(token, grant, guard::env::now_unix());
                    if exact_metadata {
                        scrub_registered_exact_literals(&mut retired)?;
                    }
                    retired_active.push(retired);
                    continue;
                }
                if allow_changed {
                    active_exact_updates.push((
                        token.clone(),
                        encode_exact_vec(&grant.allow_exact)?,
                        encode_exact_vec(&grant.deny_exact)?,
                    ));
                }
                if let Some(old_revision) = additive_access_old_revision {
                    // The replacement revision covers every startup mutation,
                    // including sensitive exact-rule normalization above. A
                    // dependent must never be rebased to an intermediate
                    // grant shape that is not the one retained in memory and
                    // persisted by this transaction.
                    let new_revision = session_grant_revision_key(&grant)
                        .context("compute final additive access session revision")?;
                    additive_access_updates.push(SessionRevisionUpdate {
                        token: token.clone(),
                        old_revision,
                        new_revision,
                        token_fingerprint: access_session_token_fingerprint(&token),
                    });
                }
                grants.insert(token, grant);
            }
        }
        after_grants();

        let mut history = Vec::new();
        let mut history_exact_updates = Vec::new();
        let mut history_replacements = Vec::new();
        {
            let mut stmt = tx.prepare(
                "SELECT id, token, allow_json, deny_json, allow_exact_json, deny_exact_json, activated_verbs_json, override_markers_json, scope_json, granted_at, expires_at, ended_at, status, prompt_append, generated_notes_json, static_only, auto_amend, owner_json
                 FROM session_history
                 ORDER BY ended_at ASC, id ASC",
            )?;
            let rows = stmt.query_map([], |row| {
                let allow_json: String = row.get(2)?;
                let deny_json: String = row.get(3)?;
                let allow_exact_json: String = row.get(4)?;
                let deny_exact_json: String = row.get(5)?;
                let status: String = row.get(12)?;
                Ok((
                    row.get::<_, i64>(0)?,
                    HistoricalGrant {
                        token: row.get(1)?,
                        allow: decode_vec(&allow_json)?,
                        deny: decode_vec(&deny_json)?,
                        allow_exact: decode_exact_vec(&allow_exact_json)?,
                        deny_exact: decode_exact_vec(&deny_exact_json)?,
                        activated_verbs: decode_vec(&row.get::<_, String>(6)?)?,
                        override_markers: decode_vec(&row.get::<_, String>(7)?)?,
                        scope: decode_scope(&row.get::<_, String>(8)?)?,
                        granted_at: decode_u64(row.get(9)?)?,
                        expires_at: decode_optional_u64(row.get(10)?)?,
                        ended_at: decode_u64(row.get(11)?)?,
                        status: decode_historical_status(&status)?,
                        prompt_append: row.get(13)?,
                        generated_notes: decode_vec(&row.get::<_, String>(14)?)?,
                        static_only: decode_bool(row.get(15)?)?,
                        auto_amend: decode_bool(row.get(16)?)?,
                        owner: decode_owner(&row.get::<_, String>(17)?)?,
                    },
                ))
            })?;
            for row in rows {
                let (id, mut grant) = row?;
                let changed = purge_sensitive_exact_rules(&mut grant.allow_exact)
                    | purge_sensitive_exact_rules(&mut grant.deny_exact);
                let exact_metadata = serialized_contains_registered_exact_literals(&grant)?;
                if exact_metadata {
                    scrub_registered_exact_literals(&mut grant)?;
                    history_replacements.push((id, grant.clone()));
                } else if changed {
                    history_exact_updates.push((
                        id,
                        encode_exact_vec(&grant.allow_exact)?,
                        encode_exact_vec(&grant.deny_exact)?,
                    ));
                }
                history.push(grant);
            }
        }
        history.extend(retired_active.iter().cloned());

        let mut interactions = Vec::new();
        {
            let mut stmt = tx.prepare(
                "SELECT token, at_unix, command, allowed, source, reason, risk, exec_status, exit_code, secret_refs_json, decision_trace_json
                 FROM session_interactions
                 ORDER BY at_unix ASC, id ASC",
            )?;
            let rows = stmt.query_map([], |row| {
                let source: String = row.get(4)?;
                let exec_status: String = row.get(7)?;
                Ok((
                    row.get::<_, String>(0)?,
                    SessionInteraction {
                        at_unix: decode_u64(row.get(1)?)?,
                        command: row.get(2)?,
                        allowed: row.get::<_, i64>(3)? != 0,
                        source: decode_decision_source(&source)?,
                        reason: row.get(5)?,
                        risk: row.get(6)?,
                        exec_status: decode_exec_status(&exec_status)?,
                        exit_code: row.get(8)?,
                        credential_references: decode_credential_references(
                            &row.get::<_, String>(9)?,
                        )?,
                        decision_trace: row
                            .get::<_, Option<String>>(10)?
                            .map(|json| serde_json::from_str(&json))
                            .transpose()
                            .map_err(|error| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    10,
                                    rusqlite::types::Type::Text,
                                    Box::new(error),
                                )
                            })?,
                    },
                ))
            })?;
            for row in rows {
                interactions.push(row?);
            }
        }

        let mut registry =
            SessionRegistry::from_parts(grants, history, interactions, history_retention_secs);
        registry.purge_expired();
        let generation = Self::read_registry_generation(&tx)?;
        for (token, allow, deny) in &active_exact_updates {
            tx.execute(
                "UPDATE session_grants SET allow_exact_json = ?1, deny_exact_json = ?2 WHERE token = ?3",
                params![allow, deny, token],
            )?;
        }
        for update in &additive_access_updates {
            tx.execute(
                "UPDATE session_grants SET static_only = 0 WHERE token = ?1",
                params![update.token],
            )?;
        }
        Self::rebase_pending_session_dependents(&tx, &additive_access_updates)?;
        for grant in &retired_active {
            tx.execute(
                "DELETE FROM session_grants WHERE token = ?1",
                params![grant.token],
            )?;
            insert_historical_grant(&tx, grant)?;
        }
        for (id, allow, deny) in &history_exact_updates {
            tx.execute(
                "UPDATE session_history SET allow_exact_json = ?1, deny_exact_json = ?2 WHERE id = ?3",
                params![allow, deny, id],
            )?;
        }
        for (id, grant) in &history_replacements {
            tx.execute("DELETE FROM session_history WHERE id = ?1", params![id])?;
            insert_historical_grant(&tx, grant)?;
        }
        let generation = if active_exact_updates.is_empty()
            && additive_access_updates.is_empty()
            && history_exact_updates.is_empty()
            && history_replacements.is_empty()
            && retired_active.is_empty()
        {
            generation
        } else {
            let next = generation
                .checked_add(1)
                .context("session registry generation exhausted")?;
            let changed = tx.execute(
                "UPDATE state_metadata SET value = ?1 WHERE key = ?2 AND value = ?3",
                params![
                    encode_u64(next)?,
                    REGISTRY_GENERATION_KEY,
                    encode_u64(generation)?
                ],
            )?;
            if changed != 1 {
                anyhow::bail!("session registry generation compare-and-swap was lost during startup normalization");
            }
            next
        };
        tx.commit()?;
        Ok((registry, generation))
    }

    fn persist_registry_sync(
        path: &Path,
        history_retention_secs: u64,
        registry: &SessionRegistry,
        expected_generation: u64,
    ) -> Result<u64> {
        let mut conn = Self::open_connection(path)?;
        Self::init_schema(&conn)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let generation = Self::rewrite_registry_cas_transaction(
            &tx,
            history_retention_secs,
            registry,
            expected_generation,
        )?;
        tx.commit()?;
        Ok(generation)
    }

    fn read_registry_generation(conn: &Connection) -> Result<u64> {
        let encoded = conn.query_row(
            "SELECT value FROM state_metadata WHERE key = ?1",
            params![REGISTRY_GENERATION_KEY],
            |row| row.get::<_, i64>(0),
        )?;
        Ok(decode_u64(encoded)?)
    }

    fn rewrite_registry_cas_transaction(
        tx: &Transaction<'_>,
        history_retention_secs: u64,
        registry: &SessionRegistry,
        expected_generation: u64,
    ) -> Result<u64> {
        let durable_generation = Self::read_registry_generation(tx)?;
        if durable_generation != expected_generation {
            return Err(RegistryGenerationConflict {
                expected: expected_generation,
                found: durable_generation,
            }
            .into());
        }
        Self::rewrite_registry_transaction(tx, history_retention_secs, registry)?;
        let next_generation = expected_generation
            .checked_add(1)
            .context("session registry generation exhausted")?;
        let changed = tx.execute(
            "UPDATE state_metadata SET value = ?1 WHERE key = ?2 AND value = ?3",
            params![
                encode_u64(next_generation)?,
                REGISTRY_GENERATION_KEY,
                encode_u64(expected_generation)?
            ],
        )?;
        if changed != 1 {
            anyhow::bail!("session registry generation compare-and-swap was lost");
        }
        Ok(next_generation)
    }

    fn rewrite_registry_transaction(
        tx: &Transaction<'_>,
        history_retention_secs: u64,
        registry: &SessionRegistry,
    ) -> Result<()> {
        let mut snapshot = registry
            .clone()
            .with_history_retention(history_retention_secs);
        snapshot.purge_expired();
        for (_, grant) in snapshot.grants_snapshot() {
            validate_exact_rules_safe(&grant.allow_exact)?;
            validate_exact_rules_safe(&grant.deny_exact)?;
            if serialized_contains_registered_exact_literals(&grant)? {
                anyhow::bail!("session authority contains a daemon-managed credential literal");
            }
        }
        for grant in snapshot.history_snapshot() {
            validate_exact_rules_safe(&grant.allow_exact)?;
            validate_exact_rules_safe(&grant.deny_exact)?;
            if serialized_contains_registered_exact_literals(&grant)? {
                anyhow::bail!("session history contains a daemon-managed credential literal");
            }
        }

        tx.execute("DELETE FROM session_grants", [])?;
        tx.execute("DELETE FROM session_history", [])?;
        tx.execute("DELETE FROM session_interactions", [])?;

        for (token, grant) in snapshot.grants_snapshot() {
            tx.execute(
                "INSERT INTO session_grants
                 (token, allow_json, deny_json, allow_exact_json, deny_exact_json, activated_verbs_json, override_markers_json, scope_json, expires_at, prompt_append, generated_notes_json, granted_at, static_only, auto_amend, owner_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    token,
                    encode_vec(&grant.allow)?,
                    encode_vec(&grant.deny)?,
                    encode_exact_vec(&grant.allow_exact)?,
                    encode_exact_vec(&grant.deny_exact)?,
                    encode_vec(&grant.activated_verbs)?,
                    encode_vec(&grant.override_markers)?,
                    encode_scope(&grant.scope)?,
                    encode_optional_u64(grant.expires_at)?,
                    grant.prompt_append,
                    encode_vec(&grant.generated_notes)?,
                    encode_u64(grant.granted_at)?,
                    encode_bool(grant.static_only),
                    encode_bool(grant.auto_amend),
                    encode_owner(&grant.owner)?
                ],
            )?;
        }

        for grant in snapshot.history_snapshot() {
            tx.execute(
                "INSERT INTO session_history
                 (token, allow_json, deny_json, allow_exact_json, deny_exact_json, activated_verbs_json, override_markers_json, scope_json, granted_at, expires_at, ended_at, status, prompt_append, generated_notes_json, static_only, auto_amend, owner_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
                params![
                    grant.token,
                    encode_vec(&grant.allow)?,
                    encode_vec(&grant.deny)?,
                    encode_exact_vec(&grant.allow_exact)?,
                    encode_exact_vec(&grant.deny_exact)?,
                    encode_vec(&grant.activated_verbs)?,
                    encode_vec(&grant.override_markers)?,
                    encode_scope(&grant.scope)?,
                    encode_u64(grant.granted_at)?,
                    encode_optional_u64(grant.expires_at)?,
                    encode_u64(grant.ended_at)?,
                    encode_historical_status(grant.status),
                    grant.prompt_append,
                    encode_vec(&grant.generated_notes)?,
                    encode_bool(grant.static_only),
                    encode_bool(grant.auto_amend),
                    encode_owner(&grant.owner)?
                ],
            )?;
        }

        for (token, mut interaction) in snapshot.interactions_snapshot() {
            interaction.command = redact_output_text(&interaction.command);
            interaction.reason = guard::gating::sanitize_gate_text(&interaction.reason);
            if let Some(trace) = interaction.decision_trace.as_mut() {
                trace.sanitize_explanatory_text();
            }
            if serialized_contains_registered_exact_literals(&interaction)? {
                anyhow::bail!("session interaction contains a daemon-managed credential literal");
            }
            tx.execute(
                "INSERT INTO session_interactions
                 (token, at_unix, command, allowed, source, reason, risk, exec_status, exit_code, secret_refs_json, decision_trace_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    token,
                    encode_u64(interaction.at_unix)?,
                    interaction.command,
                    if interaction.allowed { 1 } else { 0 },
                    encode_decision_source(interaction.source),
                    interaction.reason,
                    interaction.risk,
                    encode_exec_status(interaction.exec_status),
                    interaction.exit_code,
                    encode_credential_references(&interaction.credential_references)?,
                    interaction
                        .decision_trace
                        .as_ref()
                        .map(serde_json::to_string)
                        .transpose()?
                ],
            )?;
        }

        Ok(())
    }

    fn load_session_grant(conn: &Connection, token: &str) -> Result<Option<SessionGrant>> {
        let grant = conn.query_row(
            "SELECT allow_json, deny_json, allow_exact_json, deny_exact_json, activated_verbs_json, override_markers_json, scope_json, expires_at, prompt_append, generated_notes_json, granted_at, static_only, auto_amend, owner_json
             FROM session_grants WHERE token = ?1",
            params![token],
            |row| {
                Ok(SessionGrant {
                    allow: decode_vec(&row.get::<_, String>(0)?)?,
                    deny: decode_vec(&row.get::<_, String>(1)?)?,
                    allow_exact: decode_exact_vec(&row.get::<_, String>(2)?)?,
                    deny_exact: decode_exact_vec(&row.get::<_, String>(3)?)?,
                    activated_verbs: decode_vec(&row.get::<_, String>(4)?)?,
                    override_markers: decode_vec(&row.get::<_, String>(5)?)?,
                    scope: decode_scope(&row.get::<_, String>(6)?)?,
                    expires_at: decode_optional_u64(row.get(7)?)?,
                    prompt_append: row.get(8)?,
                    generated_notes: decode_vec(&row.get::<_, String>(9)?)?,
                    granted_at: decode_u64(row.get(10)?)?,
                    static_only: decode_bool(row.get(11)?)?,
                    auto_amend: decode_bool(row.get(12)?)?,
                    owner: decode_owner(&row.get::<_, String>(13)?)?,
                })
            },
        )
        .optional()
        .context("load session grant for request approval")?;
        if let Some(grant) = &grant {
            validate_exact_rules_safe(&grant.allow_exact)?;
            validate_exact_rules_safe(&grant.deny_exact)?;
        }
        Ok(grant)
    }

    /// Reclaim storage only when deleted pages are both substantial and a
    /// meaningful share of the database. Compaction runs outside command audit
    /// writes, so lock contention delays maintenance rather than losing an
    /// interaction.
    pub async fn compact_if_needed(&self) -> Result<bool> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Self::open_connection(&path)?;
            Self::init_schema(&conn)?;
            let page_count = conn
                .query_row("PRAGMA page_count", [], |row| row.get::<_, i64>(0))?
                .try_into()
                .context("negative sqlite page_count")?;
            let free_pages = conn
                .query_row("PRAGMA freelist_count", [], |row| row.get::<_, i64>(0))?
                .try_into()
                .context("negative sqlite freelist_count")?;
            if !should_vacuum(page_count, free_pages) {
                return Ok(false);
            }
            conn.execute_batch("VACUUM")?;
            Ok(true)
        })
        .await
        .context("session store compaction task failed")?
    }

    fn open_connection(path: &Path) -> Result<Connection> {
        prepare_state_path(path)?;
        let conn = open_state_connection(path)
            .with_context(|| format!("failed to open {}", path.display()))?;
        conn.busy_timeout(Duration::from_secs(2))?;
        enforce_private_state_files(path)?;
        Ok(conn)
    }

    fn init_schema(conn: &Connection) -> Result<()> {
        let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        ensure_supported_schema_version(version, SCHEMA_VERSION)?;
        if version == SCHEMA_VERSION {
            Self::validate_current_schema_tables(conn)?;
            let tx = conn.unchecked_transaction()?;
            sanitize_persisted_credentials(&tx)?;
            Self::validate_authority_row_indexes(&tx, true)?;
            tx.commit()?;
            return Ok(());
        }

        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS session_grants (
                token TEXT PRIMARY KEY,
                allow_json TEXT NOT NULL,
                deny_json TEXT NOT NULL,
                allow_exact_json TEXT NOT NULL DEFAULT '[]',
                deny_exact_json TEXT NOT NULL DEFAULT '[]',
                activated_verbs_json TEXT NOT NULL DEFAULT '[]',
                override_markers_json TEXT NOT NULL DEFAULT '[]',
                scope_json TEXT NOT NULL DEFAULT '{}',
                expires_at INTEGER,
                prompt_append TEXT,
                generated_notes_json TEXT NOT NULL DEFAULT '[]',
                granted_at INTEGER NOT NULL,
                static_only INTEGER NOT NULL DEFAULT 0,
                auto_amend INTEGER NOT NULL DEFAULT 0,
                owner_json TEXT NOT NULL DEFAULT '\"unowned\"'
            );
            CREATE TABLE IF NOT EXISTS session_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT NOT NULL,
                allow_json TEXT NOT NULL,
                deny_json TEXT NOT NULL,
                allow_exact_json TEXT NOT NULL DEFAULT '[]',
                deny_exact_json TEXT NOT NULL DEFAULT '[]',
                activated_verbs_json TEXT NOT NULL DEFAULT '[]',
                override_markers_json TEXT NOT NULL DEFAULT '[]',
                scope_json TEXT NOT NULL DEFAULT '{}',
                granted_at INTEGER NOT NULL,
                expires_at INTEGER,
                ended_at INTEGER NOT NULL,
                status TEXT NOT NULL,
                prompt_append TEXT,
                generated_notes_json TEXT NOT NULL DEFAULT '[]',
                static_only INTEGER NOT NULL DEFAULT 0,
                auto_amend INTEGER NOT NULL DEFAULT 0,
                owner_json TEXT NOT NULL DEFAULT '\"unowned\"'
            );
            CREATE INDEX IF NOT EXISTS idx_session_history_token ON session_history(token);
            CREATE INDEX IF NOT EXISTS idx_session_history_ended_at ON session_history(ended_at);
            CREATE TABLE IF NOT EXISTS session_interactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT NOT NULL,
                at_unix INTEGER NOT NULL,
                command TEXT NOT NULL,
                allowed INTEGER NOT NULL,
                source TEXT NOT NULL,
                reason TEXT NOT NULL,
                risk INTEGER,
                exec_status TEXT NOT NULL,
                exit_code INTEGER,
                secret_refs_json TEXT NOT NULL DEFAULT '[]',
                decision_trace_json TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_session_interactions_token ON session_interactions(token);
            CREATE INDEX IF NOT EXISTS idx_session_interactions_at ON session_interactions(at_unix);
            CREATE TABLE IF NOT EXISTS gating_provisional (
                handle TEXT PRIMARY KEY,
                json TEXT NOT NULL,
                status TEXT NOT NULL,
                created_unix INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS gating_approval (
                handle TEXT PRIMARY KEY,
                json TEXT NOT NULL,
                status TEXT NOT NULL,
                created_unix INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS read_grants (
                target_path TEXT PRIMARY KEY,
                json TEXT NOT NULL,
                status TEXT NOT NULL,
                expires_unix INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS saved_grants (
                name TEXT PRIMARY KEY,
                json TEXT NOT NULL,
                updated_unix INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS saved_grant_tombstones (
                name TEXT PRIMARY KEY,
                deleted_unix INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS grant_requests (
                handle TEXT PRIMARY KEY,
                json TEXT NOT NULL,
                status TEXT NOT NULL,
                created_unix INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS state_metadata (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL
            );
            INSERT OR IGNORE INTO state_metadata (key, value)
            VALUES ('registry_generation', 0);",
        )?;
        ensure_column(
            &tx,
            "session_grants",
            "generated_notes_json",
            "TEXT NOT NULL DEFAULT '[]'",
        )?;
        ensure_column(
            &tx,
            "session_history",
            "activated_verbs_json",
            "TEXT NOT NULL DEFAULT '[]'",
        )?;
        ensure_column(
            &tx,
            "session_history",
            "override_markers_json",
            "TEXT NOT NULL DEFAULT '[]'",
        )?;
        ensure_column(
            &tx,
            "session_history",
            "scope_json",
            "TEXT NOT NULL DEFAULT '{}'",
        )?;
        ensure_column(
            &tx,
            "session_grants",
            "static_only",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_column(
            &tx,
            "session_grants",
            "auto_amend",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_column(
            &tx,
            "session_grants",
            "allow_exact_json",
            "TEXT NOT NULL DEFAULT '[]'",
        )?;
        ensure_column(
            &tx,
            "session_grants",
            "deny_exact_json",
            "TEXT NOT NULL DEFAULT '[]'",
        )?;
        ensure_column(
            &tx,
            "session_grants",
            "activated_verbs_json",
            "TEXT NOT NULL DEFAULT '[]'",
        )?;
        ensure_column(
            &tx,
            "session_grants",
            "override_markers_json",
            "TEXT NOT NULL DEFAULT '[]'",
        )?;
        ensure_column(
            &tx,
            "session_grants",
            "scope_json",
            "TEXT NOT NULL DEFAULT '{}'",
        )?;
        ensure_column(
            &tx,
            "session_history",
            "generated_notes_json",
            "TEXT NOT NULL DEFAULT '[]'",
        )?;
        ensure_column(
            &tx,
            "session_history",
            "static_only",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_column(
            &tx,
            "session_history",
            "auto_amend",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_column(
            &tx,
            "session_history",
            "allow_exact_json",
            "TEXT NOT NULL DEFAULT '[]'",
        )?;
        ensure_column(
            &tx,
            "session_history",
            "deny_exact_json",
            "TEXT NOT NULL DEFAULT '[]'",
        )?;
        ensure_column(&tx, "session_interactions", "exit_code", "INTEGER")?;
        ensure_column(
            &tx,
            "session_interactions",
            "secret_refs_json",
            "TEXT NOT NULL DEFAULT '[]'",
        )?;
        ensure_column(&tx, "session_interactions", "decision_trace_json", "TEXT")?;
        // Schema v7: bind sessions to their creating principal. Rows migrated
        // from v6 default to the `Unowned` sentinel and are refused for
        // execution until reissued.
        ensure_column(
            &tx,
            "session_grants",
            "owner_json",
            &format!("TEXT NOT NULL DEFAULT {OWNER_JSON_DEFAULT}"),
        )?;
        ensure_column(
            &tx,
            "session_history",
            "owner_json",
            &format!("TEXT NOT NULL DEFAULT {OWNER_JSON_DEFAULT}"),
        )?;
        // Validate every authority-bearing index before migration sanitization
        // can rewrite redundant columns from JSON and conceal corruption.
        Self::validate_authority_row_indexes(&tx, false)?;
        if version == 13 {
            migrate_v13_dispatch_rows(&tx)?;
        }
        // Apply the idempotent pre-current-schema cleanup before recording the
        // current version. The pass sanitizes prose, retires active sessions
        // whose sensitive exact denies cannot be preserved, removes sensitive
        // exact authority from history, and repairs durable gate snapshots.
        sanitize_persisted_credentials(&tx)?;
        Self::validate_authority_row_indexes(&tx, true)?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tx.commit()?;
        Ok(())
    }

    fn validate_authority_row_indexes(
        conn: &Connection,
        validate_access_authority: bool,
    ) -> Result<()> {
        {
            let mut stmt =
                conn.prepare("SELECT name, updated_unix, json FROM saved_grants ORDER BY name")?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            for row in rows {
                let (name, updated_unix, json) = row?;
                let grant = serde_json::from_str::<SavedGrant>(&json)
                    .with_context(|| format!("decode durable saved grant {name}"))?;
                if grant.name != name || grant.updated_unix != decode_u64(updated_unix)? {
                    anyhow::bail!(
                        "durable saved-grant index disagrees with serialized row for {name}"
                    );
                }
                grant
                    .validate_canonical()
                    .with_context(|| format!("validate durable saved grant {name}"))?;
            }
        }
        {
            let mut stmt = conn.prepare(
                "SELECT handle, status, created_unix, json FROM grant_requests ORDER BY handle",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?;
            for row in rows {
                let (handle, status, created_unix, json) = row?;
                let request = serde_json::from_str::<GrantRequest>(&json).with_context(|| {
                    format!("decode durable grant request {handle} with status {status}")
                })?;
                if validate_access_authority {
                    if let Err(error) = validate_persisted_access_request(&request) {
                        tracing::warn!(
                            %handle,
                            %error,
                            "skipping durable grant request that fails current validation; \
                             the row is never honored and can be cleared with guard access"
                        );
                        continue;
                    }
                }
                if request.handle != handle
                    || request.status.as_str() != status
                    || request.created_unix != decode_u64(created_unix)?
                {
                    anyhow::bail!(
                        "durable grant-request index disagrees with serialized row for {handle}"
                    );
                }
            }
        }
        {
            let mut stmt = conn.prepare(
                "SELECT handle, status, created_unix, json FROM gating_provisional ORDER BY handle",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?;
            for row in rows {
                let (handle, status, created_unix, json) = row?;
                let provisional =
                    serde_json::from_str::<Provisional>(&json).with_context(|| {
                        format!("decode durable provisional {handle} with status {status}")
                    })?;
                if provisional.handle != handle
                    || provisional.status.as_str() != status
                    || provisional.created_unix != decode_u64(created_unix)?
                {
                    anyhow::bail!(
                        "durable provisional index disagrees with serialized row for {handle}"
                    );
                }
            }
        }
        {
            let mut stmt = conn.prepare(
                "SELECT handle, status, created_unix, json FROM gating_approval ORDER BY handle",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?;
            for row in rows {
                let (handle, status, created_unix, json) = row?;
                let approval = serde_json::from_str::<Approval>(&json).with_context(|| {
                    format!("decode durable approval {handle} with status {status}")
                })?;
                if approval.handle != handle
                    || approval.status.as_str() != status
                    || approval.created_unix != decode_u64(created_unix)?
                {
                    anyhow::bail!(
                        "durable approval index disagrees with serialized row for {handle}"
                    );
                }
            }
        }
        {
            let mut stmt = conn.prepare(
                "SELECT target_path, status, expires_unix, json FROM read_grants ORDER BY target_path",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?;
            for row in rows {
                let (target_path, status, expires_unix, json) = row?;
                let grant = serde_json::from_str::<ReadGrant>(&json).with_context(|| {
                    format!("decode durable read grant {target_path} with status {status}")
                })?;
                if grant.target_path != target_path
                    || grant.status.as_str() != status
                    || grant.expires_unix != decode_u64(expires_unix)?
                {
                    anyhow::bail!(
                        "durable read-grant index disagrees with serialized row for {target_path}"
                    );
                }
            }
        }
        Ok(())
    }

    fn validate_current_schema_tables(conn: &Connection) -> Result<()> {
        const REQUIRED_TABLES: &[&str] = &[
            "session_grants",
            "session_history",
            "session_interactions",
            "gating_provisional",
            "gating_approval",
            "read_grants",
            "saved_grants",
            "saved_grant_tombstones",
            "grant_requests",
            "state_metadata",
        ];
        for table in REQUIRED_TABLES {
            let exists: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                params![table],
                |row| row.get(0),
            )?;
            if !exists {
                anyhow::bail!("current state database is missing required table {table}");
            }
        }
        let generation_exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM state_metadata WHERE key = ?1)",
            params![REGISTRY_GENERATION_KEY],
            |row| row.get(0),
        )?;
        if !generation_exists {
            anyhow::bail!("current state database is missing registry generation metadata");
        }
        Ok(())
    }

    #[cfg(test)]
    pub async fn save_saved_grant(&self, grant: SavedGrant) -> Result<()> {
        grant.validate_canonical()?;
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = Self::open_connection(&path)?;
            Self::init_schema(&conn)?;
            let json = serde_json::to_string(&grant).context("encode saved grant")?;
            let tx = conn.transaction()?;
            tx.execute(
                "INSERT OR REPLACE INTO saved_grants (name, json, updated_unix) VALUES (?1, ?2, ?3)",
                params![&grant.name, json, encode_u64(grant.updated_unix)?],
            )?;
            tx.execute(
                "DELETE FROM saved_grant_tombstones WHERE name = ?1",
                params![grant.name],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await
        .context("save saved grant task failed")?
    }

    #[cfg(test)]
    pub async fn delete_saved_grant(&self, name: String) -> Result<()> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = Self::open_connection(&path)?;
            Self::init_schema(&conn)?;
            let tx = conn.transaction()?;
            tx.execute("DELETE FROM saved_grants WHERE name = ?1", params![&name])?;
            tx.execute(
                "INSERT OR REPLACE INTO saved_grant_tombstones (name, deleted_unix) VALUES (?1, ?2)",
                params![name, encode_u64(guard::env::now_unix())?],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await
        .context("delete saved grant task failed")?
    }

    pub async fn load_saved_grants(&self) -> Result<Vec<SavedGrant>> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Self::open_connection(&path)?;
            Self::init_schema(&conn)?;
            let mut stmt = conn.prepare("SELECT name, updated_unix, json FROM saved_grants")?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            let mut grants = Vec::new();
            for row in rows {
                let (name, updated_unix, json) = row?;
                let grant = serde_json::from_str::<SavedGrant>(&json)
                    .with_context(|| format!("decode durable saved grant {name}"))?;
                if grant.name != name || grant.updated_unix != decode_u64(updated_unix)? {
                    anyhow::bail!(
                        "durable saved-grant index disagrees with serialized row for {name}"
                    );
                }
                grant
                    .validate_canonical()
                    .with_context(|| format!("validate durable saved grant {name}"))?;
                grants.push(grant);
            }
            Ok(grants)
        })
        .await
        .context("load saved grants task failed")?
    }

    pub async fn load_saved_grant_tombstones(&self) -> Result<Vec<String>> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Self::open_connection(&path)?;
            Self::init_schema(&conn)?;
            let mut stmt = conn.prepare("SELECT name FROM saved_grant_tombstones ORDER BY name")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .context("load saved grant tombstones")
        })
        .await
        .context("load saved grant tombstones task failed")?
    }

    pub async fn save_grant_request(&self, request: GrantRequest) -> Result<()> {
        #[cfg(test)]
        if self
            .fail_next_write
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            anyhow::bail!("simulated session-store write failure");
        }
        let path = self.path.clone();
        let request = sanitize_grant_request(request);
        validate_persisted_access_request(&request)?;
        tokio::task::spawn_blocking(move || {
            let conn = Self::open_connection(&path)?;
            Self::init_schema(&conn)?;
            let json = serde_json::to_string(&request).context("encode grant request")?;
            conn.execute(
                "INSERT OR REPLACE INTO grant_requests (handle, json, status, created_unix) VALUES (?1, ?2, ?3, ?4)",
                params![request.handle, json, request.status.as_str(), encode_u64(request.created_unix)?],
            )?;
            Ok(())
        })
        .await
        .context("save grant request task failed")?
    }

    /// Replace a pending grant request with one terminal outcome. The durable
    /// row must still exactly match the caller's pending snapshot.
    pub async fn compare_and_swap_grant_request(
        &self,
        pending: GrantRequest,
        terminal: GrantRequest,
    ) -> Result<()> {
        #[cfg(test)]
        if self
            .fail_next_write
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            anyhow::bail!("simulated session-store write failure");
        }
        let path = self.path.clone();
        let pending = sanitize_grant_request(pending);
        let terminal = sanitize_grant_request(terminal);
        validate_persisted_access_request(&pending)?;
        validate_persisted_access_request(&terminal)?;
        tokio::task::spawn_blocking(move || {
            Self::compare_and_swap_grant_request_sync(&path, &pending, &terminal)
        })
        .await
        .context("grant request transition task failed")?
    }

    fn compare_and_swap_grant_request_sync(
        path: &Path,
        pending: &GrantRequest,
        terminal: &GrantRequest,
    ) -> Result<()> {
        if pending.status != crate::grant_profile::GrantRequestStatus::Pending
            || !matches!(
                terminal.status,
                crate::grant_profile::GrantRequestStatus::Denied
                    | crate::grant_profile::GrantRequestStatus::Withdrawn
            )
            || terminal.handle != pending.handle
            || terminal.session_token != pending.session_token
            || terminal.saved_grant != pending.saved_grant
            || terminal.issued_saved_revision != pending.issued_saved_revision
            || terminal.issued_session_revision != pending.issued_session_revision
            || terminal.delta != pending.delta
            || terminal.requested_uses != pending.requested_uses
            || terminal.authority_verbs != pending.authority_verbs
            || terminal.proposed_verbs != pending.proposed_verbs
        {
            anyhow::bail!("invalid grant request terminal transition");
        }

        let mut conn = Self::open_connection(path)?;
        Self::init_schema(&conn)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let durable_json = tx
            .query_row(
                "SELECT json FROM grant_requests WHERE handle = ?1",
                params![pending.handle],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .context("durable pending grant request is missing")?;
        let durable: GrantRequest =
            serde_json::from_str(&durable_json).context("decode durable pending grant request")?;
        validate_persisted_access_request(&durable)?;
        if durable != *pending {
            anyhow::bail!("durable grant request already has a terminal outcome");
        }
        let terminal_json =
            serde_json::to_string(terminal).context("encode terminal grant request")?;
        tx.execute(
            "UPDATE grant_requests SET json = ?1, status = ?2, created_unix = ?3 WHERE handle = ?4",
            params![
                terminal_json,
                terminal.status.as_str(),
                encode_u64(terminal.created_unix)?,
                terminal.handle
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub async fn load_grant_request(&self, handle: String) -> Result<Option<GrantRequest>> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Self::open_connection(&path)?;
            Self::init_schema(&conn)?;
            let json = conn
                .query_row(
                    "SELECT json FROM grant_requests WHERE handle = ?1",
                    params![handle],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            json.map(|json| {
                let request =
                    serde_json::from_str::<GrantRequest>(&json).context("decode grant request")?;
                validate_persisted_access_request(&request)?;
                Ok(request)
            })
            .transpose()
        })
        .await
        .context("load grant request task failed")?
    }

    /// Commit an approved request and the session authority it changes in one
    /// SQLite transaction. The durable pending request and session revision
    /// are rechecked inside that transaction before either row set changes.
    pub async fn commit_grant_request_approval(
        &self,
        pending: GrantRequest,
        approved: GrantRequest,
        registry: SessionRegistry,
        rebased_pending: Vec<(GrantRequest, GrantRequest)>,
    ) -> Result<()> {
        #[cfg(test)]
        if self
            .fail_next_approval
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            anyhow::bail!("simulated grant approval transaction failure");
        }
        #[cfg(test)]
        if self
            .fail_next_write
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            anyhow::bail!("simulated session-store write failure");
        }
        let pending = sanitize_grant_request(pending);
        let approved = sanitize_grant_request(approved);
        let rebased_pending = rebased_pending
            .into_iter()
            .map(|(previous, next)| {
                (
                    sanitize_grant_request(previous),
                    sanitize_grant_request(next),
                )
            })
            .collect::<Vec<_>>();
        validate_persisted_access_request(&pending)?;
        validate_persisted_access_request(&approved)?;
        for (previous, next) in &rebased_pending {
            validate_persisted_access_request(previous)?;
            validate_persisted_access_request(next)?;
        }
        let path = self.path.clone();
        let retention = self.history_retention_secs;
        let revision = registry.revision();
        self.run_registry_write(
            "grant request approval transaction",
            revision,
            StaleRegistryWrite::Reject("approved session snapshot is stale"),
            move |expected_generation| {
                Self::commit_grant_request_approval_sync(
                    &path,
                    retention,
                    &pending,
                    &approved,
                    &registry,
                    &rebased_pending,
                    RegistryCommitOptions {
                        fail_before_commit: false,
                        expected_generation,
                    },
                )
            },
        )
        .await
    }

    fn commit_grant_request_approval_sync(
        path: &Path,
        history_retention_secs: u64,
        pending: &GrantRequest,
        approved: &GrantRequest,
        registry: &SessionRegistry,
        rebased_pending: &[(GrantRequest, GrantRequest)],
        options: RegistryCommitOptions,
    ) -> Result<u64> {
        if pending.status != crate::grant_profile::GrantRequestStatus::Pending
            || approved.status != crate::grant_profile::GrantRequestStatus::Approved
            || approved.handle != pending.handle
            || (!pending.session_token.is_empty()
                && approved.session_token != pending.session_token)
            || approved.requester != pending.requester
            || approved.issued_saved_revision != pending.issued_saved_revision
            || approved.issued_session_revision != pending.issued_session_revision
            || approved.delta != pending.delta
            || approved.authority_verbs != pending.authority_verbs
            || approved.proposed_verbs != pending.proposed_verbs
        {
            anyhow::bail!("invalid grant request approval transition");
        }

        let mut conn = Self::open_connection(path)?;
        Self::init_schema(&conn)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let durable_json = tx
            .query_row(
                "SELECT json FROM grant_requests WHERE handle = ?1",
                params![pending.handle],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .context("durable pending grant request is missing")?;
        let durable: GrantRequest =
            serde_json::from_str(&durable_json).context("decode durable pending grant request")?;
        validate_persisted_access_request(&durable)?;
        if durable != *pending {
            anyhow::bail!("durable grant request changed after approval began");
        }
        if !pending.session_token.is_empty() {
            let durable_grant = Self::load_session_grant(&tx, &pending.session_token)?
                .context("durable session for grant request is missing")?;
            if durable_grant.is_expired(guard::env::now_unix())
                || session_grant_revision_key(&durable_grant) != pending.issued_session_revision
            {
                anyhow::bail!("durable session changed after grant request issuance");
            }
        }

        let generation = Self::rewrite_registry_cas_transaction(
            &tx,
            history_retention_secs,
            registry,
            options.expected_generation,
        )?;
        let approved_json =
            serde_json::to_string(approved).context("encode approved grant request")?;
        tx.execute(
            "UPDATE grant_requests SET json = ?1, status = ?2, created_unix = ?3 WHERE handle = ?4",
            params![
                approved_json,
                approved.status.as_str(),
                encode_u64(approved.created_unix)?,
                approved.handle
            ],
        )?;
        for (original, rebased) in rebased_pending {
            let mut expected = original.clone();
            expected.session_token = rebased.session_token.clone();
            expected.issued_session_revision = rebased.issued_session_revision.clone();
            expected.request_key = expected
                .canonical_access_key()
                .context("recompute sibling access request key after session rebase")?;
            if original.status != crate::grant_profile::GrantRequestStatus::Pending
                || rebased.status != crate::grant_profile::GrantRequestStatus::Pending
                || expected != *rebased
                || original.handle == pending.handle
                || original.session_token != pending.session_token
                || original.issued_session_revision != pending.issued_session_revision
                || rebased.session_token != approved.session_token
            {
                anyhow::bail!("invalid sibling grant request rebase");
            }
            let durable_json = tx
                .query_row(
                    "SELECT json FROM grant_requests WHERE handle = ?1",
                    params![original.handle],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .context("durable sibling grant request is missing")?;
            let durable: GrantRequest = serde_json::from_str(&durable_json)
                .context("decode durable sibling grant request")?;
            if durable != *original {
                anyhow::bail!("durable sibling grant request changed before rebase");
            }
            let rebased_json =
                serde_json::to_string(rebased).context("encode rebased sibling grant request")?;
            tx.execute(
                "UPDATE grant_requests SET json = ?1, status = ?2, created_unix = ?3 WHERE handle = ?4",
                params![
                    rebased_json,
                    rebased.status.as_str(),
                    encode_u64(rebased.created_unix)?,
                    rebased.handle
                ],
            )?;
        }
        if options.fail_before_commit {
            anyhow::bail!("simulated crash before approval transaction commit");
        }
        tx.commit()?;
        Ok(generation)
    }

    /// Revoke one access session and withdraw every pending request targeting
    /// it in the same transaction.
    pub async fn commit_access_revoke(
        &self,
        token: String,
        expected_revision: Option<String>,
        registry: SessionRegistry,
        withdrawals: Vec<(GrantRequest, GrantRequest)>,
    ) -> Result<()> {
        #[cfg(test)]
        if self
            .fail_next_write
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            anyhow::bail!("simulated session-store write failure");
        }
        let withdrawals = withdrawals
            .into_iter()
            .map(|(previous, next)| {
                (
                    sanitize_grant_request(previous),
                    sanitize_grant_request(next),
                )
            })
            .collect::<Vec<_>>();
        for (previous, next) in &withdrawals {
            validate_persisted_access_request(previous)?;
            validate_persisted_access_request(next)?;
        }
        let path = self.path.clone();
        let retention = self.history_retention_secs;
        let revision = registry.revision();
        self.run_registry_write(
            "access revoke transaction",
            revision,
            StaleRegistryWrite::Reject("access revoke session snapshot is stale"),
            move |expected_generation| {
            let mut conn = Self::open_connection(&path)?;
            Self::init_schema(&conn)?;
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let durable_grant = Self::load_session_grant(&tx, &token)?
                .context("durable access session is missing")?;
            if session_grant_revision_key(&durable_grant) != expected_revision {
                anyhow::bail!("durable access session changed before revoke");
            }
            for (pending, withdrawn) in &withdrawals {
                if pending.status != crate::grant_profile::GrantRequestStatus::Pending
                    || withdrawn.status != crate::grant_profile::GrantRequestStatus::Withdrawn
                    || pending.handle != withdrawn.handle
                    || pending.session_token != token
                {
                    anyhow::bail!("invalid access request withdrawal");
                }
                let mut expected = withdrawn.clone();
                expected.status = pending.status;
                expected.decided_unix = pending.decided_unix;
                expected.decided_reason = pending.decided_reason.clone();
                expected.next_action = pending.next_action.clone();
                if expected != *pending {
                    anyhow::bail!("access request withdrawal changed immutable fields");
                }
                let durable_json = tx
                    .query_row(
                        "SELECT json FROM grant_requests WHERE handle = ?1",
                        params![pending.handle],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()?
                    .context("durable pending access request is missing")?;
                let durable: GrantRequest = serde_json::from_str(&durable_json)
                    .context("decode durable pending access request")?;
                validate_persisted_access_request(&durable)?;
                if durable != *pending {
                    anyhow::bail!("durable access request changed before revoke");
                }
            }
            let generation = Self::rewrite_registry_cas_transaction(
                &tx,
                retention,
                &registry,
                expected_generation,
            )?;
            for (_, withdrawn) in &withdrawals {
                let json = serde_json::to_string(withdrawn)
                    .context("encode withdrawn access request")?;
                tx.execute(
                    "UPDATE grant_requests SET json = ?1, status = ?2, created_unix = ?3 WHERE handle = ?4",
                    params![
                        json,
                        withdrawn.status.as_str(),
                        encode_u64(withdrawn.created_unix)?,
                        withdrawn.handle
                    ],
                )?;
            }
            tx.commit()?;
                Ok(generation)
            },
        )
        .await
    }

    pub async fn load_grant_requests(&self) -> Result<Vec<GrantRequest>> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Self::open_connection(&path)?;
            Self::init_schema(&conn)?;
            let mut stmt =
                conn.prepare("SELECT handle, status, created_unix, json FROM grant_requests")?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?;
            let mut requests = Vec::new();
            for row in rows {
                let (handle, status, created_unix, json) = row?;
                let request = serde_json::from_str::<GrantRequest>(&json).with_context(|| {
                    format!("decode durable grant request {handle} with status {status}")
                })?;
                if let Err(error) = validate_persisted_access_request(&request) {
                    tracing::warn!(
                        %handle,
                        %error,
                        "skipping durable grant request that fails current validation; \
                         the row is never honored and can be cleared with guard access"
                    );
                    continue;
                }
                let created_unix = decode_u64(created_unix)?;
                if request.handle != handle
                    || request.status.as_str() != status
                    || request.created_unix != created_unix
                {
                    anyhow::bail!(
                        "durable grant-request index disagrees with serialized row for {handle}"
                    );
                }
                requests.push(request);
            }
            Ok(requests)
        })
        .await
        .context("load grant requests task failed")?
    }

    pub async fn delete_grant_requests(&self, handles: Vec<String>) -> Result<()> {
        if handles.is_empty() {
            return Ok(());
        }
        #[cfg(test)]
        if self
            .fail_next_write
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            anyhow::bail!("simulated session-store write failure");
        }
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = Self::open_connection(&path)?;
            Self::init_schema(&conn)?;
            let tx = conn.transaction()?;
            for handle in handles {
                tx.execute(
                    "DELETE FROM grant_requests WHERE handle = ?1",
                    params![handle],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
        .context("delete grant requests task failed")?
    }

    #[cfg(test)]
    pub(crate) fn fail_next_write_for_test(&self) {
        self.fail_next_write
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn fail_next_approval_for_test(&self) {
        self.fail_next_approval
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn fail_next_provisional_delete_for_test(&self) {
        self.fail_next_provisional_delete
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    // --- Consequence-gating runtime state (provisional executions and operator
    // approvals). These are high-churn, handle-keyed rows, so unlike the session
    // registry they persist incrementally (per-row upsert/delete) rather than by
    // full-table snapshot, and a provisional is committed before its forward
    // command runs so a crash still leaves a recoverable revert.

    /// Insert a new provisional or advance an existing row through a legal,
    /// monotonic transition. Creation uses a plain insert. Existing rows are
    /// compared and replaced under one immediate transaction.
    pub async fn save_provisional(&self, mut p: Provisional) -> Result<()> {
        #[cfg(test)]
        if self
            .fail_next_write
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            anyhow::bail!("simulated session-store write failure");
        }
        p.sanitize_explanatory_text();
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || Self::insert_or_advance_provisional_sync(&path, &p))
            .await
            .context("save_provisional task failed")?
    }

    pub async fn compare_and_swap_provisional(
        &self,
        mut expected: Provisional,
        mut next: Provisional,
    ) -> Result<()> {
        #[cfg(test)]
        if self
            .fail_next_write
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            anyhow::bail!("simulated session-store write failure");
        }
        expected.sanitize_explanatory_text();
        next.sanitize_explanatory_text();
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            Self::compare_and_swap_provisional_sync(&path, &expected, &next)
        })
        .await
        .context("provisional transition task failed")?
    }

    fn insert_or_advance_provisional_sync(path: &Path, next: &Provisional) -> Result<()> {
        validate_persisted_provisional(next)?;
        let mut conn = Self::open_connection(path)?;
        Self::init_schema(&conn)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let durable_json = tx
            .query_row(
                "SELECT json FROM gating_provisional WHERE handle = ?1",
                params![next.handle],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        match durable_json {
            None => {
                if !matches!(
                    next.status,
                    ProvisionalStatus::Armed | ProvisionalStatus::Staged
                ) {
                    anyhow::bail!("new provisional must begin armed or staged");
                }
                if next.status == ProvisionalStatus::Staged && next.api_revert.is_none() {
                    anyhow::bail!("only API provisionals may begin staged");
                }
                let next_json = serde_json::to_string(next).context("encode new provisional")?;
                let changed = tx.execute(
                    "INSERT INTO gating_provisional (handle, json, status, created_unix)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        next.handle,
                        next_json,
                        next.status.as_str(),
                        encode_u64(next.created_unix)?
                    ],
                )?;
                if changed != 1 {
                    anyhow::bail!("provisional creation insert was lost");
                }
            }
            Some(durable_json) => {
                let mut expected: Provisional =
                    serde_json::from_str(&durable_json).context("decode durable provisional")?;
                expected.sanitize_explanatory_text();
                Self::compare_and_swap_provisional_transaction(
                    &tx,
                    &expected,
                    next,
                    &durable_json,
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn compare_and_swap_provisional_sync(
        path: &Path,
        expected: &Provisional,
        next: &Provisional,
    ) -> Result<()> {
        let mut conn = Self::open_connection(path)?;
        Self::init_schema(&conn)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let expected_json =
            serde_json::to_string(expected).context("encode expected provisional")?;
        Self::compare_and_swap_provisional_transaction(&tx, expected, next, &expected_json)?;
        tx.commit()?;
        Ok(())
    }

    fn compare_and_swap_provisional_transaction(
        tx: &Transaction<'_>,
        expected: &Provisional,
        next: &Provisional,
        expected_json: &str,
    ) -> Result<()> {
        validate_persisted_provisional(next)?;
        if !valid_provisional_transition(expected, next)? {
            anyhow::bail!(
                "invalid provisional transition from {} to {}",
                expected.status.as_str(),
                next.status.as_str()
            );
        }
        let next_json = serde_json::to_string(next).context("encode next provisional")?;
        if next_json == expected_json {
            return Ok(());
        }
        let changed = tx.execute(
            "UPDATE gating_provisional
             SET json = ?1, status = ?2, created_unix = ?3
             WHERE handle = ?4 AND status = ?5 AND json = ?6",
            params![
                next_json,
                next.status.as_str(),
                encode_u64(next.created_unix)?,
                next.handle,
                expected.status.as_str(),
                expected_json
            ],
        )?;
        if changed != 1 {
            anyhow::bail!("durable provisional changed before transition");
        }
        Ok(())
    }

    pub async fn delete_provisional(&self, handle: String) -> Result<()> {
        #[cfg(test)]
        if self
            .fail_next_provisional_delete
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            anyhow::bail!("simulated provisional-delete failure");
        }
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Self::open_connection(&path)?;
            Self::init_schema(&conn)?;
            conn.execute(
                "DELETE FROM gating_provisional WHERE handle = ?1",
                params![handle],
            )?;
            Ok(())
        })
        .await
        .context("delete_provisional task failed")?
    }

    /// Delete only the exact inert document observed by the caller. A durable
    /// dispatch transition makes the predicate false, so cleanup cannot erase
    /// evidence after upstream handoff becomes possible.
    pub async fn compare_and_delete_provisional(&self, mut expected: Provisional) -> Result<()> {
        #[cfg(test)]
        if self
            .fail_next_provisional_delete
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            anyhow::bail!("simulated provisional-delete failure");
        }
        expected.sanitize_explanatory_text();
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            if expected.status != ProvisionalStatus::Staged || expected.forward_done {
                anyhow::bail!("only an exact inert staged provisional may be cancelled");
            }
            let conn = Self::open_connection(&path)?;
            Self::init_schema(&conn)?;
            let expected_json =
                serde_json::to_string(&expected).context("encode staged provisional")?;
            let changed = conn.execute(
                "DELETE FROM gating_provisional
                 WHERE handle = ?1 AND status = ?2 AND json = ?3",
                params![expected.handle, expected.status.as_str(), expected_json],
            )?;
            if changed != 1 {
                anyhow::bail!("durable provisional changed before staged cancellation");
            }
            Ok(())
        })
        .await
        .context("cancel staged provisional task failed")?
    }

    pub async fn load_provisionals(&self) -> Result<Vec<Provisional>> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = Self::open_connection(&path)?;
            Self::init_schema(&conn)?;
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let rows = {
                let mut stmt = tx
                    .prepare("SELECT handle, status, created_unix, json FROM gating_provisional")?;
                let rows = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            };
            let mut out = Vec::new();
            for row in rows {
                let (handle, status, created_unix, json) = row;
                let mut provisional =
                    serde_json::from_str::<Provisional>(&json).with_context(|| {
                        format!("decode durable provisional {handle} with status {status}")
                    })?;
                if provisional.handle != handle
                    || provisional.status.as_str() != status
                    || provisional.created_unix != decode_u64(created_unix)?
                {
                    anyhow::bail!(
                        "durable provisional index disagrees with serialized row for {handle}"
                    );
                }
                let identity_repaired = repair_legacy_create_revert(&mut provisional);
                validate_persisted_provisional(&provisional)
                    .with_context(|| format!("validate durable provisional {handle}"))?;
                if provisional.sanitize_explanatory_text() || identity_repaired {
                    let sanitized = serde_json::to_string(&provisional)?;
                    tx.execute(
                        "UPDATE gating_provisional
                         SET json = ?1, status = ?2
                         WHERE handle = ?3 AND json = ?4",
                        params![sanitized, provisional.status.as_str(), handle, json],
                    )?;
                }
                out.push(provisional);
            }
            tx.commit()?;
            Ok(out)
        })
        .await
        .context("load_provisionals task failed")?
    }

    /// Insert a new pending approval or advance an existing row through a
    /// legal, monotonic transition. A stale caller can never replace a decided
    /// row with Pending because the durable row is compared inside the write
    /// transaction.
    pub async fn save_approval(&self, mut a: Approval) -> Result<()> {
        #[cfg(test)]
        if self
            .fail_next_write
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            anyhow::bail!("simulated session-store write failure");
        }
        a.sanitize_explanatory_text();
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || Self::insert_or_advance_approval_sync(&path, &a))
            .await
            .context("save_approval task failed")?
    }

    pub async fn compare_and_swap_approval(
        &self,
        mut expected: Approval,
        mut next: Approval,
    ) -> Result<()> {
        #[cfg(test)]
        if self
            .fail_next_write
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            anyhow::bail!("simulated session-store write failure");
        }
        expected.sanitize_explanatory_text();
        next.sanitize_explanatory_text();
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            Self::compare_and_swap_approval_sync(&path, &expected, &next)
        })
        .await
        .context("approval transition task failed")?
    }

    fn insert_or_advance_approval_sync(path: &Path, next: &Approval) -> Result<()> {
        validate_persisted_approval(next)?;
        let mut conn = Self::open_connection(path)?;
        Self::init_schema(&conn)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let durable_json = tx
            .query_row(
                "SELECT json FROM gating_approval WHERE handle = ?1",
                params![next.handle],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        match durable_json {
            None => {
                if next.status != ApprovalStatus::Pending {
                    anyhow::bail!("new approval must begin pending");
                }
                let next_json = serde_json::to_string(next).context("encode new approval")?;
                let changed = tx.execute(
                    "INSERT INTO gating_approval (handle, json, status, created_unix)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        next.handle,
                        next_json,
                        next.status.as_str(),
                        encode_u64(next.created_unix)?
                    ],
                )?;
                if changed != 1 {
                    anyhow::bail!("approval creation insert was lost");
                }
            }
            Some(durable_json) => {
                let mut expected: Approval =
                    serde_json::from_str(&durable_json).context("decode durable approval")?;
                expected.sanitize_explanatory_text();
                Self::compare_and_swap_approval_transaction(&tx, &expected, next, &durable_json)?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn compare_and_swap_approval_sync(
        path: &Path,
        expected: &Approval,
        next: &Approval,
    ) -> Result<()> {
        let mut conn = Self::open_connection(path)?;
        Self::init_schema(&conn)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let expected_json = serde_json::to_string(expected).context("encode expected approval")?;
        Self::compare_and_swap_approval_transaction(&tx, expected, next, &expected_json)?;
        tx.commit()?;
        Ok(())
    }

    fn compare_and_swap_approval_transaction(
        tx: &Transaction<'_>,
        expected: &Approval,
        next: &Approval,
        expected_json: &str,
    ) -> Result<()> {
        validate_persisted_approval(next)?;
        if !valid_approval_transition(expected, next)? {
            anyhow::bail!(
                "invalid approval transition from {} to {}",
                expected.status.as_str(),
                next.status.as_str()
            );
        }
        let next_json = serde_json::to_string(next).context("encode next approval")?;
        if next_json == expected_json {
            return Ok(());
        }
        let changed = tx.execute(
            "UPDATE gating_approval
             SET json = ?1, status = ?2, created_unix = ?3
             WHERE handle = ?4 AND status = ?5 AND json = ?6",
            params![
                next_json,
                next.status.as_str(),
                encode_u64(next.created_unix)?,
                next.handle,
                expected.status.as_str(),
                expected_json
            ],
        )?;
        if changed != 1 {
            anyhow::bail!("durable approval changed before transition");
        }
        Ok(())
    }

    /// Claim a pending approval with an exact durable compare-and-swap. This
    /// is the execution ownership boundary for daemons sharing one database.
    pub async fn compare_and_swap_approval_claim(
        &self,
        pending: Approval,
        approving: Approval,
    ) -> Result<()> {
        self.compare_and_swap_approval(pending, approving).await
    }

    pub async fn delete_approval(&self, handle: String) -> Result<()> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Self::open_connection(&path)?;
            Self::init_schema(&conn)?;
            conn.execute(
                "DELETE FROM gating_approval WHERE handle = ?1",
                params![handle],
            )?;
            Ok(())
        })
        .await
        .context("delete_approval task failed")?
    }

    pub async fn load_approvals(&self) -> Result<Vec<Approval>> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = Self::open_connection(&path)?;
            Self::init_schema(&conn)?;
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let rows = {
                let mut stmt =
                    tx.prepare("SELECT handle, status, created_unix, json FROM gating_approval")?;
                let rows = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            };
            let mut out = Vec::new();
            for row in rows {
                let (handle, status, created_unix, json) = row;
                let mut approval = serde_json::from_str::<Approval>(&json).with_context(|| {
                    format!("decode durable approval {handle} with status {status}")
                })?;
                if approval.handle != handle
                    || approval.status.as_str() != status
                    || approval.created_unix != decode_u64(created_unix)?
                {
                    anyhow::bail!(
                        "durable approval index disagrees with serialized row for {handle}"
                    );
                }
                validate_persisted_approval(&approval)
                    .with_context(|| format!("validate durable approval {handle}"))?;
                if approval.sanitize_explanatory_text() {
                    let sanitized = serde_json::to_string(&approval)?;
                    tx.execute(
                        "UPDATE gating_approval SET json = ?1 WHERE handle = ?2 AND json = ?3",
                        params![sanitized, handle, json],
                    )?;
                }
                out.push(approval);
            }
            tx.commit()?;
            Ok(out)
        })
        .await
        .context("load_approvals task failed")?
    }

    // --- Filesystem read grants. Persisted incrementally per-row (keyed by
    // target path) and committed before the ACLs are applied, so a crash after
    // granting still leaves a row the reconciler can revoke on restart.

    pub async fn save_read_grant(&self, g: ReadGrant) -> Result<()> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Self::open_connection(&path)?;
            Self::init_schema(&conn)?;
            let json = serde_json::to_string(&g).context("encode read grant")?;
            conn.execute(
                "INSERT OR REPLACE INTO read_grants (target_path, json, status, expires_unix)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    g.target_path,
                    json,
                    g.status.as_str(),
                    encode_u64(g.expires_unix)?
                ],
            )?;
            Ok(())
        })
        .await
        .context("save_read_grant task failed")?
    }

    pub async fn delete_read_grant(&self, target_path: String) -> Result<()> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Self::open_connection(&path)?;
            Self::init_schema(&conn)?;
            conn.execute(
                "DELETE FROM read_grants WHERE target_path = ?1",
                params![target_path],
            )?;
            Ok(())
        })
        .await
        .context("delete_read_grant task failed")?
    }

    /// Read grants are a POSIX-ACL primitive; only the Unix startup path loads them.
    #[cfg(unix)]
    pub async fn load_read_grants(&self) -> Result<Vec<ReadGrant>> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Self::open_connection(&path)?;
            Self::init_schema(&conn)?;
            let mut stmt =
                conn.prepare("SELECT target_path, status, expires_unix, json FROM read_grants")?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (target_path, status, expires_unix, json) = row?;
                let grant = serde_json::from_str::<ReadGrant>(&json).with_context(|| {
                    format!("decode durable read grant {target_path} with status {status}")
                })?;
                if grant.target_path != target_path
                    || grant.status.as_str() != status
                    || grant.expires_unix != decode_u64(expires_unix)?
                {
                    anyhow::bail!(
                        "durable read-grant index disagrees with serialized row for {target_path}"
                    );
                }
                out.push(grant);
            }
            Ok(out)
        })
        .await
        .context("load_read_grants task failed")?
    }
}

fn ensure_supported_schema_version(version: i64, maximum: i64) -> Result<()> {
    if version > maximum {
        anyhow::bail!(
            "state database schema version {} is newer than supported version {}",
            version,
            maximum
        );
    }
    Ok(())
}

fn serialized_eq<T: serde::Serialize>(left: &T, right: &T) -> Result<bool> {
    Ok(serde_json::to_vec(left)? == serde_json::to_vec(right)?)
}

fn serialized_prefix<T: serde::Serialize>(prefix: &[T], values: &[T]) -> Result<bool> {
    if prefix.len() > values.len() {
        return Ok(false);
    }
    prefix
        .iter()
        .zip(values)
        .try_fold(true, |equal, (left, right)| {
            Ok(equal && serialized_eq(left, right)?)
        })
}

fn option_only_adds_or_preserves<T: serde::Serialize>(
    previous: &Option<T>,
    next: &Option<T>,
) -> Result<bool> {
    match (previous, next) {
        (None, _) => Ok(true),
        (Some(left), Some(right)) => serialized_eq(left, right),
        (Some(_), None) => Ok(false),
    }
}

fn valid_approval_transition(previous: &Approval, next: &Approval) -> Result<bool> {
    if previous.handle != next.handle
        || !serialized_eq(&previous.snapshot, &next.snapshot)?
        || previous.reason != next.reason
        || previous.risk != next.risk
        || !serialized_eq(&previous.reversibility, &next.reversibility)?
        || previous.created_unix != next.created_unix
        || previous.ttl_secs != next.ttl_secs
        || !serialized_prefix(&previous.notes, &next.notes)?
        || !option_only_adds_or_preserves(&previous.decision_trace, &next.decision_trace)?
    {
        return Ok(false);
    }

    let legal_status = matches!(
        (previous.status, next.status),
        (ApprovalStatus::Pending, ApprovalStatus::Pending)
            | (ApprovalStatus::Pending, ApprovalStatus::Approving)
            | (ApprovalStatus::Pending, ApprovalStatus::Denied)
            | (ApprovalStatus::Pending, ApprovalStatus::Expired)
            | (ApprovalStatus::Pending, ApprovalStatus::ExecFailed)
            | (ApprovalStatus::Approving, ApprovalStatus::Approved)
            | (ApprovalStatus::Approving, ApprovalStatus::ExecFailed)
            | (ApprovalStatus::Approved, ApprovalStatus::Approved)
            | (ApprovalStatus::Denied, ApprovalStatus::Denied)
            | (ApprovalStatus::Expired, ApprovalStatus::Expired)
            | (ApprovalStatus::ExecFailed, ApprovalStatus::ExecFailed)
    );
    if !legal_status {
        return Ok(false);
    }
    if previous.status == next.status && previous.status != ApprovalStatus::Pending {
        return serialized_eq(previous, next);
    }
    if matches!(
        next.status,
        ApprovalStatus::Denied | ApprovalStatus::Expired
    ) && next.decided_unix.is_none()
    {
        return Ok(false);
    }
    if matches!(
        next.status,
        ApprovalStatus::Approved | ApprovalStatus::ExecFailed
    ) && next.decided_unix.is_none()
    {
        return Ok(false);
    }
    Ok(true)
}

fn provisional_identity(provisional: &Provisional) -> Provisional {
    let mut identity = provisional.clone();
    identity.decision_trace = None;
    // The confirmation deadline, the window behind it, and the automatic
    // rollback stamp are all assigned after the forward command completes.
    // They are lifecycle state, not immutable identity.
    identity.deadline_unix = 0;
    identity.window_secs = 0;
    identity.auto_reverted_unix = None;
    identity.forward_done = false;
    identity.forward_exit = None;
    identity.forward_persistence_failed = false;
    identity.status = ProvisionalStatus::Armed;
    if let Some(api) = identity.api_revert.as_mut() {
        api.resource_uid = None;
    }
    identity.revert_exit = None;
    identity.revert_detail = None;
    identity
}

fn valid_provisional_transition(previous: &Provisional, next: &Provisional) -> Result<bool> {
    if terminal_body_cleanup_transition(previous, next)? {
        return Ok(true);
    }
    let previous_uid = previous
        .api_revert
        .as_ref()
        .and_then(|api| api.resource_uid.as_deref());
    let next_uid = next
        .api_revert
        .as_ref()
        .and_then(|api| api.resource_uid.as_deref());
    if !serialized_eq(&provisional_identity(previous), &provisional_identity(next))?
        || (previous.forward_done && !next.forward_done)
        || (previous_uid.is_some() && previous_uid != next_uid)
        || !option_only_adds_or_preserves(&previous.decision_trace, &next.decision_trace)?
    {
        return Ok(false);
    }
    if previous.forward_done
        && (previous.deadline_unix != next.deadline_unix
            || previous.window_secs != next.window_secs)
    {
        return Ok(false);
    }
    if !previous.forward_done && next.forward_done {
        let successful_completion =
            next.status == ProvisionalStatus::Armed && next.deadline_unix > next.created_unix;
        let failed_completion =
            next.status == ProvisionalStatus::NeedsOperatorDecision && next.deadline_unix == 0;
        if !successful_completion && !failed_completion {
            return Ok(false);
        }
    } else if !next.forward_done && (next.deadline_unix != 0 || next.window_secs != 0) {
        return Ok(false);
    }
    let legal_status = matches!(
        (previous.status, next.status),
        (ProvisionalStatus::Staged, ProvisionalStatus::Staged)
            | (ProvisionalStatus::Staged, ProvisionalStatus::Dispatching)
            | (ProvisionalStatus::Dispatching, ProvisionalStatus::Armed)
            | (
                ProvisionalStatus::Dispatching,
                ProvisionalStatus::NeedsOperatorDecision
            )
            | (ProvisionalStatus::Dispatching, ProvisionalStatus::Reverted)
            | (ProvisionalStatus::Armed, ProvisionalStatus::Armed)
            | (ProvisionalStatus::Armed, ProvisionalStatus::Reverting)
            | (ProvisionalStatus::Armed, ProvisionalStatus::Confirmed)
            | (ProvisionalStatus::Armed, ProvisionalStatus::Reverted)
            | (
                ProvisionalStatus::Armed,
                ProvisionalStatus::NeedsOperatorDecision
            )
            | (
                ProvisionalStatus::NeedsOperatorDecision,
                ProvisionalStatus::NeedsOperatorDecision
            )
            | (
                ProvisionalStatus::NeedsOperatorDecision,
                ProvisionalStatus::Reverting
            )
            | (
                ProvisionalStatus::NeedsOperatorDecision,
                ProvisionalStatus::Confirmed
            )
            | (ProvisionalStatus::Reverting, ProvisionalStatus::Confirmed)
            | (ProvisionalStatus::Reverting, ProvisionalStatus::Reverted)
            | (
                ProvisionalStatus::Reverting,
                ProvisionalStatus::RevertFailed
            )
            | (
                ProvisionalStatus::Reverting,
                ProvisionalStatus::NeedsOperatorDecision
            )
            | (ProvisionalStatus::Confirmed, ProvisionalStatus::Confirmed)
            | (ProvisionalStatus::Reverted, ProvisionalStatus::Reverted)
            | (
                ProvisionalStatus::RevertFailed,
                ProvisionalStatus::RevertFailed
            )
    );
    if !legal_status {
        return Ok(false);
    }
    if previous.status == next.status
        && !matches!(
            previous.status,
            ProvisionalStatus::Staged
                | ProvisionalStatus::Dispatching
                | ProvisionalStatus::Armed
                | ProvisionalStatus::NeedsOperatorDecision
        )
    {
        return serialized_eq(previous, next);
    }
    Ok(true)
}

fn terminal_body_cleanup_transition(previous: &Provisional, next: &Provisional) -> Result<bool> {
    if previous.status != next.status || !previous.status.is_lifecycle_final() {
        return Ok(false);
    }
    let Some(detail) = previous
        .revert_detail
        .as_deref()
        .and_then(|detail| detail.strip_prefix(REVERT_BODY_CLEANUP_PREFIX))
    else {
        return Ok(false);
    };
    let previous_body = previous
        .api_revert
        .as_ref()
        .and_then(|revert| revert.body_file.as_ref());
    let next_body = next
        .api_revert
        .as_ref()
        .and_then(|revert| revert.body_file.as_ref());
    if previous_body.is_none() || next_body.is_some() {
        return Ok(false);
    }
    let mut expected = previous.clone();
    if let Some(revert) = expected.api_revert.as_mut() {
        revert.body_file = None;
    }
    expected.revert_detail = (detail != "rollback completed").then(|| detail.to_string());
    serialized_eq(&expected, next)
}

fn validate_persisted_access_request(request: &GrantRequest) -> Result<()> {
    if serialized_contains_registered_exact_literals(request)? {
        anyhow::bail!("grant request contains a daemon-managed credential literal");
    }
    if !request.has_access_projection() {
        return Ok(());
    }
    request
        .validate_principal_access_shape()
        .context("validate principal-bound access request")?;
    Ok(())
}

fn validate_persisted_approval(approval: &Approval) -> Result<()> {
    if !approval.snapshot.env.is_empty() {
        anyhow::bail!("approval snapshots cannot persist plain environment values");
    }
    if approval.snapshot.contains_sensitive_literals() {
        anyhow::bail!("{SENSITIVE_ARGV_REPLAY_GUIDANCE}");
    }
    if !approval.snapshot.verb_params.is_empty() {
        anyhow::bail!("approval snapshots cannot persist rendered verb parameter values");
    }
    if serialized_contains_registered_exact_literals(approval)? {
        anyhow::bail!("approval state contains a daemon-managed credential literal");
    }
    Ok(())
}

fn validate_persisted_provisional(provisional: &Provisional) -> Result<()> {
    if provisional.contains_sensitive_literals() {
        anyhow::bail!("{SENSITIVE_ARGV_REPLAY_GUIDANCE}");
    }
    if serialized_contains_registered_exact_literals(provisional)? {
        anyhow::bail!("provisional state contains a daemon-managed credential literal");
    }
    if let Some(api) = provisional.api_revert.as_ref() {
        if api.requires_uid_precondition
            && api.create_provenance.as_ref().is_none_or(|value| {
                value.is_empty() || value.len() > 256 || value.chars().any(char::is_control)
            })
            && matches!(
                provisional.status,
                ProvisionalStatus::Staged
                    | ProvisionalStatus::Dispatching
                    | ProvisionalStatus::Armed
                    | ProvisionalStatus::Reverting
            )
        {
            anyhow::bail!("created-resource rollback is missing canonical provenance");
        }
        if api.requires_uid_precondition
            && api.resource_uid.is_none()
            && matches!(
                provisional.status,
                ProvisionalStatus::Armed | ProvisionalStatus::Reverting
            )
        {
            anyhow::bail!("created-resource rollback is missing its UID precondition");
        }
        if api.resource_uid.as_ref().is_some_and(|uid| {
            uid.is_empty() || uid.len() > 256 || uid.chars().any(char::is_control)
        }) {
            anyhow::bail!("created-resource rollback UID is invalid");
        }
    }
    Ok(())
}

fn serialized_contains_registered_exact_literals(value: &impl serde::Serialize) -> Result<bool> {
    let value =
        serde_json::to_value(value).context("encode durable state for exact-secret check")?;
    Ok(guard::redact::json_contains_exact_secrets(&value, &[]))
}

fn scrub_registered_exact_literals<T>(value: &mut T) -> Result<bool>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let mut encoded =
        serde_json::to_value(&*value).context("encode durable state for exact-secret scrub")?;
    if !guard::redact::json_contains_exact_secrets(&encoded, &[]) {
        return Ok(false);
    }
    guard::redact::redact_json_exact_secrets(&mut encoded, &[]);
    *value =
        serde_json::from_value(encoded).context("decode durable state after exact-secret scrub")?;
    Ok(true)
}

fn repair_legacy_create_revert(provisional: &mut Provisional) -> bool {
    let Some(api) = provisional.api_revert.as_mut() else {
        return false;
    };
    if !api.protocol.eq_ignore_ascii_case("kubernetes")
        || !api.method.eq_ignore_ascii_case("DELETE")
        || (api.requires_uid_precondition && api.create_provenance.is_some())
    {
        return false;
    }

    api.requires_uid_precondition = true;
    if (api.resource_uid.is_none() || api.create_provenance.is_none())
        && matches!(
            provisional.status,
            ProvisionalStatus::Armed | ProvisionalStatus::Reverting
        )
    {
        provisional.status = ProvisionalStatus::NeedsOperatorDecision;
        provisional.deadline_unix = 0;
        provisional.window_secs = 0;
        provisional.revert_detail = Some(
            "created-resource rollback identity is unavailable; automatic rollback is disabled"
                .to_string(),
        );
    }
    true
}

pub(crate) fn sanitize_grant_request(mut request: GrantRequest) -> GrantRequest {
    let submitted_key_is_consistent = !request.request_key.is_empty()
        && request
            .canonical_access_key()
            .is_ok_and(|expected| expected == request.request_key);
    request.justification = redact_output_text(&request.justification);
    request.delta.prompt_append = request
        .delta
        .prompt_append
        .take()
        .map(|prompt| redact_output_text(&prompt));
    request.decided_reason = request
        .decided_reason
        .take()
        .map(|reason| redact_output_text(&reason));
    let mut proposal_changed = false;
    for proposal in &mut request.proposed_verbs {
        let Ok(verb) = serde_json::from_value::<guard::gating::verb::Verb>(proposal.clone()) else {
            continue;
        };
        if !verb.name.starts_with("access-generated-") {
            continue;
        }
        if let Ok(normalized) = guard::gating::verb::normalize_generated_access_verb(verb) {
            if let Ok(value) = serde_json::to_value(normalized) {
                proposal_changed |= value != *proposal;
                *proposal = value;
            }
        }
    }
    if proposal_changed && submitted_key_is_consistent {
        if let Ok(request_key) = request.canonical_access_key() {
            request.request_key = request_key;
        }
    }
    request
}

fn sanitize_grant_request_for_migration(request: GrantRequest) -> Result<GrantRequest> {
    // The shared sanitizer rewrites a key only when the original pending
    // envelope already proves that key and a known canonical normalization
    // changes the proposal. An inconsistent original remains inconsistent so
    // validation fails transactionally instead of concealing corruption.
    let mut request = sanitize_grant_request(request);
    if serialized_contains_registered_exact_literals(&request)? {
        request.status = crate::grant_profile::GrantRequestStatus::Denied;
        request.decided_unix = Some(guard::env::now_unix());
        request.decided_reason = Some(
            "request authority contained a managed credential literal and was retired".to_string(),
        );
        request.target = None;
        request.request_key.clear();
        request.requested_uses = None;
        request.authority_verbs.clear();
        request.proposed_verbs.clear();
        request.saved_grant = None;
        request.issued_saved_revision = None;
        request.issued_session_revision = None;
        request.delta = crate::grant_profile::GrantRequestDelta::default();
        scrub_registered_exact_literals(&mut request)?;
    }
    Ok(request)
}

/// Migration pass for persisted command-derived text and durable gate state.
/// Rows first move to a fail-closed lifecycle state where necessary, then
/// literal-sensitive structured commands are removed. New writes enforce the
/// same invariant before storage.
fn migrate_v13_dispatch_rows(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare(
        "SELECT rowid, handle, status, created_unix, json FROM gating_provisional ORDER BY rowid",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);

    for (rowid, handle, status, created_unix, json) in rows {
        let mut provisional = serde_json::from_str::<Provisional>(&json)
            .with_context(|| format!("decode v13 provisional {handle}"))?;
        if provisional.handle != handle
            || provisional.status.as_str() != status
            || provisional.created_unix != decode_u64(created_unix)?
        {
            anyhow::bail!("v13 provisional index disagrees with serialized row for {handle}");
        }
        if provisional.status != ProvisionalStatus::Dispatching {
            continue;
        }
        provisional.status = ProvisionalStatus::NeedsOperatorDecision;
        provisional.forward_done = true;
        provisional.forward_exit = None;
        provisional.deadline_unix = 0;
        provisional.window_secs = 0;
        provisional.revert_detail = Some(
            "the API handoff was interrupted; the mutation outcome is indeterminate".to_string(),
        );
        provisional.sanitize_explanatory_text();
        conn.execute(
            "UPDATE gating_provisional
             SET json = ?1, status = ?2
             WHERE rowid = ?3",
            params![
                serde_json::to_string(&provisional)?,
                provisional.status.as_str(),
                rowid
            ],
        )?;
    }
    Ok(())
}

fn sanitize_persisted_credentials(conn: &Connection) -> Result<()> {
    let (exact_authority_changed, exact_revision_updates) =
        repair_sensitive_session_exact_authority(conn)?;
    {
        let mut stmt = conn.prepare(
            "SELECT rowid, command, reason, secret_refs_json, decision_trace_json FROM session_interactions",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (rowid, command, reason, secret_refs_json, trace_json) in rows {
            let sanitized_command = redact_output_text(&command);
            let sanitized_reason = redact_output_text(&reason);
            let sanitized_secret_refs = sanitize_string_vec_json(&secret_refs_json);
            let sanitized_trace = trace_json.as_deref().and_then(sanitize_decision_trace_json);
            if sanitized_command != command
                || sanitized_reason != reason
                || sanitized_secret_refs != secret_refs_json
                || sanitized_trace != trace_json
            {
                conn.execute(
                    "UPDATE session_interactions
                     SET command = ?1, reason = ?2, secret_refs_json = ?3,
                         decision_trace_json = ?4
                     WHERE rowid = ?5",
                    params![
                        sanitized_command,
                        sanitized_reason,
                        sanitized_secret_refs,
                        sanitized_trace,
                        rowid
                    ],
                )?;
            }
        }
    }
    for table in ["session_grants", "session_history"] {
        let mut stmt = conn.prepare(&format!(
            "SELECT rowid, prompt_append, generated_notes_json, allow_json, deny_json FROM {table}"
        ))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (rowid, prompt, notes, allow, deny) in rows {
            let sanitized_prompt = prompt.as_deref().map(redact_output_text);
            let sanitized_notes = sanitize_string_vec_json(&notes);
            let sanitized_allow = sanitize_string_vec_json(&allow);
            let sanitized_deny = sanitize_string_vec_json(&deny);
            if sanitized_prompt != prompt
                || sanitized_notes != notes
                || sanitized_allow != allow
                || sanitized_deny != deny
            {
                conn.execute(
                    &format!(
                        "UPDATE {table}
                         SET prompt_append = ?1, generated_notes_json = ?2, allow_json = ?3,
                             deny_json = ?4
                         WHERE rowid = ?5"
                    ),
                    params![
                        sanitized_prompt,
                        sanitized_notes,
                        sanitized_allow,
                        sanitized_deny,
                        rowid
                    ],
                )?;
            }
        }
    }
    {
        let mut stmt = conn.prepare("SELECT rowid, json FROM saved_grants")?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (rowid, json) in rows {
            let Ok(grant) = serde_json::from_str::<SavedGrant>(&json) else {
                continue;
            };
            let canonical = grant.canonicalized_for_migration().ok();
            if let Some(canonical) = canonical {
                let canonical_json = serde_json::to_string(&canonical)?;
                if canonical_json != json {
                    conn.execute(
                        "UPDATE saved_grants SET json = ?1 WHERE rowid = ?2",
                        params![canonical_json, rowid],
                    )?;
                }
            } else {
                // Keep invalid authority-bearing rows visible to the
                // transactional index validator below. Deleting them here
                // would turn durable corruption into an apparently valid
                // startup and would incorrectly create a user deletion
                // tombstone.
            }
        }
    }
    {
        let mut stmt = conn.prepare("SELECT rowid, json FROM grant_requests")?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (rowid, json) in rows {
            let Ok(request) = serde_json::from_str::<GrantRequest>(&json) else {
                continue;
            };
            let sanitized = sanitize_grant_request_for_migration(request)?;
            let sanitized_json = serde_json::to_string(&sanitized)?;
            if sanitized_json != json {
                conn.execute(
                    "UPDATE grant_requests
                     SET json = ?1, status = ?2, created_unix = ?3
                     WHERE rowid = ?4",
                    params![
                        sanitized_json,
                        sanitized.status.as_str(),
                        encode_u64(sanitized.created_unix)?,
                        rowid
                    ],
                )?;
            }
        }
    }
    {
        let mut stmt = conn.prepare("SELECT rowid, json FROM gating_approval")?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (rowid, json) in rows {
            let Ok(mut approval) = serde_json::from_str::<Approval>(&json) else {
                continue;
            };
            let prose_changed = approval.sanitize_explanatory_text();
            let plain_environment = !approval.snapshot.env.is_empty();
            let sensitive_snapshot = approval.snapshot.contains_sensitive_literals();
            let persisted_verb_params = !approval.snapshot.verb_params.is_empty();
            let exact_contamination = serialized_contains_registered_exact_literals(&approval)?;
            if !prose_changed
                && !plain_environment
                && !sensitive_snapshot
                && !persisted_verb_params
                && !exact_contamination
            {
                continue;
            }
            approval.snapshot.env.clear();
            approval.snapshot.verb_params.clear();
            approval.snapshot.scrub_sensitive_literals();
            if (plain_environment || sensitive_snapshot || exact_contamination)
                && matches!(
                    approval.status,
                    ApprovalStatus::Pending | ApprovalStatus::Approving
                )
            {
                approval.status = ApprovalStatus::ExecFailed;
                approval.decided_unix = Some(guard::env::now_unix());
                approval.decided_reason = Some(if sensitive_snapshot || exact_contamination {
                    SENSITIVE_ARGV_REPLAY_GUIDANCE.to_string()
                } else {
                    "plain environment values were removed from persisted approval state"
                        .to_string()
                });
            }
            if exact_contamination {
                scrub_registered_exact_literals(&mut approval)?;
            }
            let sanitized_json = serde_json::to_string(&approval)?;
            conn.execute(
                "UPDATE gating_approval
                 SET json = ?1, status = ?2, created_unix = ?3
                 WHERE rowid = ?4",
                params![
                    sanitized_json,
                    approval.status.as_str(),
                    encode_u64(approval.created_unix)?,
                    rowid
                ],
            )?;
        }
    }
    {
        let mut stmt = conn.prepare("SELECT rowid, json FROM gating_provisional")?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (rowid, json) in rows {
            let Ok(mut provisional) = serde_json::from_str::<Provisional>(&json) else {
                continue;
            };
            let prose_changed = provisional.sanitize_explanatory_text();
            let identity_repaired = repair_legacy_create_revert(&mut provisional);
            let original_status = provisional.status;
            let command_sensitive = provisional.contains_sensitive_literals();
            let exact_contamination = serialized_contains_registered_exact_literals(&provisional)?;
            if !prose_changed && !identity_repaired && !command_sensitive && !exact_contamination {
                continue;
            }
            if command_sensitive {
                match provisional.status {
                    ProvisionalStatus::Staged
                    | ProvisionalStatus::Dispatching
                    | ProvisionalStatus::Armed
                    | ProvisionalStatus::Reverting => {
                        provisional.status = ProvisionalStatus::NeedsOperatorDecision;
                        provisional.revert_detail =
                            Some(SENSITIVE_ARGV_REPLAY_GUIDANCE.to_string());
                    }
                    ProvisionalStatus::NeedsOperatorDecision => {
                        if provisional.revert_detail.is_none() {
                            provisional.revert_detail =
                                Some(SENSITIVE_ARGV_REPLAY_GUIDANCE.to_string());
                        }
                    }
                    ProvisionalStatus::Confirmed
                    | ProvisionalStatus::Reverted
                    | ProvisionalStatus::RevertFailed => {}
                }
                provisional.scrub_sensitive_literals();
            }
            if exact_contamination {
                match original_status {
                    ProvisionalStatus::Staged => {
                        provisional.status = ProvisionalStatus::Reverted;
                        provisional.revert_detail = Some(
                            "pre-dispatch containment authority contained a managed credential literal and was retired"
                                .to_string(),
                        );
                    }
                    ProvisionalStatus::Dispatching
                    | ProvisionalStatus::Armed
                    | ProvisionalStatus::Reverting => {
                        provisional.status = ProvisionalStatus::RevertFailed;
                        provisional.forward_done = true;
                        provisional.forward_exit = None;
                        provisional.deadline_unix = 0;
                        provisional.window_secs = 0;
                        provisional.revert_detail = Some(
                            "containment authority contained a managed credential literal and automatic replay was disabled"
                                .to_string(),
                        );
                    }
                    ProvisionalStatus::NeedsOperatorDecision => {
                        provisional.status = ProvisionalStatus::RevertFailed;
                        provisional.revert_detail = Some(
                            "containment authority contained a managed credential literal and automatic replay was disabled"
                                .to_string(),
                        );
                    }
                    ProvisionalStatus::Confirmed
                    | ProvisionalStatus::Reverted
                    | ProvisionalStatus::RevertFailed => {}
                }
                scrub_registered_exact_literals(&mut provisional)?;
            }
            provisional.sanitize_explanatory_text();
            let sanitized_json = serde_json::to_string(&provisional)?;
            conn.execute(
                "UPDATE gating_provisional
                 SET json = ?1, status = ?2, created_unix = ?3
                 WHERE rowid = ?4",
                params![
                    sanitized_json,
                    provisional.status.as_str(),
                    encode_u64(provisional.created_unix)?,
                    rowid
                ],
            )?;
        }
    }
    SessionStore::rebase_pending_session_dependents(conn, &exact_revision_updates)?;
    if exact_authority_changed {
        conn.execute(
            "UPDATE state_metadata SET value = value + 1 WHERE key = ?1",
            params![REGISTRY_GENERATION_KEY],
        )?;
    }
    Ok(())
}

/// Sanitize the string members of one persisted `DecisionTrace`. Malformed
/// JSON is disposable explanatory detail, so migration clears it instead of
/// retaining raw text that would make the migrated row unloadable.
fn sanitize_decision_trace_json(json: &str) -> Option<String> {
    let Ok(mut trace) = serde_json::from_str::<guard::gating::DecisionTrace>(json) else {
        return None;
    };
    trace.sanitize_explanatory_text();
    serde_json::to_string(&trace).ok()
}

fn sanitize_string_vec_json(json: &str) -> String {
    let Ok(mut values) = serde_json::from_str::<Vec<String>>(json) else {
        return json.to_string();
    };
    for value in &mut values {
        *value = redact_output_text(value);
    }
    serde_json::to_string(&values).unwrap_or_else(|_| json.to_string())
}

fn revoked_history_from_grant(
    token: String,
    grant: SessionGrant,
    ended_at: u64,
) -> HistoricalGrant {
    HistoricalGrant {
        token,
        allow: grant.allow,
        deny: grant.deny,
        allow_exact: grant.allow_exact,
        deny_exact: grant.deny_exact,
        activated_verbs: grant.activated_verbs,
        override_markers: grant.override_markers,
        scope: grant.scope,
        granted_at: grant.granted_at,
        expires_at: grant.expires_at,
        ended_at,
        status: HistoricalStatus::Revoked,
        prompt_append: grant.prompt_append,
        generated_notes: grant.generated_notes,
        static_only: grant.static_only,
        auto_amend: grant.auto_amend,
        owner: grant.owner,
    }
}

fn insert_historical_grant(conn: &Connection, grant: &HistoricalGrant) -> Result<()> {
    conn.execute(
        "INSERT INTO session_history
         (token, allow_json, deny_json, allow_exact_json, deny_exact_json, activated_verbs_json, override_markers_json, scope_json, granted_at, expires_at, ended_at, status, prompt_append, generated_notes_json, static_only, auto_amend, owner_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
        params![
            grant.token,
            encode_vec(&grant.allow)?,
            encode_vec(&grant.deny)?,
            encode_exact_vec(&grant.allow_exact)?,
            encode_exact_vec(&grant.deny_exact)?,
            encode_vec(&grant.activated_verbs)?,
            encode_vec(&grant.override_markers)?,
            encode_scope(&grant.scope)?,
            encode_u64(grant.granted_at)?,
            encode_optional_u64(grant.expires_at)?,
            encode_u64(grant.ended_at)?,
            encode_historical_status(grant.status),
            grant.prompt_append,
            encode_vec(&grant.generated_notes)?,
            encode_bool(grant.static_only),
            encode_bool(grant.auto_amend),
            encode_owner(&grant.owner)?,
        ],
    )?;
    Ok(())
}

/// Remove literal-sensitive exact authority from pre-current-schema rows.
/// Sensitive allows can be dropped safely. A sensitive deny on an active
/// session retires the entire session because preserving broader authority
/// without that deny would widen access.
fn repair_sensitive_session_exact_authority(
    conn: &Connection,
) -> Result<(bool, Vec<SessionRevisionUpdate>)> {
    let mut changed = false;
    let mut revision_updates = Vec::new();
    let mut active = Vec::new();
    {
        let mut stmt = conn.prepare(
            "SELECT token, allow_json, deny_json, allow_exact_json, deny_exact_json, activated_verbs_json, override_markers_json, scope_json, expires_at, prompt_append, generated_notes_json, granted_at, static_only, auto_amend, owner_json
             FROM session_grants",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                SessionGrant {
                    allow: decode_vec(&row.get::<_, String>(1)?)?,
                    deny: decode_vec(&row.get::<_, String>(2)?)?,
                    allow_exact: decode_exact_vec(&row.get::<_, String>(3)?)?,
                    deny_exact: decode_exact_vec(&row.get::<_, String>(4)?)?,
                    activated_verbs: decode_vec(&row.get::<_, String>(5)?)?,
                    override_markers: decode_vec(&row.get::<_, String>(6)?)?,
                    scope: decode_scope(&row.get::<_, String>(7)?)?,
                    expires_at: decode_optional_u64(row.get(8)?)?,
                    prompt_append: row.get(9)?,
                    generated_notes: decode_vec(&row.get::<_, String>(10)?)?,
                    granted_at: decode_u64(row.get(11)?)?,
                    static_only: decode_bool(row.get(12)?)?,
                    auto_amend: decode_bool(row.get(13)?)?,
                    owner: decode_owner(&row.get::<_, String>(14)?)?,
                },
            ))
        })?;
        for row in rows {
            active.push(row?);
        }
    }

    for (token, mut grant) in active {
        let old_revision = session_grant_revision_key(&grant)
            .context("compute pre-sanitization session revision")?;
        let allow_changed = purge_sensitive_exact_rules(&mut grant.allow_exact);
        let deny_changed = purge_sensitive_exact_rules(&mut grant.deny_exact);
        match (allow_changed, deny_changed) {
            (_, true) => {
                // Removing a deny would widen authority, so retire the session
                // instead of manufacturing a replacement revision.
                conn.execute(
                    "DELETE FROM session_grants WHERE token = ?1",
                    params![token],
                )?;
                insert_historical_grant(
                    conn,
                    &revoked_history_from_grant(token, grant, guard::env::now_unix()),
                )?;
                changed = true;
            }
            (true, false) => {
                // Removing an allow narrows authority but keeps the session
                // active. Rebase pending dependents to that exact retained
                // revision after their own sensitive fields are sanitized.
                conn.execute(
                    "UPDATE session_grants SET allow_exact_json = ?1 WHERE token = ?2",
                    params![encode_exact_vec(&grant.allow_exact)?, token],
                )?;
                revision_updates.push(SessionRevisionUpdate {
                    token: token.clone(),
                    old_revision,
                    new_revision: session_grant_revision_key(&grant)
                        .context("compute sanitized session revision")?,
                    token_fingerprint: access_session_token_fingerprint(&token),
                });
                changed = true;
            }
            (false, false) => {}
        }
    }
    let history_rows = {
        let mut stmt =
            conn.prepare("SELECT id, allow_exact_json, deny_exact_json FROM session_history")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    for (id, allow_json, deny_json) in history_rows {
        let mut allow = decode_exact_vec(&allow_json)?;
        let mut deny = decode_exact_vec(&deny_json)?;
        let row_changed =
            purge_sensitive_exact_rules(&mut allow) | purge_sensitive_exact_rules(&mut deny);
        if row_changed {
            conn.execute(
                "UPDATE session_history
                 SET allow_exact_json = ?1, deny_exact_json = ?2 WHERE id = ?3",
                params![encode_exact_vec(&allow)?, encode_exact_vec(&deny)?, id],
            )?;
            changed = true;
        }
    }
    Ok((changed, revision_updates))
}

fn purge_sensitive_exact_rules(rules: &mut Vec<SessionExactRule>) -> bool {
    let original_len = rules.len();
    rules.retain(|rule| {
        !guard::redact::command_contains_sensitive_literals(&rule.binary, &rule.args)
    });
    rules.len() != original_len
}

fn validate_exact_rules_safe(rules: &[SessionExactRule]) -> Result<()> {
    if rules
        .iter()
        .any(|rule| guard::redact::command_contains_sensitive_literals(&rule.binary, &rule.args))
    {
        anyhow::bail!("session exact rules cannot persist literal credential argv");
    }
    Ok(())
}

fn should_vacuum(page_count: u64, free_pages: u64) -> bool {
    page_count >= VACUUM_MIN_PAGES
        && free_pages >= VACUUM_MIN_FREE_PAGES
        && free_pages.saturating_mul(4) >= page_count
}

fn encode_vec(values: &[String]) -> Result<String> {
    serde_json::to_string(values).context("failed to encode session list")
}

fn encode_credential_references(values: &[CredentialReference]) -> Result<String> {
    serde_json::to_string(values).context("failed to encode credential references")
}

fn encode_scope(scope: &IssuedGrantScope) -> Result<String> {
    serde_json::to_string(scope).context("failed to encode issued grant scope")
}

/// The default `owner_json` column value: the legacy `Unowned` sentinel, applied
/// to session rows written before schema v7 so they are refused for authority
/// use until reissued. Must stay in sync with `SessionOwner`'s serialization.
const OWNER_JSON_DEFAULT: &str = "'\"unowned\"'";

fn encode_owner(owner: &SessionOwner) -> Result<String> {
    serde_json::to_string(owner).context("failed to encode session owner")
}

#[cfg(unix)]
fn prepare_state_path(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    if let Some(parent) = parent {
        create_parent_without_symlinks(parent)?;
        secure_state_parent(parent)?;
    }

    match std::fs::symlink_metadata(path) {
        Ok(metadata) => secure_existing_state_file(path, &metadata)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut options = std::fs::OpenOptions::new();
            options
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            options
                .open(path)
                .with_context(|| format!("failed to securely create {}", path.display()))?;
        }
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()))
        }
    }
    enforce_private_state_files(path)
}

#[cfg(unix)]
fn open_state_connection(path: &Path) -> rusqlite::Result<Connection> {
    let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
        | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
        | rusqlite::OpenFlags::SQLITE_OPEN_URI
        | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
        | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW;
    Connection::open_with_flags(path, flags)
}

#[cfg(not(unix))]
fn open_state_connection(path: &Path) -> rusqlite::Result<Connection> {
    Connection::open(path)
}

#[cfg(windows)]
fn prepare_state_path(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    SessionStore::ensure_windows_path_has_no_reparse_points(path)
}

#[cfg(not(any(unix, windows)))]
fn prepare_state_path(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    Ok(())
}

#[cfg(unix)]
fn create_parent_without_symlinks(parent: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    let effective_uid = unsafe { libc::geteuid() };
    for component in parent.components() {
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    anyhow::bail!("state database parent {} is a symlink", current.display());
                }
                if !metadata.is_dir() {
                    anyhow::bail!(
                        "state database parent {} is not a directory",
                        current.display()
                    );
                }
                validate_state_ancestor(&current, &metadata, effective_uid, current == parent)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut builder = std::fs::DirBuilder::new();
                builder.mode(0o700);
                builder
                    .create(&current)
                    .with_context(|| format!("failed to securely create {}", current.display()))?;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect {}", current.display()))
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_state_ancestor(
    path: &Path,
    metadata: &std::fs::Metadata,
    effective_uid: u32,
    is_immediate_parent: bool,
) -> Result<()> {
    let owner = metadata.uid();
    if owner != effective_uid && owner != 0 {
        anyhow::bail!(
            "state database ancestor {} is controlled by another principal",
            path.display()
        );
    }
    let mode = metadata.mode();
    // libc exposes mode_t constants with platform-specific integer widths.
    #[allow(clippy::unnecessary_cast)]
    let sticky_mode_bit = libc::S_ISVTX as u32;
    let protected_by_sticky_root = owner == 0 && mode & sticky_mode_bit != 0;
    if mode & 0o022 != 0
        && !protected_by_sticky_root
        && !(is_immediate_parent && owner == effective_uid)
    {
        anyhow::bail!(
            "state database ancestor {} is writable by another principal",
            path.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn secure_state_parent(parent: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(parent)
        .with_context(|| format!("failed to inspect {}", parent.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!(
            "state database parent {} is not a real directory",
            parent.display()
        );
    }
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() == effective_uid {
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to protect {}", parent.display()))?;
    } else if metadata.mode() & 0o022 != 0 {
        anyhow::bail!(
            "state database parent {} is writable by another principal",
            parent.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn secure_existing_state_file(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!("state database {} is not a regular file", path.display());
    }
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid {
        anyhow::bail!(
            "state database {} is not owned by the daemon",
            path.display()
        );
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to protect {}", path.display()))
}

#[cfg(unix)]
fn enforce_private_state_files(path: &Path) -> Result<()> {
    let sidecar = |suffix: &str| {
        let mut value = path.as_os_str().to_os_string();
        value.push(suffix);
        PathBuf::from(value)
    };
    for candidate in [
        path.to_path_buf(),
        sidecar("-wal"),
        sidecar("-shm"),
        sidecar("-journal"),
    ] {
        match std::fs::symlink_metadata(&candidate) {
            Ok(metadata) => secure_existing_state_file(&candidate, &metadata)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect {}", candidate.display()))
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn enforce_private_state_files(path: &Path) -> Result<()> {
    let sidecar = |suffix: &str| {
        let mut value = path.as_os_str().to_os_string();
        value.push(suffix);
        PathBuf::from(value)
    };
    for candidate in [
        path.to_path_buf(),
        sidecar("-wal"),
        sidecar("-shm"),
        sidecar("-journal"),
    ] {
        match std::fs::symlink_metadata(&candidate) {
            Ok(_) if crate::server::secure_fs::harden_existing_state_path(&candidate, false) => {}
            Ok(_) => anyhow::bail!(
                "state database file {} is not protected from ordinary local users",
                candidate.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspect state database file {}", candidate.display())
                })
            }
        }
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn enforce_private_state_files(_path: &Path) -> Result<()> {
    Ok(())
}

fn encode_u64(value: u64) -> Result<i64> {
    i64::try_from(value).context("session timestamp exceeds sqlite integer range")
}

fn encode_optional_u64(value: Option<u64>) -> Result<Option<i64>> {
    value.map(encode_u64).transpose()
}

fn decode_u64(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(8, rusqlite::types::Type::Integer, Box::new(err))
    })
}

fn decode_optional_u64(value: Option<i64>) -> rusqlite::Result<Option<u64>> {
    value.map(decode_u64).transpose()
}

fn encode_bool(value: bool) -> i64 {
    if value {
        1
    } else {
        0
    }
}

fn decode_bool(value: i64) -> rusqlite::Result<bool> {
    Ok(value != 0)
}

fn decode_vec(value: &str) -> rusqlite::Result<Vec<String>> {
    serde_json::from_str(value).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Text,
            Box::new(err),
        )
    })
}

fn decode_credential_references(value: &str) -> rusqlite::Result<Vec<CredentialReference>> {
    let names: Vec<String> = serde_json::from_str(value).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Text,
            Box::new(err),
        )
    })?;
    Ok(names
        .into_iter()
        .filter_map(CredentialReference::from_persisted_name)
        .collect())
}

fn decode_scope(value: &str) -> rusqlite::Result<IssuedGrantScope> {
    serde_json::from_str(value).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Text,
            Box::new(err),
        )
    })
}

fn decode_owner(value: &str) -> rusqlite::Result<SessionOwner> {
    serde_json::from_str(value).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Text,
            Box::new(err),
        )
    })
}

fn encode_exact_vec(values: &[SessionExactRule]) -> rusqlite::Result<String> {
    serde_json::to_string(values).map_err(|err| {
        rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("encode exact rules: {err}"),
        )))
    })
}

fn decode_exact_vec(value: &str) -> rusqlite::Result<Vec<SessionExactRule>> {
    serde_json::from_str(value).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(err))
    })
}

fn ensure_column(conn: &Connection, table: &str, column: &str, definition: &str) -> Result<()> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for row in rows {
        if row? == column {
            return Ok(());
        }
    }
    conn.execute(
        &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
        [],
    )?;
    Ok(())
}

fn encode_historical_status(status: HistoricalStatus) -> &'static str {
    match status {
        HistoricalStatus::Revoked => "revoked",
        HistoricalStatus::Expired => "expired",
    }
}

fn decode_historical_status(value: &str) -> rusqlite::Result<HistoricalStatus> {
    match value {
        "revoked" => Ok(HistoricalStatus::Revoked),
        "expired" => Ok(HistoricalStatus::Expired),
        other => Err(rusqlite::Error::FromSqlConversionFailure(
            other.len(),
            rusqlite::types::Type::Text,
            format!("unknown historical status '{other}'").into(),
        )),
    }
}

fn encode_decision_source(source: SessionDecisionSource) -> &'static str {
    match source {
        SessionDecisionSource::SessionAllow => "session_allow",
        SessionDecisionSource::SessionDeny => "session_deny",
        SessionDecisionSource::SessionStaticOnly => "session_static_only",
        SessionDecisionSource::Llm => "llm",
        SessionDecisionSource::Cache => "cache",
        SessionDecisionSource::StaticPolicy => "static_policy",
        SessionDecisionSource::LearnedDeny => "learned_deny",
        SessionDecisionSource::Validation => "validation",
        SessionDecisionSource::EvaluatorError => "evaluator_error",
        SessionDecisionSource::ApiProxy => "api_proxy",
    }
}

fn decode_decision_source(value: &str) -> rusqlite::Result<SessionDecisionSource> {
    match value {
        "session_allow" => Ok(SessionDecisionSource::SessionAllow),
        "session_deny" => Ok(SessionDecisionSource::SessionDeny),
        "session_static_only" => Ok(SessionDecisionSource::SessionStaticOnly),
        "llm" => Ok(SessionDecisionSource::Llm),
        "cache" => Ok(SessionDecisionSource::Cache),
        "static_policy" => Ok(SessionDecisionSource::StaticPolicy),
        "learned_deny" => Ok(SessionDecisionSource::LearnedDeny),
        "validation" => Ok(SessionDecisionSource::Validation),
        "evaluator_error" => Ok(SessionDecisionSource::EvaluatorError),
        "api_proxy" => Ok(SessionDecisionSource::ApiProxy),
        other => Err(rusqlite::Error::FromSqlConversionFailure(
            other.len(),
            rusqlite::types::Type::Text,
            format!("unknown session decision source '{other}'").into(),
        )),
    }
}

fn encode_exec_status(status: SessionExecStatus) -> &'static str {
    match status {
        SessionExecStatus::NotAttempted => "not_attempted",
        SessionExecStatus::Completed => "completed",
        SessionExecStatus::CompletedAfterApproval => "completed_after_approval",
        SessionExecStatus::Failed => "failed",
        SessionExecStatus::DryRun => "dry_run",
        SessionExecStatus::Held => "held",
        SessionExecStatus::Provisional => "provisional",
    }
}

fn decode_exec_status(value: &str) -> rusqlite::Result<SessionExecStatus> {
    match value {
        "not_attempted" => Ok(SessionExecStatus::NotAttempted),
        "completed" => Ok(SessionExecStatus::Completed),
        "completed_after_approval" => Ok(SessionExecStatus::CompletedAfterApproval),
        "failed" => Ok(SessionExecStatus::Failed),
        "dry_run" => Ok(SessionExecStatus::DryRun),
        "held" => Ok(SessionExecStatus::Held),
        "provisional" => Ok(SessionExecStatus::Provisional),
        other => Err(rusqlite::Error::FromSqlConversionFailure(
            other.len(),
            rusqlite::types::Type::Text,
            format!("unknown exec status '{other}'").into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard::gating::provisional::{ApiRevertPlan, ProvisionalRegistry};
    use guard::gating::verb::Verb;

    #[cfg(unix)]
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    fn pending_approval(handle: &str) -> Approval {
        Approval {
            handle: handle.to_string(),
            snapshot: guard::gating::approval::ApprovalSnapshot {
                binary: "fixture-command".to_string(),
                args: Vec::new(),
                cwd: None,
                env: std::collections::BTreeMap::new(),
                secret_keys: std::collections::BTreeMap::new(),
                session_fingerprint: None,
                session_revision: None,
                secret_entitlements: None,
                secret_file_keys: std::collections::BTreeMap::new(),
                verb_name: None,
                verb_params: std::collections::BTreeMap::new(),
                catalog_version: None,
                verb_digest: None,
                verb_composition_digest: None,
                exec_timeout_secs: None,
                access_verbs: Vec::new(),
                access_requests: Vec::new(),
                principal: Some(guard::principal::PrincipalKey::from_uid(1001)),
                secret_binding: None,
            },
            reason: "fixture approval".to_string(),
            risk: Some(7),
            reversibility: Some(guard::gating::Reversibility::Irreversible),
            decision_trace: None,
            created_unix: 1,
            ttl_secs: u64::MAX,
            status: ApprovalStatus::Pending,
            decided_unix: None,
            decided_reason: None,
            result_exit: None,
            result_stdout: None,
            result_stderr: None,
            notes: Vec::new(),
        }
    }

    fn provisional_row(handle: &str, status: ProvisionalStatus) -> Provisional {
        Provisional {
            handle: handle.to_string(),
            principal: Some(guard::principal::PrincipalKey::from_uid(1001)),
            requester_principal: None,
            binary: "fixture-forward".to_string(),
            args: Vec::new(),
            cwd: None,
            secret_keys: std::collections::BTreeMap::new(),
            secret_file_keys: std::collections::BTreeMap::new(),
            revert_binary: "fixture-revert".to_string(),
            revert_args: Vec::new(),
            confirm_check_binary: None,
            confirm_check_args: Vec::new(),
            control_path: Some("fixture".to_string()),
            session_fingerprint: None,
            session_revision: None,
            secret_entitlements: None,
            api_revert: None,
            reason: "fixture provisional".to_string(),
            decision_trace: None,
            created_unix: 1,
            deadline_unix: 2,
            window_secs: 1,
            auto_reverted_unix: None,
            forward_done: true,
            forward_exit: Some(0),
            forward_persistence_failed: false,
            status,
            revert_exit: None,
            revert_detail: None,
        }
    }

    fn exact_rule_grant(rules: Vec<SessionExactRule>) -> SessionGrant {
        SessionGrant {
            allow: Vec::new(),
            deny: Vec::new(),
            allow_exact: rules,
            deny_exact: Vec::new(),
            activated_verbs: Vec::new(),
            override_markers: Vec::new(),
            scope: IssuedGrantScope::default(),
            expires_at: None,
            prompt_append: None,
            generated_notes: Vec::new(),
            granted_at: 1,
            static_only: false,
            auto_amend: true,
            owner: SessionOwner::Principal(guard::principal::PrincipalKey::from_uid(1001)),
        }
    }

    fn contaminated_trace(value: &str) -> guard::gating::DecisionTrace {
        guard::gating::DecisionTrace {
            version: guard::gating::DecisionTrace::VERSION,
            decision_source: format!("password={value}"),
            verb_matches: vec![guard::gating::DecisionVerbMatch {
                verb: format!("password={value}"),
                cell: format!("password={value}"),
                scope: format!("password={value}"),
                action: format!("password={value}"),
                features: vec![format!("password={value}")],
                selected: true,
                overridden: false,
            }],
            failed_dimensions: vec![format!("password={value}")],
            conflict: Some(format!("password={value}")),
            guidance: Some(format!("password={value}")),
            suggested_grant_delta: Some(format!("password={value}")),
        }
    }

    fn generated_access_request() -> GrantRequest {
        let mut verb = Verb {
            name: "access-generated-fixture".to_string(),
            description: "fixture coverage".to_string(),
            binary: "fixturectl".to_string(),
            args: vec!["status".to_string(), "resource/example".to_string()],
            baseline: false,
            coverage: Vec::new(),
            credential_plan: None,
            params: std::collections::BTreeMap::new(),
            consequence: guard::gating::Reversibility::Irreversible,
            revert: None,
            hold: false,
            trusted: false,
            prompt_context: None,
            exec_timeout_secs: None,
            source_prose: None,
            evidence: None,
            auto_promoted: false,
            promotion_stamp: None,
        };
        verb = guard::gating::verb::normalize_generated_access_verb(verb).unwrap();
        verb.name = guard::gating::verb::generated_access_verb_name(&verb);
        let mut request = GrantRequest::new_access(
            guard::principal::PrincipalKey::from_uid(1001),
            None,
            "agent:fixture".to_string(),
            crate::grant_profile::GrantRequestDelta {
                activated_verbs: vec![verb.name.clone()],
                ..Default::default()
            },
            "request fixture coverage".to_string(),
        )
        .unwrap();
        request.authority_verbs = vec![verb.name.clone()];
        request.proposed_verbs = vec![serde_json::to_value(verb).unwrap()];
        request.request_key = request.canonical_access_key().unwrap();
        request
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        std::fs::symlink_metadata(path).unwrap().mode() & 0o777
    }

    /// Create a temporary directory pinned to mode 0700.
    ///
    /// tempfile::tempdir() inherits the process umask, so on hosts with a
    /// group-writable umask (e.g. 007 -> mode 0770) the directory is created
    /// group-writable. When the state database lives in a subdirectory of the
    /// tempdir, the tempdir is a non-immediate ancestor, which
    /// validate_state_ancestor rejects (only the immediate parent is exempt,
    /// since secure_state_parent tightens it to 0700). Pinning the tempdir to
    /// 0700 keeps these tests umask-independent.
    #[cfg(unix)]
    fn secure_tempdir() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700))
            .expect("restrict tempdir permissions");
        tmp
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn state_store_creates_private_parent_database_and_sidecars() {
        let tmp = secure_tempdir();
        let parent = tmp.path().join("private-state");
        let path = parent.join("state.db");
        let store = SessionStore::open(path.clone(), 3600).await.unwrap();
        assert_eq!(mode(&parent), 0o700);
        assert_eq!(mode(&path), 0o600);

        let conn = SessionStore::open_connection(&path).unwrap();
        conn.pragma_update(None, "journal_mode", "WAL").unwrap();
        conn.execute("CREATE TABLE IF NOT EXISTS sidecar_test (value TEXT)", [])
            .unwrap();
        conn.execute("INSERT INTO sidecar_test VALUES ('value')", [])
            .unwrap();
        enforce_private_state_files(&path).unwrap();
        for suffix in ["-wal", "-shm"] {
            let sidecar = PathBuf::from(format!("{}{suffix}", path.display()));
            assert!(sidecar.exists(), "{} must exist", sidecar.display());
            assert_eq!(mode(&sidecar), 0o600);
        }
        drop(conn);
        drop(store);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn state_store_repairs_owned_existing_modes_and_protects_raw_bearers() {
        let tmp = secure_tempdir();
        let parent = tmp.path().join("state");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
        let path = parent.join("state.db");
        std::fs::write(&path, []).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();

        let store = SessionStore::open(path.clone(), 3600).await.unwrap();
        let mut registry = SessionRegistry::new();
        registry.grant(
            "raw-bearer-must-stay-owner-only".to_string(),
            SessionGrant {
                allow: Vec::new(),
                deny: Vec::new(),
                allow_exact: Vec::new(),
                deny_exact: Vec::new(),
                activated_verbs: Vec::new(),
                override_markers: Vec::new(),
                scope: Default::default(),
                expires_at: None,
                prompt_append: None,
                generated_notes: Vec::new(),
                granted_at: 0,
                static_only: false,
                auto_amend: false,
                owner: SessionOwner::Principal(guard::principal::PrincipalKey::from_uid(1000)),
            },
        );
        store.persist_registry(&registry).await.unwrap();
        assert_eq!(mode(&parent), 0o700);
        assert_eq!(mode(&path), 0o600);
        let bytes = std::fs::read(&path).unwrap();
        assert!(
            bytes
                .windows(b"raw-bearer-must-stay-owner-only".len())
                .any(|window| window == b"raw-bearer-must-stay-owner-only"),
            "test must prove the protected database contains bearer authority"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn legacy_v4_migration_is_private_and_adds_decision_traces() {
        let tmp = secure_tempdir();
        let parent = tmp.path().join("migration-state");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
        let path = parent.join("state.db");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA user_version = 4;").unwrap();
        drop(conn);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();

        let _store = SessionStore::open(path.clone(), 3600).await.unwrap();
        let conn = Connection::open(&path).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        let trace_columns: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('session_interactions') WHERE name = 'decision_trace_json'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        assert_eq!(trace_columns, 1);
        assert_eq!(mode(&parent), 0o700);
        assert_eq!(mode(&path), 0o600);
    }

    #[tokio::test]
    async fn access_request_persistence_rejects_noncanonical_generated_matchers() {
        let mut verb = Verb {
            name: "access-generated-fixture".to_string(),
            description: "fixture coverage".to_string(),
            binary: "kubectl".to_string(),
            args: vec!["annotate".to_string(), "pod/example".to_string()],
            baseline: false,
            coverage: Vec::new(),
            credential_plan: None,
            params: std::collections::BTreeMap::new(),
            consequence: guard::gating::Reversibility::Irreversible,
            revert: None,
            hold: false,
            trusted: false,
            prompt_context: None,
            exec_timeout_secs: None,
            source_prose: None,
            evidence: None,
            auto_promoted: false,
            promotion_stamp: None,
        };
        verb.params.insert(
            "overwrite".to_string(),
            guard::gating::verb::ParamSpec {
                pattern: "^(true|false)$".to_string(),
                required: false,
                default: Some("true".to_string()),
                allow_dash: false,
            },
        );
        verb.revert = Some(guard::gating::verb::VerbCommand {
            binary: "kubectl".to_string(),
            args: vec![
                "annotate".to_string(),
                "--overwrite={overwrite}".to_string(),
            ],
        });
        verb.name = guard::gating::verb::generated_access_verb_name(&verb);
        let mut request = crate::grant_profile::GrantRequest::new_access(
            guard::principal::PrincipalKey::from_uid(1001),
            None,
            "agent:fixture".to_string(),
            crate::grant_profile::GrantRequestDelta {
                activated_verbs: vec![verb.name.clone()],
                ..Default::default()
            },
            "request fixture coverage".to_string(),
        )
        .unwrap();
        request.authority_verbs = vec![verb.name.clone()];
        request.proposed_verbs = vec![serde_json::to_value(&verb).unwrap()];
        request.request_key = request.canonical_access_key().unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state.db");
        let store = SessionStore::open(path.clone(), 3600).await.unwrap();
        assert!(store.save_grant_request(request.clone()).await.is_err());

        let conn = Connection::open(path).unwrap();
        conn.execute(
            "INSERT INTO grant_requests (handle, json, status, created_unix)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                request.handle,
                serde_json::to_string(&request).unwrap(),
                request.status.as_str(),
                encode_u64(request.created_unix).unwrap()
            ],
        )
        .unwrap();
        drop(conn);
        // A row an older binary wrote under a superseded scheme must not
        // refuse the daemon boot: it is skipped fail-closed instead.
        assert!(store.load_grant_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn generated_proposal_envelope_is_canonicalized_on_write_and_migration() {
        let value = ["q", "7"].concat();
        let canonical = generated_access_request();
        let canonical_verb: Verb =
            serde_json::from_value(canonical.proposed_verbs[0].clone()).unwrap();

        let contaminate = |mut request: GrantRequest| {
            let mut verb: Verb = serde_json::from_value(request.proposed_verbs[0].clone()).unwrap();
            verb.description = format!("password={value}");
            verb.prompt_context = Some(format!("password={value}"));
            verb.source_prose = Some(format!("password={value}"));
            verb.evidence = Some(format!("password={value}"));
            verb.auto_promoted = true;
            verb.promotion_stamp = Some(format!("password={value}"));
            verb.baseline = true;
            verb.trusted = true;
            verb.revert = Some(guard::gating::verb::VerbCommand {
                binary: "fixturectl".to_string(),
                args: vec!["undo".to_string()],
            });
            request.proposed_verbs = vec![serde_json::to_value(verb).unwrap()];
            request.request_key = request.canonical_access_key().unwrap();
            request
        };

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("write.db");
        let store = SessionStore::open(path.clone(), 3_600).await.unwrap();
        store
            .save_grant_request(contaminate(canonical.clone()))
            .await
            .unwrap();
        let loaded = store.load_grant_requests().await.unwrap().remove(0);
        let loaded_verb = loaded
            .validated_generated_access_proposals()
            .unwrap()
            .remove(0);
        assert_eq!(
            guard::gating::verb::generated_access_matcher_shape(&loaded_verb),
            guard::gating::verb::generated_access_matcher_shape(&canonical_verb)
        );
        assert_eq!(loaded_verb.name, canonical_verb.name);
        assert!(loaded_verb.prompt_context.is_none());
        assert!(loaded_verb.source_prose.is_none());
        assert!(loaded_verb.evidence.is_none());
        assert!(loaded_verb.promotion_stamp.is_none());
        assert!(!loaded_verb.auto_promoted);
        assert!(!loaded_verb.baseline);
        assert!(!loaded_verb.trusted);
        assert!(loaded_verb.revert.is_none());
        assert!(!std::fs::read(&path)
            .unwrap()
            .windows(value.len())
            .any(|window| window == value.as_bytes()));

        let migration_path = temp.path().join("migration.db");
        let migration_store = SessionStore::open(migration_path.clone(), 3_600)
            .await
            .unwrap();
        let contaminated = contaminate(canonical);
        let connection = Connection::open(&migration_path).unwrap();
        connection
            .execute(
                "INSERT INTO grant_requests (handle, json, status, created_unix)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    contaminated.handle,
                    serde_json::to_string(&contaminated).unwrap(),
                    contaminated.status.as_str(),
                    encode_u64(contaminated.created_unix).unwrap()
                ],
            )
            .unwrap();
        connection
            .pragma_update(None, "user_version", SCHEMA_VERSION - 1)
            .unwrap();
        let seeded_version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(seeded_version, SCHEMA_VERSION - 1);
        drop(connection);
        drop(migration_store);
        let restarted = SessionStore::open(migration_path.clone(), 3_600)
            .await
            .unwrap();
        let migrated = restarted.load_grant_requests().await.unwrap().remove(0);
        let migrated_verb = migrated
            .validated_generated_access_proposals()
            .unwrap()
            .remove(0);
        assert_eq!(
            serde_json::to_value(migrated_verb).unwrap(),
            serde_json::to_value(canonical_verb).unwrap()
        );
        let connection = Connection::open(&migration_path).unwrap();
        let raw_json: String = connection
            .query_row("SELECT json FROM grant_requests", [], |row| row.get(0))
            .unwrap();
        assert!(!raw_json.contains(&value));
        drop(connection);
        drop(restarted);

        let second_restart = SessionStore::open(migration_path.clone(), 3_600)
            .await
            .unwrap();
        second_restart.load_grant_requests().await.unwrap();
        drop(second_restart);
        let connection = Connection::open(migration_path).unwrap();
        let repeated_json: String = connection
            .query_row("SELECT json FROM grant_requests", [], |row| row.get(0))
            .unwrap();
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(repeated_json, raw_json);
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[tokio::test]
    async fn schema_v13_rejects_an_inconsistent_original_pending_key_transactionally() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.db");
        let store = SessionStore::open(path.clone(), 3_600).await.unwrap();
        let mut request = generated_access_request();
        request.request_key.push_str("-mismatch");
        let json = serde_json::to_string(&request).unwrap();
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "INSERT INTO grant_requests (handle, json, status, created_unix)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    request.handle,
                    json,
                    request.status.as_str(),
                    encode_u64(request.created_unix).unwrap()
                ],
            )
            .unwrap();
        connection
            .pragma_update(None, "user_version", SCHEMA_VERSION - 1)
            .unwrap();
        drop(connection);
        drop(store);

        for _ in 0..2 {
            // An inconsistent legacy row must not refuse the boot. It is
            // skipped fail-closed on load and never rewritten: sanitizing a
            // row that fails validation would launder it.
            let reopened = SessionStore::open(path.clone(), 3_600).await.unwrap();
            assert!(reopened.load_grant_requests().await.unwrap().is_empty());
            drop(reopened);
            let connection = Connection::open(&path).unwrap();
            let durable: String = connection
                .query_row("SELECT json FROM grant_requests", [], |row| row.get(0))
                .unwrap();
            assert_eq!(durable, json);
        }
    }

    #[tokio::test]
    async fn sensitive_generated_parameter_authority_fails_new_and_restart_loads() {
        let value = ["q", "7"].concat();
        let mut request = generated_access_request();
        let mut verb: Verb = serde_json::from_value(request.proposed_verbs[0].clone()).unwrap();
        verb.args.push("{password}".to_string());
        verb.params.insert(
            "password".to_string(),
            guard::gating::verb::ParamSpec {
                pattern: "^[a-z0-9]+$".to_string(),
                required: false,
                default: Some(value.clone()),
                allow_dash: false,
            },
        );
        verb.name = guard::gating::verb::generated_access_verb_name(&verb);
        request.authority_verbs = vec![verb.name.clone()];
        request.delta.activated_verbs = vec![verb.name.clone()];
        request.proposed_verbs = vec![serde_json::to_value(&verb).unwrap()];
        request.request_key = request.canonical_access_key().unwrap();

        for version in [SCHEMA_VERSION, SCHEMA_VERSION - 1] {
            let tmp = tempfile::tempdir().unwrap();
            let path = tmp.path().join("state.db");
            let store = SessionStore::open(path.clone(), 3600).await.unwrap();
            let error = store.save_grant_request(request.clone()).await.unwrap_err();
            assert!(!error.to_string().contains(&value));

            let conn = Connection::open(&path).unwrap();
            conn.execute(
                "INSERT INTO grant_requests (handle, json, status, created_unix)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    request.handle,
                    serde_json::to_string(&request).unwrap(),
                    request.status.as_str(),
                    encode_u64(request.created_unix).unwrap()
                ],
            )
            .unwrap();
            conn.pragma_update(None, "user_version", version).unwrap();
            drop(conn);
            drop(store);

            // A sensitive row an older binary persisted must not refuse the
            // daemon boot; it is skipped fail-closed on load instead.
            let reopened = SessionStore::open(path.clone(), 3600).await.unwrap();
            assert!(reopened.load_grant_requests().await.unwrap().is_empty());
            drop(reopened);

            let reopened = SessionStore::open(path, 3600).await.unwrap();
            assert!(reopened.load_grant_requests().await.unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn restarted_generated_parameter_matchers_reject_sensitive_concrete_argv() {
        use guard::gating::verb::{generated_access_verb_name, ParamSpec, VerbCatalog};
        use std::collections::BTreeMap;

        fn parameter(pattern: &str, allow_dash: bool) -> ParamSpec {
            ParamSpec {
                pattern: pattern.to_string(),
                required: true,
                default: None,
                allow_dash,
            }
        }
        fn generated(binary: &str, args: &[&str], params: BTreeMap<String, ParamSpec>) -> Verb {
            let mut verb = generated_access_request()
                .proposed_verbs
                .into_iter()
                .next()
                .and_then(|value| serde_json::from_value::<Verb>(value).ok())
                .unwrap();
            verb.binary = binary.to_string();
            verb.args = args.iter().map(|value| (*value).to_string()).collect();
            verb.params = params;
            verb.name = generated_access_verb_name(&verb);
            verb
        }

        let verbs = [
            generated(
                "fixturectl",
                &["{option}", "{operand}"],
                BTreeMap::from([
                    ("option".to_string(), parameter("^--[a-z]{8}$", true)),
                    ("operand".to_string(), parameter("^[a-z0-9]{2}$", false)),
                ]),
            ),
            generated(
                "fixturectl",
                &["{argument}"],
                BTreeMap::from([(
                    "argument".to_string(),
                    parameter("^--[a-z]{8}=[a-z0-9]{2}$", true),
                )]),
            ),
            generated(
                "mysql",
                &["{argument}"],
                BTreeMap::from([(
                    "argument".to_string(),
                    parameter("^-[a-z][a-z0-9]{2}$", true),
                )]),
            ),
        ];
        let mut request = generated_access_request();
        request.authority_verbs = verbs.iter().map(|verb| verb.name.clone()).collect();
        request.delta.activated_verbs = request.authority_verbs.clone();
        request.proposed_verbs = verbs
            .iter()
            .map(|verb| serde_json::to_value(verb).unwrap())
            .collect();
        request.request_key = request.canonical_access_key().unwrap();

        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("state.db");
        let store = SessionStore::open(path.clone(), 3_600).await.unwrap();
        store.save_grant_request(request).await.unwrap();
        drop(store);

        let restarted = SessionStore::open(path, 3_600).await.unwrap();
        let request = restarted.load_grant_requests().await.unwrap().remove(0);
        let mut catalog = VerbCatalog::empty();
        for proposal in request.proposed_verbs {
            catalog
                .upsert_access_verb(
                    guard::gating::verb::parse_normalized_generated_access_verb(&proposal).unwrap(),
                )
                .unwrap();
        }
        let value = ["q", "7"].concat();
        for (index, params, binary, args) in [
            (
                0,
                BTreeMap::from([
                    ("option".to_string(), "--password".to_string()),
                    ("operand".to_string(), value.clone()),
                ]),
                "fixturectl",
                vec!["--password".to_string(), value.clone()],
            ),
            (
                1,
                BTreeMap::from([("argument".to_string(), format!("--password={value}"))]),
                "fixturectl",
                vec![format!("--password={value}")],
            ),
            (
                2,
                BTreeMap::from([("argument".to_string(), format!("-p{value}"))]),
                "mysql",
                vec![format!("-p{value}")],
            ),
        ] {
            assert!(catalog.render(&verbs[index].name, &params).is_err());
            assert!(catalog.match_command(binary, &args).is_none());
        }
    }

    #[tokio::test]
    async fn sensitive_generated_provenance_fails_write_migration_and_restart_loads() {
        use guard::gating::verb::{CoverageAction, CoverageProvenance, VerbCoverageCell};

        let value = ["q", "7"].concat();
        let mut request = generated_access_request();
        let mut verb: Verb = serde_json::from_value(request.proposed_verbs[0].clone()).unwrap();
        verb.coverage = vec![VerbCoverageCell {
            name: "exact".to_string(),
            action: CoverageAction::Evaluate,
            required_args: Vec::new(),
            forbidden_args: Vec::new(),
            min_args: Some(2),
            max_args: Some(2),
            options: Vec::new(),
            target: None,
            inventory: None,
            namespace: None,
            fanout: None,
            cwd: None,
            environment: Vec::new(),
            override_marker: None,
            sticky: false,
            provenance: Some(CoverageProvenance {
                source: "fixture".to_string(),
                evidence: Vec::new(),
                regime_stamp: "safe-regime".to_string(),
                prompt_stamp: format!("password={value}"),
                model_stamp: "safe-model".to_string(),
                generated_unix: 1,
                probes: Vec::new(),
                observation_replays: Vec::new(),
            }),
        }];
        verb.name = guard::gating::verb::generated_access_verb_name(&verb);
        request.authority_verbs = vec![verb.name.clone()];
        request.delta.activated_verbs = vec![verb.name.clone()];
        request.proposed_verbs = vec![serde_json::to_value(&verb).unwrap()];
        request.request_key = request.canonical_access_key().unwrap();

        for version in [SCHEMA_VERSION, SCHEMA_VERSION - 1] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("state.db");
            let store = SessionStore::open(path.clone(), 3600).await.unwrap();
            let error = store.save_grant_request(request.clone()).await.unwrap_err();
            assert!(!error.to_string().contains(&value));

            let conn = Connection::open(&path).unwrap();
            conn.execute(
                "INSERT INTO grant_requests (handle, json, status, created_unix)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    request.handle,
                    serde_json::to_string(&request).unwrap(),
                    request.status.as_str(),
                    encode_u64(request.created_unix).unwrap()
                ],
            )
            .unwrap();
            conn.pragma_update(None, "user_version", version).unwrap();
            drop(conn);
            drop(store);

            for _ in 0..2 {
                // Rows persisted by an older binary must not refuse the boot;
                // they are skipped fail-closed on load instead.
                let reopened = SessionStore::open(path.clone(), 3600).await.unwrap();
                assert!(reopened.load_grant_requests().await.unwrap().is_empty());
            }
        }
    }

    #[tokio::test]
    async fn access_request_persistence_rejects_invalid_scope_and_convergence_key() {
        let mut invalid_scope = generated_access_request();
        invalid_scope.authority_verbs = vec!["access-generated-other".to_string()];
        invalid_scope.request_key = invalid_scope.canonical_access_key().unwrap();

        let mut invalid_key = generated_access_request();
        invalid_key.request_key = "ar-invalid".to_string();

        for request in [invalid_scope, invalid_key] {
            let tmp = tempfile::tempdir().unwrap();
            let path = tmp.path().join("state.db");
            let store = SessionStore::open(path.clone(), 3600).await.unwrap();
            assert!(store.save_grant_request(request.clone()).await.is_err());

            let conn = Connection::open(path).unwrap();
            conn.execute(
                "INSERT INTO grant_requests (handle, json, status, created_unix)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    request.handle,
                    serde_json::to_string(&request).unwrap(),
                    request.status.as_str(),
                    encode_u64(request.created_unix).unwrap()
                ],
            )
            .unwrap();
            drop(conn);
            assert!(store.load_grant_requests().await.unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn access_request_persistence_rejects_stripped_projection_fields() {
        let mut requesterless = generated_access_request();
        requesterless.requester = None;

        let mut partially_stripped = generated_access_request();
        partially_stripped.target = None;

        let mut uses_only = generated_access_request();
        uses_only.requester = None;
        uses_only.target = None;
        uses_only.request_key.clear();
        uses_only.authority_verbs.clear();
        uses_only.proposed_verbs.clear();
        uses_only.delta.activated_verbs.clear();
        uses_only.requested_uses = Some(1);

        for request in [requesterless, partially_stripped, uses_only] {
            let tmp = tempfile::tempdir().unwrap();
            let path = tmp.path().join("state.db");
            let store = SessionStore::open(path.clone(), 3600).await.unwrap();
            assert!(store.save_grant_request(request.clone()).await.is_err());

            let conn = Connection::open(path).unwrap();
            conn.execute(
                "INSERT INTO grant_requests (handle, json, status, created_unix)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    request.handle,
                    serde_json::to_string(&request).unwrap(),
                    request.status.as_str(),
                    encode_u64(request.created_unix).unwrap()
                ],
            )
            .unwrap();
            drop(conn);
            assert!(store.load_grant_requests().await.unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn provisional_decision_trace_survives_restart_recovery() {
        use guard::gating::provisional::{ProvisionalRegistry, ProvisionalStatus};
        use std::collections::BTreeMap;

        let tmp = tempfile::tempdir().unwrap();
        let store = SessionStore::open(tmp.path().join("state.db"), 3600)
            .await
            .unwrap();
        let trace = guard::gating::DecisionTrace::source("static_policy");
        store
            .save_provisional(Provisional {
                handle: "restart-trace".to_string(),
                principal: Some(guard::principal::PrincipalKey::from_uid(1001)),
                requester_principal: None,
                binary: "true".to_string(),
                args: Vec::new(),
                cwd: None,
                secret_keys: BTreeMap::new(),
                secret_file_keys: BTreeMap::new(),
                revert_binary: "true".to_string(),
                revert_args: Vec::new(),
                confirm_check_binary: None,
                confirm_check_args: Vec::new(),
                control_path: Some("local".to_string()),
                session_fingerprint: Some("sha256:test".to_string()),
                session_revision: Some("revision".to_string()),
                secret_entitlements: Some(Vec::new()),
                api_revert: None,
                reason: "bounded change".to_string(),
                decision_trace: Some(trace.clone()),
                created_unix: 1,
                deadline_unix: u64::MAX,
                window_secs: 0,
                auto_reverted_unix: None,
                forward_done: true,
                forward_exit: Some(0),
                forward_persistence_failed: false,
                status: ProvisionalStatus::Armed,
                revert_exit: None,
                revert_detail: None,
            })
            .await
            .unwrap();

        let rows = SessionStore::open(tmp.path().join("state.db"), 3600)
            .await
            .unwrap()
            .load_provisionals()
            .await
            .unwrap();
        let (registry, moved) = ProvisionalRegistry::from_rows(rows);
        assert!(moved.is_empty());
        let restored = registry.get("restart-trace").unwrap();
        assert_eq!(restored.status, ProvisionalStatus::Armed);
        assert_eq!(restored.decision_trace.as_ref(), Some(&trace));
    }

    #[tokio::test]
    async fn historical_kubernetes_create_rollback_is_retired_without_provenance() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        let store = SessionStore::open(path.clone(), 3600).await.unwrap();
        let mut row = provisional_row("legacy-create", ProvisionalStatus::Armed);
        row.api_revert = Some(ApiRevertPlan {
            endpoint: "cluster".to_string(),
            protocol: "kubernetes".to_string(),
            upstream_target: "https://cluster.invalid".to_string(),
            upstream_identity: "identity".to_string(),
            method: "DELETE".to_string(),
            path: "/api/v1/namespaces/dev/pods/example".to_string(),
            requires_uid_precondition: true,
            resource_uid: Some("legacy-uid".to_string()),
            create_provenance: None,
            body_file: None,
        });
        drop(store);
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "INSERT INTO gating_provisional (handle, json, status, created_unix)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    row.handle,
                    serde_json::to_string(&row).unwrap(),
                    row.status.as_str(),
                    encode_u64(row.created_unix).unwrap()
                ],
            )
            .unwrap();
        connection
            .pragma_update(None, "user_version", 13_i64)
            .unwrap();
        drop(connection);

        let reopened = SessionStore::open(path, 3600).await.unwrap();
        let rows = reopened.load_provisionals().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, ProvisionalStatus::NeedsOperatorDecision);
        let api = rows[0].api_revert.as_ref().unwrap();
        assert!(api.requires_uid_precondition);
        assert!(api.resource_uid.is_some());
        assert!(api.create_provenance.is_none());
        let mut registry = ProvisionalRegistry::new();
        registry.insert(rows[0].clone());
        assert!(registry.begin_revert("legacy-create").is_err());
    }

    #[tokio::test]
    async fn restart_retires_pre_handoff_stage_and_escalates_dispatch_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        let store = SessionStore::open(path.clone(), 3600).await.unwrap();
        let api_revert = ApiRevertPlan {
            endpoint: "cluster".to_string(),
            protocol: "kubernetes".to_string(),
            upstream_target: "https://cluster.invalid".to_string(),
            upstream_identity: "identity".to_string(),
            method: "PUT".to_string(),
            path: "/api/v1/namespaces/dev/configmaps/example".to_string(),
            requires_uid_precondition: false,
            resource_uid: None,
            create_provenance: None,
            body_file: None,
        };
        let mut staged = provisional_row("never-dispatched", ProvisionalStatus::Staged);
        staged.forward_done = false;
        staged.forward_exit = None;
        staged.deadline_unix = 0;
        staged.window_secs = 0;
        staged.api_revert = Some(api_revert.clone());
        store.save_provisional(staged.clone()).await.unwrap();

        let mut cleanup_pending = staged.clone();
        cleanup_pending.handle = "cleanup-pending".to_string();
        cleanup_pending.revert_detail =
            Some("pre-dispatch containment cleanup is pending".to_string());
        store.save_provisional(cleanup_pending).await.unwrap();

        let mut dispatching = staged.clone();
        dispatching.handle = "dispatch-evidence".to_string();
        store.save_provisional(dispatching.clone()).await.unwrap();
        let mut dispatch_marker = dispatching.clone();
        dispatch_marker.status = ProvisionalStatus::Dispatching;
        store
            .compare_and_swap_provisional(dispatching, dispatch_marker)
            .await
            .unwrap();
        drop(store);

        let reopened = SessionStore::open(path, 3600).await.unwrap();
        let rows = reopened.load_provisionals().await.unwrap();
        let (registry, moved, retired) = ProvisionalRegistry::recover_rows(rows);
        assert_eq!(retired, vec!["never-dispatched".to_string()]);
        assert_eq!(moved, vec!["dispatch-evidence".to_string()]);
        assert!(registry.get("never-dispatched").is_none());
        let cleanup_pending = registry.get("cleanup-pending").unwrap();
        assert_eq!(cleanup_pending.status, ProvisionalStatus::Staged);
        assert_eq!(cleanup_pending.forward_outcome(), "cleanup_pending");
        let recovered = registry.get("dispatch-evidence").unwrap();
        assert_eq!(recovered.status, ProvisionalStatus::NeedsOperatorDecision);
        assert!(recovered.forward_done);
        assert!(recovered.forward_exit.is_none());
        assert_eq!(recovered.forward_outcome(), "indeterminate");
    }

    #[tokio::test]
    async fn schema_v14_migrates_v13_dispatch_to_indeterminate_idempotently() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        let store = SessionStore::open(path.clone(), 3600).await.unwrap();
        drop(store);
        let mut row = provisional_row("legacy-dispatch", ProvisionalStatus::Dispatching);
        row.forward_done = false;
        row.forward_exit = None;
        row.deadline_unix = 0;
        row.window_secs = 0;
        row.api_revert = Some(ApiRevertPlan {
            endpoint: "cluster".to_string(),
            protocol: "kubernetes".to_string(),
            upstream_target: "https://cluster.invalid".to_string(),
            upstream_identity: "identity".to_string(),
            method: "PUT".to_string(),
            path: "/api/v1/namespaces/dev/configmaps/example".to_string(),
            requires_uid_precondition: false,
            resource_uid: None,
            create_provenance: None,
            body_file: None,
        });
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "INSERT INTO gating_provisional (handle, json, status, created_unix)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    row.handle,
                    serde_json::to_string(&row).unwrap(),
                    row.status.as_str(),
                    encode_u64(row.created_unix).unwrap()
                ],
            )
            .unwrap();
        connection
            .pragma_update(None, "user_version", 13_i64)
            .unwrap();
        drop(connection);

        let reopened = SessionStore::open(path.clone(), 3600).await.unwrap();
        let migrated = reopened.load_provisionals().await.unwrap();
        assert_eq!(migrated.len(), 1);
        assert_eq!(migrated[0].status, ProvisionalStatus::NeedsOperatorDecision);
        assert!(migrated[0].forward_done);
        assert_eq!(migrated[0].forward_exit, None);
        assert_eq!(migrated[0].forward_outcome(), "indeterminate");
        drop(reopened);

        let first_json: String = Connection::open(&path)
            .unwrap()
            .query_row("SELECT json FROM gating_provisional", [], |row| row.get(0))
            .unwrap();
        drop(SessionStore::open(path.clone(), 3600).await.unwrap());
        let connection = Connection::open(path).unwrap();
        let second_json: String = connection
            .query_row("SELECT json FROM gating_provisional", [], |row| row.get(0))
            .unwrap();
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(first_json, second_json);
        assert_eq!(version, 14);
    }

    #[test]
    fn schema_v13_reader_rejects_v14_before_authority_decoding() {
        let error = ensure_supported_schema_version(14, 13).unwrap_err();
        assert!(error.to_string().contains("newer than supported"));
    }

    #[tokio::test]
    async fn malformed_provisional_row_fails_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state.db");
        let store = SessionStore::open(path.clone(), 3600).await.unwrap();
        let conn = Connection::open(path).unwrap();
        conn.execute(
            "INSERT INTO gating_provisional (handle, json, status, created_unix)
             VALUES (?1, ?2, ?3, ?4)",
            params!["malformed-armed", "{", "armed", 1],
        )
        .unwrap();
        drop(conn);

        let error = store.load_provisionals().await.unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("malformed-armed"), "{rendered}");
        assert!(rendered.contains("armed"), "{rendered}");
    }

    #[tokio::test]
    async fn grant_request_index_mismatch_fails_closed() {
        let request = GrantRequest::new(
            "fixture-session".to_string(),
            None,
            crate::grant_profile::GrantRequestDelta {
                ttl_secs: Some(60),
                ..Default::default()
            },
            "inspect the fixture".to_string(),
        )
        .unwrap();
        let json = serde_json::to_string(&request).unwrap();
        let cases = [
            (
                format!("{}-different", request.handle),
                request.status.as_str().to_string(),
                request.created_unix,
            ),
            (
                request.handle.clone(),
                "approved".to_string(),
                request.created_unix,
            ),
            (
                request.handle.clone(),
                request.status.as_str().to_string(),
                request.created_unix + 1,
            ),
        ];

        for (handle, status, created_unix) in cases {
            let tmp = tempfile::tempdir().unwrap();
            let path = tmp.path().join("state.db");
            let store = SessionStore::open(path.clone(), 3600).await.unwrap();
            let conn = Connection::open(path).unwrap();
            conn.execute(
                "INSERT INTO grant_requests (handle, json, status, created_unix)
                 VALUES (?1, ?2, ?3, ?4)",
                params![handle, json, status, encode_u64(created_unix).unwrap()],
            )
            .unwrap();
            drop(conn);

            let error = format!("{:#}", store.load_grant_requests().await.unwrap_err());
            assert!(error.contains("index disagrees"), "{error}");
        }
    }

    #[tokio::test]
    async fn migration_rejects_grant_request_index_corruption_before_sanitizing() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state.db");
        let store = SessionStore::open(path.clone(), 3600).await.unwrap();
        let request = GrantRequest::new(
            "fixture-session".to_string(),
            None,
            crate::grant_profile::GrantRequestDelta {
                prompt_append: Some("Authorization: Bearer fixture-value".to_string()),
                ..Default::default()
            },
            "inspect the fixture".to_string(),
        )
        .unwrap();
        store.save_grant_request(request.clone()).await.unwrap();
        drop(store);

        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE grant_requests SET json = ?1, status = 'approved', created_unix = ?2 WHERE handle = ?3",
            params![
                serde_json::to_string(&request).unwrap(),
                encode_u64(request.created_unix + 1).unwrap(),
                request.handle
            ],
        )
        .unwrap();
        conn.pragma_update(None, "user_version", SCHEMA_VERSION - 1)
            .unwrap();
        drop(conn);

        let error = SessionStore::open(path.clone(), 3600).await.unwrap_err();
        assert!(format!("{error:#}").contains("grant-request index disagrees"));
        let conn = Connection::open(path).unwrap();
        let (status, created_unix, version): (String, i64, i64) = (
            conn.query_row("SELECT status FROM grant_requests", [], |row| row.get(0))
                .unwrap(),
            conn.query_row("SELECT created_unix FROM grant_requests", [], |row| {
                row.get(0)
            })
            .unwrap(),
            conn.query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap(),
        );
        assert_eq!(status, "approved");
        assert_eq!(decode_u64(created_unix).unwrap(), request.created_unix + 1);
        assert_eq!(version, SCHEMA_VERSION - 1);
        let json: String = conn
            .query_row("SELECT json FROM grant_requests", [], |row| row.get(0))
            .unwrap();
        assert!(json.contains("fixture-value"));
    }

    #[tokio::test]
    async fn current_schema_missing_authority_table_fails_without_repair() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state.db");
        let store = SessionStore::open(path.clone(), 3600).await.unwrap();
        drop(store);

        let conn = Connection::open(&path).unwrap();
        conn.execute("DROP TABLE grant_requests", []).unwrap();
        drop(conn);

        let error = SessionStore::open(path.clone(), 3600)
            .await
            .expect_err("current authority tables must never be recreated implicitly");
        assert!(format!("{error:#}").contains("missing required table grant_requests"));
        let conn = Connection::open(path).unwrap();
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'grant_requests')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!exists, "failed startup repaired missing authority state");
    }

    #[tokio::test]
    async fn saved_grant_name_index_mismatch_fails_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state.db");
        let store = SessionStore::open(path.clone(), 3600).await.unwrap();
        let grant = crate::grant_profile::SavedGrantCatalog::from_yaml(
            "grants:\n  - name: expected-name\n    activated_verbs: [inspect]\n",
        )
        .unwrap()
        .get("expected-name")
        .unwrap()
        .clone();
        store.save_saved_grant(grant).await.unwrap();
        drop(store);

        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE saved_grants SET name = 'different-name' WHERE name = 'expected-name'",
            [],
        )
        .unwrap();
        drop(conn);

        let error = SessionStore::open(path, 3600).await.unwrap_err();
        assert!(format!("{error:#}").contains("saved-grant index disagrees"));
    }

    #[tokio::test]
    async fn invalid_current_saved_grant_remains_visible_to_startup_validation() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state.db");
        let store = SessionStore::open(path.clone(), 3600).await.unwrap();
        drop(store);

        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO saved_grants (name, json, updated_unix)
             VALUES (?1, ?2, 0)",
            params!["indexed-name", r#"{"name":"serialized-name"}"#],
        )
        .unwrap();
        drop(conn);

        let error = SessionStore::open(path.clone(), 3600).await.unwrap_err();
        assert!(format!("{error:#}").contains("saved-grant index disagrees"));

        let conn = Connection::open(path).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM saved_grants WHERE name = ?1",
                params!["indexed-name"],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM saved_grant_tombstones WHERE name = ?1",
                params!["indexed-name"],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn malformed_approval_and_read_grant_rows_fail_closed() {
        let approval_tmp = tempfile::tempdir().unwrap();
        let approval_path = approval_tmp.path().join("state.db");
        let approval_store = SessionStore::open(approval_path.clone(), 3600)
            .await
            .unwrap();
        let approval_conn = Connection::open(approval_path).unwrap();
        approval_conn
            .execute(
                "INSERT INTO gating_approval (handle, json, status, created_unix)
                 VALUES (?1, ?2, ?3, ?4)",
                params!["malformed-approval", "{", "pending", 1],
            )
            .unwrap();
        drop(approval_conn);

        let approval_error = format!("{:#}", approval_store.load_approvals().await.unwrap_err());
        assert!(approval_error.contains("malformed-approval"));

        let read_tmp = tempfile::tempdir().unwrap();
        let read_path = read_tmp.path().join("state.db");
        let read_store = SessionStore::open(read_path.clone(), 3600).await.unwrap();
        let read_conn = Connection::open(read_path).unwrap();
        read_conn
            .execute(
                "INSERT INTO read_grants (target_path, json, status, expires_unix)
                 VALUES (?1, ?2, ?3, ?4)",
                params!["/fixture/path", "{", "active", 1],
            )
            .unwrap();
        drop(read_conn);

        let read_error = format!("{:#}", read_store.load_read_grants().await.unwrap_err());
        assert!(read_error.contains("/fixture/path"));
    }

    #[tokio::test]
    async fn provisional_claim_failure_leaves_durable_rollback_armed() {
        use std::collections::BTreeMap;

        let tmp = tempfile::tempdir().unwrap();
        let store = SessionStore::open(tmp.path().join("state.db"), 3600)
            .await
            .unwrap();
        let armed = Provisional {
            handle: "provisional-cas".to_string(),
            principal: Some(guard::principal::PrincipalKey::from_uid(1001)),
            requester_principal: None,
            binary: "fixture-forward".to_string(),
            args: Vec::new(),
            cwd: None,
            secret_keys: BTreeMap::new(),
            secret_file_keys: BTreeMap::new(),
            revert_binary: "fixture-revert".to_string(),
            revert_args: Vec::new(),
            confirm_check_binary: None,
            confirm_check_args: Vec::new(),
            control_path: Some("fixture".to_string()),
            session_fingerprint: None,
            session_revision: None,
            secret_entitlements: None,
            api_revert: None,
            reason: "fixture provisional".to_string(),
            decision_trace: None,
            created_unix: 1,
            deadline_unix: 2,
            window_secs: 0,
            auto_reverted_unix: None,
            forward_done: true,
            forward_exit: Some(0),
            forward_persistence_failed: false,
            status: ProvisionalStatus::Armed,
            revert_exit: None,
            revert_detail: None,
        };
        store.save_provisional(armed.clone()).await.unwrap();
        let mut armed = armed;
        armed.decision_trace = Some(guard::gating::DecisionTrace::source("static_policy"));
        store.save_provisional(armed.clone()).await.unwrap();
        let mut reverting = armed.clone();
        reverting.status = ProvisionalStatus::Reverting;
        store.fail_next_write_for_test();
        assert!(store
            .compare_and_swap_provisional(armed.clone(), reverting.clone())
            .await
            .is_err());
        assert_eq!(
            store.load_provisionals().await.unwrap()[0].status,
            ProvisionalStatus::Armed
        );

        store
            .compare_and_swap_provisional(armed.clone(), reverting)
            .await
            .unwrap();
        assert!(store.save_provisional(armed).await.is_err());
        assert_eq!(
            store.load_provisionals().await.unwrap()[0].status,
            ProvisionalStatus::Reverting
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn state_store_rejects_symlinks_and_non_regular_database_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target.db");
        std::fs::write(&target, []).unwrap();
        let linked = tmp.path().join("linked.db");
        symlink(&target, &linked).unwrap();
        assert!(SessionStore::open(linked, 3600).await.is_err());

        let direct_link = tmp.path().join("direct-link.db");
        symlink(&target, &direct_link).unwrap();
        assert!(open_state_connection(&direct_link).is_err());

        let directory = tmp.path().join("directory.db");
        std::fs::create_dir(&directory).unwrap();
        assert!(SessionStore::open(directory, 3600).await.is_err());

        let real_parent = tmp.path().join("real-parent");
        std::fs::create_dir(&real_parent).unwrap();
        let linked_parent = tmp.path().join("linked-parent");
        symlink(&real_parent, &linked_parent).unwrap();
        assert!(SessionStore::open(linked_parent.join("state.db"), 3600)
            .await
            .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn state_store_rejects_shared_writable_parent_not_owned_by_daemon() {
        let shared = Path::new("/tmp");
        let metadata = std::fs::symlink_metadata(shared).unwrap();
        if metadata.uid() != unsafe { libc::geteuid() } && metadata.mode() & 0o022 != 0 {
            let error = secure_state_parent(shared).unwrap_err();
            assert!(error.to_string().contains("writable by another principal"));
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn state_store_rejects_writable_ancestor() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let error = SessionStore::open(tmp.path().join("private/state.db"), 3600)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("writable by another principal"));
    }

    #[test]
    fn api_proxy_decision_source_round_trips() {
        let encoded = encode_decision_source(SessionDecisionSource::ApiProxy);
        assert_eq!(encoded, "api_proxy");
        assert_eq!(
            decode_decision_source(encoded).unwrap(),
            SessionDecisionSource::ApiProxy
        );
    }

    #[tokio::test]
    async fn saved_grants_and_requests_round_trip() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = SessionStore::open(tmp.path().join("state.db"), 24 * 60 * 60)
            .await
            .expect("open store");
        let grant = crate::grant_profile::SavedGrantCatalog::from_yaml(
            "grants:\n  - name: deploy\n    activated_verbs: [deploy-host]\n    ttl_secs: 300\n",
        )
        .expect("catalog")
        .get("deploy")
        .expect("grant")
        .clone();
        store
            .save_saved_grant(grant.clone())
            .await
            .expect("save grant");
        let request = crate::grant_profile::GrantRequest::new(
            "session-token".to_string(),
            Some("deploy".to_string()),
            crate::grant_profile::GrantRequestDelta {
                ttl_secs: Some(120),
                ..Default::default()
            },
            "extend the bounded deployment".to_string(),
        )
        .expect("request");
        store
            .save_grant_request(request.clone())
            .await
            .expect("save request");

        let saved = store.load_saved_grants().await.unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].name, grant.name);
        assert_eq!(saved[0].revision, grant.revision);
        assert_eq!(store.load_grant_requests().await.unwrap(), vec![request]);
    }

    #[tokio::test]
    async fn grant_request_storage_and_migration_redact_command_credentials() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("state.db");
        let store = SessionStore::open(path.clone(), 3600).await.unwrap();
        let mut request = GrantRequest::new(
            "fixture-session".to_string(),
            None,
            crate::grant_profile::GrantRequestDelta {
                prompt_append: Some(format!(
                    "inspect with Authorization: Bearer {}",
                    fixture_bearer_jwt()
                )),
                ..Default::default()
            },
            format!(
                "curl -H 'Authorization: Bearer {}' /status",
                fixture_bearer_jwt()
            ),
        )
        .unwrap();
        store.save_grant_request(request.clone()).await.unwrap();

        let conn = Connection::open(&path).unwrap();
        let stored: String = conn
            .query_row(
                "SELECT json FROM grant_requests WHERE handle = ?1",
                params![request.handle],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!stored.contains(&fixture_bearer_jwt()));
        assert!(stored.contains("[REDACTED]"));

        request.justification = format!("tool {}", FIXTURE_PASSWORD_FLAG);
        request.delta.prompt_append = Some(format!("legacy {}", FIXTURE_PASSWORD_FLAG));
        let legacy_json = serde_json::to_string(&request).unwrap();
        conn.execute(
            "UPDATE grant_requests SET json = ?1 WHERE handle = ?2",
            params![legacy_json, request.handle],
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 8).unwrap();
        drop(conn);

        let migrated = SessionStore::open(path.clone(), 3600).await.unwrap();
        let migrated_json =
            serde_json::to_string(&migrated.load_grant_requests().await.unwrap()).unwrap();
        assert!(!migrated_json.contains(FIXTURE_PASSWORD_FLAG));
        assert!(migrated_json.contains("[REDACTED]"));
        let migrated_stored: String = Connection::open(path)
            .unwrap()
            .query_row("SELECT json FROM grant_requests", [], |row| row.get(0))
            .unwrap();
        assert!(!migrated_stored.contains(FIXTURE_PASSWORD_FLAG));
    }

    #[tokio::test]
    async fn saved_grant_tombstone_survives_restart_and_save_restores_name() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("state.db");
        let store = SessionStore::open(path.clone(), 3600).await.unwrap();
        store
            .delete_saved_grant("file-only".to_string())
            .await
            .unwrap();

        let restarted = SessionStore::open(path.clone(), 3600).await.unwrap();
        let mut catalog = crate::grant_profile::SavedGrantCatalog::from_yaml(
            "grants:\n  - name: file-only\n    prompt_append: file definition\n",
        )
        .unwrap();
        catalog
            .overlay_rows(restarted.load_saved_grants().await.unwrap())
            .unwrap();
        catalog.apply_tombstones(&restarted.load_saved_grant_tombstones().await.unwrap());
        assert!(catalog.get("file-only").is_none());

        let restored = crate::grant_profile::SavedGrantCatalog::from_yaml(
            "grants:\n  - name: file-only\n    prompt_append: explicit restore\n",
        )
        .unwrap()
        .get("file-only")
        .unwrap()
        .clone();
        restarted.save_saved_grant(restored).await.unwrap();
        let restored_store = SessionStore::open(path, 3600).await.unwrap();
        assert!(restored_store
            .load_saved_grant_tombstones()
            .await
            .unwrap()
            .is_empty());
        assert_eq!(restored_store.load_saved_grants().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn approval_transaction_rolls_back_request_and_session_before_commit() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("state.db");
        let store = SessionStore::open(path.clone(), 3600).await.unwrap();
        let token = "atomic-approval".to_string();
        let mut registry = SessionRegistry::new();
        registry.grant(
            token.clone(),
            SessionGrant {
                allow: Vec::new(),
                deny: Vec::new(),
                allow_exact: Vec::new(),
                deny_exact: Vec::new(),
                activated_verbs: Vec::new(),
                override_markers: Vec::new(),
                scope: Default::default(),
                expires_at: None,
                prompt_append: None,
                generated_notes: Vec::new(),
                granted_at: 0,
                static_only: false,
                auto_amend: false,
                owner: SessionOwner::Principal(guard::principal::PrincipalKey::from_uid(1000)),
            },
        );
        store.persist_registry(&registry).await.unwrap();
        let mut pending = GrantRequest::new(
            token.clone(),
            None,
            crate::grant_profile::GrantRequestDelta {
                activated_verbs: vec!["inspect".to_string()],
                ..Default::default()
            },
            "inspect".to_string(),
        )
        .unwrap();
        pending.issued_session_revision = registry.effective_revision_key(&token);
        store.save_grant_request(pending.clone()).await.unwrap();
        let mut approved = pending.clone();
        approved.status = crate::grant_profile::GrantRequestStatus::Approved;
        approved.decided_unix = Some(guard::env::now_unix());
        let mut staged = registry.clone();
        staged.apply_delta(&token, &pending.delta).unwrap();
        let expected_generation = store.registry_write_gate.lock().await.database_generation;

        let error = SessionStore::commit_grant_request_approval_sync(
            &path,
            3600,
            &pending,
            &approved,
            &staged,
            &[],
            RegistryCommitOptions {
                fail_before_commit: true,
                expected_generation,
            },
        )
        .expect_err("simulated crash must roll back");
        assert!(error.to_string().contains("simulated crash"));
        let after_crash = SessionStore::open(path.clone(), 3600).await.unwrap();
        assert!(after_crash
            .load_registry()
            .await
            .unwrap()
            .verb_scope_for(&token)
            .unwrap()
            .0
            .is_empty());
        assert_eq!(
            after_crash.load_grant_requests().await.unwrap()[0].status,
            crate::grant_profile::GrantRequestStatus::Pending
        );

        after_crash
            .commit_grant_request_approval(pending, approved, staged, Vec::new())
            .await
            .unwrap();
        let committed = SessionStore::open(path, 3600).await.unwrap();
        let committed_requests = committed.load_grant_requests().await.unwrap();
        let committed_request = &committed_requests[0];
        assert_eq!(
            committed_request.status,
            crate::grant_profile::GrantRequestStatus::Approved
        );
        assert_eq!(committed_request.requested_uses, None);
        assert_eq!(
            committed
                .load_registry()
                .await
                .unwrap()
                .verb_scope_for(&token)
                .unwrap()
                .0,
            vec!["inspect"]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn aborted_registry_writers_retain_coordination_until_live_adoption() {
        let tmp = tempfile::tempdir().expect("tempdir");

        let persist_path = tmp.path().join("persist.db");
        let persist_store = SessionStore::open(persist_path.clone(), 3600)
            .await
            .unwrap();
        let mut first_registry = SessionRegistry::new();
        assert!(first_registry.grant("first".to_string(), exact_rule_grant(Vec::new())));
        let mut second_registry = first_registry.clone();
        assert!(second_registry.grant("second".to_string(), exact_rule_grant(Vec::new())));
        let (committed, release) =
            persist_store.pause_registry_commit_for_test("session store persist");
        let detached_store = persist_store.clone();
        let detached_snapshot = first_registry.clone();
        let detached =
            tokio::spawn(async move { detached_store.persist_registry(&detached_snapshot).await });
        committed.acquire().await.unwrap().forget();
        detached.abort();
        let attempted =
            persist_store.observe_registry_write_attempt_for_test("session store persist");
        let successor_store = persist_store.clone();
        let successor =
            tokio::spawn(async move { successor_store.persist_registry(&second_registry).await });
        attempted.acquire().await.unwrap().forget();
        assert!(persist_store.registry_write_gate.try_lock().is_err());
        release.add_permits(1);
        successor.await.unwrap().unwrap();
        let loaded = SessionStore::open(persist_path, 3600)
            .await
            .unwrap()
            .load_registry()
            .await
            .unwrap();
        assert!(loaded.has("first"));
        assert!(loaded.has("second"));

        let approval_path = tmp.path().join("approval.db");
        let approval_store = SessionStore::open(approval_path.clone(), 3600)
            .await
            .unwrap();
        let token = "approval-session".to_string();
        let mut approval_registry = SessionRegistry::new();
        assert!(approval_registry.grant(token.clone(), exact_rule_grant(Vec::new())));
        approval_store
            .persist_registry(&approval_registry)
            .await
            .unwrap();
        let mut pending = GrantRequest::new(
            token.clone(),
            None,
            crate::grant_profile::GrantRequestDelta {
                activated_verbs: vec!["inspect".to_string()],
                ..Default::default()
            },
            "inspect".to_string(),
        )
        .unwrap();
        pending.issued_session_revision = approval_registry.effective_revision_key(&token);
        approval_store
            .save_grant_request(pending.clone())
            .await
            .unwrap();
        let mut approved = pending.clone();
        approved.status = crate::grant_profile::GrantRequestStatus::Approved;
        approved.decided_unix = Some(guard::env::now_unix());
        let mut approved_registry = approval_registry.clone();
        approved_registry
            .apply_delta(&token, &pending.delta)
            .unwrap();
        let (committed, release) =
            approval_store.pause_registry_commit_for_test("grant request approval transaction");
        let detached_store = approval_store.clone();
        let detached_pending = pending.clone();
        let detached_approved = approved.clone();
        let detached_registry = approved_registry.clone();
        let detached = tokio::spawn(async move {
            detached_store
                .commit_grant_request_approval(
                    detached_pending,
                    detached_approved,
                    detached_registry,
                    Vec::new(),
                )
                .await
        });
        committed.acquire().await.unwrap().forget();
        detached.abort();
        let attempted =
            approval_store.observe_registry_write_attempt_for_test("session store persist");
        let successor_store = approval_store.clone();
        let successor_snapshot = approved_registry.clone();
        let successor =
            tokio::spawn(
                async move { successor_store.persist_registry(&successor_snapshot).await },
            );
        attempted.acquire().await.unwrap().forget();
        assert!(approval_store.registry_write_gate.try_lock().is_err());
        release.add_permits(1);
        successor.await.unwrap().unwrap();
        let reopened = SessionStore::open(approval_path, 3600).await.unwrap();
        assert_eq!(
            reopened.load_grant_requests().await.unwrap()[0].status,
            crate::grant_profile::GrantRequestStatus::Approved
        );
        assert_eq!(
            reopened
                .load_registry()
                .await
                .unwrap()
                .verb_scope_for(&token)
                .unwrap()
                .0,
            vec!["inspect"]
        );

        let revoke_path = tmp.path().join("revoke.db");
        let revoke_store = SessionStore::open(revoke_path.clone(), 3600).await.unwrap();
        let token = "revoked-session".to_string();
        let mut live_registry = SessionRegistry::new();
        assert!(live_registry.grant(token.clone(), exact_rule_grant(Vec::new())));
        revoke_store.persist_registry(&live_registry).await.unwrap();
        let expected_revision = live_registry.effective_revision_key(&token);
        let mut revoked_registry = live_registry.clone();
        assert!(revoked_registry.revoke(&token));
        let (committed, release) =
            revoke_store.pause_registry_commit_for_test("access revoke transaction");
        let detached_store = revoke_store.clone();
        let detached_token = token.clone();
        let detached_registry = revoked_registry.clone();
        let detached = tokio::spawn(async move {
            detached_store
                .commit_access_revoke(
                    detached_token,
                    expected_revision,
                    detached_registry,
                    Vec::new(),
                )
                .await
        });
        committed.acquire().await.unwrap().forget();
        detached.abort();
        let attempted =
            revoke_store.observe_registry_write_attempt_for_test("session store persist");
        let successor_store = revoke_store.clone();
        let successor_snapshot = revoked_registry.clone();
        let successor =
            tokio::spawn(
                async move { successor_store.persist_registry(&successor_snapshot).await },
            );
        attempted.acquire().await.unwrap().forget();
        assert!(revoke_store.registry_write_gate.try_lock().is_err());
        release.add_permits(1);
        successor.await.unwrap().unwrap();
        assert!(!SessionStore::open(revoke_path, 3600)
            .await
            .unwrap()
            .load_registry()
            .await
            .unwrap()
            .has(&token));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn aborted_registry_load_retains_coordination_through_generation_adoption() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("load-cancellation.db");
        let stale_store = SessionStore::open(path.clone(), 3600).await.unwrap();
        let mut initial = SessionRegistry::new();
        assert!(initial.grant("initial".to_string(), exact_rule_grant(Vec::new())));
        stale_store.persist_registry(&initial).await.unwrap();

        let competing = SessionStore::open(path.clone(), 3600).await.unwrap();
        let mut advanced = competing.load_registry().await.unwrap();
        assert!(advanced.grant("advanced".to_string(), exact_rule_grant(Vec::new())));
        competing.persist_registry_strict(&advanced).await.unwrap();
        let mut successor_snapshot = advanced.clone();
        assert!(successor_snapshot.grant("successor".to_string(), exact_rule_grant(Vec::new())));

        let (loaded, release) = stale_store.pause_registry_commit_for_test("session store load");
        let detached_store = stale_store.clone();
        let detached = tokio::spawn(async move { detached_store.load_registry().await });
        loaded.acquire().await.unwrap().forget();
        detached.abort();

        let attempted =
            stale_store.observe_registry_write_attempt_for_test("session store persist");
        let successor_store = stale_store.clone();
        let successor = tokio::spawn(async move {
            successor_store
                .persist_registry_strict(&successor_snapshot)
                .await
        });
        attempted.acquire().await.unwrap().forget();
        assert!(stale_store.registry_write_gate.try_lock().is_err());
        release.add_permits(1);
        successor.await.unwrap().unwrap();

        let durable = SessionStore::open(path, 3600)
            .await
            .unwrap()
            .load_registry()
            .await
            .unwrap();
        assert!(durable.has("initial"));
        assert!(durable.has("advanced"));
        assert!(durable.has("successor"));
    }

    /// A stale snapshot (cloned before a later mutation) must never clobber a
    /// newer snapshot that already landed: the registry is persisted as a
    /// full-table rewrite, so out-of-order completion would silently roll the
    /// on-disk state back.
    #[tokio::test]
    async fn stale_snapshot_does_not_overwrite_newer_persisted_state() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = SessionStore::open(tmp.path().join("state.db"), 24 * 60 * 60)
            .await
            .expect("open store");

        let grant = SessionGrant {
            allow: vec!["echo*".into()],
            deny: Vec::new(),
            allow_exact: Vec::new(),
            deny_exact: Vec::new(),
            activated_verbs: Vec::new(),
            override_markers: Vec::new(),
            scope: Default::default(),
            expires_at: None,
            prompt_append: None,
            generated_notes: Vec::new(),
            granted_at: 0,
            static_only: false,
            auto_amend: false,
            owner: SessionOwner::Principal(guard::principal::PrincipalKey::from_uid(1000)),
        };

        let mut registry = SessionRegistry::new();
        registry.grant("first".to_string(), grant.clone());
        let stale = registry.clone();
        registry.grant("second".to_string(), grant);
        let fresh = registry.clone();
        assert!(fresh.revision() > stale.revision());

        // The newer snapshot lands first; the stale one arrives late (the
        // out-of-order completion this guards against) and must be dropped.
        store.persist_registry(&fresh).await.expect("persist fresh");
        store.persist_registry(&stale).await.expect("persist stale");

        let loaded = store.load_registry().await.expect("load registry");
        assert!(loaded.has("first"));
        assert!(
            loaded.has("second"),
            "the stale snapshot must not roll back the newer grant"
        );
    }

    #[test]
    fn registry_load_rebases_sensitive_allow_and_additive_access_mutations() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("state.db");
        let (_, initial_generation) = SessionStore::load_registry_sync(&path, 3600).unwrap();
        let legacy_token = "legacy-access-policy-only".to_string();
        let explicit_token = "explicit-access-policy-only".to_string();
        let access_grant = |evaluation_mode| SessionGrant {
            allow: Vec::new(),
            deny: Vec::new(),
            allow_exact: Vec::new(),
            deny_exact: Vec::new(),
            activated_verbs: vec!["host-inspect".to_string()],
            override_markers: Vec::new(),
            scope: IssuedGrantScope {
                access_managed: true,
                evaluation_mode,
                ..IssuedGrantScope::default()
            },
            expires_at: None,
            prompt_append: None,
            generated_notes: Vec::new(),
            granted_at: 1,
            static_only: true,
            auto_amend: false,
            owner: SessionOwner::Principal(guard::principal::PrincipalKey::from_uid(1001)),
        };
        let sensitive_exact = SessionExactRule::new(
            "curl",
            vec![
                "--user".to_string(),
                "SyntheticUser:SyntheticPassphrase123".to_string(),
            ],
        );
        assert!(guard::redact::command_contains_sensitive_literals(
            &sensitive_exact.binary,
            &sensitive_exact.args,
        ));
        let mut legacy_grant = access_grant(EvaluationMode::Evaluator);
        legacy_grant.allow_exact.push(sensitive_exact.clone());
        let old_revision = session_grant_revision_key(&legacy_grant).unwrap();
        let mut persisted_legacy_grant = legacy_grant;
        persisted_legacy_grant.allow_exact.clear();
        let mut registry = SessionRegistry::new();
        registry.grant(legacy_token.clone(), persisted_legacy_grant);
        registry.grant(
            explicit_token.clone(),
            access_grant(EvaluationMode::PolicyOnly),
        );
        let seeded_generation =
            SessionStore::persist_registry_sync(&path, 3600, &registry, initial_generation)
                .unwrap();
        let mut request = generated_access_request();
        request.session_token = legacy_token.clone();
        request.issued_session_revision = Some(old_revision.clone());
        request.request_key = request.canonical_access_key().unwrap();
        let mut approval = pending_approval("legacy-access-hold");
        approval.snapshot.session_fingerprint =
            Some(access_session_token_fingerprint(&legacy_token));
        approval.snapshot.session_revision = Some(old_revision);
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE session_grants SET allow_exact_json = ?1 WHERE token = ?2",
            params![encode_exact_vec(&[sensitive_exact]).unwrap(), legacy_token],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO grant_requests (handle, json, status, created_unix) VALUES (?1, ?2, ?3, ?4)",
            params![
                request.handle,
                serde_json::to_string(&request).unwrap(),
                request.status.as_str(),
                encode_u64(request.created_unix).unwrap()
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO gating_approval (handle, json, status, created_unix) VALUES (?1, ?2, ?3, ?4)",
            params![
                approval.handle,
                serde_json::to_string(&approval).unwrap(),
                approval.status.as_str(),
                encode_u64(approval.created_unix).unwrap()
            ],
        )
        .unwrap();
        drop(conn);

        let (loaded, normalized_generation) =
            SessionStore::load_registry_sync(&path, 3600).unwrap();
        assert!(!loaded.static_only_for(&legacy_token));
        assert!(loaded.static_only_for(&explicit_token));
        assert_eq!(
            normalized_generation,
            seeded_generation + 2,
            "sensitive-rule sanitation and additive access normalization each advance authority"
        );
        let new_revision = loaded.effective_revision_key(&legacy_token).unwrap();
        let conn = Connection::open(&path).unwrap();
        let normalized: i64 = conn
            .query_row(
                "SELECT static_only FROM session_grants WHERE token = ?1",
                params![legacy_token],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(normalized, 0);
        let rebased_request: GrantRequest = serde_json::from_str(
            &conn
                .query_row(
                    "SELECT json FROM grant_requests WHERE handle = ?1",
                    params![request.handle],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            rebased_request.issued_session_revision.as_deref(),
            Some(new_revision.as_str())
        );
        assert_eq!(
            rebased_request.request_key,
            rebased_request.canonical_access_key().unwrap()
        );
        let rebased_approval: Approval = serde_json::from_str(
            &conn
                .query_row(
                    "SELECT json FROM gating_approval WHERE handle = ?1",
                    params![approval.handle],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            rebased_approval.snapshot.session_revision.as_deref(),
            Some(new_revision.as_str())
        );
        drop(conn);

        let (_, idempotent_generation) = SessionStore::load_registry_sync(&path, 3600).unwrap();
        assert_eq!(idempotent_generation, normalized_generation);
    }

    #[test]
    fn registry_load_keeps_grants_and_generation_in_one_sqlite_snapshot() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("state.db");
        let (_, initial_generation) = SessionStore::load_registry_sync(&path, 3600).unwrap();
        assert_eq!(initial_generation, 0);
        let conn = Connection::open(&path).unwrap();
        conn.pragma_update(None, "journal_mode", "WAL").unwrap();
        drop(conn);

        let token = "snapshot-race".to_string();
        let mut before = SessionRegistry::new();
        before.grant(
            token.clone(),
            SessionGrant {
                allow: Vec::new(),
                deny: Vec::new(),
                allow_exact: Vec::new(),
                deny_exact: Vec::new(),
                activated_verbs: vec!["host-inspect".to_string()],
                override_markers: Vec::new(),
                scope: IssuedGrantScope {
                    access_managed: true,
                    ..IssuedGrantScope::default()
                },
                expires_at: None,
                prompt_append: None,
                generated_notes: Vec::new(),
                granted_at: 1,
                static_only: false,
                auto_amend: false,
                owner: SessionOwner::Principal(guard::principal::PrincipalKey::from_uid(1001)),
            },
        );
        before.install_access_grant(
            &token,
            Some(1),
            "access-final-use".to_string(),
            vec!["host-inspect".to_string()],
        );
        let seeded_generation =
            SessionStore::persist_registry_sync(&path, 3600, &before, initial_generation).unwrap();
        assert_eq!(seeded_generation, 1);

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let reader_barrier = barrier.clone();
        let reader_path = path.clone();
        let reader = std::thread::spawn(move || {
            SessionStore::load_registry_sync_with_hook(&reader_path, 3600, || {
                reader_barrier.wait();
                reader_barrier.wait();
            })
        });
        barrier.wait();

        let mut after = before.clone();
        after
            .consume_access_use(&token, &["host-inspect".to_string()], None)
            .unwrap();
        let advanced_generation =
            SessionStore::persist_registry_sync(&path, 3600, &after, seeded_generation);
        barrier.wait();
        let (loaded, loaded_generation) = reader.join().unwrap().unwrap();
        assert_eq!(advanced_generation.unwrap(), 2);
        assert_eq!(loaded_generation, seeded_generation);
        assert_eq!(
            loaded.access_grant_uses(&token, "access-final-use"),
            Some((Some(1), Some(1)))
        );
        let stale_write =
            SessionStore::persist_registry_sync(&path, 3600, &loaded, loaded_generation)
                .unwrap_err();
        assert!(SessionStore::is_registry_generation_conflict(&stale_write));
    }

    #[tokio::test]
    async fn first_daemon_lease_creates_lock_file_and_excludes_a_second_owner() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("state.db");
        let first = SessionStore::open(path.clone(), 3600).await.unwrap();
        let second = SessionStore::open(path.clone(), 3600).await.unwrap();
        let mut lock_name = path.as_os_str().to_os_string();
        lock_name.push(".daemon.lock");
        let lock_path = PathBuf::from(lock_name);
        if lock_path.exists() {
            std::fs::remove_file(&lock_path).unwrap();
        }

        let lease = first.acquire_daemon_lease().await.unwrap();
        assert!(lock_path.is_file());
        let error = second.acquire_daemon_lease().await.unwrap_err();
        assert!(error.to_string().contains("already has an active daemon"));
        drop(lease);
        second.acquire_daemon_lease().await.unwrap();
    }

    #[tokio::test]
    async fn rejected_daemon_open_cannot_repair_or_migrate_a_live_database() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("state.db");
        let seed = SessionStore::open(path.clone(), 3600).await.unwrap();
        drop(seed);

        let first = SessionStore::open_for_daemon(path.clone(), 3600)
            .await
            .unwrap();
        assert!(first.has_daemon_lease());

        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "DELETE FROM state_metadata WHERE key = ?1",
            params![REGISTRY_GENERATION_KEY],
        )
        .unwrap();
        drop(conn);

        let error = SessionStore::open_for_daemon(path.clone(), 3600)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("already has an active daemon"));

        let conn = Connection::open(path).unwrap();
        let metadata_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM state_metadata WHERE key = ?1",
                params![REGISTRY_GENERATION_KEY],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            metadata_rows, 0,
            "rejected startup mutated the live database"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn daemon_open_rejects_hard_linked_database_aliases() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("state.db");
        let alias = tmp.path().join("state-alias.db");
        let seed = SessionStore::open(path.clone(), 3600).await.unwrap();
        drop(seed);
        std::fs::hard_link(&path, &alias).unwrap();

        for candidate in [path, alias] {
            let error = SessionStore::open_for_daemon(candidate, 3600)
                .await
                .unwrap_err();
            assert!(error.to_string().contains("hard links"), "{error:#}");
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn daemon_open_rejects_file_and_directory_reparse_aliases() {
        use std::os::windows::fs::{symlink_dir, symlink_file};

        let tmp = tempfile::tempdir().expect("tempdir");
        let target_dir = tmp.path().join("target");
        std::fs::create_dir(&target_dir).unwrap();
        let path = target_dir.join("state.db");
        let seed = SessionStore::open(path.clone(), 3600).await.unwrap();
        drop(seed);

        let file_alias = tmp.path().join("state-alias.db");
        symlink_file(&path, &file_alias).unwrap();
        let file_error = SessionStore::open_for_daemon(file_alias, 3600)
            .await
            .unwrap_err();
        assert!(file_error.to_string().contains("reparse point"));

        let directory_alias = tmp.path().join("target-alias");
        symlink_dir(&target_dir, &directory_alias).unwrap();
        let directory_error = SessionStore::open_for_daemon(directory_alias.join("state.db"), 3600)
            .await
            .unwrap_err();
        assert!(directory_error.to_string().contains("reparse point"));

        let lock_target = target_dir.join("lock-target");
        std::fs::write(&lock_target, b"fixture").unwrap();
        let mut lock_name = path.as_os_str().to_os_string();
        lock_name.push(".daemon.lock");
        symlink_file(lock_target, PathBuf::from(lock_name)).unwrap();
        let lease_error = SessionStore::open_for_daemon(path, 3600).await.unwrap_err();
        assert!(lease_error.to_string().contains("reparse point"));
    }

    #[tokio::test]
    async fn second_daemon_cannot_reclassify_a_live_reverting_claim() {
        use std::collections::BTreeMap;

        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("state.db");
        let first = SessionStore::open(path.clone(), 3600).await.unwrap();
        let second = SessionStore::open(path, 3600).await.unwrap();
        let reverting = Provisional {
            handle: "live-revert".to_string(),
            principal: Some(guard::principal::PrincipalKey::from_uid(1001)),
            requester_principal: None,
            binary: "fixture-forward".to_string(),
            args: Vec::new(),
            cwd: None,
            secret_keys: BTreeMap::new(),
            secret_file_keys: BTreeMap::new(),
            revert_binary: "fixture-revert".to_string(),
            revert_args: Vec::new(),
            confirm_check_binary: None,
            confirm_check_args: Vec::new(),
            control_path: Some("fixture".to_string()),
            session_fingerprint: None,
            session_revision: None,
            secret_entitlements: None,
            api_revert: None,
            reason: "bounded change".to_string(),
            decision_trace: None,
            created_unix: 1,
            deadline_unix: u64::MAX,
            window_secs: 0,
            auto_reverted_unix: None,
            forward_done: true,
            forward_exit: Some(0),
            forward_persistence_failed: false,
            status: ProvisionalStatus::Reverting,
            revert_exit: None,
            revert_detail: None,
        };
        let mut armed = reverting.clone();
        armed.status = ProvisionalStatus::Armed;
        first.save_provisional(armed.clone()).await.unwrap();
        first
            .compare_and_swap_provisional(armed, reverting)
            .await
            .unwrap();
        let _lease = first.acquire_daemon_lease().await.unwrap();

        assert!(second.acquire_daemon_lease().await.is_err());
        let durable = second.load_provisionals().await.unwrap();
        assert_eq!(durable[0].status, ProvisionalStatus::Reverting);
    }

    #[tokio::test]
    async fn independent_stores_cannot_both_consume_the_final_access_use() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("state.db");
        let seed = SessionStore::open(path.clone(), 3600).await.unwrap();
        let token = "bounded-access".to_string();
        let mut registry = SessionRegistry::new();
        registry.grant(
            token.clone(),
            SessionGrant {
                allow: Vec::new(),
                deny: Vec::new(),
                allow_exact: Vec::new(),
                deny_exact: Vec::new(),
                activated_verbs: vec!["host-inspect".to_string()],
                override_markers: Vec::new(),
                scope: IssuedGrantScope {
                    access_managed: true,
                    ..IssuedGrantScope::default()
                },
                expires_at: None,
                prompt_append: None,
                generated_notes: Vec::new(),
                granted_at: 1,
                static_only: false,
                auto_amend: false,
                owner: SessionOwner::Principal(guard::principal::PrincipalKey::from_uid(1001)),
            },
        );
        registry.install_access_grant(
            &token,
            Some(1),
            "access-final-use".to_string(),
            vec!["host-inspect".to_string()],
        );
        registry.install_access_grant(
            &token,
            Some(1),
            "access-later-use".to_string(),
            vec!["host-maintain".to_string()],
        );
        seed.persist_registry(&registry).await.unwrap();

        let first = SessionStore::open(path.clone(), 3600).await.unwrap();
        let second = SessionStore::open(path.clone(), 3600).await.unwrap();
        let mut first_snapshot = first.load_registry().await.unwrap();
        let mut second_snapshot = second.load_registry().await.unwrap();
        first_snapshot
            .consume_access_use(&token, &["host-inspect".to_string()], None)
            .unwrap();
        second_snapshot
            .consume_access_use(&token, &["host-inspect".to_string()], None)
            .unwrap();

        let (first_result, second_result) = tokio::join!(
            first.persist_registry(&first_snapshot),
            second.persist_registry(&second_snapshot)
        );
        assert_ne!(first_result.is_ok(), second_result.is_ok());
        let stale_store = if first_result.is_err() {
            &first
        } else {
            &second
        };
        let stale_snapshot = if first_result.is_err() {
            &first_snapshot
        } else {
            &second_snapshot
        };
        let stale_retry = stale_store.persist_registry(stale_snapshot).await;
        assert!(
            stale_retry.is_err(),
            "a stale store must reload before writing"
        );
        assert!(SessionStore::is_registry_generation_conflict(
            &stale_retry.unwrap_err()
        ));

        let mut refreshed = stale_store.load_registry().await.unwrap();
        assert!(refreshed
            .consume_access_use(&token, &["host-inspect".to_string()], None)
            .is_err());
        refreshed
            .consume_access_use(&token, &["host-maintain".to_string()], None)
            .unwrap();
        stale_store.persist_registry(&refreshed).await.unwrap();

        let verifier = SessionStore::open(path, 3600).await.unwrap();
        let mut durable = verifier.load_registry().await.unwrap();
        assert_eq!(
            durable.access_grant_uses(&token, "access-final-use"),
            Some((Some(1), Some(0)))
        );
        assert_eq!(
            durable.access_grant_uses(&token, "access-later-use"),
            Some((Some(1), Some(0)))
        );
        assert!(durable
            .consume_access_use(&token, &["host-inspect".to_string()], None)
            .is_err());
    }

    #[tokio::test]
    async fn unrelated_interaction_generation_conflict_does_not_stale_lock_admission() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("state.db");
        let seed = SessionStore::open(path.clone(), 3600).await.unwrap();
        let token = "interaction-race".to_string();
        let mut registry = SessionRegistry::new();
        registry.grant(
            token.clone(),
            SessionGrant {
                allow: Vec::new(),
                deny: Vec::new(),
                allow_exact: Vec::new(),
                deny_exact: Vec::new(),
                activated_verbs: vec!["host-inspect".to_string()],
                override_markers: Vec::new(),
                scope: IssuedGrantScope {
                    access_managed: true,
                    ..IssuedGrantScope::default()
                },
                expires_at: None,
                prompt_append: None,
                generated_notes: Vec::new(),
                granted_at: 1,
                static_only: false,
                auto_amend: false,
                owner: SessionOwner::Principal(guard::principal::PrincipalKey::from_uid(1001)),
            },
        );
        registry.install_access_grant(
            &token,
            Some(1),
            "access-after-interaction".to_string(),
            vec!["host-inspect".to_string()],
        );
        seed.persist_registry(&registry).await.unwrap();

        let admission_store = SessionStore::open(path.clone(), 3600).await.unwrap();
        let interaction_store = SessionStore::open(path.clone(), 3600).await.unwrap();
        let mut stale_admission = admission_store.load_registry().await.unwrap();
        let mut interaction = interaction_store.load_registry().await.unwrap();
        interaction.record_interaction(
            &token,
            SessionInteraction {
                at_unix: guard::env::now_unix(),
                command: "host-inspect".to_string(),
                allowed: true,
                source: SessionDecisionSource::StaticPolicy,
                reason: "fixture interaction".to_string(),
                risk: Some(0),
                exec_status: SessionExecStatus::Completed,
                exit_code: Some(0),
                credential_references: Vec::new(),
                decision_trace: None,
            },
        );
        interaction_store
            .persist_registry(&interaction)
            .await
            .unwrap();

        stale_admission
            .consume_access_use(&token, &["host-inspect".to_string()], None)
            .unwrap();
        let conflict = admission_store
            .persist_registry(&stale_admission)
            .await
            .unwrap_err();
        assert!(SessionStore::is_registry_generation_conflict(&conflict));

        let mut refreshed = admission_store.load_registry().await.unwrap();
        refreshed
            .consume_access_use(&token, &["host-inspect".to_string()], None)
            .unwrap();
        admission_store.persist_registry(&refreshed).await.unwrap();

        let loaded = SessionStore::open(path, 3600)
            .await
            .unwrap()
            .load_registry()
            .await
            .unwrap();
        assert_eq!(
            loaded.access_grant_uses(&token, "access-after-interaction"),
            Some((Some(1), Some(0)))
        );
        assert_eq!(loaded.show(&token, 10).unwrap().stats.total, 1);
    }

    // Synthetic test-fixture credential shapes (never real secrets).
    fn fixture_bearer_jwt() -> String {
        [
            "eyJhbGciOiJSUzI1NiJ9",
            "eyJzdWIiOiJndWFyZC10ZXN0LWZpeHR1cmUifQ",
            "c3ludGhldGljLXNpZ25hdHVyZS1ub3QtYS1jcmVkZW50aWFs",
        ]
        .join(".")
    }
    const FIXTURE_PASSWORD_FLAG: &str = "--password=SyntheticHunter2Value";

    #[test]
    fn credential_reference_decoder_discards_noncanonical_legacy_entries() {
        let decoded = decode_credential_references(
            r#"["service/token","../invalid","api-endpoint:prod:upstream"]"#,
        )
        .expect("decode credential references");
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].as_reference_name(), "service/token");
        assert_eq!(decoded[1].as_reference_name(), "api-endpoint:prod:upstream");
    }

    #[tokio::test]
    async fn v5_migration_sanitizes_persisted_credentials_and_bumps_version() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("state.db");
        {
            // Seed a database exactly one schema version back, holding
            // credential material the way a pre-v6 daemon persisted it.
            let store = SessionStore::open(path.clone(), 24 * 60 * 60)
                .await
                .expect("open store");
            drop(store);
            let conn = Connection::open(&path).expect("reopen seeded db");
            conn.execute(
                "INSERT INTO session_grants
                 (token, allow_json, deny_json, allow_exact_json, deny_exact_json, scope_json, prompt_append, generated_notes_json, granted_at)
                 VALUES ('tok', '[]', '[]', ?1, '[]', '{}', ?2, ?3, 1)",
                params![
                    serde_json::to_string(&vec![SessionExactRule::new(
                        "kubectl",
                        vec![format!("--token={}", fixture_bearer_jwt()), "get".to_string()],
                    )])
                    .unwrap(),
                    format!("session context {FIXTURE_PASSWORD_FLAG}"),
                    serde_json::to_string(&vec![format!("note {FIXTURE_PASSWORD_FLAG}")]).unwrap(),
                ],
            )
            .expect("seed grant");
            conn.execute(
                "INSERT INTO session_interactions
                 (token, at_unix, command, allowed, source, reason, risk, exec_status)
                 VALUES ('tok', ?1, ?2, 1, 'llm', ?3, 1, 'completed')",
                params![
                    encode_u64(guard::env::now_unix()).unwrap(),
                    format!("kubectl --token={} get pods", fixture_bearer_jwt()),
                    format!("allowed with {FIXTURE_PASSWORD_FLAG}"),
                ],
            )
            .expect("seed interaction");
            conn.pragma_update(None, "user_version", SCHEMA_VERSION - 1)
                .expect("set previous schema version");
            drop(conn);
        }

        let store = SessionStore::open(path.clone(), 24 * 60 * 60)
            .await
            .expect("migrate store");
        drop(store);

        let conn = Connection::open(&path).expect("reopen migrated db");
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let (command, reason): (String, String) = conn
            .query_row(
                "SELECT command, reason FROM session_interactions WHERE token = 'tok'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(
            !command.contains("SyntheticSignature123"),
            "bearer token survived migration: {command}"
        );
        assert!(command.contains("[REDACTED]"), "marker missing: {command}");
        assert!(command.contains("kubectl"), "utility lost: {command}");
        assert!(!reason.contains("SyntheticHunter2Value"), "got: {reason}");
        assert!(reason.contains("[REDACTED]"), "got: {reason}");
        let (prompt, notes, allow_exact): (String, String, String) = conn
            .query_row(
                "SELECT prompt_append, generated_notes_json, allow_exact_json FROM session_grants WHERE token = 'tok'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert!(!prompt.contains("SyntheticHunter2Value"), "got: {prompt}");
        assert!(prompt.contains("[REDACTED]"), "got: {prompt}");
        assert!(!notes.contains("SyntheticHunter2Value"), "got: {notes}");
        assert!(
            !allow_exact.contains("SyntheticSignature123"),
            "exact rule survived migration: {allow_exact}"
        );
        let rules: Vec<SessionExactRule> = serde_json::from_str(&allow_exact).unwrap();
        assert!(rules.is_empty());
        drop(conn);

        // The migrated database still loads as a normal registry.
        let store = SessionStore::open(path, 24 * 60 * 60)
            .await
            .expect("reopen migrated store");
        let registry = store.load_registry().await.expect("load registry");
        let prompt = registry.prompt_append_for("tok").expect("prompt");
        assert!(!prompt.contains("SyntheticHunter2Value"));
    }

    #[tokio::test]
    async fn v6_migration_stamps_unowned_owner_and_bumps_to_current_schema() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("state.db");
        {
            // Seed a database as a pre-v7 daemon left it: the session tables have
            // no owner column, and a live session row carries no owner.
            let store = SessionStore::open(path.clone(), 24 * 60 * 60)
                .await
                .expect("open store");
            drop(store);
            let conn = Connection::open(&path).expect("reopen seeded db");
            conn.execute("ALTER TABLE session_grants DROP COLUMN owner_json", [])
                .expect("drop grant owner column");
            conn.execute("ALTER TABLE session_history DROP COLUMN owner_json", [])
                .expect("drop history owner column");
            conn.execute(
                "INSERT INTO session_grants (token, allow_json, deny_json, scope_json, granted_at)
                 VALUES ('legacy', '[\"true\"]', '[]', '{}', 1)",
                [],
            )
            .expect("seed ownerless session");
            conn.pragma_update(None, "user_version", 6)
                .expect("set previous schema version");
            drop(conn);
        }

        // Opening migrates schema 6 to the current schema, adding the owner
        // column with the Unowned sentinel default.
        let store = SessionStore::open(path.clone(), 24 * 60 * 60)
            .await
            .expect("migrate store");
        let registry = store.load_registry().await.expect("load registry");
        assert_eq!(
            registry.owner_for("legacy"),
            Some(SessionOwner::Unowned),
            "a session carried across the migration must be stamped Unowned, \
             which the execute path refuses fail-closed until reissue"
        );
        drop(store);

        let conn = Connection::open(&path).expect("reopen migrated db");
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[tokio::test]
    async fn migrates_legacy_schema_and_rejects_future_versions() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let legacy_path = tmp.path().join("legacy.db");
        let now = guard::env::now_unix();
        {
            let conn = Connection::open(&legacy_path).expect("open legacy db");
            conn.execute_batch(
                "CREATE TABLE session_interactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token TEXT NOT NULL,
                    at_unix INTEGER NOT NULL,
                    command TEXT NOT NULL,
                    allowed INTEGER NOT NULL,
                    source TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    risk INTEGER,
                    exec_status TEXT NOT NULL
                );",
            )
            .expect("create legacy schema");
            conn.execute(
                "INSERT INTO session_interactions
                 (token, at_unix, command, allowed, source, reason, risk, exec_status)
                 VALUES (?1, ?2, 'true', 1, 'static_policy', 'legacy', 0, 'completed')",
                params!["legacy-token", encode_u64(now).unwrap()],
            )
            .expect("insert legacy interaction");
        }

        let store = SessionStore::open(legacy_path.clone(), 3600)
            .await
            .expect("migrate legacy store");
        let registry = store.load_registry().await.expect("load migrated store");
        let report = registry.show("legacy-token", 10).expect("legacy report");
        assert_eq!(report.recent[0].exit_code, None);
        assert!(report.recent[0].credential_references.is_empty());
        let conn = Connection::open(&legacy_path).expect("reopen migrated db");
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        drop(conn);

        let future_path = tmp.path().join("future.db");
        let conn = Connection::open(&future_path).expect("open future db");
        conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
        drop(conn);
        let error = SessionStore::open(future_path, 3600)
            .await
            .expect_err("future schema must fail closed");
        assert!(error.to_string().contains("newer than supported"));
    }

    #[test]
    fn migrates_missing_columns_from_v1_schema() {
        let conn = Connection::open_in_memory().expect("open database");
        conn.execute_batch(
            "CREATE TABLE session_interactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT NOT NULL,
                at_unix INTEGER NOT NULL,
                command TEXT NOT NULL,
                allowed INTEGER NOT NULL,
                source TEXT NOT NULL,
                reason TEXT NOT NULL,
                risk INTEGER,
                exec_status TEXT NOT NULL
            );
            PRAGMA user_version = 1;",
        )
        .expect("create partial v1 schema");

        SessionStore::init_schema(&conn).expect("repair current schema");

        let mut stmt = conn
            .prepare("PRAGMA table_info(session_interactions)")
            .expect("prepare table info");
        let columns: Vec<String> = stmt
            .query_map([], |row| row.get(1))
            .expect("query columns")
            .collect::<rusqlite::Result<_>>()
            .expect("collect columns");
        assert!(columns.iter().any(|column| column == "exit_code"));
        assert!(columns.iter().any(|column| column == "secret_refs_json"));
    }

    #[test]
    fn vacuum_threshold_requires_absolute_and_relative_free_space() {
        assert!(!should_vacuum(511, 200));
        assert!(!should_vacuum(1024, 127));
        assert!(!should_vacuum(1024, 255));
        assert!(should_vacuum(1024, 256));
    }

    #[tokio::test]
    async fn compaction_reclaims_a_database_above_the_threshold() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("state.db");
        let store = SessionStore::open(path.clone(), 3600)
            .await
            .expect("open store");
        {
            let mut conn = Connection::open(&path).expect("open filler db");
            conn.execute("CREATE TABLE filler (body BLOB NOT NULL)", [])
                .unwrap();
            let tx = conn.transaction().unwrap();
            for _ in 0..700 {
                tx.execute("INSERT INTO filler VALUES (zeroblob(4096))", [])
                    .unwrap();
            }
            tx.commit().unwrap();
            conn.execute("DELETE FROM filler", []).unwrap();
        }
        let before = std::fs::metadata(&path).unwrap().len();
        assert!(store.compact_if_needed().await.unwrap());
        let after = std::fs::metadata(&path).unwrap().len();
        assert!(after < before, "before={before} after={after}");
    }

    #[tokio::test]
    async fn configured_retention_prunes_expired_interactions_on_persist() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("state.db");
        let store = SessionStore::open(path.clone(), 1)
            .await
            .expect("open store");
        let registry = SessionRegistry::from_parts(
            HashMap::new(),
            Vec::new(),
            vec![(
                "expired-token".into(),
                SessionInteraction {
                    at_unix: guard::env::now_unix().saturating_sub(60),
                    command: "true".into(),
                    allowed: true,
                    source: SessionDecisionSource::StaticPolicy,
                    reason: "test".into(),
                    risk: Some(0),
                    exec_status: SessionExecStatus::Completed,
                    exit_code: Some(0),
                    credential_references: Vec::new(),
                    decision_trace: None,
                },
            )],
            1,
        );
        store.persist_registry(&registry).await.expect("persist");
        let conn = Connection::open(path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM session_interactions", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn approval_claim_is_owned_by_exactly_one_store_instance() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state.db");
        let first = SessionStore::open(path.clone(), 3600).await.unwrap();
        let second = SessionStore::open(path, 3600).await.unwrap();
        let pending = Approval {
            handle: "ap-shared-claim".to_string(),
            snapshot: guard::gating::approval::ApprovalSnapshot {
                binary: "fixture-command".to_string(),
                args: Vec::new(),
                cwd: None,
                env: std::collections::BTreeMap::new(),
                secret_keys: std::collections::BTreeMap::new(),
                session_fingerprint: None,
                session_revision: None,
                secret_entitlements: None,
                secret_file_keys: std::collections::BTreeMap::new(),
                verb_name: None,
                verb_params: std::collections::BTreeMap::new(),
                catalog_version: None,
                verb_digest: None,
                verb_composition_digest: None,
                exec_timeout_secs: None,
                access_verbs: Vec::new(),
                access_requests: Vec::new(),
                principal: Some(guard::principal::PrincipalKey::from_uid(1001)),
                secret_binding: None,
            },
            reason: "fixture approval".to_string(),
            risk: Some(7),
            reversibility: Some(guard::gating::Reversibility::Irreversible),
            decision_trace: None,
            created_unix: 1,
            ttl_secs: u64::MAX,
            status: ApprovalStatus::Pending,
            decided_unix: None,
            decided_reason: None,
            result_exit: None,
            result_stdout: None,
            result_stderr: None,
            notes: Vec::new(),
        };
        first.save_approval(pending.clone()).await.unwrap();
        let mut pending = pending;
        pending.decision_trace = Some(guard::gating::DecisionTrace::source("static_policy"));
        first.save_approval(pending.clone()).await.unwrap();
        let mut approving = pending.clone();
        approving.status = ApprovalStatus::Approving;

        let (left, right) = tokio::join!(
            first.compare_and_swap_approval_claim(pending.clone(), approving.clone()),
            second.compare_and_swap_approval_claim(pending, approving)
        );
        assert_ne!(left.is_ok(), right.is_ok());
        let durable = first.load_approvals().await.unwrap();
        assert_eq!(durable.len(), 1);
        assert_eq!(durable[0].status, ApprovalStatus::Approving);
    }

    #[tokio::test]
    async fn stale_approval_save_cannot_restore_pending() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state.db");
        let store = SessionStore::open(path, 3600).await.unwrap();
        let pending = pending_approval("ap-no-restore");
        store.save_approval(pending.clone()).await.unwrap();
        let mut approving = pending.clone();
        approving.status = ApprovalStatus::Approving;
        store
            .compare_and_swap_approval(pending.clone(), approving.clone())
            .await
            .unwrap();

        assert!(store.save_approval(pending).await.is_err());
        assert_eq!(
            store.load_approvals().await.unwrap()[0].status,
            ApprovalStatus::Approving
        );

        let mut denied = approving.clone();
        denied.status = ApprovalStatus::Denied;
        denied.decided_unix = Some(2);
        denied.decided_reason = Some("late denial".to_string());
        assert!(store
            .compare_and_swap_approval(approving, denied)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn approval_store_rejects_plain_environment_values() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state.db");
        let store = SessionStore::open(path, 3600).await.unwrap();
        let mut approval = pending_approval("ap-plain-env");
        approval
            .snapshot
            .env
            .insert("FIXTURE_VALUE".to_string(), "synthetic-secret".to_string());

        assert!(store.save_approval(approval).await.is_err());
        assert!(store.load_approvals().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn approval_store_rejects_rendered_verb_parameter_values() {
        let tmp = tempfile::tempdir().unwrap();
        let store = SessionStore::open(tmp.path().join("state.db"), 3600)
            .await
            .unwrap();
        let mut approval = pending_approval("ap-verb-params");
        approval.snapshot.verb_name = Some("fixture-verb".to_string());
        approval
            .snapshot
            .verb_params
            .insert("rollback_only".to_string(), ["q", "7"].concat());

        assert!(store.save_approval(approval).await.is_err());
        assert!(store.load_approvals().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn current_schema_load_clears_rendered_verb_parameter_values() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state.db");
        let store = SessionStore::open(path.clone(), 3600).await.unwrap();
        let mut approval = pending_approval("ap-current-verb-params");
        approval
            .snapshot
            .verb_params
            .insert("fixture".to_string(), ["q", "7"].concat());
        let conn = Connection::open(path).unwrap();
        conn.execute(
            "INSERT INTO gating_approval (handle, json, status, created_unix)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                approval.handle,
                serde_json::to_string(&approval).unwrap(),
                approval.status.as_str(),
                encode_u64(approval.created_unix).unwrap()
            ],
        )
        .unwrap();
        drop(conn);

        let loaded = store.load_approvals().await.unwrap();
        assert!(loaded[0].snapshot.verb_params.is_empty());
    }

    #[tokio::test]
    async fn gate_store_rejects_literal_sensitive_snapshots() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state.db");
        let store = SessionStore::open(path, 3600).await.unwrap();
        let sensitive = ["q", "7"].concat();

        let mut approval = pending_approval("ap-sensitive-new");
        approval.snapshot.binary = "curl.EXE".to_string();
        approval.snapshot.args = vec![format!("-u{sensitive}")];
        assert!(store.save_approval(approval).await.is_err());
        assert!(store.load_approvals().await.unwrap().is_empty());

        let mut provisional = provisional_row("pv-sensitive-new", ProvisionalStatus::Armed);
        provisional.revert_binary = "docker.CMD".to_string();
        provisional.revert_args = vec!["login".to_string(), format!("-p={sensitive}")];
        assert!(store.save_provisional(provisional).await.is_err());
        assert!(store.load_provisionals().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn current_schema_terminalizes_registered_exact_literals_without_replayable_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.db");
        let store = SessionStore::open(path.clone(), 3600).await.unwrap();
        let value = ["µ", "!"].concat();
        let mut approval = pending_approval("ap-exact-current");
        approval.snapshot.args = vec![value.clone()];
        let mut provisional = provisional_row("pv-exact-current", ProvisionalStatus::Armed);
        provisional.revert_args = vec![value.clone()];
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO gating_approval (handle, json, status, created_unix)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                approval.handle,
                serde_json::to_string(&approval).unwrap(),
                approval.status.as_str(),
                encode_u64(approval.created_unix).unwrap()
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO gating_provisional (handle, json, status, created_unix)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                provisional.handle,
                serde_json::to_string(&provisional).unwrap(),
                provisional.status.as_str(),
                encode_u64(provisional.created_unix).unwrap()
            ],
        )
        .unwrap();
        drop(conn);
        let _scope =
            guard::redact::register_trusted_exact_secrets(std::slice::from_ref(&value)).unwrap();

        let approvals = store.load_approvals().await.unwrap();
        let provisionals = store.load_provisionals().await.unwrap();
        assert_eq!(approvals[0].status, ApprovalStatus::ExecFailed);
        assert_eq!(provisionals[0].status, ProvisionalStatus::RevertFailed);
        let conn = Connection::open(path).unwrap();
        for table in ["gating_approval", "gating_provisional"] {
            let json: String = conn
                .query_row(&format!("SELECT json FROM {table}"), [], |row| row.get(0))
                .unwrap();
            assert!(!json.contains(&value));
        }
    }

    #[tokio::test]
    async fn current_schema_scrubs_exact_literals_from_generated_request_metadata() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.db");
        let store = SessionStore::open(path.clone(), 3600).await.unwrap();
        let value = ["request", "-metadata-fixture"].concat();
        let mut request = generated_access_request();
        let mut verb: Verb = serde_json::from_value(request.proposed_verbs[0].clone()).unwrap();
        verb.evidence = Some(value.clone());
        request.proposed_verbs = vec![serde_json::to_value(verb).unwrap()];
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO grant_requests (handle, json, status, created_unix)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                request.handle,
                serde_json::to_string(&request).unwrap(),
                request.status.as_str(),
                encode_u64(request.created_unix).unwrap()
            ],
        )
        .unwrap();
        drop(conn);
        let _scope =
            guard::redact::register_trusted_exact_secrets(std::slice::from_ref(&value)).unwrap();

        let loaded = store.load_grant_requests().await.unwrap();
        assert_eq!(
            loaded[0].status,
            crate::grant_profile::GrantRequestStatus::Pending
        );
        assert!(loaded[0].has_access_projection());
        assert!(!serde_json::to_string(&loaded[0]).unwrap().contains(&value));
        let json: String = Connection::open(path)
            .unwrap()
            .query_row("SELECT json FROM grant_requests", [], |row| row.get(0))
            .unwrap();
        assert!(!json.contains(&value));
    }

    #[tokio::test]
    async fn current_schema_terminalizes_exact_literals_in_api_revert_metadata() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.db");
        let store = SessionStore::open(path.clone(), 3600).await.unwrap();
        let value = ["api", "-metadata-fixture"].concat();
        let mut provisional = provisional_row("pv-exact-api", ProvisionalStatus::Armed);
        provisional.api_revert = Some(ApiRevertPlan {
            endpoint: "fixture".to_string(),
            protocol: "kubernetes".to_string(),
            upstream_target: "https://fixture.invalid".to_string(),
            upstream_identity: "fixture-identity".to_string(),
            method: "DELETE".to_string(),
            path: "/api/v1/namespaces/dev/pods/example".to_string(),
            requires_uid_precondition: true,
            resource_uid: Some("fixture-uid".to_string()),
            create_provenance: Some(value.clone()),
            body_file: None,
        });
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO gating_provisional (handle, json, status, created_unix)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                provisional.handle,
                serde_json::to_string(&provisional).unwrap(),
                provisional.status.as_str(),
                encode_u64(provisional.created_unix).unwrap()
            ],
        )
        .unwrap();
        drop(conn);
        let _scope =
            guard::redact::register_trusted_exact_secrets(std::slice::from_ref(&value)).unwrap();

        let loaded = store.load_provisionals().await.unwrap();
        assert_eq!(loaded[0].status, ProvisionalStatus::RevertFailed);
        let json: String = Connection::open(path)
            .unwrap()
            .query_row("SELECT json FROM gating_provisional", [], |row| row.get(0))
            .unwrap();
        assert!(!json.contains(&value));
    }

    #[tokio::test]
    async fn gate_prose_is_sanitized_on_write_load_and_durable_repair() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.db");
        let store = SessionStore::open(path.clone(), 3600).await.unwrap();
        let value = ["q", "7"].concat();
        let contaminated = format!("password={value}");

        let mut approval = pending_approval("ap-prose");
        approval.reason = contaminated.clone();
        approval.decided_reason = Some(contaminated.clone());
        approval.notes.push(guard::gating::approval::ApprovalNote {
            at_unix: 1,
            author: contaminated.clone(),
            text: contaminated.clone(),
        });
        approval.decision_trace = Some(contaminated_trace(&value));
        store.save_approval(approval).await.unwrap();

        let mut provisional = provisional_row("pv-prose", ProvisionalStatus::Armed);
        provisional.reason = contaminated.clone();
        provisional.control_path = Some(contaminated.clone());
        provisional.revert_detail = Some(contaminated.clone());
        provisional.decision_trace = Some(contaminated_trace(&value));
        store.save_provisional(provisional).await.unwrap();

        let conn = Connection::open(&path).unwrap();
        let approval_json: String = conn
            .query_row(
                "SELECT json FROM gating_approval WHERE handle = 'ap-prose'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let provisional_json: String = conn
            .query_row(
                "SELECT json FROM gating_provisional WHERE handle = 'pv-prose'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!approval_json.contains(&value));
        assert!(!provisional_json.contains(&value));

        let mut approval: Approval = serde_json::from_str(&approval_json).unwrap();
        approval.reason = contaminated.clone();
        approval.decision_trace = Some(contaminated_trace(&value));
        let mut provisional: Provisional = serde_json::from_str(&provisional_json).unwrap();
        provisional.reason = contaminated;
        provisional.decision_trace = Some(contaminated_trace(&value));
        conn.execute(
            "UPDATE gating_approval SET json = ?1 WHERE handle = ?2",
            params![serde_json::to_string(&approval).unwrap(), approval.handle],
        )
        .unwrap();
        conn.execute(
            "UPDATE gating_provisional SET json = ?1 WHERE handle = ?2",
            params![
                serde_json::to_string(&provisional).unwrap(),
                provisional.handle
            ],
        )
        .unwrap();
        conn.pragma_update(None, "user_version", SCHEMA_VERSION - 1)
            .unwrap();
        drop(conn);

        let loaded_approvals = store.load_approvals().await.unwrap();
        let loaded_provisionals = store.load_provisionals().await.unwrap();
        let approval_bytes = serde_json::to_vec(&loaded_approvals).unwrap();
        let provisional_bytes = serde_json::to_vec(&loaded_provisionals).unwrap();
        assert!(!approval_bytes
            .windows(value.len())
            .any(|window| window == value.as_bytes()));
        assert!(!provisional_bytes
            .windows(value.len())
            .any(|window| window == value.as_bytes()));

        let conn = Connection::open(&path).unwrap();
        let json: String = conn
            .query_row(
                "SELECT json FROM gating_approval WHERE handle = 'ap-prose'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let mut approval: Approval = serde_json::from_str(&json).unwrap();
        approval.reason = format!("password={value}");
        conn.execute(
            "UPDATE gating_approval SET json = ?1 WHERE handle = ?2",
            params![serde_json::to_string(&approval).unwrap(), approval.handle],
        )
        .unwrap();
        drop(conn);
        let current_schema = store.load_approvals().await.unwrap();
        let current_bytes = serde_json::to_vec(&current_schema).unwrap();
        assert!(!current_bytes
            .windows(value.len())
            .any(|window| window == value.as_bytes()));

        let conn = Connection::open(path).unwrap();
        for table in ["gating_approval", "gating_provisional"] {
            let json: String = conn
                .query_row(&format!("SELECT json FROM {table}"), [], |row| row.get(0))
                .unwrap();
            assert!(!json.contains(&value));
        }
    }

    #[tokio::test]
    async fn current_schema_terminalizes_literal_sensitive_gate_rows() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state.db");
        let store = SessionStore::open(path.clone(), 3600).await.unwrap();
        let sensitive = ["q", "7"].concat();
        let mut approval = pending_approval("ap-sensitive-current");
        approval.snapshot.binary = "curl".to_string();
        approval.snapshot.args = vec!["-u".to_string(), sensitive.clone()];
        let mut provisional = provisional_row("pv-sensitive-current", ProvisionalStatus::Armed);
        provisional.confirm_check_binary = Some("redis-cli".to_string());
        provisional.confirm_check_args = vec![format!("-a:{sensitive}")];
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO gating_approval (handle, json, status, created_unix)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                approval.handle,
                serde_json::to_string(&approval).unwrap(),
                approval.status.as_str(),
                encode_u64(approval.created_unix).unwrap()
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO gating_provisional (handle, json, status, created_unix)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                provisional.handle,
                serde_json::to_string(&provisional).unwrap(),
                provisional.status.as_str(),
                encode_u64(provisional.created_unix).unwrap()
            ],
        )
        .unwrap();
        drop(conn);

        let approvals = store.load_approvals().await.unwrap();
        let provisionals = store.load_provisionals().await.unwrap();
        assert_eq!(approvals[0].status, ApprovalStatus::ExecFailed);
        assert!(approvals[0].snapshot.args.is_empty());
        assert_eq!(
            provisionals[0].status,
            ProvisionalStatus::NeedsOperatorDecision
        );
        assert!(provisionals[0].confirm_check_args.is_empty());
    }

    #[tokio::test]
    async fn migration_terminalizes_active_sensitive_gate_rows_and_scrubs_all_rows() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state.db");
        let store = SessionStore::open(path.clone(), 3600).await.unwrap();
        drop(store);
        let sensitive = ["q", "7"].concat();

        let mut active_approval = pending_approval("ap-sensitive-active");
        active_approval.snapshot.binary = "curl.EXE".to_string();
        active_approval.snapshot.args = vec![format!("-u{sensitive}")];
        active_approval
            .snapshot
            .verb_params
            .insert("mirrored".to_string(), sensitive.clone());
        let mut terminal_approval = pending_approval("ap-sensitive-terminal");
        terminal_approval.status = ApprovalStatus::Denied;
        terminal_approval.decided_unix = Some(2);
        terminal_approval.decided_reason = Some("operator denied".to_string());
        terminal_approval.snapshot.binary = "redis-cli.BAT".to_string();
        terminal_approval.snapshot.args = vec!["-a".to_string(), sensitive.clone()];

        let mut active_provisional =
            provisional_row("pv-sensitive-active", ProvisionalStatus::Armed);
        active_provisional.revert_binary = "docker.COM".to_string();
        active_provisional.revert_args = vec!["login".to_string(), format!("-p:{sensitive}")];
        let mut terminal_provisional =
            provisional_row("pv-sensitive-terminal", ProvisionalStatus::Confirmed);
        terminal_provisional.binary = "curl.CMD".to_string();
        terminal_provisional.args = vec!["--user".to_string(), sensitive.clone()];
        let mut safe_approval = pending_approval("ap-safe-active");
        safe_approval.snapshot.verb_name = Some("safe-forward".to_string());
        safe_approval
            .snapshot
            .verb_params
            .insert("rollback_only".to_string(), sensitive.clone());
        let safe_provisional = provisional_row("pv-safe-active", ProvisionalStatus::Armed);

        let conn = Connection::open(&path).unwrap();
        for approval in [&active_approval, &terminal_approval, &safe_approval] {
            conn.execute(
                "INSERT INTO gating_approval (handle, json, status, created_unix)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    approval.handle,
                    serde_json::to_string(approval).unwrap(),
                    approval.status.as_str(),
                    encode_u64(approval.created_unix).unwrap()
                ],
            )
            .unwrap();
        }
        for provisional in [
            &active_provisional,
            &terminal_provisional,
            &safe_provisional,
        ] {
            conn.execute(
                "INSERT INTO gating_provisional (handle, json, status, created_unix)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    provisional.handle,
                    serde_json::to_string(provisional).unwrap(),
                    provisional.status.as_str(),
                    encode_u64(provisional.created_unix).unwrap()
                ],
            )
            .unwrap();
        }
        conn.pragma_update(None, "user_version", SCHEMA_VERSION - 1)
            .unwrap();
        drop(conn);

        let migrated = SessionStore::open(path.clone(), 3600).await.unwrap();
        let approvals = migrated.load_approvals().await.unwrap();
        let provisionals = migrated.load_provisionals().await.unwrap();
        assert_eq!(
            approvals
                .iter()
                .find(|row| row.handle == active_approval.handle)
                .unwrap()
                .status,
            ApprovalStatus::ExecFailed
        );
        assert_eq!(
            approvals
                .iter()
                .find(|row| row.handle == terminal_approval.handle)
                .unwrap()
                .status,
            ApprovalStatus::Denied
        );
        let migrated_safe_approval = approvals
            .iter()
            .find(|row| row.handle == safe_approval.handle)
            .unwrap();
        assert_eq!(migrated_safe_approval.status, ApprovalStatus::Pending);
        assert!(migrated_safe_approval.snapshot.verb_params.is_empty());
        let mut expected_safe_snapshot = safe_approval.snapshot.clone();
        expected_safe_snapshot.verb_params.clear();
        assert_eq!(migrated_safe_approval.snapshot, expected_safe_snapshot);
        assert_eq!(
            provisionals
                .iter()
                .find(|row| row.handle == active_provisional.handle)
                .unwrap()
                .status,
            ProvisionalStatus::NeedsOperatorDecision
        );
        assert_eq!(
            provisionals
                .iter()
                .find(|row| row.handle == terminal_provisional.handle)
                .unwrap()
                .status,
            ProvisionalStatus::Confirmed
        );
        let migrated_safe_provisional = provisionals
            .iter()
            .find(|row| row.handle == safe_provisional.handle)
            .unwrap();
        assert_eq!(migrated_safe_provisional.status, ProvisionalStatus::Armed);
        assert_eq!(migrated_safe_provisional.binary, safe_provisional.binary);
        assert_eq!(migrated_safe_provisional.args, safe_provisional.args);
        assert_eq!(
            migrated_safe_provisional.revert_binary,
            safe_provisional.revert_binary
        );
        assert_eq!(
            migrated_safe_provisional.revert_args,
            safe_provisional.revert_args
        );
        assert!(approvals
            .iter()
            .all(|row| !row.snapshot.contains_sensitive_literals()));
        assert!(provisionals
            .iter()
            .all(|row| !row.contains_sensitive_literals()));
        drop(migrated);

        let restarted = SessionStore::open(path.clone(), 3600).await.unwrap();
        assert_eq!(restarted.load_approvals().await.unwrap().len(), 3);
        assert_eq!(restarted.load_provisionals().await.unwrap().len(), 3);
        let conn = Connection::open(path).unwrap();
        for table in ["gating_approval", "gating_provisional"] {
            let mut stmt = conn.prepare(&format!("SELECT json FROM {table}")).unwrap();
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert!(rows.iter().all(|json| !json.contains(&sensitive)));
        }
    }

    #[tokio::test]
    async fn provisional_sensitive_migration_maps_every_status_once() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state.db");
        drop(SessionStore::open(path.clone(), 3600).await.unwrap());
        let value = ["q", "7"].concat();
        let statuses = [
            ProvisionalStatus::Armed,
            ProvisionalStatus::Reverting,
            ProvisionalStatus::Confirmed,
            ProvisionalStatus::Reverted,
            ProvisionalStatus::RevertFailed,
            ProvisionalStatus::NeedsOperatorDecision,
        ];
        let conn = Connection::open(&path).unwrap();
        for (index, status) in statuses.into_iter().enumerate() {
            let mut row = provisional_row(&format!("pv-status-{index}"), status);
            row.binary = "redis-cli.EXE".to_string();
            row.args = vec![format!("-a={value}")];
            row.revert_detail = matches!(
                status,
                ProvisionalStatus::RevertFailed | ProvisionalStatus::NeedsOperatorDecision
            )
            .then(|| format!("password={value}"));
            conn.execute(
                "INSERT INTO gating_provisional (handle, json, status, created_unix)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    row.handle,
                    serde_json::to_string(&row).unwrap(),
                    row.status.as_str(),
                    encode_u64(row.created_unix).unwrap()
                ],
            )
            .unwrap();
        }
        conn.pragma_update(None, "user_version", SCHEMA_VERSION - 1)
            .unwrap();
        drop(conn);

        let migrated = SessionStore::open(path.clone(), 3600).await.unwrap();
        let mut rows = migrated.load_provisionals().await.unwrap();
        rows.sort_by(|left, right| left.handle.cmp(&right.handle));
        let expected = [
            ProvisionalStatus::NeedsOperatorDecision,
            ProvisionalStatus::NeedsOperatorDecision,
            ProvisionalStatus::Confirmed,
            ProvisionalStatus::Reverted,
            ProvisionalStatus::RevertFailed,
            ProvisionalStatus::NeedsOperatorDecision,
        ];
        for (row, expected_status) in rows.iter().zip(expected) {
            assert_eq!(row.status, expected_status);
            assert!(!row.contains_sensitive_literals());
            if matches!(
                expected_status,
                ProvisionalStatus::RevertFailed | ProvisionalStatus::NeedsOperatorDecision
            ) {
                assert!(row.revert_detail.is_some());
            }
        }
        let failed = rows.iter().find(|row| row.handle == "pv-status-4").unwrap();
        assert_eq!(failed.status, ProvisionalStatus::RevertFailed);
        assert!(failed
            .revert_detail
            .as_deref()
            .is_some_and(|detail| detail.contains("[REDACTED]")));
        drop(migrated);

        let conn = Connection::open(&path).unwrap();
        let first_json = conn
            .prepare("SELECT json FROM gating_provisional ORDER BY handle")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(first_json.iter().all(|json| !json.contains(&value)));
        drop(conn);
        drop(SessionStore::open(path.clone(), 3600).await.unwrap());
        let conn = Connection::open(path).unwrap();
        let second_json = conn
            .prepare("SELECT json FROM gating_provisional ORDER BY handle")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(second_json, first_json);
    }

    #[tokio::test]
    async fn migration_removes_plain_environment_values_from_approval_rows() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state.db");
        let store = SessionStore::open(path.clone(), 3600).await.unwrap();
        drop(store);
        let mut approval = pending_approval("ap-migrate-env");
        approval.snapshot.env.insert(
            "FIXTURE_VALUE".to_string(),
            "synthetic-credential-value".to_string(),
        );
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO gating_approval (handle, json, status, created_unix)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                approval.handle,
                serde_json::to_string(&approval).unwrap(),
                approval.status.as_str(),
                encode_u64(approval.created_unix).unwrap()
            ],
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 8).unwrap();
        drop(conn);

        let migrated = SessionStore::open(path.clone(), 3600).await.unwrap();
        let rows = migrated.load_approvals().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].snapshot.env.is_empty());
        assert_eq!(rows[0].status, ApprovalStatus::ExecFailed);
        let stored: String = Connection::open(path)
            .unwrap()
            .query_row("SELECT json FROM gating_approval", [], |row| row.get(0))
            .unwrap();
        assert!(!stored.contains("synthetic-credential-value"));
    }

    #[tokio::test]
    async fn current_schema_terminalizes_plain_environment_values_in_approval_rows() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state.db");
        let store = SessionStore::open(path.clone(), 3600).await.unwrap();
        let mut approval = pending_approval("ap-current-plain-env");
        approval.snapshot.env.insert(
            "FIXTURE_VALUE".to_string(),
            "synthetic-credential-value".to_string(),
        );
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO gating_approval (handle, json, status, created_unix)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                approval.handle,
                serde_json::to_string(&approval).unwrap(),
                approval.status.as_str(),
                encode_u64(approval.created_unix).unwrap()
            ],
        )
        .unwrap();
        drop(conn);

        let loaded = store.load_approvals().await.unwrap();
        assert_eq!(loaded[0].status, ApprovalStatus::ExecFailed);
        assert!(loaded[0].snapshot.env.is_empty());
        assert!(loaded[0]
            .decided_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("plain environment")));
    }

    #[tokio::test]
    async fn old_session_schema_migrates_typed_verb_scope_columns() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("state.db");
        let conn = Connection::open(&path).expect("create old database");
        conn.execute_batch(
            "CREATE TABLE session_grants (
                token TEXT PRIMARY KEY,
                allow_json TEXT NOT NULL,
                deny_json TEXT NOT NULL,
                allow_exact_json TEXT NOT NULL DEFAULT '[]',
                deny_exact_json TEXT NOT NULL DEFAULT '[]',
                expires_at INTEGER,
                prompt_append TEXT,
                generated_notes_json TEXT NOT NULL DEFAULT '[]',
                granted_at INTEGER NOT NULL,
                static_only INTEGER NOT NULL DEFAULT 0,
                auto_amend INTEGER NOT NULL DEFAULT 0
            );
            INSERT INTO session_grants
                (token, allow_json, deny_json, granted_at)
                VALUES ('legacy', '[]', '[]', 1);
            CREATE TABLE session_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT NOT NULL,
                allow_json TEXT NOT NULL,
                deny_json TEXT NOT NULL,
                allow_exact_json TEXT NOT NULL DEFAULT '[]',
                deny_exact_json TEXT NOT NULL DEFAULT '[]',
                granted_at INTEGER NOT NULL,
                expires_at INTEGER,
                ended_at INTEGER NOT NULL,
                status TEXT NOT NULL,
                prompt_append TEXT,
                generated_notes_json TEXT NOT NULL DEFAULT '[]',
                static_only INTEGER NOT NULL DEFAULT 0,
                auto_amend INTEGER NOT NULL DEFAULT 0
            );
            INSERT INTO session_history
                (token, allow_json, deny_json, granted_at, ended_at, status)
                VALUES ('legacy-history', '[]', '[]', 1, 2000000000, 'revoked');",
        )
        .expect("seed old schema");
        drop(conn);

        let store = SessionStore::open(path, 24 * 60 * 60)
            .await
            .expect("migrate old database");
        let loaded = store.load_registry().await.expect("load migrated database");
        assert_eq!(
            loaded.verb_scope_for("legacy"),
            Some((Vec::new(), Vec::new()))
        );
        let history = loaded.list_history(None);
        assert_eq!(history.len(), 1);
        assert!(history[0].activated_verbs.is_empty());
        assert!(history[0].override_markers.is_empty());
    }

    #[tokio::test]
    async fn session_store_round_trips_registry() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = SessionStore::open(tmp.path().join("state.db"), 24 * 60 * 60)
            .await
            .expect("open store");
        let now = guard::env::now_unix();

        let mut grants = HashMap::new();
        grants.insert(
            "tok".to_string(),
            SessionGrant {
                allow: vec!["echo*".into()],
                deny: vec!["rm*".into()],
                allow_exact: vec![SessionExactRule::new(
                    "kubectl",
                    vec!["get".into(), "pods".into()],
                )],
                deny_exact: vec![SessionExactRule::new(
                    "kubectl",
                    vec!["get".into(), "secrets".into()],
                )],
                activated_verbs: vec!["inspect-secrets".into()],
                override_markers: vec!["operator:inspect-secrets".into()],
                scope: Default::default(),
                expires_at: None,
                prompt_append: Some("persistent".into()),
                generated_notes: vec!["generated note".into()],
                granted_at: now.saturating_sub(2),
                static_only: true,
                auto_amend: true,
                owner: SessionOwner::Principal(guard::principal::PrincipalKey::from_uid(4242)),
            },
        );
        let registry = SessionRegistry::from_parts(
            grants,
            vec![HistoricalGrant {
                token: "old".into(),
                allow: vec!["ls*".into()],
                deny: Vec::new(),
                allow_exact: Vec::new(),
                deny_exact: Vec::new(),
                activated_verbs: vec!["historical-read".into()],
                override_markers: vec!["operator:historical-read".into()],
                scope: Default::default(),
                granted_at: now.saturating_sub(10),
                expires_at: None,
                ended_at: now.saturating_sub(5),
                status: HistoricalStatus::Revoked,
                prompt_append: None,
                generated_notes: Vec::new(),
                static_only: false,
                auto_amend: false,
                owner: SessionOwner::Principal(guard::principal::PrincipalKey::from_uid(4343)),
            }],
            vec![(
                "tok".into(),
                SessionInteraction {
                    at_unix: now.saturating_sub(1),
                    command: "echo hi".into(),
                    allowed: true,
                    source: SessionDecisionSource::Llm,
                    reason: "safe".into(),
                    risk: Some(1),
                    exec_status: SessionExecStatus::CompletedAfterApproval,
                    exit_code: Some(0),
                    credential_references: vec![CredentialReference::from_store_name(
                        "service/token",
                    )
                    .expect("valid fixture credential reference")],
                    decision_trace: Some(guard::gating::DecisionTrace::source("cache")),
                },
            )],
            24 * 60 * 60,
        );

        store
            .persist_registry(&registry)
            .await
            .expect("persist registry");
        let loaded = store.load_registry().await.expect("load registry");

        assert!(loaded.has("tok"));
        let report = loaded.show("tok", 10).expect("session report");
        assert_eq!(report.stats.total, 1);
        assert_eq!(report.stats.completed, 1);
        assert_eq!(report.stats.holds, 1);
        assert_eq!(report.stats.risk_histogram[1], 1);
        assert_eq!(
            report.recent[0]
                .decision_trace
                .as_ref()
                .map(|trace| trace.decision_source.as_str()),
            Some("cache")
        );
        assert_eq!(report.stats.evaluator_calls, 1);
        assert_eq!(report.stats.novel_shapes, 1);
        assert_eq!(report.stats.novel_shape_rate_percent, 100);
        assert_eq!(report.recent[0].exit_code, Some(0));
        assert_eq!(
            report.recent[0].exec_status,
            SessionExecStatus::CompletedAfterApproval
        );
        assert_eq!(
            report.recent[0].credential_references[0].as_reference_name(),
            "service/token"
        );
        assert_eq!(
            report.active.and_then(|grant| grant.prompt_append),
            Some("persistent".into())
        );
        let report = loaded.show("tok", 10).expect("session report");
        assert_eq!(
            report
                .active
                .and_then(|grant| grant.generated_notes.into_iter().next()),
            Some("generated note".into())
        );
        assert!(loaded.static_only_for("tok"));
        assert!(loaded.auto_amend_for("tok"));
        assert_eq!(
            loaded.verb_scope_for("tok"),
            Some((
                vec!["inspect-secrets".to_string()],
                vec!["operator:inspect-secrets".to_string()]
            ))
        );
        assert!(loaded
            .check("tok", "kubectl", &["get".into(), "pods".into()], None)
            .is_some());
        assert!(matches!(
            loaded
                .check("tok", "kubectl", &["get".into(), "secrets".into()], None)
                .map(|hit| hit.0),
            Some(crate::session::SessionDecision::Deny)
        ));
        let history = loaded.list_history(None);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].activated_verbs, vec!["historical-read"]);
        assert_eq!(
            history[0].override_markers,
            vec!["operator:historical-read"]
        );
    }

    #[tokio::test]
    async fn schema_v12_nested_trace_cleanup_is_transactional_and_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.db");
        let store = SessionStore::open(path.clone(), 3600).await.unwrap();
        let safe_rule = SessionExactRule::new("fixturectl", vec!["status".to_string()]);
        let mut registry = SessionRegistry::new();
        registry.grant(
            "safe".to_string(),
            exact_rule_grant(vec![safe_rule.clone()]),
        );
        registry.record_interaction(
            "safe",
            SessionInteraction {
                at_unix: guard::env::now_unix(),
                command: "fixturectl status".to_string(),
                allowed: true,
                source: SessionDecisionSource::Llm,
                reason: "safe rationale".to_string(),
                risk: Some(1),
                exec_status: SessionExecStatus::Completed,
                exit_code: Some(0),
                credential_references: Vec::new(),
                decision_trace: Some(guard::gating::DecisionTrace::source("llm")),
            },
        );
        store.persist_registry(&registry).await.unwrap();

        let value = ["q", "7"].concat();
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE session_interactions SET decision_trace_json = ?1",
            params![serde_json::to_string(&contaminated_trace(&value)).unwrap()],
        )
        .unwrap();
        conn.pragma_update(None, "user_version", SCHEMA_VERSION - 1)
            .unwrap();
        drop(conn);
        drop(store);

        for _ in 0..2 {
            let restarted = SessionStore::open(path.clone(), 3600).await.unwrap();
            let loaded = restarted.load_registry().await.unwrap();
            assert!(loaded.has("safe"));
            assert!(matches!(
                loaded
                    .check("safe", "fixturectl", &["status".to_string()], None)
                    .map(|decision| decision.0),
                Some(crate::session::SessionDecision::Allow)
            ));
            let report = loaded.show("safe", 10).unwrap();
            assert_eq!(report.recent.len(), 1);
            assert!(!serde_json::to_string(&report.recent[0])
                .unwrap()
                .contains(&value));
            drop(restarted);

            let conn = Connection::open(&path).unwrap();
            let version: i64 = conn
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap();
            let durable: String = conn
                .query_row(
                    "SELECT decision_trace_json FROM session_interactions",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(version, SCHEMA_VERSION);
            assert!(!durable.contains(&value));
        }
    }

    #[tokio::test]
    async fn schema_v12_clears_malformed_trace_without_changing_safe_authority() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.db");
        let store = SessionStore::open(path.clone(), 3600).await.unwrap();
        let safe_rule = SessionExactRule::new("fixturectl", vec!["status".to_string()]);
        let mut registry = SessionRegistry::new();
        registry.grant(
            "safe".to_string(),
            exact_rule_grant(vec![safe_rule.clone()]),
        );
        registry.record_interaction(
            "safe",
            SessionInteraction {
                at_unix: guard::env::now_unix(),
                command: "fixturectl status".to_string(),
                allowed: true,
                source: SessionDecisionSource::Llm,
                reason: "safe rationale".to_string(),
                risk: Some(1),
                exec_status: SessionExecStatus::Completed,
                exit_code: Some(0),
                credential_references: Vec::new(),
                decision_trace: Some(guard::gating::DecisionTrace::source("llm")),
            },
        );
        store.persist_registry(&registry).await.unwrap();

        let value = ["q", "7"].concat();
        let malformed = format!("{{\"reason\":\"password={value}\"");
        let conn = Connection::open(&path).unwrap();
        let safe_allow: String = conn
            .query_row(
                "SELECT allow_exact_json FROM session_grants WHERE token = 'safe'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        conn.execute(
            "UPDATE session_interactions SET decision_trace_json = ?1",
            params![malformed],
        )
        .unwrap();
        conn.pragma_update(None, "user_version", SCHEMA_VERSION - 1)
            .unwrap();
        drop(conn);
        drop(store);

        for _ in 0..2 {
            let restarted = SessionStore::open(path.clone(), 3600).await.unwrap();
            let loaded = restarted.load_registry().await.unwrap();
            assert!(matches!(
                loaded
                    .check("safe", "fixturectl", &["status".to_string()], None)
                    .map(|decision| decision.0),
                Some(crate::session::SessionDecision::Allow)
            ));
            assert!(loaded.show("safe", 10).unwrap().recent[0]
                .decision_trace
                .is_none());
            drop(restarted);

            let conn = Connection::open(&path).unwrap();
            let version: i64 = conn
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap();
            let trace: Option<String> = conn
                .query_row(
                    "SELECT decision_trace_json FROM session_interactions",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let durable_allow: String = conn
                .query_row(
                    "SELECT allow_exact_json FROM session_grants WHERE token = 'safe'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(version, SCHEMA_VERSION);
            assert!(trace.is_none());
            assert_eq!(durable_allow, safe_allow);
        }
    }

    #[tokio::test]
    async fn session_exact_rule_writes_reject_sensitive_argv() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.db");
        let store = SessionStore::open(path.clone(), 3600).await.unwrap();
        let value = ["q", "7"].concat();
        let mut registry = SessionRegistry::new();
        registry.grant(
            "sensitive".to_string(),
            exact_rule_grant(vec![SessionExactRule::new(
                "curl",
                vec!["-u".to_string(), value.clone()],
            )]),
        );

        assert!(store.persist_registry(&registry).await.is_err());
        let conn = Connection::open(path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM session_grants", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn session_exact_rule_load_purges_active_and_historical_authority_once() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.db");
        let store = SessionStore::open(path.clone(), 3600).await.unwrap();
        let safe_rule = SessionExactRule::new("kubectl", vec!["get".into(), "pods".into()]);
        let mut grants = HashMap::new();
        grants.insert(
            "mixed-active".to_string(),
            exact_rule_grant(vec![safe_rule.clone()]),
        );
        grants.insert(
            "safe-active".to_string(),
            exact_rule_grant(vec![safe_rule.clone()]),
        );
        let historical = HistoricalGrant {
            token: "mixed-history".to_string(),
            allow: Vec::new(),
            deny: Vec::new(),
            allow_exact: vec![safe_rule.clone()],
            deny_exact: Vec::new(),
            activated_verbs: Vec::new(),
            override_markers: Vec::new(),
            scope: IssuedGrantScope::default(),
            granted_at: 1,
            expires_at: None,
            ended_at: guard::env::now_unix(),
            status: HistoricalStatus::Revoked,
            prompt_append: None,
            generated_notes: Vec::new(),
            static_only: false,
            auto_amend: true,
            owner: SessionOwner::Principal(guard::principal::PrincipalKey::from_uid(1001)),
        };
        let registry = SessionRegistry::from_parts(grants, vec![historical], Vec::new(), 3600);
        store.persist_registry(&registry).await.unwrap();

        let value = ["q", "7"].concat();
        let mixed = serde_json::to_string(&vec![
            safe_rule.clone(),
            SessionExactRule::new(
                "docker.EXE",
                vec!["login".to_string(), format!("-p={value}")],
            ),
        ])
        .unwrap();
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE session_grants SET allow_exact_json = ?1 WHERE token = 'mixed-active'",
            params![mixed],
        )
        .unwrap();
        conn.execute(
            "UPDATE session_history SET deny_exact_json = ?1 WHERE token = 'mixed-history'",
            params![serde_json::to_string(&vec![SessionExactRule::new(
                "redis-cli",
                vec!["-a".to_string(), value.clone()],
            )])
            .unwrap()],
        )
        .unwrap();
        let safe_before: String = conn
            .query_row(
                "SELECT allow_exact_json FROM session_grants WHERE token = 'safe-active'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        drop(conn);

        let loaded = store.load_registry().await.unwrap();
        let active = loaded
            .grants_snapshot()
            .into_iter()
            .find(|(token, _)| token == "mixed-active")
            .unwrap()
            .1;
        assert_eq!(active.allow_exact, vec![safe_rule.clone()]);
        let history = loaded
            .history_snapshot()
            .into_iter()
            .find(|grant| grant.token == "mixed-history")
            .unwrap();
        assert_eq!(history.allow_exact, vec![safe_rule]);
        assert!(history.deny_exact.is_empty());

        let conn = Connection::open(&path).unwrap();
        let safe_after: String = conn
            .query_row(
                "SELECT allow_exact_json FROM session_grants WHERE token = 'safe-active'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(safe_after, safe_before);
        let sanitized_rows: Vec<(String, String)> = conn
            .prepare(
                "SELECT allow_exact_json, deny_exact_json FROM session_grants
                 UNION ALL SELECT allow_exact_json, deny_exact_json FROM session_history",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(sanitized_rows.iter().all(|(allow, deny)| {
            !allow
                .as_bytes()
                .windows(value.len())
                .any(|window| window == value.as_bytes())
                && !deny
                    .as_bytes()
                    .windows(value.len())
                    .any(|window| window == value.as_bytes())
        }));
        let generation_after_first = SessionStore::read_registry_generation(&conn).unwrap();
        drop(conn);

        store.load_registry().await.unwrap();
        let conn = Connection::open(path).unwrap();
        assert_eq!(
            SessionStore::read_registry_generation(&conn).unwrap(),
            generation_after_first
        );
    }

    async fn assert_sensitive_exact_deny_retires_active_session(schema_version: i64) {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.db");
        let store = SessionStore::open(path.clone(), 3600).await.unwrap();
        let token = format!("deny-retire-{schema_version}");
        let mut grant = exact_rule_grant(Vec::new());
        grant.allow = vec!["docker*".to_string()];
        let mut registry = SessionRegistry::new();
        registry.grant(token.clone(), grant);
        store.persist_registry(&registry).await.unwrap();
        drop(store);

        let value = ["q", "7"].concat();
        let deny = vec![SessionExactRule::new(
            "docker",
            vec!["login".to_string(), "-p".to_string(), value.clone()],
        )];
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE session_grants SET deny_exact_json = ?1 WHERE token = ?2",
            params![serde_json::to_string(&deny).unwrap(), token],
        )
        .unwrap();
        conn.pragma_update(None, "user_version", schema_version)
            .unwrap();
        drop(conn);

        let restarted = SessionStore::open(path.clone(), 3600).await.unwrap();
        let loaded = restarted.load_registry().await.unwrap();
        assert!(!loaded.has(&token));
        assert!(loaded
            .check(
                &token,
                "docker",
                &["run".to_string(), "ordinary-image".to_string()],
                None,
            )
            .is_none());
        assert!(loaded
            .check(
                &token,
                "docker",
                &["login".to_string(), "-p".to_string(), value.clone()],
                None,
            )
            .is_none());
        let retired = loaded
            .history_snapshot()
            .into_iter()
            .find(|row| row.token == token)
            .unwrap();
        assert_eq!(retired.status, HistoricalStatus::Revoked);
        assert!(retired.deny_exact.is_empty());

        let conn = Connection::open(path).unwrap();
        let active: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM session_grants WHERE token = ?1",
                params![retired.token],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(active, 0);
        let durable: String = conn
            .query_row(
                "SELECT deny_exact_json FROM session_history WHERE token = ?1 ORDER BY id DESC LIMIT 1",
                params![retired.token],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!durable
            .as_bytes()
            .windows(value.len())
            .any(|window| window == value.as_bytes()));
    }

    #[tokio::test]
    async fn current_load_retires_session_when_sensitive_exact_deny_is_stripped() {
        assert_sensitive_exact_deny_retires_active_session(SCHEMA_VERSION).await;
    }

    #[tokio::test]
    async fn pre_current_migration_retires_session_when_sensitive_exact_deny_is_stripped() {
        assert_sensitive_exact_deny_retires_active_session(SCHEMA_VERSION - 1).await;
    }
}
