use crate::grant_profile::{GrantRequest, SavedGrant};
use crate::session::{
    session_grant_revision_key, HistoricalGrant, HistoricalStatus, IssuedGrantScope,
    SessionDecisionSource, SessionExactRule, SessionExecStatus, SessionGrant, SessionInteraction,
    SessionOwner, SessionRegistry,
};
use anyhow::{Context, Result};
use guard::gating::approval::{Approval, ApprovalStatus};
use guard::gating::provisional::{Provisional, ProvisionalStatus};
use guard::gating::read_grant::ReadGrant;
use guard::redact::redact_output_text;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
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
const SCHEMA_VERSION: i64 = 9;
const VACUUM_MIN_PAGES: u64 = 512;
const VACUUM_MIN_FREE_PAGES: u64 = 128;
const REGISTRY_GENERATION_KEY: &str = "registry_generation";

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
}

/// Process-lifetime ownership of one state database. The operating system
/// releases the advisory lock if the daemon exits or crashes. The lock file is
/// intentionally retained so a new inode cannot bypass a live lock.
#[derive(Debug)]
pub struct StateDatabaseLease {
    _file: File,
}

impl SessionStore {
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
            if !crate::server::secure_fs::harden_existing_private_path(parent, true) {
                anyhow::bail!(
                    "state database parent {} is not daemon-only",
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
        let mut write_state = self.registry_write_gate.lock().await;
        let (registry, generation) =
            tokio::task::spawn_blocking(move || Self::load_registry_sync(&path, retention))
                .await
                .context("session store load task failed")??;
        write_state.database_generation = generation;
        write_state.last_written_revision = registry.revision();
        Ok(registry)
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
        let mut write_state = self.registry_write_gate.lock().await;
        if revision < write_state.last_written_revision {
            // A newer snapshot already landed; a full-table rewrite from this
            // one would roll the on-disk state back.
            return Ok(());
        }
        let expected_generation = write_state.database_generation;
        let generation = tokio::task::spawn_blocking(move || {
            Self::persist_registry_sync(&path, retention, &snapshot, expected_generation)
        })
        .await
        .context("session store persist task failed")??;
        write_state.database_generation = generation;
        write_state.last_written_revision = revision;
        Ok(())
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
        };
        Ok(store)
    }

    fn load_registry_sync(
        path: &Path,
        history_retention_secs: u64,
    ) -> Result<(SessionRegistry, u64)> {
        Self::load_registry_sync_with_hook(path, history_retention_secs, || {})
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
                let (token, grant) = row?;
                grants.insert(token, grant);
            }
        }
        after_grants();

        let mut history = Vec::new();
        {
            let mut stmt = tx.prepare(
                "SELECT token, allow_json, deny_json, allow_exact_json, deny_exact_json, activated_verbs_json, override_markers_json, scope_json, granted_at, expires_at, ended_at, status, prompt_append, generated_notes_json, static_only, auto_amend, owner_json
                 FROM session_history
                 ORDER BY ended_at ASC, id ASC",
            )?;
            let rows = stmt.query_map([], |row| {
                let allow_json: String = row.get(1)?;
                let deny_json: String = row.get(2)?;
                let allow_exact_json: String = row.get(3)?;
                let deny_exact_json: String = row.get(4)?;
                let status: String = row.get(11)?;
                Ok(HistoricalGrant {
                    token: row.get(0)?,
                    allow: decode_vec(&allow_json)?,
                    deny: decode_vec(&deny_json)?,
                    allow_exact: decode_exact_vec(&allow_exact_json)?,
                    deny_exact: decode_exact_vec(&deny_exact_json)?,
                    activated_verbs: decode_vec(&row.get::<_, String>(5)?)?,
                    override_markers: decode_vec(&row.get::<_, String>(6)?)?,
                    scope: decode_scope(&row.get::<_, String>(7)?)?,
                    granted_at: decode_u64(row.get(8)?)?,
                    expires_at: decode_optional_u64(row.get(9)?)?,
                    ended_at: decode_u64(row.get(10)?)?,
                    status: decode_historical_status(&status)?,
                    prompt_append: row.get(12)?,
                    generated_notes: decode_vec(&row.get::<_, String>(13)?)?,
                    static_only: decode_bool(row.get(14)?)?,
                    auto_amend: decode_bool(row.get(15)?)?,
                    owner: decode_owner(&row.get::<_, String>(16)?)?,
                })
            })?;
            for row in rows {
                history.push(row?);
            }
        }

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
                        exposed_secret_refs: decode_vec(&row.get::<_, String>(9)?)?,
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
        tx.execute("DELETE FROM session_grants", [])?;
        tx.execute("DELETE FROM session_history", [])?;
        tx.execute("DELETE FROM session_interactions", [])?;

        let mut snapshot = registry
            .clone()
            .with_history_retention(history_retention_secs);
        snapshot.purge_expired();

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

        for (token, interaction) in snapshot.interactions_snapshot() {
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
                    encode_vec(&interaction.exposed_secret_refs)?,
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
        conn.query_row(
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
        .context("load session grant for request approval")
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
        if version > SCHEMA_VERSION {
            anyhow::bail!(
                "state database schema version {} is newer than supported version {}",
                version,
                SCHEMA_VERSION
            );
        }
        if version == SCHEMA_VERSION {
            Self::validate_current_schema_tables(conn)?;
            Self::validate_authority_row_indexes(conn)?;
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
        Self::validate_authority_row_indexes(&tx)?;
        // Databases written before schema v6 may hold credential material that
        // transited a command line (recorded argv, learned rules, prompts).
        // Sanitize once as part of the migration; the version bump below makes
        // this pass run exactly once per database.
        sanitize_persisted_credentials(&tx)?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tx.commit()?;
        Ok(())
    }

    fn validate_authority_row_indexes(conn: &Connection) -> Result<()> {
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
            json.map(|json| serde_json::from_str(&json).context("decode grant request"))
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
        let path = self.path.clone();
        let retention = self.history_retention_secs;
        let revision = registry.revision();
        let mut write_state = self.registry_write_gate.lock().await;
        if revision < write_state.last_written_revision {
            anyhow::bail!("approved session snapshot is stale");
        }
        let expected_generation = write_state.database_generation;
        let generation = tokio::task::spawn_blocking(move || {
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
        })
        .await
        .context("grant request approval transaction task failed")??;
        write_state.database_generation = generation;
        write_state.last_written_revision = revision;
        Ok(())
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
        let path = self.path.clone();
        let retention = self.history_retention_secs;
        let revision = registry.revision();
        let mut write_state = self.registry_write_gate.lock().await;
        if revision < write_state.last_written_revision {
            anyhow::bail!("access revoke session snapshot is stale");
        }
        let expected_generation = write_state.database_generation;
        let generation = tokio::task::spawn_blocking(move || {
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
        })
        .await
        .context("access revoke transaction task failed")??;
        write_state.database_generation = generation;
        write_state.last_written_revision = revision;
        Ok(())
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

    // --- Consequence-gating runtime state (provisional executions and operator
    // approvals). These are high-churn, handle-keyed rows, so unlike the session
    // registry they persist incrementally (per-row upsert/delete) rather than by
    // full-table snapshot, and a provisional is committed before its forward
    // command runs so a crash still leaves a recoverable revert.

    /// Insert a new provisional or advance an existing row through a legal,
    /// monotonic transition. Creation uses a plain insert. Existing rows are
    /// compared and replaced under one immediate transaction.
    pub async fn save_provisional(&self, p: Provisional) -> Result<()> {
        #[cfg(test)]
        if self
            .fail_next_write
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            anyhow::bail!("simulated session-store write failure");
        }
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || Self::insert_or_advance_provisional_sync(&path, &p))
            .await
            .context("save_provisional task failed")?
    }

    pub async fn compare_and_swap_provisional(
        &self,
        expected: Provisional,
        next: Provisional,
    ) -> Result<()> {
        #[cfg(test)]
        if self
            .fail_next_write
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            anyhow::bail!("simulated session-store write failure");
        }
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            Self::compare_and_swap_provisional_sync(&path, &expected, &next)
        })
        .await
        .context("provisional transition task failed")?
    }

    fn insert_or_advance_provisional_sync(path: &Path, next: &Provisional) -> Result<()> {
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
                if next.status != ProvisionalStatus::Armed {
                    anyhow::bail!("new provisional must begin armed");
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
                let expected: Provisional =
                    serde_json::from_str(&durable_json).context("decode durable provisional")?;
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

    pub async fn load_provisionals(&self) -> Result<Vec<Provisional>> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Self::open_connection(&path)?;
            Self::init_schema(&conn)?;
            let mut stmt =
                conn.prepare("SELECT handle, status, created_unix, json FROM gating_provisional")?;
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
                out.push(provisional);
            }
            Ok(out)
        })
        .await
        .context("load_provisionals task failed")?
    }

    /// Insert a new pending approval or advance an existing row through a
    /// legal, monotonic transition. A stale caller can never replace a decided
    /// row with Pending because the durable row is compared inside the write
    /// transaction.
    pub async fn save_approval(&self, a: Approval) -> Result<()> {
        #[cfg(test)]
        if self
            .fail_next_write
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            anyhow::bail!("simulated session-store write failure");
        }
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || Self::insert_or_advance_approval_sync(&path, &a))
            .await
            .context("save_approval task failed")?
    }

    pub async fn compare_and_swap_approval(
        &self,
        expected: Approval,
        next: Approval,
    ) -> Result<()> {
        #[cfg(test)]
        if self
            .fail_next_write
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            anyhow::bail!("simulated session-store write failure");
        }
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            Self::compare_and_swap_approval_sync(&path, &expected, &next)
        })
        .await
        .context("approval transition task failed")?
    }

    fn insert_or_advance_approval_sync(path: &Path, next: &Approval) -> Result<()> {
        if !next.snapshot.env.is_empty() {
            anyhow::bail!("approval snapshots cannot persist plain environment values");
        }
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
                let expected: Approval =
                    serde_json::from_str(&durable_json).context("decode durable approval")?;
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
        if !next.snapshot.env.is_empty() {
            anyhow::bail!("approval snapshots cannot persist plain environment values");
        }
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
            let conn = Self::open_connection(&path)?;
            Self::init_schema(&conn)?;
            let mut stmt =
                conn.prepare("SELECT handle, status, created_unix, json FROM gating_approval")?;
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
                if !approval.snapshot.env.is_empty() {
                    anyhow::bail!(
                        "durable approval {handle} contains prohibited plain environment values"
                    );
                }
                out.push(approval);
            }
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
    identity.forward_done = false;
    identity.status = ProvisionalStatus::Armed;
    identity.revert_exit = None;
    identity.revert_detail = None;
    identity
}

fn valid_provisional_transition(previous: &Provisional, next: &Provisional) -> Result<bool> {
    if !serialized_eq(&provisional_identity(previous), &provisional_identity(next))?
        || (previous.forward_done && !next.forward_done)
        || !option_only_adds_or_preserves(&previous.decision_trace, &next.decision_trace)?
    {
        return Ok(false);
    }
    let legal_status = matches!(
        (previous.status, next.status),
        (ProvisionalStatus::Armed, ProvisionalStatus::Armed)
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
            ProvisionalStatus::Armed | ProvisionalStatus::NeedsOperatorDecision
        )
    {
        return serialized_eq(previous, next);
    }
    Ok(true)
}

pub(crate) fn sanitize_grant_request(mut request: GrantRequest) -> GrantRequest {
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
    if !request.request_key.is_empty() {
        if let Ok(request_key) = request.canonical_access_key() {
            request.request_key = request_key;
        }
    }
    request
}

/// Migration pass for persisted command-derived text and durable gate state.
/// persisted command-derived text so a secret that entered the state database
/// under an older schema does not outlive the upgrade. Rows are sanitized in
/// place -- diagnostic utility is kept, credential-shaped values become the
/// `[REDACTED]` marker. New writes are sanitized before they reach the store
/// (see `SessionRegistry::record_interaction` and the session amendment
/// paths), so this only has to cover historical rows.
fn sanitize_persisted_credentials(conn: &Connection) -> Result<()> {
    {
        let mut stmt = conn.prepare(
            "SELECT rowid, command, reason, decision_trace_json FROM session_interactions",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (rowid, command, reason, trace_json) in rows {
            let sanitized_command = redact_output_text(&command);
            let sanitized_reason = redact_output_text(&reason);
            let sanitized_trace = trace_json.as_deref().map(sanitize_decision_trace_json);
            if sanitized_command != command
                || sanitized_reason != reason
                || sanitized_trace != trace_json
            {
                conn.execute(
                    "UPDATE session_interactions
                     SET command = ?1, reason = ?2, decision_trace_json = ?3
                     WHERE rowid = ?4",
                    params![sanitized_command, sanitized_reason, sanitized_trace, rowid],
                )?;
            }
        }
    }
    for table in ["session_grants", "session_history"] {
        let mut stmt = conn.prepare(&format!(
            "SELECT rowid, prompt_append, generated_notes_json, allow_json, deny_json, allow_exact_json, deny_exact_json FROM {table}"
        ))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (rowid, prompt, notes, allow, deny, allow_exact, deny_exact) in rows {
            let sanitized_prompt = prompt.as_deref().map(redact_output_text);
            let sanitized_notes = sanitize_string_vec_json(&notes);
            let sanitized_allow = sanitize_string_vec_json(&allow);
            let sanitized_deny = sanitize_string_vec_json(&deny);
            let sanitized_allow_exact = sanitize_exact_rules_json(&allow_exact);
            let sanitized_deny_exact = sanitize_exact_rules_json(&deny_exact);
            if sanitized_prompt != prompt
                || sanitized_notes != notes
                || sanitized_allow != allow
                || sanitized_deny != deny
                || sanitized_allow_exact != allow_exact
                || sanitized_deny_exact != deny_exact
            {
                conn.execute(
                    &format!(
                        "UPDATE {table}
                         SET prompt_append = ?1, generated_notes_json = ?2, allow_json = ?3,
                             deny_json = ?4, allow_exact_json = ?5, deny_exact_json = ?6
                         WHERE rowid = ?7"
                    ),
                    params![
                        sanitized_prompt,
                        sanitized_notes,
                        sanitized_allow,
                        sanitized_deny,
                        sanitized_allow_exact,
                        sanitized_deny_exact,
                        rowid
                    ],
                )?;
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
            let sanitized = sanitize_grant_request(request);
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
            if approval.snapshot.env.is_empty() {
                continue;
            }
            approval.snapshot.env.clear();
            if matches!(
                approval.status,
                ApprovalStatus::Pending | ApprovalStatus::Approving
            ) {
                approval.status = ApprovalStatus::ExecFailed;
                approval.decided_unix = Some(guard::env::now_unix());
                approval.decided_reason = Some(
                    "plain environment values were removed from persisted approval state"
                        .to_string(),
                );
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
    Ok(())
}

/// Sanitize the string members of one persisted `DecisionTrace`. Unreadable
/// JSON is left untouched: the load path already tolerates and reports it.
fn sanitize_decision_trace_json(json: &str) -> String {
    let Ok(mut trace) = serde_json::from_str::<guard::gating::DecisionTrace>(json) else {
        return json.to_string();
    };
    for field in [
        &mut trace.conflict,
        &mut trace.guidance,
        &mut trace.suggested_grant_delta,
    ] {
        if let Some(value) = field.as_mut() {
            *value = redact_output_text(value);
        }
    }
    serde_json::to_string(&trace).unwrap_or_else(|_| json.to_string())
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

fn sanitize_exact_rules_json(json: &str) -> String {
    let Ok(mut rules) = serde_json::from_str::<Vec<SessionExactRule>>(json) else {
        return json.to_string();
    };
    for rule in &mut rules {
        rule.binary = redact_output_text(&rule.binary);
        for arg in &mut rule.args {
            *arg = redact_output_text(arg);
        }
    }
    serde_json::to_string(&rules).unwrap_or_else(|_| json.to_string())
}

fn should_vacuum(page_count: u64, free_pages: u64) -> bool {
    page_count >= VACUUM_MIN_PAGES
        && free_pages >= VACUUM_MIN_FREE_PAGES
        && free_pages.saturating_mul(4) >= page_count
}

fn encode_vec(values: &[String]) -> Result<String> {
    serde_json::to_string(values).context("failed to encode session list")
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
            Ok(_) if crate::server::secure_fs::harden_existing_private_path(&candidate, false) => {}
            Ok(_) => anyhow::bail!(
                "state database file {} is not daemon-only",
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
                forward_done: true,
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
            forward_done: true,
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
                    FIXTURE_BEARER_JWT
                )),
                ..Default::default()
            },
            format!(
                "curl -H 'Authorization: Bearer {}' /status",
                FIXTURE_BEARER_JWT
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
        assert!(!stored.contains(FIXTURE_BEARER_JWT));
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
        pending.requested_uses = Some(4);
        pending.issued_session_revision = registry.effective_revision_key(&token);
        store.save_grant_request(pending.clone()).await.unwrap();
        let mut approved = pending.clone();
        approved.requested_uses = Some(2);
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
        assert_eq!(committed_request.requested_uses, Some(2));
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
                static_only: true,
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
            forward_done: true,
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
                static_only: true,
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
                static_only: true,
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
                exposed_secret_refs: Vec::new(),
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
    const FIXTURE_BEARER_JWT: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6IlN5bnRoZXRpYyJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50In0.SyntheticSignature123";
    const FIXTURE_PASSWORD_FLAG: &str = "--password=SyntheticHunter2Value";

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
                        vec![format!("--token={FIXTURE_BEARER_JWT}"), "get".to_string()],
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
                    format!("kubectl --token={FIXTURE_BEARER_JWT} get pods"),
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
        assert_eq!(rules[0].binary, "kubectl");
        assert!(rules[0].args[0].contains("[REDACTED]"));
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
        assert!(report.recent[0].exposed_secret_refs.is_empty());
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
                    exposed_secret_refs: Vec::new(),
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
    async fn current_schema_rejects_plain_environment_values_in_approval_rows() {
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

        let error = store
            .load_approvals()
            .await
            .expect_err("current-schema approval environment must fail closed");
        assert!(error.to_string().contains("prohibited plain environment"));
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
                    exposed_secret_refs: vec!["service/token".into()],
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
        assert_eq!(report.recent[0].exposed_secret_refs, vec!["service/token"]);
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
}
