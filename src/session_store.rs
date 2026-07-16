use crate::grant_profile::{GrantRequest, SavedGrant};
use crate::session::{
    session_grant_revision_key, HistoricalGrant, HistoricalStatus, IssuedGrantScope,
    SessionDecisionSource, SessionExactRule, SessionExecStatus, SessionGrant, SessionInteraction,
    SessionRegistry,
};
use anyhow::{Context, Result};
use guard::gating::approval::Approval;
use guard::gating::provisional::Provisional;
use guard::gating::read_grant::ReadGrant;
use guard::redact::redact_output_text;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

/// Version 6 sanitizes persisted command-derived text (recorded argv, deny
/// reasons, prompts, learned exact rules) with credential redaction; see
/// `sanitize_persisted_credentials`.
const SCHEMA_VERSION: i64 = 6;
const VACUUM_MIN_PAGES: u64 = 512;
const VACUUM_MIN_FREE_PAGES: u64 = 128;

#[derive(Debug, Clone)]
pub struct SessionStore {
    path: PathBuf,
    history_retention_secs: u64,
    /// Serializes session-registry writes and records the revision of the last
    /// snapshot written. The registry is persisted as a full-table rewrite, so
    /// two concurrent persists completing out of order would let a stale
    /// snapshot clobber a newer one on disk; the writer holds this lock across
    /// the rewrite and drops any snapshot older than what already landed.
    /// Shared across clones so every handle to the same store agrees.
    registry_write_gate: std::sync::Arc<tokio::sync::Mutex<u64>>,
    #[cfg(test)]
    fail_next_write: std::sync::Arc<std::sync::atomic::AtomicBool>,
    #[cfg(test)]
    fail_next_approval: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl SessionStore {
    pub async fn open(path: PathBuf, history_retention_secs: u64) -> Result<Self> {
        let path_for_open = path.clone();
        tokio::task::spawn_blocking(move || Self::open_sync(path_for_open, history_retention_secs))
            .await
            .context("session store open task failed")?
    }

    pub async fn load_registry(&self) -> Result<SessionRegistry> {
        let path = self.path.clone();
        let retention = self.history_retention_secs;
        tokio::task::spawn_blocking(move || Self::load_registry_sync(&path, retention))
            .await
            .context("session store load task failed")?
    }

    pub async fn persist_registry(&self, registry: &SessionRegistry) -> Result<()> {
        let path = self.path.clone();
        let retention = self.history_retention_secs;
        let mut snapshot = registry.clone().with_history_retention(retention);
        snapshot.purge_expired();
        let revision = snapshot.revision();
        let mut last_written = self.registry_write_gate.lock().await;
        if revision < *last_written {
            // A newer snapshot already landed; a full-table rewrite from this
            // one would roll the on-disk state back.
            return Ok(());
        }
        tokio::task::spawn_blocking(move || {
            Self::persist_registry_sync(&path, retention, &snapshot)
        })
        .await
        .context("session store persist task failed")??;
        *last_written = revision;
        Ok(())
    }

    fn open_sync(path: PathBuf, history_retention_secs: u64) -> Result<Self> {
        let store = Self {
            path,
            history_retention_secs,
            registry_write_gate: std::sync::Arc::new(tokio::sync::Mutex::new(0)),
            #[cfg(test)]
            fail_next_write: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            #[cfg(test)]
            fail_next_approval: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let registry = Self::load_registry_sync(&store.path, history_retention_secs)?;
        Self::persist_registry_sync(&store.path, history_retention_secs, &registry)?;
        Ok(store)
    }

    fn load_registry_sync(path: &Path, history_retention_secs: u64) -> Result<SessionRegistry> {
        let conn = Self::open_connection(path)?;
        Self::init_schema(&conn)?;

        let mut grants = HashMap::new();
        {
            let mut stmt = conn.prepare(
                "SELECT token, allow_json, deny_json, allow_exact_json, deny_exact_json, activated_verbs_json, override_markers_json, scope_json, expires_at, prompt_append, generated_notes_json, granted_at, static_only, auto_amend
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
                    },
                ))
            })?;
            for row in rows {
                let (token, grant) = row?;
                grants.insert(token, grant);
            }
        }

        let mut history = Vec::new();
        {
            let mut stmt = conn.prepare(
                "SELECT token, allow_json, deny_json, allow_exact_json, deny_exact_json, activated_verbs_json, override_markers_json, scope_json, granted_at, expires_at, ended_at, status, prompt_append, generated_notes_json, static_only, auto_amend
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
                })
            })?;
            for row in rows {
                history.push(row?);
            }
        }

        let mut interactions = Vec::new();
        {
            let mut stmt = conn.prepare(
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
        Ok(registry)
    }

    fn persist_registry_sync(
        path: &Path,
        history_retention_secs: u64,
        registry: &SessionRegistry,
    ) -> Result<()> {
        let conn = Self::open_connection(path)?;
        Self::init_schema(&conn)?;
        let tx = conn.unchecked_transaction()?;

        Self::rewrite_registry_transaction(&tx, history_retention_secs, registry)?;
        tx.commit()?;
        Ok(())
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
                 (token, allow_json, deny_json, allow_exact_json, deny_exact_json, activated_verbs_json, override_markers_json, scope_json, expires_at, prompt_append, generated_notes_json, granted_at, static_only, auto_amend)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
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
                    encode_bool(grant.auto_amend)
                ],
            )?;
        }

        for grant in snapshot.history_snapshot() {
            tx.execute(
                "INSERT INTO session_history
                 (token, allow_json, deny_json, allow_exact_json, deny_exact_json, activated_verbs_json, override_markers_json, scope_json, granted_at, expires_at, ended_at, status, prompt_append, generated_notes_json, static_only, auto_amend)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
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
                    encode_bool(grant.auto_amend)
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
            "SELECT allow_json, deny_json, allow_exact_json, deny_exact_json, activated_verbs_json, override_markers_json, scope_json, expires_at, prompt_append, generated_notes_json, granted_at, static_only, auto_amend
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
            Self::repair_current_schema(conn)?;
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
                auto_amend INTEGER NOT NULL DEFAULT 0
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
                auto_amend INTEGER NOT NULL DEFAULT 0
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
            );",
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
        // Databases written before schema v6 may hold credential material that
        // transited a command line (recorded argv, learned rules, prompts).
        // Sanitize once as part of the migration; the version bump below makes
        // this pass run exactly once per database.
        sanitize_persisted_credentials(&tx)?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tx.commit()?;
        Ok(())
    }

    /// Repair columns that belong to the current schema version. This keeps
    /// startup safe after an interrupted or partially applied current migration.
    fn repair_current_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS saved_grants (
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
            );",
        )?;
        ensure_column(
            conn,
            "session_grants",
            "activated_verbs_json",
            "TEXT NOT NULL DEFAULT '[]'",
        )?;
        ensure_column(
            conn,
            "session_grants",
            "override_markers_json",
            "TEXT NOT NULL DEFAULT '[]'",
        )?;
        ensure_column(
            conn,
            "session_grants",
            "scope_json",
            "TEXT NOT NULL DEFAULT '{}'",
        )?;
        ensure_column(
            conn,
            "session_history",
            "activated_verbs_json",
            "TEXT NOT NULL DEFAULT '[]'",
        )?;
        ensure_column(
            conn,
            "session_history",
            "override_markers_json",
            "TEXT NOT NULL DEFAULT '[]'",
        )?;
        ensure_column(
            conn,
            "session_history",
            "scope_json",
            "TEXT NOT NULL DEFAULT '{}'",
        )?;
        ensure_column(conn, "session_interactions", "exit_code", "INTEGER")?;
        ensure_column(
            conn,
            "session_interactions",
            "secret_refs_json",
            "TEXT NOT NULL DEFAULT '[]'",
        )?;
        ensure_column(conn, "session_interactions", "decision_trace_json", "TEXT")?;
        Ok(())
    }

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
        self.load_json_rows("SELECT json FROM saved_grants", "saved grant")
            .await
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
        let path = self.path.clone();
        let retention = self.history_retention_secs;
        let revision = registry.revision();
        let mut last_written = self.registry_write_gate.lock().await;
        if revision < *last_written {
            anyhow::bail!("approved session snapshot is stale");
        }
        tokio::task::spawn_blocking(move || {
            Self::commit_grant_request_approval_sync(
                &path, retention, &pending, &approved, &registry, false,
            )
        })
        .await
        .context("grant request approval transaction task failed")??;
        *last_written = revision;
        Ok(())
    }

    fn commit_grant_request_approval_sync(
        path: &Path,
        history_retention_secs: u64,
        pending: &GrantRequest,
        approved: &GrantRequest,
        registry: &SessionRegistry,
        fail_before_commit: bool,
    ) -> Result<()> {
        if pending.status != crate::grant_profile::GrantRequestStatus::Pending
            || approved.status != crate::grant_profile::GrantRequestStatus::Approved
            || approved.handle != pending.handle
            || approved.session_token != pending.session_token
            || approved.issued_saved_revision != pending.issued_saved_revision
            || approved.issued_session_revision != pending.issued_session_revision
            || approved.delta != pending.delta
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
        let durable_grant = Self::load_session_grant(&tx, &pending.session_token)?
            .context("durable session for grant request is missing")?;
        if durable_grant.is_expired(guard::env::now_unix())
            || session_grant_revision_key(&durable_grant) != pending.issued_session_revision
        {
            anyhow::bail!("durable session changed after grant request issuance");
        }

        Self::rewrite_registry_transaction(&tx, history_retention_secs, registry)?;
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
        if fail_before_commit {
            anyhow::bail!("simulated crash before approval transaction commit");
        }
        tx.commit()?;
        Ok(())
    }

    pub async fn load_grant_requests(&self) -> Result<Vec<GrantRequest>> {
        self.load_json_rows("SELECT json FROM grant_requests", "grant request")
            .await
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

    async fn load_json_rows<T>(&self, query: &'static str, kind: &'static str) -> Result<Vec<T>>
    where
        T: serde::de::DeserializeOwned + Send + 'static,
    {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Self::open_connection(&path)?;
            Self::init_schema(&conn)?;
            let mut stmt = conn.prepare(query)?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            let mut values = Vec::new();
            for row in rows {
                let json = row?;
                match serde_json::from_str::<T>(&json) {
                    Ok(value) => values.push(value),
                    Err(error) => tracing::warn!("skipping unreadable {} row: {}", kind, error),
                }
            }
            Ok(values)
        })
        .await
        .with_context(|| format!("load {kind} task failed"))?
    }

    // --- Consequence-gating runtime state (provisional executions and operator
    // approvals). These are high-churn, handle-keyed rows, so unlike the session
    // registry they persist incrementally (per-row upsert/delete) rather than by
    // full-table snapshot, and a provisional is committed before its forward
    // command runs so a crash still leaves a recoverable revert.

    pub async fn save_provisional(&self, p: Provisional) -> Result<()> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Self::open_connection(&path)?;
            Self::init_schema(&conn)?;
            let json = serde_json::to_string(&p).context("encode provisional")?;
            conn.execute(
                "INSERT OR REPLACE INTO gating_provisional (handle, json, status, created_unix)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    p.handle,
                    json,
                    p.status.as_str(),
                    encode_u64(p.created_unix)?
                ],
            )?;
            Ok(())
        })
        .await
        .context("save_provisional task failed")?
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
            let mut stmt = conn.prepare("SELECT json FROM gating_provisional")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            let mut out = Vec::new();
            for row in rows {
                let json = row?;
                match serde_json::from_str::<Provisional>(&json) {
                    Ok(p) => out.push(p),
                    Err(e) => tracing::warn!("skipping unreadable provisional row: {}", e),
                }
            }
            Ok(out)
        })
        .await
        .context("load_provisionals task failed")?
    }

    pub async fn save_approval(&self, a: Approval) -> Result<()> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Self::open_connection(&path)?;
            Self::init_schema(&conn)?;
            let json = serde_json::to_string(&a).context("encode approval")?;
            conn.execute(
                "INSERT OR REPLACE INTO gating_approval (handle, json, status, created_unix)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    a.handle,
                    json,
                    a.status.as_str(),
                    encode_u64(a.created_unix)?
                ],
            )?;
            Ok(())
        })
        .await
        .context("save_approval task failed")?
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
            let mut stmt = conn.prepare("SELECT json FROM gating_approval")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            let mut out = Vec::new();
            for row in rows {
                let json = row?;
                match serde_json::from_str::<Approval>(&json) {
                    Ok(a) => out.push(a),
                    Err(e) => tracing::warn!("skipping unreadable approval row: {}", e),
                }
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
            let mut stmt = conn.prepare("SELECT json FROM read_grants")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            let mut out = Vec::new();
            for row in rows {
                let json = row?;
                match serde_json::from_str::<ReadGrant>(&json) {
                    Ok(g) => out.push(g),
                    Err(e) => tracing::warn!("skipping unreadable read-grant row: {}", e),
                }
            }
            Ok(out)
        })
        .await
        .context("load_read_grants task failed")?
    }
}

/// One-time migration pass (schema v6): run credential redaction over
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

#[cfg(not(unix))]
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

#[cfg(not(unix))]
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

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        std::fs::symlink_metadata(path).unwrap().mode() & 0o777
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn state_store_creates_private_parent_database_and_sidecars() {
        let tmp = tempfile::tempdir().unwrap();
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
        let tmp = tempfile::tempdir().unwrap();
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
        let tmp = tempfile::tempdir().unwrap();
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

        let error = SessionStore::commit_grant_request_approval_sync(
            &path, 3600, &pending, &approved, &staged, true,
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
            .commit_grant_request_approval(pending, approved, staged)
            .await
            .unwrap();
        let committed = SessionStore::open(path, 3600).await.unwrap();
        assert_eq!(
            committed.load_grant_requests().await.unwrap()[0].status,
            crate::grant_profile::GrantRequestStatus::Approved
        );
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
