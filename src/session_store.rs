use crate::session::{
    HistoricalGrant, HistoricalStatus, SessionDecisionSource, SessionExecStatus, SessionGrant,
    SessionInteraction, SessionRegistry,
};
use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct SessionStore {
    path: PathBuf,
    history_retention_secs: u64,
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
        let mut snapshot = registry.clone();
        tokio::task::spawn_blocking(move || {
            snapshot.purge_expired();
            Self::persist_registry_sync(&path, retention, &snapshot)
        })
        .await
        .context("session store persist task failed")?
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn open_sync(path: PathBuf, history_retention_secs: u64) -> Result<Self> {
        let store = Self {
            path,
            history_retention_secs,
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
                "SELECT token, allow_json, deny_json, expires_at, prompt_append, granted_at
                 FROM session_grants",
            )?;
            let rows = stmt.query_map([], |row| {
                let token: String = row.get(0)?;
                let allow_json: String = row.get(1)?;
                let deny_json: String = row.get(2)?;
                Ok((
                    token,
                    SessionGrant {
                        allow: decode_vec(&allow_json)?,
                        deny: decode_vec(&deny_json)?,
                        expires_at: decode_optional_u64(row.get(3)?)?,
                        prompt_append: row.get(4)?,
                        granted_at: decode_u64(row.get(5)?)?,
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
                "SELECT token, allow_json, deny_json, granted_at, expires_at, ended_at, status, prompt_append
                 FROM session_history
                 ORDER BY ended_at ASC, id ASC",
            )?;
            let rows = stmt.query_map([], |row| {
                let allow_json: String = row.get(1)?;
                let deny_json: String = row.get(2)?;
                let status: String = row.get(6)?;
                Ok(HistoricalGrant {
                    token: row.get(0)?,
                    allow: decode_vec(&allow_json)?,
                    deny: decode_vec(&deny_json)?,
                    granted_at: decode_u64(row.get(3)?)?,
                    expires_at: decode_optional_u64(row.get(4)?)?,
                    ended_at: decode_u64(row.get(5)?)?,
                    status: decode_historical_status(&status)?,
                    prompt_append: row.get(7)?,
                })
            })?;
            for row in rows {
                history.push(row?);
            }
        }

        let mut interactions = Vec::new();
        {
            let mut stmt = conn.prepare(
                "SELECT token, at_unix, command, allowed, source, reason, risk, exec_status
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
                 (token, allow_json, deny_json, expires_at, prompt_append, granted_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    token,
                    encode_vec(&grant.allow)?,
                    encode_vec(&grant.deny)?,
                    encode_optional_u64(grant.expires_at)?,
                    grant.prompt_append,
                    encode_u64(grant.granted_at)?
                ],
            )?;
        }

        for grant in snapshot.history_snapshot() {
            tx.execute(
                "INSERT INTO session_history
                 (token, allow_json, deny_json, granted_at, expires_at, ended_at, status, prompt_append)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    grant.token,
                    encode_vec(&grant.allow)?,
                    encode_vec(&grant.deny)?,
                    encode_u64(grant.granted_at)?,
                    encode_optional_u64(grant.expires_at)?,
                    encode_u64(grant.ended_at)?,
                    encode_historical_status(grant.status),
                    grant.prompt_append
                ],
            )?;
        }

        for (token, interaction) in snapshot.interactions_snapshot() {
            tx.execute(
                "INSERT INTO session_interactions
                 (token, at_unix, command, allowed, source, reason, risk, exec_status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    token,
                    encode_u64(interaction.at_unix)?,
                    interaction.command,
                    if interaction.allowed { 1 } else { 0 },
                    encode_decision_source(interaction.source),
                    interaction.reason,
                    interaction.risk,
                    encode_exec_status(interaction.exec_status)
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    fn open_connection(path: &Path) -> Result<Connection> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let conn =
            Connection::open(path).with_context(|| format!("failed to open {}", path.display()))?;
        conn.busy_timeout(Duration::from_secs(2))?;
        Ok(conn)
    }

    fn init_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS session_grants (
                token TEXT PRIMARY KEY,
                allow_json TEXT NOT NULL,
                deny_json TEXT NOT NULL,
                expires_at INTEGER,
                prompt_append TEXT,
                granted_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS session_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT NOT NULL,
                allow_json TEXT NOT NULL,
                deny_json TEXT NOT NULL,
                granted_at INTEGER NOT NULL,
                expires_at INTEGER,
                ended_at INTEGER NOT NULL,
                status TEXT NOT NULL,
                prompt_append TEXT
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
                exec_status TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_session_interactions_token ON session_interactions(token);
            CREATE INDEX IF NOT EXISTS idx_session_interactions_at ON session_interactions(at_unix);",
        )?;
        Ok(())
    }
}

fn encode_vec(values: &[String]) -> Result<String> {
    serde_json::to_string(values).context("failed to encode session list")
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

fn decode_vec(value: &str) -> rusqlite::Result<Vec<String>> {
    serde_json::from_str(value).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Text,
            Box::new(err),
        )
    })
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
        SessionDecisionSource::Llm => "llm",
        SessionDecisionSource::StaticPolicy => "static_policy",
        SessionDecisionSource::Validation => "validation",
        SessionDecisionSource::EvaluatorError => "evaluator_error",
    }
}

fn decode_decision_source(value: &str) -> rusqlite::Result<SessionDecisionSource> {
    match value {
        "session_allow" => Ok(SessionDecisionSource::SessionAllow),
        "session_deny" => Ok(SessionDecisionSource::SessionDeny),
        "llm" => Ok(SessionDecisionSource::Llm),
        "static_policy" => Ok(SessionDecisionSource::StaticPolicy),
        "validation" => Ok(SessionDecisionSource::Validation),
        "evaluator_error" => Ok(SessionDecisionSource::EvaluatorError),
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
        SessionExecStatus::Failed => "failed",
        SessionExecStatus::DryRun => "dry_run",
    }
}

fn decode_exec_status(value: &str) -> rusqlite::Result<SessionExecStatus> {
    match value {
        "not_attempted" => Ok(SessionExecStatus::NotAttempted),
        "completed" => Ok(SessionExecStatus::Completed),
        "failed" => Ok(SessionExecStatus::Failed),
        "dry_run" => Ok(SessionExecStatus::DryRun),
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

    #[tokio::test]
    async fn session_store_round_trips_registry() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = SessionStore::open(tmp.path().join("state.db"), 24 * 60 * 60)
            .await
            .expect("open store");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);

        let mut grants = HashMap::new();
        grants.insert(
            "tok".to_string(),
            SessionGrant {
                allow: vec!["echo*".into()],
                deny: vec!["rm*".into()],
                expires_at: None,
                prompt_append: Some("persistent".into()),
                granted_at: now.saturating_sub(2),
            },
        );
        let registry = SessionRegistry::from_parts(
            grants,
            vec![HistoricalGrant {
                token: "old".into(),
                allow: vec!["ls*".into()],
                deny: Vec::new(),
                granted_at: now.saturating_sub(10),
                expires_at: None,
                ended_at: now.saturating_sub(5),
                status: HistoricalStatus::Revoked,
                prompt_append: None,
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
                    exec_status: SessionExecStatus::Completed,
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
        assert_eq!(report.stats.risk_histogram[1], 1);
        assert_eq!(
            report.active.and_then(|grant| grant.prompt_append),
            Some("persistent".into())
        );
        assert_eq!(loaded.list_history(None).len(), 1);
    }
}
