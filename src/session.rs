//! Session grant registry and reporting model.
//!
//! A session is an opaque bearer token the caller includes in `ExecuteRequest`.
//! Saved grants attach typed verb coverage, evaluator context, secret-name
//! entitlements, and an evaluation mode to that token. Session-scoped coverage
//! remains inside the server binary floor, consequence routing, held-command
//! snapshot binding, audit logging, and session recording. Legacy allow and
//! deny patterns remain serialized only for migration compatibility.
//!
//! The daemon keeps a live in-memory registry for fast decision checks,
//! while `session_store.rs` persists grants and bounded interaction
//! history across daemon restarts.

use crate::grant_profile::{EvaluationMode, GrantRequestDelta};
use guard::env::now_unix;
use guard::policy::{Decision, PolicyRule};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

/// Default daemon-side history retention. Anything older than this is
/// dropped on the next opportunistic purge. 24h matches the "I want
/// to debug what an agent did yesterday" use case without growing the
/// persisted interaction history unboundedly.
pub const DEFAULT_HISTORY_RETENTION_SECS: u64 = 24 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionGrant {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_exact: Vec<SessionExactRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_exact: Vec<SessionExactRule>,
    /// Catalog verbs activated only while this session grant is live.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub activated_verbs: Vec<String>,
    /// Exact operator-issued markers that may override matching baseline
    /// evaluate or deny cells. Automatic promotion never writes this field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub override_markers: Vec<String>,
    /// Saved-grant identity, label, entitlements, and per-session evaluator
    /// posture. One nested field keeps compatibility migrations atomic.
    #[serde(default)]
    pub scope: IssuedGrantScope,
    /// Unix seconds after which this grant is treated as absent.
    pub expires_at: Option<u64>,
    /// Free-form text appended to the LLM system prompt for evaluator
    /// calls made under this session token. Use to give the model
    /// task context typed verb coverage does not encode, e.g. "this
    /// session is restoring a Postgres backup; treat pg_restore and
    /// related psql copy commands as expected".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_append: Option<String>,
    /// Human-readable migration notes. These are displayed to the operator but
    /// are not appended to the evaluator prompt.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub generated_notes: Vec<String>,
    /// If true, commands outside activated verb coverage are denied instead of
    /// falling through to the evaluator.
    #[serde(default)]
    pub static_only: bool,
    /// Legacy compatibility bit for exact session amendments.
    #[serde(default)]
    pub auto_amend: bool,
    /// Unix seconds when the grant was installed. Used by `session
    /// list` to show grant age.
    #[serde(default)]
    pub granted_at: u64,
}

pub(crate) fn session_grant_revision_key(grant: &SessionGrant) -> Option<String> {
    let encoded = serde_json::to_vec(grant).ok()?;
    let digest = sha2::Sha256::digest(encoded);
    Some(
        digest[..16]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct IssuedGrantScope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saved_grant: Option<String>,
    #[serde(default)]
    pub saved_revision: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_names: Vec<String>,
    #[serde(default)]
    pub evaluation_mode: EvaluationMode,
}

impl SessionGrant {
    pub fn is_expired(&self, now: u64) -> bool {
        matches!(self.expires_at, Some(exp) if now >= exp)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionExactRule {
    pub binary: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<PathBuf>,
}

impl SessionExactRule {
    #[allow(dead_code)]
    pub fn new(binary: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            binary: binary.into(),
            args,
            cwd: None,
        }
    }

    #[allow(dead_code)]
    pub fn with_cwd(binary: impl Into<String>, args: Vec<String>, cwd: PathBuf) -> Self {
        Self {
            binary: binary.into(),
            args,
            cwd: Some(cwd),
        }
    }

    pub fn command_line(&self) -> String {
        command_line(&self.binary, &self.args)
    }

    fn matches_base(&self, cmd: &str, args: &[String]) -> bool {
        self.binary == cmd && self.args == args
    }

    fn matches_deny(&self, cmd: &str, args: &[String], cwd: Option<&Path>) -> bool {
        self.matches_base(cmd, args)
            && self
                .cwd
                .as_deref()
                .is_none_or(|rule_cwd| cwd.is_some_and(|cwd| cwd == rule_cwd))
    }

    fn matches_allow(&self, cmd: &str, args: &[String], cwd: Option<&Path>) -> bool {
        self.matches_base(cmd, args) && self.cwd.as_deref() == cwd
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalStatus {
    Revoked,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalGrant {
    pub token: String,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_exact: Vec<SessionExactRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_exact: Vec<SessionExactRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub activated_verbs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub override_markers: Vec<String>,
    #[serde(default)]
    pub scope: IssuedGrantScope,
    pub granted_at: u64,
    pub expires_at: Option<u64>,
    /// Unix seconds when the grant left the active set.
    pub ended_at: u64,
    pub status: HistoricalStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_append: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub generated_notes: Vec<String>,
    #[serde(default)]
    pub static_only: bool,
    #[serde(default)]
    pub auto_amend: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAmendment {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionGrantSummary {
    pub token: String,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_exact: Vec<SessionExactRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_exact: Vec<SessionExactRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub activated_verbs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub override_markers: Vec<String>,
    #[serde(default)]
    pub scope: IssuedGrantScope,
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub granted_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_append: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub generated_notes: Vec<String>,
    #[serde(default)]
    pub static_only: bool,
    #[serde(default)]
    pub auto_amend: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionDecisionSource {
    SessionAllow,
    SessionDeny,
    SessionStaticOnly,
    Llm,
    Cache,
    StaticPolicy,
    /// A deny fast path the daemon synthesized itself from repeated LLM
    /// denials of this shape (`gating::deny_shape`). Kept distinct from
    /// `StaticPolicy` (operator-authored) for audit clarity.
    LearnedDeny,
    Validation,
    EvaluatorError,
}

impl SessionDecisionSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::SessionAllow => "session_allow",
            Self::SessionDeny => "session_deny",
            Self::SessionStaticOnly => "session_static_only",
            Self::Llm => "llm",
            Self::Cache => "cache",
            Self::StaticPolicy => "static_policy",
            Self::LearnedDeny => "learned_deny",
            Self::Validation => "validation",
            Self::EvaluatorError => "evaluator_error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionExecStatus {
    NotAttempted,
    Completed,
    Failed,
    DryRun,
    /// Approved but held for operator approval (consequence gating); not run.
    Held,
    /// Executed inside a containment envelope (consequence gating).
    Provisional,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInteraction {
    pub at_unix: u64,
    pub command: String,
    pub allowed: bool,
    pub source: SessionDecisionSource,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<i32>,
    pub exec_status: SessionExecStatus,
    /// Child exit status when the command reached a terminal process result.
    /// `None` also covers signals and paths where no child was started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Secret-store key names whose values entered the environment of a
    /// successfully spawned child. This records exposure, not proof that the
    /// child read or consumed a value. Values are never persisted.
    #[serde(default, alias = "secret_refs", skip_serializing_if = "Vec::is_empty")]
    pub exposed_secret_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStats {
    pub total: u64,
    pub allowed: u64,
    pub denied: u64,
    pub completed: u64,
    pub exec_failed: u64,
    pub dry_run: u64,
    pub not_attempted: u64,
    pub source_counts: BTreeMap<String, u64>,
    pub risk_histogram: Vec<u64>,
    #[serde(default)]
    pub evaluator_calls: u64,
    #[serde(default)]
    pub cache_hits: u64,
    #[serde(default)]
    pub holds: u64,
    #[serde(default)]
    pub novel_shapes: u64,
    #[serde(default)]
    pub novel_shape_rate_percent: u8,
    #[serde(default)]
    pub suspended: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspension_reason: Option<String>,
}

impl Default for SessionStats {
    fn default() -> Self {
        Self {
            total: 0,
            allowed: 0,
            denied: 0,
            completed: 0,
            exec_failed: 0,
            dry_run: 0,
            not_attempted: 0,
            source_counts: BTreeMap::new(),
            risk_histogram: vec![0; 11],
            evaluator_calls: 0,
            cache_hits: 0,
            holds: 0,
            novel_shapes: 0,
            novel_shape_rate_percent: 0,
            suspended: false,
            suspension_reason: None,
        }
    }
}

/// Optional daemon-wide behavioral circuit breakers. `None` thresholds are
/// disabled so a default deployment remains deploy-and-forget.
#[derive(Debug, Clone, Default)]
pub struct SessionBehaviorLimits {
    pub window_secs: u64,
    pub max_denials: Option<u64>,
    pub max_holds: Option<u64>,
    pub max_deny_ratio_percent: Option<u8>,
    pub min_commands_for_ratio: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionReport {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<SessionGrantSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<HistoricalGrant>,
    pub stats: SessionStats,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recent: Vec<SessionInteraction>,
}

#[derive(Debug, Clone)]
struct StoredSessionInteraction {
    token: String,
    interaction: SessionInteraction,
}

#[derive(Debug, Clone)]
pub struct SessionRegistry {
    grants: HashMap<String, SessionGrant>,
    history: Vec<HistoricalGrant>,
    interactions: Vec<StoredSessionInteraction>,
    history_retention_secs: u64,
    /// Monotonic mutation counter, bumped by every state-changing operation
    /// (all of which run under the registry's write lock). A snapshot clone
    /// carries the revision of the state it represents, so the store can
    /// refuse to overwrite newer on-disk state with a stale snapshot when
    /// concurrent persists complete out of order. Expiry and retention pruning
    /// also bump the revision when they remove state, so every distinct
    /// persistable snapshot has a distinct revision.
    revision: u64,
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self {
            grants: HashMap::new(),
            history: Vec::new(),
            interactions: Vec::new(),
            history_retention_secs: DEFAULT_HISTORY_RETENTION_SECS,
            revision: 0,
        }
    }
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_history_retention(mut self, secs: u64) -> Self {
        self.history_retention_secs = secs;
        self
    }

    pub fn from_parts(
        grants: HashMap<String, SessionGrant>,
        history: Vec<HistoricalGrant>,
        interactions: Vec<(String, SessionInteraction)>,
        history_retention_secs: u64,
    ) -> Self {
        Self {
            grants,
            history,
            interactions: interactions
                .into_iter()
                .map(|(token, interaction)| StoredSessionInteraction { token, interaction })
                .collect(),
            history_retention_secs,
            revision: 0,
        }
    }

    /// The revision of the state this registry (or snapshot clone) represents.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn grants_snapshot(&self) -> HashMap<String, SessionGrant> {
        self.grants.clone()
    }

    pub fn history_snapshot(&self) -> Vec<HistoricalGrant> {
        self.history.clone()
    }

    pub fn interactions_snapshot(&self) -> Vec<(String, SessionInteraction)> {
        self.interactions
            .iter()
            .map(|entry| (entry.token.clone(), entry.interaction.clone()))
            .collect()
    }

    pub fn grant(&mut self, token: String, mut grant: SessionGrant) {
        self.revision += 1;
        if grant.granted_at == 0 {
            grant.granted_at = now_unix();
        }
        // If we are overwriting an active grant, archive the previous
        // version so the audit trail still shows what was in effect.
        if let Some(prev) = self.grants.remove(&token) {
            self.history.push(historical(
                &token,
                prev,
                now_unix(),
                HistoricalStatus::Revoked,
            ));
        }
        self.grants.insert(token, grant);
    }

    pub fn revoke(&mut self, token: &str) -> bool {
        let Some(grant) = self.grants.remove(token) else {
            return false;
        };
        self.revision += 1;
        self.history.push(historical(
            token,
            grant,
            now_unix(),
            HistoricalStatus::Revoked,
        ));
        true
    }

    /// True if this token currently maps to a non-expired grant.
    pub fn has(&self, token: &str) -> bool {
        let Some(grant) = self.grants.get(token) else {
            return false;
        };
        !grant.is_expired(now_unix())
    }

    pub fn list(&self) -> Vec<SessionGrantSummary> {
        let now = now_unix();
        self.grants
            .iter()
            .filter(|(_, g)| !g.is_expired(now))
            .map(|(token, g)| SessionGrantSummary {
                token: token.clone(),
                allow: g.allow.clone(),
                deny: g.deny.clone(),
                allow_exact: g.allow_exact.clone(),
                deny_exact: g.deny_exact.clone(),
                activated_verbs: g.activated_verbs.clone(),
                override_markers: g.override_markers.clone(),
                scope: g.scope.clone(),
                expires_at: g.expires_at,
                granted_at: g.granted_at,
                prompt_append: g.prompt_append.clone(),
                generated_notes: g.generated_notes.clone(),
                static_only: g.static_only,
                auto_amend: g.auto_amend,
            })
            .collect()
    }

    /// Return historical grants no older than `since_unix`. When
    /// `since_unix` is None, return everything still in retention.
    pub fn list_history(&self, since_unix: Option<u64>) -> Vec<HistoricalGrant> {
        self.history
            .iter()
            .filter(|h| match since_unix {
                Some(t) => h.ended_at >= t,
                None => true,
            })
            .cloned()
            .collect()
    }

    pub fn record_interaction(&mut self, token: &str, mut interaction: SessionInteraction) {
        self.revision += 1;
        if interaction.at_unix == 0 {
            interaction.at_unix = now_unix();
        }
        self.interactions.push(StoredSessionInteraction {
            token: token.to_string(),
            interaction,
        });
    }

    #[cfg(test)]
    pub fn show(&self, token: &str, limit: usize) -> Option<SessionReport> {
        self.show_with_limits(token, limit, &SessionBehaviorLimits::default())
    }

    pub fn show_with_limits(
        &self,
        token: &str,
        limit: usize,
        limits: &SessionBehaviorLimits,
    ) -> Option<SessionReport> {
        let active = self.grants.get(token).and_then(|grant| {
            if grant.is_expired(now_unix()) {
                None
            } else {
                Some(SessionGrantSummary {
                    token: token.to_string(),
                    allow: grant.allow.clone(),
                    deny: grant.deny.clone(),
                    allow_exact: grant.allow_exact.clone(),
                    deny_exact: grant.deny_exact.clone(),
                    activated_verbs: grant.activated_verbs.clone(),
                    override_markers: grant.override_markers.clone(),
                    scope: grant.scope.clone(),
                    expires_at: grant.expires_at,
                    granted_at: grant.granted_at,
                    prompt_append: grant.prompt_append.clone(),
                    generated_notes: grant.generated_notes.clone(),
                    static_only: grant.static_only,
                    auto_amend: grant.auto_amend,
                })
            }
        });

        let history: Vec<HistoricalGrant> = self
            .history
            .iter()
            .filter(|entry| entry.token == token)
            .cloned()
            .collect();

        let matching: Vec<SessionInteraction> = self
            .interactions
            .iter()
            .filter(|entry| entry.token == token)
            .map(|entry| entry.interaction.clone())
            .collect();

        if active.is_none() && history.is_empty() && matching.is_empty() {
            return None;
        }

        let mut stats = SessionStats::default();
        for interaction in &matching {
            stats.total += 1;
            if interaction.allowed {
                stats.allowed += 1;
            } else {
                stats.denied += 1;
            }
            match interaction.exec_status {
                // Provisional commands did execute (inside a containment
                // envelope); held commands did not run. The fine-grained gating
                // states are surfaced by `guard provisionals` / `guard approvals`.
                SessionExecStatus::Completed | SessionExecStatus::Provisional => {
                    stats.completed += 1
                }
                SessionExecStatus::Failed => stats.exec_failed += 1,
                SessionExecStatus::DryRun => stats.dry_run += 1,
                SessionExecStatus::NotAttempted | SessionExecStatus::Held => {
                    stats.not_attempted += 1
                }
            }
            *stats
                .source_counts
                .entry(interaction.source.as_str().to_string())
                .or_insert(0) += 1;
            if let Some(risk) = interaction.risk {
                let bucket = risk.clamp(0, 10) as usize;
                stats.risk_histogram[bucket] += 1;
            }
            if matches!(
                interaction.source,
                SessionDecisionSource::Llm | SessionDecisionSource::EvaluatorError
            ) {
                stats.evaluator_calls += 1;
            }
            if interaction.source == SessionDecisionSource::Cache {
                stats.cache_hits += 1;
            }
            if interaction.exec_status == SessionExecStatus::Held {
                stats.holds += 1;
            }
        }
        stats.novel_shapes = matching
            .iter()
            .map(|interaction| session_command_shape(&interaction.command))
            .collect::<std::collections::HashSet<_>>()
            .len() as u64;
        stats.novel_shape_rate_percent = stats
            .novel_shapes
            .saturating_mul(100)
            .checked_div(stats.total)
            .unwrap_or(0)
            .min(100) as u8;
        stats.suspension_reason = self.suspension_reason(token, limits);
        stats.suspended = stats.suspension_reason.is_some();

        let mut recent = matching;
        if recent.len() > limit {
            recent = recent.split_off(recent.len() - limit);
        }

        Some(SessionReport {
            active,
            history,
            stats,
            recent,
        })
    }

    pub fn suspension_reason(&self, token: &str, limits: &SessionBehaviorLimits) -> Option<String> {
        if !self.has(token) {
            return None;
        }
        let cutoff = now_unix().saturating_sub(limits.window_secs.max(1));
        let window = self
            .interactions
            .iter()
            .filter(|entry| entry.token == token && entry.interaction.at_unix >= cutoff)
            .map(|entry| &entry.interaction)
            .collect::<Vec<_>>();
        let denials = window.iter().filter(|entry| !entry.allowed).count() as u64;
        let holds = window
            .iter()
            .filter(|entry| entry.exec_status == SessionExecStatus::Held)
            .count() as u64;
        if limits.max_denials.is_some_and(|limit| denials >= limit) {
            return Some(format!(
                "session suspended after {denials} denials within {}s",
                limits.window_secs.max(1)
            ));
        }
        if limits.max_holds.is_some_and(|limit| holds >= limit) {
            return Some(format!(
                "session suspended after {holds} holds within {}s",
                limits.window_secs.max(1)
            ));
        }
        let total = window.len() as u64;
        if total >= limits.min_commands_for_ratio.max(1) {
            if let Some(limit) = limits.max_deny_ratio_percent {
                let ratio = denials.saturating_mul(100) / total.max(1);
                if ratio >= u64::from(limit) {
                    return Some(format!(
                        "session suspended at {ratio}% denials ({denials}/{total}) within {}s",
                        limits.window_secs.max(1)
                    ));
                }
            }
        }
        None
    }

    /// Return the additive prompt for this session, if the grant exists,
    /// has not expired, and has a prompt attached.
    pub fn prompt_append_for(&self, token: &str) -> Option<String> {
        let grant = self.grants.get(token)?;
        if grant.is_expired(now_unix()) {
            return None;
        }
        grant.prompt_append.clone()
    }

    pub fn verb_scope_for(&self, token: &str) -> Option<(Vec<String>, Vec<String>)> {
        let grant = self.grants.get(token)?;
        if grant.is_expired(now_unix()) {
            return None;
        }
        Some((
            grant.activated_verbs.clone(),
            grant.override_markers.clone(),
        ))
    }

    pub fn static_only_for(&self, token: &str) -> bool {
        let Some(grant) = self.grants.get(token) else {
            return false;
        };
        !grant.is_expired(now_unix())
            && (grant.static_only || grant.scope.evaluation_mode == EvaluationMode::PolicyOnly)
    }

    pub fn evaluation_mode_for(&self, token: &str) -> Option<EvaluationMode> {
        let grant = self.grants.get(token)?;
        (!grant.is_expired(now_unix())).then_some(grant.scope.evaluation_mode)
    }

    pub fn saved_grant_for(&self, token: &str) -> Option<(String, u64)> {
        let grant = self.grants.get(token)?;
        if grant.is_expired(now_unix()) {
            return None;
        }
        grant
            .scope
            .saved_grant
            .clone()
            .map(|name| (name, grant.scope.saved_revision))
    }

    pub fn expires_at_for(&self, token: &str) -> Option<Option<u64>> {
        let grant = self.grants.get(token)?;
        (!grant.is_expired(now_unix())).then_some(grant.expires_at)
    }

    /// Immutable authority captured when a hold or containment envelope is
    /// created. `None` selectors mean the session is not saved-grant scoped.
    pub fn authority_snapshot(&self, token: &str) -> Option<(String, Option<Vec<String>>)> {
        let grant = self.grants.get(token)?;
        if grant.is_expired(now_unix()) {
            return None;
        }
        let selectors = grant
            .scope
            .saved_grant
            .is_some()
            .then(|| grant.scope.secret_names.clone());
        Some((self.effective_revision_key(token)?, selectors))
    }

    pub fn effective_revision_for_fingerprint(&self, fingerprint: &str) -> Option<String> {
        self.grants.keys().find_map(|token| {
            let digest = sha2::Sha256::digest(token.as_bytes());
            let candidate = format!(
                "sha256:{}",
                digest[..16]
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            );
            (candidate == fingerprint)
                .then(|| self.effective_revision_key(token))
                .flatten()
        })
    }

    pub fn effective_revision_key(&self, token: &str) -> Option<String> {
        let grant = self.grants.get(token)?;
        if grant.is_expired(now_unix()) {
            return None;
        }
        session_grant_revision_key(grant)
    }

    pub fn extend(&mut self, token: &str, ttl_secs: u64) -> Option<u64> {
        let grant = self.grants.get_mut(token)?;
        if grant.is_expired(now_unix()) {
            return None;
        }
        let expires_at = now_unix().saturating_add(ttl_secs);
        grant.expires_at = Some(expires_at);
        self.revision = self.revision.saturating_add(1);
        Some(expires_at)
    }

    pub fn set_label(&mut self, token: &str, label: Option<String>) -> Option<bool> {
        let grant = self.grants.get_mut(token)?;
        if grant.is_expired(now_unix()) {
            return None;
        }
        let changed = grant.scope.label != label;
        grant.scope.label = label;
        if changed {
            self.revision = self.revision.saturating_add(1);
        }
        Some(changed)
    }

    pub fn apply_delta(&mut self, token: &str, delta: &GrantRequestDelta) -> Option<bool> {
        let grant = self.grants.get_mut(token)?;
        if grant.is_expired(now_unix()) {
            return None;
        }
        let before = serde_json::to_vec(grant).ok()?;
        grant
            .activated_verbs
            .extend(delta.activated_verbs.iter().cloned());
        grant
            .override_markers
            .extend(delta.override_markers.iter().cloned());
        grant
            .scope
            .secret_names
            .extend(delta.secret_names.iter().cloned());
        grant.activated_verbs.sort();
        grant.activated_verbs.dedup();
        grant.override_markers.sort();
        grant.override_markers.dedup();
        grant.scope.secret_names.sort();
        grant.scope.secret_names.dedup();
        if let Some(ttl_secs) = delta.ttl_secs {
            grant.expires_at = Some(now_unix().saturating_add(ttl_secs));
        }
        if let Some(prompt) = &delta.prompt_append {
            grant.prompt_append = Some(prompt.clone());
        }
        if let Some(mode) = delta.evaluation_mode {
            grant.scope.evaluation_mode = mode;
        }
        let changed = before != serde_json::to_vec(grant).ok()?;
        if changed {
            self.revision = self.revision.saturating_add(1);
        }
        Some(changed)
    }

    pub fn revoke_filtered(&mut self, label: Option<&str>, saved_grant: Option<&str>) -> usize {
        let tokens = self
            .grants
            .iter()
            .filter(|(_, grant)| {
                label.is_none_or(|label| grant.scope.label.as_deref() == Some(label))
                    && saved_grant
                        .is_none_or(|name| grant.scope.saved_grant.as_deref() == Some(name))
            })
            .map(|(token, _)| token.clone())
            .collect::<Vec<_>>();
        let mut revoked = 0;
        for token in tokens {
            revoked += usize::from(self.revoke(&token));
        }
        revoked
    }

    pub fn auto_amend_for(&self, token: &str) -> bool {
        let Some(grant) = self.grants.get(token) else {
            return false;
        };
        !grant.is_expired(now_unix()) && grant.auto_amend
    }

    pub fn amend_exact(
        &mut self,
        token: &str,
        decision: SessionAmendment,
        binary: String,
        args: Vec<String>,
        cwd: Option<PathBuf>,
    ) -> Option<bool> {
        if self
            .grants
            .get(token)
            .is_none_or(|g| g.is_expired(now_unix()))
        {
            return None;
        }
        // Bump even on a Some(false) outcome: the opposite-side retain below
        // can still have removed a rule.
        self.revision += 1;
        let grant = self.grants.get_mut(token).expect("presence checked above");

        let rule = SessionExactRule { binary, args, cwd };
        match decision {
            SessionAmendment::Allow => {
                grant.deny_exact.retain(|existing| existing != &rule);
                if grant.allow_exact.iter().any(|existing| existing == &rule) {
                    Some(false)
                } else {
                    grant.allow_exact.push(rule);
                    Some(true)
                }
            }
            SessionAmendment::Deny => {
                grant.allow_exact.retain(|existing| existing != &rule);
                if grant.deny_exact.iter().any(|existing| existing == &rule) {
                    Some(false)
                } else {
                    grant.deny_exact.push(rule);
                    Some(true)
                }
            }
        }
    }

    /// Remove expired entries (move them to history) and trim history older
    /// than the retention window. Increments the revision exactly once when
    /// persisted state changes and leaves it unchanged on a no-op.
    pub fn purge_expired(&mut self) -> bool {
        let mut changed = false;
        let now = now_unix();
        let retention_cutoff = now.saturating_sub(self.history_retention_secs);

        let expired_tokens: Vec<String> = self
            .grants
            .iter()
            .filter(|(_, g)| g.is_expired(now))
            .map(|(t, _)| t.clone())
            .collect();
        let had_expired_grants = !expired_tokens.is_empty();
        changed |= had_expired_grants;
        for token in expired_tokens {
            if let Some(grant) = self.grants.remove(&token) {
                self.history
                    .push(historical(&token, grant, now, HistoricalStatus::Expired));
            }
        }

        let history_before = self.history.len();
        self.history.retain(|h| h.ended_at >= retention_cutoff);
        changed |= self.history.len() != history_before;
        let interactions_before = self.interactions.len();
        self.interactions
            .retain(|entry| entry.interaction.at_unix >= retention_cutoff);
        changed |= self.interactions.len() != interactions_before;
        if changed {
            self.revision += 1;
        }
        changed
    }

    /// Check whether the session's grants short-circuit the decision.
    ///
    /// Returns `Some(Deny)` if a deny pattern matches — deny always wins.
    /// Returns `Some(Allow)` if an allow pattern matches.
    /// Returns `None` if the session has no matching rule (fall through
    /// to normal evaluation), including when the token is unknown,
    /// expired, or has no patterns.
    pub fn check(
        &self,
        token: &str,
        cmd: &str,
        args: &[String],
        cwd: Option<&Path>,
    ) -> Option<(SessionDecision, String)> {
        let grant = self.grants.get(token)?;
        if grant.is_expired(now_unix()) {
            return None;
        }

        let full_cmd = command_line(cmd, args);
        let cmd_only = cmd.to_string();
        let cmd_with_first_arg = if let Some(first) = args.first() {
            format!("{cmd} {first}")
        } else {
            cmd_only.clone()
        };

        if let Some(rule) = grant
            .deny_exact
            .iter()
            .find(|rule| rule.matches_deny(cmd, args, cwd))
        {
            return Some((
                SessionDecision::Deny,
                format!("session exact deny: {}", rule.command_line()),
            ));
        }

        let deny_rule = PolicyRule {
            patterns: grant.deny.clone(),
            decision: Decision::Deny,
            description: None,
        };
        if deny_rule.matches_command(&full_cmd, &cmd_with_first_arg, &cmd_only) {
            let which = grant
                .deny
                .iter()
                .find(|p| {
                    PolicyRule {
                        patterns: vec![(*p).clone()],
                        decision: Decision::Deny,
                        description: None,
                    }
                    .matches_command(&full_cmd, &cmd_with_first_arg, &cmd_only)
                })
                .cloned()
                .unwrap_or_else(|| "<unknown>".to_string());
            return Some((
                SessionDecision::Deny,
                format!("session deny pattern: {}", which),
            ));
        }

        if let Some(rule) = grant
            .allow_exact
            .iter()
            .find(|rule| rule.matches_allow(cmd, args, cwd))
        {
            return Some((
                SessionDecision::Allow,
                format!("session exact allow: {}", rule.command_line()),
            ));
        }

        let allow_rule = PolicyRule {
            patterns: grant.allow.clone(),
            decision: Decision::Allow,
            description: None,
        };
        if cwd.is_none() && allow_rule.matches_command(&full_cmd, &cmd_with_first_arg, &cmd_only) {
            let which = grant
                .allow
                .iter()
                .find(|p| {
                    PolicyRule {
                        patterns: vec![(*p).clone()],
                        decision: Decision::Allow,
                        description: None,
                    }
                    .matches_command(&full_cmd, &cmd_with_first_arg, &cmd_only)
                })
                .cloned()
                .unwrap_or_else(|| "<unknown>".to_string());
            return Some((
                SessionDecision::Allow,
                format!("session allow pattern: {}", which),
            ));
        }

        None
    }
}

/// Stable, value-insensitive behavioral bucket matching the command-learning
/// tuple: binary, first argument, and arity. It distinguishes operation families
/// without treating every object name or path as a fresh shape.
fn session_command_shape(command: &str) -> String {
    let parts = shell_words::split(command).unwrap_or_else(|_| {
        command
            .split_whitespace()
            .map(str::to_string)
            .collect::<Vec<_>>()
    });
    let binary = parts.first().map(String::as_str).unwrap_or("");
    let first_arg = parts.get(1).map(String::as_str).unwrap_or("");
    format!(
        "{binary}\u{1f}{first_arg}\u{1f}{}",
        parts.len().saturating_sub(1)
    )
}

fn historical(
    token: &str,
    grant: SessionGrant,
    ended_at: u64,
    status: HistoricalStatus,
) -> HistoricalGrant {
    HistoricalGrant {
        token: token.to_string(),
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
        status,
        prompt_append: grant.prompt_append,
        generated_notes: grant.generated_notes,
        static_only: grant.static_only,
        auto_amend: grant.auto_amend,
    }
}

fn command_line(cmd: &str, args: &[String]) -> String {
    if args.is_empty() {
        cmd.to_string()
    } else {
        format!("{} {}", cmd, args.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg_with(token: &str, allow: &[&str], deny: &[&str]) -> SessionRegistry {
        let mut reg = SessionRegistry::new();
        reg.grant(
            token.to_string(),
            SessionGrant {
                allow: allow.iter().map(|s| s.to_string()).collect(),
                deny: deny.iter().map(|s| s.to_string()).collect(),
                allow_exact: Vec::new(),
                deny_exact: Vec::new(),
                activated_verbs: Vec::new(),
                override_markers: Vec::new(),
                scope: Default::default(),
                expires_at: None,
                granted_at: 0,
                prompt_append: None,
                generated_notes: Vec::new(),
                static_only: false,
                auto_amend: false,
            },
        );
        reg
    }

    #[test]
    fn unknown_token_returns_none() {
        let reg = reg_with("tok", &["mkdir*"], &[]);
        assert!(reg
            .check("other", "mkdir", &["/tmp/x".into()], None)
            .is_none());
    }

    #[test]
    fn allow_pattern_matches() {
        let reg = reg_with("tok", &["mkdir /tmp/work/*"], &[]);
        let hit = reg
            .check("tok", "mkdir", &["/tmp/work/out".into()], None)
            .expect("allow should match");
        assert_eq!(hit.0, SessionDecision::Allow);
    }

    #[test]
    fn deny_wins_over_allow() {
        let reg = reg_with("tok", &["rm*"], &["rm -rf /*"]);
        let hit = reg
            .check("tok", "rm", &["-rf".into(), "/".into()], None)
            .expect("deny should match");
        assert_eq!(hit.0, SessionDecision::Deny);
    }

    #[test]
    fn no_match_returns_none_even_with_grants() {
        let reg = reg_with("tok", &["mkdir*"], &["rm*"]);
        assert!(reg.check("tok", "ls", &["-la".into()], None).is_none());
    }

    #[test]
    fn exact_rules_do_not_treat_glob_characters_as_wildcards() {
        let mut reg = reg_with("tok", &[], &[]);
        assert_eq!(
            reg.amend_exact(
                "tok",
                SessionAmendment::Allow,
                "echo".into(),
                vec!["literal*".into()],
                None
            ),
            Some(true)
        );

        assert!(reg
            .check("tok", "echo", &["literal*".into()], None)
            .is_some_and(|hit| hit.0 == SessionDecision::Allow));
        assert!(reg
            .check("tok", "echo", &["literal123".into()], None)
            .is_none());
    }

    #[test]
    fn cwd_binds_exact_allows_and_disables_legacy_allow_globs() {
        let mut reg = reg_with("tok", &["make deploy"], &[]);
        let cwd = PathBuf::from("/srv/app");
        let other = PathBuf::from("/srv/other");

        assert!(reg
            .check("tok", "make", &["deploy".into()], Some(&cwd))
            .is_none());
        assert!(reg
            .check("tok", "make", &["deploy".into()], None)
            .is_some_and(|hit| hit.0 == SessionDecision::Allow));

        assert_eq!(
            reg.amend_exact(
                "tok",
                SessionAmendment::Allow,
                "make".into(),
                vec!["deploy".into()],
                Some(cwd.clone()),
            ),
            Some(true)
        );

        assert!(reg
            .check("tok", "make", &["deploy".into()], Some(&cwd))
            .is_some_and(|hit| hit.0 == SessionDecision::Allow));
        assert!(reg
            .check("tok", "make", &["deploy".into()], Some(&other))
            .is_none());
    }

    #[test]
    fn exact_deny_wins_and_amend_dedupes_without_history() {
        let mut reg = reg_with("tok", &[], &[]);
        assert_eq!(
            reg.amend_exact(
                "tok",
                SessionAmendment::Allow,
                "kubectl".into(),
                vec!["get".into(), "pods".into()],
                None
            ),
            Some(true)
        );
        assert_eq!(
            reg.amend_exact(
                "tok",
                SessionAmendment::Deny,
                "kubectl".into(),
                vec!["get".into(), "pods".into()],
                None
            ),
            Some(true)
        );
        assert_eq!(
            reg.amend_exact(
                "tok",
                SessionAmendment::Deny,
                "kubectl".into(),
                vec!["get".into(), "pods".into()],
                None
            ),
            Some(false)
        );

        let hit = reg
            .check("tok", "kubectl", &["get".into(), "pods".into()], None)
            .expect("exact deny should match");
        assert_eq!(hit.0, SessionDecision::Deny);
        assert!(reg.list_history(None).is_empty());
    }

    #[test]
    fn expired_grant_is_ignored() {
        let mut reg = SessionRegistry::new();
        reg.grant(
            "tok".to_string(),
            SessionGrant {
                allow: vec!["mkdir*".to_string()],
                deny: vec![],
                allow_exact: Vec::new(),
                deny_exact: Vec::new(),
                activated_verbs: Vec::new(),
                override_markers: Vec::new(),
                scope: Default::default(),
                expires_at: Some(1),
                granted_at: 0, // 1970-01-01 +1s
                prompt_append: None,
                generated_notes: Vec::new(),
                static_only: false,
                auto_amend: false,
            },
        );
        assert!(reg.check("tok", "mkdir", &["/tmp".into()], None).is_none());
    }

    #[test]
    fn revoke_removes_grant() {
        let mut reg = reg_with("tok", &["mkdir*"], &[]);
        assert!(reg.revoke("tok"));
        assert!(reg.check("tok", "mkdir", &["/tmp".into()], None).is_none());
        assert!(!reg.revoke("tok"));
    }

    #[test]
    fn prompt_append_returned_for_live_grant() {
        let mut reg = SessionRegistry::new();
        reg.grant(
            "tok".to_string(),
            SessionGrant {
                allow: vec![],
                deny: vec![],
                allow_exact: Vec::new(),
                deny_exact: Vec::new(),
                activated_verbs: Vec::new(),
                override_markers: Vec::new(),
                scope: Default::default(),
                expires_at: None,
                granted_at: 0,
                prompt_append: Some("session is restoring a backup".to_string()),
                generated_notes: Vec::new(),
                static_only: false,
                auto_amend: false,
            },
        );
        assert_eq!(
            reg.prompt_append_for("tok").as_deref(),
            Some("session is restoring a backup")
        );
        assert!(reg.prompt_append_for("missing").is_none());
    }

    #[test]
    fn prompt_append_suppressed_for_expired_grant() {
        let mut reg = SessionRegistry::new();
        reg.grant(
            "tok".to_string(),
            SessionGrant {
                allow: vec![],
                deny: vec![],
                allow_exact: Vec::new(),
                deny_exact: Vec::new(),
                activated_verbs: Vec::new(),
                override_markers: Vec::new(),
                scope: Default::default(),
                expires_at: Some(1),
                granted_at: 0,
                prompt_append: Some("ignored".to_string()),
                generated_notes: Vec::new(),
                static_only: false,
                auto_amend: false,
            },
        );
        assert!(reg.prompt_append_for("tok").is_none());
    }

    #[test]
    fn list_returns_non_expired() {
        let mut reg = SessionRegistry::new();
        reg.grant(
            "live".to_string(),
            SessionGrant {
                allow: vec!["*".into()],
                deny: vec![],
                allow_exact: Vec::new(),
                deny_exact: Vec::new(),
                activated_verbs: Vec::new(),
                override_markers: Vec::new(),
                scope: Default::default(),
                expires_at: None,
                granted_at: 0,
                prompt_append: None,
                generated_notes: Vec::new(),
                static_only: false,
                auto_amend: false,
            },
        );
        reg.grant(
            "dead".to_string(),
            SessionGrant {
                allow: vec!["*".into()],
                deny: vec![],
                allow_exact: Vec::new(),
                deny_exact: Vec::new(),
                activated_verbs: Vec::new(),
                override_markers: Vec::new(),
                scope: Default::default(),
                expires_at: Some(1),
                granted_at: 0,
                prompt_append: None,
                generated_notes: Vec::new(),
                static_only: false,
                auto_amend: false,
            },
        );
        let listed = reg.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].token, "live");
    }

    #[test]
    fn has_returns_true_only_for_live_grants() {
        let reg = reg_with("live", &[], &[]);
        assert!(reg.has("live"));
        assert!(!reg.has("ghost"));
    }

    #[test]
    fn static_only_is_reported_for_live_grant() {
        let mut reg = SessionRegistry::new();
        reg.grant(
            "tok".to_string(),
            SessionGrant {
                allow: vec![],
                deny: vec![],
                allow_exact: Vec::new(),
                deny_exact: Vec::new(),
                activated_verbs: Vec::new(),
                override_markers: Vec::new(),
                scope: Default::default(),
                expires_at: None,
                granted_at: 0,
                prompt_append: None,
                generated_notes: Vec::new(),
                static_only: true,
                auto_amend: true,
            },
        );
        assert!(reg.static_only_for("tok"));
        assert!(reg.auto_amend_for("tok"));
        assert!(!reg.static_only_for("missing"));
        assert!(!reg.auto_amend_for("missing"));
    }

    #[test]
    fn revoke_moves_grant_into_history() {
        let mut reg = reg_with("tok", &["mkdir*"], &[]);
        assert!(reg.revoke("tok"));
        assert!(!reg.has("tok"));
        let history = reg.list_history(None);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].token, "tok");
        assert_eq!(history[0].status, HistoricalStatus::Revoked);
    }

    #[test]
    fn purge_moves_expired_to_history() {
        let mut reg = SessionRegistry::new();
        reg.grant(
            "expired".to_string(),
            SessionGrant {
                allow: vec!["*".into()],
                deny: vec![],
                allow_exact: Vec::new(),
                deny_exact: Vec::new(),
                activated_verbs: Vec::new(),
                override_markers: Vec::new(),
                scope: Default::default(),
                expires_at: Some(1),
                granted_at: 0,
                prompt_append: None,
                generated_notes: Vec::new(),
                static_only: false,
                auto_amend: false,
            },
        );
        let before = reg.revision();
        assert!(reg.purge_expired());
        assert_eq!(reg.revision(), before + 1);
        assert!(!reg.has("expired"));
        let history = reg.list_history(None);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].status, HistoricalStatus::Expired);
        let after = reg.revision();
        assert!(!reg.purge_expired());
        assert_eq!(reg.revision(), after);
    }

    #[test]
    fn list_history_since_filters_by_ended_at() {
        let mut reg = SessionRegistry::new();
        reg.grant(
            "a".to_string(),
            SessionGrant {
                allow: vec![],
                deny: vec![],
                allow_exact: Vec::new(),
                deny_exact: Vec::new(),
                activated_verbs: Vec::new(),
                override_markers: Vec::new(),
                scope: Default::default(),
                expires_at: None,
                granted_at: 0,
                prompt_append: None,
                generated_notes: Vec::new(),
                static_only: false,
                auto_amend: false,
            },
        );
        reg.revoke("a");
        let after = now_unix() + 1;
        let before = now_unix().saturating_sub(60);
        assert_eq!(reg.list_history(Some(after)).len(), 0);
        assert_eq!(reg.list_history(Some(before)).len(), 1);
    }

    #[test]
    fn show_aggregates_recent_interactions_and_risk_histogram() {
        let mut reg = reg_with("tok", &["cat*"], &["rm*"]);
        reg.record_interaction(
            "tok",
            SessionInteraction {
                at_unix: 10,
                command: "cat /tmp/a".into(),
                allowed: true,
                source: SessionDecisionSource::Llm,
                reason: "safe".into(),
                risk: Some(2),
                exec_status: SessionExecStatus::Completed,
                exit_code: Some(0),
                exposed_secret_refs: Vec::new(),
            },
        );
        reg.record_interaction(
            "tok",
            SessionInteraction {
                at_unix: 11,
                command: "rm -rf /tmp/a".into(),
                allowed: false,
                source: SessionDecisionSource::SessionDeny,
                reason: "session deny pattern: rm*".into(),
                risk: None,
                exec_status: SessionExecStatus::NotAttempted,
                exit_code: None,
                exposed_secret_refs: Vec::new(),
            },
        );
        reg.record_interaction(
            "tok",
            SessionInteraction {
                at_unix: 12,
                command: "echo hi".into(),
                allowed: true,
                source: SessionDecisionSource::Llm,
                reason: "ok".into(),
                risk: Some(1),
                exec_status: SessionExecStatus::Failed,
                exit_code: None,
                exposed_secret_refs: Vec::new(),
            },
        );

        let report = reg.show("tok", 2).expect("session report");
        assert!(report.active.is_some());
        assert_eq!(report.stats.total, 3);
        assert_eq!(report.stats.allowed, 2);
        assert_eq!(report.stats.denied, 1);
        assert_eq!(report.stats.completed, 1);
        assert_eq!(report.stats.exec_failed, 1);
        assert_eq!(report.stats.not_attempted, 1);
        assert_eq!(report.stats.risk_histogram[1], 1);
        assert_eq!(report.stats.risk_histogram[2], 1);
        assert_eq!(report.stats.evaluator_calls, 2);
        assert_eq!(report.stats.cache_hits, 0);
        assert_eq!(report.stats.holds, 0);
        assert_eq!(report.stats.novel_shapes, 3);
        assert_eq!(report.stats.novel_shape_rate_percent, 100);
        assert_eq!(report.recent.len(), 2);
        assert_eq!(report.recent[0].command, "rm -rf /tmp/a");
        assert_eq!(report.recent[1].command, "echo hi");
    }

    #[test]
    fn behavioral_limits_use_the_persistable_interaction_history() {
        let mut reg = reg_with("tok", &[], &[]);
        let now = now_unix();
        for (command, allowed, source, status) in [
            (
                "kubectl get services",
                true,
                SessionDecisionSource::Llm,
                SessionExecStatus::Completed,
            ),
            (
                "kubectl get pods",
                true,
                SessionDecisionSource::Cache,
                SessionExecStatus::Completed,
            ),
            (
                "kubectl delete pod x",
                false,
                SessionDecisionSource::Llm,
                SessionExecStatus::NotAttempted,
            ),
            (
                "kubectl apply -f change.yaml",
                true,
                SessionDecisionSource::Llm,
                SessionExecStatus::Held,
            ),
        ] {
            reg.record_interaction(
                "tok",
                SessionInteraction {
                    at_unix: now,
                    command: command.into(),
                    allowed,
                    source,
                    reason: "test".into(),
                    risk: None,
                    exec_status: status,
                    exit_code: None,
                    exposed_secret_refs: Vec::new(),
                },
            );
        }

        let limits = SessionBehaviorLimits {
            window_secs: 60,
            max_denials: None,
            max_holds: Some(1),
            max_deny_ratio_percent: None,
            min_commands_for_ratio: 1,
        };
        let report = reg.show_with_limits("tok", 10, &limits).unwrap();
        assert_eq!(report.stats.total, 4);
        assert_eq!(report.stats.evaluator_calls, 3);
        assert_eq!(report.stats.cache_hits, 1);
        assert_eq!(report.stats.denied, 1);
        assert_eq!(report.stats.holds, 1);
        assert_eq!(report.stats.novel_shapes, 3);
        assert_eq!(report.stats.novel_shape_rate_percent, 75);
        assert!(report.stats.suspended);
        assert!(report
            .stats
            .suspension_reason
            .as_deref()
            .unwrap()
            .contains("1 holds"));

        let ratio_limits = SessionBehaviorLimits {
            max_holds: None,
            max_deny_ratio_percent: Some(25),
            min_commands_for_ratio: 4,
            ..limits
        };
        assert!(reg
            .suspension_reason("tok", &ratio_limits)
            .unwrap()
            .contains("25% denials"));
    }

    #[test]
    fn session_label_can_be_cleared() {
        let mut registry = reg_with("tok", &[], &[]);
        assert_eq!(
            registry.set_label("tok", Some("incident".to_string())),
            Some(true)
        );
        assert_eq!(registry.set_label("tok", None), Some(true));
        assert_eq!(
            registry
                .show_with_limits("tok", 1, &SessionBehaviorLimits::default())
                .unwrap()
                .active
                .unwrap()
                .scope
                .label,
            None
        );
    }
}
