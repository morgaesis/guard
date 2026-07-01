//! Session grant registry and reporting model.
//!
//! A session is an opaque token the caller includes in `ExecuteRequest`.
//! Grants attach extra allow/deny glob patterns to that token. Session
//! denies short-circuit to DENY before the evaluator. Session allows
//! short-circuit to ALLOW before the evaluator, letting an operator
//! hand a specific agent narrow extra permissions (e.g. "mkdir
//! /tmp/work/*", "rm /tmp/work/scratch.txt") without relaxing the
//! global mode.
//!
//! The daemon keeps a live in-memory registry for fast decision checks,
//! while `session_store.rs` persists grants and bounded interaction
//! history across daemon restarts.

use guard::policy::{Decision, PolicyRule};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};

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
    /// Unix seconds after which this grant is treated as absent.
    pub expires_at: Option<u64>,
    /// Free-form text appended to the LLM system prompt for evaluator
    /// calls made under this session token. Use to give the model
    /// context the static glob patterns cannot express, e.g. "this
    /// session is restoring a Postgres backup; treat pg_restore and
    /// related psql copy commands as expected".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_append: Option<String>,
    /// If true, commands that miss the grant's static allow/deny rules are
    /// denied instead of falling through to the normal evaluator.
    #[serde(default)]
    pub static_only: bool,
    /// If true, fresh low-risk LLM fallback decisions may amend this grant
    /// with exact allow/deny rules for future calls.
    #[serde(default)]
    pub auto_amend: bool,
    /// Unix seconds when the grant was installed. Used by `session
    /// list` to show grant age.
    #[serde(default)]
    pub granted_at: u64,
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
}

impl SessionExactRule {
    pub fn new(binary: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            binary: binary.into(),
            args,
        }
    }

    pub fn command_line(&self) -> String {
        command_line(&self.binary, &self.args)
    }

    fn matches(&self, cmd: &str, args: &[String]) -> bool {
        self.binary == cmd && self.args == args
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
    pub granted_at: u64,
    pub expires_at: Option<u64>,
    /// Unix seconds when the grant left the active set.
    pub ended_at: u64,
    pub status: HistoricalStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_append: Option<String>,
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
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub granted_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_append: Option<String>,
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
        }
    }
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
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self {
            grants: HashMap::new(),
            history: Vec::new(),
            interactions: Vec::new(),
            history_retention_secs: DEFAULT_HISTORY_RETENTION_SECS,
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
        }
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
        if grant.granted_at == 0 {
            grant.granted_at = current_unix_secs();
        }
        // If we are overwriting an active grant, archive the previous
        // version so the audit trail still shows what was in effect.
        if let Some(prev) = self.grants.remove(&token) {
            self.history.push(historical(
                &token,
                prev,
                current_unix_secs(),
                HistoricalStatus::Revoked,
            ));
        }
        self.grants.insert(token, grant);
    }

    pub fn revoke(&mut self, token: &str) -> bool {
        let Some(grant) = self.grants.remove(token) else {
            return false;
        };
        self.history.push(historical(
            token,
            grant,
            current_unix_secs(),
            HistoricalStatus::Revoked,
        ));
        true
    }

    /// True if this token currently maps to a non-expired grant.
    pub fn has(&self, token: &str) -> bool {
        let Some(grant) = self.grants.get(token) else {
            return false;
        };
        !grant.is_expired(current_unix_secs())
    }

    pub fn list(&self) -> Vec<SessionGrantSummary> {
        let now = current_unix_secs();
        self.grants
            .iter()
            .filter(|(_, g)| !g.is_expired(now))
            .map(|(token, g)| SessionGrantSummary {
                token: token.clone(),
                allow: g.allow.clone(),
                deny: g.deny.clone(),
                allow_exact: g.allow_exact.clone(),
                deny_exact: g.deny_exact.clone(),
                expires_at: g.expires_at,
                granted_at: g.granted_at,
                prompt_append: g.prompt_append.clone(),
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
        if interaction.at_unix == 0 {
            interaction.at_unix = current_unix_secs();
        }
        self.interactions.push(StoredSessionInteraction {
            token: token.to_string(),
            interaction,
        });
    }

    pub fn show(&self, token: &str, limit: usize) -> Option<SessionReport> {
        let active = self.grants.get(token).and_then(|grant| {
            if grant.is_expired(current_unix_secs()) {
                None
            } else {
                Some(SessionGrantSummary {
                    token: token.to_string(),
                    allow: grant.allow.clone(),
                    deny: grant.deny.clone(),
                    allow_exact: grant.allow_exact.clone(),
                    deny_exact: grant.deny_exact.clone(),
                    expires_at: grant.expires_at,
                    granted_at: grant.granted_at,
                    prompt_append: grant.prompt_append.clone(),
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
        }

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

    /// Return the additive prompt for this session, if the grant exists,
    /// has not expired, and has a prompt attached.
    pub fn prompt_append_for(&self, token: &str) -> Option<String> {
        let grant = self.grants.get(token)?;
        if grant.is_expired(current_unix_secs()) {
            return None;
        }
        grant.prompt_append.clone()
    }

    pub fn static_only_for(&self, token: &str) -> bool {
        let Some(grant) = self.grants.get(token) else {
            return false;
        };
        !grant.is_expired(current_unix_secs()) && grant.static_only
    }

    pub fn auto_amend_for(&self, token: &str) -> bool {
        let Some(grant) = self.grants.get(token) else {
            return false;
        };
        !grant.is_expired(current_unix_secs()) && grant.auto_amend
    }

    pub fn amend_exact(
        &mut self,
        token: &str,
        decision: SessionAmendment,
        binary: String,
        args: Vec<String>,
    ) -> Option<bool> {
        let grant = self.grants.get_mut(token)?;
        if grant.is_expired(current_unix_secs()) {
            return None;
        }

        let rule = SessionExactRule::new(binary, args);
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

    /// Remove expired entries (move them to history) and trim history
    /// older than the retention window. Called opportunistically.
    pub fn purge_expired(&mut self) {
        let now = current_unix_secs();
        let retention_cutoff = now.saturating_sub(self.history_retention_secs);

        let expired_tokens: Vec<String> = self
            .grants
            .iter()
            .filter(|(_, g)| g.is_expired(now))
            .map(|(t, _)| t.clone())
            .collect();
        for token in expired_tokens {
            if let Some(grant) = self.grants.remove(&token) {
                self.history
                    .push(historical(&token, grant, now, HistoricalStatus::Expired));
            }
        }

        self.history.retain(|h| h.ended_at >= retention_cutoff);
        self.interactions
            .retain(|entry| entry.interaction.at_unix >= retention_cutoff);
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
    ) -> Option<(SessionDecision, String)> {
        let grant = self.grants.get(token)?;
        if grant.is_expired(current_unix_secs()) {
            return None;
        }

        let full_cmd = command_line(cmd, args);
        let cmd_only = cmd.to_string();
        let cmd_with_first_arg = if let Some(first) = args.first() {
            format!("{cmd} {first}")
        } else {
            cmd_only.clone()
        };

        if let Some(rule) = grant.deny_exact.iter().find(|rule| rule.matches(cmd, args)) {
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
            .find(|rule| rule.matches(cmd, args))
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
        if allow_rule.matches_command(&full_cmd, &cmd_with_first_arg, &cmd_only) {
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
        granted_at: grant.granted_at,
        expires_at: grant.expires_at,
        ended_at,
        status,
        prompt_append: grant.prompt_append,
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

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
                expires_at: None,
                granted_at: 0,
                prompt_append: None,
                static_only: false,
                auto_amend: false,
            },
        );
        reg
    }

    #[test]
    fn unknown_token_returns_none() {
        let reg = reg_with("tok", &["mkdir*"], &[]);
        assert!(reg.check("other", "mkdir", &["/tmp/x".into()]).is_none());
    }

    #[test]
    fn allow_pattern_matches() {
        let reg = reg_with("tok", &["mkdir /tmp/work/*"], &[]);
        let hit = reg
            .check("tok", "mkdir", &["/tmp/work/out".into()])
            .expect("allow should match");
        assert_eq!(hit.0, SessionDecision::Allow);
    }

    #[test]
    fn deny_wins_over_allow() {
        let reg = reg_with("tok", &["rm*"], &["rm -rf /*"]);
        let hit = reg
            .check("tok", "rm", &["-rf".into(), "/".into()])
            .expect("deny should match");
        assert_eq!(hit.0, SessionDecision::Deny);
    }

    #[test]
    fn no_match_returns_none_even_with_grants() {
        let reg = reg_with("tok", &["mkdir*"], &["rm*"]);
        assert!(reg.check("tok", "ls", &["-la".into()]).is_none());
    }

    #[test]
    fn exact_rules_do_not_treat_glob_characters_as_wildcards() {
        let mut reg = reg_with("tok", &[], &[]);
        assert_eq!(
            reg.amend_exact(
                "tok",
                SessionAmendment::Allow,
                "echo".into(),
                vec!["literal*".into()]
            ),
            Some(true)
        );

        assert!(reg
            .check("tok", "echo", &["literal*".into()])
            .is_some_and(|hit| hit.0 == SessionDecision::Allow));
        assert!(reg.check("tok", "echo", &["literal123".into()]).is_none());
    }

    #[test]
    fn exact_deny_wins_and_amend_dedupes_without_history() {
        let mut reg = reg_with("tok", &[], &[]);
        assert_eq!(
            reg.amend_exact(
                "tok",
                SessionAmendment::Allow,
                "kubectl".into(),
                vec!["get".into(), "pods".into()]
            ),
            Some(true)
        );
        assert_eq!(
            reg.amend_exact(
                "tok",
                SessionAmendment::Deny,
                "kubectl".into(),
                vec!["get".into(), "pods".into()]
            ),
            Some(true)
        );
        assert_eq!(
            reg.amend_exact(
                "tok",
                SessionAmendment::Deny,
                "kubectl".into(),
                vec!["get".into(), "pods".into()]
            ),
            Some(false)
        );

        let hit = reg
            .check("tok", "kubectl", &["get".into(), "pods".into()])
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
                expires_at: Some(1),
                granted_at: 0, // 1970-01-01 +1s
                prompt_append: None,
                static_only: false,
                auto_amend: false,
            },
        );
        assert!(reg.check("tok", "mkdir", &["/tmp".into()]).is_none());
    }

    #[test]
    fn revoke_removes_grant() {
        let mut reg = reg_with("tok", &["mkdir*"], &[]);
        assert!(reg.revoke("tok"));
        assert!(reg.check("tok", "mkdir", &["/tmp".into()]).is_none());
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
                expires_at: None,
                granted_at: 0,
                prompt_append: Some("session is restoring a backup".to_string()),
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
                expires_at: Some(1),
                granted_at: 0,
                prompt_append: Some("ignored".to_string()),
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
                expires_at: None,
                granted_at: 0,
                prompt_append: None,
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
                expires_at: Some(1),
                granted_at: 0,
                prompt_append: None,
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
                expires_at: None,
                granted_at: 0,
                prompt_append: None,
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
                expires_at: Some(1),
                granted_at: 0,
                prompt_append: None,
                static_only: false,
                auto_amend: false,
            },
        );
        reg.purge_expired();
        assert!(!reg.has("expired"));
        let history = reg.list_history(None);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].status, HistoricalStatus::Expired);
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
                expires_at: None,
                granted_at: 0,
                prompt_append: None,
                static_only: false,
                auto_amend: false,
            },
        );
        reg.revoke("a");
        let after = current_unix_secs() + 1;
        let before = current_unix_secs().saturating_sub(60);
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
        assert_eq!(report.recent.len(), 2);
        assert_eq!(report.recent[0].command, "rm -rf /tmp/a");
        assert_eq!(report.recent[1].command, "echo hi");
    }
}
