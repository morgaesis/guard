//! Evidence-based API request shape learning for proxied `evaluate` traffic.
//!
//! API promotion is deterministic: the learned shape is the exact observed
//! `ApiShape` identity, with the object name deliberately excluded and the body
//! reduced to a value-free key skeleton. There is no regex and no model-authored
//! synthesis in this path, so a promoted shape matches only requests structurally
//! identical across every field `ApiShape::key` defines. A learned verdict is
//! stamped with the evaluator regime that produced it and is distrusted once
//! that regime changes, mirroring verb-promotion stamping.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::{Reversibility, EXECUTE_NOW_MAX_RISK, HOLD_RISK_THRESHOLD};
use crate::env::now_unix;
use crate::learned_rules::{
    load_learning_file_snapshot, preserve_corrupt_learning_file, retry_learning_snapshot_conflicts,
    sanitize_learning_text, write_learning_file_atomically_for_locked_snapshot, AsyncDurableStore,
    LearningFileSnapshot, LearningWriteOutcome,
};
use crate::proxy::ApiRequestSummary;
use crate::redact::{named_value_contains_sensitive_literals, text_contains_sensitive_literals};

const MAX_EVIDENCE_PER_BUCKET: usize = 8;
const MAX_BUCKETS: usize = 500;
const DEFAULT_GENERATED_TTL_SECS: u64 = 7 * 24 * 60 * 60;

#[derive(Debug, Clone)]
pub struct ApiPromotionConfig {
    pub path: PathBuf,
    pub enabled: bool,
    pub min_approvals: u32,
    pub min_denials: u32,
    pub generated_ttl_secs: u64,
}

impl ApiPromotionConfig {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            enabled: true,
            min_approvals: 5,
            min_denials: 3,
            generated_ttl_secs: DEFAULT_GENERATED_TTL_SECS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiPromotionFile {
    pub version: u32,
    #[serde(default)]
    pub buckets: BTreeMap<String, ApiShapeBucket>,
}

fn default_version() -> u32 {
    4
}

impl Default for ApiPromotionFile {
    fn default() -> Self {
        Self {
            version: default_version(),
            buckets: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiShapeBucket {
    #[serde(default)]
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_revision: Option<String>,
    pub protocol: String,
    pub verb: String,
    pub group: String,
    #[serde(default)]
    pub version: String,
    pub resource: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subresource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub authority_selectors: BTreeMap<String, String>,
    #[serde(default)]
    pub body_shape: String,
    pub approvals: u32,
    pub denials: u32,
    /// Object names observed for this shape, so an operator reading the file
    /// sees which concrete requests fed a promotion rather than the bucket key
    /// repeated.
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class_seen: Option<Reversibility>,
    #[serde(default)]
    pub mixed_class: bool,
    /// Set once an ineligible allow (too risky, or irreversible) is observed for
    /// the shape, permanently blocking promotion so a low-risk subset of a
    /// shape's history cannot promote while its risky observations are ignored.
    #[serde(default)]
    pub disqualified: bool,
    #[serde(default)]
    pub promoted_allow: bool,
    #[serde(default)]
    pub learned_deny: bool,
    /// Evaluator regime that produced the current learned state. A bucket whose
    /// stamp differs from the running config is not trusted.
    #[serde(default)]
    pub stamp: String,
    #[serde(default)]
    pub provenance: ApiCoverageProvenance,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<u64>,
    pub max_risk_seen: i32,
    pub first_seen_unix: u64,
    pub last_seen_unix: u64,
    pub last_reason: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiCoverageProvenance {
    Operator,
    #[default]
    Evaluator,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiCoverageEntry {
    pub key: String,
    pub protocol: String,
    pub endpoint: String,
    pub session_fingerprint: Option<String>,
    pub session_revision: Option<String>,
    pub verb: String,
    pub group: String,
    pub version: String,
    pub resource: String,
    pub subresource: Option<String>,
    pub namespace: Option<String>,
    pub authority_selectors: BTreeMap<String, String>,
    pub body_shape: String,
    pub decision: String,
    pub provenance: ApiCoverageProvenance,
    pub regime: String,
    pub approvals: u32,
    pub denials: u32,
    pub expires_at_unix: Option<u64>,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiShape {
    pub endpoint: String,
    pub session_fingerprint: Option<String>,
    pub session_revision: Option<String>,
    pub protocol: String,
    pub verb: String,
    pub group: String,
    pub version: String,
    pub resource: String,
    pub subresource: Option<String>,
    pub namespace: Option<String>,
    pub authority_selectors: BTreeMap<String, String>,
    /// The value-free body key skeleton. Included so promotion is scoped to the
    /// exact request structure the evaluator approved; a request that adds or
    /// renames a field lands in a different bucket and is judged fresh.
    pub body_shape: String,
}

impl ApiShape {
    pub fn from_summary(summary: &ApiRequestSummary) -> Self {
        Self {
            endpoint: summary.endpoint.clone(),
            session_fingerprint: summary.session_fingerprint.clone(),
            session_revision: summary.session_revision.clone(),
            protocol: summary.protocol.clone(),
            verb: summary.verb.clone(),
            group: summary.group.clone(),
            version: summary.version.clone(),
            resource: summary.resource.clone(),
            subresource: summary.subresource.clone(),
            namespace: summary.namespace.clone(),
            authority_selectors: summary.authority_selectors.clone(),
            body_shape: summary.coverage_body_shape.clone(),
        }
    }

    fn key(&self) -> String {
        let identity = serde_json::json!({
            "endpoint": self.endpoint,
            "session_fingerprint": self.session_fingerprint,
            "session_revision": self.session_revision,
            "protocol": self.protocol,
            "verb": self.verb,
            "group": self.group,
            "version": self.version,
            "resource": self.resource,
            "subresource": self.subresource,
            "namespace": self.namespace,
            "authority_selectors": self.authority_selectors,
            "body_shape": self.body_shape,
        });
        let digest = sha2::Sha256::digest(
            serde_json::to_vec(&identity).expect("API shape identity serializes"),
        );
        let digest = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("api-shape-v1:{digest}")
    }

    fn contains_sensitive_literals(&self) -> bool {
        [
            self.endpoint.as_str(),
            self.protocol.as_str(),
            self.verb.as_str(),
            self.group.as_str(),
            self.version.as_str(),
            self.resource.as_str(),
            self.subresource.as_deref().unwrap_or(""),
            self.namespace.as_deref().unwrap_or(""),
            self.body_shape.as_str(),
        ]
        .into_iter()
        .any(text_contains_sensitive_literals)
            || self
                .session_fingerprint
                .as_deref()
                .is_some_and(opaque_identity_is_invalid)
            || self
                .session_revision
                .as_deref()
                .is_some_and(opaque_identity_is_invalid)
            || self.authority_selectors.iter().any(|(name, value)| {
                text_contains_sensitive_literals(name)
                    || text_contains_sensitive_literals(value)
                    || named_value_contains_sensitive_literals(name, value)
            })
    }

    pub fn audit_label(&self) -> String {
        let label = format!(
            "protocol={} verb={} group={} version={} resource={} subresource={} namespace={} selectors={}",
            self.protocol,
            self.verb,
            if self.group.is_empty() {
                "(core)"
            } else {
                &self.group
            },
            self.version,
            self.resource,
            self.subresource.as_deref().unwrap_or("(none)"),
            self.namespace.as_deref().unwrap_or("(cluster)"),
            if self.authority_selectors.is_empty() {
                "(none)".to_string()
            } else {
                self.authority_selectors
                    .iter()
                    .map(|(key, value)| format!("{key}={value}"))
                    .collect::<Vec<_>>()
                    .join(",")
            }
        );
        // Shape components derive from the caller's request URL and body;
        // escape control characters so the label cannot split an audit line.
        crate::redact::audit_escape(&label).into_owned()
    }
}

fn opaque_identity_is_invalid(value: &str) -> bool {
    value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':'))
}

fn stamp_contains_sensitive_literal(stamp: &str) -> bool {
    let canonical_digest = stamp.len() == 64
        && stamp
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'));
    !canonical_digest && text_contains_sensitive_literals(stamp)
}

fn shape_from_bucket(bucket: &ApiShapeBucket) -> ApiShape {
    ApiShape {
        endpoint: bucket.endpoint.clone(),
        session_fingerprint: bucket.session_fingerprint.clone(),
        session_revision: bucket.session_revision.clone(),
        protocol: bucket.protocol.clone(),
        verb: bucket.verb.clone(),
        group: bucket.group.clone(),
        version: bucket.version.clone(),
        resource: bucket.resource.clone(),
        subresource: bucket.subresource.clone(),
        namespace: bucket.namespace.clone(),
        authority_selectors: bucket.authority_selectors.clone(),
        body_shape: bucket.body_shape.clone(),
    }
}

fn validate_current_api_file(data: &ApiPromotionFile) -> Result<()> {
    if data.version != default_version() {
        anyhow::bail!("API coverage write requires the current schema version");
    }
    for (key, bucket) in &data.buckets {
        let shape = shape_from_bucket(bucket);
        if shape.contains_sensitive_literals() || stamp_contains_sensitive_literal(&bucket.stamp) {
            anyhow::bail!("API coverage contains sensitive authority metadata");
        }
        if *key != shape.key() {
            anyhow::bail!("API coverage key does not match its complete shape identity");
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ApiLearnedAllow {
    pub shape: ApiShape,
    pub risk: i32,
    pub reversibility: Reversibility,
    pub approvals: u32,
}

#[derive(Debug, Clone)]
pub struct ApiLearnedDeny {
    pub shape: ApiShape,
    pub denials: u32,
    pub reason: String,
    pub provenance: ApiCoverageProvenance,
}

#[derive(Debug, Clone)]
pub enum ApiPromotionOutcome {
    AllowPromoted {
        shape: ApiShape,
        approvals: u32,
        risk: i32,
        reversibility: Reversibility,
    },
    DenyLearned {
        shape: ApiShape,
        denials: u32,
    },
}

#[derive(Debug, Clone)]
pub struct ApiPromotionStore {
    config: ApiPromotionConfig,
    data: ApiPromotionFile,
    snapshot: LearningFileSnapshot,
    #[cfg(test)]
    fail_writes: bool,
}

impl ApiPromotionStore {
    pub fn load(config: ApiPromotionConfig) -> Result<Self> {
        retry_learning_snapshot_conflicts(|| Self::load_once(config.clone()))
    }

    fn load_once(config: ApiPromotionConfig) -> Result<Self> {
        let snapshot = load_learning_file_snapshot(&config.path)?;
        let mut data = if let Some(content) = snapshot.content() {
            if content.iter().all(u8::is_ascii_whitespace) {
                ApiPromotionFile::default()
            } else {
                let parsed = std::str::from_utf8(content)
                    .context("API coverage state is not UTF-8")
                    .and_then(|text| serde_yaml_ng::from_str(text).context("parse API coverage"));
                parsed.map_err(|error| match preserve_corrupt_learning_file(&config.path, content)
                {
                    Ok(preserved) => anyhow::anyhow!(
                        "API coverage state is unreadable; the original remains in place and a verified copy was preserved at {}: {}",
                        preserved.display(),
                        sanitize_learning_text(&error.to_string())
                    ),
                    Err(preserve_error) => anyhow::anyhow!(
                        "API coverage state is unreadable and could not be preserved: {}; parse error: {}",
                        preserve_error,
                        sanitize_learning_text(&error.to_string())
                    ),
                })?
            }
        } else {
            ApiPromotionFile::default()
        };
        if data.version == 0 || data.version > default_version() {
            anyhow::bail!(
                "unsupported API coverage schema version {}; supported versions are 1 through {}",
                data.version,
                default_version()
            );
        }
        let source_version = data.version;
        let now = now_unix();
        let mut changed = source_version != default_version();
        let mut migrated: BTreeMap<String, ApiShapeBucket> = BTreeMap::new();
        for (old_key, mut bucket) in std::mem::take(&mut data.buckets) {
            let sanitized_reason = sanitize_learning_text(&bucket.last_reason);
            changed |= sanitized_reason != bucket.last_reason;
            bucket.last_reason = sanitized_reason;
            for evidence in &mut bucket.evidence {
                let sanitized = sanitize_learning_text(evidence);
                changed |= sanitized != *evidence;
                *evidence = sanitized;
            }
            if source_version < default_version() && bucket.endpoint.is_empty() {
                bucket.endpoint = "default".to_string();
                changed = true;
            }
            if bucket.provenance == ApiCoverageProvenance::Evaluator
                && bucket.expires_at_unix.is_none()
            {
                bucket.expires_at_unix = Some(
                    bucket
                        .last_seen_unix
                        .max(now.saturating_sub(config.generated_ttl_secs))
                        .saturating_add(config.generated_ttl_secs),
                );
                changed = true;
            }
            let shape = shape_from_bucket(&bucket);
            if shape.contains_sensitive_literals()
                || stamp_contains_sensitive_literal(&bucket.stamp)
            {
                anyhow::bail!(
                    "API coverage contains sensitive authority metadata and cannot be loaded"
                );
            }
            let key = shape.key();
            if source_version == default_version() && key != old_key {
                anyhow::bail!("API coverage key does not match its complete shape identity");
            }
            changed |= key != old_key;
            if migrated.insert(key.clone(), bucket).is_some() {
                anyhow::bail!("API coverage normalization produced a conflicting canonical key");
            }
        }
        data.version = default_version();
        data.buckets = migrated;
        validate_current_api_file(&data)?;
        let mut store = Self {
            config,
            data,
            snapshot,
            #[cfg(test)]
            fail_writes: false,
        };
        if changed {
            let content = store.canonical_content(&store.data)?;
            let outcome = write_learning_file_atomically_for_locked_snapshot(
                &store.config.path,
                &store.snapshot,
                &content,
            )?;
            let (committed, warning) = outcome.into_parts();
            store.snapshot = committed;
            if let Some(error) = warning {
                tracing::warn!(
                    "API coverage migration committed with a durability warning: {}",
                    error
                );
            }
        }
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.config.path
    }

    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn min_approvals(&self) -> u32 {
        self.config.min_approvals
    }

    pub fn min_denials(&self) -> u32 {
        self.config.min_denials
    }

    pub fn bucket_count(&self) -> usize {
        self.data.buckets.len()
    }

    #[doc(hidden)]
    pub fn refreshed_copy(&self) -> Result<Self> {
        Self::load(self.config.clone())
    }

    pub fn coverage(&self) -> Vec<ApiCoverageEntry> {
        let now = now_unix();
        self.data
            .buckets
            .iter()
            .filter_map(|(key, bucket)| {
                let decision = if bucket.learned_deny {
                    "deny"
                } else if bucket.promoted_allow {
                    "allow"
                } else {
                    return None;
                };
                Some(ApiCoverageEntry {
                    key: key.clone(),
                    protocol: bucket.protocol.clone(),
                    endpoint: bucket.endpoint.clone(),
                    session_fingerprint: bucket.session_fingerprint.clone(),
                    session_revision: bucket.session_revision.clone(),
                    verb: bucket.verb.clone(),
                    group: bucket.group.clone(),
                    version: bucket.version.clone(),
                    resource: bucket.resource.clone(),
                    subresource: bucket.subresource.clone(),
                    namespace: bucket.namespace.clone(),
                    authority_selectors: bucket.authority_selectors.clone(),
                    body_shape: bucket.body_shape.clone(),
                    decision: decision.to_string(),
                    provenance: bucket.provenance,
                    regime: bucket.stamp.clone(),
                    approvals: bucket.approvals,
                    denials: bucket.denials,
                    expires_at_unix: bucket.expires_at_unix,
                    active: !Self::expired(bucket, now),
                })
            })
            .collect()
    }

    #[cfg(test)]
    fn has_generated_coverage(&self) -> bool {
        self.data
            .buckets
            .values()
            .any(|bucket| bucket.provenance == ApiCoverageProvenance::Evaluator)
    }

    pub fn clear_generated(&mut self) -> Result<usize> {
        let config = self.config.clone();
        let (current, removed) = retry_learning_snapshot_conflicts(|| {
            let mut current = Self::load(config.clone())?;
            let mut candidate = current.data.clone();
            let before = candidate.buckets.len();
            candidate
                .buckets
                .retain(|_, bucket| bucket.provenance == ApiCoverageProvenance::Operator);
            let removed = before.saturating_sub(candidate.buckets.len());
            if removed > 0 {
                current.commit_candidate(candidate)?;
            }
            Ok((current, removed))
        })?;
        *self = current;
        Ok(removed)
    }

    fn expired(bucket: &ApiShapeBucket, now: u64) -> bool {
        bucket.provenance == ApiCoverageProvenance::Evaluator
            && bucket
                .expires_at_unix
                .is_some_and(|deadline| now >= deadline)
    }

    /// Whether a bucket's learned state was produced under the given evaluator
    /// regime stamp. An empty stamp disables the check (no intent configured, or
    /// tests).
    fn stamp_current(bucket: &ApiShapeBucket, stamp: &str) -> bool {
        bucket.provenance == ApiCoverageProvenance::Operator
            || stamp.is_empty()
            || bucket.stamp == stamp
    }

    pub fn learned_allow(
        &self,
        summary: &ApiRequestSummary,
        stamp: &str,
    ) -> Option<ApiLearnedAllow> {
        let shape = ApiShape::from_summary(summary);
        let bucket = self.data.buckets.get(&shape.key())?;
        if !bucket.promoted_allow || bucket.mixed_class || bucket.disqualified {
            return None;
        }
        if Self::expired(bucket, now_unix()) {
            return None;
        }
        if !Self::stamp_current(bucket, stamp) {
            return None;
        }
        Some(ApiLearnedAllow {
            shape,
            risk: bucket.max_risk_seen,
            reversibility: bucket.class_seen?,
            approvals: bucket.approvals,
        })
    }

    pub fn learned_deny(&self, summary: &ApiRequestSummary, stamp: &str) -> Option<ApiLearnedDeny> {
        let shape = ApiShape::from_summary(summary);
        let bucket = self.data.buckets.get(&shape.key())?;
        if !bucket.learned_deny || !Self::stamp_current(bucket, stamp) {
            return None;
        }
        if Self::expired(bucket, now_unix()) {
            return None;
        }
        Some(ApiLearnedDeny {
            shape,
            denials: bucket.denials,
            reason: bucket.last_reason.clone(),
            provenance: bucket.provenance,
        })
    }

    pub fn record_allow(
        &mut self,
        summary: &ApiRequestSummary,
        risk: Option<i32>,
        reversibility: Option<Reversibility>,
        reason: &str,
        stamp: &str,
    ) -> Result<Option<ApiPromotionOutcome>> {
        let config = self.config.clone();
        let mut first = Some(self.clone());
        let (current, outcome) = retry_learning_snapshot_conflicts(|| {
            let mut current = match first.take() {
                Some(current) => current,
                None => Self::load(config.clone())?,
            };
            let mut candidate = current.clone();
            let outcome =
                candidate.record_allow_in_memory(summary, risk, reversibility, reason, stamp)?;
            current.commit_candidate(candidate.data)?;
            Ok((current, outcome))
        })?;
        *self = current;
        Ok(outcome)
    }

    fn record_allow_in_memory(
        &mut self,
        summary: &ApiRequestSummary,
        risk: Option<i32>,
        reversibility: Option<Reversibility>,
        reason: &str,
        stamp: &str,
    ) -> Result<Option<ApiPromotionOutcome>> {
        if !self.config.enabled {
            return Ok(None);
        }
        // A dry-run request persists nothing, so the evaluator judges it more
        // leniently; it must never contribute evidence that a real, persisting
        // request of the same shape would ride.
        if summary.dry_run {
            return Ok(None);
        }
        // A value-free body skeleton cannot constrain the values in a write.
        // Until coverage carries field-aware value constraints, every
        // value-bearing mutation stays on the evaluator path.
        if !matches!(summary.verb.as_str(), "get" | "list" | "watch")
            && summary.redacted_body_shape != "(no body)"
        {
            return Ok(None);
        }
        let reason = sanitize_learning_text(reason);
        let class = reversibility;
        let risk = risk.unwrap_or(10);
        // An ineligible allow (no class, irreversible, or over the per-class risk
        // ceiling) permanently disqualifies the shape rather than being dropped,
        // so a low-risk subset cannot promote while riskier observations of the
        // same shape are silently ignored.
        let eligible = match class {
            Some(Reversibility::Reversible) => risk < EXECUTE_NOW_MAX_RISK,
            Some(Reversibility::Recoverable) => risk < HOLD_RISK_THRESHOLD,
            Some(Reversibility::Irreversible) | None => false,
        };

        let min_approvals = self.config.min_approvals.max(2);
        let expires_at = now_unix().saturating_add(self.config.generated_ttl_secs);
        let shape = ApiShape::from_summary(summary);
        if shape.contains_sensitive_literals() || stamp_contains_sensitive_literal(stamp) {
            anyhow::bail!(
                "API coverage observation contains sensitive authority metadata and was rejected"
            );
        }
        let Some(bucket) = self.bucket_mut(&shape, &reason, stamp) else {
            return Ok(None);
        };
        bucket.last_reason = reason;
        bucket.last_seen_unix = now_unix();
        bucket.expires_at_unix = Some(expires_at);
        push_evidence(bucket, summary);
        if !eligible {
            bucket.disqualified = true;
            bucket.max_risk_seen = bucket.max_risk_seen.max(risk);
            return Ok(None);
        }
        let class = class.expect("eligible implies a class");
        bucket.approvals = bucket.approvals.saturating_add(1);
        bucket.max_risk_seen = bucket.max_risk_seen.max(risk);
        match bucket.class_seen {
            None => bucket.class_seen = Some(class),
            Some(seen) if seen != class => bucket.mixed_class = true,
            Some(_) => {}
        }

        let promoted = !bucket.promoted_allow
            && !bucket.mixed_class
            && !bucket.disqualified
            && bucket.class_seen.is_some()
            && bucket.approvals >= min_approvals;
        if promoted {
            bucket.promoted_allow = true;
        }
        let approvals = bucket.approvals;
        let max_risk_seen = bucket.max_risk_seen;
        let class_seen = bucket.class_seen;

        if promoted {
            Ok(Some(ApiPromotionOutcome::AllowPromoted {
                shape,
                approvals,
                risk: max_risk_seen,
                reversibility: class_seen.expect("checked above"),
            }))
        } else {
            Ok(None)
        }
    }

    pub fn record_deny(
        &mut self,
        summary: &ApiRequestSummary,
        reason: &str,
        stamp: &str,
    ) -> Result<Option<ApiPromotionOutcome>> {
        let config = self.config.clone();
        let mut first = Some(self.clone());
        let (current, outcome) = retry_learning_snapshot_conflicts(|| {
            let mut current = match first.take() {
                Some(current) => current,
                None => Self::load(config.clone())?,
            };
            let mut candidate = current.clone();
            let outcome = candidate.record_deny_in_memory(summary, reason, stamp)?;
            current.commit_candidate(candidate.data)?;
            Ok((current, outcome))
        })?;
        *self = current;
        Ok(outcome)
    }

    fn record_deny_in_memory(
        &mut self,
        summary: &ApiRequestSummary,
        reason: &str,
        stamp: &str,
    ) -> Result<Option<ApiPromotionOutcome>> {
        if !self.config.enabled {
            return Ok(None);
        }
        if summary.dry_run {
            return Ok(None);
        }
        let reason = sanitize_learning_text(reason);
        let min_denials = self.config.min_denials.max(1);
        let expires_at = now_unix().saturating_add(self.config.generated_ttl_secs);
        let shape = ApiShape::from_summary(summary);
        if shape.contains_sensitive_literals() || stamp_contains_sensitive_literal(stamp) {
            anyhow::bail!(
                "API coverage observation contains sensitive authority metadata and was rejected"
            );
        }
        let Some(bucket) = self.bucket_mut(&shape, &reason, stamp) else {
            return Ok(None);
        };
        bucket.denials = bucket.denials.saturating_add(1);
        // One deny proves the value-free shape is not uniformly safe to
        // auto-allow. Keep future allows on the evaluator path even before the
        // deny reaches its own generation threshold.
        bucket.disqualified = true;
        bucket.promoted_allow = false;
        bucket.last_reason = reason;
        bucket.last_seen_unix = now_unix();
        bucket.expires_at_unix = Some(expires_at);
        push_evidence(bucket, summary);

        let learned = !bucket.learned_deny && bucket.denials >= min_denials;
        if learned {
            bucket.learned_deny = true;
        }
        let denials = bucket.denials;

        if learned {
            Ok(Some(ApiPromotionOutcome::DenyLearned { shape, denials }))
        } else {
            Ok(None)
        }
    }

    fn bucket_mut(
        &mut self,
        shape: &ApiShape,
        reason: &str,
        stamp: &str,
    ) -> Option<&mut ApiShapeBucket> {
        let generated_ttl_secs = self.config.generated_ttl_secs;
        let key = shape.key();
        if !self.data.buckets.contains_key(&key) && self.data.buckets.len() >= MAX_BUCKETS {
            let oldest_key = self
                .data
                .buckets
                .iter()
                .filter(|(_, bucket)| bucket.provenance == ApiCoverageProvenance::Evaluator)
                .min_by_key(|(_, bucket)| bucket.last_seen_unix)
                .map(|(key, _)| key.clone())?;
            self.data.buckets.remove(&oldest_key);
        }
        let now = now_unix();
        let bucket = self
            .data
            .buckets
            .entry(key)
            .or_insert_with(|| ApiShapeBucket {
                protocol: shape.protocol.clone(),
                endpoint: shape.endpoint.clone(),
                session_fingerprint: shape.session_fingerprint.clone(),
                session_revision: shape.session_revision.clone(),
                verb: shape.verb.clone(),
                group: shape.group.clone(),
                version: shape.version.clone(),
                resource: shape.resource.clone(),
                subresource: shape.subresource.clone(),
                namespace: shape.namespace.clone(),
                authority_selectors: shape.authority_selectors.clone(),
                body_shape: shape.body_shape.clone(),
                approvals: 0,
                denials: 0,
                evidence: Vec::new(),
                class_seen: None,
                mixed_class: false,
                disqualified: false,
                promoted_allow: false,
                learned_deny: false,
                stamp: stamp.to_string(),
                provenance: ApiCoverageProvenance::Evaluator,
                expires_at_unix: Some(now.saturating_add(generated_ttl_secs)),
                max_risk_seen: 0,
                first_seen_unix: now,
                last_seen_unix: now,
                last_reason: reason.to_string(),
            });
        // Evaluator observations never rewrite operator-authored authority,
        // including when the evaluator regime changes.
        if bucket.provenance == ApiCoverageProvenance::Operator {
            return None;
        }
        // A bucket learned under a different evaluator regime or past its TTL
        // must re-earn its evidence rather than becoming active again after one
        // fresh observation.
        let expired = bucket.provenance == ApiCoverageProvenance::Evaluator
            && bucket
                .expires_at_unix
                .is_some_and(|deadline| now >= deadline);
        if expired || (!stamp.is_empty() && bucket.stamp != stamp) {
            bucket.approvals = 0;
            bucket.denials = 0;
            bucket.evidence.clear();
            bucket.class_seen = None;
            bucket.mixed_class = false;
            bucket.disqualified = false;
            bucket.promoted_allow = false;
            bucket.learned_deny = false;
            bucket.max_risk_seen = 0;
            bucket.stamp = stamp.to_string();
            bucket.provenance = ApiCoverageProvenance::Evaluator;
            bucket.expires_at_unix = Some(now.saturating_add(generated_ttl_secs));
        }
        Some(bucket)
    }

    fn commit_candidate(&mut self, candidate: ApiPromotionFile) -> Result<()> {
        if candidate == self.data {
            return Ok(());
        }
        let outcome = self.save_data(&candidate)?;
        let (committed, warning) = outcome.into_parts();
        self.data = candidate;
        self.snapshot = committed;
        if let Some(error) = warning {
            tracing::warn!(
                "API coverage replacement committed with a durability warning: {}",
                error
            );
        }
        Ok(())
    }

    fn save_data(&self, data: &ApiPromotionFile) -> Result<LearningWriteOutcome> {
        #[cfg(test)]
        if self.fail_writes {
            anyhow::bail!("simulated API coverage write failure");
        }
        let content = self.canonical_content(data)?;
        write_learning_file_atomically_for_locked_snapshot(
            &self.config.path,
            &self.snapshot,
            &content,
        )
    }

    fn canonical_content(&self, data: &ApiPromotionFile) -> Result<String> {
        validate_current_api_file(data)?;
        Ok(serde_yaml_ng::to_string(data)?)
    }

    #[cfg(test)]
    fn fail_writes_for_test(&mut self) {
        self.fail_writes = true;
    }
}

/// Record the object name (not the shape, which is the bucket key) so the
/// persisted file shows an operator which concrete requests fed the bucket.
fn push_evidence(bucket: &mut ApiShapeBucket, summary: &ApiRequestSummary) {
    let evidence = sanitize_learning_text(
        &summary
            .name
            .clone()
            .unwrap_or_else(|| "(collection)".to_string()),
    );
    if !bucket.evidence.contains(&evidence) && bucket.evidence.len() < MAX_EVIDENCE_PER_BUCKET {
        bucket.evidence.push(evidence);
    }
}

impl AsyncDurableStore for ApiPromotionStore {
    fn authority_name(&self) -> &'static str {
        "API coverage"
    }

    fn durable_path(&self) -> Option<&Path> {
        Some(&self.config.path)
    }

    fn same_durable_snapshot(&self, snapshot: &LearningFileSnapshot) -> bool {
        self.snapshot.same_authority(snapshot)
    }

    fn same_in_memory_epoch(&self, other: &Self) -> bool {
        self.snapshot.same_authority(&other.snapshot) && self.data == other.data
    }
}

#[cfg(test)]
mod tests;
