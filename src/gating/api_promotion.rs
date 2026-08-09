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
    is_learning_snapshot_conflict, preserve_corrupt_learning_file,
    recover_learning_file_transaction, sanitize_learning_text,
    write_learning_file_atomically_for_snapshot, LearningWriteOutcome,
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
            body_shape: summary.redacted_body_shape.clone(),
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
    snapshot: Option<Vec<u8>>,
    #[cfg(test)]
    fail_writes: bool,
}

impl ApiPromotionStore {
    pub fn load(config: ApiPromotionConfig) -> Result<Self> {
        recover_learning_file_transaction(&config.path)?;
        let snapshot = if config.path.exists() {
            Some(
                std::fs::read(&config.path)
                    .with_context(|| format!("failed to read {}", config.path.display()))?,
            )
        } else {
            None
        };
        let mut data = if let Some(content) = snapshot.as_deref() {
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
            let outcome = write_learning_file_atomically_for_snapshot(
                &store.config.path,
                store.snapshot.as_deref(),
                &content,
            )?;
            store.snapshot = Some(content.into_bytes());
            if let Some(error) = outcome.warning() {
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

    pub fn clear_generated(&mut self) -> Result<usize> {
        let mut candidate = self.data.clone();
        let before = candidate.buckets.len();
        candidate
            .buckets
            .retain(|_, bucket| bucket.provenance == ApiCoverageProvenance::Operator);
        let removed = before.saturating_sub(candidate.buckets.len());
        if removed > 0 {
            self.commit_candidate(candidate)?;
        }
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
        let mut candidate = self.clone();
        let outcome =
            candidate.record_allow_in_memory(summary, risk, reversibility, reason, stamp)?;
        match self.commit_candidate(candidate.data) {
            Ok(()) => Ok(outcome),
            Err(error) if is_learning_snapshot_conflict(&error) => {
                let mut current = Self::load(self.config.clone())?;
                let mut retry = current.clone();
                let outcome =
                    retry.record_allow_in_memory(summary, risk, reversibility, reason, stamp)?;
                current.commit_candidate(retry.data)?;
                *self = current;
                Ok(outcome)
            }
            Err(error) => Err(error),
        }
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
        let mut candidate = self.clone();
        let outcome = candidate.record_deny_in_memory(summary, reason, stamp)?;
        match self.commit_candidate(candidate.data) {
            Ok(()) => Ok(outcome),
            Err(error) if is_learning_snapshot_conflict(&error) => {
                let mut current = Self::load(self.config.clone())?;
                let mut retry = current.clone();
                let outcome = retry.record_deny_in_memory(summary, reason, stamp)?;
                current.commit_candidate(retry.data)?;
                *self = current;
                Ok(outcome)
            }
            Err(error) => Err(error),
        }
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
        self.data = candidate;
        self.snapshot = Some(self.canonical_content(&self.data)?.into_bytes());
        if let Some(error) = outcome.warning() {
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
        write_learning_file_atomically_for_snapshot(
            &self.config.path,
            self.snapshot.as_deref(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::RevertConstructible;

    fn config(path: PathBuf, min_approvals: u32, min_denials: u32) -> ApiPromotionConfig {
        ApiPromotionConfig {
            path,
            enabled: true,
            min_approvals,
            min_denials,
            generated_ttl_secs: DEFAULT_GENERATED_TTL_SECS,
        }
    }

    fn summary(name: &str) -> ApiRequestSummary {
        ApiRequestSummary {
            protocol: "kubernetes".to_string(),
            verb: "get".to_string(),
            path: format!("/apis/apps/v1/namespaces/dev/deployments/{name}"),
            redacted_query: String::new(),
            group: "apps".to_string(),
            version: "v1".to_string(),
            resource: "deployments".to_string(),
            subresource: None,
            namespace: Some("dev".to_string()),
            name: Some(name.to_string()),
            dry_run: false,
            authority_selectors: BTreeMap::new(),
            redacted_body_shape: "{\"spec\":{\"replicas\":<number>}}".to_string(),
            revert_constructible: RevertConstructible::RestorePriorState,
            rarity: false,
            endpoint: "default".to_string(),
            session_fingerprint: None,
            session_revision: None,
            session_intent: None,
            credential_ref: "upstream".to_string(),
        }
    }

    #[test]
    fn approvals_promote_at_threshold_with_max_risk_and_class() {
        let temp = tempfile::tempdir().unwrap();
        let mut store =
            ApiPromotionStore::load(config(temp.path().join("api.yaml"), 2, 3)).unwrap();
        let s = summary("api");

        assert!(store
            .record_allow(&s, Some(1), Some(Reversibility::Reversible), "ok", "")
            .unwrap()
            .is_none());
        let outcome = store
            .record_allow(&s, Some(3), Some(Reversibility::Reversible), "ok", "")
            .unwrap()
            .unwrap();

        match outcome {
            ApiPromotionOutcome::AllowPromoted {
                approvals,
                risk,
                reversibility,
                ..
            } => {
                assert_eq!(approvals, 2);
                assert_eq!(risk, 3);
                assert_eq!(reversibility, Reversibility::Reversible);
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
        let learned = store.learned_allow(&s, "").unwrap();
        assert_eq!(learned.risk, 3);
        assert_eq!(learned.reversibility, Reversibility::Reversible);
    }

    #[test]
    fn failed_durable_write_does_not_commit_api_learning_state() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("api.yaml");
        let mut store = ApiPromotionStore::load(config(path.clone(), 3, 2)).unwrap();
        let request = summary("api");
        store.record_deny(&request, "no", "regime").unwrap();
        let before_memory = store.data.clone();
        let before_file = std::fs::read(&path).unwrap();

        store.fail_writes_for_test();
        assert!(store.record_deny(&request, "no", "regime").is_err());
        assert_eq!(store.data, before_memory);
        assert_eq!(std::fs::read(path).unwrap(), before_file);
        assert!(store.learned_deny(&request, "regime").is_none());
    }

    #[test]
    fn corrupt_api_coverage_fails_closed_and_deduplicates_verified_copies() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("api.yaml");
        let config = config(path.clone(), 3, 1);
        let request = summary("api");
        let mut store = ApiPromotionStore::load(config.clone()).unwrap();
        store.record_deny(&request, "no", "regime").unwrap();
        let mut corrupt = std::fs::read(&path).unwrap();
        corrupt.push(0xff);
        std::fs::write(&path, &corrupt).unwrap();

        assert!(ApiPromotionStore::load(config.clone()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), corrupt);
        assert!(ApiPromotionStore::load(config).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), corrupt);
        let copies = std::fs::read_dir(temp.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".api.yaml.corrupt-")
            })
            .collect::<Vec<_>>();
        assert_eq!(copies.len(), 1);
        assert!(copies
            .iter()
            .all(|entry| std::fs::read(entry.path()).unwrap() == corrupt));
    }

    #[test]
    fn current_api_coverage_rejects_newer_schema_unknown_fields_and_key_mismatch() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("api.yaml");
        let cfg = config(path.clone(), 2, 1);
        let request = summary("api");
        let mut store = ApiPromotionStore::load(cfg.clone()).unwrap();
        store.record_deny(&request, "no", "regime").unwrap();
        let original = std::fs::read(&path).unwrap();

        let mut newer = store.data.clone();
        newer.version = default_version() + 1;
        std::fs::write(&path, serde_yaml_ng::to_string(&newer).unwrap()).unwrap();
        assert!(ApiPromotionStore::load(cfg.clone()).is_err());

        let mut unknown = String::from_utf8(original.clone()).unwrap();
        unknown.push_str("unknown_authority_field: true\n");
        std::fs::write(&path, unknown).unwrap();
        assert!(ApiPromotionStore::load(cfg.clone()).is_err());

        let mut missing_version: serde_yaml_ng::Value =
            serde_yaml_ng::from_slice(&original).unwrap();
        missing_version
            .as_mapping_mut()
            .unwrap()
            .remove(serde_yaml_ng::Value::String("version".to_string()));
        std::fs::write(&path, serde_yaml_ng::to_string(&missing_version).unwrap()).unwrap();
        assert!(ApiPromotionStore::load(cfg.clone()).is_err());

        let mut mismatched = store.data.clone();
        let (key, bucket) = mismatched.buckets.pop_first().unwrap();
        mismatched.buckets.insert(format!("{key}-changed"), bucket);
        std::fs::write(&path, serde_yaml_ng::to_string(&mismatched).unwrap()).unwrap();
        assert!(ApiPromotionStore::load(cfg).is_err());
    }

    #[test]
    fn legacy_api_key_collision_fails_closed_without_rewriting_authority() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("api.yaml");
        let cfg = config(path.clone(), 2, 1);
        let request = summary("api");
        let mut store = ApiPromotionStore::load(cfg.clone()).unwrap();
        store.record_deny(&request, "no", "regime").unwrap();
        let bucket = store.data.buckets.values().next().unwrap().clone();
        let mut legacy = ApiPromotionFile {
            version: default_version() - 1,
            buckets: BTreeMap::new(),
        };
        legacy
            .buckets
            .insert("legacy-one".to_string(), bucket.clone());
        legacy.buckets.insert("legacy-two".to_string(), bucket);
        let bytes = serde_yaml_ng::to_string(&legacy).unwrap();
        std::fs::write(&path, &bytes).unwrap();

        assert!(ApiPromotionStore::load(cfg).is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), bytes);
    }

    #[test]
    fn sensitive_api_authority_is_rejected_without_changing_safe_state() {
        let value = ["q", "7"].concat();
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("api.yaml");
        let config = config(path.clone(), 2, 2);
        let mut store = ApiPromotionStore::load(config.clone()).unwrap();
        let safe = summary("safe");
        store.record_deny(&safe, "no", "regime").unwrap();
        let before_memory = store.data.clone();
        let before_file = std::fs::read(&path).unwrap();
        let mut sensitive = summary("sensitive");
        sensitive
            .authority_selectors
            .insert("password".to_string(), value.clone());

        assert!(store.record_deny(&sensitive, "no", "regime").is_err());
        assert_eq!(store.data, before_memory);
        assert_eq!(std::fs::read(&path).unwrap(), before_file);
        assert!(store
            .record_deny(&safe, "no", &format!("password={value}"))
            .is_err());
        assert_eq!(store.data, before_memory);
        assert_eq!(std::fs::read(&path).unwrap(), before_file);

        let mut contaminated = before_memory;
        let mut bucket = contaminated.buckets.values().next().unwrap().clone();
        bucket
            .authority_selectors
            .insert("password".to_string(), value.clone());
        contaminated
            .buckets
            .insert("contaminated".to_string(), bucket);
        let bytes = serde_yaml_ng::to_string(&contaminated).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        assert!(ApiPromotionStore::load(config).is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), bytes);
    }

    #[test]
    fn api_reason_fields_are_sanitized_on_mutation_and_reload() {
        let value = ["q", "7"].concat();
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("api.yaml");
        let config = config(path.clone(), 2, 1);
        let mut store = ApiPromotionStore::load(config.clone()).unwrap();
        let request = summary("api");
        store
            .record_deny(&request, &format!("password={value}"), "fixture")
            .unwrap();
        assert!(!std::fs::read_to_string(&path).unwrap().contains(&value));

        let bucket = store.data.buckets.values_mut().next().unwrap();
        bucket.last_reason = format!("password={value}");
        store.save_data(&store.data).unwrap();
        let reloaded = ApiPromotionStore::load(config).unwrap();
        let hit = reloaded.learned_deny(&request, "fixture").unwrap();
        assert!(!hit.reason.contains(&value));
        assert!(!std::fs::read_to_string(path).unwrap().contains(&value));
    }

    #[test]
    fn value_bearing_mutations_never_promote_without_field_constraints() {
        let temp = tempfile::tempdir().unwrap();
        let mut store =
            ApiPromotionStore::load(config(temp.path().join("api.yaml"), 2, 3)).unwrap();
        let mut write = summary("api");
        write.verb = "patch".to_string();

        for _ in 0..4 {
            assert!(store
                .record_allow(
                    &write,
                    Some(1),
                    Some(Reversibility::Reversible),
                    "ok",
                    "regime-A",
                )
                .unwrap()
                .is_none());
        }
        assert_eq!(store.bucket_count(), 0);
        assert!(store.learned_allow(&write, "regime-A").is_none());
    }

    #[test]
    fn evaluator_evidence_never_mutates_operator_coverage() {
        let temp = tempfile::tempdir().unwrap();
        let mut store =
            ApiPromotionStore::load(config(temp.path().join("api.yaml"), 2, 2)).unwrap();
        let request = summary("api");
        let shape = ApiShape::from_summary(&request);
        store
            .record_deny(&request, "operator decision seed", "regime-A")
            .unwrap();
        let bucket = store.data.buckets.get_mut(&shape.key()).unwrap();
        bucket.provenance = ApiCoverageProvenance::Operator;
        bucket.last_reason = "operator deny".to_string();
        bucket.learned_deny = true;
        let before = serde_yaml_ng::to_string(bucket).unwrap();

        store
            .record_allow(
                &request,
                Some(1),
                Some(Reversibility::Reversible),
                "evaluator allow",
                "regime-B",
            )
            .unwrap();
        store
            .record_deny(&request, "evaluator deny", "regime-B")
            .unwrap();

        let after =
            serde_yaml_ng::to_string(store.data.buckets.get(&shape.key()).unwrap()).unwrap();
        assert_eq!(after, before);
        assert_eq!(
            store
                .learned_deny(&request, "unrelated-regime")
                .unwrap()
                .provenance,
            ApiCoverageProvenance::Operator
        );
    }

    #[test]
    fn mixed_classes_disqualify_allow_promotion() {
        let temp = tempfile::tempdir().unwrap();
        let mut store =
            ApiPromotionStore::load(config(temp.path().join("api.yaml"), 2, 3)).unwrap();
        let s = summary("api");

        store
            .record_allow(&s, Some(1), Some(Reversibility::Reversible), "ok", "")
            .unwrap();
        let second = store
            .record_allow(&s, Some(1), Some(Reversibility::Recoverable), "ok", "")
            .unwrap();

        assert!(second.is_none());
        assert!(store.learned_allow(&s, "").is_none());
    }

    #[test]
    fn full_session_revision_partitions_coverage_and_unchanged_revision_hits() {
        let temp = tempfile::tempdir().unwrap();
        let mut store =
            ApiPromotionStore::load(config(temp.path().join("api.yaml"), 2, 2)).unwrap();
        let mut first = summary("api");
        first.session_fingerprint = Some("session".to_string());
        first.session_revision = Some("revision-one".to_string());
        for _ in 0..2 {
            store
                .record_allow(
                    &first,
                    Some(1),
                    Some(Reversibility::Reversible),
                    "ok",
                    "regime-one",
                )
                .unwrap();
        }
        assert!(store.learned_allow(&first, "regime-one").is_some());
        assert!(store.learned_allow(&first.clone(), "regime-one").is_some());

        let mut edited = first.clone();
        edited.session_revision = Some("revision-two".to_string());
        assert!(store.learned_allow(&edited, "regime-one").is_none());
        assert_ne!(
            ApiShape::from_summary(&first).key(),
            ApiShape::from_summary(&edited).key()
        );
    }

    #[test]
    fn authority_selectors_partition_typed_coverage() {
        let mut first = summary("api");
        first
            .authority_selectors
            .insert("teamId".to_string(), "team-a".to_string());
        let mut second = first.clone();
        second
            .authority_selectors
            .insert("teamId".to_string(), "team-b".to_string());
        assert_ne!(
            ApiShape::from_summary(&first).key(),
            ApiShape::from_summary(&second).key()
        );
    }

    #[test]
    fn risk_ceiling_blocks_allow_promotion_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let mut store =
            ApiPromotionStore::load(config(temp.path().join("api.yaml"), 2, 3)).unwrap();
        let s = summary("api");

        let result = store
            .record_allow(
                &s,
                Some(EXECUTE_NOW_MAX_RISK),
                Some(Reversibility::Reversible),
                "too risky",
                "",
            )
            .unwrap();

        // An over-ceiling allow does not promote, and it disqualifies the shape
        // (recorded, not dropped) so a later low-risk subset cannot promote it.
        assert!(result.is_none());
        assert_eq!(store.bucket_count(), 1);
        assert!(store.learned_allow(&s, "").is_none());
    }

    #[test]
    fn denials_learn_fast_deny_at_threshold() {
        let temp = tempfile::tempdir().unwrap();
        let mut store =
            ApiPromotionStore::load(config(temp.path().join("api.yaml"), 5, 2)).unwrap();
        let s = summary("api");

        assert!(store.record_deny(&s, "no", "").unwrap().is_none());
        let outcome = store.record_deny(&s, "no", "").unwrap().unwrap();

        match outcome {
            ApiPromotionOutcome::DenyLearned { denials, .. } => assert_eq!(denials, 2),
            other => panic!("unexpected outcome: {other:?}"),
        }
        assert_eq!(store.learned_deny(&s, "").unwrap().denials, 2);
    }

    #[test]
    fn observation_buckets_are_lru_capped() {
        let temp = tempfile::tempdir().unwrap();
        let mut store =
            ApiPromotionStore::load(config(temp.path().join("api.yaml"), 2, 2)).unwrap();

        let mut seeded_keys = Vec::new();
        for i in 0..MAX_BUCKETS {
            let bucket = ApiShapeBucket {
                endpoint: String::new(),
                session_fingerprint: None,
                session_revision: None,
                protocol: format!("p{i}"),
                verb: "get".to_string(),
                group: String::new(),
                version: "v1".to_string(),
                resource: "pods".to_string(),
                subresource: None,
                namespace: Some(format!("ns{i}")),
                authority_selectors: BTreeMap::new(),
                body_shape: "{}".to_string(),
                approvals: 1,
                denials: 0,
                evidence: Vec::new(),
                class_seen: Some(Reversibility::Reversible),
                mixed_class: false,
                disqualified: false,
                promoted_allow: false,
                learned_deny: false,
                stamp: String::new(),
                provenance: ApiCoverageProvenance::Evaluator,
                expires_at_unix: None,
                max_risk_seen: 1,
                first_seen_unix: i as u64,
                last_seen_unix: i as u64,
                last_reason: String::new(),
            };
            let key = shape_from_bucket(&bucket).key();
            seeded_keys.push(key.clone());
            store.data.buckets.insert(key, bucket);
        }
        store
            .data
            .buckets
            .get_mut(&seeded_keys[0])
            .unwrap()
            .provenance = ApiCoverageProvenance::Operator;
        assert_eq!(store.bucket_count(), MAX_BUCKETS);

        store
            .record_deny(&summary("brand-new"), "no", "")
            .expect("record deny");

        assert_eq!(store.bucket_count(), MAX_BUCKETS);
        assert!(store.data.buckets.contains_key(&seeded_keys[0]));
        assert!(!store.data.buckets.contains_key(&seeded_keys[1]));
    }

    #[test]
    fn yaml_round_trip_preserves_promoted_shape() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("api.yaml");
        let s = summary("api");
        {
            let mut store = ApiPromotionStore::load(config(path.clone(), 2, 2)).unwrap();
            store
                .record_allow(&s, Some(1), Some(Reversibility::Reversible), "ok", "")
                .unwrap();
            store
                .record_allow(&s, Some(2), Some(Reversibility::Reversible), "ok", "")
                .unwrap();
        }

        let store = ApiPromotionStore::load(config(path, 2, 2)).unwrap();
        assert!(store.learned_allow(&s, "").is_some());
    }

    #[test]
    fn object_name_is_excluded_from_keying() {
        let temp = tempfile::tempdir().unwrap();
        let mut store =
            ApiPromotionStore::load(config(temp.path().join("api.yaml"), 2, 3)).unwrap();

        store
            .record_allow(
                &summary("api-a"),
                Some(1),
                Some(Reversibility::Reversible),
                "ok",
                "",
            )
            .unwrap();
        store
            .record_allow(
                &summary("api-b"),
                Some(1),
                Some(Reversibility::Reversible),
                "ok",
                "",
            )
            .unwrap();

        assert_eq!(store.bucket_count(), 1);
        assert!(store.learned_allow(&summary("api-c"), "").is_some());
    }

    #[test]
    fn dry_run_requests_never_feed_promotion() {
        let temp = tempfile::tempdir().unwrap();
        let mut store =
            ApiPromotionStore::load(config(temp.path().join("api.yaml"), 2, 2)).unwrap();
        let mut s = summary("api");
        s.dry_run = true;

        for _ in 0..5 {
            assert!(store
                .record_allow(&s, Some(1), Some(Reversibility::Reversible), "ok", "")
                .unwrap()
                .is_none());
        }
        // A real request of the same shape must still be judged fresh.
        let mut real = summary("api");
        real.dry_run = false;
        assert!(store.learned_allow(&real, "").is_none());
        assert_eq!(store.bucket_count(), 0);
    }

    #[test]
    fn a_different_body_shape_is_a_different_bucket() {
        let temp = tempfile::tempdir().unwrap();
        let mut store =
            ApiPromotionStore::load(config(temp.path().join("api.yaml"), 2, 2)).unwrap();
        let base = summary("api");
        store
            .record_allow(&base, Some(1), Some(Reversibility::Reversible), "ok", "")
            .unwrap();
        store
            .record_allow(&base, Some(1), Some(Reversibility::Reversible), "ok", "")
            .unwrap();
        assert!(store.learned_allow(&base, "").is_some());

        // Same verb/resource/namespace, different body structure: not covered.
        let mut other = summary("api");
        other.redacted_body_shape = "{\"spec\":{\"image\":<string>}}".to_string();
        assert!(store.learned_allow(&other, "").is_none());
    }

    #[test]
    fn an_ineligible_allow_disqualifies_the_shape() {
        let temp = tempfile::tempdir().unwrap();
        let mut store =
            ApiPromotionStore::load(config(temp.path().join("api.yaml"), 2, 2)).unwrap();
        let s = summary("api");
        // One low-risk allow, then a high-risk allow of the same shape.
        store
            .record_allow(&s, Some(1), Some(Reversibility::Reversible), "ok", "")
            .unwrap();
        store
            .record_allow(&s, Some(99), Some(Reversibility::Reversible), "risky", "")
            .unwrap();
        // Further low-risk allows must not resurrect promotion.
        store
            .record_allow(&s, Some(1), Some(Reversibility::Reversible), "ok", "")
            .unwrap();
        store
            .record_allow(&s, Some(1), Some(Reversibility::Reversible), "ok", "")
            .unwrap();
        assert!(
            store.learned_allow(&s, "").is_none(),
            "a shape with any ineligible observation must never fast-path allow"
        );
    }

    #[test]
    fn a_stamp_change_invalidates_prior_learning() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("api.yaml");
        let s = summary("api");
        {
            let mut store = ApiPromotionStore::load(config(path.clone(), 2, 2)).unwrap();
            store
                .record_allow(
                    &s,
                    Some(1),
                    Some(Reversibility::Reversible),
                    "ok",
                    "regime-A",
                )
                .unwrap();
            store
                .record_allow(
                    &s,
                    Some(1),
                    Some(Reversibility::Reversible),
                    "ok",
                    "regime-A",
                )
                .unwrap();
            assert!(store.learned_allow(&s, "regime-A").is_some());
        }
        // Reload and consult under a narrowed intent (new stamp): the old
        // promotion is not trusted, and a fresh allow starts the count over.
        let mut store = ApiPromotionStore::load(config(path, 2, 2)).unwrap();
        assert!(store.learned_allow(&s, "regime-B").is_none());
        assert!(store
            .record_allow(
                &s,
                Some(1),
                Some(Reversibility::Reversible),
                "ok",
                "regime-B"
            )
            .unwrap()
            .is_none());
        assert!(store.learned_allow(&s, "regime-B").is_none());
    }

    #[test]
    fn old_generated_coverage_migrates_to_bounded_expiry() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("api.yaml");
        std::fs::write(
            &path,
            r#"version: 1
buckets:
  old:
    protocol: kubernetes
    verb: get
    group: ''
    version: v1
    resource: pods
    approvals: 5
    denials: 0
    promoted_allow: true
    stamp: old-regime
    max_risk_seen: 1
    first_seen_unix: 1
    last_seen_unix: 1
    last_reason: ok
"#,
        )
        .unwrap();
        let store = ApiPromotionStore::load(config(path, 2, 2)).unwrap();
        let entries = store.coverage();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].provenance, ApiCoverageProvenance::Evaluator);
        assert!(entries[0].expires_at_unix.is_some());
        assert!(!entries[0].active, "ancient migrated coverage is stale");
    }

    #[test]
    fn old_bucket_keys_migrate_to_the_default_endpoint() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("api.yaml");
        let now = now_unix();
        std::fs::write(
            &path,
            format!(
                r#"version: 1
buckets:
  kubernetes|get|apps|v1|deployments||dev|body:
    protocol: kubernetes
    verb: get
    group: apps
    version: v1
    resource: deployments
    namespace: dev
    body_shape: '{{"spec":{{"replicas":<number>}}}}'
    approvals: 5
    denials: 0
    class_seen: reversible
    promoted_allow: true
    stamp: old-regime
    max_risk_seen: 1
    first_seen_unix: {now}
    last_seen_unix: {now}
    last_reason: ok
"#
            ),
        )
        .unwrap();
        let store = ApiPromotionStore::load(config(path, 2, 2)).unwrap();
        let s = summary("api");
        assert!(store.learned_allow(&s, "old-regime").is_some());
        let entries = store.coverage();
        assert_eq!(entries[0].endpoint, "default");
    }

    #[test]
    fn any_deny_disqualifies_an_existing_generated_allow() {
        let temp = tempfile::tempdir().unwrap();
        let mut store =
            ApiPromotionStore::load(config(temp.path().join("api.yaml"), 2, 2)).unwrap();
        let s = summary("api");
        for _ in 0..2 {
            store
                .record_allow(&s, Some(1), Some(Reversibility::Reversible), "ok", "regime")
                .unwrap();
        }
        assert!(store.learned_allow(&s, "regime").is_some());

        store
            .record_deny(&s, "unsafe value in this shape", "regime")
            .unwrap();
        assert!(store.learned_allow(&s, "regime").is_none());
        store
            .record_deny(&s, "unsafe value in this shape", "regime")
            .unwrap();
        assert!(store.learned_deny(&s, "regime").is_some());
        assert_eq!(store.coverage()[0].decision, "deny");
    }

    #[test]
    fn generated_coverage_is_scoped_by_endpoint_and_session() {
        let temp = tempfile::tempdir().unwrap();
        let mut store =
            ApiPromotionStore::load(config(temp.path().join("api.yaml"), 2, 2)).unwrap();
        let mut scoped = summary("api");
        scoped.endpoint = "cluster-a".to_string();
        scoped.session_fingerprint = Some("session-a".to_string());
        for _ in 0..2 {
            store
                .record_allow(
                    &scoped,
                    Some(1),
                    Some(Reversibility::Reversible),
                    "ok",
                    "regime",
                )
                .unwrap();
        }
        assert!(store.learned_allow(&scoped, "regime").is_some());
        let mut other_session = scoped.clone();
        other_session.session_fingerprint = Some("session-b".to_string());
        assert!(store.learned_allow(&other_session, "regime").is_none());
        let mut other_endpoint = scoped.clone();
        other_endpoint.endpoint = "cluster-b".to_string();
        assert!(store.learned_allow(&other_endpoint, "regime").is_none());
        assert_eq!(store.clear_generated().unwrap(), 1);
        assert!(store.coverage().is_empty());
    }

    #[test]
    fn expired_coverage_restarts_evidence_collection() {
        let temp = tempfile::tempdir().unwrap();
        let mut store =
            ApiPromotionStore::load(config(temp.path().join("api.yaml"), 2, 2)).unwrap();
        let s = summary("api");
        for _ in 0..2 {
            store
                .record_allow(&s, Some(1), Some(Reversibility::Reversible), "ok", "regime")
                .unwrap();
        }
        assert!(store.learned_allow(&s, "regime").is_some());
        let bucket = store
            .data
            .buckets
            .get_mut(&ApiShape::from_summary(&s).key())
            .unwrap();
        bucket.expires_at_unix = Some(now_unix());

        store
            .record_allow(
                &s,
                Some(1),
                Some(Reversibility::Reversible),
                "fresh",
                "regime",
            )
            .unwrap();
        assert!(
            store.learned_allow(&s, "regime").is_none(),
            "one observation must not reactivate expired generated coverage"
        );
    }

    #[test]
    fn stale_api_instances_merge_observations_and_preserve_concurrent_denies() {
        let temp = tempfile::tempdir().unwrap();
        let config = config(temp.path().join("api.yaml"), 2, 1);
        let mut first = ApiPromotionStore::load(config.clone()).unwrap();
        let mut second = ApiPromotionStore::load(config.clone()).unwrap();
        let request = summary("api");

        first
            .record_allow(
                &request,
                Some(1),
                Some(Reversibility::Reversible),
                "safe",
                "regime",
            )
            .unwrap();
        second
            .record_allow(
                &request,
                Some(1),
                Some(Reversibility::Reversible),
                "safe",
                "regime",
            )
            .unwrap();
        assert!(second.learned_allow(&request, "regime").is_some());

        let mut deny_writer = ApiPromotionStore::load(config.clone()).unwrap();
        let mut stale_allow_writer = ApiPromotionStore::load(config.clone()).unwrap();
        deny_writer
            .record_deny(&request, "unsafe", "regime")
            .unwrap();
        stale_allow_writer
            .record_allow(
                &request,
                Some(1),
                Some(Reversibility::Reversible),
                "safe",
                "regime",
            )
            .unwrap();

        let loaded = ApiPromotionStore::load(config).unwrap();
        assert!(loaded.learned_allow(&request, "regime").is_none());
        assert!(loaded.learned_deny(&request, "regime").is_some());
    }
}
