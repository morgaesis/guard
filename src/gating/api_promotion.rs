//! Evidence-based API request shape learning for proxied `evaluate` traffic.
//!
//! API promotion is deterministic: the learned shape is the exact observed
//! `(protocol, verb, group, version, resource, subresource, namespace,
//! body-shape)` tuple, with the object name deliberately excluded and the body
//! reduced to a value-free key skeleton. There is no regex and no model-authored
//! synthesis in this path, so a promoted shape matches only requests structurally
//! identical to the ones the evaluator approved. A learned verdict is stamped
//! with the evaluator regime (model plus intent) that produced it and is
//! distrusted once that regime changes, mirroring verb-promotion stamping.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::{Reversibility, EXECUTE_NOW_MAX_RISK, HOLD_RISK_THRESHOLD};
use crate::env::now_unix;
use crate::proxy::ApiRequestSummary;

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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApiPromotionFile {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub buckets: BTreeMap<String, ApiShapeBucket>,
}

fn default_version() -> u32 {
    3
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
        // Escape the field delimiter so no component value can collide two
        // distinct shapes into one bucket.
        fn esc(s: &str) -> String {
            s.replace('\\', "\\\\").replace('|', "\\|")
        }
        let authority_selectors = self
            .authority_selectors
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(",");
        [
            self.endpoint.as_str(),
            self.session_fingerprint.as_deref().unwrap_or(""),
            self.session_revision.as_deref().unwrap_or(""),
            self.protocol.as_str(),
            self.verb.as_str(),
            self.group.as_str(),
            self.version.as_str(),
            self.resource.as_str(),
            self.subresource.as_deref().unwrap_or(""),
            self.namespace.as_deref().unwrap_or(""),
            authority_selectors.as_str(),
            self.body_shape.as_str(),
        ]
        .iter()
        .map(|f| esc(f))
        .collect::<Vec<_>>()
        .join("|")
    }

    pub fn audit_label(&self) -> String {
        format!(
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
        )
    }
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
}

impl ApiPromotionStore {
    pub fn load(config: ApiPromotionConfig) -> Result<Self> {
        let mut data = if config.path.exists() {
            let content = std::fs::read_to_string(&config.path)
                .with_context(|| format!("failed to read {}", config.path.display()))?;
            if content.trim().is_empty() {
                ApiPromotionFile::default()
            } else {
                match serde_yaml_ng::from_str(&content) {
                    Ok(data) => data,
                    // A corrupt learned-shape file must never brick daemon
                    // startup. Quarantine it, start from an empty store, and
                    // surface it loudly so an operator can inspect the salvage.
                    Err(e) => {
                        let quarantine = config.path.with_extension("corrupt");
                        let _ = std::fs::rename(&config.path, &quarantine);
                        tracing::error!(target: "guard::audit",
                            "[AUDIT] API_PROMOTION_CORRUPT path=\"{}\" quarantined=\"{}\" error={} (starting from an empty store)",
                            config.path.display(),
                            quarantine.display(),
                            e
                        );
                        ApiPromotionFile::default()
                    }
                }
            }
        } else {
            ApiPromotionFile::default()
        };
        let now = now_unix();
        let mut migrated: BTreeMap<String, ApiShapeBucket> = BTreeMap::new();
        for (_, mut bucket) in std::mem::take(&mut data.buckets) {
            if bucket.endpoint.is_empty() {
                bucket.endpoint = "default".to_string();
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
            }
            let shape = ApiShape {
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
            };
            let key = shape.key();
            match migrated.get(&key) {
                Some(existing) if existing.last_seen_unix >= bucket.last_seen_unix => {}
                _ => {
                    migrated.insert(key, bucket);
                }
            }
        }
        data.version = default_version();
        data.buckets = migrated;
        Ok(Self { config, data })
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
        let before = self.data.buckets.len();
        self.data
            .buckets
            .retain(|_, bucket| bucket.provenance == ApiCoverageProvenance::Operator);
        let removed = before.saturating_sub(self.data.buckets.len());
        if removed > 0 {
            self.save()?;
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
        let Some(bucket) = self.bucket_mut(&shape, reason, stamp) else {
            return Ok(None);
        };
        bucket.last_reason = reason.to_string();
        bucket.last_seen_unix = now_unix();
        bucket.expires_at_unix = Some(expires_at);
        push_evidence(bucket, summary);
        if !eligible {
            bucket.disqualified = true;
            bucket.max_risk_seen = bucket.max_risk_seen.max(risk);
            self.save()?;
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

        self.save()?;

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
        if !self.config.enabled {
            return Ok(None);
        }
        if summary.dry_run {
            return Ok(None);
        }
        let min_denials = self.config.min_denials.max(1);
        let expires_at = now_unix().saturating_add(self.config.generated_ttl_secs);
        let shape = ApiShape::from_summary(summary);
        let Some(bucket) = self.bucket_mut(&shape, reason, stamp) else {
            return Ok(None);
        };
        bucket.denials = bucket.denials.saturating_add(1);
        // One deny proves the value-free shape is not uniformly safe to
        // auto-allow. Keep future allows on the evaluator path even before the
        // deny reaches its own generation threshold.
        bucket.disqualified = true;
        bucket.promoted_allow = false;
        bucket.last_reason = reason.to_string();
        bucket.last_seen_unix = now_unix();
        bucket.expires_at_unix = Some(expires_at);
        push_evidence(bucket, summary);

        let learned = !bucket.learned_deny && bucket.denials >= min_denials;
        if learned {
            bucket.learned_deny = true;
        }
        let denials = bucket.denials;

        self.save()?;

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

    fn save(&self) -> Result<()> {
        if let Some(parent) = self.config.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let content = serde_yaml_ng::to_string(&self.data)?;
        // Write to a sibling temp file and rename, so a crash mid-write cannot
        // truncate the store into unparseable YAML.
        let tmp = self.config.path.with_extension("tmp");
        std::fs::write(&tmp, content)
            .with_context(|| format!("failed to write {}", tmp.display()))?;
        std::fs::rename(&tmp, &self.config.path)
            .with_context(|| format!("failed to replace {}", self.config.path.display()))
    }
}

/// Record the object name (not the shape, which is the bucket key) so the
/// persisted file shows an operator which concrete requests fed the bucket.
fn push_evidence(bucket: &mut ApiShapeBucket, summary: &ApiRequestSummary) {
    let evidence = summary
        .name
        .clone()
        .unwrap_or_else(|| "(collection)".to_string());
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

        for i in 0..MAX_BUCKETS {
            let key = format!("p{i}|get||v1|pods||ns{i}|{{}}");
            store.data.buckets.insert(
                key,
                ApiShapeBucket {
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
                },
            );
        }
        store
            .data
            .buckets
            .get_mut("p0|get||v1|pods||ns0|{}")
            .unwrap()
            .provenance = ApiCoverageProvenance::Operator;
        assert_eq!(store.bucket_count(), MAX_BUCKETS);

        store
            .record_deny(&summary("brand-new"), "no", "")
            .expect("record deny");

        assert_eq!(store.bucket_count(), MAX_BUCKETS);
        assert!(store.data.buckets.contains_key("p0|get||v1|pods||ns0|{}"));
        assert!(!store.data.buckets.contains_key("p1|get||v1|pods||ns1|{}"));
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
}
