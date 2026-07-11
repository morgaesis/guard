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

#[derive(Debug, Clone)]
pub struct ApiPromotionConfig {
    pub path: PathBuf,
    pub enabled: bool,
    pub min_approvals: u32,
    pub min_denials: u32,
}

impl ApiPromotionConfig {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            enabled: true,
            min_approvals: 5,
            min_denials: 3,
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
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiShapeBucket {
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
    pub max_risk_seen: i32,
    pub first_seen_unix: u64,
    pub last_seen_unix: u64,
    pub last_reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiShape {
    pub protocol: String,
    pub verb: String,
    pub group: String,
    pub version: String,
    pub resource: String,
    pub subresource: Option<String>,
    pub namespace: Option<String>,
    /// The value-free body key skeleton. Included so promotion is scoped to the
    /// exact request structure the evaluator approved; a request that adds or
    /// renames a field lands in a different bucket and is judged fresh.
    pub body_shape: String,
}

impl ApiShape {
    pub fn from_summary(summary: &ApiRequestSummary) -> Self {
        Self {
            protocol: summary.protocol.clone(),
            verb: summary.verb.clone(),
            group: summary.group.clone(),
            version: summary.version.clone(),
            resource: summary.resource.clone(),
            subresource: summary.subresource.clone(),
            namespace: summary.namespace.clone(),
            body_shape: summary.redacted_body_shape.clone(),
        }
    }

    fn key(&self) -> String {
        // Escape the field delimiter so no component value can collide two
        // distinct shapes into one bucket.
        fn esc(s: &str) -> String {
            s.replace('\\', "\\\\").replace('|', "\\|")
        }
        [
            self.protocol.as_str(),
            self.verb.as_str(),
            self.group.as_str(),
            self.version.as_str(),
            self.resource.as_str(),
            self.subresource.as_deref().unwrap_or(""),
            self.namespace.as_deref().unwrap_or(""),
            self.body_shape.as_str(),
        ]
        .iter()
        .map(|f| esc(f))
        .collect::<Vec<_>>()
        .join("|")
    }

    pub fn audit_label(&self) -> String {
        format!(
            "protocol={} verb={} group={} version={} resource={} subresource={} namespace={}",
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
            self.namespace.as_deref().unwrap_or("(cluster)")
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
        let data = if config.path.exists() {
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
                        tracing::error!(
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

    /// Whether a bucket's learned state was produced under the given evaluator
    /// regime stamp. An empty stamp disables the check (no intent configured, or
    /// tests).
    fn stamp_current(bucket: &ApiShapeBucket, stamp: &str) -> bool {
        stamp.is_empty() || bucket.stamp == stamp
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
        Some(ApiLearnedDeny {
            shape,
            denials: bucket.denials,
            reason: bucket.last_reason.clone(),
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
        let shape = ApiShape::from_summary(summary);
        let bucket = self.bucket_mut(&shape, reason, stamp);
        bucket.last_reason = reason.to_string();
        bucket.last_seen_unix = now_unix();
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
        let shape = ApiShape::from_summary(summary);
        let bucket = self.bucket_mut(&shape, reason, stamp);
        bucket.denials = bucket.denials.saturating_add(1);
        bucket.last_reason = reason.to_string();
        bucket.last_seen_unix = now_unix();
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

    fn bucket_mut(&mut self, shape: &ApiShape, reason: &str, stamp: &str) -> &mut ApiShapeBucket {
        let key = shape.key();
        if !self.data.buckets.contains_key(&key) && self.data.buckets.len() >= MAX_BUCKETS {
            if let Some(oldest_key) = self
                .data
                .buckets
                .iter()
                .min_by_key(|(_, bucket)| bucket.last_seen_unix)
                .map(|(key, _)| key.clone())
            {
                self.data.buckets.remove(&oldest_key);
            }
        }
        let now = now_unix();
        let bucket = self
            .data
            .buckets
            .entry(key)
            .or_insert_with(|| ApiShapeBucket {
                protocol: shape.protocol.clone(),
                verb: shape.verb.clone(),
                group: shape.group.clone(),
                version: shape.version.clone(),
                resource: shape.resource.clone(),
                subresource: shape.subresource.clone(),
                namespace: shape.namespace.clone(),
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
                max_risk_seen: 0,
                first_seen_unix: now,
                last_seen_unix: now,
                last_reason: reason.to_string(),
            });
        // A bucket learned under a different evaluator regime is stale: reset its
        // accrued state so learning restarts under the new stamp rather than
        // topping up a rule the current model and intent never produced.
        if !stamp.is_empty() && bucket.stamp != stamp {
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
        }
        bucket
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
        }
    }

    fn summary(name: &str) -> ApiRequestSummary {
        ApiRequestSummary {
            protocol: "kubernetes".to_string(),
            verb: "patch".to_string(),
            path: format!("/apis/apps/v1/namespaces/dev/deployments/{name}"),
            redacted_query: String::new(),
            group: "apps".to_string(),
            version: "v1".to_string(),
            resource: "deployments".to_string(),
            subresource: None,
            namespace: Some("dev".to_string()),
            name: Some(name.to_string()),
            dry_run: false,
            redacted_body_shape: "{\"spec\":{\"replicas\":<number>}}".to_string(),
            revert_constructible: RevertConstructible::RestorePriorState,
            rarity: false,
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
                    protocol: format!("p{i}"),
                    verb: "get".to_string(),
                    group: String::new(),
                    version: "v1".to_string(),
                    resource: "pods".to_string(),
                    subresource: None,
                    namespace: Some(format!("ns{i}")),
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
                    max_risk_seen: 1,
                    first_seen_unix: i as u64,
                    last_seen_unix: i as u64,
                    last_reason: String::new(),
                },
            );
        }
        assert_eq!(store.bucket_count(), MAX_BUCKETS);

        store
            .record_deny(&summary("brand-new"), "no", "")
            .expect("record deny");

        assert_eq!(store.bucket_count(), MAX_BUCKETS);
        assert!(!store.data.buckets.contains_key("p0|get||v1|pods||ns0|{}"));
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
}
