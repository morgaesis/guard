//! Auto-promotion of trusted verbs from repeated low-risk LLM approvals: the
//! allow-side analog of `gating::deny_shape`.
//!
//! `learned_rules` already detects a repeated LLM approval and tells the
//! operator they *could* run `guard verb create --prompt` to turn it into a
//! deterministic allow. That is deliberately manual: an agent's own repeated
//! behavior is not, by itself, a signal that can safely grant that same agent
//! a bypass without a human noticing. This module exists because that manual
//! step does not scale to gating every invocation of a high-volume,
//! parameter-heavy tool (`kubectl`, `ansible`) across many hosts and unknown
//! future tools, some of which nobody will ever hand-author a verb for -- and
//! because most real deployments of this daemon are unattended, so a design
//! that depends on an operator noticing a notice and typing a command does
//! not actually fire in practice.
//!
//! The asymmetry that made `deny_shape` safe to automate is not available
//! here: an over-broad *deny* shape costs availability; an over-broad *allow*
//! shape costs security. So this module is deliberately far more
//! conservative than either `deny_shape` or the operator-invoked
//! `guard verb create --prompt` path, on several independent axes:
//!
//! - **What gets bucketed together.** Observations are keyed on
//!   `(service, binary, first-arg, arity)`. The first argument (the
//!   subcommand/verb for almost every real CLI: `get`, `restart`, `delete`)
//!   and the argument count are part of the bucket key, never something a
//!   pattern is asked to generalize over. A model can never widen `get` into
//!   `(get|delete)`, because `get`-evidence and `delete`-evidence never share
//!   a bucket to begin with.
//! - **How a parameter's allowed values are derived.** Positions that vary
//!   across the evidence in a bucket become a parameter whose pattern is a
//!   plain alternation of the *exact, regex-escaped* values actually
//!   observed (see `derive_template`). There is no free-form,
//!   model-authored regex anywhere in this path -- unlike verb synthesis and
//!   deny-shape synthesis, which both trust the model to propose a pattern
//!   and merely validate it. Nothing here for a model (or a caller nudging
//!   one through many approved requests) to widen.
//! - **Which consequence classes are eligible.** Reversible and Recoverable
//!   only. Irreversible is never even attempted: it always holds for
//!   operator approval regardless of `trusted` (see `decide_gate`), so
//!   promoting one buys no latency and only discards the per-instance LLM
//!   reasoning a human would otherwise see in the hold queue. A Recoverable
//!   verb may be promoted only with a validated revert, so the auto-revert
//!   envelope -- not the model's word -- is what absorbs the residual risk
//!   that a not-yet-observed parameter value behaves differently than the
//!   evidence.
//! - **Consistency across evidence.** Every approval folded into a bucket
//!   must agree on the same reversibility class; a bucket that ever saw a
//!   mixed or irreversible classification is permanently disqualified
//!   (`mixed_class`), never promoted.
//! - **Cache-busting.** A promoted verb is stamped with a hash of the model
//!   and prompts that justified it (`Evaluator::verb_promotion_stamp`). If
//!   either changes, the daemon stops trusting verbs promoted under the old
//!   judgment (see `server::execute_command_inner`) without any operator
//!   action -- consistent with never fully trusting a frozen model verdict.
//!
//! The LLM is still consulted once per promotion attempt with at least one
//! varying position, but only to name the verb, write its description, judge
//! whether generalizing over these *specific* varying positions is coherent
//! for this binary, and -- for a Recoverable verb -- propose a revert. It
//! never chooses the binary, the args template, the parameter patterns, or
//! the consequence class; those are derived here from evidence and re-
//! validated from scratch regardless of what the model returns (see
//! `gating::verb::validate_auto_promoted_verb_safety`). A fully literal
//! bucket (every position constant, i.e. the exact same command approved
//! `min_approvals` times) skips the LLM call entirely: there is no shape
//! judgment to make.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::verb::{is_kebab_name, ParamSpec, Verb, VerbCommand};
use super::{Reversibility, EXECUTE_NOW_MAX_RISK, HOLD_RISK_THRESHOLD};
use crate::learned_rules::{infer_service_from_binary, looks_dangerous_for_learned_allow};

/// Evidence samples kept per observation bucket: enough to see whether more
/// than one distinct value occupies a varying position, bounded so neither
/// memory nor the synthesis prompt grows without limit.
const MAX_SAMPLES_PER_OBSERVATION: usize = 8;

/// Total distinct observation buckets tracked at once, mirroring
/// `deny_shape::MAX_OBSERVATION_BUCKETS` for the same reason: otherwise a
/// workload touching many distinct (service, binary, subcommand, arity)
/// shapes would grow the persisted YAML without limit for the daemon's life.
/// When full, the least-recently-seen bucket is evicted; this only ever
/// discards observation bookkeeping, never a verb already promoted into the
/// catalog.
const MAX_OBSERVATION_BUCKETS: usize = 500;

#[derive(Debug, Clone)]
pub struct AllowPromotionConfig {
    pub path: PathBuf,
    pub enabled: bool,
    pub min_approvals: u32,
}

impl AllowPromotionConfig {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            enabled: true,
            min_approvals: 5,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AllowPromotionFile {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub observations: BTreeMap<String, AllowObservation>,
}

fn default_version() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowObservation {
    pub service: String,
    pub binary: String,
    pub subcommand: String,
    pub arity: usize,
    pub approvals: u32,
    #[serde(default)]
    pub samples: Vec<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class_seen: Option<Reversibility>,
    /// Once true, this bucket saw disagreeing reversibility classifications
    /// (or an irreversible one) across its evidence and is permanently
    /// disqualified from promotion -- a single inconsistent vote is treated
    /// as "this shape's safety depends on context the bucket key doesn't
    /// capture," not averaged away.
    #[serde(default)]
    pub mixed_class: bool,
    /// Once true, this bucket reached a definitive outcome -- a verb was
    /// promoted, or promotion failed for a reason that will recur identically
    /// for the same evidence (a structural validation failure, or an
    /// unrecoverable catalog error such as a name collision) -- and is
    /// permanently excluded from further promotion attempts. Set by
    /// `server::maybe_promote_allow_verb` via `mark_resolved` once it has a
    /// definitive verdict; NOT set when the model simply wasn't confident yet
    /// or an LLM call transiently failed, both of which should keep
    /// retrying as more evidence accumulates.
    #[serde(default)]
    pub resolved: bool,
    pub max_risk_seen: i32,
    pub first_seen_unix: u64,
    pub last_seen_unix: u64,
    pub last_command: String,
    pub last_reason: String,
    /// Approval count at which promotion was last attempted, so crossing the
    /// threshold doesn't re-trigger the LLM on every subsequent approval.
    #[serde(default)]
    pub last_attempt_at_approvals: u32,
}

/// Outcome of recording one LLM approval. Mirrors
/// `deny_shape::DenyLearningOutcome` in shape: `ready_to_synthesize` drives
/// automatic action, not an operator-facing notice -- there is no human in
/// this loop at all.
#[derive(Debug, Clone)]
pub struct AllowPromotionOutcome {
    pub service: String,
    pub binary: String,
    pub subcommand: String,
    pub arity: usize,
    pub approvals: u32,
    pub required_approvals: u32,
    pub ready_to_synthesize: bool,
    pub samples: Vec<Vec<String>>,
    pub class: Reversibility,
    pub max_risk_seen: i32,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct AllowPromotionStore {
    config: AllowPromotionConfig,
    data: AllowPromotionFile,
}

impl AllowPromotionStore {
    pub fn load(config: AllowPromotionConfig) -> Result<Self> {
        let data = if config.path.exists() {
            let content = std::fs::read_to_string(&config.path)
                .with_context(|| format!("failed to read {}", config.path.display()))?;
            if content.trim().is_empty() {
                AllowPromotionFile::default()
            } else {
                serde_yaml::from_str(&content)
                    .with_context(|| format!("failed to parse {}", config.path.display()))?
            }
        } else {
            AllowPromotionFile::default()
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

    pub fn observation_count(&self) -> usize {
        self.data.observations.len()
    }

    /// Record one fresh LLM approval. Returns `Ok(None)` when this approval
    /// is ineligible for promotion bookkeeping at all (disabled, gating was
    /// off so there is no reversibility classification, irreversible, risk
    /// at or above the ceiling for its class, or the command matches the
    /// same "obviously never auto-trust" floor `learned_rules` uses).
    /// Otherwise records it and reports whether this bucket just became (or
    /// remains) eligible for a promotion attempt.
    #[allow(clippy::too_many_arguments)]
    pub fn record_approval(
        &mut self,
        binary: &str,
        args: &[String],
        command: &str,
        risk: Option<i32>,
        reversibility: Option<Reversibility>,
        reason: &str,
    ) -> Result<Option<AllowPromotionOutcome>> {
        if !self.config.enabled {
            return Ok(None);
        }
        let Some(class) = reversibility else {
            // No consequence classification (gate mode off): this module has
            // nothing to key eligibility on, so it stays inert.
            return Ok(None);
        };
        if class == Reversibility::Irreversible {
            return Ok(None);
        }
        let risk_val = risk.unwrap_or(10);
        let risk_ceiling = match class {
            Reversibility::Reversible => EXECUTE_NOW_MAX_RISK,
            Reversibility::Recoverable => HOLD_RISK_THRESHOLD,
            Reversibility::Irreversible => unreachable!("rejected above"),
        };
        if risk_val >= risk_ceiling {
            return Ok(None);
        }
        if looks_dangerous_for_learned_allow(command) {
            return Ok(None);
        }

        let service = infer_service_from_binary(binary);
        let subcommand = args.first().cloned().unwrap_or_default();
        let arity = args.len();
        let key = format!("{service}|{binary}|{subcommand}|{arity}");
        let now = now_unix();

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
            .or_insert_with(|| AllowObservation {
                service: service.clone(),
                binary: binary.to_string(),
                subcommand: subcommand.clone(),
                arity,
                approvals: 0,
                samples: Vec::new(),
                class_seen: None,
                mixed_class: false,
                resolved: false,
                max_risk_seen: risk_val,
                first_seen_unix: now,
                last_seen_unix: now,
                last_command: command.to_string(),
                last_reason: reason.to_string(),
                last_attempt_at_approvals: 0,
            });

        observation.approvals = observation.approvals.saturating_add(1);
        observation.max_risk_seen = observation.max_risk_seen.max(risk_val);
        observation.last_seen_unix = now;
        observation.last_command = command.to_string();
        observation.last_reason = reason.to_string();
        match observation.class_seen {
            None => observation.class_seen = Some(class),
            Some(seen) if seen != class => observation.mixed_class = true,
            Some(_) => {}
        }
        let sample = args.to_vec();
        if !observation.samples.contains(&sample)
            && observation.samples.len() < MAX_SAMPLES_PER_OBSERVATION
        {
            observation.samples.push(sample);
        }

        let approvals = observation.approvals;
        // Clamped at the point of use, not just at the CLI parse layer
        // (`main.rs` already does `.max(2)`): `AllowPromotionConfig`'s fields
        // are public, so a `min_approvals` of 0 or 1 constructed directly (an
        // embedder, a test) must not degenerate into treating a single
        // approval as "repeated" -- the entire premise of this module.
        let min_approvals = self.config.min_approvals.max(2);
        let eligible =
            !observation.mixed_class && !observation.resolved && observation.class_seen.is_some();
        let ready_to_synthesize = eligible
            && approvals >= min_approvals
            && (approvals - min_approvals).is_multiple_of(min_approvals)
            && observation.last_attempt_at_approvals != approvals;
        if ready_to_synthesize {
            observation.last_attempt_at_approvals = approvals;
        }
        let samples = observation.samples.clone();
        let max_risk_seen = observation.max_risk_seen;
        let out_class = observation.class_seen;

        self.save()?;

        let Some(out_class) = out_class else {
            return Ok(None);
        };
        Ok(Some(AllowPromotionOutcome {
            service,
            binary: binary.to_string(),
            subcommand,
            arity,
            approvals,
            required_approvals: min_approvals,
            ready_to_synthesize,
            samples,
            class: out_class,
            max_risk_seen,
            reason: reason.to_string(),
        }))
    }

    /// Permanently exclude a bucket from further promotion attempts: called
    /// once the caller (`server::maybe_promote_allow_verb`) has a definitive
    /// verdict for it -- a verb was promoted, or promotion failed for a
    /// structural reason (evidence round-trip mismatch, catalog name
    /// collision) that the same evidence will reproduce identically forever.
    /// Not called when the model simply declined for lack of confidence, or
    /// an LLM call transiently failed: both should keep retrying as more
    /// evidence accumulates. A no-op if the bucket is no longer present
    /// (evicted under `MAX_OBSERVATION_BUCKETS` pressure in the meantime).
    pub fn mark_resolved(
        &mut self,
        service: &str,
        binary: &str,
        subcommand: &str,
        arity: usize,
    ) -> Result<()> {
        let key = format!("{service}|{binary}|{subcommand}|{arity}");
        if let Some(observation) = self.data.observations.get_mut(&key) {
            observation.resolved = true;
            self.save()?;
        }
        Ok(())
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

/// One derived template slot: either a literal token (identical across every
/// evidence sample) or a parameter whose exact allowed values are enumerated
/// from what was actually observed. Deliberately no free-form regex option:
/// every promotable pattern is compiled from evidence with `regex::escape`
/// applied, never authored by a model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TemplateSlot {
    Literal(String),
    Param(BTreeSet<String>),
}

/// Diff same-arity evidence samples positionally: a position constant across
/// every sample stays literal; a position with more than one distinct value
/// becomes a parameter enumerating exactly those values. Returns `None` for
/// empty evidence or mismatched arity (defensive only -- callers already
/// bucket by arity, so samples within one bucket always agree).
pub(crate) fn derive_template(samples: &[Vec<String>]) -> Option<Vec<TemplateSlot>> {
    let arity = samples.first()?.len();
    if samples.iter().any(|s| s.len() != arity) {
        return None;
    }
    let mut slots = Vec::with_capacity(arity);
    for i in 0..arity {
        let values: BTreeSet<String> = samples.iter().map(|s| s[i].clone()).collect();
        if values.len() == 1 {
            slots.push(TemplateSlot::Literal(
                values.into_iter().next().expect("len == 1"),
            ));
        } else {
            slots.push(TemplateSlot::Param(values));
        }
    }
    Some(slots)
}

/// True if every slot is literal: the evidence is one exact command approved
/// repeatedly, with no varying position to generalize over.
pub(crate) fn is_fully_literal(slots: &[TemplateSlot]) -> bool {
    slots.iter().all(|s| matches!(s, TemplateSlot::Literal(_)))
}

/// Build the verb's `args` template tokens and named `ParamSpec`s from
/// derived slots. A parameter's pattern is a plain anchored alternation of
/// its exact, regex-escaped observed values -- never a free-form regex.
///
/// Two distinct varying positions can derive the same base name (e.g. a
/// repeated flag: `rsync --exclude A --exclude B`), which would otherwise
/// collapse two independent parameters into one template placeholder used
/// twice -- forcing both positions to carry the same value and failing the
/// evidence round-trip check in `validate_auto_promoted_verb_safety` for any
/// evidence where they legitimately differ (safe -- promotion just never
/// succeeds -- but needlessly so). `unique_param_name` disambiguates by
/// suffixing `_2`, `_3`, ... so each varying position gets its own parameter.
pub(crate) fn build_args_and_params(
    slots: &[TemplateSlot],
) -> (Vec<String>, BTreeMap<String, ParamSpec>) {
    let mut args = Vec::with_capacity(slots.len());
    let mut params = BTreeMap::new();
    let mut ordinal = 0usize;
    for (i, slot) in slots.iter().enumerate() {
        match slot {
            TemplateSlot::Literal(value) => args.push(value.clone()),
            TemplateSlot::Param(values) => {
                ordinal += 1;
                let name = unique_param_name(param_name(slots, i, ordinal), &params);
                let allow_dash = values.iter().any(|v| v.starts_with('-'));
                let alternation = values
                    .iter()
                    .map(|v| regex::escape(v))
                    .collect::<Vec<_>>()
                    .join("|");
                args.push(format!("{{{name}}}"));
                params.insert(
                    name,
                    ParamSpec {
                        pattern: format!("^({alternation})$"),
                        required: true,
                        default: None,
                        allow_dash,
                    },
                );
            }
        }
    }
    (args, params)
}

/// Disambiguate `base` against already-assigned parameter names by suffixing
/// `_2`, `_3`, ... until unique.
fn unique_param_name(base: String, existing: &BTreeMap<String, ParamSpec>) -> String {
    if !existing.contains_key(&base) {
        return base;
    }
    let mut n = 2u32;
    loop {
        let candidate = format!("{base}_{n}");
        if !existing.contains_key(&candidate) {
            return candidate;
        }
        n += 1;
    }
}

/// Derive a readable parameter name from the literal flag token immediately
/// preceding a varying position (`-n foo` -> `n`, `--namespace foo` ->
/// `namespace`), falling back to a positional name when there is no usable
/// preceding flag. `unique_param_name` (the only caller) disambiguates a
/// collision, so two positions deriving the same base name still get
/// independent parameters.
fn param_name(slots: &[TemplateSlot], index: usize, ordinal: usize) -> String {
    if index > 0 {
        if let TemplateSlot::Literal(prev) = &slots[index - 1] {
            let stripped = prev.strip_prefix("--").or_else(|| prev.strip_prefix('-'));
            if let Some(stripped) = stripped {
                let candidate: String = stripped
                    .chars()
                    .map(|c| {
                        if c.is_ascii_alphanumeric() {
                            c.to_ascii_lowercase()
                        } else {
                            '_'
                        }
                    })
                    .collect();
                let candidate = candidate.trim_matches('_').to_string();
                if candidate
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic())
                {
                    return candidate;
                }
            }
        }
    }
    format!("arg{ordinal}")
}

/// Deterministic, collision-resistant verb name for a bucket, used for a
/// fully literal promotion (no LLM call) and as the fallback when a model-
/// proposed name is missing or not kebab-case.
pub(crate) fn deterministic_verb_name(service: &str, subcommand: &str, arity: usize) -> String {
    let mut hasher = DefaultHasher::new();
    (service, subcommand, arity).hash(&mut hasher);
    let hash = hasher.finish();
    let base = kebabify(&format!("{service}-{subcommand}"));
    let base = if base.is_empty() {
        "auto-verb".to_string()
    } else {
        base
    };
    format!("auto-{base}-{:x}", hash & 0xffff)
}

fn kebabify(value: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

/// Pick the verb name for a promotion: prefer a valid kebab-case model
/// proposal (more discoverable), else fall back to the deterministic name.
pub(crate) fn choose_verb_name(
    proposed: Option<&str>,
    service: &str,
    subcommand: &str,
    arity: usize,
) -> String {
    match proposed {
        Some(name) if is_kebab_name(name) => name.to_string(),
        _ => deterministic_verb_name(service, subcommand, arity),
    }
}

/// Build the candidate `Verb` from mechanically-derived shape plus the
/// (optional) model-confirmed name/description/revert. The caller
/// (`Evaluator::try_confirm_verb_promotion`) still runs
/// `verb::validate_auto_promoted_verb_safety` on the result before it is
/// ever appended to the catalog.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_candidate_verb(
    binary: &str,
    name: String,
    description: String,
    args: Vec<String>,
    params: BTreeMap<String, ParamSpec>,
    consequence: Reversibility,
    revert: Option<VerbCommand>,
    evidence: String,
    promotion_stamp: String,
) -> Verb {
    Verb {
        name,
        description,
        binary: binary.to_string(),
        args,
        params,
        consequence,
        revert,
        trusted: true,
        prompt_context: None,
        source_prose: None,
        evidence: Some(evidence),
        auto_promoted: true,
        promotion_stamp: Some(promotion_stamp),
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

    fn config(path: PathBuf, min_approvals: u32) -> AllowPromotionConfig {
        AllowPromotionConfig {
            path,
            enabled: true,
            min_approvals,
        }
    }

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn repeated_reversible_approvals_become_ready_once() {
        let temp = tempfile::tempdir().unwrap();
        let mut store =
            AllowPromotionStore::load(config(temp.path().join("allow.yaml"), 2)).unwrap();
        let a = args(&["get", "pods", "-n", "foo"]);

        let first = store
            .record_approval(
                "kubectl",
                &a,
                "kubectl get pods -n foo",
                Some(1),
                Some(Reversibility::Reversible),
                "read-only",
            )
            .unwrap()
            .unwrap();
        assert!(!first.ready_to_synthesize);

        let second = store
            .record_approval(
                "kubectl",
                &a,
                "kubectl get pods -n foo",
                Some(1),
                Some(Reversibility::Reversible),
                "read-only",
            )
            .unwrap()
            .unwrap();
        assert!(second.ready_to_synthesize);

        // A third approval before the next multiple must not re-trigger.
        let third = store
            .record_approval(
                "kubectl",
                &a,
                "kubectl get pods -n foo",
                Some(1),
                Some(Reversibility::Reversible),
                "read-only",
            )
            .unwrap()
            .unwrap();
        assert!(!third.ready_to_synthesize);
    }

    #[test]
    fn irreversible_is_never_recorded() {
        let temp = tempfile::tempdir().unwrap();
        let mut store =
            AllowPromotionStore::load(config(temp.path().join("allow.yaml"), 1)).unwrap();
        let result = store
            .record_approval(
                "kubectl",
                &args(&["delete", "namespace", "prod"]),
                "kubectl delete namespace prod",
                Some(1),
                Some(Reversibility::Irreversible),
                "reason",
            )
            .unwrap();
        assert!(result.is_none());
        assert_eq!(store.observation_count(), 0);
    }

    #[test]
    fn missing_reversibility_is_never_recorded() {
        // Gate mode off: no classification at all. This module must stay
        // completely inert rather than guessing.
        let temp = tempfile::tempdir().unwrap();
        let mut store =
            AllowPromotionStore::load(config(temp.path().join("allow.yaml"), 1)).unwrap();
        let result = store
            .record_approval(
                "kubectl",
                &args(&["get", "pods"]),
                "kubectl get pods",
                Some(1),
                None,
                "reason",
            )
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn risk_at_or_above_ceiling_is_not_recorded() {
        let temp = tempfile::tempdir().unwrap();
        let mut store =
            AllowPromotionStore::load(config(temp.path().join("allow.yaml"), 1)).unwrap();
        // Reversible ceiling is EXECUTE_NOW_MAX_RISK (4).
        let result = store
            .record_approval(
                "kubectl",
                &args(&["get", "pods"]),
                "kubectl get pods",
                Some(4),
                Some(Reversibility::Reversible),
                "reason",
            )
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn mixed_classification_permanently_disqualifies_the_bucket() {
        let temp = tempfile::tempdir().unwrap();
        let mut store =
            AllowPromotionStore::load(config(temp.path().join("allow.yaml"), 2)).unwrap();
        let a = args(&["scale", "deployment", "web", "--replicas", "3"]);
        store
            .record_approval(
                "kubectl",
                &a,
                "kubectl scale deployment web --replicas 3",
                Some(1),
                Some(Reversibility::Reversible),
                "reason",
            )
            .unwrap();
        let second = store
            .record_approval(
                "kubectl",
                &a,
                "kubectl scale deployment web --replicas 3",
                Some(1),
                Some(Reversibility::Recoverable),
                "reason",
            )
            .unwrap()
            .unwrap();
        assert!(!second.ready_to_synthesize);
        // Even after crossing the threshold on a later, consistent vote, a
        // permanently mixed bucket must never become eligible.
        let third = store
            .record_approval(
                "kubectl",
                &a,
                "kubectl scale deployment web --replicas 3",
                Some(1),
                Some(Reversibility::Recoverable),
                "reason",
            )
            .unwrap()
            .unwrap();
        assert!(!third.ready_to_synthesize);
    }

    #[test]
    fn dangerous_command_is_never_recorded() {
        let temp = tempfile::tempdir().unwrap();
        let mut store =
            AllowPromotionStore::load(config(temp.path().join("allow.yaml"), 1)).unwrap();
        let result = store
            .record_approval(
                "sh",
                &args(&["-c", "rm -rf /"]),
                "sh -c rm -rf /",
                Some(1),
                Some(Reversibility::Reversible),
                "reason",
            )
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn derive_template_finds_varying_and_constant_positions() {
        let samples = vec![
            args(&["get", "pods", "-n", "foo"]),
            args(&["get", "pods", "-n", "bar"]),
        ];
        let slots = derive_template(&samples).unwrap();
        assert_eq!(slots[0], TemplateSlot::Literal("get".to_string()));
        assert_eq!(slots[1], TemplateSlot::Literal("pods".to_string()));
        assert_eq!(slots[2], TemplateSlot::Literal("-n".to_string()));
        assert!(matches!(&slots[3], TemplateSlot::Param(v) if v.len() == 2));
        assert!(!is_fully_literal(&slots));
    }

    #[test]
    fn derive_template_all_constant_is_fully_literal() {
        let samples = vec![args(&["get", "pods"]), args(&["get", "pods"])];
        let slots = derive_template(&samples).unwrap();
        assert!(is_fully_literal(&slots));
    }

    #[test]
    fn build_args_and_params_pins_exact_observed_values() {
        let samples = vec![
            args(&["get", "pods", "-n", "foo"]),
            args(&["get", "pods", "-n", "bar"]),
        ];
        let slots = derive_template(&samples).unwrap();
        let (built_args, params) = build_args_and_params(&slots);
        assert_eq!(built_args[0], "get");
        assert_eq!(built_args[1], "pods");
        assert_eq!(built_args[2], "-n");
        assert_eq!(built_args[3], "{n}");
        let spec = params.get("n").unwrap();
        assert!(spec.pattern == "^(bar|foo)$" || spec.pattern == "^(foo|bar)$");
        // A value outside the observed set must not match.
        let re = regex::Regex::new(&spec.pattern).unwrap();
        assert!(!re.is_match("kube-system"));
        assert!(re.is_match("foo"));
        assert!(re.is_match("bar"));
    }

    #[test]
    fn build_args_and_params_escapes_regex_metacharacters_in_values() {
        let samples = vec![
            args(&["get", "pods", "-n", "a.b"]),
            args(&["get", "pods", "-n", "a+b"]),
        ];
        let slots = derive_template(&samples).unwrap();
        let (_, params) = build_args_and_params(&slots);
        let spec = params.get("n").unwrap();
        let re = regex::Regex::new(&spec.pattern).unwrap();
        assert!(re.is_match("a.b"));
        assert!(re.is_match("a+b"));
        // Unescaped `.` or `+` would otherwise admit unrelated values.
        assert!(!re.is_match("aXb"));
        assert!(!re.is_match("aaab"));
    }

    #[test]
    fn deterministic_name_is_kebab_case() {
        let name = deterministic_verb_name("kubectl", "get", 4);
        assert!(is_kebab_name(&name), "{name} must be kebab-case");
    }

    #[test]
    fn choose_verb_name_prefers_valid_model_proposal() {
        let chosen = choose_verb_name(Some("k-get-pods"), "kubectl", "get", 4);
        assert_eq!(chosen, "k-get-pods");
        let fallback = choose_verb_name(Some("Not Kebab"), "kubectl", "get", 4);
        assert!(is_kebab_name(&fallback));
        let none = choose_verb_name(None, "kubectl", "get", 4);
        assert!(is_kebab_name(&none));
    }

    #[test]
    fn param_name_falls_back_to_positional_with_no_preceding_flag() {
        // The varying position is first in the argv (index 0), so there is
        // no preceding literal token at all to derive a name from.
        let slots = vec![TemplateSlot::Param(
            ["foo".to_string(), "bar".to_string()].into_iter().collect(),
        )];
        assert_eq!(param_name(&slots, 0, 1), "arg1");

        // A preceding literal that isn't flag-shaped (no leading dash) also
        // falls back positionally.
        let slots = vec![
            TemplateSlot::Literal("get".to_string()),
            TemplateSlot::Param(["a".to_string(), "b".to_string()].into_iter().collect()),
        ];
        assert_eq!(param_name(&slots, 1, 1), "arg1");
    }

    #[test]
    fn build_args_and_params_disambiguates_colliding_names() {
        // Two independent varying positions both preceded by the same
        // repeated flag (e.g. `rsync --exclude A --exclude B`) must not
        // collapse into one shared parameter -- each needs its own name so
        // both can vary independently.
        let samples = vec![
            args(&["--exclude", "A", "--exclude", "C"]),
            args(&["--exclude", "B", "--exclude", "D"]),
        ];
        let slots = derive_template(&samples).unwrap();
        let (built_args, params) = build_args_and_params(&slots);
        assert_eq!(built_args.len(), 4);
        assert_ne!(
            built_args[1], built_args[3],
            "the two varying positions must get distinct placeholders"
        );
        assert_eq!(params.len(), 2, "each varying position needs its own param");
        // Each param independently enumerates only its own column's values.
        let pattern1 = &params[built_args[1].trim_matches(['{', '}'])].pattern;
        let pattern2 = &params[built_args[3].trim_matches(['{', '}'])].pattern;
        let re1 = regex::Regex::new(pattern1).unwrap();
        let re2 = regex::Regex::new(pattern2).unwrap();
        assert!(re1.is_match("A") && re1.is_match("B"));
        assert!(re2.is_match("C") && re2.is_match("D"));
    }

    #[test]
    fn degenerate_min_approvals_does_not_fire_on_the_first_approval() {
        // AllowPromotionConfig's fields are public and constructible
        // directly; record_approval must clamp to >= 2 itself rather than
        // trusting every call site already did (defense in depth alongside
        // main.rs's own `.max(2)` at the CLI layer). "Repeated" approvals is
        // this module's entire premise, so 0 or 1 must not degenerate into
        // treating a single approval as sufficient.
        for degenerate in [0u32, 1] {
            let temp = tempfile::tempdir().unwrap();
            let mut degenerate_config = config(temp.path().join("allow.yaml"), 1);
            degenerate_config.min_approvals = degenerate;
            let mut store = AllowPromotionStore::load(degenerate_config).unwrap();
            let outcome = store
                .record_approval(
                    "kubectl",
                    &args(&["get", "pods"]),
                    "kubectl get pods",
                    Some(1),
                    Some(Reversibility::Reversible),
                    "ok",
                )
                .unwrap()
                .unwrap();
            assert!(
                !outcome.ready_to_synthesize,
                "a single approval must not be treated as sufficient just because \
                 min_approvals was {degenerate}"
            );
        }
    }

    #[test]
    fn resolved_bucket_never_becomes_ready_again() {
        let temp = tempfile::tempdir().unwrap();
        let mut store =
            AllowPromotionStore::load(config(temp.path().join("allow.yaml"), 2)).unwrap();
        let a = args(&["get", "pods"]);
        store
            .record_approval(
                "kubectl",
                &a,
                "kubectl get pods",
                Some(1),
                Some(Reversibility::Reversible),
                "ok",
            )
            .unwrap();
        let second = store
            .record_approval(
                "kubectl",
                &a,
                "kubectl get pods",
                Some(1),
                Some(Reversibility::Reversible),
                "ok",
            )
            .unwrap()
            .unwrap();
        assert!(second.ready_to_synthesize);

        // Simulate a definitive verdict (promoted, or permanently failed).
        store.mark_resolved("kubectl", "kubectl", "get", 2).unwrap();

        // Even as approvals keep climbing past further min_approvals
        // multiples, a resolved bucket must never fire again.
        for _ in 0..10 {
            let outcome = store
                .record_approval(
                    "kubectl",
                    &a,
                    "kubectl get pods",
                    Some(1),
                    Some(Reversibility::Reversible),
                    "ok",
                )
                .unwrap()
                .unwrap();
            assert!(
                !outcome.ready_to_synthesize,
                "a resolved bucket must never re-fire, got approvals={}",
                outcome.approvals
            );
        }
    }

    #[test]
    fn mark_resolved_on_missing_bucket_is_a_harmless_noop() {
        let temp = tempfile::tempdir().unwrap();
        let mut store =
            AllowPromotionStore::load(config(temp.path().join("allow.yaml"), 2)).unwrap();
        // No observation was ever recorded for this key; this must not error.
        store
            .mark_resolved("nonexistent", "nope", "nope", 0)
            .unwrap();
    }

    #[test]
    fn observation_buckets_are_capped_by_evicting_the_oldest() {
        let temp = tempfile::tempdir().unwrap();
        let mut store =
            AllowPromotionStore::load(config(temp.path().join("allow.yaml"), 2)).unwrap();

        for i in 0..MAX_OBSERVATION_BUCKETS {
            store.data.observations.insert(
                format!("service-{i}|bin-{i}|get|1"),
                AllowObservation {
                    service: format!("service-{i}"),
                    binary: format!("bin-{i}"),
                    subcommand: "get".to_string(),
                    arity: 1,
                    approvals: 1,
                    samples: Vec::new(),
                    class_seen: Some(Reversibility::Reversible),
                    mixed_class: false,
                    resolved: false,
                    max_risk_seen: 1,
                    first_seen_unix: i as u64,
                    last_seen_unix: i as u64,
                    last_command: String::new(),
                    last_reason: String::new(),
                    last_attempt_at_approvals: 0,
                },
            );
        }
        assert_eq!(store.observation_count(), MAX_OBSERVATION_BUCKETS);

        store
            .record_approval(
                "brand-new-bin",
                &args(&["x"]),
                "brand-new-bin x",
                Some(1),
                Some(Reversibility::Reversible),
                "new",
            )
            .unwrap();
        assert_eq!(store.observation_count(), MAX_OBSERVATION_BUCKETS);
        assert!(!store
            .data
            .observations
            .contains_key("service-0|bin-0|get|1"));
    }
}
