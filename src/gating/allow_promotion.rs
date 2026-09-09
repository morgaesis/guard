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
//! - **Which consequence classes are eligible.** Only locally proven
//!   read-only commands are eligible. Irreversible and Recoverable commands
//!   remain under operator review or live inverse assessment; a model label or
//!   model-generated rollback never creates unattended authority.
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
//! for this binary. It never chooses the binary, the args template, the parameter patterns, or
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

use super::verb::{
    is_kebab_name, CoverageAction, CoverageObservationReplay, CoverageProvenance, ParamSpec, Verb,
    VerbCommand, VerbCoverageCell,
};
use super::{Reversibility, EXECUTE_NOW_MAX_RISK, HOLD_RISK_THRESHOLD};
use crate::env::now_unix;
#[cfg(test)]
use crate::learned_rules::write_learning_file_atomically;
use crate::learned_rules::{infer_service_from_binary, looks_dangerous_for_learned_allow};
use crate::learned_rules::{
    retry_learning_snapshot_conflicts, rewrite_learning_file_bounded, sanitize_learning_text,
    write_learning_file_atomically_for_locked_snapshot, AsyncDurableStore, LearningFileSnapshot,
    LearningWriteOutcome,
};
use crate::redact::{
    command_contains_sensitive_literals, command_metadata,
    flattened_command_contains_sensitive_literals, scrub_flattened_command_metadata,
};

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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowPromotionFile {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub observations: BTreeMap<String, AllowObservation>,
}

fn default_version() -> u32 {
    1
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// `server::learning::maybe_promote_allow_verb` via `mark_resolved` once it has a
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
    snapshot: LearningFileSnapshot,
}

impl AllowPromotionStore {
    pub fn load(config: AllowPromotionConfig) -> Result<Self> {
        let path = config.path.clone();
        let (data, snapshot, warning) = rewrite_learning_file_bounded(&path, |snapshot| {
            let mut data = if let Some(content) = snapshot.content() {
                let content = std::str::from_utf8(content)
                    .with_context(|| format!("{} is not UTF-8", config.path.display()))?;
                if content.trim().is_empty() {
                    AllowPromotionFile::default()
                } else {
                    serde_yaml_ng::from_str(content)
                        .with_context(|| format!("failed to parse {}", config.path.display()))?
                }
            } else {
                AllowPromotionFile::default()
            };
            let original_len = data.observations.len();
            data.observations.retain(|_, observation| {
                !allow_observation_contains_sensitive_literals(observation)
            });
            let mut changed = original_len != data.observations.len();
            for observation in data.observations.values_mut() {
                let sanitized = sanitize_learning_text(&observation.last_reason);
                changed |= sanitized != observation.last_reason;
                observation.last_reason = sanitized;
                let metadata = scrub_flattened_command_metadata(&observation.last_command);
                changed |= metadata != observation.last_command;
                observation.last_command = metadata;
            }
            let content = changed
                .then(|| serde_yaml_ng::to_string(&data))
                .transpose()?;
            Ok((content, data))
        })?;
        if let Some(error) = warning {
            tracing::warn!("allow-promotion cleanup committed with a durability warning: {error}");
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
        let config = self.config.clone();
        let mut first = Some(self.clone());
        let (current, outcome) = retry_learning_snapshot_conflicts(|| {
            let mut current = match first.take() {
                Some(current) => current,
                None => Self::load(config.clone())?,
            };
            let mut candidate = current.clone();
            let outcome = candidate.record_approval_in_memory(
                binary,
                args,
                command,
                risk,
                reversibility,
                reason,
            )?;
            current.commit_candidate(candidate.data)?;
            Ok((current, outcome))
        })?;
        *self = current;
        Ok(outcome)
    }

    #[allow(clippy::too_many_arguments)]
    fn record_approval_in_memory(
        &mut self,
        binary: &str,
        args: &[String],
        command: &str,
        risk: Option<i32>,
        reversibility: Option<Reversibility>,
        reason: &str,
    ) -> Result<Option<AllowPromotionOutcome>> {
        if command_contains_sensitive_literals(binary, args) {
            return Ok(None);
        }
        let metadata = command_metadata(binary, args);
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
        let reason = sanitize_learning_text(reason);
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
                last_command: metadata.clone(),
                last_reason: reason.clone(),
                last_attempt_at_approvals: 0,
            });

        observation.approvals = observation.approvals.saturating_add(1);
        observation.max_risk_seen = observation.max_risk_seen.max(risk_val);
        observation.last_seen_unix = now;
        observation.last_command = metadata;
        observation.last_reason = reason.clone();
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
            reason,
        }))
    }

    /// Permanently exclude a bucket from further promotion attempts: called
    /// once the caller (`server::learning::maybe_promote_allow_verb`) has a definitive
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
        let mut candidate = self.data.clone();
        if let Some(observation) = candidate.observations.get_mut(&key) {
            observation.resolved = true;
            self.commit_candidate(candidate)?;
        }
        Ok(())
    }

    fn commit_candidate(&mut self, candidate: AllowPromotionFile) -> Result<()> {
        if candidate == self.data {
            return Ok(());
        }
        let outcome = self.save_data(&candidate)?;
        let (committed, warning) = outcome.into_parts();
        self.data = candidate;
        self.snapshot = committed;
        if let Some(error) = warning {
            tracing::warn!(
                "allow-promotion replacement committed with a durability warning: {}",
                error
            );
        }
        Ok(())
    }

    fn save_data(&self, data: &AllowPromotionFile) -> Result<LearningWriteOutcome> {
        let content = self.canonical_content(data)?;
        write_learning_file_atomically_for_locked_snapshot(
            &self.config.path,
            &self.snapshot,
            &content,
        )
    }

    fn canonical_content(&self, data: &AllowPromotionFile) -> Result<String> {
        let mut data = data.clone();
        for observation in data.observations.values_mut() {
            observation.last_reason = sanitize_learning_text(&observation.last_reason);
            observation.last_command = scrub_flattened_command_metadata(&observation.last_command);
        }
        Ok(serde_yaml_ng::to_string(&data)?)
    }
}

fn allow_observation_contains_sensitive_literals(observation: &AllowObservation) -> bool {
    observation
        .samples
        .iter()
        .any(|args| command_contains_sensitive_literals(&observation.binary, args))
        || flattened_command_contains_sensitive_literals(&observation.last_command)
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

/// Automatic promotion does not create durable authority for tools whose
/// behavior can be supplied by a project tree, implicit configuration, or
/// plugins discovered from a caller working directory. Operators express
/// these tools through a reviewed typed verb with an exact `cwd` constraint.
pub fn is_cwd_dependent_opaque_carrier(binary: &str) -> bool {
    let binary = super::semantic_executable_key(binary);
    matches!(
        binary.as_str(),
        "ansible"
            | "ansible-playbook"
            | "ansible-galaxy"
            | "chef-client"
            | "helm"
            | "kustomize"
            | "make"
            | "nix"
            | "nix-build"
            | "nix-shell"
            | "packer"
            | "pulumi"
            | "puppet"
            | "salt"
            | "salt-call"
            | "terraform"
            | "terragrunt"
            | "tofu"
    )
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
/// Whitespace-bearing values use `single_argv` semantics and the exact
/// observed maximum length, so they remain one bounded argv element.
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
                let pattern = format!("^({alternation})$");
                let spec = if values
                    .iter()
                    .any(|value| value.chars().any(char::is_whitespace))
                {
                    ParamSpec::bounded_single_argv(
                        pattern,
                        values
                            .iter()
                            .map(|value| value.chars().count())
                            .max()
                            .expect("parameter values are non-empty"),
                        allow_dash,
                    )
                } else {
                    ParamSpec {
                        pattern,
                        required: true,
                        default: None,
                        allow_dash,
                    }
                };
                params.insert(name, spec);
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
///
/// Two structural bounds are enforced here rather than trusted from the
/// caller:
///
/// - Automatic promotion never mints authority above
///   `Reversibility::Reversible`; any other class is refused outright.
/// - Provenance is honest about how it was produced: the recorded argv
///   records are `observation_replays` derived from the observed evaluator
///   decisions the template was compiled from, never `probes`, which would
///   claim an executed match that never ran.
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
) -> Result<Verb> {
    if consequence != Reversibility::Reversible {
        anyhow::bail!(
            "automatic promotion may not mint a '{}' verb: only statically read-only \
             (reversible) shapes are eligible",
            consequence.as_str()
        );
    }
    let description = sanitize_learning_text(&description);
    let evidence = sanitize_learning_text(&evidence);
    let fixed_args = args
        .iter()
        .filter(|arg| !(arg.starts_with('{') && arg.ends_with('}')))
        .cloned()
        .collect::<Vec<_>>();
    let coverage = vec![VerbCoverageCell {
        name: "evidence-backed".to_string(),
        action: CoverageAction::Preauthorized,
        command_path: Vec::new(),
        required_args: fixed_args,
        forbidden_args: Vec::new(),
        min_args: None,
        max_args: None,
        options: Vec::new(),
        target: None,
        inventory: None,
        namespace: None,
        fanout: None,
        cwd: None,
        environment: Vec::new(),
        override_marker: None,
        sticky: false,
        provenance: Some(CoverageProvenance {
            source: "automatic_evaluator_promotion".to_string(),
            evidence: vec![evidence.clone()],
            regime_stamp: promotion_stamp.clone(),
            prompt_stamp: promotion_stamp.clone(),
            model_stamp: promotion_stamp.clone(),
            generated_unix: now_unix(),
            probes: Vec::new(),
            observation_replays: vec![
                CoverageObservationReplay {
                    dimension: "observed_shape".to_string(),
                    args: args.clone(),
                    template_match: true,
                },
                CoverageObservationReplay {
                    dimension: "outside_shape".to_string(),
                    args: vec!["--guard-outside-coverage".to_string()],
                    template_match: false,
                },
            ],
        }),
    }];
    Ok(Verb {
        name,
        description,
        binary: binary.to_string(),
        args,
        baseline: true,
        coverage,
        credential_plan: None,
        params,
        consequence,
        revert,
        hold: false,
        trusted: true,
        prompt_context: None,
        exec_timeout_secs: None,
        source_prose: None,
        evidence: Some(evidence),
        auto_promoted: true,
        promotion_stamp: Some(promotion_stamp),
    })
}

impl AsyncDurableStore for AllowPromotionStore {
    fn authority_name(&self) -> &'static str {
        "allow-promotion"
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
