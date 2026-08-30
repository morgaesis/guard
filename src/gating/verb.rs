//! Verb catalog: the operator-authored, typed, least-expressive interface that
//! agents call instead of raw shell.
//!
//! A verb names a fixed binary and an argv template with typed, pattern-validated
//! parameters. Rendering substitutes each `{param}` as exactly one argv element
//! (no shell, no word-splitting), so a parameter value can never expand into
//! extra, unintended arguments. A verb declares its own reversibility class
//! (which drives the consequence gate) and, for recoverable verbs, a
//! structured rollback template.
//!
//! The catalog is the "slow clock": only operator-owned deployment paths and
//! authenticated operator RPCs can change it. A trusted verb may skip the LLM
//! evaluator entirely (a deterministic allow path, like a static policy allow),
//! since its shape is already operator-reviewed.

use super::approval::{DelayedAuthorityPlan, DelayedAuthorityProfile, DelayedAuthoritySource};
use super::coverage::reversibility_rank;
use super::{semantic_executable_key as executable_match_key, Reversibility};
use crate::learned_rules::{
    load_immutable_learning_file_snapshot, load_learning_file_snapshot,
    rewrite_learning_file_bounded, write_learning_file_atomically_for_locked_snapshot,
    AsyncDurableStore, LearningFileSnapshot,
};
use crate::redact::{
    command_contains_sensitive_literals, named_value_contains_sensitive_literals,
    text_contains_sensitive_literals, SENSITIVE_ARGV_REPLAY_GUIDANCE,
};
use anyhow::{bail, Context, Result};
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// A single parameter's validation rule.
#[derive(Debug, Clone)]
pub struct ParamSpec {
    /// Fully-anchored regex (`^...$`) the value must match. Rejected at load if
    /// not anchored, so a permissive pattern cannot silently allow a substring
    /// with shell metacharacters or a value that gets reinterpreted as a flag.
    pub pattern: String,
    pub required: bool,
    pub default: Option<String>,
    /// Allow a rendered value to begin with `-`. Off by default so a value can
    /// never pass itself off as an option flag (e.g. `-o ProxyCommand=...`).
    pub allow_dash: bool,
}

/// How Guard interprets a parameter after regex validation.
///
/// `token` retains the conservative no-whitespace behavior. `single_argv`
/// permits spaces inside one bounded argv element while rejecting shell
/// control characters at render time. The latter is useful for exact
/// JSONPath and field-selector values without introducing word splitting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamValueType {
    #[default]
    Token,
    SingleArgv,
}

const SINGLE_ARGV_PATTERN_PREFIX: &str = "\0guard-single-argv:";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParamSpecWire {
    pattern: String,
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    allow_dash: bool,
    #[serde(default, skip_serializing_if = "is_token_value_type")]
    value_type: ParamValueType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_length: Option<usize>,
}

fn is_token_value_type(value_type: &ParamValueType) -> bool {
    *value_type == ParamValueType::Token
}

impl ParamSpec {
    fn encoded_single_argv(pattern: String, max_length: usize) -> String {
        format!("{SINGLE_ARGV_PATTERN_PREFIX}{max_length}:{pattern}")
    }

    /// Construct the bounded one-argv form used by mechanically generated
    /// matchers. The public YAML representation keeps this metadata separate
    /// from the pattern, while the in-memory representation preserves the
    /// existing `ParamSpec` struct shape for catalog callers.
    pub(crate) fn bounded_single_argv(
        pattern: String,
        max_length: usize,
        allow_dash: bool,
    ) -> Self {
        Self {
            pattern: Self::encoded_single_argv(pattern, max_length),
            required: true,
            default: None,
            allow_dash,
        }
    }

    fn semantics(&self) -> (ParamValueType, Option<usize>, &str) {
        let Some(encoded) = self.pattern.strip_prefix(SINGLE_ARGV_PATTERN_PREFIX) else {
            return (ParamValueType::Token, None, &self.pattern);
        };
        let Some((length, pattern)) = encoded.split_once(':') else {
            return (ParamValueType::SingleArgv, None, encoded);
        };
        (
            ParamValueType::SingleArgv,
            length.parse::<usize>().ok(),
            pattern,
        )
    }

    pub fn value_type(&self) -> ParamValueType {
        self.semantics().0
    }

    pub fn max_length(&self) -> Option<usize> {
        self.semantics().1
    }

    pub fn pattern_text(&self) -> &str {
        self.semantics().2
    }
}

impl Serialize for ParamSpec {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let (value_type, max_length, pattern) = self.semantics();
        ParamSpecWire {
            pattern: pattern.to_string(),
            required: self.required,
            default: self.default.clone(),
            allow_dash: self.allow_dash,
            value_type,
            max_length,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ParamSpec {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ParamSpecWire::deserialize(deserializer)?;
        let pattern = match wire.value_type {
            ParamValueType::Token => {
                if wire.max_length.is_some() {
                    return Err(serde::de::Error::custom(
                        "max_length requires value_type: single_argv",
                    ));
                }
                wire.pattern
            }
            ParamValueType::SingleArgv => {
                let max_length = wire.max_length.ok_or_else(|| {
                    serde::de::Error::custom(
                        "value_type: single_argv requires a positive max_length",
                    )
                })?;
                Self::encoded_single_argv(wire.pattern, max_length)
            }
        };
        Ok(Self {
            pattern,
            required: wire.required,
            default: wire.default,
            allow_dash: wire.allow_dash,
        })
    }
}

fn default_true() -> bool {
    true
}

fn is_true(b: &bool) -> bool {
    *b
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// What a matching coverage cell authorizes. A cell that does not match says
/// nothing about the command, so coverage never denies its complement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageAction {
    Preauthorized,
    Evaluate,
    Deny,
}

/// Origin of one caller-controlled child-environment binding. Daemon tool
/// configuration is intentionally absent: it is trusted server state, not a
/// request input that a coverage cell needs to authorize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnvironmentBindingSource {
    Plain,
    Secret,
    SecretFile,
}

fn default_environment_source() -> EnvironmentBindingSource {
    EnvironmentBindingSource::Plain
}

/// Explicit typed authority for one caller-controlled environment binding.
/// `values` matches the plain value or daemon secret-store name exactly. An
/// anchored `pattern` supports bounded path-like inputs. Omitting both permits
/// any value for this exact source and environment variable name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentConstraint {
    pub name: String,
    #[serde(
        default = "default_environment_source",
        skip_serializing_if = "is_plain_source"
    )]
    pub source: EnvironmentBindingSource,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
}

fn is_plain_source(source: &EnvironmentBindingSource) -> bool {
    *source == EnvironmentBindingSource::Plain
}

/// Select one or more argv values either by option spelling or by exact argv
/// position. Option spellings accept both `--name value` and `--name=value`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValueConstraint {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
    /// Permit a selected value to begin with `-`. Off by default so a missing
    /// option value cannot consume the next flag and satisfy a broad cell.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_dash: bool,
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub required: bool,
    /// Duplicate option spellings are rejected unless this is set. This keeps a
    /// later value from silently changing the meaning checked by the cell.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_multiple: bool,
}

/// A bound on a list-valued target selector such as Ansible `--limit a,b`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FanoutConstraint {
    #[serde(flatten)]
    pub selector: ValueConstraint,
    pub max: usize,
    #[serde(default = "default_fanout_separator")]
    pub separator: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FanoutConstraintWire {
    #[serde(default)]
    options: Vec<String>,
    #[serde(default)]
    position: Option<usize>,
    #[serde(default)]
    values: Vec<String>,
    #[serde(default)]
    allow_dash: bool,
    #[serde(default = "default_true")]
    required: bool,
    #[serde(default)]
    allow_multiple: bool,
    max: usize,
    #[serde(default = "default_fanout_separator")]
    separator: String,
}

impl<'de> Deserialize<'de> for FanoutConstraint {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = FanoutConstraintWire::deserialize(deserializer)?;
        Ok(Self {
            selector: ValueConstraint {
                options: wire.options,
                position: wire.position,
                values: wire.values,
                allow_dash: wire.allow_dash,
                required: wire.required,
                allow_multiple: wire.allow_multiple,
            },
            max: wire.max,
            separator: wire.separator,
        })
    }
}

fn default_fanout_separator() -> String {
    ",".to_string()
}

/// One typed region of a verb's command space. Constraints are conjunctive.
/// Required and forbidden argv tokens are exact argv elements, never globs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerbCoverageCell {
    pub name: String,
    pub action: CoverageAction,
    /// Parsed local command path for protected multi-command tools. This binds
    /// coverage to the actual subcommand instead of matching command names as
    /// unordered argv data.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command_path: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_args: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forbidden_args: Vec<String>,
    /// Inclusive argv cardinality bounds. These constrain the complete argv,
    /// including tokens not otherwise selected by a value constraint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_args: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_args: Option<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<ValueConstraint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<ValueConstraint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inventory: Option<ValueConstraint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<ValueConstraint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fanout: Option<FanoutConstraint>,
    /// Exact canonical caller working directory required by this cell. This
    /// binds tools whose configuration, plugins, or input selection can be
    /// discovered from the working directory to an operator-reviewed project
    /// root. The path is validated as an existing canonical directory when the
    /// catalog loads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<PathBuf>,
    /// Caller-controlled environment bindings this cell may preauthorize.
    /// Empty is migration-safe and means no `--env`, `--secret`, or
    /// `--secret-file` injection can skip evaluator review.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub environment: Vec<EnvironmentConstraint>,
    /// Exact marker an operator-issued session grant must carry to override an
    /// `evaluate` or `deny` cell. Generated verbs cannot mint these markers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub override_marker: Option<String>,
    /// Explicit operator boundaries survive regeneration and automatic
    /// promotion. Generated coverage cannot replace a sticky deny or
    /// always-evaluate cell.
    #[serde(default, skip_serializing_if = "is_false")]
    pub sticky: bool,
    /// Evidence and evaluator regime that produced this cell. Hand-authored
    /// cells may omit provenance; generated cells must carry it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<CoverageProvenance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageProvenance {
    pub source: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    pub regime_stamp: String,
    pub prompt_stamp: String,
    pub model_stamp: String,
    pub generated_unix: u64,
    /// Probes a generator actually executed against the finished matcher.
    /// Generators that only replay evidence they already held record
    /// `observation_replays` instead; a record here asserts that a real
    /// match was run and observed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub probes: Vec<CoverageProbe>,
    /// Argv records replayed from evidence the generator already held: the
    /// evaluator-approved samples a matcher was derived from, plus the
    /// generator's own boundary example. `template_match` states what the
    /// matcher's construction implies for the argv; nothing was executed or
    /// independently probed to produce these records.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observation_replays: Vec<CoverageObservationReplay>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageProbe {
    pub dimension: String,
    pub args: Vec<String>,
    pub expected_match: bool,
    pub observed_match: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageObservationReplay {
    pub dimension: String,
    pub args: Vec<String>,
    pub template_match: bool,
}

/// One concrete reverse match before session/global precedence is resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageMatch {
    pub rendered: RenderedVerb,
    pub cell: String,
    pub action: CoverageAction,
    pub override_marker: Option<String>,
    pub sticky: bool,
    pub features: BTreeSet<String>,
    pub specificity: CoverageSpecificity,
    /// Every caller-controlled environment binding fits explicit typed cell
    /// authority. False downgrades preauthorization to evaluator review.
    pub environment_authorized: bool,
    /// The command came from an exact argv template whose local file values
    /// passed static authority validation.
    pub local_file_authorized: bool,
    /// The matched cell binds the caller working directory to one exact path.
    /// This typed authority is separate from `features`, which is explanatory
    /// output and must never be interpreted as an execution grant.
    pub exact_cwd_authorized: bool,
}

/// Comparable semantic restrictions for one matched cell. Observed values are
/// deliberately excluded so ordering depends on authored coverage, not argv
/// spelling or catalog declaration order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CoverageSpecificity {
    pub requirements: BTreeSet<String>,
    pub values: BTreeMap<String, ValueDomain>,
    pub fanout: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueDomain {
    pub required: bool,
    pub allow_multiple: bool,
    pub allow_dash: bool,
    /// Empty means unrestricted.
    pub values: BTreeSet<String>,
}

/// A structured command template (binary + argv templates). No shell.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerbCommand {
    pub binary: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
}

/// One catalog verb.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verb {
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    pub binary: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Baseline verbs apply without a session. A session can activate a
    /// non-baseline verb by name for its own lifetime.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub baseline: bool,
    /// Typed command-space regions. An empty list preserves the legacy exact
    /// argv-template behavior as one implicit cell.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coverage: Vec<VerbCoverageCell>,
    /// Opaque identifier for the daemon-held credential plan. Different
    /// non-empty plans are incompatible and force evaluator conflict handling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_plan: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, ParamSpec>,
    pub consequence: Reversibility,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revert: Option<VerbCommand>,
    /// Require operator approval even when the declared consequence would
    /// otherwise execute or enter containment immediately.
    #[serde(default, skip_serializing_if = "is_false")]
    pub hold: bool,
    /// When true the rendered command skips the LLM evaluator (deterministic
    /// allow). The reversibility class still drives the gate.
    #[serde(default, skip_serializing_if = "is_false")]
    pub trusted: bool,
    /// Extra context appended to the LLM system prompt when this verb IS
    /// evaluated (untrusted verbs only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_context: Option<String>,
    /// Optional wall-clock execution limit. A present value overrides the
    /// daemon default, including zero to select unbounded execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec_timeout_secs: Option<u64>,
    /// Operator prose this verb was generated from (`guard verb create
    /// --prompt`), stored for posterity. Metadata only; never used in rendering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_prose: Option<String>,
    /// Concise rationale/evidence for the generated shape (why this binary, these
    /// params, patterns, and class). Metadata only; never used in rendering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    /// True for a verb appended automatically by `gating::allow_promotion` from
    /// repeated low-risk approvals, rather than authored or reviewed by an
    /// operator. Metadata only; never used in rendering. Drives the staleness
    /// check below: an operator-authored verb has no such expiry.
    #[serde(default, skip_serializing_if = "is_false")]
    pub auto_promoted: bool,
    /// For an auto-promoted verb, a hash of the model + prompts that produced
    /// it. If the daemon's current stamp (`Evaluator::verb_promotion_stamp`)
    /// no longer matches, the trust that led to promotion no longer applies --
    /// the caller downgrades `trusted` to `false` rather than trusting a
    /// judgment made under a since-changed model or prompt. Ignored for a
    /// verb that isn't `auto_promoted`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promotion_stamp: Option<String>,
}

impl Verb {
    /// Content digest (SHA-256 hex) of this verb's full definition. The JSON
    /// serialization is deterministic because every collection in a verb is a
    /// `BTreeMap`, so two identical definitions always share one digest. Held
    /// approvals bind to this digest rather than the whole-catalog version, so
    /// an unrelated catalog change does not void them.
    pub fn definition_digest(&self) -> String {
        let serialized = serde_json::to_string(self).expect("verb serializes");
        Sha256::digest(serialized.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// Enumerate every parameter binding admitted by finite literal patterns.
    /// `None` means at least one regex is non-finite or the Cartesian product
    /// exceeds the admission-preview bound.
    pub fn finite_parameter_sets(&self) -> Option<Vec<BTreeMap<String, String>>> {
        enumerate_parameter_sets(self, self.params.keys().cloned().collect())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum CatalogPlatform {
    Unix,
    Windows,
}

impl CatalogPlatform {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unix => "unix",
            Self::Windows => "windows",
        }
    }

    fn is_current(self) -> bool {
        match self {
            Self::Unix => cfg!(unix),
            Self::Windows => cfg!(windows),
        }
    }
}

fn validate_catalog_platform(platform: Option<CatalogPlatform>) -> Result<()> {
    if let Some(platform) = platform.filter(|platform| !platform.is_current()) {
        bail!(
            "verb catalog targets platform '{}', but this Guard binary targets '{}'",
            platform.as_str(),
            std::env::consts::FAMILY
        );
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct CatalogFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    platform: Option<CatalogPlatform>,
    #[serde(default)]
    verbs: Vec<Verb>,
}

fn is_synthesized_verb(verb: &Verb) -> bool {
    verb.auto_promoted
        || verb.source_prose.is_some()
        || verb.evidence.is_some()
        || verb.promotion_stamp.is_some()
}

/// The result of rendering a verb invocation: a concrete command ready to gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedVerb {
    pub name: String,
    pub binary: String,
    pub args: Vec<String>,
    pub consequence: Reversibility,
    pub revert: Option<(String, Vec<String>)>,
    pub hold: bool,
    pub trusted: bool,
    pub prompt_context: Option<String>,
    pub exec_timeout_secs: Option<u64>,
    pub baseline: bool,
    pub credential_plan: Option<String>,
    /// Validated params used while rendering and resolving coverage. Approval
    /// snapshots bind the resulting immutable argv and do not persist values.
    pub params: BTreeMap<String, String>,
    /// Mirrors `Verb::auto_promoted` / `Verb::promotion_stamp`. The caller
    /// (`server::execute_command_inner`) downgrades `trusted` to `false` when
    /// `auto_promoted` is true and `promotion_stamp` no longer matches the
    /// daemon's current model/prompt stamp.
    pub auto_promoted: bool,
    pub promotion_stamp: Option<String>,
}

/// The daemon's effective verb catalog, composed from durable operator-owned
/// definitions and runtime-only generated coverage. The content version
/// fingerprints the effective set and voids approvals when either plane
/// changes.
#[derive(Debug, Clone, Default)]
pub struct VerbCatalog {
    verbs: BTreeMap<String, Verb>,
    version: u64,
    path: Option<PathBuf>,
    mtime: Option<SystemTime>,
    snapshot: Option<LearningFileSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerbCatalogFinding {
    pub verb: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerbCatalogRepair {
    pub verb: String,
    pub changes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct VerbCatalogLintReport {
    pub findings: Vec<VerbCatalogFinding>,
    pub repairs: Vec<VerbCatalogRepair>,
    pub verb_count: usize,
    pub fixed: bool,
    pub durability_warning: Option<String>,
    canonical: Option<String>,
}

impl VerbCatalog {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build an isolated catalog containing one synthesized candidate for a
    /// non-executing admission preview. The temporary baseline flag makes the
    /// candidate's Evaluate cell selectable without granting durable session
    /// authority; the original candidate remains unchanged.
    pub fn for_admission_preview(candidate: &Verb) -> Result<Self> {
        let mut verb = candidate.clone();
        if is_synthesized_verb(&verb) {
            validate_canonical_synthesized_verb_envelope(&verb)?;
        }
        verb.baseline = true;
        verb.trusted = false;
        validate_verb(&verb)?;
        let serialized = serde_json::to_vec(&verb).context("failed to fingerprint preview verb")?;
        let digest = Sha256::digest(&serialized);
        let mut version_bytes = [0u8; 8];
        version_bytes.copy_from_slice(&digest[..8]);
        Ok(Self {
            verbs: BTreeMap::from([(verb.name.clone(), verb)]),
            version: u64::from_be_bytes(version_bytes),
            path: None,
            mtime: None,
            snapshot: None,
        })
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    /// Stable, compact representation of the loaded catalog content version.
    pub fn short_hash(&self) -> String {
        format!("{:012x}", self.version & 0x0000_ffff_ffff_ffff)
    }

    /// Filesystem change time for file-backed catalogs, in Unix seconds.
    pub fn changed_unix(&self) -> Option<u64> {
        self.mtime.and_then(|time| {
            time.duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|duration| duration.as_secs())
        })
    }

    pub fn is_empty(&self) -> bool {
        self.verbs.is_empty()
    }

    pub fn names(&self) -> Vec<String> {
        self.verbs.keys().cloned().collect()
    }

    pub fn get(&self, name: &str) -> Option<&Verb> {
        self.verbs.get(name)
    }

    /// Definition digest of one named verb, or `None` if the catalog has no
    /// verb by that name (see [`Verb::definition_digest`]).
    pub fn verb_definition_digest(&self, name: &str) -> Option<String> {
        self.get(name).map(Verb::definition_digest)
    }

    pub fn list(&self) -> Vec<Verb> {
        self.verbs.values().cloned().collect()
    }

    /// Parse and validate a catalog from YAML text. Validation rejects:
    /// duplicate names, non-anchored param patterns, invalid regexes, and
    /// template placeholders that reference an undeclared param.
    pub fn from_yaml(text: &str) -> Result<Self> {
        Self::from_yaml_with_repair(text).map(|(catalog, _)| catalog)
    }

    fn from_yaml_with_repair(text: &str) -> Result<(Self, Option<String>)> {
        let file: CatalogFile =
            serde_yaml_ng::from_str(text).context("failed to parse verb catalog")?;
        validate_catalog_platform(file.platform)?;
        let mut verbs = BTreeMap::new();
        let mut repaired = false;
        for verb in file.verbs {
            let (verb, repairs) = prepare_catalog_verb(verb)?;
            repaired |= !repairs.is_empty();
            if verbs.insert(verb.name.clone(), verb.clone()).is_some() {
                bail!("duplicate verb name: '{}'", verb.name);
            }
        }
        let canonical = repaired
            .then(|| canonical_catalog_yaml(text, verbs.values()))
            .transpose()?;
        let version_text = canonical.as_deref().unwrap_or(text);
        let digest = Sha256::digest(version_text.as_bytes());
        let mut version_bytes = [0u8; 8];
        version_bytes.copy_from_slice(&digest[..8]);
        Ok((
            Self {
                verbs,
                version: u64::from_be_bytes(version_bytes),
                path: None,
                mtime: None,
                snapshot: None,
            },
            canonical,
        ))
    }

    /// Validate every independently decodable verb in a catalog. Unlike
    /// `from_yaml`, this reports one structural failure per verb instead of
    /// stopping at the first invalid definition.
    pub fn lint_yaml(text: &str) -> VerbCatalogLintReport {
        lint_catalog_yaml(text)
    }

    /// Validate one file without contacting a daemon. Canonical repairs are
    /// committed through the same bounded atomic rewrite path used by daemon
    /// catalog loading, and only when the complete catalog is otherwise valid.
    pub fn lint_file(path: &Path, fix: bool) -> Result<VerbCatalogLintReport> {
        if fix {
            let (mut report, _snapshot, warning) =
                rewrite_learning_file_bounded(path, |snapshot| {
                    let bytes = snapshot.content().context("verb catalog does not exist")?;
                    let text = std::str::from_utf8(bytes)
                        .with_context(|| format!("verb catalog {} is not UTF-8", path.display()))?;
                    let mut report = lint_catalog_yaml(text);
                    let replacement = if report.findings.is_empty() {
                        report.canonical.take()
                    } else {
                        None
                    };
                    report.fixed = replacement.is_some();
                    Ok((replacement, report))
                })?;
            report.durability_warning = warning.map(|error| error.to_string());
            return Ok(report);
        }

        let snapshot = load_immutable_learning_file_snapshot(path)?;
        let bytes = snapshot.content().context("verb catalog does not exist")?;
        let text = std::str::from_utf8(bytes)
            .with_context(|| format!("verb catalog {} is not UTF-8", path.display()))?;
        Ok(lint_catalog_yaml(text))
    }

    /// Load a catalog from a file, recording its path and mtime for reloads.
    pub fn load(path: &Path) -> Result<Self> {
        let (mut catalog, snapshot, warning) = rewrite_learning_file_bounded(path, |snapshot| {
            let bytes = snapshot.content().context("verb catalog does not exist")?;
            let text = std::str::from_utf8(bytes)
                .with_context(|| format!("verb catalog {} is not UTF-8", path.display()))?;
            let (catalog, repair) = Self::from_yaml_with_repair(text)?;
            Ok((repair, catalog))
        })?;
        if let Some(error) = warning {
            tracing::warn!("catalog repair committed with a durability warning: {error}");
        }
        catalog.path = Some(path.to_path_buf());
        catalog.mtime = snapshot.modified();
        catalog.snapshot = Some(snapshot);
        Ok(catalog)
    }

    /// Load an operator-owned catalog as immutable process input. This mode
    /// never creates a transaction lock beside the catalog and never observes
    /// later path changes, so a read-only packaged configuration directory
    /// does not become writable by the daemon.
    pub fn load_immutable(path: &Path) -> Result<Self> {
        let snapshot = load_immutable_learning_file_snapshot(path)?;
        let bytes = snapshot.content().context("verb catalog does not exist")?;
        let text = std::str::from_utf8(bytes)
            .with_context(|| format!("verb catalog {} is not UTF-8", path.display()))?;
        let (catalog, repair) = Self::from_yaml_with_repair(text)?;
        if repair.is_some() {
            anyhow::bail!(
                "immutable verb catalog requires canonical repair; update it before starting the service"
            );
        }
        Ok(catalog)
    }

    /// Reload the catalog if its file changed on disk. Returns `Ok(true)` if it
    /// was reloaded. A parse error keeps the previous catalog and is reported.
    pub fn reload_if_stale(&mut self) -> Result<bool> {
        let Some(path) = self.path.clone() else {
            return Ok(false);
        };
        let current = load_learning_file_snapshot(&path)?;
        if self
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| current.same_authority(snapshot))
        {
            return Ok(false);
        }
        let durable_catalog = Self::load(&path)?;
        *self = self.effective_catalog_with_runtime_overlays(durable_catalog)?;
        Ok(true)
    }

    #[doc(hidden)]
    pub fn refreshed_copy(&self) -> Result<Self> {
        let Some(path) = self.path.clone() else {
            return Ok(self.clone());
        };
        let durable_catalog = Self::load(&path)?;
        self.effective_catalog_with_runtime_overlays(durable_catalog)
    }

    #[doc(hidden)]
    pub fn adopt_refreshed_file_authority(&mut self, mut refreshed: Self) -> Result<()> {
        refreshed.verbs.retain(|name, _| !reserved_verb_name(name));
        *self = self.effective_catalog_with_runtime_overlays(refreshed)?;
        Ok(())
    }

    /// Build the effective daemon catalog from a durable operator document and
    /// the runtime-only coverage already installed in this process. Keeping
    /// these authority planes as separate values prevents generated grants from
    /// entering an operator catalog serialization while preserving them across
    /// file reloads and mutations.
    fn effective_catalog_with_runtime_overlays(&self, mut durable_catalog: Self) -> Result<Self> {
        let runtime_overlays = self
            .verbs
            .values()
            .filter(|verb| reserved_verb_name(&verb.name))
            .cloned()
            .collect::<Vec<_>>();
        for mut verb in runtime_overlays {
            if verb.name.starts_with("grant-") {
                durable_catalog.upsert_saved_grant_verb(verb)?;
            } else {
                // Approved generated coverage is trusted only in memory. Demote
                // it to its validated proposal form before reinstalling it.
                verb.trusted = false;
                durable_catalog.upsert_access_verb(verb)?;
            }
        }
        Ok(durable_catalog)
    }

    /// Render a verb invocation into a concrete, gated command. Each param is
    /// validated against its anchored pattern; placeholders become single argv
    /// elements; values may not begin with `-` unless the spec opts in.
    pub fn render(&self, name: &str, params: &BTreeMap<String, String>) -> Result<RenderedVerb> {
        let verb = self
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("unknown verb: '{}'", name))?;

        // Reject params the verb does not declare.
        for key in params.keys() {
            if !verb.params.contains_key(key) {
                bail!("verb '{}' has no parameter '{}'", name, key);
            }
        }

        // Resolve + validate each declared param.
        let mut resolved: BTreeMap<String, String> = BTreeMap::new();
        for (pname, spec) in &verb.params {
            let value = match params.get(pname) {
                Some(v) => v.clone(),
                None => match &spec.default {
                    Some(d) => d.clone(),
                    None if spec.required => {
                        bail!("verb '{}' requires parameter '{}'", name, pname)
                    }
                    None => continue,
                },
            };
            let re = compile_anchored(spec.pattern_text())
                .with_context(|| format!("invalid pattern for param '{}'", pname))?;
            if !re.is_match(&value) {
                bail!(
                    "value for '{}' does not match required pattern {}",
                    pname,
                    spec.pattern_text()
                );
            }
            if spec
                .max_length()
                .is_some_and(|maximum| value.chars().count() > maximum)
            {
                bail!(
                    "value for '{}' exceeds its maximum length of {} characters",
                    pname,
                    spec.max_length().unwrap_or_default()
                );
            }
            if spec.value_type() == ParamValueType::SingleArgv {
                validate_single_argv_value(pname, &value)?;
            }
            if !spec.allow_dash && value.starts_with('-') {
                bail!(
                    "value for '{}' may not begin with '-' (would be parsed as an option)",
                    pname
                );
            }
            resolved.insert(pname.clone(), value);
        }

        let binary = render_token(&verb.binary, &resolved, name)?;
        let args = render_args(&verb.args, &resolved, name)?;
        let revert = match &verb.revert {
            Some(cmd) => {
                let rb = render_token(&cmd.binary, &resolved, name)?;
                let ra = render_args(&cmd.args, &resolved, name)?;
                Some((rb, ra))
            }
            None => None,
        };
        validate_known_file_arguments(verb, &binary, &args, &verb.args, "rendered command")?;
        if let Some((revert_binary, revert_args)) = &revert {
            let revert_template_args = verb
                .revert
                .as_ref()
                .map(|command| command.args.as_slice())
                .unwrap_or_default();
            validate_known_file_arguments(
                verb,
                revert_binary,
                revert_args,
                revert_template_args,
                "rendered revert command",
            )?;
        }
        if verb.name.starts_with("access-generated-")
            && (command_contains_sensitive_literals(&binary, &args)
                || revert.as_ref().is_some_and(|(revert_binary, revert_args)| {
                    command_contains_sensitive_literals(revert_binary, revert_args)
                }))
        {
            bail!("{SENSITIVE_ARGV_REPLAY_GUIDANCE}");
        }

        Ok(RenderedVerb {
            name: name.to_string(),
            binary,
            args,
            consequence: verb.consequence,
            revert,
            hold: verb.hold,
            trusted: verb.trusted,
            prompt_context: verb.prompt_context.clone(),
            exec_timeout_secs: verb.exec_timeout_secs,
            baseline: verb.baseline,
            credential_plan: verb.credential_plan.clone(),
            params: resolved,
            auto_promoted: verb.auto_promoted,
            promotion_stamp: verb.promotion_stamp.clone(),
        })
    }

    /// The backing catalog file, if this catalog was loaded from one.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Collect every verb coverage cell applicable to a concrete command. The
    /// returned order is canonical `(verb name, cell name)` order and therefore
    /// independent of YAML declaration order. Resolution happens after this
    /// collection step so an alphabetically earlier verb can never shadow a
    /// semantically stronger match.
    pub fn match_command_all(&self, binary: &str, args: &[String]) -> Vec<CoverageMatch> {
        self.match_command_all_with_environment(
            binary,
            args,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
    }

    /// Collect coverage while binding every caller-controlled environment
    /// input to explicit typed authority. Tool-configured daemon environment is
    /// intentionally not accepted here because callers cannot choose it.
    pub fn match_command_all_with_environment(
        &self,
        binary: &str,
        args: &[String],
        plain: &BTreeMap<String, String>,
        secrets: &BTreeMap<String, String>,
        secret_files: &BTreeMap<String, String>,
    ) -> Vec<CoverageMatch> {
        self.match_command_all_inner(binary, args, plain, secrets, secret_files, None)
    }

    /// Collect coverage with a canonical caller working directory. Cells that
    /// carry `cwd` match only that exact directory. The executor calls this
    /// after canonicalizing a local request, so configuration discovered from
    /// the current directory remains within operator-reviewed authority.
    pub fn match_command_all_with_environment_and_cwd(
        &self,
        binary: &str,
        args: &[String],
        plain: &BTreeMap<String, String>,
        secrets: &BTreeMap<String, String>,
        secret_files: &BTreeMap<String, String>,
        cwd: Option<&Path>,
    ) -> Vec<CoverageMatch> {
        self.match_command_all_inner(binary, args, plain, secrets, secret_files, cwd)
    }

    fn match_command_all_inner(
        &self,
        binary: &str,
        args: &[String],
        plain: &BTreeMap<String, String>,
        secrets: &BTreeMap<String, String>,
        secret_files: &BTreeMap<String, String>,
        cwd: Option<&Path>,
    ) -> Vec<CoverageMatch> {
        let mut matches = Vec::new();
        for verb in self.verbs.values() {
            if !binary_names_match(binary, &verb.binary) {
                continue;
            }
            if verb.name.starts_with("access-generated-")
                && command_contains_sensitive_literals(binary, args)
            {
                continue;
            }

            let captured = if verb.args.is_empty() && !verb.coverage.is_empty() {
                BTreeMap::new()
            } else {
                let Some(captured) = match_args_template(&verb.args, args) else {
                    continue;
                };
                captured
            };
            let Ok(mut rendered) = self.render(&verb.name, &captured) else {
                continue;
            };
            if verb.args.is_empty() && !verb.coverage.is_empty() {
                rendered.binary = binary.to_string();
                rendered.args = args.to_vec();
            }
            if validate_known_file_arguments(
                verb,
                &rendered.binary,
                &rendered.args,
                &verb.args,
                "matched command",
            )
            .is_err()
            {
                continue;
            }

            if verb.coverage.is_empty() {
                if verb.trusted && cwd.is_some() {
                    continue;
                }
                matches.push(CoverageMatch {
                    rendered,
                    cell: "legacy-template".to_string(),
                    action: if verb.trusted {
                        CoverageAction::Preauthorized
                    } else {
                        CoverageAction::Evaluate
                    },
                    override_marker: None,
                    sticky: false,
                    features: legacy_template_features(&verb.args),
                    specificity: CoverageSpecificity {
                        requirements: legacy_template_features(&verb.args),
                        ..CoverageSpecificity::default()
                    },
                    environment_authorized: plain.is_empty()
                        && secrets.is_empty()
                        && secret_files.is_empty(),
                    local_file_authorized: true,
                    exact_cwd_authorized: false,
                });
                continue;
            }

            for cell in &verb.coverage {
                if cell.action == CoverageAction::Preauthorized
                    && cwd.is_some()
                    && cell.cwd.is_none()
                {
                    continue;
                }
                // Deny cells constrain matching and grant no execution
                // authority, so affirmative file-authority eligibility must
                // not make a matching deny disappear.
                if cell.action != CoverageAction::Deny
                    && !generic_cell_authorizes_operator_fixed_options(verb, cell, args)
                {
                    continue;
                }
                if cell.action != CoverageAction::Deny
                    && !generic_cell_authorizes_ansible_inventory(verb, cell, args)
                {
                    continue;
                }
                if let Some((features, specificity)) = coverage_cell_matches(verb, cell, args, cwd)
                {
                    matches.push(CoverageMatch {
                        rendered: rendered.clone(),
                        cell: cell.name.clone(),
                        action: cell.action,
                        override_marker: cell.override_marker.clone(),
                        sticky: cell.sticky,
                        features,
                        specificity,
                        environment_authorized: environment_is_authorized(
                            binary,
                            cell,
                            plain,
                            secrets,
                            secret_files,
                        ),
                        local_file_authorized: cell_authorizes_local_file_authority(
                            verb, cell, args,
                        ),
                        exact_cwd_authorized: cell.cwd.is_some(),
                    });
                }
            }
        }
        matches.sort_by(|a, b| (&a.rendered.name, &a.cell).cmp(&(&b.rendered.name, &b.cell)));
        matches
    }

    /// Compatibility wrapper for callers that have not migrated to collect-all
    /// resolution. It returns the first canonical match, not declaration order.
    pub fn match_command(&self, binary: &str, args: &[String]) -> Option<RenderedVerb> {
        self.match_command_all(binary, args)
            .into_iter()
            .next()
            .map(|matched| matched.rendered)
    }

    /// Validate a candidate verb against this catalog: it must pass the same
    /// structural validation as a loaded verb (anchored patterns, declared
    /// placeholders) and must not collide with an existing verb name.
    pub fn validate_candidate(&self, verb: &Verb) -> Result<()> {
        validate_verb(verb)?;
        if self.verbs.contains_key(&verb.name) {
            bail!("a verb named '{}' already exists in the catalog", verb.name);
        }
        Ok(())
    }

    /// Validate, then persist, a new verb by appending it to the backing catalog
    /// file, then adopt the validated result so the in-memory catalog (and its
    /// content version) reflect the write. Requires the catalog to be
    /// file-backed. Nothing is written if validation fails.
    pub fn append_verb(&mut self, verb: &Verb) -> Result<()> {
        let canonical;
        let verb = if is_synthesized_verb(verb) {
            canonical = canonicalize_generated_authority_envelope(verb.clone())?;
            &canonical
        } else {
            verb
        };
        // Reject an invalid candidate before reading a stale catalog through
        // the repairing parser. A failed append must never canonicalize an
        // externally changed file as a side effect.
        validate_verb(verb)?;
        let path = self.path.clone().ok_or_else(|| {
            anyhow::anyhow!("verb catalog is not backed by a file; cannot persist a new verb")
        })?;
        let snapshot = load_learning_file_snapshot(&path)?;
        let existing = snapshot
            .content()
            .map(std::str::from_utf8)
            .transpose()
            .context("verb catalog is not UTF-8")?
            .unwrap_or_default()
            .to_string();
        // Compose against the current snapshot before parsing. Duplicate
        // detection and canonical repair therefore observe concurrent edits,
        // support every accepted empty-catalog shape, and remain read-only
        // until the complete append transaction succeeds.
        let new_content = compose_appended_catalog(&existing, verb)?;
        // Validate the COMBINED catalog in memory BEFORE touching the file, so a
        // bad or duplicate verb can never corrupt the catalog on disk.
        let (durable_catalog, canonical) = Self::from_yaml_with_repair(&new_content)
            .context("appending this verb would make the catalog invalid")?;
        let durable_content = canonical.unwrap_or(new_content);
        let mut effective_catalog =
            self.effective_catalog_with_runtime_overlays(durable_catalog)?;
        let outcome =
            write_learning_file_atomically_for_locked_snapshot(&path, &snapshot, &durable_content)?;
        let (committed, warning) = outcome.into_parts();
        // Adopt the already-validated content rather than re-reading the file: a
        // post-write reload failure would otherwise report an error to the
        // operator even though the write landed, desyncing memory from disk.
        effective_catalog.path = Some(path);
        effective_catalog.mtime = committed.modified();
        effective_catalog.snapshot = Some(committed);
        *self = effective_catalog;
        if let Some(error) = warning {
            tracing::warn!("catalog append committed with a durability warning: {error}");
        }
        Ok(())
    }

    /// Persist one explicitly operator-authored verb without admitting a
    /// runtime-reserved or automatically promoted identity through the file
    /// import boundary.
    pub fn append_operator_verb(&mut self, verb: &Verb) -> Result<Verb> {
        if reserved_verb_name(&verb.name) {
            bail!(
                "reserved verb '{}' cannot be added as an operator-authored verb",
                verb.name
            );
        }
        let mut generated_fields = Vec::new();
        if verb.auto_promoted {
            generated_fields.push("auto_promoted");
        }
        if verb.promotion_stamp.is_some() {
            generated_fields.push("promotion_stamp");
        }
        if verb.source_prose.is_some() {
            generated_fields.push("source_prose");
        }
        if verb.evidence.is_some() {
            generated_fields.push("evidence");
        }
        if !generated_fields.is_empty() {
            bail!(
                "operator-authored verb '{}' cannot set generated-authority field(s): {}; remove these fields before adding the verb",
                verb.name,
                generated_fields.join(", ")
            );
        }
        let mut normalized = verb.clone();
        normalize_operator_boundaries(&mut normalized);
        self.append_verb(&normalized)?;
        self.get(&normalized.name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("persisted verb '{}' is unavailable", normalized.name))
    }

    /// Replace one operator-authored file verb only when its live definition
    /// still matches `expected_digest`. Validation and whole-catalog
    /// composition complete before the backing file is atomically replaced.
    /// The in-memory catalog adopts that validated document plus its existing
    /// runtime-only coverage after the durable replacement succeeds.
    pub fn amend_verb_if_digest(
        &mut self,
        name: &str,
        expected_digest: &str,
        replacement: &Verb,
    ) -> Result<Verb> {
        if expected_digest.len() != 64
            || !expected_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            bail!("expected verb digest must be 64 lowercase hexadecimal characters");
        }
        if replacement.name != name {
            bail!(
                "replacement verb name '{}' does not match '{}'; amend preserves the existing name",
                replacement.name,
                name
            );
        }
        if reserved_verb_name(name) || replacement.auto_promoted {
            bail!("generated or reserved verb '{}' cannot be amended", name);
        }
        validate_verb(replacement)?;

        self.reload_if_stale()?;
        let path = self.path.clone().ok_or_else(|| {
            anyhow::anyhow!("verb catalog is not backed by a file; cannot amend a verb")
        })?;
        let snapshot = load_learning_file_snapshot(&path)?;
        let existing =
            std::str::from_utf8(snapshot.content().context("verb catalog does not exist")?)
                .with_context(|| format!("verb catalog {} is not UTF-8", path.display()))?
                .to_string();
        let disk_catalog = Self::from_yaml(&existing)?;
        let current = disk_catalog
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown verb: '{}'", name))?;
        if current.auto_promoted || reserved_verb_name(&current.name) {
            bail!("generated or reserved verb '{}' cannot be amended", name);
        }
        let current_digest = current.definition_digest();
        if current_digest != expected_digest {
            bail!(
                "verb '{}' changed before amend: expected digest {}, found {}",
                name,
                expected_digest,
                current_digest
            );
        }

        let new_content = compose_replaced_catalog(&existing, name, replacement)?;
        let (durable_catalog, canonical) = Self::from_yaml_with_repair(&new_content)
            .context("amending this verb would make the catalog invalid")?;
        let durable_content = canonical.unwrap_or(new_content);
        let mut effective_catalog =
            self.effective_catalog_with_runtime_overlays(durable_catalog)?;
        // Every fallible catalog adoption step completes before the durable
        // rewrite. After this point, success requires only the atomic file
        // replacement and assigning the already validated state.
        let outcome = atomic_replace_if_unchanged(&path, &snapshot, durable_content.as_bytes())?;
        let (committed, warning) = outcome.into_parts();
        effective_catalog.path = Some(path.clone());
        effective_catalog.mtime = committed.modified();
        effective_catalog.snapshot = Some(committed);
        *self = effective_catalog;
        if let Some(error) = warning {
            tracing::warn!("catalog amendment committed with a durability warning: {error}");
        }
        Ok(current)
    }

    /// Install or replace a validated daemon-owned verb without writing the
    /// operator catalog. Saved grants use this for generated coverage that is
    /// persisted with the grant definition rather than mixed into the catalog
    /// file. Names outside the reserved `grant-` namespace cannot be replaced.
    pub fn upsert_saved_grant_verb(&mut self, verb: Verb) -> Result<()> {
        let verb = canonicalize_generated_authority_envelope(verb)?;
        validate_verb(&verb)?;
        if !verb.name.starts_with("grant-") {
            bail!(
                "saved-grant verb '{}' must use the reserved 'grant-' prefix",
                verb.name
            );
        }
        if self
            .verbs
            .get(&verb.name)
            .is_some_and(|existing| !existing.name.starts_with("grant-"))
        {
            bail!(
                "saved-grant verb '{}' collides with catalog state",
                verb.name
            );
        }
        self.verbs.insert(verb.name.clone(), verb);
        self.refresh_version()?;
        Ok(())
    }

    /// Install approved generated access coverage without writing the
    /// operator-authored catalog. The exact candidate remains durable in its
    /// approved access request and is restored from SQLite at startup.
    pub fn canonical_generated_access_verb(&self, verb: Verb) -> Result<Verb> {
        let mut verb = normalize_generated_access_verb(verb)?;
        if verb.baseline {
            bail!("generated access coverage must not be baseline");
        }
        if verb.name != generated_access_verb_name(&verb) {
            bail!("generated access coverage name does not match its matcher digest");
        }
        // Synthesis proposes the matcher, not its safety class. Consequence
        // routing is derived locally from the matcher and exact operator
        // coverage, so provenance and model metadata cannot affect it.
        verb.consequence = canonical_generated_access_consequence(&verb);
        if verb.consequence == Reversibility::Irreversible {
            if let Some(inherited) = self.wrapped_operator_consequence(&verb) {
                verb.consequence = inherited;
            }
        }
        Ok(verb)
    }

    pub fn upsert_access_verb(&mut self, verb: Verb) -> Result<()> {
        let mut verb = self.canonical_generated_access_verb(verb)?;
        verb.trusted = true;
        if let Some(existing) = self.verbs.get(&verb.name) {
            if serde_json::to_value(existing)? == serde_json::to_value(&verb)? {
                return Ok(());
            }
            bail!(
                "generated access verb '{}' conflicts with catalog state",
                verb.name
            );
        }
        self.verbs.insert(verb.name.clone(), verb);
        self.refresh_version()?;
        Ok(())
    }

    /// Inherit an operator-reviewed consequence only when every concrete argv
    /// admitted by the generated matcher reverse-matches compatible catalog
    /// coverage. Non-enumerable or broader matchers inherit nothing and stay
    /// at the fail-closed generated default.
    fn wrapped_operator_consequence(&self, candidate: &Verb) -> Option<Reversibility> {
        if !candidate.coverage.is_empty() || candidate.binary.contains('{') {
            return None;
        }
        let mut inherited: Option<Reversibility> = None;
        for args in enumerate_matcher_commands(candidate)? {
            let class = self
                .match_command_all(&candidate.binary, &args)
                .into_iter()
                .filter(|matched| {
                    matched.action != CoverageAction::Deny
                        && matched.rendered.name != candidate.name
                        && !matched.rendered.name.starts_with("grant-")
                        && !matched.rendered.name.starts_with("access-generated-")
                })
                .map(|matched| matched.rendered.consequence)
                .max_by_key(|class| reversibility_rank(*class))?;
            inherited = Some(match inherited {
                Some(previous) if reversibility_rank(previous) >= reversibility_rank(class) => {
                    previous
                }
                _ => class,
            });
        }
        inherited
    }

    pub fn remove_saved_grant_verbs(&mut self, grant_name: &str) -> Result<usize> {
        let prefix = format!("grant-{grant_name}-");
        let before = self.verbs.len();
        self.verbs.retain(|name, _| !name.starts_with(&prefix));
        let removed = before.saturating_sub(self.verbs.len());
        if removed > 0 {
            self.refresh_version()?;
        }
        Ok(removed)
    }

    /// Delete an operator catalog verb and atomically adopt the rewritten
    /// catalog. Saved-grant generated verbs are deleted through their grant.
    pub fn delete_verb(&mut self, name: &str) -> Result<Verb> {
        let verb = self
            .verbs
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown verb: '{}'", name))?;
        if reserved_verb_name(name) {
            bail!(
                "runtime-generated coverage cannot be deleted directly; use its owning access or grant operation"
            );
        }
        let path = self.path.clone().ok_or_else(|| {
            anyhow::anyhow!("verb catalog is not backed by a file; cannot delete a verb")
        })?;
        let snapshot = load_learning_file_snapshot(&path)?;
        let existing = snapshot
            .content()
            .map(std::str::from_utf8)
            .transpose()
            .context("verb catalog is not UTF-8")?
            .unwrap_or_default()
            .to_string();
        let new_content = compose_removed_catalog(&existing, name)?;
        let (durable_catalog, canonical) = Self::from_yaml_with_repair(&new_content)
            .context("deleting this verb would make the catalog invalid")?;
        let durable_content = canonical.unwrap_or(new_content);
        let mut effective_catalog =
            self.effective_catalog_with_runtime_overlays(durable_catalog)?;
        let outcome =
            write_learning_file_atomically_for_locked_snapshot(&path, &snapshot, &durable_content)?;
        let (committed, warning) = outcome.into_parts();
        effective_catalog.path = Some(path);
        effective_catalog.mtime = committed.modified();
        effective_catalog.snapshot = Some(committed);
        *self = effective_catalog;
        if let Some(error) = warning {
            tracing::warn!("catalog deletion committed with a durability warning: {error}");
        }
        Ok(verb)
    }

    fn refresh_version(&mut self) -> Result<()> {
        let yaml = serde_yaml_ng::to_string(&CatalogFile {
            platform: None,
            verbs: self.verbs.values().cloned().collect(),
        })
        .context("failed to fingerprint verb catalog")?;
        let digest = Sha256::digest(yaml.as_bytes());
        let mut version_bytes = [0u8; 8];
        version_bytes.copy_from_slice(&digest[..8]);
        self.version = u64::from_be_bytes(version_bytes);
        Ok(())
    }
}

#[cfg(test)]
fn catalog_repair_warning(
    canonical: &str,
    outcome: crate::learned_rules::LearningWriteOutcome,
) -> Result<Option<anyhow::Error>> {
    if outcome.committed_snapshot().content() != Some(canonical.as_bytes()) {
        bail!("committed catalog repair does not match its canonical candidate");
    }
    let (_, warning) = outcome.into_parts();
    let Some(error) = warning else {
        return Ok(None);
    };
    Ok(Some(error))
}

fn prepare_catalog_verb(mut verb: Verb) -> Result<(Verb, Vec<String>)> {
    if is_synthesized_verb(&verb) && text_contains_sensitive_literals(&verb.name) {
        bail!("generated verb name contains sensitive material");
    }
    if verb.name.starts_with("grant-") {
        bail!(
            "verb name '{}' uses the reserved saved-grant namespace",
            verb.name
        );
    }
    if verb.name.starts_with("access-generated-") {
        bail!(
            "verb name '{}' uses the reserved generated-access namespace",
            verb.name
        );
    }

    let mut repairs = Vec::new();
    if is_synthesized_verb(&verb) {
        let before = serde_json::to_value(&verb)?;
        verb = canonicalize_generated_authority_envelope(verb)?;
        if before != serde_json::to_value(&verb)? {
            repairs.push("canonicalize generated authority envelope".to_string());
        }
    }
    let before_boundaries = serde_json::to_value(&verb)?;
    normalize_operator_boundaries(&mut verb);
    if before_boundaries != serde_json::to_value(&verb)? {
        repairs.push("normalize operator boundaries".to_string());
    }
    validate_verb(&verb)?;
    if verb.auto_promoted {
        validate_auto_promoted_verb_durable_safety(&verb)?;
    }
    Ok((verb, repairs))
}

fn lint_catalog_yaml(text: &str) -> VerbCatalogLintReport {
    let mut report = VerbCatalogLintReport {
        findings: Vec::new(),
        repairs: Vec::new(),
        verb_count: 0,
        fixed: false,
        durability_warning: None,
        canonical: None,
    };
    let body = text.strip_prefix('\u{feff}').unwrap_or(text);
    let document: serde_yaml_ng::Value = match serde_yaml_ng::from_str(body) {
        Ok(document) => document,
        Err(error) => {
            report.findings.push(VerbCatalogFinding {
                verb: "<catalog>".to_string(),
                message: format!("failed to parse verb catalog: {error}"),
            });
            return report;
        }
    };
    let Some(mapping) = document.as_mapping() else {
        report.findings.push(VerbCatalogFinding {
            verb: "<catalog>".to_string(),
            message: "verb catalog must be a YAML mapping".to_string(),
        });
        return report;
    };
    let platform_key = serde_yaml_ng::Value::String("platform".to_string());
    if let Some(value) = mapping.get(&platform_key) {
        let platform = match serde_yaml_ng::from_value::<CatalogPlatform>(value.clone()) {
            Ok(platform) => platform,
            Err(error) => {
                report.findings.push(VerbCatalogFinding {
                    verb: "<catalog>".to_string(),
                    message: format!("invalid catalog platform: {error}"),
                });
                return report;
            }
        };
        if let Err(error) = validate_catalog_platform(Some(platform)) {
            report.findings.push(VerbCatalogFinding {
                verb: "<catalog>".to_string(),
                message: error.to_string(),
            });
            return report;
        }
    }
    let key = serde_yaml_ng::Value::String("verbs".to_string());
    let values = match mapping.get(&key) {
        None => Vec::new(),
        Some(serde_yaml_ng::Value::Sequence(values)) => values.clone(),
        Some(_) => {
            report.findings.push(VerbCatalogFinding {
                verb: "<catalog>".to_string(),
                message: "the catalog's `verbs` key is not a sequence".to_string(),
            });
            return report;
        }
    };
    report.verb_count = values.len();

    let mut names = BTreeSet::new();
    let mut verbs = BTreeMap::new();
    for (index, value) in values.into_iter().enumerate() {
        let fallback = format!("<item {}>", index + 1);
        let declared_name = value
            .as_mapping()
            .and_then(|mapping| mapping.get(serde_yaml_ng::Value::String("name".to_string())))
            .and_then(serde_yaml_ng::Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| fallback.clone());
        let verb: Verb = match serde_yaml_ng::from_value(value) {
            Ok(verb) => verb,
            Err(error) => {
                report.findings.push(VerbCatalogFinding {
                    verb: declared_name,
                    message: format!("failed to decode verb definition: {error}"),
                });
                continue;
            }
        };
        let name = verb.name.clone();
        if !names.insert(name.clone()) {
            report.findings.push(VerbCatalogFinding {
                verb: name.clone(),
                message: format!("duplicate verb name: '{name}'"),
            });
        }
        match prepare_catalog_verb(verb) {
            Ok((verb, changes)) => {
                if !changes.is_empty() {
                    report.repairs.push(VerbCatalogRepair {
                        verb: name.clone(),
                        changes,
                    });
                }
                verbs.entry(name).or_insert(verb);
            }
            Err(error) => report.findings.push(VerbCatalogFinding {
                verb: name,
                message: format!("{error:#}"),
            }),
        }
    }

    if report.findings.is_empty() && !report.repairs.is_empty() {
        match canonical_catalog_yaml(text, verbs.values()) {
            Ok(canonical) => report.canonical = Some(canonical),
            Err(error) => report.findings.push(VerbCatalogFinding {
                verb: "<catalog>".to_string(),
                message: format!("failed to serialize canonical catalog: {error:#}"),
            }),
        }
    }
    report
}

/// Compose the new catalog text by adding one verb to the top-level `verbs:`
/// sequence. Parses the existing catalog into the YAML model (tolerating a
/// leading UTF-8 BOM), pushes the verb, and re-serializes the whole document.
/// Re-serializing - rather than text-appending at EOF - handles a missing,
/// null, empty (`[]`), or flow-style `verbs:` key and preserves any other
/// top-level keys, instead of assuming `verbs:` is the last block in the file.
/// The caller validates the result before writing. (Comments in the catalog are
/// not preserved across an append; the prose/evidence are stored in-band.)
fn compose_appended_catalog(existing: &str, verb: &Verb) -> Result<String> {
    let body = existing.strip_prefix('\u{feff}').unwrap_or(existing);
    let verb_value = serde_yaml_ng::to_value(verb).context("failed to serialize verb")?;

    if body.trim().is_empty() {
        let mut map = serde_yaml_ng::Mapping::new();
        map.insert(
            serde_yaml_ng::Value::String("verbs".to_string()),
            serde_yaml_ng::Value::Sequence(vec![verb_value]),
        );
        return serde_yaml_ng::to_string(&serde_yaml_ng::Value::Mapping(map))
            .context("failed to serialize the new catalog");
    }

    let mut doc: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(body).context("the existing verb catalog is not valid YAML")?;
    let map = doc
        .as_mapping_mut()
        .ok_or_else(|| anyhow::anyhow!("verb catalog is not a YAML mapping"))?;
    let key = serde_yaml_ng::Value::String("verbs".to_string());
    let is_seq = matches!(map.get(&key), Some(serde_yaml_ng::Value::Sequence(_)));
    let is_null_or_absent = matches!(map.get(&key), None | Some(serde_yaml_ng::Value::Null));
    if is_seq {
        if let Some(serde_yaml_ng::Value::Sequence(seq)) = map.get_mut(&key) {
            if seq.iter().any(|value| {
                value
                    .as_mapping()
                    .and_then(|candidate| {
                        candidate.get(serde_yaml_ng::Value::String("name".to_string()))
                    })
                    .and_then(serde_yaml_ng::Value::as_str)
                    == Some(verb.name.as_str())
            }) {
                bail!("a verb named '{}' already exists in the catalog", verb.name);
            }
            seq.push(verb_value);
        }
    } else if is_null_or_absent {
        map.insert(key, serde_yaml_ng::Value::Sequence(vec![verb_value]));
    } else {
        bail!("the catalog's `verbs` key is not a sequence");
    }
    serde_yaml_ng::to_string(&doc).context("failed to serialize the updated catalog")
}

fn canonical_catalog_yaml<'a>(
    existing: &str,
    verbs: impl Iterator<Item = &'a Verb>,
) -> Result<String> {
    let body = existing.strip_prefix('\u{feff}').unwrap_or(existing);
    let mut document: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(body).context("the existing verb catalog is not valid YAML")?;
    let mapping = document
        .as_mapping_mut()
        .ok_or_else(|| anyhow::anyhow!("verb catalog is not a YAML mapping"))?;
    let values = verbs
        .map(serde_yaml_ng::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to serialize canonical verbs")?;
    mapping.insert(
        serde_yaml_ng::Value::String("verbs".to_string()),
        serde_yaml_ng::Value::Sequence(values),
    );
    serde_yaml_ng::to_string(&document).context("failed to serialize the canonical catalog")
}

fn compose_removed_catalog(existing: &str, name: &str) -> Result<String> {
    let body = existing.strip_prefix('\u{feff}').unwrap_or(existing);
    let mut doc: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(body).context("the existing verb catalog is not valid YAML")?;
    let map = doc
        .as_mapping_mut()
        .ok_or_else(|| anyhow::anyhow!("verb catalog is not a YAML mapping"))?;
    let key = serde_yaml_ng::Value::String("verbs".to_string());
    let Some(serde_yaml_ng::Value::Sequence(verbs)) = map.get_mut(&key) else {
        bail!("the catalog's `verbs` key is not a sequence");
    };
    let before = verbs.len();
    verbs.retain(|value| {
        value
            .as_mapping()
            .and_then(|verb| verb.get(serde_yaml_ng::Value::String("name".to_string())))
            .and_then(serde_yaml_ng::Value::as_str)
            != Some(name)
    });
    if verbs.len() == before {
        bail!("unknown verb: '{}'", name);
    }
    serde_yaml_ng::to_string(&doc).context("failed to serialize the updated catalog")
}

fn compose_replaced_catalog(existing: &str, name: &str, replacement: &Verb) -> Result<String> {
    let body = existing.strip_prefix('\u{feff}').unwrap_or(existing);
    let mut doc: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(body).context("the existing verb catalog is not valid YAML")?;
    let map = doc
        .as_mapping_mut()
        .ok_or_else(|| anyhow::anyhow!("verb catalog is not a YAML mapping"))?;
    let key = serde_yaml_ng::Value::String("verbs".to_string());
    let Some(serde_yaml_ng::Value::Sequence(verbs)) = map.get_mut(&key) else {
        bail!("the catalog's `verbs` key is not a sequence");
    };
    let replacement = serde_yaml_ng::to_value(replacement).context("failed to serialize verb")?;
    let mut replaced = false;
    for value in verbs {
        let candidate_name = value
            .as_mapping()
            .and_then(|verb| verb.get(serde_yaml_ng::Value::String("name".to_string())))
            .and_then(serde_yaml_ng::Value::as_str);
        if candidate_name == Some(name) {
            *value = replacement.clone();
            replaced = true;
            break;
        }
    }
    if !replaced {
        bail!("unknown verb: '{}'", name);
    }
    serde_yaml_ng::to_string(&doc).context("failed to serialize the updated catalog")
}

fn reserved_verb_name(name: &str) -> bool {
    name.starts_with("grant-") || name.starts_with("access-generated-")
}

fn atomic_replace_if_unchanged(
    path: &Path,
    expected: &LearningFileSnapshot,
    replacement: &[u8],
) -> Result<crate::learned_rules::LearningWriteOutcome> {
    let replacement =
        std::str::from_utf8(replacement).context("catalog replacement is not UTF-8")?;
    write_learning_file_atomically_for_locked_snapshot(path, expected, replacement)
}

/// Executables whose invocation grammar has a closed, built-in process
/// authority profile. An authorized command fails closed unless its executable
/// appears here or has one of the structured profiles selected below. This is
/// deliberately a positive registry: adding another dispatcher elsewhere does
/// not silently grant it authority.
const PRIMARY_ONLY_AUTHORIZED_EXECUTABLES: &[&str] = &[
    "cat", "df", "echo", "false", "free", "hostname", "id", "ls", "printf", "printenv", "ps",
    "pwd", "tail", "true", "uptime", "whoami",
];

#[cfg(test)]
const TEST_PRIMARY_ONLY_AUTHORIZED_EXECUTABLES: &[&str] = &[
    "allowed-tool",
    "apictl",
    "bounded-sleep",
    "finite-start",
    "fixture-denied",
    "fixture-inspect",
    "fixture-private-binary",
    "fixturectl",
    "guard-command-that-does-not-exist",
    "guard-missing-fixture-binary",
    "missing-tool",
    "novel-fixture",
    "one",
    "ping",
    "redis-cli",
];

/// Return the only process-authority profile an authorized executable may use.
/// Unknown executables have no profile and are rejected before process start.
pub fn authorized_executable_profile(binary: &str) -> Option<DelayedAuthorityProfile> {
    let key = executable_match_key(binary);
    match key.as_str() {
        "ansible" | "ansible-playbook" => Some(DelayedAuthorityProfile::TypedAnsible),
        "kubectl" => Some(DelayedAuthorityProfile::TypedKubectl),
        "helm" => Some(DelayedAuthorityProfile::TypedHelm),
        "systemctl" => Some(DelayedAuthorityProfile::SystemdControl),
        direct if PRIMARY_ONLY_AUTHORIZED_EXECUTABLES.contains(&direct) => {
            Some(DelayedAuthorityProfile::PrimaryOnly)
        }
        #[cfg(test)]
        direct if TEST_PRIMARY_ONLY_AUTHORIZED_EXECUTABLES.contains(&direct) => {
            Some(DelayedAuthorityProfile::PrimaryOnly)
        }
        _ => None,
    }
}

/// Strings a least-privilege parameter pattern must NOT match: whitespace and
/// shell control metacharacters. A pattern that matches any of these is too
/// permissive to be a safe verb parameter (e.g. `^.+$`).
const OVERBROAD_CANARIES: &[&str] = &[
    "a b", "a\tb", "a\nb", "a;b", "a|b", "a&b", "a$b", "a`b", "a>b", "a<b", "a(b)", "a{b}", "a*b",
    "a?b", "a[b", "a\\b", "a!b", "x y z",
];

const SINGLE_ARGV_DANGEROUS_CANARIES: &[&str] = &[
    "a\tb", "a\nb", "a\rb", "a;b", "a|b", "a&b", "a$b", "a`b", "a>b", "a<b",
];

const MAX_SINGLE_ARGV_LENGTH: usize = 4096;

fn validate_single_argv_value(name: &str, value: &str) -> Result<()> {
    if value.chars().any(|character| {
        character.is_control() || matches!(character, ';' | '|' | '&' | '$' | '`' | '>' | '<')
    }) {
        bail!(
            "value for '{}' contains a shell control character that single_argv parameters do not permit",
            name
        );
    }
    Ok(())
}

/// True if `name` is kebab-case (`^[a-z0-9][a-z0-9-]*$`), so it is unambiguously
/// invokable on the `guard verb run <name>` command line. `pub(crate)`: also
/// used by `gating::allow_promotion` to validate a model-proposed name before
/// falling back to a deterministic one.
pub(crate) fn is_kebab_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

/// Binary-name match consistent with `gating::deny_shape::binary_matches` and
/// `server::binary_allowed`: a path-qualified binary (either side) requires an
/// exact match, so a binary reached via a different, path-qualified location
/// (e.g. `/tmp/other/kubectl`) can never reverse-match a verb authored for the
/// bare name, or vice versa; a bare name matches case-insensitively by
/// basename with a stripped `.exe` suffix.
fn binary_names_match(observed: &str, verb_binary: &str) -> bool {
    if observed.contains('/')
        || observed.contains('\\')
        || verb_binary.contains('/')
        || verb_binary.contains('\\')
    {
        return observed == verb_binary;
    }
    executable_match_key(observed) == executable_match_key(verb_binary)
}

fn legacy_template_features(args: &[String]) -> BTreeSet<String> {
    args.iter()
        .enumerate()
        .map(|(index, arg)| format!("template:{index}:{arg}"))
        .collect()
}

fn protected_command_path_matches(verb: &Verb, cell: &VerbCoverageCell, args: &[String]) -> bool {
    if !verb.args.is_empty() {
        return true;
    }
    let binary = executable_match_key(&verb.binary);
    let known_commands = match binary.as_str() {
        "kubectl" => KUBECTL_BUILTIN_SUBCOMMANDS,
        "helm" => HELM_BUILTIN_SUBCOMMANDS,
        _ => return cell.command_path.is_empty(),
    };
    let expected = if cell.command_path.is_empty() {
        if cell.action == CoverageAction::Preauthorized {
            return false;
        }
        let inferred = cell
            .required_args
            .iter()
            .filter(|argument| known_commands.contains(&argument.as_str()))
            .collect::<Vec<_>>();
        if inferred.len() != 1 {
            return false;
        }
        vec![inferred[0].as_str()]
    } else {
        cell.command_path.iter().map(String::as_str).collect()
    };
    let actual_index = match binary.as_str() {
        "kubectl" => kubectl_subcommand_index(&verb.name, args, "coverage command")
            .ok()
            .flatten(),
        "helm" => helm_subcommand_index(&verb.name, args, "coverage command")
            .ok()
            .flatten(),
        _ => None,
    };
    let Some(actual_index) = actual_index else {
        return false;
    };
    expected.iter().enumerate().all(|(offset, expected)| {
        args.get(actual_index + offset).map(String::as_str) == Some(*expected)
    })
}

fn coverage_cell_matches(
    verb: &Verb,
    cell: &VerbCoverageCell,
    args: &[String],
    cwd: Option<&Path>,
) -> Option<(BTreeSet<String>, CoverageSpecificity)> {
    if !protected_command_path_matches(verb, cell, args) {
        return None;
    }
    if cell
        .cwd
        .as_deref()
        .is_some_and(|required| cwd != Some(required))
    {
        return None;
    }
    if cell.min_args.is_some_and(|minimum| args.len() < minimum)
        || cell.max_args.is_some_and(|maximum| args.len() > maximum)
    {
        return None;
    }
    if cell
        .required_args
        .iter()
        .any(|required| !args.contains(required))
        || cell
            .forbidden_args
            .iter()
            .any(|forbidden| args.contains(forbidden))
    {
        return None;
    }

    let mut features = BTreeSet::new();
    if !cell.command_path.is_empty() {
        features.insert(format!("command:{}", cell.command_path.join(" ")));
    }
    for arg in &cell.required_args {
        features.insert(format!("required:{arg}"));
    }
    for arg in &cell.forbidden_args {
        features.insert(format!("forbidden:{arg}"));
    }
    let mut specificity = CoverageSpecificity {
        requirements: features.clone(),
        ..CoverageSpecificity::default()
    };
    if cell.cwd.is_some() {
        features.insert("cwd:exact".to_string());
        specificity.requirements.insert("cwd:exact".to_string());
    }
    if let Some(minimum) = cell.min_args {
        features.insert(format!("argv:min={minimum}"));
        specificity
            .requirements
            .insert(format!("argv:min={minimum}"));
    }
    if let Some(maximum) = cell.max_args {
        features.insert(format!("argv:max={maximum}"));
        specificity
            .requirements
            .insert(format!("argv:max={maximum}"));
    }

    for (kind, constraint) in cell
        .options
        .iter()
        .map(|constraint| ("option", constraint))
        .chain(cell.target.iter().map(|constraint| ("target", constraint)))
        .chain(
            cell.inventory
                .iter()
                .map(|constraint| ("inventory", constraint)),
        )
        .chain(
            cell.namespace
                .iter()
                .map(|constraint| ("namespace", constraint)),
        )
    {
        matched_values(constraint, args)?;
        add_constraint_features(&mut features, &mut specificity, kind, constraint);
    }

    if let Some(fanout) = &cell.fanout {
        let values = matched_values(&fanout.selector, args)?;
        let members = values
            .iter()
            .flat_map(|value| value.split(&fanout.separator))
            .collect::<Vec<_>>();
        if !values.is_empty()
            && (members.iter().any(|value| value.is_empty()) || members.len() > fanout.max)
        {
            return None;
        }
        add_constraint_features(&mut features, &mut specificity, "fanout", &fanout.selector);
        features.insert(format!("fanout:max={}", fanout.max));
        let selector = constraint_selector(&fanout.selector);
        specificity.fanout.insert(selector, fanout.max);
    }

    Some((features, specificity))
}

fn generic_cell_authorizes_ansible_inventory(
    verb: &Verb,
    cell: &VerbCoverageCell,
    args: &[String],
) -> bool {
    if !verb.args.is_empty()
        || !matches!(
            executable_match_key(&verb.binary).as_str(),
            "ansible" | "ansible-playbook"
        )
    {
        return true;
    }
    let Some(mut inventory_sources) = ansible_inventory_sources(args) else {
        return false;
    };
    if inventory_sources.is_empty() {
        return true;
    }
    let Some(constraint) = &cell.inventory else {
        return false;
    };
    let Some(mut constrained_sources) = matched_values(constraint, args) else {
        return false;
    };
    inventory_sources.sort_unstable();
    constrained_sources.sort_unstable();
    inventory_sources == constrained_sources
}

fn generic_cell_authorizes_operator_fixed_options(
    verb: &Verb,
    cell: &VerbCoverageCell,
    args: &[String],
) -> bool {
    if !verb.args.is_empty() || cell.action != CoverageAction::Preauthorized {
        return true;
    }
    let binary = executable_match_key(&verb.binary);
    if matches!(binary.as_str(), "ansible" | "ansible-playbook")
        && ansible_selects_secondary_authority_option(args)
    {
        return false;
    }
    let options: &[&str] = match binary.as_str() {
        "ansible" | "ansible-playbook" => ANSIBLE_OPERATOR_FIXED_OPTIONS,
        "kubectl" => KUBECTL_OPERATOR_FIXED_OPTIONS,
        "helm" => HELM_OPERATOR_FIXED_OPTIONS,
        _ => &[],
    };
    for (index, argument) in args.iter().enumerate() {
        for option in options {
            let Some(value) = operator_option_value_at(args, index, option) else {
                continue;
            };
            let Some(value) = value else {
                return false;
            };
            let exact_argument = format!("{option}={value}");
            let fixed_by_required_argument = cell.required_args.iter().any(|required| {
                required == argument && argument != option || required == &exact_argument
            });
            let fixed_by_value_constraint = cell.options.iter().any(|constraint| {
                constraint.options.iter().any(|known| known == option)
                    && !constraint.values.is_empty()
                    && constraint.values.iter().any(|allowed| allowed == value)
            });
            if !fixed_by_required_argument && !fixed_by_value_constraint {
                return false;
            }
        }
    }
    let fixed_flags: &[&str] = match binary.as_str() {
        "ansible" | "ansible-playbook" => ANSIBLE_OPERATOR_FIXED_FLAGS,
        "kubectl" => KUBECTL_OPERATOR_FIXED_FLAGS,
        "helm" => HELM_OPERATOR_FIXED_FLAGS,
        _ => &[],
    };
    if args.iter().any(|argument| {
        fixed_flags.contains(
            &argument
                .split_once('=')
                .map_or(argument.as_str(), |pair| pair.0),
        ) && !cell.required_args.contains(argument)
    }) {
        return false;
    }
    true
}

/// Parse one exact option spelling using the forms supported by the protected
/// tool grammars. The outer option distinguishes "not this option" from an
/// option that is present but missing its required following value.
fn operator_option_value_at<'a>(
    args: &'a [String],
    index: usize,
    option: &str,
) -> Option<Option<&'a str>> {
    let argument = args.get(index)?;
    if argument == option {
        return Some(args.get(index + 1).map(String::as_str));
    }
    if option.len() == 2 {
        return argument
            .strip_prefix(option)
            .filter(|value| !value.is_empty())
            .map(|value| Some(value.strip_prefix('=').unwrap_or(value)));
    }
    argument.strip_prefix(&format!("{option}=")).map(Some)
}

/// Resolve an Ansible long option using its exact spelling or an unambiguous
/// prefix. The protected subset is shared by static verb validation and
/// generic coverage so both paths apply the same command grammar.
fn resolve_ansible_long_option(option: &str) -> Option<&'static str> {
    if !option.starts_with("--") {
        return None;
    }

    let known_options = ANSIBLE_FILE_OPTIONS
        .iter()
        .chain(ANSIBLE_AD_HOC_OUTPUT_OPTIONS.iter())
        .map(|known| known.name)
        .chain(ANSIBLE_OPERATOR_FIXED_OPTIONS.iter().copied())
        .chain(ANSIBLE_OPERATOR_FIXED_FLAGS.iter().copied())
        .chain(ANSIBLE_INTERACTIVE_FLAGS.iter().copied())
        .chain(ANSIBLE_REJECTED_SECONDARY_AUTHORITY_OPTIONS.iter().copied())
        .filter(|known| known.starts_with("--"));

    let candidates = known_options
        .filter(|known| *known == option || known.starts_with(option))
        .collect::<Vec<_>>();
    if let Some(exact) = candidates.iter().find(|candidate| **candidate == option) {
        return Some(*exact);
    }
    match candidates.as_slice() {
        [candidate] => Some(*candidate),
        _ => None,
    }
}

fn abbreviated_ansible_long_option(args: &[String]) -> Option<(&str, &'static str)> {
    args.iter().find_map(|argument| {
        let option = argument
            .split_once('=')
            .map_or(argument.as_str(), |pair| pair.0);
        let resolved = resolve_ansible_long_option(option)?;
        (resolved != option).then_some((option, resolved))
    })
}

/// Reject Ansible's unique-prefix long-option grammar at the runtime boundary.
/// Static catalog validation and delayed replay share this check so an option
/// cannot acquire weaker artifact extraction merely by using an abbreviation.
pub fn validate_runtime_option_authority(binary: &str, args: &[String]) -> Result<()> {
    let binary = executable_match_key(binary);
    let _ = primary_file_arguments(&binary, args)?;
    if matches!(binary.as_str(), "ansible" | "ansible-playbook") {
        if let Some((option, resolved)) = abbreviated_ansible_long_option(args) {
            bail!(
                "Ansible option '{}' abbreviates authority-bearing option '{}'; spell every long option in full",
                option,
                resolved
            );
        }
        if let Some(option) = args.iter().find_map(|argument| {
            let option = argument
                .split_once('=')
                .map_or(argument.as_str(), |pair| pair.0);
            let resolved = resolve_ansible_long_option(option).unwrap_or(option);
            ANSIBLE_INTERACTIVE_FLAGS
                .contains(&resolved)
                .then_some(option)
        }) {
            bail!(
                "Ansible interactive credential option '{}' is unavailable because Guard supplies no child stdin; use a daemon-managed secret binding",
                option
            );
        }
    }
    Ok(())
}

fn validate_systemctl_authority(args: &[String], allow_placeholders: bool) -> Result<()> {
    let Some((operation, units)) = args.split_first() else {
        bail!("systemctl delayed execution requires an explicit operation and unit")
    };
    if !matches!(
        operation.as_str(),
        "stop"
            | "disable"
            | "mask"
            | "reset-failed"
            | "is-active"
            | "is-enabled"
            | "show"
            | "status"
    ) {
        bail!(
            "systemctl delayed execution is limited to non-starting control and inspection operations"
        );
    }
    if units.is_empty() {
        bail!("systemctl delayed execution requires an explicit unit")
    }
    if let Some(unit) = units.iter().find(|unit| {
        let mut rendered = (*unit).clone();
        if allow_placeholders {
            for placeholder in placeholders(unit) {
                rendered = rendered.replace(&format!("{{{placeholder}}}"), "fixture");
            }
        }
        rendered.is_empty()
            || rendered.starts_with('-')
            || !rendered
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._@:-".contains(&byte))
    }) {
        bail!(
            "systemctl delayed execution rejects option, path, glob, and non-literal unit argument '{}'",
            unit
        );
    }
    Ok(())
}

fn validate_durable_systemctl_authority(args: &[String]) -> Result<()> {
    validate_systemctl_authority(args, false)
}

fn validate_catalog_delayed_authority(
    binary: &str,
    args: &[String],
    source: DelayedAuthoritySource,
) -> Result<()> {
    if executable_match_key(binary) != "systemctl" {
        return delayed_authority_plan(binary, args, source).map(|_| ());
    }

    validate_systemctl_authority(args, true)
}

fn normalized_delayed_command_digest(binary: &str, args: &[String]) -> String {
    let binary = executable_match_key(binary);
    let mut hasher = Sha256::new();
    hasher.update(b"guard-delayed-command-v1\0");
    hasher.update(binary.len().to_le_bytes());
    hasher.update(binary.as_bytes());
    hasher.update(args.len().to_le_bytes());
    for argument in args {
        hasher.update(argument.len().to_le_bytes());
        hasher.update(argument.as_bytes());
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Build the versioned positive authority plan for a command that may execute
/// after an approval or restart gap. Protected tools require typed operator
/// provenance in addition to their structured command grammar.
pub fn delayed_authority_plan(
    binary: &str,
    args: &[String],
    source: DelayedAuthoritySource,
) -> Result<DelayedAuthorityPlan> {
    validate_runtime_option_authority(binary, args)?;
    if matches!(
        source,
        DelayedAuthoritySource::RawApproval | DelayedAuthoritySource::RawControl
    ) && Path::new(binary).components().count() != 1
    {
        bail!("raw delayed execution requires a bare binary name selected from the daemon PATH");
    }
    let key = executable_match_key(binary);
    let profile = authorized_executable_profile(binary).ok_or_else(|| {
        anyhow::anyhow!(
            "binary '{}' has no closed executable authority profile",
            binary
        )
    })?;
    let typed = matches!(
        source,
        DelayedAuthoritySource::TypedVerb | DelayedAuthoritySource::TypedControl
    );
    let secondary_path_search = match profile {
        DelayedAuthorityProfile::TypedAnsible
        | DelayedAuthorityProfile::TypedKubectl
        | DelayedAuthorityProfile::TypedHelm
            if typed =>
        {
            true
        }
        DelayedAuthorityProfile::TypedAnsible
        | DelayedAuthorityProfile::TypedKubectl
        | DelayedAuthorityProfile::TypedHelm => bail!(
            "binary '{}' requires typed operator authority before delayed execution",
            binary
        ),
        DelayedAuthorityProfile::SystemdControl => {
            validate_durable_systemctl_authority(args)?;
            false
        }
        DelayedAuthorityProfile::PrimaryOnly if typed => false,
        DelayedAuthorityProfile::PrimaryOnly
            if matches!(key.as_str(), "true" | "false" | "echo" | "printf") =>
        {
            false
        }
        DelayedAuthorityProfile::PrimaryOnly
            if matches!(key.as_str(), "hostname" | "id" | "whoami") && args.is_empty() =>
        {
            false
        }
        DelayedAuthorityProfile::PrimaryOnly
            if key == "uptime"
                && args
                    .iter()
                    .all(|argument| matches!(argument.as_str(), "-p" | "--pretty")) =>
        {
            false
        }
        DelayedAuthorityProfile::PrimaryOnly
            if key == "printenv"
                && !args.is_empty()
                && args.iter().all(|argument| valid_environment_name(argument)) =>
        {
            false
        }
        DelayedAuthorityProfile::PrimaryOnly
            if key == "pwd"
                && args
                    .iter()
                    .all(|argument| matches!(argument.as_str(), "-L" | "-P")) =>
        {
            false
        }
        DelayedAuthorityProfile::PrimaryOnly => bail!(
            "binary '{}' requires typed operator authority before delayed execution",
            binary
        ),
    };
    Ok(DelayedAuthorityPlan {
        version: 1,
        source,
        profile,
        normalized_command_digest: normalized_delayed_command_digest(binary, args),
        secondary_path_search,
    })
}

/// Validate the raw-approval form of the delayed command grammar.
pub fn validate_durable_process_authority(binary: &str, args: &[String]) -> Result<()> {
    delayed_authority_plan(binary, args, DelayedAuthoritySource::RawApproval).map(|_| ())
}

fn ansible_selects_secondary_authority_option(args: &[String]) -> bool {
    args.iter().any(|argument| {
        let option = argument
            .split_once('=')
            .map_or(argument.as_str(), |pair| pair.0);
        resolve_ansible_long_option(option).is_some_and(|resolved| {
            ANSIBLE_REJECTED_SECONDARY_AUTHORITY_OPTIONS.contains(&resolved)
        })
    })
}

/// Parse every supported explicit Ansible inventory spelling into one semantic
/// source list. Matching and post-execution diagnostics share this parser so
/// an alias cannot receive weaker handling in one phase.
pub fn ansible_inventory_sources(args: &[String]) -> Option<Vec<String>> {
    let mut sources = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let argument = &args[index];
        let inventory = if matches!(argument.as_str(), "-i" | "--inventory" | "--inventory-file") {
            let value = args.get(index + 1)?.clone();
            index += 2;
            Some(value)
        } else if let Some(value) = argument
            .strip_prefix("-i")
            .filter(|value| !value.is_empty())
        {
            index += 1;
            Some(value.strip_prefix('=').unwrap_or(value).to_string())
        } else {
            let value = ["--inventory=", "--inventory-file="]
                .iter()
                .find_map(|prefix| argument.strip_prefix(prefix))
                .map(str::to_string);
            index += 1;
            value
        };
        if let Some(inventory) = inventory {
            if inventory.is_empty() {
                return None;
            }
            sources.push(inventory);
        }
    }
    Some(sources)
}

fn environment_is_authorized(
    binary: &str,
    cell: &VerbCoverageCell,
    plain: &BTreeMap<String, String>,
    secrets: &BTreeMap<String, String>,
    secret_files: &BTreeMap<String, String>,
) -> bool {
    [
        (EnvironmentBindingSource::Plain, plain),
        (EnvironmentBindingSource::Secret, secrets),
        (EnvironmentBindingSource::SecretFile, secret_files),
    ]
    .into_iter()
    .all(|(source, bindings)| {
        bindings.iter().all(|(name, value)| {
            cell.environment.iter().any(|constraint| {
                constraint.source == source
                    && constraint.name == *name
                    && environment_value_matches(constraint, value)
                    && environment_value_has_safe_tool_semantics(binary, source, name, value)
            })
        })
    })
}

fn environment_value_has_safe_tool_semantics(
    binary: &str,
    source: EnvironmentBindingSource,
    name: &str,
    value: &str,
) -> bool {
    match tool_environment_authority(binary, name) {
        None => !tool_has_closed_environment_authority(binary),
        Some(ToolEnvironmentAuthority::Forbidden) => false,
        Some(ToolEnvironmentAuthority::FixedScalar) => {
            source == EnvironmentBindingSource::Plain
                && tool_environment_scalar_is_safe(binary, name, value)
        }
        Some(ToolEnvironmentAuthority::SecretScalar) => source == EnvironmentBindingSource::Secret,
        Some(ToolEnvironmentAuthority::File(file)) => match source {
            EnvironmentBindingSource::Plain => file.kind.accepts(value),
            EnvironmentBindingSource::SecretFile => file.accepts_secret_file,
            EnvironmentBindingSource::Secret => false,
        },
    }
}

/// Enforce the closed environment-authority schema for every execution route,
/// including evaluator approvals and exact replay without a typed verb.
pub fn validate_runtime_tool_environment_binding(
    binary: &str,
    source: EnvironmentBindingSource,
    name: &str,
    value: &str,
    typed_environment_authority: bool,
) -> Result<()> {
    if !tool_has_closed_environment_authority(binary) {
        return Ok(());
    }
    if matches!(
        tool_environment_authority(binary, name),
        Some(ToolEnvironmentAuthority::FixedScalar)
    ) && !typed_environment_authority
    {
        bail!(
            "tool environment '{}' requires an exact typed verb environment constraint",
            name
        )
    }
    if environment_value_has_safe_tool_semantics(binary, source, name, value) {
        return Ok(());
    }
    bail!(
        "tool environment '{}' introduces unclassified executable, credential, configuration, or filesystem authority",
        name
    )
}

fn tool_has_closed_environment_authority(binary: &str) -> bool {
    authorized_executable_profile(binary)
        .is_some_and(DelayedAuthorityProfile::discovers_profile_authority)
}

#[derive(Clone, Copy)]
struct ToolEnvironmentFile {
    kind: KnownFileArgument,
    accepts_secret_file: bool,
}

#[derive(Clone, Copy)]
enum ToolEnvironmentAuthority {
    File(ToolEnvironmentFile),
    FixedScalar,
    SecretScalar,
    Forbidden,
}

const fn plain_environment_file(kind: KnownFileArgument) -> ToolEnvironmentAuthority {
    ToolEnvironmentAuthority::File(ToolEnvironmentFile {
        kind,
        accepts_secret_file: false,
    })
}

const fn secret_environment_file(kind: KnownFileArgument) -> ToolEnvironmentAuthority {
    ToolEnvironmentAuthority::File(ToolEnvironmentFile {
        kind,
        accepts_secret_file: true,
    })
}

fn tool_environment_authority(binary: &str, name: &str) -> Option<ToolEnvironmentAuthority> {
    let binary = executable_match_key(binary);
    let canonical = name.to_ascii_uppercase();
    match binary.as_str() {
        "ansible" | "ansible-playbook" => match canonical.as_str() {
            "ANSIBLE_PRIVATE_KEY_FILE"
            | "ANSIBLE_VAULT_PASSWORD_FILE"
            | "ANSIBLE_BECOME_PASSWORD_FILE"
            | "ANSIBLE_CONNECTION_PASSWORD_FILE" => Some(secret_environment_file(
                KnownFileArgument::FixedAbsolutePath,
            )),
            "ANSIBLE_CONFIG"
            | "ANSIBLE_HOME"
            | "ANSIBLE_LOCAL_TEMP"
            | "ANSIBLE_EXECUTABLE"
            | "ANSIBLE_BECOME_EXE"
            | "ANSIBLE_SSH_EXECUTABLE"
            | "ANSIBLE_SSH_AGENT_EXECUTABLE" => {
                Some(plain_environment_file(KnownFileArgument::FixedAbsolutePath))
            }
            "ANSIBLE_INVENTORY" => {
                Some(plain_environment_file(KnownFileArgument::AnsibleInventory))
            }
            "ANSIBLE_VAULT_IDENTITY_LIST" => Some(plain_environment_file(
                KnownFileArgument::AnsibleVaultIdentityList,
            )),
            "ANSIBLE_COLLECTIONS_PATH"
            | "ANSIBLE_COLLECTIONS_PATHS"
            | "ANSIBLE_LIBRARY"
            | "ANSIBLE_MODULE_UTILS"
            | "ANSIBLE_ROLES_PATH"
            | "ANSIBLE_CONNECTION_PATH" => Some(plain_environment_file(
                KnownFileArgument::FixedAbsolutePathList,
            )),
            value if value.starts_with("ANSIBLE_") && value.ends_with("_PLUGINS") => Some(
                plain_environment_file(KnownFileArgument::FixedAbsolutePathList),
            ),
            "ANSIBLE_TRANSPORT"
            | "ANSIBLE_STRATEGY"
            | "ANSIBLE_STDOUT_CALLBACK"
            | "ANSIBLE_CALLBACKS_ENABLED"
            | "ANSIBLE_CACHE_PLUGIN"
            | "ANSIBLE_INVENTORY_ENABLED"
            | "ANSIBLE_VARS_ENABLED"
            | "ANSIBLE_BECOME_METHOD" => Some(ToolEnvironmentAuthority::FixedScalar),
            "ANSIBLE_LOG_PATH" | "ANSIBLE_SSH_ARGS" | "ANSIBLE_SSH_COMMON_ARGS" => {
                Some(ToolEnvironmentAuthority::Forbidden)
            }
            value if value.starts_with("ANSIBLE_") => Some(ToolEnvironmentAuthority::Forbidden),
            _ => None,
        },
        "kubectl" => match canonical.as_str() {
            "KUBECONFIG" => Some(plain_environment_file(
                KnownFileArgument::FixedAbsolutePathList,
            )),
            "KUBERC" => Some(plain_environment_file(KnownFileArgument::FixedAbsolutePath)),
            "KUBECTL_KUBERC"
            | "KUBECTL_ENABLE_CMD_SHADOW"
            | "KUBECTL_EXPLAIN_OPENAPIV3"
            | "KUBECTL_REMOTE_COMMAND_WEBSOCKETS"
            | "KUBECTL_PORT_FORWARD_WEBSOCKETS" => Some(ToolEnvironmentAuthority::FixedScalar),
            "KUBECTL_EXTERNAL_DIFF" => Some(ToolEnvironmentAuthority::Forbidden),
            value if value.starts_with("KUBECTL_") => Some(ToolEnvironmentAuthority::Forbidden),
            _ => None,
        },
        "helm" => match canonical.as_str() {
            "KUBECONFIG" => Some(plain_environment_file(
                KnownFileArgument::FixedAbsolutePathList,
            )),
            "HELM_REGISTRY_CONFIG"
            | "HELM_REPOSITORY_CONFIG"
            | "HELM_REPOSITORY_CACHE"
            | "HELM_CONFIG_HOME"
            | "HELM_DATA_HOME"
            | "HELM_CACHE_HOME"
            | "HELM_KUBECAFILE" => {
                Some(plain_environment_file(KnownFileArgument::FixedAbsolutePath))
            }
            "HELM_KUBETOKEN" | "HELM_DRIVER_SQL_CONNECTION_STRING" => {
                Some(ToolEnvironmentAuthority::SecretScalar)
            }
            "HELM_NO_PLUGINS" | "HELM_DEBUG" | "HELM_COLOR" | "HELM_MAX_HISTORY" | "HELM_QPS"
            | "HELM_BURST_LIMIT" | "HELM_DRIVER" => Some(ToolEnvironmentAuthority::FixedScalar),
            "HELM_PLUGINS" => Some(ToolEnvironmentAuthority::Forbidden),
            value if value.starts_with("HELM_") => Some(ToolEnvironmentAuthority::Forbidden),
            _ => None,
        },
        _ => None,
    }
}

fn tool_environment_scalar_is_safe(binary: &str, name: &str, value: &str) -> bool {
    let binary = executable_match_key(binary);
    let name = name.to_ascii_uppercase();
    match (binary.as_str(), name.as_str()) {
        ("kubectl", "KUBECTL_KUBERC" | "KUBECTL_ENABLE_CMD_SHADOW") => {
            matches!(value.to_ascii_lowercase().as_str(), "0" | "false" | "off")
        }
        ("helm", "HELM_NO_PLUGINS") => {
            matches!(value.to_ascii_lowercase().as_str(), "1" | "true")
        }
        _ => !value.is_empty(),
    }
}

fn validate_tool_environment_constraint(
    verb: &Verb,
    cell: &VerbCoverageCell,
    constraint: &EnvironmentConstraint,
) -> Result<()> {
    let Some(authority) = tool_environment_authority(&verb.binary, &constraint.name) else {
        if tool_has_closed_environment_authority(&verb.binary) {
            bail!(
                "verb '{}' coverage cell '{}': tool environment '{}' is not in the closed authority schema and cannot be preauthorized",
                verb.name,
                cell.name,
                constraint.name
            );
        }
        return Ok(());
    };
    match authority {
        ToolEnvironmentAuthority::Forbidden => {
            bail!(
                "verb '{}' coverage cell '{}': tool environment '{}' can introduce implicit executable, configuration, or filesystem authority and cannot be preauthorized",
                verb.name,
                cell.name,
                constraint.name
            );
        }
        ToolEnvironmentAuthority::FixedScalar => {
            if constraint.source != EnvironmentBindingSource::Plain
                || constraint.values.is_empty()
                || constraint.pattern.is_some()
                || constraint.values.iter().any(|value| {
                    !tool_environment_scalar_is_safe(&verb.binary, &constraint.name, value)
                })
            {
                bail!(
                    "verb '{}' coverage cell '{}': tool environment '{}' must enumerate safe operator-fixed literal values",
                    verb.name,
                    cell.name,
                    constraint.name
                );
            }
        }
        ToolEnvironmentAuthority::SecretScalar => {
            if constraint.source != EnvironmentBindingSource::Secret
                || constraint.values.is_empty()
                || constraint.pattern.is_some()
            {
                bail!(
                    "verb '{}' coverage cell '{}': credential environment '{}' requires exact daemon secret references",
                    verb.name,
                    cell.name,
                    constraint.name
                );
            }
        }
        ToolEnvironmentAuthority::File(file) => match constraint.source {
            EnvironmentBindingSource::Plain => {
                if constraint.values.is_empty()
                    || constraint.pattern.is_some()
                    || constraint
                        .values
                        .iter()
                        .any(|value| !file.kind.accepts(value))
                {
                    bail!(
                    "verb '{}' coverage cell '{}': tool file environment '{}' must enumerate operator-fixed {} values",
                    verb.name,
                    cell.name,
                    constraint.name,
                    file.kind.requirement()
                );
                }
            }
            EnvironmentBindingSource::SecretFile
                if file.accepts_secret_file
                    && !constraint.values.is_empty()
                    && constraint.pattern.is_none() => {}
            EnvironmentBindingSource::SecretFile | EnvironmentBindingSource::Secret => {
                bail!(
                    "verb '{}' coverage cell '{}': tool file environment '{}' requires a plain fixed path or daemon-created secret file",
                    verb.name,
                    cell.name,
                    constraint.name
                );
            }
        },
    }
    Ok(())
}

fn environment_value_matches(constraint: &EnvironmentConstraint, value: &str) -> bool {
    if !constraint.values.is_empty() && !constraint.values.iter().any(|allowed| allowed == value) {
        return false;
    }
    constraint
        .pattern
        .as_deref()
        .is_none_or(|pattern| compile_anchored(pattern).is_ok_and(|regex| regex.is_match(value)))
}

fn matched_values(constraint: &ValueConstraint, args: &[String]) -> Option<Vec<String>> {
    let mut found = Vec::new();
    if let Some(position) = constraint.position {
        if let Some(value) = args.get(position) {
            found.push(value.clone());
        }
    } else {
        for (index, _arg) in args.iter().enumerate() {
            for option in &constraint.options {
                if let Some(value) = operator_option_value_at(args, index, option) {
                    found.push(value?.to_string());
                }
            }
        }
    }

    if found.is_empty() {
        return (!constraint.required).then_some(found);
    }
    if found.iter().any(String::is_empty)
        || (!constraint.allow_dash && found.iter().any(|value| value.starts_with('-')))
    {
        return None;
    }
    if found.len() > 1 && !constraint.allow_multiple {
        return None;
    }
    if !constraint.values.is_empty() && found.iter().any(|value| !constraint.values.contains(value))
    {
        return None;
    }
    Some(found)
}

fn add_constraint_features(
    features: &mut BTreeSet<String>,
    specificity: &mut CoverageSpecificity,
    kind: &str,
    constraint: &ValueConstraint,
) {
    let selector = constraint_selector(constraint);
    let key = format!("{kind}:{selector}");
    features.insert(key.clone());
    specificity.values.insert(
        key.clone(),
        ValueDomain {
            required: constraint.required,
            allow_multiple: constraint.allow_multiple,
            allow_dash: constraint.allow_dash,
            values: constraint.values.iter().cloned().collect(),
        },
    );
}

/// A generated access matcher can execute immediately only when its exact
/// command shape proves a read operation. Everything else is held as
/// irreversible. The model's consequence and rollback fields are never part
/// of this decision.
fn synthesized_access_is_statically_read_only(verb: &Verb) -> bool {
    if !verb.coverage.is_empty() {
        return false;
    }

    let binary = executable_match_key(&verb.binary);
    if matches!(
        binary.as_str(),
        "false" | "id" | "pwd" | "true" | "uname" | "uptime" | "whoami"
    ) {
        return verb
            .args
            .iter()
            .all(|argument| !argument.contains(['{', '}']));
    }
    if binary == "hostname" {
        return verb.args.is_empty();
    }
    if matches!(binary.as_str(), "cargo" | "rustc") {
        return verb.args == ["--version"];
    }

    let literal_tokens = verb
        .args
        .iter()
        .filter(|argument| !argument.contains(['{', '}']))
        .map(|argument| argument.to_ascii_lowercase())
        .collect::<Vec<_>>();
    if literal_tokens.iter().any(|argument| {
        matches!(
            argument.as_str(),
            "annotate"
                | "apply"
                | "attach"
                | "cordon"
                | "create"
                | "delete"
                | "disable"
                | "drain"
                | "edit"
                | "enable"
                | "exec"
                | "expose"
                | "install"
                | "label"
                | "patch"
                | "remove"
                | "replace"
                | "restart"
                | "rollout"
                | "run"
                | "scale"
                | "set"
                | "start"
                | "stop"
                | "taint"
                | "uninstall"
                | "update"
                | "upgrade"
        )
    }) {
        return false;
    }

    let Some(operation) = verb
        .args
        .iter()
        .find(|argument| !argument.starts_with('-'))
        .filter(|argument| !argument.contains(['{', '}']))
        .map(|operation| operation.to_ascii_lowercase())
    else {
        return false;
    };

    match binary.as_str() {
        "kubectl" => match operation.as_str() {
            "cluster-info" => !verb.args.iter().any(|argument| argument == "dump"),
            "api-resources" | "api-versions" | "describe" | "explain" | "get" | "logs"
            | "version" => true,
            _ => false,
        },
        "systemctl" => matches!(
            operation.as_str(),
            "is-active"
                | "is-enabled"
                | "is-failed"
                | "list-dependencies"
                | "list-unit-files"
                | "list-units"
                | "show"
                | "status"
        ),
        "helm" => {
            matches!(
                operation.as_str(),
                "env" | "get" | "history" | "list" | "search" | "show" | "status" | "version"
            )
        }
        _ => false,
    }
}

/// Derive the fail-closed consequence permitted for generated access coverage
/// before any exact operator coverage refinement is considered.
///
/// This function intentionally reads only executable matcher authority. It is
/// shared by pending reductions, durable proposal parsing, approval
/// projection, and installation, so provenance and model-supplied metadata
/// cannot make the same matcher converge to different gate behavior.
pub fn canonical_generated_access_consequence(verb: &Verb) -> Reversibility {
    if synthesized_access_is_statically_read_only(verb) {
        Reversibility::Reversible
    } else {
        Reversibility::Irreversible
    }
}

/// Derive the only consequence an automatically promoted command may carry.
/// Auto-promoted verbs also contain coverage metadata for display, but that
/// metadata is not executable matcher authority and must not make a command
/// appear safer than its binary and argv shape prove.
pub fn canonical_auto_promoted_consequence(verb: &Verb) -> Reversibility {
    let mut matcher = verb.clone();
    matcher.coverage.clear();
    canonical_generated_access_consequence(&matcher)
}

/// Every concrete argv a generated matcher's template admits, or `None` when
/// a referenced parameter pattern is not a plain literal enumeration or the
/// combination space exceeds the bound.
fn enumerate_matcher_commands(candidate: &Verb) -> Option<Vec<Vec<String>>> {
    let referenced: BTreeSet<String> = candidate
        .args
        .iter()
        .flat_map(|token| placeholders(token))
        .collect();
    enumerate_parameter_sets(candidate, referenced)?
        .iter()
        .map(|params| render_args(&candidate.args, params, &candidate.name).ok())
        .collect()
}

fn enumerate_parameter_sets(
    candidate: &Verb,
    referenced: BTreeSet<String>,
) -> Option<Vec<BTreeMap<String, String>>> {
    const MAX_COMMANDS: usize = 64;
    let mut combinations: Vec<BTreeMap<String, String>> = vec![BTreeMap::new()];
    for name in &referenced {
        let spec = candidate.params.get(name)?;
        let values = enumerate_pattern_literals(spec.pattern_text())?;
        if combinations.len().checked_mul(values.len())? > MAX_COMMANDS {
            return None;
        }
        combinations = combinations
            .iter()
            .flat_map(|combination| {
                values.iter().map(move |value| {
                    let mut expanded = combination.clone();
                    expanded.insert(name.clone(), value.clone());
                    expanded
                })
            })
            .collect();
    }
    Some(combinations)
}

/// The literal branches of an anchored alternation such as `^(status|df)$`,
/// or `None` when any branch uses regex syntax beyond a plain literal.
fn enumerate_pattern_literals(pattern: &str) -> Option<Vec<String>> {
    let mut inner = pattern.strip_prefix('^').unwrap_or(pattern);
    inner = inner.strip_suffix('$').unwrap_or(inner);
    if let Some(stripped) = inner
        .strip_prefix("(?:")
        .or_else(|| inner.strip_prefix('('))
        .and_then(|stripped| stripped.strip_suffix(')'))
    {
        inner = stripped;
    }
    let mut branches = vec![String::new()];
    let mut escaped = false;
    for character in inner.chars() {
        if escaped {
            branches.last_mut()?.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if character == '|' {
            branches.push(String::new());
            continue;
        }
        if r"^$.?*+()[]{}".contains(character) {
            return None;
        }
        branches.last_mut()?.push(character);
    }
    (!escaped && branches.iter().all(|branch| !branch.is_empty())).then_some(branches)
}

fn constraint_selector(constraint: &ValueConstraint) -> String {
    constraint
        .position
        .map(|position| format!("position:{position}"))
        .unwrap_or_else(|| {
            let mut options = constraint.options.clone();
            options.sort();
            format!("options:{}", options.join("|"))
        })
}

/// Reject executables without a closed process-authority profile. Shared by
/// both synthesis paths below.
fn validate_binary_not_shell(binary: &str, context: &str) -> Result<()> {
    if authorized_executable_profile(binary).is_none() {
        bail!(
            "{context} binary '{}' has no closed executable authority profile",
            binary
        );
    }
    Ok(())
}

/// Reject a parameter pattern broad enough to admit whitespace or shell
/// metacharacters (see `OVERBROAD_CANARIES`). Shared by both synthesis paths.
fn validate_param_not_overbroad(pname: &str, spec: &ParamSpec, context: &str) -> Result<()> {
    let re = compile_anchored(spec.pattern_text())
        .with_context(|| format!("param '{}' pattern", pname))?;
    let canaries = match spec.value_type() {
        ParamValueType::Token => OVERBROAD_CANARIES,
        ParamValueType::SingleArgv => SINGLE_ARGV_DANGEROUS_CANARIES,
    };
    if let Some(canary) = canaries.iter().find(|canary| re.is_match(canary)) {
        bail!(
            "{context} parameter '{}' pattern {:?} is too permissive (it matches {:?}); a verb \
             parameter must be narrowly pinned and must not admit shell control characters{}",
            pname,
            spec.pattern_text(),
            canary,
            if spec.value_type() == ParamValueType::Token {
                " or whitespace"
            } else {
                ""
            }
        );
    }
    Ok(())
}

/// Verify the generated representation of an exact finite parameter domain.
/// Whitespace-bearing values stay one bounded argv element; all other values
/// retain token semantics. Both forms reject control characters that could
/// become shell syntax if a downstream tool ever reparsed the value.
fn validate_auto_promoted_param_spec(pname: &str, spec: &ParamSpec) -> Result<Vec<String>> {
    validate_param_not_overbroad(pname, spec, "auto-promoted verb")?;
    let literals = enumerate_pattern_literals(spec.pattern_text()).ok_or_else(|| {
        anyhow::anyhow!(
            "auto-promoted verb parameter '{}' must be a finite plain literal alternation",
            pname
        )
    })?;
    let contains_whitespace = literals
        .iter()
        .any(|value| value.chars().any(char::is_whitespace));
    let expected_value_type = if contains_whitespace {
        ParamValueType::SingleArgv
    } else {
        ParamValueType::Token
    };
    if spec.value_type() != expected_value_type {
        bail!(
            "auto-promoted verb parameter '{}' must use {} semantics for its exact observed values",
            pname,
            match expected_value_type {
                ParamValueType::Token => "token",
                ParamValueType::SingleArgv => "single_argv",
            }
        );
    }
    if expected_value_type == ParamValueType::SingleArgv {
        let maximum = literals
            .iter()
            .map(|value| value.chars().count())
            .max()
            .expect("literal enumeration is non-empty");
        if spec.max_length() != Some(maximum) {
            bail!(
                "auto-promoted verb parameter '{}' max_length must equal the longest exact observed value ({})",
                pname,
                maximum
            );
        }
    }
    for value in &literals {
        if value.chars().any(|character| {
            character.is_control() || matches!(character, ';' | '|' | '&' | '$' | '`' | '>' | '<')
        }) {
            bail!(
                "auto-promoted verb parameter '{}' contains a shell control character in an exact observed value",
                pname
            );
        }
    }
    Ok(literals)
}

fn path_is_absolute(value: &str) -> bool {
    let path = Path::new(value);
    path.is_absolute()
        && path.components().all(|component| {
            !matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
}

#[derive(Clone, Copy)]
enum KnownFileArgument {
    AbsolutePath,
    AbsolutePathOrStdin,
    // These classes bind caller authority to an operator-authored path. File
    // integrity remains inside the daemon host's operator-controlled
    // filesystem trust boundary, the same boundary used for primary binaries.
    FixedAbsolutePath,
    FixedAbsolutePathOrStdin,
    FixedAbsolutePathList,
    OperatorSelectedAbsolutePath,
    KubectlFilename,
    KeyEqualsPath,
    HelmSetFile,
    AnsibleInventory,
    AnsibleExtraVars,
    AnsibleVaultId,
    AnsibleVaultIdentityList,
}

impl KnownFileArgument {
    fn accepts(self, value: &str) -> bool {
        match self {
            Self::AbsolutePath => path_is_absolute(value),
            Self::AbsolutePathOrStdin => value == "-" || path_is_absolute(value),
            Self::FixedAbsolutePath => path_is_absolute(value),
            Self::FixedAbsolutePathOrStdin => value == "-" || path_is_absolute(value),
            Self::FixedAbsolutePathList => absolute_path_list(value),
            Self::OperatorSelectedAbsolutePath => path_is_absolute(value),
            Self::KubectlFilename => {
                !value.contains(',') && (value == "-" || path_is_absolute(value))
            }
            Self::KeyEqualsPath => key_equals_path_payload(value).is_some_and(path_is_absolute),
            Self::HelmSetFile => helm_set_file_payload(value).is_some_and(path_is_absolute),
            Self::AnsibleInventory => path_is_absolute(value) || value.ends_with(','),
            Self::AnsibleExtraVars => value.strip_prefix('@').is_none_or(path_is_absolute),
            Self::AnsibleVaultId => {
                let source = value.rsplit_once('@').map_or(value, |(_, source)| source);
                source == "prompt" || path_is_absolute(source)
            }
            Self::AnsibleVaultIdentityList => {
                !value.is_empty()
                    && value.split(',').all(|entry| {
                        !entry.is_empty() && KnownFileArgument::AnsibleVaultId.accepts(entry)
                    })
            }
        }
    }

    fn requirement(self) -> &'static str {
        match self {
            Self::AbsolutePath => "an absolute path",
            Self::AbsolutePathOrStdin => "an absolute path or '-' for standard input",
            Self::FixedAbsolutePath => "one operator-fixed absolute path",
            Self::FixedAbsolutePathOrStdin => {
                "one operator-fixed absolute path or '-' for standard input"
            }
            Self::FixedAbsolutePathList => "one operator-fixed list of absolute paths",
            Self::OperatorSelectedAbsolutePath => {
                "one operator-selected absolute path from a finite parameter set"
            }
            Self::KubectlFilename => {
                "one absolute path or '-' for standard input; repeat the option for multiple sources"
            }
            Self::KeyEqualsPath => "an absolute path, optionally prefixed with key=",
            Self::HelmSetFile => "one key=absolute-path pair; repeat the option for multiple files",
            Self::AnsibleInventory => "an absolute path or comma-terminated inline host list",
            Self::AnsibleExtraVars => "an inline value or an @-prefixed absolute path",
            Self::AnsibleVaultId => "a prompt source or an absolute vault client path",
            Self::AnsibleVaultIdentityList => {
                "a comma-separated list of prompt sources or absolute vault client paths"
            }
        }
    }

    /// Extract the local-path payload from the documented argument grammar.
    /// `None` means the form is an allowed non-file value, such as an inline
    /// Ansible variable assignment or a vault prompt.
    fn path_payload_template(self, value: &str) -> Option<&str> {
        match self {
            Self::KeyEqualsPath => key_equals_path_payload(value),
            Self::HelmSetFile => helm_set_file_payload(value),
            Self::AnsibleExtraVars => value.strip_prefix('@'),
            Self::AnsibleVaultId => {
                let source = value.rsplit_once('@').map_or(value, |(_, source)| source);
                (!source.is_empty() && source != "prompt").then_some(source)
            }
            Self::AnsibleVaultIdentityList => None,
            _ => Some(value),
        }
    }

    fn accepts_parameter_value(self, value: &str) -> bool {
        match self {
            Self::KeyEqualsPath | Self::HelmSetFile | Self::AnsibleExtraVars => {
                path_is_absolute(value)
            }
            Self::FixedAbsolutePath
            | Self::FixedAbsolutePathOrStdin
            | Self::FixedAbsolutePathList => false,
            Self::AnsibleInventory => self.accepts(value) && !path_is_absolute(value),
            Self::AnsibleVaultId => {
                let source = value.rsplit_once('@').map_or(value, |(_, source)| source);
                source == "prompt"
            }
            Self::AnsibleVaultIdentityList => false,
            _ => self.accepts(value),
        }
    }

    fn requires_operator_fixed_source(self, value: &str) -> bool {
        match self {
            Self::FixedAbsolutePath
            | Self::FixedAbsolutePathOrStdin
            | Self::FixedAbsolutePathList => true,
            Self::AnsibleInventory => path_is_absolute(value),
            Self::AnsibleExtraVars => true,
            Self::AnsibleVaultId => {
                let source = value.rsplit_once('@').map_or(value, |(_, source)| source);
                source != "prompt"
            }
            Self::AnsibleVaultIdentityList => true,
            _ => false,
        }
    }
}

const ABSOLUTE_FILE_ARGUMENT: KnownFileArgument = KnownFileArgument::AbsolutePath;
const PATH_OR_STDIN_FILE_ARGUMENT: KnownFileArgument = KnownFileArgument::AbsolutePathOrStdin;
const FIXED_ABSOLUTE_FILE_ARGUMENT: KnownFileArgument = KnownFileArgument::FixedAbsolutePath;
const FIXED_ABSOLUTE_OR_STDIN_FILE_ARGUMENT: KnownFileArgument =
    KnownFileArgument::FixedAbsolutePathOrStdin;
const FIXED_ABSOLUTE_LIST_FILE_ARGUMENT: KnownFileArgument =
    KnownFileArgument::FixedAbsolutePathList;
const OPERATOR_SELECTED_ABSOLUTE_FILE_ARGUMENT: KnownFileArgument =
    KnownFileArgument::OperatorSelectedAbsolutePath;
const KUBECTL_FILE_ARGUMENT: KnownFileArgument = KnownFileArgument::KubectlFilename;
const KEY_PATH_FILE_ARGUMENT: KnownFileArgument = KnownFileArgument::KeyEqualsPath;
const HELM_SET_FILE_ARGUMENT: KnownFileArgument = KnownFileArgument::HelmSetFile;
const ANSIBLE_INVENTORY_FILE_ARGUMENT: KnownFileArgument = KnownFileArgument::AnsibleInventory;
const ANSIBLE_EXTRA_VARS_FILE_ARGUMENT: KnownFileArgument = KnownFileArgument::AnsibleExtraVars;
const ANSIBLE_VAULT_ID_FILE_ARGUMENT: KnownFileArgument = KnownFileArgument::AnsibleVaultId;

#[derive(Clone, Copy, PartialEq, Eq)]
enum FileAuthorityRole {
    CallerData,
    OperatorInput,
    OutputDestination,
}

#[derive(Clone, Copy)]
struct KnownFileOption {
    name: &'static str,
    kind: KnownFileArgument,
    authority_role: FileAuthorityRole,
}

const fn caller_file_option(name: &'static str, kind: KnownFileArgument) -> KnownFileOption {
    KnownFileOption {
        name,
        kind,
        authority_role: FileAuthorityRole::CallerData,
    }
}

const fn operator_file_option(name: &'static str, kind: KnownFileArgument) -> KnownFileOption {
    KnownFileOption {
        name,
        kind,
        authority_role: FileAuthorityRole::OperatorInput,
    }
}

const fn output_file_option(name: &'static str, kind: KnownFileArgument) -> KnownFileOption {
    KnownFileOption {
        name,
        kind,
        authority_role: FileAuthorityRole::OutputDestination,
    }
}

const ANSIBLE_FILE_OPTIONS: &[KnownFileOption] = &[
    operator_file_option("-i", ANSIBLE_INVENTORY_FILE_ARGUMENT),
    operator_file_option("--inventory", ANSIBLE_INVENTORY_FILE_ARGUMENT),
    operator_file_option("--inventory-file", ANSIBLE_INVENTORY_FILE_ARGUMENT),
    operator_file_option("-e", ANSIBLE_EXTRA_VARS_FILE_ARGUMENT),
    operator_file_option("--extra-vars", ANSIBLE_EXTRA_VARS_FILE_ARGUMENT),
    operator_file_option("-M", FIXED_ABSOLUTE_LIST_FILE_ARGUMENT),
    operator_file_option("--module-path", FIXED_ABSOLUTE_LIST_FILE_ARGUMENT),
    operator_file_option("--playbook-dir", FIXED_ABSOLUTE_FILE_ARGUMENT),
    operator_file_option("--vault-id", ANSIBLE_VAULT_ID_FILE_ARGUMENT),
    operator_file_option("--private-key", FIXED_ABSOLUTE_FILE_ARGUMENT),
    operator_file_option("--key-file", FIXED_ABSOLUTE_FILE_ARGUMENT),
    operator_file_option("--become-password-file", FIXED_ABSOLUTE_FILE_ARGUMENT),
    operator_file_option("--become-pass-file", FIXED_ABSOLUTE_FILE_ARGUMENT),
    operator_file_option("--connection-password-file", FIXED_ABSOLUTE_FILE_ARGUMENT),
    operator_file_option("--conn-pass-file", FIXED_ABSOLUTE_FILE_ARGUMENT),
    operator_file_option("--vault-password-file", FIXED_ABSOLUTE_FILE_ARGUMENT),
    operator_file_option("--vault-pass-file", FIXED_ABSOLUTE_FILE_ARGUMENT),
];

const ANSIBLE_AD_HOC_OUTPUT_OPTIONS: &[KnownFileOption] = &[
    output_file_option("-t", ABSOLUTE_FILE_ARGUMENT),
    output_file_option("--tree", ABSOLUTE_FILE_ARGUMENT),
];

const KUBECTL_FILE_OPTIONS: &[KnownFileOption] = &[
    caller_file_option("-f", KUBECTL_FILE_ARGUMENT),
    caller_file_option("--filename", KUBECTL_FILE_ARGUMENT),
    caller_file_option("-k", ABSOLUTE_FILE_ARGUMENT),
    caller_file_option("--kustomize", ABSOLUTE_FILE_ARGUMENT),
    operator_file_option("--kubeconfig", OPERATOR_SELECTED_ABSOLUTE_FILE_ARGUMENT),
    operator_file_option("--kuberc", FIXED_ABSOLUTE_FILE_ARGUMENT),
    operator_file_option("--cache-dir", FIXED_ABSOLUTE_FILE_ARGUMENT),
    output_file_option("--profile-output", ABSOLUTE_FILE_ARGUMENT),
    output_file_option("--output-directory", PATH_OR_STDIN_FILE_ARGUMENT),
    operator_file_option("--www", FIXED_ABSOLUTE_FILE_ARGUMENT),
    output_file_option("--unix-socket", ABSOLUTE_FILE_ARGUMENT),
    operator_file_option("--helm-command", FIXED_ABSOLUTE_FILE_ARGUMENT),
    caller_file_option("--from-file", KEY_PATH_FILE_ARGUMENT),
    caller_file_option("--from-env-file", ABSOLUTE_FILE_ARGUMENT),
    caller_file_option("--cert", ABSOLUTE_FILE_ARGUMENT),
    caller_file_option("--key", ABSOLUTE_FILE_ARGUMENT),
    caller_file_option("--patch-file", ABSOLUTE_FILE_ARGUMENT),
    operator_file_option("--certificate-authority", FIXED_ABSOLUTE_FILE_ARGUMENT),
    operator_file_option("--client-certificate", FIXED_ABSOLUTE_FILE_ARGUMENT),
    operator_file_option("--client-key", FIXED_ABSOLUTE_FILE_ARGUMENT),
];

const HELM_FILE_OPTIONS: &[KnownFileOption] = &[
    caller_file_option("-f", ABSOLUTE_FILE_ARGUMENT),
    caller_file_option("--values", ABSOLUTE_FILE_ARGUMENT),
    operator_file_option("--kubeconfig", OPERATOR_SELECTED_ABSOLUTE_FILE_ARGUMENT),
    operator_file_option("--repository-config", FIXED_ABSOLUTE_FILE_ARGUMENT),
    operator_file_option("--registry-config", FIXED_ABSOLUTE_FILE_ARGUMENT),
    operator_file_option("--repository-cache", FIXED_ABSOLUTE_FILE_ARGUMENT),
    operator_file_option("--content-cache", FIXED_ABSOLUTE_FILE_ARGUMENT),
    operator_file_option("--kube-ca-file", FIXED_ABSOLUTE_FILE_ARGUMENT),
    operator_file_option("--ca-file", FIXED_ABSOLUTE_FILE_ARGUMENT),
    operator_file_option("--cert-file", FIXED_ABSOLUTE_FILE_ARGUMENT),
    operator_file_option("--key-file", FIXED_ABSOLUTE_FILE_ARGUMENT),
    operator_file_option("--keyring", FIXED_ABSOLUTE_FILE_ARGUMENT),
    caller_file_option("--set-file", HELM_SET_FILE_ARGUMENT),
    operator_file_option("--post-renderer", FIXED_ABSOLUTE_FILE_ARGUMENT),
    output_file_option("--output-dir", ABSOLUTE_FILE_ARGUMENT),
    output_file_option("-d", ABSOLUTE_FILE_ARGUMENT),
    output_file_option("--destination", ABSOLUTE_FILE_ARGUMENT),
    output_file_option("--untardir", ABSOLUTE_FILE_ARGUMENT),
    caller_file_option("--merge", ABSOLUTE_FILE_ARGUMENT),
    operator_file_option("--passphrase-file", FIXED_ABSOLUTE_OR_STDIN_FILE_ARGUMENT),
];

#[derive(Clone, Copy)]
struct PrimaryFileArgument<'a> {
    argument_index: usize,
    value: &'a str,
    source_value_offset: usize,
    kind: KnownFileArgument,
    authority_role: FileAuthorityRole,
}

impl PrimaryFileArgument<'_> {
    fn source_template<'a>(&self, template_args: &'a [String]) -> Option<&'a str> {
        template_args
            .get(self.argument_index)?
            .get(self.source_value_offset..)
    }
}

struct ParsedPrimaryFileCommand<'a> {
    files: Vec<PrimaryFileArgument<'a>>,
    implicit_working_directory: bool,
}

#[derive(Clone, Copy)]
enum PrimaryPositionals {
    Scalar {
        maximum: usize,
    },
    Files {
        kind: KnownFileArgument,
        authority_role: FileAuthorityRole,
        dash_is_stream: bool,
        implicit_working_directory: bool,
    },
}

#[derive(Clone, Copy)]
struct PrimaryFileGrammar {
    short_flags: &'static str,
    short_scalar_options: &'static str,
    short_file_options: &'static [(char, KnownFileArgument, FileAuthorityRole)],
    long_flags: &'static [&'static str],
    long_scalar_options: &'static [&'static str],
    long_optional_scalar_options: &'static [&'static str],
    long_file_options: &'static [(&'static str, KnownFileArgument, FileAuthorityRole)],
    positionals: PrimaryPositionals,
    numeric_tail_offsets: bool,
}

const NO_SHORT_FILE_OPTIONS: &[(char, KnownFileArgument, FileAuthorityRole)] = &[];
const NO_LONG_OPTIONS: &[&str] = &[];
const NO_LONG_FILE_OPTIONS: &[(&str, KnownFileArgument, FileAuthorityRole)] = &[];

const CAT_GRAMMAR: PrimaryFileGrammar = PrimaryFileGrammar {
    short_flags: "AbeEnstTuv",
    short_scalar_options: "",
    short_file_options: NO_SHORT_FILE_OPTIONS,
    long_flags: &[
        "--show-all",
        "--number-nonblank",
        "--show-ends",
        "--number",
        "--squeeze-blank",
        "--show-tabs",
        "--show-nonprinting",
        "--help",
        "--version",
    ],
    long_scalar_options: NO_LONG_OPTIONS,
    long_optional_scalar_options: NO_LONG_OPTIONS,
    long_file_options: NO_LONG_FILE_OPTIONS,
    positionals: PrimaryPositionals::Files {
        kind: KnownFileArgument::AbsolutePathOrStdin,
        authority_role: FileAuthorityRole::CallerData,
        dash_is_stream: true,
        implicit_working_directory: false,
    },
    numeric_tail_offsets: false,
};

const DF_GRAMMAR: PrimaryFileGrammar = PrimaryFileGrammar {
    short_flags: "ahHiklPTv",
    short_scalar_options: "Btx",
    short_file_options: NO_SHORT_FILE_OPTIONS,
    long_flags: &[
        "--all",
        "--human-readable",
        "--si",
        "--inodes",
        "--local",
        "--no-sync",
        "--portability",
        "--sync",
        "--total",
        "--print-type",
        "--help",
        "--version",
    ],
    long_scalar_options: &["--block-size", "--type", "--exclude-type"],
    long_optional_scalar_options: &["--output"],
    long_file_options: NO_LONG_FILE_OPTIONS,
    positionals: PrimaryPositionals::Files {
        kind: KnownFileArgument::AbsolutePath,
        authority_role: FileAuthorityRole::CallerData,
        dash_is_stream: false,
        implicit_working_directory: false,
    },
    numeric_tail_offsets: false,
};

const LS_GRAMMAR: PrimaryFileGrammar = PrimaryFileGrammar {
    short_flags: "1ABCDFGHLNQRSUXZabcdfghiklmnopqrstuvx",
    short_scalar_options: "ITw",
    short_file_options: NO_SHORT_FILE_OPTIONS,
    long_flags: &[
        "--all",
        "--almost-all",
        "--author",
        "--escape",
        "--ignore-backups",
        "--directory",
        "--dired",
        "--file-type",
        "--full-time",
        "--group-directories-first",
        "--no-group",
        "--human-readable",
        "--si",
        "--dereference-command-line",
        "--dereference-command-line-symlink-to-dir",
        "--inode",
        "--kibibytes",
        "--dereference",
        "--numeric-uid-gid",
        "--literal",
        "--hide-control-chars",
        "--show-control-chars",
        "--quote-name",
        "--reverse",
        "--recursive",
        "--size",
        "--zero",
        "--context",
        "--help",
        "--version",
    ],
    long_scalar_options: &[
        "--block-size",
        "--format",
        "--hide",
        "--indicator-style",
        "--ignore",
        "--quoting-style",
        "--sort",
        "--time",
        "--time-style",
        "--tabsize",
        "--width",
    ],
    long_optional_scalar_options: &["--color", "--classify", "--hyperlink"],
    long_file_options: NO_LONG_FILE_OPTIONS,
    positionals: PrimaryPositionals::Files {
        kind: KnownFileArgument::AbsolutePath,
        authority_role: FileAuthorityRole::CallerData,
        dash_is_stream: false,
        implicit_working_directory: true,
    },
    numeric_tail_offsets: false,
};

const TAIL_GRAMMAR: PrimaryFileGrammar = PrimaryFileGrammar {
    short_flags: "Ffqvz",
    short_scalar_options: "cns",
    short_file_options: NO_SHORT_FILE_OPTIONS,
    long_flags: &[
        "--quiet",
        "--silent",
        "--retry",
        "--verbose",
        "--zero-terminated",
        "--help",
        "--version",
    ],
    long_scalar_options: &[
        "--bytes",
        "--lines",
        "--max-unchanged-stats",
        "--pid",
        "--sleep-interval",
    ],
    long_optional_scalar_options: &["--follow"],
    long_file_options: NO_LONG_FILE_OPTIONS,
    positionals: PrimaryPositionals::Files {
        kind: KnownFileArgument::AbsolutePathOrStdin,
        authority_role: FileAuthorityRole::CallerData,
        dash_is_stream: true,
        implicit_working_directory: false,
    },
    numeric_tail_offsets: true,
};

const HOSTNAME_SHORT_FILE_OPTIONS: &[(char, KnownFileArgument, FileAuthorityRole)] = &[(
    'F',
    KnownFileArgument::FixedAbsolutePath,
    FileAuthorityRole::OperatorInput,
)];
const HOSTNAME_LONG_FILE_OPTIONS: &[(&str, KnownFileArgument, FileAuthorityRole)] = &[(
    "--file",
    KnownFileArgument::FixedAbsolutePath,
    FileAuthorityRole::OperatorInput,
)];
const HOSTNAME_GRAMMAR: PrimaryFileGrammar = PrimaryFileGrammar {
    short_flags: "aAbdfhiIsVvy",
    short_scalar_options: "",
    short_file_options: HOSTNAME_SHORT_FILE_OPTIONS,
    long_flags: &[
        "--alias",
        "--all-fqdns",
        "--boot",
        "--domain",
        "--fqdn",
        "--long",
        "--help",
        "--ip-address",
        "--all-ip-addresses",
        "--short",
        "--version",
        "--yp",
        "--nis",
    ],
    long_scalar_options: NO_LONG_OPTIONS,
    long_optional_scalar_options: NO_LONG_OPTIONS,
    long_file_options: HOSTNAME_LONG_FILE_OPTIONS,
    positionals: PrimaryPositionals::Scalar { maximum: 1 },
    numeric_tail_offsets: false,
};

fn primary_file_grammar(binary: &str) -> Option<PrimaryFileGrammar> {
    match binary {
        "cat" => Some(CAT_GRAMMAR),
        "df" => Some(DF_GRAMMAR),
        "hostname" => Some(HOSTNAME_GRAMMAR),
        "ls" => Some(LS_GRAMMAR),
        "tail" => Some(TAIL_GRAMMAR),
        _ => None,
    }
}

fn option_value<'a>(
    args: &'a [String],
    index: &mut usize,
    argument: &'a str,
    value_offset: usize,
    option: &str,
) -> Result<(&'a str, usize, usize)> {
    if value_offset < argument.len() {
        let mut offset = value_offset;
        if argument.as_bytes().get(offset) == Some(&b'=') {
            offset += 1;
        }
        let value = &argument[offset..];
        if value.is_empty() {
            bail!("option '{option}' has an empty value")
        }
        return Ok((value, *index, offset));
    }
    let value_index = *index + 1;
    let value = args
        .get(value_index)
        .ok_or_else(|| anyhow::anyhow!("option '{option}' requires a value"))?;
    *index += 1;
    Ok((value, value_index, 0))
}

fn parse_primary_file_grammar<'a>(
    binary: &str,
    args: &'a [String],
    grammar: PrimaryFileGrammar,
) -> Result<ParsedPrimaryFileCommand<'a>> {
    let mut files = Vec::new();
    let mut positional_count = 0usize;
    let mut options = true;
    let mut index = 0usize;
    while index < args.len() {
        let argument = args[index].as_str();
        if options && argument == "--" {
            options = false;
            index += 1;
            continue;
        }
        if options && argument.starts_with("--") {
            let (name, attached) = argument
                .split_once('=')
                .map_or((argument, None), |(name, value)| (name, Some(value)));
            if grammar.long_flags.contains(&name) {
                if attached.is_some() {
                    bail!("binary '{binary}' flag '{name}' does not take a value")
                }
            } else if grammar.long_scalar_options.contains(&name) {
                let _ = option_value(args, &mut index, argument, name.len(), name)?;
            } else if grammar.long_optional_scalar_options.contains(&name) {
                if attached.is_some_and(str::is_empty) {
                    bail!("binary '{binary}' option '{name}' has an empty value")
                }
            } else if let Some((_, kind, authority_role)) = grammar
                .long_file_options
                .iter()
                .find(|(known, _, _)| *known == name)
            {
                let (value, argument_index, source_value_offset) =
                    option_value(args, &mut index, argument, name.len(), name)?;
                files.push(PrimaryFileArgument {
                    argument_index,
                    value,
                    source_value_offset,
                    kind: *kind,
                    authority_role: *authority_role,
                });
            } else {
                bail!("binary '{binary}' uses unknown option '{name}'")
            }
            index += 1;
            continue;
        }
        if options && argument.starts_with('-') && argument != "-" {
            if grammar.numeric_tail_offsets
                && argument.strip_prefix('-').is_some_and(|value| {
                    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
                })
            {
                index += 1;
                continue;
            }
            let mut offset = 1usize;
            while offset < argument.len() {
                let option = argument[offset..]
                    .chars()
                    .next()
                    .context("short option is not valid UTF-8")?;
                if !option.is_ascii() {
                    bail!("binary '{binary}' uses unknown short option in '{argument}'")
                }
                let option_len = option.len_utf8();
                if grammar.short_flags.contains(option) {
                    offset += option_len;
                    continue;
                }
                if grammar.short_scalar_options.contains(option) {
                    let option_name = format!("-{option}");
                    let _ = option_value(
                        args,
                        &mut index,
                        argument,
                        offset + option_len,
                        &option_name,
                    )?;
                    break;
                }
                if let Some((_, kind, authority_role)) = grammar
                    .short_file_options
                    .iter()
                    .find(|(known, _, _)| *known == option)
                {
                    let option_name = format!("-{option}");
                    let (value, argument_index, source_value_offset) = option_value(
                        args,
                        &mut index,
                        argument,
                        offset + option_len,
                        &option_name,
                    )?;
                    files.push(PrimaryFileArgument {
                        argument_index,
                        value,
                        source_value_offset,
                        kind: *kind,
                        authority_role: *authority_role,
                    });
                    break;
                }
                bail!("binary '{binary}' uses unknown short option '-{option}'")
            }
            index += 1;
            continue;
        }
        if options
            && grammar.numeric_tail_offsets
            && argument
                .strip_prefix('+')
                .is_some_and(|value| !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
        {
            index += 1;
            continue;
        }

        positional_count += 1;
        match grammar.positionals {
            PrimaryPositionals::Scalar { maximum } => {
                if positional_count > maximum {
                    bail!("binary '{binary}' accepts at most {maximum} positional argument(s)")
                }
            }
            PrimaryPositionals::Files {
                kind,
                authority_role,
                dash_is_stream,
                ..
            } => {
                if !(dash_is_stream && argument == "-") {
                    files.push(PrimaryFileArgument {
                        argument_index: index,
                        value: argument,
                        source_value_offset: 0,
                        kind,
                        authority_role,
                    });
                }
            }
        }
        index += 1;
    }

    if binary == "hostname" && !files.is_empty() && positional_count != 0 {
        bail!("binary 'hostname' cannot combine a file source with a hostname operand")
    }
    let implicit_working_directory = matches!(
        grammar.positionals,
        PrimaryPositionals::Files {
            implicit_working_directory: true,
            ..
        }
    ) && positional_count == 0;
    Ok(ParsedPrimaryFileCommand {
        files,
        implicit_working_directory,
    })
}

fn primary_file_arguments<'a>(
    binary: &str,
    args: &'a [String],
) -> Result<Option<ParsedPrimaryFileCommand<'a>>> {
    primary_file_grammar(binary)
        .map(|grammar| parse_primary_file_grammar(binary, args, grammar))
        .transpose()
}

fn known_file_options(binary: &str) -> Vec<KnownFileOption> {
    let mut options = match binary {
        "ansible" | "ansible-playbook" => ANSIBLE_FILE_OPTIONS.to_vec(),
        "kubectl" => KUBECTL_FILE_OPTIONS.to_vec(),
        "helm" => HELM_FILE_OPTIONS.to_vec(),
        _ => Vec::new(),
    };
    if binary == "ansible" {
        options.extend_from_slice(ANSIBLE_AD_HOC_OUTPUT_OPTIONS);
    }
    options
}

fn absolute_path_list(value: &str) -> bool {
    !value.is_empty() && std::env::split_paths(value).all(|path| path.is_absolute())
}

fn key_equals_path_payload(value: &str) -> Option<&str> {
    let path = value.split_once('=').map_or(value, |(_, payload)| payload);
    (!path.is_empty()).then_some(path)
}

fn helm_set_file_payload(value: &str) -> Option<&str> {
    let (key, path) = value.split_once('=')?;
    (!key.is_empty() && !path.is_empty() && !value.contains(',')).then_some(path)
}

const ANSIBLE_OPERATOR_FIXED_OPTIONS: &[&str] = &[
    "-a",
    "--args",
    "-c",
    "--connection",
    "-m",
    "--module-name",
    "--become-method",
    "--become-user",
    "-u",
    "--user",
];

// These options admit a secondary local executable through SSH transport
// configuration. Guard does not parse shell fragments or discover arbitrary
// executables from them, so every nonempty value is rejected.
const ANSIBLE_REJECTED_SECONDARY_AUTHORITY_OPTIONS: &[&str] = &[
    "--ssh-args",
    "--ssh-common-args",
    "--ssh-extra-args",
    "--scp-extra-args",
    "--sftp-extra-args",
];

const ANSIBLE_OPERATOR_FIXED_FLAGS: &[&str] = &["-b", "--become"];

const ANSIBLE_INTERACTIVE_FLAGS: &[&str] = &[
    "-J",
    "--ask-vault-password",
    "--ask-vault-pass",
    "-K",
    "--ask-become-pass",
    "-k",
    "--ask-pass",
];

const KUBECTL_OPERATOR_FIXED_OPTIONS: &[&str] = &[
    "--as",
    "--as-group",
    "--as-uid",
    "--as-user-extra",
    "--cluster",
    "--context",
    "-s",
    "--server",
    "--tls-server-name",
    "--user",
    "--username",
];

const KUBECTL_OPERATOR_FIXED_FLAGS: &[&str] = &["--insecure-skip-tls-verify"];

const KUBECTL_FORBIDDEN_STATIC_OPTIONS: &[&str] =
    &["--password", "--storage-driver-password", "--token"];

// These values select or configure secondary executables. Static authority
// preserves the operator-authored argv exactly instead of admitting a caller
// parameter at an executable boundary.
const HELM_OPERATOR_FIXED_OPTIONS: &[&str] = &[
    "--key",
    "-n",
    "--namespace",
    "--repo",
    "--username",
    "--kube-apiserver",
    "--kube-as-group",
    "--kube-as-user",
    "--kube-context",
    "--kube-tls-server-name",
    "--post-renderer",
    "--post-renderer-args",
];

const HELM_OPERATOR_ENUMERATED_OPTIONS: &[&str] = &[
    "-n",
    "--namespace",
    "--repo",
    "--username",
    "--kube-apiserver",
    "--kube-as-group",
    "--kube-as-user",
    "--kube-context",
    "--kube-tls-server-name",
];

const HELM_OPERATOR_FIXED_FLAGS: &[&str] = &["--kube-insecure-skip-tls-verify"];

const HELM_FORBIDDEN_STATIC_OPTIONS: &[&str] = &["--kube-token", "--password", "--passphrase"];

const ANSIBLE_PLAYBOOK_NON_FILE_VALUE_OPTIONS: &[&str] = &[
    "-l",
    "--limit",
    "-t",
    "--tags",
    "--skip-tags",
    "--start-at-task",
    "-u",
    "--user",
    "-f",
    "--forks",
    "-T",
    "--timeout",
];

fn ansible_playbook_option_takes_value(option: &str) -> bool {
    ANSIBLE_FILE_OPTIONS
        .iter()
        .any(|known| known.name == option)
        || ANSIBLE_OPERATOR_FIXED_OPTIONS.contains(&option)
        || ANSIBLE_REJECTED_SECONDARY_AUTHORITY_OPTIONS.contains(&option)
        || ANSIBLE_PLAYBOOK_NON_FILE_VALUE_OPTIONS.contains(&option)
}

fn ansible_playbook_paths(args: &[String]) -> Vec<(usize, &str)> {
    let mut skip_value = false;
    let mut playbooks = Vec::new();
    for (index, argument) in args.iter().enumerate() {
        if skip_value {
            skip_value = false;
            continue;
        }
        if argument.starts_with('-') {
            skip_value = ansible_playbook_option_takes_value(argument);
            continue;
        }
        playbooks.push((index, argument.as_str()));
    }
    playbooks
}

fn collect_operator_authority_value(
    kind: KnownFileArgument,
    value: &str,
    paths: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    match kind {
        KnownFileArgument::AbsolutePath
        | KnownFileArgument::FixedAbsolutePath
        | KnownFileArgument::OperatorSelectedAbsolutePath => {
            paths.insert(PathBuf::from(value));
        }
        KnownFileArgument::AbsolutePathOrStdin
        | KnownFileArgument::FixedAbsolutePathOrStdin
        | KnownFileArgument::KubectlFilename => {
            if value != "-" {
                paths.insert(PathBuf::from(value));
            }
        }
        KnownFileArgument::FixedAbsolutePathList => {
            paths.extend(std::env::split_paths(value));
        }
        KnownFileArgument::AnsibleInventory => {
            if path_is_absolute(value) {
                paths.insert(PathBuf::from(value));
            }
        }
        KnownFileArgument::AnsibleExtraVars => {
            if let Some(path) = kind.path_payload_template(value) {
                paths.insert(PathBuf::from(path));
            }
        }
        KnownFileArgument::AnsibleVaultId => {
            if let Some(path) = kind.path_payload_template(value) {
                paths.insert(PathBuf::from(path));
            }
        }
        KnownFileArgument::AnsibleVaultIdentityList => {
            for entry in value.split(',') {
                collect_operator_authority_value(KnownFileArgument::AnsibleVaultId, entry, paths)?;
            }
        }
        KnownFileArgument::KeyEqualsPath | KnownFileArgument::HelmSetFile => {
            let path = kind
                .path_payload_template(value)
                .context("file argument has no local path payload")?;
            paths.insert(PathBuf::from(path));
        }
    }
    Ok(())
}

/// Return every caller-visible filesystem object that contributes executable
/// or credential authority to a typed command. The daemon retains validated
/// handles for these paths for the child lifetime.
pub fn operator_authority_paths(
    binary: &str,
    args: &[String],
    plain_env: &HashMap<String, String>,
) -> Result<Vec<PathBuf>> {
    let binary = executable_match_key(binary);
    validate_runtime_option_authority(&binary, args)?;
    let local_args = if binary == "kubectl" {
        &args[..args
            .iter()
            .position(|argument| argument == "--")
            .unwrap_or(args.len())]
    } else {
        args
    };
    let file_options = known_file_options(&binary);
    let mut paths = BTreeSet::new();

    if let Some(parsed) = primary_file_arguments(&binary, args)? {
        for file in parsed.files {
            if !file.kind.accepts(file.value) {
                bail!(
                    "binary '{}' file argument must be {}, got {:?}",
                    binary,
                    file.kind.requirement(),
                    file.value
                )
            }
            collect_operator_authority_value(file.kind, file.value, &mut paths)?;
        }
    }

    for (index, argument) in local_args.iter().enumerate() {
        if let Some(option) = file_options
            .iter()
            .find(|option| option.name == argument)
            .filter(|option| option.authority_role != FileAuthorityRole::OutputDestination)
        {
            let value = local_args.get(index + 1).ok_or_else(|| {
                anyhow::anyhow!(
                    "operator authority option '{}' requires a value",
                    option.name
                )
            })?;
            collect_operator_authority_value(option.kind, value, &mut paths)?;
        }
        for option in file_options
            .iter()
            .filter(|option| option.authority_role != FileAuthorityRole::OutputDestination)
        {
            let value = if option.name.len() == 2 {
                argument
                    .strip_prefix(option.name)
                    .filter(|value| !value.is_empty())
                    .map(|value| value.strip_prefix('=').unwrap_or(value))
            } else {
                argument.strip_prefix(&format!("{}=", option.name))
            };
            if let Some(value) = value {
                collect_operator_authority_value(option.kind, value, &mut paths)?;
            }
        }
    }

    if binary == "ansible-playbook" {
        for (_, playbook) in ansible_playbook_paths(args) {
            paths.insert(PathBuf::from(playbook));
        }
    }
    if binary == "kubectl" {
        for argument in local_args {
            let candidate = argument
                .split_once('=')
                .map_or(argument.as_str(), |(_, value)| value);
            if Path::new(candidate).is_absolute() {
                paths.insert(PathBuf::from(candidate));
            }
        }
        for (index, _) in local_args.iter().enumerate() {
            for option in ["-o", "--output"] {
                let Some(Some(output)) = operator_option_value_at(local_args, index, option) else {
                    continue;
                };
                for prefix in [
                    "custom-columns-file=",
                    "jsonpath-file=",
                    "go-template-file=",
                    "templatefile=",
                ] {
                    if let Some(path) = output.strip_prefix(prefix) {
                        paths.insert(PathBuf::from(path));
                    }
                }
            }
        }
    }
    if binary == "helm" {
        for argument in args {
            let candidate = argument
                .split_once('=')
                .map_or(argument.as_str(), |(_, value)| value);
            if Path::new(candidate).is_absolute() {
                paths.insert(PathBuf::from(candidate));
            }
        }
    }

    for (name, value) in plain_env {
        match tool_environment_authority(&binary, name) {
            Some(ToolEnvironmentAuthority::File(file)) => {
                collect_operator_authority_value(file.kind, value, &mut paths)?;
            }
            Some(ToolEnvironmentAuthority::Forbidden) => {
                bail!(
                    "tool environment '{}' introduces unclassified executable, configuration, or filesystem authority",
                    name
                );
            }
            Some(ToolEnvironmentAuthority::FixedScalar) => {
                if !tool_environment_scalar_is_safe(&binary, name, value) {
                    bail!("tool environment '{}' has an unsafe authority value", name);
                }
            }
            Some(ToolEnvironmentAuthority::SecretScalar) | None => {}
        }
    }

    Ok(paths.into_iter().collect())
}

fn file_argument_uses_local_path(kind: KnownFileArgument, value: &str) -> bool {
    match kind {
        KnownFileArgument::AbsolutePathOrStdin
        | KnownFileArgument::FixedAbsolutePathOrStdin
        | KnownFileArgument::KubectlFilename => value != "-",
        KnownFileArgument::KeyEqualsPath | KnownFileArgument::HelmSetFile => {
            kind.path_payload_template(value).is_some()
        }
        KnownFileArgument::AnsibleInventory => !value.ends_with(','),
        KnownFileArgument::AnsibleExtraVars => value.starts_with('@'),
        KnownFileArgument::AnsibleVaultId => kind.path_payload_template(value).is_some(),
        KnownFileArgument::AnsibleVaultIdentityList => value
            .split(',')
            .any(|entry| file_argument_uses_local_path(KnownFileArgument::AnsibleVaultId, entry)),
        _ => !value.is_empty(),
    }
}

/// File-capable argv can disclose daemon-readable input or mutate the daemon's
/// filesystem. Such commands require exact typed authority instead of
/// evaluator-only or legacy replay authority.
pub fn command_uses_untyped_local_file_authority(binary: &str, args: &[String]) -> bool {
    let binary = executable_match_key(binary);
    // `ip` object grammars include local file input (`monitor ... file`) and
    // secondary execution (`netns exec`, `vrf exec`). Until every supported
    // object has a bounded grammar, no evaluator-issued command may exercise
    // this dispatcher.
    if binary == "ip" {
        return true;
    }
    if validate_runtime_option_authority(&binary, args).is_err() {
        return true;
    }
    if let Ok(Some(parsed)) = primary_file_arguments(&binary, args) {
        if parsed.implicit_working_directory
            || parsed
                .files
                .iter()
                .any(|file| file_argument_uses_local_path(file.kind, file.value))
        {
            return true;
        }
    }
    let local_end = if binary == "kubectl" {
        args.iter()
            .position(|argument| argument == "--")
            .unwrap_or(args.len())
    } else {
        args.len()
    };
    let local_args = &args[..local_end];
    for (index, _) in local_args.iter().enumerate() {
        for option in known_file_options(&binary) {
            if operator_option_value_at(local_args, index, option.name)
                .flatten()
                .is_some_and(|value| file_argument_uses_local_path(option.kind, value))
            {
                return true;
            }
        }
    }
    if binary == "ansible-playbook" && !ansible_playbook_paths(args).is_empty() {
        return true;
    }
    if binary == "kubectl" {
        for (index, _) in local_args.iter().enumerate() {
            for option in ["-o", "--output"] {
                let Some(Some(output)) = operator_option_value_at(local_args, index, option) else {
                    continue;
                };
                if [
                    "custom-columns-file=",
                    "jsonpath-file=",
                    "go-template-file=",
                    "templatefile=",
                ]
                .iter()
                .any(|prefix| {
                    output
                        .strip_prefix(prefix)
                        .is_some_and(|path| !path.is_empty())
                }) {
                    return true;
                }
            }
            if operator_option_value_at(local_args, index, "--template")
                .flatten()
                .is_some_and(|value| !value.is_empty())
            {
                return true;
            }
        }
        if let Some(index) = kubectl_subcommand_index("untyped command", local_args, "command")
            .ok()
            .flatten()
        {
            return match local_args[index].as_str() {
                "cp" => true,
                "kustomize" => local_args[index + 1..]
                    .iter()
                    .any(|argument| !argument.starts_with('-')),
                _ => false,
            };
        }
    }
    if binary == "helm" {
        if let Some(index) = helm_subcommand_index("untyped command", local_args, "command")
            .ok()
            .flatten()
        {
            return HELM_COMMANDS_REQUIRING_EXACT_FILE_AUTHORITY
                .contains(&local_args[index].as_str());
        }
    }
    false
}

fn authored_value_binds_path(value: &str, path: &Path) -> bool {
    let expected = path.to_string_lossy();
    let mut candidates = vec![value];
    if let Some((_, payload)) = value.split_once('=') {
        candidates.push(payload);
        if let Some((_, nested)) = payload.split_once('=') {
            candidates.push(nested);
        }
    }
    if let Some((_, payload)) = value.rsplit_once('@') {
        candidates.push(payload);
    }
    candidates.into_iter().any(|candidate| {
        candidate == expected
            || std::env::split_paths(candidate).any(|item| item == Path::new(expected.as_ref()))
    })
}

fn cell_authorizes_local_file_authority(
    verb: &Verb,
    cell: &VerbCoverageCell,
    args: &[String],
) -> bool {
    if !command_uses_untyped_local_file_authority(&verb.binary, args) {
        return true;
    }
    if !verb.args.is_empty() {
        return true;
    }
    let Ok(paths) = operator_authority_paths(&verb.binary, args, &HashMap::new()) else {
        return false;
    };
    if paths.is_empty() || paths.iter().any(|path| !path.is_absolute()) {
        return false;
    }
    let authored = cell
        .required_args
        .iter()
        .map(String::as_str)
        .chain(
            cell.options
                .iter()
                .flat_map(|constraint| constraint.values.iter().map(String::as_str)),
        )
        .collect::<Vec<_>>();
    paths.iter().all(|path| {
        authored
            .iter()
            .any(|value| authored_value_binds_path(value, path))
    })
}

fn read_bounded_authority_text(path: &Path, label: &str) -> Result<String> {
    const MAX_CONFIG_BYTES: u64 = 8 * 1024 * 1024;
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("cannot inspect {label} {}", path.display()))?;
    if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES {
        bail!("{label} {} is not a bounded regular file", path.display())
    }
    std::fs::read_to_string(path).with_context(|| format!("cannot read {label} {}", path.display()))
}

fn collect_absolute_transitive_path(
    config: &Path,
    label: &str,
    value: &str,
    paths: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    let path = Path::new(value);
    if !path.is_absolute() {
        bail!(
            "{label} in {} must use an absolute path, got {:?}",
            config.display(),
            value
        )
    }
    paths.insert(path.to_path_buf());
    Ok(())
}

fn kubeconfig_transitive_authority(path: &Path, paths: &mut BTreeSet<PathBuf>) -> Result<()> {
    let text = read_bounded_authority_text(path, "kubeconfig")?;
    let document: serde_yaml_ng::Value = serde_yaml_ng::from_str(&text)
        .with_context(|| format!("invalid kubeconfig {}", path.display()))?;
    if let Some(clusters) = document
        .get("clusters")
        .and_then(serde_yaml_ng::Value::as_sequence)
    {
        for cluster in clusters {
            if let Some(authority) = cluster
                .get("cluster")
                .and_then(|value| value.get("certificate-authority"))
                .and_then(serde_yaml_ng::Value::as_str)
            {
                collect_absolute_transitive_path(
                    path,
                    "kubeconfig certificate-authority",
                    authority,
                    paths,
                )?;
            }
        }
    }
    if let Some(users) = document
        .get("users")
        .and_then(serde_yaml_ng::Value::as_sequence)
    {
        for user in users {
            let Some(credentials) = user.get("user") else {
                continue;
            };
            for field in ["client-certificate", "client-key", "tokenFile"] {
                if let Some(value) = credentials
                    .get(field)
                    .and_then(serde_yaml_ng::Value::as_str)
                {
                    collect_absolute_transitive_path(
                        path,
                        &format!("kubeconfig {field}"),
                        value,
                        paths,
                    )?;
                }
            }
            if let Some(command) = credentials
                .get("exec")
                .and_then(|value| value.get("command"))
                .and_then(serde_yaml_ng::Value::as_str)
            {
                collect_absolute_transitive_path(path, "kubeconfig exec command", command, paths)?;
            }
        }
    }
    Ok(())
}

fn ansible_config_value(value: &str) -> &str {
    value
        .split_once(';')
        .map_or(value, |(value, _)| value)
        .trim()
}

fn ansible_config_assignment(line: &str) -> Option<(&str, &str)> {
    line.split_once('=').or_else(|| line.split_once(':'))
}

fn reject_ansible_config_secondary_authority(path: &Path, text: &str) -> Result<()> {
    let mut continuation_key: Option<(String, usize)> = None;

    for raw_line in text.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }

        let indentation = raw_line.len() - raw_line.trim_start().len();
        if indentation == 0 && trimmed.starts_with('[') && trimmed.ends_with(']') {
            continuation_key = None;
            continue;
        }

        if let Some((key, key_indentation)) = &continuation_key {
            if indentation > *key_indentation {
                if !ansible_config_value(trimmed).is_empty() {
                    bail!(
                        "Ansible configuration key '{}' in {} contains secondary SSH authority and must be empty or omitted",
                        key,
                        path.display()
                    );
                }
                continue;
            }
            continuation_key = None;
        }

        let Some((key, value)) = ansible_config_assignment(trimmed) else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        if !SHELL_BEARING_KEYS.contains(&key.as_str()) {
            continue;
        }
        if !ansible_config_value(value).is_empty() {
            bail!(
                "Ansible configuration key '{}' in {} contains secondary SSH authority and must be empty or omitted",
                key,
                path.display()
            );
        }
        continuation_key = Some((key, indentation));
    }

    Ok(())
}

const SHELL_BEARING_KEYS: &[&str] = &[
    "ssh_args",
    "ssh_common_args",
    "ssh_extra_args",
    "scp_extra_args",
    "sftp_extra_args",
];

fn ansible_config_transitive_authority(path: &Path, paths: &mut BTreeSet<PathBuf>) -> Result<()> {
    const PATH_KEYS: &[&str] = &[
        "inventory",
        "library",
        "module_utils",
        "roles_path",
        "collections_path",
        "collections_paths",
        "action_plugins",
        "become_plugins",
        "cache_plugins",
        "callback_plugins",
        "cliconf_plugins",
        "connection_plugins",
        "filter_plugins",
        "httpapi_plugins",
        "inventory_plugins",
        "lookup_plugins",
        "netconf_plugins",
        "shell_plugins",
        "strategy_plugins",
        "terminal_plugins",
        "test_plugins",
        "vars_plugins",
        "connection_path",
        "executable",
        "ssh_executable",
        "become_exe",
        "become_password_file",
        "connection_password_file",
        "private_key_file",
        "vault_identity_list",
        "vault_password_file",
    ];
    let text = read_bounded_authority_text(path, "Ansible configuration")?;
    reject_ansible_config_secondary_authority(path, &text)?;
    let mut continuation_key: Option<(String, usize)> = None;
    for raw_line in text.lines() {
        let trimmed_start = raw_line.trim_start();
        let indentation = raw_line.len().saturating_sub(trimmed_start.len());
        let trimmed = trimmed_start.trim_end();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if trimmed.starts_with('[') {
            continuation_key = None;
            continue;
        }
        if let Some((key, assignment_indentation)) = &continuation_key {
            if indentation > *assignment_indentation {
                bail!(
                    "Ansible configuration key '{}' in {} uses an indented continuation; authority-bearing paths must be written on the assignment line",
                    key,
                    path.display()
                );
            }
        }
        continuation_key = ansible_config_assignment(trimmed).and_then(|(key, _)| {
            let key = key.trim().to_ascii_lowercase();
            PATH_KEYS
                .contains(&key.as_str())
                .then_some((key, indentation))
        });
    }
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with(';')
            || line.starts_with('[')
        {
            continue;
        }
        let Some((key, value)) = ansible_config_assignment(line) else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = ansible_config_value(value);
        if !PATH_KEYS.contains(&key.as_str()) {
            continue;
        }
        if value.is_empty()
            || value.contains("%(")
            || value.contains("{{")
            || value.contains('$')
            || value.starts_with('~')
        {
            bail!(
                "Ansible configuration key '{}' in {} must use static absolute paths",
                key,
                path.display()
            )
        }
        let values = match key.as_str() {
            "inventory" => value
                .split(',')
                .map(str::trim)
                .map(str::to_string)
                .collect::<Vec<_>>(),
            "vault_identity_list" => value
                .split(',')
                .map(str::trim)
                .map(|identity| {
                    let (_, source) = identity.rsplit_once('@').ok_or_else(|| {
                        anyhow::anyhow!(
                            "Ansible configuration key 'vault_identity_list' in {} must bind every identity to an absolute source",
                            path.display()
                        )
                    })?;
                    if source == "prompt" {
                        return Ok(None);
                    }
                    Ok(Some(source.to_string()))
                })
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .flatten()
                .collect::<Vec<_>>(),
            _ => std::env::split_paths(value)
                .map(|value| value.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
        };
        for value in values {
            collect_absolute_transitive_path(
                path,
                &format!("Ansible configuration key '{key}'"),
                &value,
                paths,
            )?;
        }
    }
    Ok(())
}

/// Resolve executable, credential, and plugin paths referenced from trusted
/// tool configuration. Dynamic or relative references fail closed because the
/// child could otherwise discover authority outside the retained artifact set.
fn operator_environment_value<'a>(
    environment: &'a HashMap<String, String>,
    name: &str,
) -> Option<&'a str> {
    #[cfg(windows)]
    let matches = |candidate: &str| candidate.eq_ignore_ascii_case(name);
    #[cfg(not(windows))]
    let matches = |candidate: &str| candidate == name;

    environment
        .iter()
        .find(|(candidate, _)| matches(candidate))
        .map(|(_, value)| value.as_str())
}

pub fn transitive_operator_authority_paths(
    binary: &str,
    args: &[String],
    plain_env: &HashMap<String, String>,
    cwd: Option<&Path>,
) -> Result<Vec<PathBuf>> {
    let binary = executable_match_key(binary);
    let mut paths = BTreeSet::new();
    if matches!(binary.as_str(), "kubectl" | "helm") {
        let mut kubeconfigs = BTreeSet::new();
        for (index, _) in args.iter().enumerate() {
            if let Some(value) = operator_option_value_at(args, index, "--kubeconfig").flatten() {
                collect_operator_authority_value(
                    KnownFileArgument::FixedAbsolutePath,
                    value,
                    &mut kubeconfigs,
                )?;
            }
        }
        if let Some(value) = operator_environment_value(plain_env, "KUBECONFIG") {
            collect_operator_authority_value(
                KnownFileArgument::FixedAbsolutePathList,
                value,
                &mut kubeconfigs,
            )?;
        }
        if kubeconfigs.is_empty() {
            if let Some(home) = operator_environment_value(plain_env, "HOME")
                .or_else(|| operator_environment_value(plain_env, "USERPROFILE"))
            {
                let default = PathBuf::from(home).join(".kube/config");
                if default.is_file() {
                    kubeconfigs.insert(default);
                }
            }
        }
        for kubeconfig in kubeconfigs {
            kubeconfig_transitive_authority(&kubeconfig, &mut paths)?;
        }
    }
    if matches!(binary.as_str(), "ansible" | "ansible-playbook") {
        let config =
            if let Some(config) = operator_environment_value(plain_env, "ANSIBLE_CONFIG") {
                Some(PathBuf::from(config))
            } else if let Some(cwd) = cwd {
                let candidate = cwd.join("ansible.cfg");
                candidate.is_file().then_some(candidate)
            } else {
                None
            }
            .or_else(|| {
                operator_environment_value(plain_env, "HOME")
                    .or_else(|| operator_environment_value(plain_env, "USERPROFILE"))
                    .map(PathBuf::from)
                    .map(|home| home.join(".ansible.cfg"))
                    .filter(|candidate| candidate.is_file())
            })
            .or_else(|| {
                let system = PathBuf::from("/etc/ansible/ansible.cfg");
                system.is_file().then_some(system)
            });
        if let Some(config) = config {
            ansible_config_transitive_authority(&config, &mut paths)?;
        }
    }
    Ok(paths.into_iter().collect())
}

fn validate_operator_fixed_options(
    verb: &Verb,
    binary: &str,
    args: &[String],
    template_args: &[String],
    command_label: &str,
) -> Result<()> {
    let operator_source_allows = |option: &str, source: &str, concrete: &str| {
        if source == concrete && placeholders(source).is_empty() {
            return true;
        }
        let allows_enumeration = binary == "kubectl"
            || (binary == "helm" && HELM_OPERATOR_ENUMERATED_OPTIONS.contains(&option));
        if !allows_enumeration {
            return false;
        }
        let names = placeholders(source);
        names.len() == 1
            && source == format!("{{{}}}", names[0])
            && verb
                .params
                .get(&names[0])
                .and_then(|spec| enumerate_pattern_literals(spec.pattern_text()))
                .is_some_and(|values| {
                    concrete == source || values.iter().any(|value| value == concrete)
                })
    };
    let options: &[&str] = match binary {
        "ansible" | "ansible-playbook" => ANSIBLE_OPERATOR_FIXED_OPTIONS,
        "kubectl" => KUBECTL_OPERATOR_FIXED_OPTIONS,
        "helm" => HELM_OPERATOR_FIXED_OPTIONS,
        _ => &[],
    };
    let fixed_flags: &[&str] = match binary {
        "ansible" | "ansible-playbook" => ANSIBLE_OPERATOR_FIXED_FLAGS,
        "kubectl" => KUBECTL_OPERATOR_FIXED_FLAGS,
        "helm" => HELM_OPERATOR_FIXED_FLAGS,
        _ => &[],
    };
    let forbidden_options: &[&str] = match binary {
        "kubectl" => KUBECTL_FORBIDDEN_STATIC_OPTIONS,
        "helm" => HELM_FORBIDDEN_STATIC_OPTIONS,
        _ => &[],
    };

    for (index, argument) in args.iter().enumerate() {
        let option = argument
            .split_once('=')
            .map_or(argument.as_str(), |pair| pair.0);
        if matches!(binary, "ansible" | "ansible-playbook")
            && resolve_ansible_long_option(option).is_some_and(|resolved| {
                ANSIBLE_REJECTED_SECONDARY_AUTHORITY_OPTIONS.contains(&resolved)
            })
        {
            bail!(
                "verb '{}' {command_label} option '{}' selects secondary SSH authority and cannot be preauthorized",
                verb.name,
                option
            );
        }
        if forbidden_options.contains(&option) {
            bail!(
                "verb '{}' {command_label} option '{}' carries credential material in argv and cannot be statically preauthorized; use a daemon-managed secret binding",
                verb.name,
                option
            );
        }
        if fixed_flags.contains(&option)
            && (template_args.is_empty() && !verb.coverage.is_empty()
                || template_args.get(index).map(String::as_str) != Some(argument.as_str())
                || !placeholders(argument).is_empty())
        {
            bail!(
                "verb '{}' {command_label} flag '{}' must be one operator-fixed literal argument",
                verb.name,
                option
            );
        }
    }

    for (index, _argument) in args.iter().enumerate() {
        for option in options {
            let Some(value) = operator_option_value_at(args, index, option) else {
                continue;
            };
            let value = value.ok_or_else(|| {
                anyhow::anyhow!(
                    "verb '{}' {command_label} option '{}' requires an operator-fixed value",
                    verb.name,
                    option
                )
            })?;
            let template_value = operator_option_value_at(template_args, index, option).flatten();
            if template_args.is_empty() && !verb.coverage.is_empty() {
                continue;
            }
            if !template_value.is_some_and(|source| operator_source_allows(option, source, value)) {
                bail!(
                    "verb '{}' {command_label} option '{}' must use an operator-authored literal or finite enumerated value",
                    verb.name,
                    option
                );
            }
        }
    }
    Ok(())
}

fn validate_known_file_template_with_source(
    verb: &Verb,
    template: &str,
    source_template: Option<&str>,
    command_label: &str,
    position: &str,
    kind: KnownFileArgument,
) -> Result<()> {
    if matches!(
        kind,
        KnownFileArgument::FixedAbsolutePath
            | KnownFileArgument::FixedAbsolutePathOrStdin
            | KnownFileArgument::FixedAbsolutePathList
    ) {
        if kind.accepts(template)
            && source_template == Some(template)
            && placeholders(template).is_empty()
        {
            return Ok(());
        }
        bail!(
            "verb '{}' {command_label} file argument {position} must be {}, got {:?}",
            verb.name,
            kind.requirement(),
            template
        );
    }
    if matches!(kind, KnownFileArgument::OperatorSelectedAbsolutePath) {
        let finite_parameter_allows = |source: &str, rendered: Option<&str>| {
            let names = placeholders(source);
            if names.len() != 1 || source != format!("{{{}}}", names[0]) {
                return false;
            }
            verb.params
                .get(&names[0])
                .and_then(|spec| enumerate_pattern_literals(spec.pattern_text()))
                .is_some_and(|values| {
                    values.iter().all(|value| path_is_absolute(value))
                        && rendered.is_none_or(|value| values.iter().any(|item| item == value))
                })
        };
        if (kind.accepts(template)
            && ((source_template == Some(template) && placeholders(template).is_empty())
                || source_template
                    .is_some_and(|source| finite_parameter_allows(source, Some(template)))))
            || (!kind.accepts(template) && finite_parameter_allows(template, None))
        {
            return Ok(());
        }
        bail!(
            "verb '{}' {command_label} file argument {position} must be {}, got {:?}",
            verb.name,
            kind.requirement(),
            template
        );
    }
    if kind.accepts(template) {
        if kind.requires_operator_fixed_source(template)
            && (source_template != Some(template) || !placeholders(template).is_empty())
        {
            let cell_constrained_inventory = source_template.is_none()
                && matches!(kind, KnownFileArgument::AnsibleInventory)
                && verb.args.is_empty()
                && !verb.coverage.is_empty();
            if !cell_constrained_inventory {
                bail!(
                    "verb '{}' {command_label} file argument {position} is executable authority and must use one operator-fixed literal value",
                    verb.name
                );
            }
        }
        return Ok(());
    }
    let path_template = kind.path_payload_template(template).ok_or_else(|| {
        anyhow::anyhow!(
            "verb '{}' {command_label} file argument {position} must be {}, got {:?}",
            verb.name,
            kind.requirement(),
            template
        )
    })?;
    let names = placeholders(path_template);
    if names.len() == 1 && path_template == format!("{{{}}}", names[0]) {
        let spec = verb.params.get(&names[0]).ok_or_else(|| {
            anyhow::anyhow!(
                "verb '{}' {command_label} file argument {position} references undeclared parameter '{}'",
                verb.name,
                names[0]
            )
        })?;
        if let Some(values) = enumerate_pattern_literals(spec.pattern_text()) {
            if values
                .iter()
                .all(|value| kind.accepts_parameter_value(value))
            {
                return Ok(());
            }
            bail!(
                "verb '{}' {command_label} file parameter '{}' enumerates a value that is not {}",
                verb.name,
                names[0],
                kind.requirement()
            );
        }
        if matches!(
            kind,
            KnownFileArgument::AnsibleInventory | KnownFileArgument::AnsibleVaultId
        ) {
            bail!(
                "verb '{}' {command_label} file parameter '{}' must enumerate non-executable values; open-ended patterns cannot select {}",
                verb.name,
                names[0],
                kind.requirement()
            );
        }
        if spec
            .default
            .as_deref()
            .is_some_and(|value| !kind.accepts_parameter_value(value))
        {
            bail!(
                "verb '{}' {command_label} file parameter '{}' has a default that is not {}",
                verb.name,
                names[0],
                kind.requirement()
            );
        }
        // Regex-language inclusion cannot be proven with representative
        // samples. `render` checks every concrete value, and raw matching uses
        // the same rendered-command check before granting coverage.
        compile_anchored(spec.pattern_text()).with_context(|| {
            format!(
                "verb '{}' {command_label} file parameter '{}' has an invalid pattern",
                verb.name, names[0]
            )
        })?;
        return Ok(());
    }
    bail!(
        "verb '{}' {command_label} file argument {position} must be {}, got {:?}",
        verb.name,
        kind.requirement(),
        template
    )
}

fn validate_known_file_template(
    verb: &Verb,
    template: &str,
    command_label: &str,
    position: &str,
    kind: KnownFileArgument,
) -> Result<()> {
    validate_known_file_template_with_source(
        verb,
        template,
        Some(template),
        command_label,
        position,
        kind,
    )
}

fn validate_static_output_destination(
    verb: &Verb,
    option: KnownFileOption,
    value: &str,
    command_label: &str,
) -> Result<()> {
    if option.authority_role != FileAuthorityRole::OutputDestination {
        return Ok(());
    }
    if matches!(option.kind, KnownFileArgument::AbsolutePathOrStdin) && value == "-" {
        return Ok(());
    }
    bail!(
        "verb '{}' {command_label} option '{}' writes through caller-visible filesystem paths and is not eligible for static coverage; use standard output where supported",
        verb.name,
        option.name
    )
}

fn validate_static_caller_data_source(
    verb: &Verb,
    option: KnownFileOption,
    value: &str,
    source_template: Option<&str>,
    command_label: &str,
) -> Result<()> {
    if option.authority_role != FileAuthorityRole::CallerData {
        return Ok(());
    }
    if value == "-"
        && matches!(
            option.kind,
            KnownFileArgument::AbsolutePathOrStdin | KnownFileArgument::KubectlFilename
        )
    {
        return Ok(());
    }
    validate_static_caller_data_template(
        verb,
        source_template,
        command_label,
        &format!("option '{}'", option.name),
    )
}

fn validate_static_caller_data_template(
    verb: &Verb,
    source_template: Option<&str>,
    command_label: &str,
    position: &str,
) -> Result<()> {
    let Some(source) = source_template else {
        bail!(
            "verb '{}' {command_label} {position} reads broker-visible data and requires an exact operator-authored template",
            verb.name,
        );
    };
    if placeholders(source).is_empty() {
        return Ok(());
    }
    let names = placeholders(source);
    if names.len() == 1
        && verb
            .params
            .get(&names[0])
            .and_then(|spec| enumerate_pattern_literals(spec.pattern_text()))
            .is_some()
    {
        return Ok(());
    }
    bail!(
        "verb '{}' {command_label} {position} reads broker-visible data and must use a literal or finite enumerated operator path",
        verb.name,
    )
}

fn validate_known_file_arguments(
    verb: &Verb,
    binary: &str,
    args: &[String],
    template_args: &[String],
    command_label: &str,
) -> Result<()> {
    let binary = executable_match_key(binary);
    validate_runtime_option_authority(&binary, args)?;
    let file_options = known_file_options(&binary);

    // Cobra stops parsing kubectl's local options at `--`; later tokens are
    // command arguments, including the remote argv accepted by `kubectl exec`.
    let local_end = if binary == "kubectl" {
        args.iter()
            .position(|argument| argument == "--")
            .unwrap_or(args.len())
    } else {
        args.len()
    };
    let local_args = &args[..local_end];
    let local_template_args = &template_args[..template_args.len().min(local_end)];

    validate_operator_fixed_options(
        verb,
        &binary,
        local_args,
        local_template_args,
        command_label,
    )?;

    if matches!(binary.as_str(), "ansible" | "ansible-playbook") {
        for argument in args {
            let option = argument
                .split_once('=')
                .map_or(argument.as_str(), |pair| pair.0);
            if resolve_ansible_long_option(option).is_some_and(|resolved| {
                ANSIBLE_REJECTED_SECONDARY_AUTHORITY_OPTIONS.contains(&resolved)
            }) {
                bail!(
                    "verb '{}' {command_label} option '{}' selects secondary SSH authority and cannot be preauthorized",
                    verb.name,
                    option
                );
            }
            if option.starts_with("--")
                && !file_options.iter().any(|known| known.name == option)
                && !ANSIBLE_OPERATOR_FIXED_OPTIONS.contains(&option)
                && !ANSIBLE_OPERATOR_FIXED_FLAGS.contains(&option)
                && file_options
                    .iter()
                    .map(|known| known.name)
                    .chain(ANSIBLE_OPERATOR_FIXED_OPTIONS.iter().copied())
                    .chain(ANSIBLE_OPERATOR_FIXED_FLAGS.iter().copied())
                    .filter(|known| known.starts_with("--"))
                    .any(|known| known != option && known.starts_with(option))
            {
                bail!(
                    "verb '{}' {command_label} uses abbreviated Ansible file option '{}'; spell the option in full",
                    verb.name,
                    option
                );
            }
            if let Some(cluster) = option
                .strip_prefix('-')
                .filter(|value| !value.starts_with('-'))
            {
                if cluster.len() > 1 && !cluster.chars().all(|flag| flag == 'v') {
                    bail!(
                        "verb '{}' {command_label} clusters or attaches an Ansible short option in '{}'; pass every value option separately",
                        verb.name,
                        option
                    );
                }
            }
        }
    }

    for (index, argument) in local_args.iter().enumerate() {
        if let Some(option) = file_options.iter().find(|option| option.name == argument) {
            let value = local_args.get(index + 1).ok_or_else(|| {
                anyhow::anyhow!(
                    "verb '{}' {command_label} option '{}' requires {}",
                    verb.name,
                    argument,
                    option.kind.requirement()
                )
            })?;
            validate_static_output_destination(verb, *option, value, command_label)?;
            let source_template = (template_args.get(index).map(String::as_str)
                == Some(argument.as_str()))
            .then(|| template_args.get(index + 1).map(String::as_str))
            .flatten();
            validate_static_caller_data_source(
                verb,
                *option,
                value,
                source_template,
                command_label,
            )?;
            validate_known_file_template_with_source(
                verb,
                value,
                source_template,
                command_label,
                &format!("after {argument}"),
                option.kind,
            )?;
        }
        for option in &file_options {
            if option.name.len() == 2 {
                if let Some(value) = argument
                    .strip_prefix(option.name)
                    .filter(|value| !value.is_empty())
                {
                    let value = value.strip_prefix('=').unwrap_or(value);
                    validate_static_output_destination(verb, *option, value, command_label)?;
                    let source_template = template_args.get(index).and_then(|template| {
                        template
                            .strip_prefix(option.name)
                            .filter(|value| !value.is_empty())
                            .map(|value| value.strip_prefix('=').unwrap_or(value))
                    });
                    validate_static_caller_data_source(
                        verb,
                        *option,
                        value,
                        source_template,
                        command_label,
                    )?;
                    validate_known_file_template_with_source(
                        verb,
                        value,
                        source_template,
                        command_label,
                        &format!("attached to {}", option.name),
                        option.kind,
                    )?;
                }
            } else if let Some(value) = argument.strip_prefix(&format!("{}=", option.name)) {
                validate_static_output_destination(verb, *option, value, command_label)?;
                let source_template = template_args
                    .get(index)
                    .and_then(|template| template.strip_prefix(&format!("{}=", option.name)));
                validate_static_caller_data_source(
                    verb,
                    *option,
                    value,
                    source_template,
                    command_label,
                )?;
                validate_known_file_template_with_source(
                    verb,
                    value,
                    source_template,
                    command_label,
                    &format!("in {}=...", option.name),
                    option.kind,
                )?;
            }
        }
    }

    if binary == "kubectl" {
        validate_kubectl_profile_output(verb, local_args, command_label)?;
        validate_kubectl_output_files(verb, local_args, local_template_args, command_label)?;
    }
    validate_known_positional_file_arguments(
        verb,
        &binary,
        local_args,
        template_args,
        command_label,
    )?;

    if binary == "ansible-playbook" {
        for (index, argument) in ansible_playbook_paths(args) {
            validate_known_file_template_with_source(
                verb,
                argument,
                template_args.get(index).map(String::as_str),
                command_label,
                "playbook",
                KnownFileArgument::FixedAbsolutePath,
            )?;
        }
    }
    Ok(())
}

fn validate_kubectl_profile_output(
    verb: &Verb,
    args: &[String],
    command_label: &str,
) -> Result<()> {
    let mut selected_profile = None;
    let mut output_is_explicit = false;
    let mut index = 0;
    while index < args.len() {
        let argument = &args[index];
        if argument == "--profile" {
            let value = args.get(index + 1).ok_or_else(|| {
                anyhow::anyhow!(
                    "verb '{}' {command_label} option '--profile' requires a profile name",
                    verb.name
                )
            })?;
            selected_profile = Some(value.as_str());
            index += 2;
            continue;
        }
        if let Some(value) = argument.strip_prefix("--profile=") {
            if value.is_empty() {
                bail!(
                    "verb '{}' {command_label} option '--profile' requires a profile name",
                    verb.name
                );
            }
            selected_profile = Some(value);
        }
        if argument == "--profile-output" || argument.starts_with("--profile-output=") {
            output_is_explicit = true;
        }
        index += 1;
    }

    if selected_profile.is_some_and(|profile| profile != "none") && !output_is_explicit {
        bail!(
            "verb '{}' {command_label} enables kubectl profiling without an explicit absolute --profile-output path",
            verb.name
        );
    }
    Ok(())
}

fn kubectl_option_value<'a>(
    verb: &Verb,
    args: &'a [String],
    short: Option<&str>,
    long: &str,
    command_label: &str,
) -> Result<Option<&'a str>> {
    let mut selected = None;
    for (index, argument) in args.iter().enumerate() {
        if argument == long || short.is_some_and(|option| argument == option) {
            selected = Some(
                args.get(index + 1)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "verb '{}' {command_label} option '{}' requires a value",
                            verb.name,
                            argument
                        )
                    })?
                    .as_str(),
            );
            continue;
        }
        if let Some(value) = argument.strip_prefix(&format!("{long}=")) {
            selected = Some(value);
            continue;
        }
        if let Some(option) = short {
            if let Some(value) = argument
                .strip_prefix(option)
                .filter(|value| !value.is_empty())
            {
                selected = Some(value.strip_prefix('=').unwrap_or(value));
            }
        }
    }
    Ok(selected)
}

fn validate_kubectl_output_files(
    verb: &Verb,
    args: &[String],
    template_args: &[String],
    command_label: &str,
) -> Result<()> {
    let Some(output) = kubectl_option_value(verb, args, Some("-o"), "--output", command_label)?
    else {
        return Ok(());
    };

    for prefix in [
        "custom-columns-file=",
        "jsonpath-file=",
        "go-template-file=",
        "templatefile=",
    ] {
        if let Some(path) = output.strip_prefix(prefix) {
            let source_template =
                kubectl_option_value(verb, template_args, Some("-o"), "--output", command_label)?
                    .and_then(|value| value.strip_prefix(prefix));
            validate_static_caller_data_template(
                verb,
                source_template,
                command_label,
                "kubectl output-format file",
            )?;
            return validate_known_file_template(
                verb,
                path,
                command_label,
                &format!("in output format {prefix}..."),
                KnownFileArgument::AbsolutePath,
            );
        }
    }

    if matches!(output, "custom-columns-file" | "jsonpath-file") {
        bail!(
            "verb '{}' {command_label} output format '{}' requires an absolute file payload",
            verb.name,
            output
        );
    }
    if matches!(output, "go-template-file" | "templatefile") {
        let template = kubectl_option_value(verb, args, None, "--template", command_label)?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "verb '{}' {command_label} output format '{}' requires an absolute --template path",
                    verb.name,
                    output
                )
            })?;
        let source_template =
            kubectl_option_value(verb, template_args, None, "--template", command_label)?;
        validate_static_caller_data_template(
            verb,
            source_template,
            command_label,
            "kubectl output template",
        )?;
        validate_known_file_template(
            verb,
            template,
            command_label,
            "kubectl output template",
            KnownFileArgument::AbsolutePath,
        )?;
    }
    Ok(())
}

const KUBECTL_GLOBAL_VALUE_OPTIONS: &[&str] = &[
    "--as",
    "--as-group",
    "--as-uid",
    "--as-user-extra",
    "--cache-dir",
    "--certificate-authority",
    "--client-certificate",
    "--client-key",
    "--cluster",
    "--context",
    "--kuberc",
    "--kubeconfig",
    "-n",
    "--namespace",
    "--password",
    "--profile",
    "--profile-output",
    "--request-timeout",
    "-s",
    "--server",
    "--storage-driver-buffer-duration",
    "--storage-driver-db",
    "--storage-driver-host",
    "--storage-driver-password",
    "--storage-driver-table",
    "--storage-driver-user",
    "--tls-server-name",
    "--token",
    "--user",
    "--username",
    "-v",
    "--v",
    "--vmodule",
];

const KUBECTL_GLOBAL_BOOLEAN_OPTIONS: &[&str] = &[
    "-h",
    "--help",
    "--disable-compression",
    "--insecure-skip-tls-verify",
    "--match-server-version",
    "--storage-driver-secure",
    "--warnings-as-errors",
];

const KUBECTL_BUILTIN_SUBCOMMANDS: &[&str] = &[
    "annotate",
    "api-resources",
    "api-versions",
    "apply",
    "attach",
    "auth",
    "autoscale",
    "certificate",
    "cluster-info",
    "completion",
    "config",
    "cordon",
    "cp",
    "create",
    "debug",
    "delete",
    "describe",
    "diff",
    "drain",
    "edit",
    "events",
    "exec",
    "explain",
    "expose",
    "get",
    "help",
    "kuberc",
    "kustomize",
    "label",
    "logs",
    "options",
    "patch",
    "port-forward",
    "proxy",
    "replace",
    "rollout",
    "run",
    "scale",
    "set",
    "taint",
    "top",
    "uncordon",
    "version",
    "wait",
];

const HELM_GLOBAL_VALUE_OPTIONS: &[&str] = &[
    "--burst-limit",
    "--color",
    "--colour",
    "--content-cache",
    "--kube-apiserver",
    "--kube-as-group",
    "--kube-as-user",
    "--kube-ca-file",
    "--kube-context",
    "--kube-tls-server-name",
    "--kube-token",
    "--kubeconfig",
    "-n",
    "--namespace",
    "--qps",
    "--registry-config",
    "--repository-cache",
    "--repository-config",
];

const HELM_GLOBAL_BOOLEAN_OPTIONS: &[&str] =
    &["--debug", "-h", "--help", "--kube-insecure-skip-tls-verify"];

const HELM_BUILTIN_SUBCOMMANDS: &[&str] = &[
    "completion",
    "create",
    "dependency",
    "env",
    "get",
    "help",
    "history",
    "install",
    "lint",
    "list",
    "package",
    "pull",
    "push",
    "registry",
    "repo",
    "rollback",
    "search",
    "show",
    "status",
    "template",
    "test",
    "uninstall",
    "upgrade",
    "verify",
    "version",
];

const HELM_COMMANDS_REQUIRING_EXACT_FILE_AUTHORITY: &[&str] = &[
    "create",
    "dependency",
    "install",
    "lint",
    "package",
    "plugin",
    "pull",
    "push",
    "registry",
    "repo",
    "show",
    "template",
    "upgrade",
    "verify",
];

fn kubectl_subcommand_index(
    verb_name: &str,
    args: &[String],
    command_label: &str,
) -> Result<Option<usize>> {
    let mut index = 0;
    while index < args.len() {
        let argument = &args[index];
        if argument == "--" {
            return Ok(None);
        }
        if !argument.starts_with('-') || argument == "-" {
            return Ok(Some(index));
        }
        if let Some((option, value)) = argument.split_once('=') {
            if value.is_empty()
                || !(KUBECTL_GLOBAL_VALUE_OPTIONS.contains(&option)
                    || KUBECTL_GLOBAL_BOOLEAN_OPTIONS.contains(&option))
            {
                bail!(
                    "verb '{}' {command_label} uses unrecognized kubectl global option '{}' before the subcommand",
                    verb_name,
                    option
                );
            }
            index += 1;
            continue;
        }
        if KUBECTL_GLOBAL_BOOLEAN_OPTIONS.contains(&argument.as_str()) {
            index += 1;
            continue;
        }
        if KUBECTL_GLOBAL_VALUE_OPTIONS.contains(&argument.as_str()) {
            if args.get(index + 1).is_none() {
                bail!(
                    "verb '{}' {command_label} kubectl global option '{}' requires a value",
                    verb_name,
                    argument
                );
            }
            index += 2;
            continue;
        }
        if ["-n", "-s", "-v"]
            .iter()
            .any(|option| argument.starts_with(option) && argument.len() > option.len())
        {
            index += 1;
            continue;
        }
        bail!(
            "verb '{}' {command_label} uses unrecognized kubectl global option '{}' before the subcommand",
            verb_name,
            argument
        );
    }
    Ok(None)
}

fn helm_subcommand_index(
    verb_name: &str,
    args: &[String],
    command_label: &str,
) -> Result<Option<usize>> {
    let mut index = 0;
    while index < args.len() {
        let argument = &args[index];
        if argument == "--" {
            return Ok(None);
        }
        if !argument.starts_with('-') || argument == "-" {
            return Ok(Some(index));
        }
        if let Some((option, value)) = argument.split_once('=') {
            if value.is_empty()
                || !(HELM_GLOBAL_VALUE_OPTIONS.contains(&option)
                    || HELM_GLOBAL_BOOLEAN_OPTIONS.contains(&option))
            {
                bail!(
                    "verb '{}' {command_label} uses unrecognized Helm global option '{}' before the subcommand",
                    verb_name,
                    option
                );
            }
            index += 1;
            continue;
        }
        if HELM_GLOBAL_BOOLEAN_OPTIONS.contains(&argument.as_str()) {
            index += 1;
            continue;
        }
        if HELM_GLOBAL_VALUE_OPTIONS.contains(&argument.as_str()) {
            if args.get(index + 1).is_none() {
                bail!(
                    "verb '{}' {command_label} Helm global option '{}' requires a value",
                    verb_name,
                    argument
                );
            }
            index += 2;
            continue;
        }
        if argument.starts_with("-n") && argument.len() > 2 {
            index += 1;
            continue;
        }
        bail!(
            "verb '{}' {command_label} uses unrecognized Helm global option '{}' before the subcommand",
            verb_name,
            argument
        );
    }
    Ok(None)
}

/// Parse the top-level local command selected by kubectl or Helm argv. Generated
/// coverage uses the same grammar boundary as runtime matching so argument
/// values cannot be mistaken for command authority.
pub fn protected_tool_command_path(binary: &str, args: &[String]) -> Result<Vec<String>> {
    let binary = executable_match_key(binary);
    let (index, known_commands) = match binary.as_str() {
        "kubectl" => (
            kubectl_subcommand_index("generated coverage", args, "command")?,
            KUBECTL_BUILTIN_SUBCOMMANDS,
        ),
        "helm" => (
            helm_subcommand_index("generated coverage", args, "command")?,
            HELM_BUILTIN_SUBCOMMANDS,
        ),
        _ => return Ok(Vec::new()),
    };
    let command = index
        .and_then(|index| args.get(index))
        .filter(|command| known_commands.contains(&command.as_str()))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "generated {} coverage must select one recognized local subcommand",
                binary
            )
        })?;
    Ok(vec![command.clone()])
}

fn kubectl_cp_remote_endpoint(value: &str) -> bool {
    if path_is_absolute(value) {
        return false;
    }
    value
        .split_once(':')
        .is_some_and(|(pod, path)| !pod.is_empty() && !path.is_empty() && !pod.contains('\\'))
}

fn validate_kubectl_cp_operands(
    verb: &Verb,
    args: &[String],
    template_args: &[String],
    subcommand_index: usize,
    command_label: &str,
) -> Result<()> {
    let mut operands = Vec::new();
    let mut index = subcommand_index + 1;
    while index < args.len() {
        let argument = &args[index];
        if matches!(argument.as_str(), "-c" | "--container" | "--retries")
            || KUBECTL_GLOBAL_VALUE_OPTIONS.contains(&argument.as_str())
        {
            if args.get(index + 1).is_none() {
                bail!(
                    "verb '{}' {command_label} kubectl cp option '{}' requires a value",
                    verb.name,
                    argument
                );
            }
            index += 2;
            continue;
        }
        if argument.starts_with('-') {
            index += 1;
            continue;
        }
        operands.push((index, argument.as_str()));
        index += 1;
    }
    if operands.len() != 2 {
        bail!(
            "verb '{}' {command_label} kubectl cp requires exactly two endpoints",
            verb.name
        );
    }
    let remote = operands
        .iter()
        .map(|(_, operand)| kubectl_cp_remote_endpoint(operand))
        .collect::<Vec<_>>();
    if remote.iter().filter(|remote| **remote).count() != 1 {
        bail!(
            "verb '{}' {command_label} kubectl cp requires one remote and one local endpoint",
            verb.name
        );
    }
    if remote[0] {
        bail!(
            "verb '{}' {command_label} kubectl cp writes a caller-selected local destination and is not eligible for static coverage",
            verb.name
        );
    }
    let local_index = usize::from(remote[0]);
    let (argument_index, local_operand) = operands[local_index];
    validate_static_caller_data_template(
        verb,
        template_args.get(argument_index).map(String::as_str),
        command_label,
        "kubectl cp local source",
    )?;
    validate_known_file_template(
        verb,
        local_operand,
        command_label,
        "kubectl cp local endpoint",
        KnownFileArgument::AbsolutePath,
    )
}

/// Validate only positional forms whose local-file grammar is explicit in the
/// relevant CLI documentation. This is deliberately not a complete parser for
/// kubectl or Helm: ambiguous chart references and arbitrary option grammar
/// remain outside this bounded file-path check.
fn validate_known_positional_file_arguments(
    verb: &Verb,
    binary: &str,
    args: &[String],
    template_args: &[String],
    command_label: &str,
) -> Result<()> {
    if let Some(parsed) = primary_file_arguments(binary, args)? {
        for file in parsed.files {
            let source_template = file.source_template(template_args);
            if file.authority_role == FileAuthorityRole::CallerData {
                validate_static_caller_data_template(
                    verb,
                    source_template,
                    command_label,
                    &format!("file argument {}", file.argument_index + 1),
                )?;
            }
            validate_known_file_template_with_source(
                verb,
                file.value,
                source_template,
                command_label,
                &format!("argument {}", file.argument_index + 1),
                file.kind,
            )?;
        }
    }
    match binary {
        "kubectl" => {
            let Some(index) = kubectl_subcommand_index(&verb.name, args, command_label)? else {
                return Ok(());
            };
            if !KUBECTL_BUILTIN_SUBCOMMANDS.contains(&args[index].as_str()) {
                bail!(
                    "verb '{}' {command_label} selects unknown kubectl subcommand '{}'; kubectl plugins are not eligible for static coverage",
                    verb.name,
                    args[index]
                );
            }
            if matches!(args[index].as_str(), "config" | "kuberc") {
                bail!(
                    "verb '{}' {command_label} kubectl subcommand '{}' changes client configuration authority and is not eligible for static coverage",
                    verb.name,
                    args[index]
                );
            }
            match args[index].as_str() {
                "kustomize" => {
                    let directory = args.get(index + 1).ok_or_else(|| {
                        anyhow::anyhow!(
                            "verb '{}' {command_label} kubectl kustomize requires an absolute directory",
                            verb.name
                        )
                    })?;
                    validate_static_caller_data_template(
                        verb,
                        template_args.get(index + 1).map(String::as_str),
                        command_label,
                        "kubectl kustomize directory",
                    )?;
                    validate_known_file_template(
                        verb,
                        directory,
                        command_label,
                        "kubectl kustomize directory",
                        KnownFileArgument::AbsolutePath,
                    )?;
                    validate_kubectl_kustomize_authority(
                        verb,
                        args,
                        template_args,
                        index,
                        command_label,
                    )?;
                }
                "cp" => {
                    validate_kubectl_cp_operands(verb, args, template_args, index, command_label)?
                }
                _ => {}
            }
        }
        "helm" => {
            let Some(index) = helm_subcommand_index(&verb.name, args, command_label)? else {
                return Ok(());
            };
            if !HELM_BUILTIN_SUBCOMMANDS.contains(&args[index].as_str()) {
                bail!(
                    "verb '{}' {command_label} selects unknown Helm subcommand '{}'; Helm plugins are not eligible for static coverage",
                    verb.name,
                    args[index]
                );
            }
            let command = args[index].as_str();
            let nested_writer = args.get(index + 1).map(String::as_str);
            let writes_local_authority = matches!(command, "create" | "pull" | "package" | "push")
                || (command == "dependency" && matches!(nested_writer, Some("build" | "update")))
                || command == "repo"
                || command == "registry";
            if writes_local_authority {
                bail!(
                    "verb '{}' {command_label} Helm command '{}' writes local chart, repository, registry, or profile state or selects an unmodeled remote endpoint and is not eligible for static coverage",
                    verb.name,
                    args[index]
                );
            }
            if !verb.args.is_empty() || verb.coverage.is_empty() {
                return Ok(());
            }
            // Generic coverage accepts only the unambiguous local-operand
            // forms below. Operator-authored argv templates retain Helm's
            // broader positional grammar and are reviewed as exact commands.
            for (index, argument) in args.iter().enumerate() {
                let operand_index = match argument.as_str() {
                    "verify" | "package" | "lint" => Some(index + 1),
                    "build" | "update"
                        if index > 0
                            && args
                                .get(index - 1)
                                .is_some_and(|previous| previous == "dependency") =>
                    {
                        Some(index + 1)
                    }
                    _ => None,
                };
                let Some(operand_index) = operand_index else {
                    continue;
                };
                let operand = args.get(operand_index).ok_or_else(|| {
                    anyhow::anyhow!(
                        "verb '{}' {command_label} Helm subcommand '{}' requires an absolute local operand",
                        verb.name,
                        argument
                    )
                })?;
                if operand.starts_with('-') {
                    bail!(
                        "verb '{}' {command_label} Helm subcommand '{}' must place its local operand immediately after the subcommand",
                        verb.name,
                        argument
                    );
                }
                validate_known_file_template(
                    verb,
                    operand,
                    command_label,
                    &format!("Helm {argument} operand"),
                    KnownFileArgument::AbsolutePath,
                )?;
                validate_static_caller_data_template(
                    verb,
                    template_args.get(operand_index).map(String::as_str),
                    command_label,
                    &format!("Helm {argument} operand"),
                )?;
            }

            // `install`, `upgrade`, and `template` accept both chart
            // references and local paths. Their full positional grammar is
            // intentionally not modeled here, but an explicit relative path
            // is unambiguously caller-local and cannot be preauthorized.
            if let Some(relative) = args.iter().find(|argument| {
                matches!(argument.as_str(), "." | "..")
                    || argument.starts_with("./")
                    || argument.starts_with("../")
            }) {
                bail!(
                    "verb '{}' {command_label} contains explicit relative Helm path operand {:?}; use an absolute path",
                    verb.name,
                    relative
                );
            }
            let file_options = known_file_options("helm");
            let mut skip_value = false;
            for argument in &args[index + 1..] {
                if skip_value {
                    skip_value = false;
                    continue;
                }
                if argument.starts_with('-') {
                    skip_value = file_options.iter().any(|option| option.name == argument)
                        || HELM_OPERATOR_FIXED_OPTIONS.contains(&argument.as_str())
                        || HELM_GLOBAL_VALUE_OPTIONS.contains(&argument.as_str());
                    continue;
                }
                if Path::new(argument).is_absolute() {
                    bail!(
                        "verb '{}' {command_label} Helm local operand reads broker-visible data and requires an exact operator-authored template",
                        verb.name
                    );
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_kubectl_kustomize_authority(
    verb: &Verb,
    args: &[String],
    template_args: &[String],
    subcommand_index: usize,
    command_label: &str,
) -> Result<()> {
    if kubectl_option_value(
        verb,
        &args[subcommand_index + 1..],
        None,
        "--load-restrictor",
        command_label,
    )?
    .is_some_and(|value| value.eq_ignore_ascii_case("LoadRestrictionsNone"))
    {
        bail!(
            "verb '{}' {command_label} kubectl kustomize '--load-restrictor=LoadRestrictionsNone' expands local file authority and is not eligible for static coverage",
            verb.name
        );
    }

    for forbidden in [
        "--as-current-user",
        "--enable-alpha-plugins",
        "--env",
        "-e",
        "--mount",
        "--network",
        "--network-name",
    ] {
        if args[subcommand_index + 1..]
            .iter()
            .any(|argument| argument == forbidden || argument.starts_with(&format!("{forbidden}=")))
        {
            bail!(
                "verb '{}' {command_label} kubectl kustomize option '{}' enables external plugin authority and is not eligible for static coverage",
                verb.name,
                forbidden
            );
        }
    }

    let enable_helm_index = args[subcommand_index + 1..]
        .iter()
        .position(|argument| {
            argument == "--enable-helm" || argument.strip_prefix("--enable-helm=") == Some("true")
        })
        .map(|offset| subcommand_index + 1 + offset);
    let helm_command = kubectl_option_value(verb, args, None, "--helm-command", command_label)?;
    if let Some(enable_index) = enable_helm_index {
        if template_args.get(enable_index) != args.get(enable_index) {
            bail!(
                "verb '{}' {command_label} kubectl kustomize '--enable-helm' must be operator-fixed",
                verb.name
            );
        }
        if helm_command.is_none() {
            bail!(
                "verb '{}' {command_label} kubectl kustomize '--enable-helm' requires an operator-fixed absolute '--helm-command'",
                verb.name
            );
        }
    }

    if kubectl_option_value(verb, args, Some("-o"), "--output", command_label)?.is_some() {
        bail!(
            "verb '{}' {command_label} kubectl kustomize '--output' writes through caller-visible filesystem paths and is not eligible for static coverage; use standard output",
            verb.name
        );
    }
    Ok(())
}

fn validate_inventory_constraint_paths(
    verb: &Verb,
    cell: &VerbCoverageCell,
    constraint: &ValueConstraint,
) -> Result<()> {
    if !matches!(
        executable_match_key(&verb.binary).as_str(),
        "ansible" | "ansible-playbook"
    ) {
        return Ok(());
    }
    if constraint.values.is_empty() {
        bail!(
            "verb '{}' coverage cell '{}': Ansible inventory coverage must enumerate absolute paths or inline host lists",
            verb.name,
            cell.name
        );
    }
    for value in &constraint.values {
        if !path_is_absolute(value) && !value.ends_with(',') {
            bail!(
                "verb '{}' coverage cell '{}': Ansible inventory value must be an absolute path or inline host list, got {:?}",
                verb.name,
                cell.name,
                value
            );
        }
    }
    Ok(())
}

fn kubectl_exec_interactive_flag(argument: &str) -> bool {
    matches!(argument, "--stdin" | "--tty")
        || argument.starts_with("--stdin=")
        || argument.starts_with("--tty=")
        || argument
            .strip_prefix('-')
            .filter(|flags| !flags.is_empty())
            .is_some_and(|flags| flags.chars().all(|flag| matches!(flag, 'i' | 't')))
}

fn validate_synthesized_kubectl_exec(verb: &Verb, args: &[String], label: &str) -> Result<()> {
    let Some(exec_index) = args.iter().position(|argument| argument == "exec") else {
        return Ok(());
    };
    if let Some(flag) = args[exec_index + 1..]
        .iter()
        .find(|argument| kubectl_exec_interactive_flag(argument))
    {
        bail!(
            "synthesized verb '{}' {label} requests an interactive exec stream ('{}'); guard refuses interactive stdin/tty",
            verb.name,
            flag
        );
    }
    let separator = args
        .iter()
        .enumerate()
        .skip(exec_index + 1)
        .find_map(|(index, argument)| (argument == "--").then_some(index))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "synthesized verb '{}' {label} kubectl exec must separate its command with '--'",
                verb.name
            )
        })?;
    let value_options = [
        "-c",
        "--container",
        "-n",
        "--namespace",
        "--pod-running-timeout",
    ];
    let mut skip_value = false;
    let target = args[exec_index + 1..separator]
        .iter()
        .find(|argument| {
            if skip_value {
                skip_value = false;
                return false;
            }
            if value_options.contains(&argument.as_str()) {
                skip_value = true;
                return false;
            }
            !argument.starts_with('-')
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "synthesized verb '{}' {label} kubectl exec has no target",
                verb.name
            )
        })?;
    let target_prefix = target.split_once('/').map(|(prefix, _)| prefix);
    if !matches!(
        target_prefix,
        Some(
            "pod"
                | "pods"
                | "deploy"
                | "deployment"
                | "deployments"
                | "statefulset"
                | "statefulsets"
                | "daemonset"
                | "daemonsets"
                | "job"
                | "jobs"
                | "service"
                | "services"
        )
    ) {
        bail!(
            "synthesized verb '{}' {label} kubectl exec target {:?} must be an explicit resource reference such as deploy/<name>, not a bare generated pod assumption",
            verb.name,
            target
        );
    }
    let executable = args.get(separator + 1).ok_or_else(|| {
        anyhow::anyhow!(
            "synthesized verb '{}' {label} kubectl exec has no executable after '--'",
            verb.name
        )
    })?;
    if executable.chars().any(char::is_whitespace)
        || placeholders(executable).iter().any(|name| {
            verb.params
                .get(name)
                .is_some_and(|spec| spec.value_type() == ParamValueType::SingleArgv)
        })
    {
        bail!(
            "synthesized verb '{}' {label} kubectl exec executable {:?} must be one whitespace-free argv token",
            verb.name,
            executable
        );
    }
    Ok(())
}

fn validate_synthesized_command_shape(
    verb: &Verb,
    binary: &str,
    args: &[String],
    label: &str,
) -> Result<()> {
    validate_binary_not_shell(binary, &format!("synthesized verb {label}"))?;
    if let Some(operator) = args
        .iter()
        .find(|argument| matches!(argument.as_str(), ";" | "&&" | "||" | "|" | ">" | "<"))
    {
        bail!(
            "synthesized verb '{}' {label} has argv element {:?}, a literal shell operator; guard runs no shell, so the element cannot chain or redirect",
            verb.name,
            operator
        );
    }
    if executable_match_key(binary) == "kubectl" {
        validate_synthesized_kubectl_exec(verb, args, label)?;
    }
    Ok(())
}

/// Extra safety gate for verbs produced by `guard verb create --prompt`. The LLM
/// chose the shape, so its safety-critical fields must not be trusted: reject a
/// `trusted` verb (a synthesized verb keeps the LLM run-time backstop), a
/// shell/interpreter binary, a non-kebab name, and any parameter pattern broad
/// enough to admit whitespace or shell metacharacters. Structural validation
/// (anchored patterns, single-argv rendering) is still enforced by `validate_verb`.
pub fn validate_synthesized_safety(verb: &Verb) -> Result<()> {
    validate_verb(verb)?;
    if verb.trusted {
        bail!(
            "a synthesized verb may not be `trusted`; promote a verb to trusted only with a \
             deliberate manual operator edit of the catalog"
        );
    }
    if !is_kebab_name(&verb.name) {
        bail!(
            "synthesized verb name '{}' must be kebab-case (^[a-z0-9][a-z0-9-]*$)",
            verb.name
        );
    }
    validate_synthesized_command_shape(verb, &verb.binary, &verb.args, "forward command")?;
    if let Some(revert) = &verb.revert {
        validate_synthesized_command_shape(verb, &revert.binary, &revert.args, "revert command")?;
    }
    let binary_name = executable_match_key(&verb.binary);
    if verb.consequence == Reversibility::Reversible
        && matches!(
            binary_name.as_str(),
            "rm" | "rmdir" | "shred" | "unlink" | "del" | "erase" | "format" | "mkfs" | "dd"
        )
    {
        bail!(
            "synthesized verb '{}' classifies destructive binary '{}' as reversible",
            verb.name,
            verb.binary
        );
    }
    for (pname, spec) in &verb.params {
        validate_param_not_overbroad(pname, spec, "synthesized verb")?;
    }
    if verb
        .coverage
        .iter()
        .any(|cell| cell.override_marker.is_some())
    {
        bail!("a synthesized verb may not mint override markers");
    }
    Ok(())
}

/// Canonical authority-bearing fields for generated access coverage. This
/// stable shape identifies the matcher shown to an operator.
pub fn generated_access_matcher_shape(verb: &Verb) -> serde_json::Value {
    let coverage = verb
        .coverage
        .iter()
        .cloned()
        .map(|mut cell| {
            cell.provenance = None;
            cell
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "binary": verb.binary,
        "args": verb.args,
        "coverage": coverage,
        "credential_plan": verb.credential_plan,
        "params": verb.params,
        "hold": verb.hold,
    })
}

pub fn generated_access_matcher_digest(matcher: &serde_json::Value) -> String {
    Sha256::digest(serde_json::to_vec(matcher).expect("access matcher serializes"))
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn generated_access_verb_name(verb: &Verb) -> String {
    let digest = generated_access_matcher_digest(&generated_access_matcher_shape(verb));
    format!("access-generated-{}", &digest[..16])
}

/// Deterministic operator-facing description derived only from the generated
/// matcher's authority-bearing shape.
pub fn generated_access_description(verb: &Verb) -> String {
    let pinned = verb
        .args
        .iter()
        .filter(|argument| !argument.contains('{'))
        .cloned()
        .collect::<Vec<_>>();
    let parameters = verb.params.keys().cloned().collect::<Vec<_>>();
    let mut description = format!("Runs {}", verb.binary);
    if !pinned.is_empty() {
        description.push_str(&format!(" with pinned arguments {}", pinned.join(" ")));
    }
    match parameters.len() {
        0 => description.push_str(" and no caller-supplied values"),
        1 => description.push_str(&format!(
            " and one caller-supplied value ({})",
            parameters[0]
        )),
        count => description.push_str(&format!(
            " and {count} caller-supplied values ({})",
            parameters.join(", ")
        )),
    }
    description.push('.');
    description
}

fn value_constraint_contains_sensitive_literal(constraint: &ValueConstraint) -> bool {
    constraint
        .options
        .iter()
        .any(|option| text_contains_sensitive_literals(option))
        || constraint.values.iter().any(|value| {
            text_contains_sensitive_literals(value)
                || constraint.options.iter().any(|option| {
                    command_contains_sensitive_literals(
                        "generated-access-parameter",
                        &[option.clone(), value.clone()],
                    )
                })
        })
}

fn generated_authority_contains_sensitive_literal(verb: &Verb) -> bool {
    if text_contains_sensitive_literals(&verb.name)
        || command_contains_sensitive_literals(&verb.binary, &verb.args)
        || verb
            .revert
            .as_ref()
            .is_some_and(|revert| command_contains_sensitive_literals(&revert.binary, &revert.args))
        || verb
            .credential_plan
            .as_deref()
            .is_some_and(text_contains_sensitive_literals)
        || verb
            .promotion_stamp
            .as_deref()
            .is_some_and(text_contains_sensitive_literals)
    {
        return true;
    }
    for (name, specification) in &verb.params {
        if named_value_contains_sensitive_literals(name, specification.pattern_text())
            || specification.default.as_deref().is_some_and(|value| {
                named_value_contains_sensitive_literals(name, value)
                    || text_contains_sensitive_literals(value)
            })
        {
            return true;
        }
    }
    verb.coverage.iter().any(|cell| {
        text_contains_sensitive_literals(&cell.name)
            || command_contains_sensitive_literals(&verb.binary, &cell.required_args)
            || command_contains_sensitive_literals(&verb.binary, &cell.forbidden_args)
            || cell
                .options
                .iter()
                .any(value_constraint_contains_sensitive_literal)
            || cell
                .target
                .as_ref()
                .is_some_and(value_constraint_contains_sensitive_literal)
            || cell
                .inventory
                .as_ref()
                .is_some_and(value_constraint_contains_sensitive_literal)
            || cell
                .namespace
                .as_ref()
                .is_some_and(value_constraint_contains_sensitive_literal)
            || cell.fanout.as_ref().is_some_and(|fanout| {
                text_contains_sensitive_literals(&fanout.separator)
                    || value_constraint_contains_sensitive_literal(&fanout.selector)
            })
            || cell
                .cwd
                .as_ref()
                .is_some_and(|cwd| text_contains_sensitive_literals(&cwd.to_string_lossy()))
            || cell
                .override_marker
                .as_deref()
                .is_some_and(text_contains_sensitive_literals)
            || cell.environment.iter().any(|environment| {
                text_contains_sensitive_literals(&environment.name)
                    || environment.values.iter().any(|value| {
                        text_contains_sensitive_literals(value)
                            || named_value_contains_sensitive_literals(&environment.name, value)
                    })
                    || environment.pattern.as_deref().is_some_and(|pattern| {
                        text_contains_sensitive_literals(pattern)
                            || named_value_contains_sensitive_literals(&environment.name, pattern)
                    })
            })
            || cell.provenance.as_ref().is_some_and(|provenance| {
                text_contains_sensitive_literals(&provenance.source)
                    || provenance
                        .evidence
                        .iter()
                        .any(|evidence| text_contains_sensitive_literals(evidence))
                    || text_contains_sensitive_literals(&provenance.regime_stamp)
                    || text_contains_sensitive_literals(&provenance.prompt_stamp)
                    || text_contains_sensitive_literals(&provenance.model_stamp)
                    || provenance
                        .probes
                        .iter()
                        .any(|probe| command_contains_sensitive_literals(&verb.binary, &probe.args))
                    || provenance.observation_replays.iter().any(|replay| {
                        command_contains_sensitive_literals(&verb.binary, &replay.args)
                    })
            })
    })
}

/// Canonicalize the explanatory envelope of a model-synthesized verb and
/// reject literal-sensitive authority without changing what the verb can run.
/// This invariant is applied before preview identity, persistence, reload, and
/// projection.
fn sanitize_synthesized_verb_prose(verb: &mut Verb) {
    verb.description = crate::redact::redact_output_text(&verb.description);
    verb.prompt_context = verb
        .prompt_context
        .take()
        .map(|value| crate::redact::redact_output_text(&value));
    verb.source_prose = verb
        .source_prose
        .take()
        .map(|value| crate::redact::redact_output_text(&value));
    verb.evidence = verb
        .evidence
        .take()
        .map(|value| crate::redact::redact_output_text(&value));
    for cell in &mut verb.coverage {
        if let Some(provenance) = &mut cell.provenance {
            provenance.source = crate::redact::redact_output_text(&provenance.source);
            for evidence in &mut provenance.evidence {
                *evidence = crate::redact::redact_output_text(evidence);
            }
            for probe in &mut provenance.probes {
                probe.dimension = crate::redact::redact_output_text(&probe.dimension);
            }
            for replay in &mut provenance.observation_replays {
                replay.dimension = crate::redact::redact_output_text(&replay.dimension);
            }
        }
    }
}

pub fn canonicalize_synthesized_verb_envelope(mut verb: Verb) -> Result<Verb> {
    verb = canonicalize_generated_authority_envelope(verb)?;
    validate_synthesized_safety(&verb)?;
    Ok(verb)
}

/// Canonicalize the complete generated-authority envelope without changing
/// executable authority. Saved grants and catalog synthesis share this gate.
pub fn canonicalize_generated_authority_envelope(mut verb: Verb) -> Result<Verb> {
    sanitize_synthesized_verb_prose(&mut verb);
    if generated_authority_contains_sensitive_literal(&verb) {
        bail!(
            "generated verb contains sensitive authority metadata or literal credential argv and cannot be persisted"
        );
    }
    Ok(verb)
}

pub fn validate_canonical_synthesized_verb_envelope(verb: &Verb) -> Result<()> {
    let canonical = canonicalize_synthesized_verb_envelope(verb.clone())?;
    if serde_json::to_value(canonical)? != serde_json::to_value(verb)? {
        bail!("generated verb metadata is not in canonical sanitized form");
    }
    Ok(())
}

/// Normalize and validate a matcher proposed for a principal-bound access
/// request. Model-authored rollback commands are never part of generated
/// access authority, so remove that untrusted envelope before any structural
/// validation, canonicalization, persistence, or installation. Ordinary
/// operator-authored verbs continue to use `validate_verb` and retain their
/// rollback semantics.
pub fn normalize_generated_access_verb(mut verb: Verb) -> Result<Verb> {
    verb.revert = None;
    verb.baseline = false;
    verb.trusted = false;
    verb.prompt_context = None;
    verb.source_prose = None;
    verb.evidence = None;
    verb.auto_promoted = false;
    verb.promotion_stamp = None;
    if generated_authority_contains_sensitive_literal(&verb) {
        bail!(
            "generated access coverage contains sensitive authority metadata or literal argv and cannot be persisted"
        );
    }
    sanitize_synthesized_verb_prose(&mut verb);
    if generated_authority_contains_sensitive_literal(&verb) {
        bail!(
            "generated access coverage is not in canonical secret-free form and cannot be persisted"
        );
    }
    verb.description = generated_access_description(&verb);
    validate_synthesized_safety(&verb)?;
    Ok(verb)
}

/// Parse one durable generated-access proposal and prove that its serialized
/// form already satisfies every normalization and namespace invariant. Durable
/// state is rejected rather than rewritten because normalization can change
/// authority.
pub fn parse_normalized_generated_access_verb(value: &serde_json::Value) -> Result<Verb> {
    let verb =
        serde_json::from_value::<Verb>(value.clone()).context("decode proposed access coverage")?;
    let normalized = normalize_generated_access_verb(verb)?;
    if normalized.baseline {
        bail!("generated access coverage must not be baseline");
    }
    if normalized.name != generated_access_verb_name(&normalized) {
        bail!("generated access coverage name does not match its matcher digest");
    }
    if canonical_generated_access_consequence(&normalized) != normalized.consequence {
        bail!(
            "generated access coverage consequence does not match the locally derived matcher consequence"
        );
    }
    if serde_json::to_value(&normalized).context("encode normalized proposed access coverage")?
        != *value
    {
        bail!("proposed access coverage is not in normalized form");
    }
    Ok(normalized)
}

/// One sentence of operator guidance for a terminal synthesis-gate rejection.
/// The operator wrote prose and the model wrote the rejected artifact, so the
/// guidance names the prose change that steers the next synthesis away from
/// the failure class. Keyed by substring of the gate's own error text because
/// gate rejections are `anyhow` strings, not typed kinds. `None` for a
/// rejection class with no prose-level correction.
pub fn gate_rejection_guidance(reason: &str) -> Option<&'static str> {
    const GUIDANCE: &[(&str, &str)] = &[
        (
            "too permissive",
            "name the exact allowed values in your prompt so the parameter can be enumerated",
        ),
        (
            "literal shell operator",
            "ask for a single command; chaining needs separate verbs",
        ),
        (
            "has no closed executable authority profile",
            "ask for an operation implemented by a profiled direct executable",
        ),
        (
            "interactive exec stream",
            "ask for non-interactive output, not a shell",
        ),
        (
            "but no template references",
            "either mention where the value is used or drop it from the prompt",
        ),
    ];
    GUIDANCE
        .iter()
        .find(|(needle, _)| reason.contains(needle))
        .map(|(_, guidance)| *guidance)
}

/// Safety gate for a verb `gating::allow_promotion` wants to append to the
/// catalog automatically, with no operator review, from repeated low-risk LLM
/// approvals. Deliberately stricter than `validate_synthesized_safety`, whose
/// output a human still reviews before it becomes `trusted`:
///
/// - `trusted` MUST be true (that is the entire point of promotion) and
///   `consequence` must not be `Irreversible` -- an irreversible verb holds
///   for operator approval regardless of `trusted`, so promoting one buys no
///   latency and only discards the per-instance LLM reasoning a human would
///   otherwise see in the hold queue.
/// - Model-generated rollback authority is never auto-promoted. Recoverable
///   candidates are declined here; caller-driven recoverable commands remain
///   under live inverse assessment or operator review.
/// - Every parameter pattern must be a plain alternation of the exact,
///   regex-escaped values observed in `evidence` (never a model-authored
///   regex) and every evidence sample must re-match its own template -- this
///   is enforced by the caller building the pattern this way in the first
///   place, verified here from scratch rather than trusted.
pub fn validate_auto_promoted_verb_safety(verb: &Verb, evidence: &[Vec<String>]) -> Result<()> {
    if !verb.trusted {
        bail!("an auto-promoted verb must be trusted (that is the point of promoting it)");
    }
    if verb.consequence == Reversibility::Irreversible {
        bail!(
            "an irreversible verb may never be auto-promoted: it always holds for operator \
             approval regardless of `trusted`, so promoting it only discards the per-instance \
             LLM reasoning a human reviewer would otherwise see"
        );
    }
    if verb.consequence == Reversibility::Recoverable {
        bail!(
            "a recoverable verb may not be auto-promoted; its rollback requires live assessment or operator review"
        );
    }
    if verb
        .coverage
        .iter()
        .any(|cell| !cell.environment.is_empty())
    {
        bail!("an auto-promoted verb may not authorize caller environment bindings");
    }
    if canonical_auto_promoted_consequence(verb) != verb.consequence {
        bail!(
            "auto-promoted verb '{}' consequence does not match its independently derived matcher safety",
            verb.name
        );
    }
    if !is_kebab_name(&verb.name) {
        bail!(
            "auto-promoted verb name '{}' must be kebab-case (^[a-z0-9][a-z0-9-]*$)",
            verb.name
        );
    }
    validate_binary_not_shell(&verb.binary, "auto-promoted verb")?;
    if command_contains_sensitive_literals(&verb.binary, &verb.args) {
        bail!("an auto-promoted verb may not contain literal credential argv");
    }
    for (pname, spec) in &verb.params {
        validate_auto_promoted_param_spec(pname, spec)?;
    }
    debug_assert_eq!(verb.consequence, Reversibility::Reversible);
    // Re-render every evidence sample against the verb's own template and
    // confirm it reproduces exactly that sample -- never trust that the
    // caller-supplied template and params actually correspond to the
    // evidence they were derived from.
    for sample in evidence {
        if command_contains_sensitive_literals(&verb.binary, sample) {
            bail!("auto-promotion evidence may not contain literal credential argv");
        }
        let rendered = render_args(&verb.args, &render_map_for(verb, sample)?, &verb.name)?;
        if &rendered != sample {
            bail!(
                "auto-promoted verb '{}' template does not reproduce its own evidence {:?} \
                 (rendered {:?}); refusing to promote",
                verb.name,
                sample,
                rendered
            );
        }
    }
    Ok(())
}

/// Validate the subset of promotion safety that can be proven from a durable
/// catalog row without replaying model evidence. Durable auto-promotion is
/// deliberately narrower than the in-memory evidence proof: it admits only
/// the mechanically generated preauthorized read shape and never persists a
/// model-proposed rollback or caller-controlled boundary.
pub fn validate_auto_promoted_verb_durable_safety(verb: &Verb) -> Result<()> {
    validate_auto_promoted_verb_safety(verb, &[])?;
    if verb.revert.is_some() {
        bail!(
            "auto-promoted verb '{}' may not persist rollback authority",
            verb.name
        );
    }
    let referenced: BTreeSet<String> = verb
        .args
        .iter()
        .flat_map(|token| placeholders(token))
        .collect();
    if referenced.len() != verb.params.len() {
        bail!(
            "auto-promoted verb '{}' durable matcher must reference every declared parameter",
            verb.name
        );
    }
    for pname in &referenced {
        let spec = verb.params.get(pname).ok_or_else(|| {
            anyhow::anyhow!(
                "auto-promoted verb '{}' durable matcher references undeclared parameter '{}'",
                verb.name,
                pname
            )
        })?;
        if !spec.required || spec.default.is_some() {
            bail!(
                "auto-promoted verb '{}' durable parameter '{}' must be required and have no default",
                verb.name,
                pname
            );
        }
        let literals = validate_auto_promoted_param_spec(pname, spec).with_context(|| {
            format!(
                "auto-promoted verb '{}' durable parameter '{}' is invalid",
                verb.name, pname
            )
        })?;
        let canonical_pattern = format!(
            "^({})$",
            literals
                .iter()
                .map(|value| regex::escape(value))
                .collect::<Vec<_>>()
                .join("|")
        );
        if spec.pattern_text() != canonical_pattern {
            bail!(
                "auto-promoted verb '{}' durable parameter '{}' pattern does not match the generator-canonical exact pattern",
                verb.name,
                pname
            );
        }
        if spec.allow_dash != literals.iter().any(|value| value.starts_with('-')) {
            bail!(
                "auto-promoted verb '{}' durable parameter '{}' has inconsistent allow_dash generator metadata",
                verb.name,
                pname
            );
        }
    }
    let concrete_commands = enumerate_matcher_commands(verb).ok_or_else(|| {
        anyhow::anyhow!(
            "auto-promoted verb '{}' durable matcher must have a bounded finite command set",
            verb.name
        )
    })?;
    for args in concrete_commands {
        let mut concrete = verb.clone();
        concrete.args = args;
        concrete.params.clear();
        concrete.coverage.clear();
        if !synthesized_access_is_statically_read_only(&concrete) {
            bail!(
                "auto-promoted verb '{}' durable matcher expands to a command that is not independently read-only",
                verb.name
            );
        }
    }
    // Coverage is display and matching metadata, not an independent source
    // of executable consequence. Existing durable promotions may omit it;
    // when present, the ordinary catalog validator has already checked its
    // structure and the checks above reject caller-controlled environment
    // bindings. The executable matcher and its parameters remain the source
    // of the independently derived consequence.
    Ok(())
}

/// Re-derive the param map that would render `verb.args` back into `sample`,
/// by matching `sample` against the verb's own binary/args template. Used
/// only by `validate_auto_promoted_verb_safety` to prove the template it is
/// about to trust actually round-trips its own evidence.
fn render_map_for(verb: &Verb, sample: &[String]) -> Result<BTreeMap<String, String>> {
    let rendered = match_args_template(&verb.args, sample).ok_or_else(|| {
        anyhow::anyhow!("evidence sample {:?} does not match the template", sample)
    })?;
    Ok(rendered)
}

/// Validate a verb at load time. A param pattern must be fully anchored and
/// compile; every `{placeholder}` in the templates must name a declared param.
fn validate_verb(verb: &Verb) -> Result<()> {
    if verb.name.trim().is_empty() {
        bail!("verb has an empty name");
    }
    if verb.binary.trim().is_empty() {
        bail!("verb '{}' has an empty binary", verb.name);
    }
    if authorized_executable_profile(&verb.binary).is_none() {
        bail!(
            "verb '{}' forward command binary '{}' has no closed executable authority profile",
            verb.name,
            verb.binary
        );
    }
    if verb.credential_plan.as_deref().is_some_and(str::is_empty) {
        bail!("verb '{}' has an empty credential_plan", verb.name);
    }
    if verb.auto_promoted {
        if command_contains_sensitive_literals(&verb.binary, &verb.args) {
            bail!(
                "auto-promoted verb '{}' contains literal credential argv",
                verb.name
            );
        }
        if verb
            .revert
            .as_ref()
            .is_some_and(|revert| command_contains_sensitive_literals(&revert.binary, &revert.args))
        {
            bail!(
                "auto-promoted verb '{}' revert contains literal credential argv",
                verb.name
            );
        }
    }
    if !verb.coverage.is_empty() && verb.args.is_empty() && !verb.params.is_empty() {
        bail!(
            "verb '{}' uses generic coverage with parameters but has no argv template to capture them",
            verb.name
        );
    }
    if verb.args.is_empty()
        && !verb.coverage.is_empty()
        && executable_match_key(&verb.binary) == "ansible-playbook"
        && verb
            .coverage
            .iter()
            .any(|cell| cell.action != CoverageAction::Deny)
    {
        bail!(
            "verb '{}' uses generic ansible-playbook coverage without an operator-fixed playbook; use an exact argv template",
            verb.name
        );
    }
    validate_known_file_arguments(
        verb,
        &verb.binary,
        &verb.args,
        &verb.args,
        "forward command",
    )?;
    if verb.hold || verb.consequence != Reversibility::Reversible {
        validate_catalog_delayed_authority(
            &verb.binary,
            &verb.args,
            DelayedAuthoritySource::TypedVerb,
        )
        .with_context(|| {
            format!(
                "verb '{}' forward command cannot retain authority across an approval or containment gap",
                verb.name
            )
        })?;
    }
    if let Some(revert) = &verb.revert {
        if authorized_executable_profile(&revert.binary).is_none() {
            bail!(
                "verb '{}' revert command binary '{}' has no closed executable authority profile",
                verb.name,
                revert.binary
            );
        }
        validate_known_file_arguments(
            verb,
            &revert.binary,
            &revert.args,
            &revert.args,
            "revert command",
        )?;
        validate_catalog_delayed_authority(
            &revert.binary,
            &revert.args,
            DelayedAuthoritySource::TypedControl,
        )
        .with_context(|| {
            format!(
                "verb '{}' revert command cannot retain authority across a containment gap",
                verb.name
            )
        })?;
    }
    for (pname, spec) in &verb.params {
        if spec.value_type() == ParamValueType::SingleArgv
            && !matches!(spec.max_length(), Some(1..=MAX_SINGLE_ARGV_LENGTH))
        {
            bail!(
                "verb '{}' param '{}': single_argv requires max_length between 1 and {}",
                verb.name,
                pname,
                MAX_SINGLE_ARGV_LENGTH
            );
        }
        if !(spec.pattern_text().starts_with('^') && spec.pattern_text().ends_with('$')) {
            bail!(
                "verb '{}' param '{}': pattern must be fully anchored (^...$), got {:?}",
                verb.name,
                pname,
                spec.pattern_text()
            );
        }
        // Compile the anchored form so an invalid regex - or one whose
        // alternation would escape the anchors - is rejected at load time.
        compile_anchored(spec.pattern_text()).with_context(|| {
            format!(
                "verb '{}' param '{}' has an invalid regex",
                verb.name, pname
            )
        })?;
        if let Some(default) = spec.default.as_deref() {
            if spec
                .max_length()
                .is_some_and(|maximum| default.chars().count() > maximum)
            {
                bail!(
                    "verb '{}' param '{}': default exceeds max_length",
                    verb.name,
                    pname
                );
            }
            if spec.value_type() == ParamValueType::SingleArgv {
                validate_single_argv_value(pname, default).with_context(|| {
                    format!(
                        "verb '{}' param '{}' has an invalid default",
                        verb.name, pname
                    )
                })?;
            }
        }
    }
    // Every placeholder referenced by the templates must be a declared param,
    // and every declared param must be referenced by some template token: an
    // unused declaration would validate an invocation value that silently never
    // reaches the rendered command.
    let mut tokens: Vec<&String> = vec![&verb.binary];
    tokens.extend(verb.args.iter());
    if let Some(rev) = &verb.revert {
        tokens.push(&rev.binary);
        tokens.extend(rev.args.iter());
    }
    let mut referenced: BTreeSet<String> = BTreeSet::new();
    for tok in tokens {
        for placeholder in placeholders(tok) {
            if !verb.params.contains_key(&placeholder) {
                bail!(
                    "verb '{}' template references undeclared param '{{{}}}'",
                    verb.name,
                    placeholder
                );
            }
            referenced.insert(placeholder);
        }
    }
    for pname in verb.params.keys() {
        if !referenced.contains(pname) {
            bail!(
                "verb '{}' declares parameter '{}' but no template references {{{}}}",
                verb.name,
                pname,
                pname
            );
        }
    }
    let mut cell_names = BTreeSet::new();
    for cell in &verb.coverage {
        if verb.baseline
            && !verb.auto_promoted
            && matches!(cell.action, CoverageAction::Deny)
            && !cell.sticky
        {
            bail!(
                "verb '{}' coverage cell '{}': baseline deny coverage must be sticky",
                verb.name,
                cell.name
            );
        }
        if cell.name.trim().is_empty() {
            bail!(
                "verb '{}' has a coverage cell with an empty name",
                verb.name
            );
        }
        if !cell_names.insert(cell.name.clone()) {
            bail!(
                "verb '{}' has duplicate coverage cell name '{}'",
                verb.name,
                cell.name
            );
        }
        if !cell.command_path.is_empty() {
            let binary = executable_match_key(&verb.binary);
            let known = match binary.as_str() {
                "kubectl" => KUBECTL_BUILTIN_SUBCOMMANDS,
                "helm" => HELM_BUILTIN_SUBCOMMANDS,
                _ => {
                    bail!(
                        "verb '{}' coverage cell '{}': command_path is available only for kubectl and Helm",
                        verb.name,
                        cell.name
                    )
                }
            };
            if verb.args.is_empty()
                && cell.action != CoverageAction::Deny
                && (!known.contains(&cell.command_path[0].as_str())
                    || cell
                        .command_path
                        .iter()
                        .any(|token| token.is_empty() || token.starts_with('-')))
            {
                bail!(
                    "verb '{}' coverage cell '{}': command_path must begin with a recognized local subcommand and contain only non-option tokens",
                    verb.name,
                    cell.name
                );
            }
            if verb.args.is_empty()
                && cell.action != CoverageAction::Deny
                && binary == "helm"
                && HELM_COMMANDS_REQUIRING_EXACT_FILE_AUTHORITY
                    .contains(&cell.command_path[0].as_str())
            {
                bail!(
                    "verb '{}' coverage cell '{}': Helm command '{}' requires an exact argv template because its positional grammar can read or mutate local authority",
                    verb.name,
                    cell.name,
                    cell.command_path[0]
                );
            }
        }
        if verb.args.is_empty() && cell.command_path.is_empty() {
            let binary = executable_match_key(&verb.binary);
            let known = match binary.as_str() {
                "kubectl" => Some(KUBECTL_BUILTIN_SUBCOMMANDS),
                "helm" => Some(HELM_BUILTIN_SUBCOMMANDS),
                _ => None,
            };
            if let Some(known) = known {
                let inferred_commands = cell
                    .required_args
                    .iter()
                    .filter(|argument| known.contains(&argument.as_str()))
                    .collect::<Vec<_>>();
                if cell.action != CoverageAction::Deny
                    && (cell.action == CoverageAction::Preauthorized
                        || inferred_commands.len() != 1)
                {
                    bail!(
                        "verb '{}' coverage cell '{}': preauthorized generic kubectl and Helm coverage must declare command_path; evaluate and deny cells may instead require exactly one recognized local subcommand",
                        verb.name,
                        cell.name
                    );
                }
                if cell.action != CoverageAction::Deny
                    && binary == "helm"
                    && HELM_COMMANDS_REQUIRING_EXACT_FILE_AUTHORITY
                        .contains(&inferred_commands[0].as_str())
                {
                    bail!(
                        "verb '{}' coverage cell '{}': Helm command '{}' requires an exact argv template because its positional grammar can read or mutate local authority",
                        verb.name,
                        cell.name,
                        inferred_commands[0]
                    );
                }
            }
        }
        if matches!(cell.action, CoverageAction::Preauthorized) && cell.override_marker.is_some() {
            bail!(
                "verb '{}' coverage cell '{}': only evaluate or deny cells may declare an override_marker",
                verb.name,
                cell.name
            );
        }
        if !verb.baseline && cell.override_marker.is_some() {
            bail!(
                "verb '{}' coverage cell '{}': only baseline verbs may declare override markers",
                verb.name,
                cell.name
            );
        }
        if matches!(cell.action, CoverageAction::Preauthorized) && !verb.trusted {
            bail!(
                "verb '{}' coverage cell '{}': preauthorized coverage requires trusted: true",
                verb.name,
                cell.name
            );
        }
        if cell
            .override_marker
            .as_deref()
            .is_some_and(|marker| !valid_override_marker(marker))
        {
            bail!(
                "verb '{}' coverage cell '{}': override_marker must begin with an ASCII letter or digit and contain only letters, digits, '.', '_', ':', '/', or '-'",
                verb.name,
                cell.name
            );
        }
        if verb.auto_promoted && cell.override_marker.is_some() {
            bail!(
                "auto-promoted verb '{}' may not mint override markers",
                verb.name
            );
        }
        let required = cell.required_args.iter().collect::<BTreeSet<_>>();
        let forbidden = cell.forbidden_args.iter().collect::<BTreeSet<_>>();
        if required.len() != cell.required_args.len()
            || forbidden.len() != cell.forbidden_args.len()
        {
            bail!(
                "verb '{}' coverage cell '{}': required_args and forbidden_args may not contain duplicates",
                verb.name,
                cell.name
            );
        }
        if !required.is_disjoint(&forbidden) {
            bail!(
                "verb '{}' coverage cell '{}': an argv element may not be both required and forbidden",
                verb.name,
                cell.name
            );
        }
        let option_selectors = cell
            .options
            .iter()
            .map(constraint_selector)
            .collect::<BTreeSet<_>>();
        if option_selectors.len() != cell.options.len() {
            bail!(
                "verb '{}' coverage cell '{}': option constraints may not repeat the same selector",
                verb.name,
                cell.name
            );
        }
        for constraint in cell
            .options
            .iter()
            .chain(cell.target.iter())
            .chain(cell.inventory.iter())
            .chain(cell.namespace.iter())
            .chain(cell.fanout.iter().map(|fanout| &fanout.selector))
        {
            validate_value_constraint(&verb.name, &cell.name, constraint)?;
        }
        if let Some(inventory) = &cell.inventory {
            validate_inventory_constraint_paths(verb, cell, inventory)?;
        }
        if let Some(cwd) = &cell.cwd {
            validate_coverage_cwd(&verb.name, &cell.name, cwd)?;
        }
        if let Some(fanout) = &cell.fanout {
            if fanout.max == 0 {
                bail!(
                    "verb '{}' coverage cell '{}': fanout max must be greater than zero",
                    verb.name,
                    cell.name
                );
            }
            if fanout.separator.is_empty() {
                bail!(
                    "verb '{}' coverage cell '{}': fanout separator may not be empty",
                    verb.name,
                    cell.name
                );
            }
        }
        if matches!((cell.min_args, cell.max_args), (Some(min), Some(max)) if min > max) {
            bail!(
                "verb '{}' coverage cell '{}': min_args cannot exceed max_args",
                verb.name,
                cell.name
            );
        }
        let mut environment_bindings = BTreeSet::new();
        for constraint in &cell.environment {
            if !valid_environment_name(&constraint.name) {
                bail!(
                    "verb '{}' coverage cell '{}': invalid environment variable name '{}'",
                    verb.name,
                    cell.name,
                    constraint.name
                );
            }
            if !environment_bindings.insert((constraint.source, constraint.name.as_str())) {
                bail!(
                    "verb '{}' coverage cell '{}': duplicate {:?} environment binding '{}'",
                    verb.name,
                    cell.name,
                    constraint.source,
                    constraint.name
                );
            }
            if constraint.values.iter().any(String::is_empty) {
                bail!(
                    "verb '{}' coverage cell '{}': environment allowed values may not be empty",
                    verb.name,
                    cell.name
                );
            }
            if constraint.values.iter().collect::<BTreeSet<_>>().len() != constraint.values.len() {
                bail!(
                    "verb '{}' coverage cell '{}': environment allowed values may not contain duplicates",
                    verb.name,
                    cell.name
                );
            }
            if let Some(pattern) = constraint.pattern.as_deref() {
                if !(pattern.starts_with('^') && pattern.ends_with('$')) {
                    bail!(
                        "verb '{}' coverage cell '{}': environment pattern for '{}' must be fully anchored (^...$)",
                        verb.name,
                        cell.name,
                        constraint.name
                    );
                }
                compile_anchored(pattern).with_context(|| {
                    format!(
                        "verb '{}' coverage cell '{}' has an invalid environment pattern for '{}'",
                        verb.name, cell.name, constraint.name
                    )
                })?;
            }
            validate_tool_environment_constraint(verb, cell, constraint)?;
        }
    }
    Ok(())
}

fn validate_coverage_cwd(verb: &str, cell: &str, cwd: &Path) -> Result<()> {
    if cwd.as_os_str().is_empty() || !cwd.is_absolute() {
        bail!(
            "verb '{}' coverage cell '{}': cwd must be an absolute canonical directory",
            verb,
            cell
        );
    }
    let canonical = std::fs::canonicalize(cwd).with_context(|| {
        format!(
            "verb '{}' coverage cell '{}': cannot canonicalize cwd '{}'",
            verb,
            cell,
            cwd.display()
        )
    })?;
    if canonical != cwd {
        bail!(
            "verb '{}' coverage cell '{}': cwd '{}' is not canonical (use '{}')",
            verb,
            cell,
            cwd.display(),
            canonical.display()
        );
    }
    if !std::fs::metadata(cwd)
        .with_context(|| {
            format!(
                "verb '{}' coverage cell '{}': cannot stat cwd '{}'",
                verb,
                cell,
                cwd.display()
            )
        })?
        .is_dir()
    {
        bail!(
            "verb '{}' coverage cell '{}': cwd '{}' is not a directory",
            verb,
            cell,
            cwd.display()
        );
    }
    Ok(())
}

fn normalize_operator_boundaries(verb: &mut Verb) {
    if !verb.baseline || verb.auto_promoted || verb.promotion_stamp.is_some() {
        return;
    }
    for cell in &mut verb.coverage {
        if matches!(cell.action, CoverageAction::Deny) {
            cell.sticky = true;
        }
    }
}

fn valid_override_marker(marker: &str) -> bool {
    let mut chars = marker.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric())
        && chars.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '/' | '-')
        })
}

fn valid_environment_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn validate_value_constraint(verb: &str, cell: &str, constraint: &ValueConstraint) -> Result<()> {
    if constraint.position.is_some() != constraint.options.is_empty() {
        bail!(
            "verb '{}' coverage cell '{}': a value constraint must set exactly one of position or options",
            verb,
            cell
        );
    }
    if constraint
        .options
        .iter()
        .any(|option| !option.starts_with('-') || option.contains('='))
    {
        bail!(
            "verb '{}' coverage cell '{}': option selectors must begin with '-' and may not contain '='",
            verb,
            cell
        );
    }
    let unique_options = constraint.options.iter().collect::<BTreeSet<_>>();
    if unique_options.len() != constraint.options.len() {
        bail!(
            "verb '{}' coverage cell '{}': option selectors may not contain duplicates",
            verb,
            cell
        );
    }
    if constraint.values.iter().any(|value| value.is_empty()) {
        bail!(
            "verb '{}' coverage cell '{}': allowed values may not be empty",
            verb,
            cell
        );
    }
    if !constraint.allow_dash && constraint.values.iter().any(|value| value.starts_with('-')) {
        bail!(
            "verb '{}' coverage cell '{}': dash-prefixed allowed values require allow_dash: true",
            verb,
            cell
        );
    }
    let unique_values = constraint.values.iter().collect::<BTreeSet<_>>();
    if unique_values.len() != constraint.values.len() {
        bail!(
            "verb '{}' coverage cell '{}': allowed values may not contain duplicates",
            verb,
            cell
        );
    }
    Ok(())
}

/// Compile a parameter pattern as a fully-anchored, full-string regex. The
/// operator's own outer `^`/`$` are stripped and the pattern is wrapped in
/// `^(?:...)$`, so a top-level alternation (e.g. `^[a-z]+$|x`) cannot introduce
/// an unanchored branch that `is_match` would satisfy on a substring.
fn compile_anchored(pattern: &str) -> Result<Regex> {
    let inner = pattern.strip_prefix('^').unwrap_or(pattern);
    let inner = inner.strip_suffix('$').unwrap_or(inner);
    Regex::new(&format!("^(?:{})$", inner)).map_err(|e| anyhow::anyhow!(e))
}

/// Extract `{name}` placeholders from a template token.
fn placeholders(token: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = token.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            if let Some(end) = token[i + 1..].find('}') {
                let name = &token[i + 1..i + 1 + end];
                if valid_placeholder_name(name) {
                    out.push(name.to_string());
                }
                i = i + 1 + end + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn valid_placeholder_name(name: &str) -> bool {
    let mut characters = name.chars();
    characters
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic() || character == '_')
        && characters
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
}

/// Render a single template token by substituting all `{name}` placeholders.
/// A token is rendered as exactly one argv element. Literal (non-placeholder)
/// text is copied as whole `str` slices so multi-byte UTF-8 passes through
/// unchanged.
fn render_token(token: &str, params: &BTreeMap<String, String>, verb: &str) -> Result<String> {
    let mut out = String::new();
    let mut rest = token;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        if let Some(close) = after.find('}') {
            let name = &after[..close];
            if valid_placeholder_name(name) {
                let value = params.get(name).ok_or_else(|| {
                    anyhow::anyhow!("verb '{}' missing value for '{{{}}}'", verb, name)
                })?;
                out.push_str(value);
            } else {
                out.push('{');
                out.push_str(name);
                out.push('}');
            }
            rest = &after[close + 1..];
        } else {
            // Unmatched '{': copy it literally and continue past it.
            out.push('{');
            rest = after;
        }
    }
    out.push_str(rest);
    Ok(out)
}

fn render_args(
    templates: &[String],
    params: &BTreeMap<String, String>,
    verb: &str,
) -> Result<Vec<String>> {
    templates
        .iter()
        .map(|t| render_token(t, params, verb))
        .collect()
}

/// Reverse-match a concrete argv against a verb's template tokens, extracting
/// parameter values. Requires the exact same arity (no variadic templates): a
/// template token with no placeholder must equal the observed token exactly;
/// one with a single placeholder yields a value by stripping the template's
/// literal prefix/suffix from the observed token. A token with more than one
/// placeholder is not reverse-matchable and always fails the match (it
/// remains invocable normally via an explicit `--verb` call, which resolves
/// params by name rather than by position). The same parameter name appearing
/// in more than one token must extract the same value everywhere, or the
/// match fails.
fn match_args_template(
    templates: &[String],
    observed: &[String],
) -> Option<BTreeMap<String, String>> {
    if templates.len() != observed.len() {
        return None;
    }
    let mut params: BTreeMap<String, String> = BTreeMap::new();
    for (template, value) in templates.iter().zip(observed.iter()) {
        let names = placeholders(template);
        match names.len() {
            0 => {
                if template != value {
                    return None;
                }
            }
            1 => {
                let name = &names[0];
                let marker = format!("{{{name}}}");
                let idx = template.find(marker.as_str())?;
                let prefix = &template[..idx];
                let suffix = &template[idx + marker.len()..];
                if value.len() < prefix.len() + suffix.len() {
                    return None;
                }
                if !value.starts_with(prefix) || !value.ends_with(suffix) {
                    return None;
                }
                let extracted = &value[prefix.len()..value.len() - suffix.len()];
                match params.get(name) {
                    Some(existing) if existing != extracted => return None,
                    Some(_) => {}
                    None => {
                        params.insert(name.clone(), extracted.to_string());
                    }
                }
            }
            _ => return None,
        }
    }
    Some(params)
}

impl VerbCatalog {
    fn same_file_generation(&self, other: &Self) -> bool {
        match (&self.snapshot, &other.snapshot) {
            (Some(left), Some(right)) => left.same_authority(right),
            (None, None) => true,
            _ => false,
        }
    }

    fn same_catalog_epoch(&self, other: &Self) -> bool {
        self.same_file_generation(other)
            && self.version == other.version
            && serde_json::to_vec(&self.verbs).ok() == serde_json::to_vec(&other.verbs).ok()
    }
}

impl AsyncDurableStore for VerbCatalog {
    fn authority_name(&self) -> &'static str {
        "verb catalog"
    }

    fn durable_path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    fn same_durable_snapshot(&self, snapshot: &LearningFileSnapshot) -> bool {
        self.snapshot
            .as_ref()
            .is_some_and(|current| current.same_authority(snapshot))
    }

    fn same_in_memory_epoch(&self, other: &Self) -> bool {
        self.same_catalog_epoch(other)
    }

    fn adopt_async_result(&mut self, baseline: &Self, result: Self) -> Result<()> {
        if self.same_catalog_epoch(&result) {
            return Ok(());
        }
        if self.same_catalog_epoch(baseline) || self.same_file_generation(baseline) {
            return self.adopt_refreshed_file_authority(result);
        }
        if self.same_file_generation(&result) {
            return Ok(());
        }
        anyhow::bail!("verb catalog authority changed during asynchronous file I/O")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_CATALOG_YAML: &str = r#"
verbs:
  - name: scale-deployment
    description: Scale a Kubernetes deployment
    binary: kubectl
    args: ["scale", "deployment/{name}", "--replicas=2", "-n", "fixture"]
    params:
      name: { pattern: "^[a-z0-9-]+$", required: true }
    consequence: recoverable
    revert: { binary: kubectl, args: ["scale", "deployment/{name}", "--replicas=1", "-n", "fixture"] }
    trusted: true
  - name: tail-log
    binary: tail
    args: ["-n", "{lines}", "{path}"]
    params:
      lines: { pattern: "^[0-9]{1,5}$" }
      path: { pattern: __NATIVE_LOG_PATH_PATTERN__ }
    consequence: reversible
"#;

    fn native_absolute_fixture_path(name: &str) -> String {
        let path = std::env::temp_dir().join("guard-verb-fixtures").join(name);
        assert!(
            path.is_absolute(),
            "fixture path must be host-native and absolute"
        );
        path.to_string_lossy().into_owned()
    }

    fn serialized_yaml_inline<T: serde::Serialize + ?Sized>(value: &T) -> String {
        serde_json::to_string(value).expect("serialize fixture value as inline YAML")
    }

    fn fixture_catalog_yaml() -> String {
        let messages = native_absolute_fixture_path("messages.log");
        let system = native_absolute_fixture_path("system.log");
        let pattern = format!(
            "^({}|{})$",
            regex::escape(&messages),
            regex::escape(&system)
        );
        FIXTURE_CATALOG_YAML.replace(
            "__NATIVE_LOG_PATH_PATTERN__",
            &serialized_yaml_inline(&pattern),
        )
    }

    fn fixture_catalog() -> VerbCatalog {
        VerbCatalog::from_yaml(&fixture_catalog_yaml()).expect("host-native fixture catalog loads")
    }

    fn params(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn catalog_lint_collects_named_findings_across_verbs() {
        let report = VerbCatalog::lint_yaml(
            r#"
verbs:
  - name: inspect-first
    binary: fixturectl
    args: ["show", "{target}"]
    params:
      target: { pattern: "[a-z]+" }
    consequence: reversible
  - name: inspect-second
    binary: fixturectl
    args: ["show", "{resource}"]
    params:
      resource: { pattern: "[0-9]+" }
    consequence: reversible
"#,
        );

        assert_eq!(report.findings.len(), 2, "{:#?}", report.findings);
        for (verb, parameter) in [("inspect-first", "target"), ("inspect-second", "resource")] {
            let finding = report
                .findings
                .iter()
                .find(|finding| finding.verb == verb)
                .unwrap_or_else(|| panic!("missing finding for {verb}"));
            assert!(finding.message.contains(verb), "{}", finding.message);
            assert!(finding.message.contains(parameter), "{}", finding.message);
        }
    }

    #[test]
    fn catalog_lint_rejects_commands_without_delayed_authority() {
        let report = VerbCatalog::lint_yaml(
            r#"
verbs:
  - name: restart-service
    binary: systemctl
    args: ["restart", "{unit}"]
    params:
      unit: { pattern: "^[a-z0-9.-]+$" }
    consequence: recoverable
    revert: { binary: systemctl, args: ["stop", "{unit}"] }
  - name: unsafe-rollback
    binary: kubectl
    args: ["scale", "deployment/web", "--replicas=2", "-n", "fixture"]
    consequence: recoverable
    revert: { binary: systemctl, args: ["restart", "fixture.service"] }
"#,
        );

        assert_eq!(report.findings.len(), 2, "{:#?}", report.findings);
        assert!(report.findings.iter().any(|finding| {
            finding.verb == "restart-service"
                && finding.message.contains("forward command")
                && finding.message.contains("non-starting")
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.verb == "unsafe-rollback"
                && finding.message.contains("revert command")
                && finding.message.contains("non-starting")
        }));
    }

    #[test]
    fn catalog_lint_fix_is_explicit_and_round_trips() {
        let directory = crate::learned_rules::authority_tempdir();
        let path = directory.path().join("verbs.yaml");
        let original = r#"metadata: preserved
verbs:
  - name: guarded-inspect
    binary: fixturectl
    consequence: reversible
    coverage:
      - name: blocked
        action: deny
"#;
        crate::learned_rules::write_authority_file(&path, original).unwrap();

        let pending = VerbCatalog::lint_file(&path, false).unwrap();
        assert!(pending.findings.is_empty());
        assert_eq!(pending.repairs.len(), 1);
        assert!(!pending.fixed);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);

        let fixed = VerbCatalog::lint_file(&path, true).unwrap();
        assert!(fixed.findings.is_empty());
        assert!(fixed.fixed);
        assert_eq!(fixed.repairs[0].verb, "guarded-inspect");
        let repaired = std::fs::read_to_string(&path).unwrap();
        assert!(repaired.contains("metadata: preserved"));
        assert!(repaired.contains("sticky: true"));

        let clean = VerbCatalog::lint_file(&path, false).unwrap();
        assert!(clean.findings.is_empty());
        assert!(clean.repairs.is_empty());
        assert!(!clean.fixed);
    }

    #[test]
    fn catalog_status_hash_is_short_and_content_sensitive() {
        let yaml = fixture_catalog_yaml();
        let first = VerbCatalog::from_yaml(&yaml).unwrap();
        let changed = VerbCatalog::from_yaml(&yaml.replace("tail-log", "show-log")).unwrap();

        assert_eq!(first.short_hash().len(), 12);
        assert_ne!(first.short_hash(), changed.short_hash());
        assert_eq!(first.changed_unix(), None);
    }

    #[test]
    fn loads_and_renders_a_verb() {
        let cat = fixture_catalog();
        assert_eq!(cat.names(), vec!["scale-deployment", "tail-log"]);
        let r = cat
            .render("scale-deployment", &params(&[("name", "web")]))
            .unwrap();
        assert_eq!(r.binary, "kubectl");
        assert_eq!(
            r.args,
            vec!["scale", "deployment/web", "--replicas=2", "-n", "fixture"]
        );
        assert_eq!(r.consequence, Reversibility::Recoverable);
        assert_eq!(
            r.revert,
            Some((
                "kubectl".to_string(),
                vec![
                    "scale".to_string(),
                    "deployment/web".to_string(),
                    "--replicas=1".to_string(),
                    "-n".to_string(),
                    "fixture".to_string(),
                ]
            ))
        );
        assert!(r.trusted);
    }

    #[test]
    fn shell_metacharacters_are_inert_single_argv() {
        // A param that somehow matched would still render as ONE argv element.
        // Here the pattern rejects it outright.
        let cat = fixture_catalog();
        let err = cat
            .render("scale-deployment", &params(&[("name", "web; invalid")]))
            .unwrap_err();
        assert!(err.to_string().contains("does not match"));
    }

    #[test]
    fn flag_injection_is_rejected() {
        // A value beginning with '-' must be refused (would be read as an argv flag).
        let yaml = r#"
verbs:
  - name: ping-host
    binary: ping
    args: ["-c", "1", "{host}"]
    params:
      host: { pattern: "^[-a-zA-Z0-9._]+$" }
    consequence: reversible
"#;
        let cat = VerbCatalog::from_yaml(yaml).unwrap();
        let err = cat
            .render("ping-host", &params(&[("host", "-o")]))
            .unwrap_err();
        assert!(err.to_string().contains("may not begin with '-'"));
        // A normal host renders fine.
        let ok = cat
            .render("ping-host", &params(&[("host", "example.com")]))
            .unwrap();
        assert_eq!(ok.args, vec!["-c", "1", "example.com"]);
    }

    #[test]
    fn unanchored_pattern_is_rejected_at_load() {
        let yaml = r#"
verbs:
  - name: bad
    binary: echo
    args: ["{x}"]
    params:
      x: { pattern: "[a-z]+" }
    consequence: reversible
"#;
        let err = VerbCatalog::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("anchored"));
    }

    #[test]
    fn undeclared_placeholder_is_rejected() {
        let yaml = r#"
verbs:
  - name: bad
    binary: echo
    args: ["{missing}"]
    consequence: reversible
"#;
        let err = VerbCatalog::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("undeclared param"));
    }

    #[test]
    fn shell_program_braces_remain_literal_argv() {
        let program = r#"/^[A-Za-z]/ {print $1}"#;
        assert!(placeholders(program).is_empty());
        assert_eq!(
            render_token(program, &BTreeMap::new(), "fixture").unwrap(),
            program
        );

        let mut verb = synth_verb("printf", None, false, "access-generated-fixture");
        verb.args = vec![program.to_string()];
        let normalized = normalize_generated_access_verb(verb).unwrap();
        assert_eq!(normalized.args, vec![program]);
    }

    #[test]
    fn unknown_param_rejected_at_render() {
        let cat = fixture_catalog();
        let err = cat
            .render("tail-log", &params(&[("lines", "10"), ("bogus", "x")]))
            .unwrap_err();
        assert!(err.to_string().contains("no parameter"));
    }

    #[test]
    fn missing_required_param_rejected() {
        let cat = fixture_catalog();
        let err = cat.render("scale-deployment", &params(&[])).unwrap_err();
        assert!(err.to_string().contains("requires parameter"));
    }

    #[test]
    fn version_changes_with_content() {
        let yaml = fixture_catalog_yaml();
        let a = VerbCatalog::from_yaml(&yaml).unwrap();
        let b = VerbCatalog::from_yaml(&format!("{yaml}\n# edit")).unwrap();
        assert_ne!(a.version(), b.version());
    }

    #[test]
    fn alternation_cannot_escape_anchors() {
        // This pattern passes the textual ^...$ check but, parsed as
        // (^safe$)|(evil.*$), has an unanchored second branch. Under a plain
        // is_match a value like "x evil" would match the bare `evil.*$` branch
        // anywhere; the anchored wrapper forces a full-string match and rejects.
        let yaml = r#"
verbs:
  - name: tricky
    binary: echo
    args: ["{x}"]
    params:
      x: { pattern: "^safe$|evil.*$" }
    consequence: reversible
    trusted: true
"#;
        let cat = VerbCatalog::from_yaml(yaml).unwrap();
        assert!(
            cat.render("tricky", &params(&[("x", "x evil; rm -rf /")]))
                .is_err(),
            "alternation must not let a substring escape the anchors"
        );
        // Genuine full-string matches still pass.
        assert!(cat.render("tricky", &params(&[("x", "safe")])).is_ok());
    }

    #[test]
    fn non_ascii_literal_template_renders_intact() {
        let yaml = r#"
verbs:
  - name: accented
    binary: echo
    args: ["café-{n}"]
    params:
      n: { pattern: "^[0-9]+$" }
    consequence: reversible
    trusted: true
"#;
        let cat = VerbCatalog::from_yaml(yaml).unwrap();
        let r = cat.render("accented", &params(&[("n", "7")])).unwrap();
        assert_eq!(r.args, vec!["café-7"]);
    }

    #[test]
    fn duplicate_names_rejected() {
        let yaml = r#"
verbs:
  - name: dup
    binary: echo
    consequence: reversible
  - name: dup
    binary: cat
    consequence: reversible
"#;
        let err = VerbCatalog::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn append_verb_persists_provenance_and_pins() {
        let dir = crate::learned_rules::authority_tempdir();
        let path = dir.path().join("verbs.yaml");
        crate::learned_rules::write_authority_file(
            &path,
            "verbs:\n  - name: existing\n    binary: echo\n    consequence: reversible\n",
        )
        .unwrap();
        let mut cat = VerbCatalog::load(&path).unwrap();

        let mut p = BTreeMap::new();
        p.insert(
            "resource".to_string(),
            ParamSpec {
                pattern: "^(zones|networks|virtualmachines)$".to_string(),
                required: true,
                default: None,
                allow_dash: false,
            },
        );
        let verb = Verb {
            name: "fixture-list".to_string(),
            description: "Read-only CloudStack listing".to_string(),
            binary: "fixturectl".to_string(),
            args: vec!["list".to_string(), "{resource}".to_string()],
            baseline: true,
            coverage: Vec::new(),
            credential_plan: None,
            params: p,
            consequence: Reversibility::Reversible,
            revert: None,
            hold: false,
            trusted: true,
            prompt_context: None,
            exec_timeout_secs: None,
            source_prose: Some("read-only fixture listing of enumerated resources".to_string()),
            evidence: Some("read-only; resource pinned to an allow-list; reversible".to_string()),
            auto_promoted: false,
            promotion_stamp: None,
        };
        let mut runtime_saved = synth_verb("true", None, false, "grant-runtime");
        runtime_saved.name = "grant-runtime".to_string();
        cat.upsert_saved_grant_verb(runtime_saved).unwrap();
        let runtime_access = cat
            .canonical_generated_access_verb(toolbox_wrapper("^(status)$"))
            .unwrap();
        let runtime_access_name = runtime_access.name.clone();
        cat.upsert_access_verb(runtime_access).unwrap();
        cat.append_verb(&verb).unwrap();
        assert!(cat.get("grant-runtime").is_some());
        assert!(cat.get(&runtime_access_name).is_some());
        let durable_content = std::fs::read_to_string(&path).unwrap();
        assert!(!durable_content.contains("grant-runtime"));
        assert!(!durable_content.contains(&runtime_access_name));

        // Reload independently: persisted, provenance kept, pinning enforced.
        let reloaded = VerbCatalog::load(&path).unwrap();
        assert_ne!(cat.version(), reloaded.version());
        let refreshed = cat.refreshed_copy().unwrap();
        assert_eq!(cat.version(), refreshed.version());
        assert!(refreshed.get("grant-runtime").is_some());
        assert!(refreshed.get(&runtime_access_name).is_some());
        assert!(reloaded.names().contains(&"fixture-list".to_string()));
        assert!(reloaded.names().contains(&"existing".to_string()));
        let got = reloaded.get("fixture-list").unwrap();
        assert_eq!(
            got.source_prose.as_deref(),
            Some("read-only fixture listing of enumerated resources")
        );
        assert!(got.evidence.is_some());
        let r = reloaded
            .render("fixture-list", &params(&[("resource", "zones")]))
            .unwrap();
        assert_eq!(r.binary, "fixturectl");
        assert_eq!(r.args, vec!["list", "zones"]);
        assert!(reloaded
            .render("fixture-list", &params(&[("resource", "volumes")]))
            .is_err());
    }

    #[test]
    fn catalog_mutations_keep_runtime_overlays_out_of_the_durable_document() {
        let directory = crate::learned_rules::authority_tempdir();
        let path = directory.path().join("verbs.yaml");
        crate::learned_rules::write_authority_file(
            &path,
            r#"verbs:
  - name: editable
    binary: echo
    consequence: reversible
  - name: removable
    binary: true
    consequence: reversible
"#,
        )
        .unwrap();
        let mut catalog = VerbCatalog::load(&path).unwrap();
        let mut saved_grant = synth_verb("true", None, false, "grant-runtime");
        saved_grant.name = "grant-runtime".to_string();
        catalog.upsert_saved_grant_verb(saved_grant).unwrap();
        let access = catalog
            .canonical_generated_access_verb(toolbox_wrapper("^(status)$"))
            .unwrap();
        let access_name = access.name.clone();
        catalog.upsert_access_verb(access).unwrap();

        let original_digest = catalog.verb_definition_digest("editable").unwrap();
        let mut replacement = catalog.get("editable").unwrap().clone();
        replacement.description = "Edited operator verb".to_string();
        catalog
            .amend_verb_if_digest("editable", &original_digest, &replacement)
            .unwrap();
        assert!(catalog.get("grant-runtime").is_some());
        assert!(catalog.get(&access_name).is_some());

        catalog.delete_verb("removable").unwrap();
        assert!(catalog.get("grant-runtime").is_some());
        assert!(catalog.get(&access_name).is_some());
        assert!(catalog.delete_verb(&access_name).is_err());

        let durable_content = std::fs::read_to_string(&path).unwrap();
        assert!(!durable_content.contains("grant-runtime"));
        assert!(!durable_content.contains(&access_name));
        assert!(durable_content.contains("Edited operator verb"));
        assert!(!durable_content.contains("removable"));
    }

    #[test]
    fn append_verb_rejects_duplicate_and_invalid_without_writing() {
        let dir = crate::learned_rules::authority_tempdir();
        let path = dir.path().join("verbs.yaml");
        let initial = "verbs:\n  - name: dup\n    binary: echo\n    consequence: reversible\n";
        crate::learned_rules::write_authority_file(&path, initial).unwrap();
        let mut cat = VerbCatalog::load(&path).unwrap();

        let mk = |name: &str, pattern: Option<&str>| {
            let mut params = BTreeMap::new();
            let mut args = vec![];
            if let Some(pat) = pattern {
                params.insert(
                    "x".to_string(),
                    ParamSpec {
                        pattern: pat.to_string(),
                        required: true,
                        default: None,
                        allow_dash: false,
                    },
                );
                args.push("{x}".to_string());
            }
            Verb {
                name: name.to_string(),
                description: String::new(),
                binary: "echo".to_string(),
                args,
                baseline: true,
                coverage: Vec::new(),
                credential_plan: None,
                params,
                consequence: Reversibility::Reversible,
                revert: None,
                hold: false,
                trusted: false,
                prompt_context: None,
                exec_timeout_secs: None,
                source_prose: None,
                evidence: None,
                auto_promoted: false,
                promotion_stamp: None,
            }
        };

        // Duplicate name -> rejected.
        assert!(cat.append_verb(&mk("dup", None)).is_err());
        // Unanchored pattern -> rejected by validation.
        assert!(cat.append_verb(&mk("bad", Some("[a-z]+"))).is_err());
        // Neither failed append touched the file.
        assert_eq!(std::fs::read_to_string(&path).unwrap(), initial);

        let repairable_stale = "verbs:\n  - name: external\n    binary: echo\n    consequence: reversible\n    coverage:\n      - name: blocked\n        action: deny\n";
        crate::learned_rules::write_authority_file(&path, repairable_stale).unwrap();
        assert!(cat.append_verb(&mk("bad-stale", Some("[a-z]+"))).is_err());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            repairable_stale,
            "invalid append must not repair a stale catalog"
        );
        assert!(cat.append_verb(&mk("external", None)).is_err());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            repairable_stale,
            "duplicate append must not repair a stale catalog"
        );

        crate::learned_rules::write_authority_file(&path, "verbs: []\n").unwrap();
        cat.append_verb(&mk("dup", None)).unwrap();
        assert!(VerbCatalog::load(&path).unwrap().get("dup").is_some());
    }

    #[test]
    fn append_tolerates_bom_and_keeps_one_verbs_key() {
        let dir = crate::learned_rules::authority_tempdir();
        let path = dir.path().join("verbs.yaml");
        // Seed with a leading UTF-8 BOM, as a Windows editor or PowerShell's
        // utf8 mode would write it.
        let seed =
            "\u{feff}verbs:\n  - name: existing\n    binary: echo\n    consequence: reversible\n";
        crate::learned_rules::write_authority_file(&path, seed).unwrap();
        let mut cat = VerbCatalog::load(&path).unwrap();

        let v = Verb {
            name: "added".to_string(),
            description: String::new(),
            binary: "echo".to_string(),
            args: vec![],
            baseline: true,
            coverage: Vec::new(),
            credential_plan: None,
            params: BTreeMap::new(),
            consequence: Reversibility::Reversible,
            revert: None,
            hold: false,
            trusted: false,
            prompt_context: None,
            exec_timeout_secs: None,
            source_prose: None,
            evidence: None,
            auto_promoted: false,
            promotion_stamp: None,
        };
        cat.append_verb(&v).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            text.matches("verbs:").count(),
            1,
            "BOM must not cause a duplicate verbs: key"
        );
        assert!(
            !text.starts_with('\u{feff}'),
            "BOM should be stripped on write"
        );
        let reloaded = VerbCatalog::load(&path).unwrap();
        assert!(reloaded.names().contains(&"existing".to_string()));
        assert!(reloaded.names().contains(&"added".to_string()));
    }

    fn synth_verb(binary: &str, pattern: Option<&str>, trusted: bool, name: &str) -> Verb {
        let mut params = BTreeMap::new();
        let mut args = vec![];
        if let Some(p) = pattern {
            params.insert(
                "x".to_string(),
                ParamSpec {
                    pattern: p.to_string(),
                    required: true,
                    default: None,
                    allow_dash: false,
                },
            );
            args.push("{x}".to_string());
        }
        Verb {
            name: name.to_string(),
            description: String::new(),
            binary: binary.to_string(),
            args,
            baseline: true,
            coverage: Vec::new(),
            credential_plan: None,
            params,
            consequence: Reversibility::Reversible,
            revert: None,
            hold: false,
            trusted,
            prompt_context: None,
            exec_timeout_secs: None,
            source_prose: None,
            evidence: None,
            auto_promoted: false,
            promotion_stamp: None,
        }
    }

    #[test]
    fn successful_synthesis_canonicalizes_all_explanatory_metadata_before_identity() {
        let value = ["q", "7"].concat();
        let contaminated = format!("password={value}");
        let mut verb = synth_verb("fixturectl", Some("^(status)$"), false, "inspect-fixture");
        verb.description = contaminated.clone();
        verb.prompt_context = Some(contaminated.clone());
        verb.source_prose = Some(contaminated.clone());
        verb.evidence = Some(contaminated.clone());
        verb.coverage.push(VerbCoverageCell {
            name: "safe".to_string(),
            action: CoverageAction::Evaluate,
            command_path: Vec::new(),
            required_args: Vec::new(),
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
                source: contaminated.clone(),
                evidence: vec![contaminated.clone()],
                regime_stamp: "safe-regime".to_string(),
                prompt_stamp: "safe-prompt".to_string(),
                model_stamp: "safe-model".to_string(),
                generated_unix: 1,
                probes: vec![CoverageProbe {
                    dimension: contaminated.clone(),
                    args: vec!["status".to_string()],
                    expected_match: true,
                    observed_match: true,
                }],
                observation_replays: Vec::new(),
            }),
        });

        let canonical = canonicalize_synthesized_verb_envelope(verb).unwrap();
        validate_canonical_synthesized_verb_envelope(&canonical).unwrap();
        let serialized = serde_json::to_string(&canonical).unwrap();
        assert!(!serialized.contains(&value));
        let digest = canonical.definition_digest();
        let yaml = serde_yaml_ng::to_string(&CatalogFile {
            platform: None,
            verbs: vec![canonical],
        })
        .unwrap();
        let reloaded = VerbCatalog::from_yaml(&yaml).unwrap();
        let reloaded = reloaded.get("inspect-fixture").unwrap();
        assert_eq!(reloaded.definition_digest(), digest);
        assert!(!serde_json::to_string(reloaded).unwrap().contains(&value));
    }

    #[test]
    fn catalog_load_durably_repairs_synthesized_metadata_and_is_idempotent() {
        let value = ["q", "7"].concat();
        let contaminated = format!("password={value}");
        let mut verb = synth_verb("fixturectl", Some("^(status)$"), false, "inspect-fixture");
        verb.source_prose = Some(contaminated.clone());
        verb.evidence = Some(contaminated.clone());
        verb.promotion_stamp = Some("regime-safe".to_string());
        let yaml = serde_yaml_ng::to_string(&CatalogFile {
            platform: None,
            verbs: vec![verb],
        })
        .unwrap();
        let directory = crate::learned_rules::authority_tempdir();
        let path = directory.path().join("verbs.yaml");
        crate::learned_rules::write_authority_file(&path, yaml).unwrap();

        let mut first = VerbCatalog::load(&path).unwrap();
        let repaired = std::fs::read_to_string(&path).unwrap();
        assert!(!repaired.contains(&value));
        assert!(!serde_json::to_string(&first.list())
            .unwrap()
            .contains(&value));
        assert_eq!(
            first
                .get("inspect-fixture")
                .unwrap()
                .promotion_stamp
                .as_deref(),
            Some("regime-safe")
        );

        let second = VerbCatalog::load(&path).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), repaired);
        assert_eq!(first.list().len(), second.list().len());

        let appended = synth_verb("true", None, false, "safe-appended");
        first.append_verb(&appended).unwrap();
        assert!(!std::fs::read_to_string(path).unwrap().contains(&value));
    }

    #[test]
    fn safe_catalog_load_preserves_exact_bytes() {
        let yaml = "# operator comment\nverbs:\n  - name: safe\n    binary: true\n    consequence: reversible\n";
        let directory = crate::learned_rules::authority_tempdir();
        let path = directory.path().join("verbs.yaml");
        crate::learned_rules::write_authority_file(&path, yaml).unwrap();
        VerbCatalog::load(&path).unwrap();
        assert_eq!(std::fs::read_to_string(path).unwrap(), yaml);
    }

    #[test]
    fn immutable_catalog_load_creates_no_sibling_state_and_retains_no_live_path() {
        let yaml = "verbs:\n  - name: safe\n    binary: true\n    consequence: reversible\n";
        let directory = crate::learned_rules::authority_tempdir();
        let path = directory.path().join("verbs.yaml");
        crate::learned_rules::write_authority_file(&path, yaml).unwrap();

        let mut catalog = VerbCatalog::load_immutable(&path).unwrap();
        assert!(catalog.get("safe").is_some());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
        std::fs::write(&path, "verbs: []\n").unwrap();
        assert!(!catalog.reload_if_stale().unwrap());
        assert!(catalog.get("safe").is_some());
        assert!(catalog
            .append_verb(&synth_verb("true", None, false, "later"))
            .unwrap_err()
            .to_string()
            .contains("not backed by a file"));
    }

    #[test]
    fn immutable_catalog_lock_is_decoupled_from_catalog_storage() {
        let yaml = "verbs:\n  - name: safe\n    binary: true\n    consequence: reversible\n";
        let catalog_directory = crate::learned_rules::authority_tempdir();
        let runtime_directory = crate::learned_rules::authority_tempdir();
        let path = catalog_directory.path().join("verbs.yaml");
        let lock_path = runtime_directory.path().join("verbs.lock");
        crate::learned_rules::write_authority_file(&path, yaml).unwrap();

        let mut catalog = VerbCatalog::load_immutable_with_lock(&path, &lock_path).unwrap();
        assert!(catalog.get("safe").is_some());
        assert_eq!(
            std::fs::read_dir(catalog_directory.path()).unwrap().count(),
            1
        );
        assert!(lock_path.is_file());
        std::fs::write(&path, "verbs: []\n").unwrap();
        assert!(!catalog.reload_if_stale().unwrap());
        assert!(catalog.get("safe").is_some());
    }

    #[test]
    fn immutable_catalog_rejects_lock_path_that_is_the_catalog_before_mutation() {
        let yaml = "verbs:\n  - name: safe\n    binary: true\n    consequence: reversible\n";
        let directory = crate::learned_rules::authority_tempdir();
        let path = directory.path().join("verbs.yaml");
        crate::learned_rules::write_authority_file(&path, yaml).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
            let original_mode = std::fs::metadata(&path).unwrap().mode() & 0o777;
            let error = VerbCatalog::load_immutable_with_lock(&path, &path).unwrap_err();
            assert!(error
                .to_string()
                .contains("aliases the immutable authority"));
            assert_eq!(
                std::fs::metadata(&path).unwrap().mode() & 0o777,
                original_mode
            );
        }
        #[cfg(not(unix))]
        {
            let error = VerbCatalog::load_immutable_with_lock(&path, &path).unwrap_err();
            assert!(error
                .to_string()
                .contains("aliases the immutable authority"));
        }
        assert_eq!(std::fs::read_to_string(path).unwrap(), yaml);
    }

    #[cfg(unix)]
    #[test]
    fn immutable_catalog_rejects_hard_link_and_symbolic_link_lock_aliases() {
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

        let yaml = "verbs:\n  - name: safe\n    binary: true\n    consequence: reversible\n";
        let directory = crate::learned_rules::authority_tempdir();
        let path = directory.path().join("verbs.yaml");
        crate::learned_rules::write_authority_file(&path, yaml).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let original_mode = std::fs::metadata(&path).unwrap().mode() & 0o777;

        let hard_link = directory.path().join("verbs-hard-link.lock");
        std::fs::hard_link(&path, &hard_link).unwrap();
        let hard_link_error = VerbCatalog::load_immutable_with_lock(&path, &hard_link).unwrap_err();
        assert!(hard_link_error
            .to_string()
            .contains("aliases the immutable authority"));
        assert_eq!(
            std::fs::metadata(&path).unwrap().mode() & 0o777,
            original_mode
        );

        std::fs::remove_file(&hard_link).unwrap();
        let symbolic_link = directory.path().join("verbs-symbolic-link.lock");
        symlink(&path, &symbolic_link).unwrap();
        let symbolic_link_error =
            VerbCatalog::load_immutable_with_lock(&path, &symbolic_link).unwrap_err();
        assert!(symbolic_link_error
            .to_string()
            .contains("must not be a symbolic link"));
        assert_eq!(
            std::fs::metadata(&path).unwrap().mode() & 0o777,
            original_mode
        );
        assert_eq!(std::fs::read_to_string(path).unwrap(), yaml);
    }

    #[cfg(windows)]
    #[test]
    fn immutable_catalog_rejects_hard_link_lock_alias_on_windows() {
        let yaml = "verbs:\n  - name: safe\n    binary: true\n    consequence: reversible\n";
        let directory = crate::learned_rules::authority_tempdir();
        let path = directory.path().join("verbs.yaml");
        let lock_path = directory.path().join("verbs-hard-link.lock");
        crate::learned_rules::write_authority_file(&path, yaml).unwrap();
        std::fs::hard_link(&path, &lock_path).unwrap();

        let error = VerbCatalog::load_immutable_with_lock(&path, &lock_path).unwrap_err();
        assert!(error
            .to_string()
            .contains("aliases the immutable authority"));
        assert_eq!(std::fs::read_to_string(path).unwrap(), yaml);
    }

    #[test]
    fn immutable_catalog_rejects_required_repair_without_writing() {
        let value = ["q", "7"].concat();
        let mut verb = synth_verb("fixturectl", Some("^(status)$"), false, "inspect-fixture");
        verb.source_prose = Some(format!("password={value}"));
        let yaml = serde_yaml_ng::to_string(&CatalogFile {
            platform: None,
            verbs: vec![verb],
        })
        .unwrap();
        let directory = crate::learned_rules::authority_tempdir();
        let path = directory.path().join("verbs.yaml");
        crate::learned_rules::write_authority_file(&path, &yaml).unwrap();

        let error = VerbCatalog::load_immutable(&path).unwrap_err();
        assert!(error.to_string().contains("requires canonical repair"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), yaml);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn committed_catalog_repair_warning_adopts_only_verified_canonical_bytes() {
        let directory = crate::learned_rules::authority_tempdir();
        let path = directory.path().join("verbs.yaml");
        let canonical = "verbs: []\n";
        crate::learned_rules::write_authority_file(&path, canonical).unwrap();
        let snapshot = load_learning_file_snapshot(&path).unwrap();
        let warning = catalog_repair_warning(
            canonical,
            crate::learned_rules::LearningWriteOutcome::committed_with_warning_for_test(
                snapshot,
                anyhow::anyhow!("simulated cleanup warning"),
            ),
        )
        .unwrap();
        assert!(warning.is_some());
        assert!(VerbCatalog::from_yaml(canonical).is_ok());

        crate::learned_rules::write_authority_file(&path, "verbs:\n  - invalid\n").unwrap();
        let snapshot = load_learning_file_snapshot(&path).unwrap();
        assert!(catalog_repair_warning(
            canonical,
            crate::learned_rules::LearningWriteOutcome::committed_with_warning_for_test(
                snapshot,
                anyhow::anyhow!("simulated cleanup warning"),
            ),
        )
        .is_err());
    }

    #[test]
    fn stale_catalog_instances_reapply_nonconflicting_appends() {
        let directory = crate::learned_rules::authority_tempdir();
        let path = directory.path().join("verbs.yaml");
        crate::learned_rules::write_authority_file(&path, "verbs: []\n").unwrap();
        let mut first = VerbCatalog::load(&path).unwrap();
        let mut second = VerbCatalog::load(&path).unwrap();

        first
            .append_verb(&synth_verb(
                "fixturectl",
                Some("^(one)$"),
                false,
                "safe-one",
            ))
            .unwrap();
        second
            .append_verb(&synth_verb(
                "fixturectl",
                Some("^(two)$"),
                false,
                "safe-two",
            ))
            .unwrap();

        let loaded = VerbCatalog::load(&path).unwrap();
        assert!(loaded.get("safe-one").is_some());
        assert!(loaded.get("safe-two").is_some());
    }

    #[test]
    fn successor_catalog_commit_does_not_turn_the_first_commit_into_failure() {
        let directory = crate::learned_rules::authority_tempdir();
        let path = directory.path().join("verbs.yaml");
        crate::learned_rules::write_authority_file(&path, "verbs: []\n").unwrap();
        let mut first = VerbCatalog::load(&path).unwrap();
        let mut successor = VerbCatalog::load(&path).unwrap();
        let (committed, release) =
            crate::learned_rules::pause_post_commit_adoption_for_test("safe-race-first");
        let first_thread = std::thread::spawn(move || {
            first
                .append_verb(&synth_verb(
                    "fixturectl",
                    Some("^(first)$"),
                    false,
                    "safe-race-first",
                ))
                .unwrap();
            first
        });
        committed.wait();
        successor
            .append_verb(&synth_verb(
                "fixturectl",
                Some("^(second)$"),
                false,
                "safe-race-second",
            ))
            .unwrap();
        release.wait();
        let first = first_thread.join().unwrap();
        assert!(first.get("safe-race-first").is_some());

        let loaded = VerbCatalog::load(&path).unwrap();
        assert!(loaded.get("safe-race-first").is_some());
        assert!(loaded.get("safe-race-second").is_some());
    }

    #[test]
    fn sensitive_synthesized_name_fails_before_preview_or_catalog_load() {
        let value = ["q", "7"].concat();
        let mut verb = synth_verb("fixturectl", Some("^(status)$"), false, "safe");
        verb.name = format!("password={value}");
        verb.source_prose = Some("generated inspection".to_string());
        assert!(generated_authority_contains_sensitive_literal(&verb));
        assert!(VerbCatalog::for_admission_preview(&verb).is_err());

        let yaml = serde_yaml_ng::to_string(&CatalogFile {
            platform: None,
            verbs: vec![verb],
        })
        .unwrap();
        let directory = crate::learned_rules::authority_tempdir();
        let path = directory.path().join("verbs.yaml");
        crate::learned_rules::write_authority_file(&path, &yaml).unwrap();
        assert!(VerbCatalog::load(&path).is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), yaml);
    }

    #[test]
    fn generated_catalog_envelope_rejects_sensitive_stamps_and_unknown_metadata() {
        let value = ["q", "7"].concat();
        let mut verb = synth_verb("fixturectl", Some("^(status)$"), false, "safe");
        verb.promotion_stamp = Some(format!("password={value}"));
        assert!(canonicalize_generated_authority_envelope(verb.clone()).is_err());

        let yaml = serde_yaml_ng::to_string(&CatalogFile {
            platform: None,
            verbs: vec![verb],
        })
        .unwrap();
        assert!(VerbCatalog::from_yaml(&yaml).is_err());

        let unknown_nested = "verbs:\n  - name: safe\n    binary: true\n    consequence: reversible\n    future_metadata: true\n";
        assert!(VerbCatalog::from_yaml(unknown_nested).is_err());
        assert!(
            serde_yaml_ng::from_str::<FanoutConstraint>("max: 2\nfuture_metadata: true\n").is_err()
        );
    }

    #[test]
    fn synthesis_safety_gate_blocks_dangerous_shapes() {
        // Every unprofiled executable fails closed, including path and .exe forms.
        assert!(validate_synthesized_safety(&synth_verb("sh", Some("^.+$"), false, "x")).is_err());
        assert!(
            validate_synthesized_safety(&synth_verb("/bin/bash", Some("^x$"), false, "x")).is_err()
        );
        assert!(validate_synthesized_safety(&synth_verb(
            "PowerShell.exe",
            Some("^x$"),
            false,
            "x"
        ))
        .is_err());
        for binary in ["python3.12", "RUBY3.4.EXE", "timeout", "sudo"] {
            assert!(
                validate_synthesized_safety(&synth_verb(binary, Some("^x$"), false, "x")).is_err(),
                "{binary} must remain unprofiled"
            );
        }
        assert!(
            validate_synthesized_safety(&synth_verb("rm", None, false, "delete-fixture")).is_err()
        );
        // over-broad / whitespace-admitting patterns
        assert!(
            validate_synthesized_safety(&synth_verb("fixturectl", Some("^.+$"), false, "x"))
                .is_err()
        );
        assert!(validate_synthesized_safety(&synth_verb(
            "fixturectl",
            Some("^[a-z ]+$"),
            false,
            "x"
        ))
        .is_err());
        // trusted synthesized verb
        assert!(
            validate_synthesized_safety(&synth_verb("fixturectl", Some("^zones$"), true, "x"))
                .is_err()
        );
        // non-kebab name
        assert!(validate_synthesized_safety(&synth_verb(
            "fixturectl",
            Some("^zones$"),
            false,
            "Bad Name"
        ))
        .is_err());
        // good narrow read-only verbs pass
        assert!(validate_synthesized_safety(&synth_verb(
            "fixturectl",
            Some("^(zones|networks)$"),
            false,
            "fixture-list"
        ))
        .is_ok());
        assert!(validate_synthesized_safety(&synth_verb(
            "fixturectl",
            Some("^[a-f0-9-]{36}$"),
            false,
            "fixture-show"
        ))
        .is_ok());
        assert!(validate_synthesized_safety(&synth_verb(
            "kubectl",
            Some("^[a-z0-9-]{1,63}$"),
            false,
            "k-get"
        ))
        .is_err());
        let mut fixed_kubectl_read =
            synth_verb("kubectl", Some("^[a-z0-9-]{1,63}$"), false, "k-get");
        fixed_kubectl_read.args.insert(0, "get".to_string());
        assert!(validate_synthesized_safety(&fixed_kubectl_read).is_ok());

        let mut generated_marker = synth_verb("kubectl", None, false, "k-check");
        generated_marker.coverage.push(VerbCoverageCell {
            name: "review".to_string(),
            action: CoverageAction::Evaluate,
            command_path: Vec::new(),
            required_args: Vec::new(),
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
            override_marker: Some("operator:k-check".to_string()),
            sticky: true,
            provenance: None,
        });
        assert!(validate_synthesized_safety(&generated_marker).is_err());
    }

    #[test]
    fn synthesized_shell_operator_argv_element_is_rejected() {
        for operator in [";", "&&", "||", "|", ">", "<"] {
            let mut verb = synth_verb("kubectl", None, false, "k-chained");
            verb.args = args_vec(&["get", "pods", operator, "get", "nodes"]);
            let error = validate_synthesized_safety(&verb).unwrap_err();
            assert!(
                error.to_string().contains("literal shell operator"),
                "got: {error}"
            );
        }
        // Only a whole argv element equal to an operator is rejected; the
        // parameter-pattern gates govern embedded characters.
        let mut plain = synth_verb("kubectl", None, false, "k-wide");
        plain.args = args_vec(&["get", "pods", "-o", "wide"]);
        assert!(validate_synthesized_safety(&plain).is_ok());
    }

    #[test]
    fn synthesized_interactive_kubectl_exec_flags_are_rejected() {
        for flag in ["-i", "-t", "-it", "-ti", "--stdin", "--tty=true"] {
            let mut verb = synth_verb("kubectl", None, false, "k-exec");
            verb.args = args_vec(&["exec", flag, "deploy/tools", "--", "ceph", "status"]);
            let error = validate_synthesized_safety(&verb).unwrap_err();
            assert!(error.to_string().contains("interactive"), "got: {error}");
        }
        // Non-interactive exec passes the gate.
        let mut batch = synth_verb("kubectl", None, false, "k-exec-batch");
        batch.args = args_vec(&["exec", "deploy/tools", "--", "ceph", "status"]);
        assert!(validate_synthesized_safety(&batch).is_ok());
        // The flags matter only for kubectl exec; another binary keeps its
        // own semantics.
        let mut other = synth_verb("fixturectl", None, false, "fixture-exec");
        other.args = args_vec(&["exec", "-it", "target"]);
        assert!(validate_synthesized_safety(&other).is_ok());

        let mut bare_target = synth_verb("kubectl", None, false, "k-exec-bare");
        bare_target.args = args_vec(&["exec", "generated-tools-pod", "--", "ceph", "status"]);
        let error = validate_synthesized_safety(&bare_target).unwrap_err();
        assert!(
            error.to_string().contains("bare generated pod"),
            "got: {error}"
        );

        let mut packed = synth_verb("kubectl", None, false, "k-exec-packed");
        packed.args = args_vec(&["exec", "deploy/tools", "--", "ceph status"]);
        let error = validate_synthesized_safety(&packed).unwrap_err();
        assert!(
            error.to_string().contains("whitespace-free"),
            "got: {error}"
        );
    }

    #[test]
    fn file_paths_use_daemon_host_semantics() {
        let native = native_absolute_fixture_path("manifest.yaml");
        let native_modules = native_absolute_fixture_path("modules");
        let native_shared_modules = native_absolute_fixture_path("shared-modules");
        let native_list =
            std::env::join_paths([native_modules.as_str(), native_shared_modules.as_str()])
                .unwrap()
                .to_string_lossy()
                .into_owned();
        let native = native.as_str();
        let native_list = native_list.as_str();
        #[cfg(unix)]
        let (foreign, foreign_list) = (
            r"C:\caller\manifest.yaml",
            r"C:\caller\modules;D:\shared\modules",
        );
        #[cfg(windows)]
        let (foreign, foreign_list) = (
            "/srv/automation/manifest.yaml",
            "/srv/automation/modules:/opt/ansible/modules",
        );

        assert!(path_is_absolute(native));
        assert!(!path_is_absolute(foreign));
        assert!(absolute_path_list(native_list));
        assert!(!absolute_path_list(foreign_list));

        let generic = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: apply-file
    binary: kubectl
    consequence: irreversible
    trusted: true
    coverage:
      - name: apply
        action: preauthorized
        command_path: ["apply"]
        required_args: ["apply"]
"#,
        )
        .unwrap();
        assert!(generic
            .match_command_all("kubectl", &args_vec(&["apply", "-f", native]))
            .is_empty());
        assert!(generic
            .match_command_all("kubectl", &args_vec(&["apply", "-f", foreign]))
            .is_empty());
        let mixed_case_executable = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: apply-mixed-case-file
    binary: KuBeCtL.ExE
    consequence: irreversible
    trusted: true
    coverage:
      - name: apply
        action: preauthorized
        command_path: ["apply"]
        required_args: ["apply"]
"#,
        )
        .unwrap();
        assert!(mixed_case_executable
            .match_command_all("kUbEcTl.eXe", &args_vec(&["apply", "-f", native]))
            .is_empty());
        assert!(mixed_case_executable
            .match_command_all(
                "kUbEcTl.eXe",
                &args_vec(&["apply", "-f", "relative/manifest.yaml"]),
            )
            .is_empty());
        assert!(mixed_case_executable
            .match_command_all(
                "kUbEcTl.eXe",
                &args_vec(&["--kubeconfig", native, "apply", "-f", native]),
            )
            .is_empty());
        let native_pattern = regex::escape(native);
        let native_pattern_yaml = serialized_yaml_inline(&format!("^{native_pattern}$"));
        let rendered_kubeconfig = VerbCatalog::from_yaml(&format!(
            "verbs:\n  - name: inspect-rendered-kubeconfig\n    binary: kubectl\n    args: [\"--kubeconfig\", \"{{path}}\", \"get\", \"pods\"]\n    params:\n      path: {{ pattern: {native_pattern_yaml} }}\n    consequence: reversible\n"
        ))
        .unwrap();
        assert!(rendered_kubeconfig
            .render("inspect-rendered-kubeconfig", &params(&[("path", native)]),)
            .is_ok());
        assert!(rendered_kubeconfig
            .render("inspect-rendered-kubeconfig", &params(&[("path", foreign)]),)
            .is_err());

        let generic_kubectl_paths = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: inspect-native-paths
    binary: kubectl
    consequence: reversible
    trusted: true
    coverage:
      - name: any
        action: preauthorized
        command_path: ["get"]
"#,
        )
        .unwrap();
        let native_kubeconfig = format!("--kubeconfig={native}");
        let foreign_kubeconfig = format!("--kubeconfig={foreign}");
        assert!(generic_kubectl_paths
            .match_command_all("kubectl", &args_vec(&[&native_kubeconfig, "get", "pods"]))
            .is_empty());
        assert!(generic_kubectl_paths
            .match_command_all("kubectl", &args_vec(&[&foreign_kubeconfig, "get", "pods"]))
            .is_empty());
        assert!(generic_kubectl_paths
            .match_command_all("kubectl", &args_vec(&["cp", native, "pod:/tmp/input"]))
            .is_empty());
        assert!(generic_kubectl_paths
            .match_command_all("kubectl", &args_vec(&["cp", foreign, "pod:/tmp/input"]))
            .is_empty());
        assert!(generic_kubectl_paths
            .match_command_all("kubectl", &args_vec(&["cp", "pod:/tmp/output", native]))
            .is_empty());
        let native_template = format!("-o=go-template-file={native}");
        let foreign_template = format!("-o=go-template-file={foreign}");
        assert!(generic_kubectl_paths
            .match_command_all("kubectl", &args_vec(&["get", "pods", &native_template]))
            .is_empty());
        assert!(generic_kubectl_paths
            .match_command_all("kubectl", &args_vec(&["get", "pods", &foreign_template]))
            .is_empty());
        for option in ["--www", "--unix-socket"] {
            let native_option = format!("{option}={native}");
            let foreign_option = format!("{option}={foreign}");
            assert!(generic_kubectl_paths
                .match_command_all("kubectl", &args_vec(&["proxy", &native_option]))
                .is_empty());
            assert!(generic_kubectl_paths
                .match_command_all("kubectl", &args_vec(&["proxy", &foreign_option]))
                .is_empty());
            assert!(generic_kubectl_paths
                .match_command_all("kubectl", &args_vec(&["proxy", option, native]))
                .is_empty());
            assert!(generic_kubectl_paths
                .match_command_all("kubectl", &args_vec(&["proxy", option, foreign]))
                .is_empty());
        }
        let fixed_www_args = vec!["proxy".to_string(), format!("--www={native}")];
        let fixed_www = format!(
            "verbs:\n  - name: fixed-proxy-root\n    binary: kubectl\n    args: {}\n    consequence: reversible\n",
            serialized_yaml_inline(&fixed_www_args)
        );
        VerbCatalog::from_yaml(&fixed_www)
            .expect("a fixed proxy content root remains explicit operator authority");
        let fixed_socket_args = vec!["proxy".to_string(), format!("--unix-socket={native}")];
        let fixed_socket = format!(
            "verbs:\n  - name: reject-proxy-socket-output\n    binary: kubectl\n    args: {}\n    consequence: reversible\n",
            serialized_yaml_inline(&fixed_socket_args)
        );
        assert!(VerbCatalog::from_yaml(&fixed_socket).is_err());

        let exact_ansible_args = vec![
            format!("--inventory={native}"),
            format!("--module-path={native_list}"),
            format!("--vault-id=production@{native}"),
            native.to_string(),
            "--check".to_string(),
        ];
        let exact_ansible_yaml = format!(
            r#"
verbs:
  - name: check-file-boundaries
    binary: ansible-playbook
    args: {}
    consequence: reversible
    trusted: true
"#,
            serialized_yaml_inline(&exact_ansible_args)
        );
        let exact_ansible = VerbCatalog::from_yaml(&exact_ansible_yaml).unwrap();
        let inventory = format!("--inventory={native}");
        let modules = format!("--module-path={native_list}");
        let vault = format!("--vault-id=production@{native}");
        assert!(!exact_ansible
            .match_command_all(
                "ansible-playbook",
                &args_vec(&[&inventory, &modules, &vault, native, "--check"]),
            )
            .is_empty());
        let foreign_ansible_args = vec![
            format!("--inventory={foreign}"),
            native.to_string(),
            "--check".to_string(),
        ];
        let foreign_ansible_yaml = format!(
            r#"
verbs:
  - name: reject-foreign-file-boundaries
    binary: ansible-playbook
    args: {}
    consequence: reversible
"#,
            serialized_yaml_inline(&foreign_ansible_args)
        );
        assert!(VerbCatalog::from_yaml(&foreign_ansible_yaml).is_err());

        let generic_kubectl_file = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: create-file-backed-resource
    binary: kubectl
    consequence: irreversible
    trusted: true
    coverage:
      - name: create
        action: preauthorized
        command_path: ["create"]
        required_args: ["create"]
"#,
        )
        .unwrap();
        let keyed_file = format!("--from-file=payload={native}");
        assert!(generic_kubectl_file
            .match_command_all(
                "kubectl",
                &args_vec(&["create", "configmap", "fixture", &keyed_file]),
            )
            .is_empty());

        let exact_helm_args = vec![
            "template".to_string(),
            "fixture".to_string(),
            "repo/chart".to_string(),
            format!("--set-file=payload={native}"),
        ];
        let exact_helm_yaml = format!(
            r#"
verbs:
  - name: render-values
    binary: helm
    args: {}
    consequence: reversible
    trusted: true
"#,
            serialized_yaml_inline(&exact_helm_args)
        );
        let exact_helm = VerbCatalog::from_yaml(&exact_helm_yaml).unwrap();
        let set_file = format!("--set-file=payload={native}");
        assert!(!exact_helm
            .match_command_all(
                "helm",
                &args_vec(&["template", "fixture", "repo/chart", &set_file]),
            )
            .is_empty());
        let foreign_helm_args = vec![
            "template".to_string(),
            "fixture".to_string(),
            "repo/chart".to_string(),
            format!("--set-file=payload={foreign}"),
        ];
        let foreign_helm_yaml = format!(
            r#"
verbs:
  - name: reject-foreign-values
    binary: helm
    args: {}
    consequence: reversible
"#,
            serialized_yaml_inline(&foreign_helm_args)
        );
        assert!(VerbCatalog::from_yaml(&foreign_helm_yaml).is_err());
    }

    #[test]
    fn operator_authority_paths_cover_typed_file_aliases() {
        #[cfg(unix)]
        let (inventory, modules, vault_client, private_key, playbook, second_playbook, config) = (
            "/srv/guard/inventory",
            "/srv/guard/modules",
            "/srv/guard/vault-client",
            "/srv/guard/id_ed25519",
            "/srv/guard/site.yaml",
            "/srv/guard/cleanup.yaml",
            "/srv/guard/ansible.cfg",
        );
        #[cfg(windows)]
        let (inventory, modules, vault_client, private_key, playbook, second_playbook, config) = (
            r"C:\guard\inventory",
            r"C:\guard\modules",
            r"C:\guard\vault-client.exe",
            r"C:\guard\id_ed25519",
            r"C:\guard\site.yaml",
            r"C:\guard\cleanup.yaml",
            r"C:\guard\ansible.cfg",
        );

        let args = vec![
            format!("-i{inventory}"),
            format!("--module-path={modules}"),
            "--vault-id".to_string(),
            format!("production@{vault_client}"),
            format!("--private-key={private_key}"),
            playbook.to_string(),
            second_playbook.to_string(),
        ];
        let env = HashMap::from([
            ("ansible_config".to_string(), config.to_string()),
            ("ANSIBLE_INVENTORY".to_string(), "host-a,".to_string()),
            (
                "ANSIBLE_VAULT_IDENTITY_LIST".to_string(),
                "development@prompt".to_string(),
            ),
        ]);
        let actual = operator_authority_paths("AnSiBlE-PlAyBoOk.ExE", &args, &env)
            .unwrap()
            .into_iter()
            .collect::<BTreeSet<_>>();
        let expected = [
            inventory,
            modules,
            vault_client,
            private_key,
            playbook,
            second_playbook,
            config,
        ]
        .into_iter()
        .map(PathBuf::from)
        .collect::<BTreeSet<_>>();
        assert_eq!(actual, expected);

        let second_relative = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: reject-second-relative-playbook
    binary: ansible-playbook
    args: ["/srv/guard/site.yaml", "./caller.yaml", "--check"]
    consequence: reversible
"#,
        )
        .unwrap_err();
        assert!(second_relative
            .to_string()
            .contains("one operator-fixed absolute path"));
    }

    #[test]
    fn operator_authority_paths_cover_kubernetes_credentials_and_executables() {
        #[cfg(unix)]
        let (
            kubeconfig,
            kuberc,
            certificate_authority,
            certificate,
            key,
            helm_command,
            ca,
            repository_config,
            registry_config,
            passphrase,
            post_renderer,
            remote,
        ) = (
            "/srv/guard/kubeconfig",
            "/srv/guard/kuberc",
            "/srv/guard/server-ca.crt",
            "/srv/guard/client.crt",
            "/srv/guard/client.key",
            "/srv/guard/helm",
            "/srv/guard/ca.crt",
            "/srv/guard/repositories.yaml",
            "/srv/guard/registry.json",
            "/srv/guard/signing-passphrase",
            "/srv/guard/post-renderer",
            "/remote/not-local",
        );
        #[cfg(windows)]
        let (
            kubeconfig,
            kuberc,
            certificate_authority,
            certificate,
            key,
            helm_command,
            ca,
            repository_config,
            registry_config,
            passphrase,
            post_renderer,
            remote,
        ) = (
            r"C:\guard\kubeconfig",
            r"C:\guard\kuberc",
            r"C:\guard\server-ca.crt",
            r"C:\guard\client.crt",
            r"C:\guard\client.key",
            r"C:\guard\helm.exe",
            r"C:\guard\ca.crt",
            r"C:\guard\repositories.yaml",
            r"C:\guard\registry.json",
            r"C:\guard\signing-passphrase",
            r"C:\guard\post-renderer.exe",
            r"C:\remote\not-local",
        );

        let kubectl = operator_authority_paths(
            "kubectl",
            &[
                format!("--kubeconfig={kubeconfig}"),
                format!("--kuberc={kuberc}"),
                format!("--certificate-authority={certificate_authority}"),
                "--client-certificate".to_string(),
                certificate.to_string(),
                format!("--client-key={key}"),
                "--helm-command".to_string(),
                helm_command.to_string(),
                "exec".to_string(),
                "pod/tool".to_string(),
                "--".to_string(),
                format!("--client-key={remote}"),
            ],
            &HashMap::new(),
        )
        .unwrap()
        .into_iter()
        .collect::<BTreeSet<_>>();
        assert_eq!(
            kubectl,
            [
                kubeconfig,
                kuberc,
                certificate_authority,
                certificate,
                key,
                helm_command,
            ]
            .into_iter()
            .map(PathBuf::from)
            .collect()
        );

        let helm = operator_authority_paths(
            "helm",
            &[
                "--kubeconfig".to_string(),
                kubeconfig.to_string(),
                format!("--ca-file={ca}"),
                format!("--repository-config={repository_config}"),
                format!("--registry-config={registry_config}"),
                format!("--passphrase-file={passphrase}"),
                "--post-renderer".to_string(),
                post_renderer.to_string(),
            ],
            &HashMap::new(),
        )
        .unwrap()
        .into_iter()
        .collect::<BTreeSet<_>>();
        assert_eq!(
            helm,
            [
                kubeconfig,
                ca,
                repository_config,
                registry_config,
                passphrase,
                post_renderer,
            ]
            .into_iter()
            .map(PathBuf::from)
            .collect()
        );

        let stdin_passphrase = operator_authority_paths(
            "helm",
            &["--passphrase-file=-".to_string()],
            &HashMap::new(),
        )
        .unwrap();
        assert!(stdin_passphrase.is_empty());
    }

    #[test]
    fn operator_authority_paths_cover_typed_tool_environment() {
        #[cfg(unix)]
        let (kubeconfig_a, kubeconfig_b, kuberc, helm_config, repository_cache) = (
            "/srv/guard/kubeconfig-a",
            "/srv/guard/kubeconfig-b",
            "/srv/guard/kuberc",
            "/srv/guard/helm-config",
            "/srv/guard/repository-cache",
        );
        #[cfg(windows)]
        let (kubeconfig_a, kubeconfig_b, kuberc, helm_config, repository_cache) = (
            r"C:\guard\kubeconfig-a",
            r"C:\guard\kubeconfig-b",
            r"C:\guard\kuberc",
            r"C:\guard\helm-config",
            r"C:\guard\repository-cache",
        );
        let kubeconfigs = std::env::join_paths([kubeconfig_a, kubeconfig_b])
            .unwrap()
            .into_string()
            .unwrap();

        let kubectl = operator_authority_paths(
            "kubectl",
            &args_vec(&["get", "pods"]),
            &HashMap::from([
                ("KUBECONFIG".to_string(), kubeconfigs.clone()),
                ("KUBERC".to_string(), kuberc.to_string()),
                ("KUBECTL_ENABLE_CMD_SHADOW".to_string(), "false".to_string()),
            ]),
        )
        .unwrap()
        .into_iter()
        .collect::<BTreeSet<_>>();
        assert_eq!(
            kubectl,
            [kubeconfig_a, kubeconfig_b, kuberc]
                .into_iter()
                .map(PathBuf::from)
                .collect()
        );

        let helm = operator_authority_paths(
            "helm",
            &args_vec(&["template", "fixture", "repo/chart"]),
            &HashMap::from([
                ("KUBECONFIG".to_string(), kubeconfigs),
                ("HELM_CONFIG_HOME".to_string(), helm_config.to_string()),
                (
                    "HELM_REPOSITORY_CACHE".to_string(),
                    repository_cache.to_string(),
                ),
                ("HELM_NO_PLUGINS".to_string(), "1".to_string()),
            ]),
        )
        .unwrap()
        .into_iter()
        .collect::<BTreeSet<_>>();
        assert_eq!(
            helm,
            [kubeconfig_a, kubeconfig_b, helm_config, repository_cache,]
                .into_iter()
                .map(PathBuf::from)
                .collect()
        );

        assert!(operator_authority_paths(
            "kubectl",
            &args_vec(&["diff", "-f", "-"]),
            &HashMap::from([("KUBECTL_EXTERNAL_DIFF".to_string(), "helper".to_string())]),
        )
        .is_err());
        assert!(operator_authority_paths(
            "helm",
            &args_vec(&["version"]),
            &HashMap::from([("HELM_PLUGINS".to_string(), helm_config.to_string())]),
        )
        .is_err());
    }

    #[test]
    fn runtime_tool_environment_schema_applies_without_typed_verb_coverage() {
        assert!(validate_runtime_tool_environment_binding(
            "kubectl",
            EnvironmentBindingSource::Plain,
            "KUBECTL_EXTERNAL_DIFF",
            "/srv/guard/diff-helper",
            false,
        )
        .is_err());
        assert!(validate_runtime_tool_environment_binding(
            "kubectl",
            EnvironmentBindingSource::Plain,
            "KUBECTL_FUTURE_EXECUTOR",
            "/srv/guard/helper",
            false,
        )
        .is_err());
        assert!(validate_runtime_tool_environment_binding(
            "helm",
            EnvironmentBindingSource::Plain,
            "HELM_KUBETOKEN",
            "literal-token",
            false,
        )
        .is_err());
        assert!(validate_runtime_tool_environment_binding(
            "helm",
            EnvironmentBindingSource::Secret,
            "HELM_KUBETOKEN",
            "cluster-token",
            false,
        )
        .is_ok());
        assert!(validate_runtime_tool_environment_binding(
            "custom-tool",
            EnvironmentBindingSource::Plain,
            "CUSTOM_HELPER",
            "/caller/helper",
            false,
        )
        .is_ok());
        assert!(validate_runtime_tool_environment_binding(
            "ansible",
            EnvironmentBindingSource::Plain,
            "ANSIBLE_STRATEGY",
            "linear",
            false,
        )
        .is_err());
        assert!(validate_runtime_tool_environment_binding(
            "ansible",
            EnvironmentBindingSource::Plain,
            "ANSIBLE_STRATEGY",
            "linear",
            true,
        )
        .is_ok());
    }

    #[test]
    fn delayed_process_authority_uses_a_positive_closed_grammar() {
        for (binary, args) in [
            ("true", args_vec(&["ignored"])),
            ("printf", args_vec(&["%s", "fixture"])),
            ("printenv", args_vec(&["GUARD_TEST_VALUE"])),
            ("pwd", args_vec(&["-P"])),
            ("systemctl", args_vec(&["stop", "fixture.service"])),
        ] {
            assert!(
                validate_durable_process_authority(binary, &args).is_ok(),
                "{binary} {args:?} must retain closed delayed authority"
            );
        }
        assert!(validate_catalog_delayed_authority(
            "systemctl",
            &args_vec(&["status", "{unit}.service"]),
            DelayedAuthoritySource::TypedVerb,
        )
        .is_ok());
        for unit in ["{unit}/bad", "{unit}*", "{bad placeholder}.service"] {
            assert!(validate_catalog_delayed_authority(
                "systemctl",
                &args_vec(&["status", unit]),
                DelayedAuthoritySource::TypedVerb,
            )
            .is_err());
        }
        assert!(validate_durable_process_authority("/tmp/true", &[]).is_err());
        assert!(delayed_authority_plan(
            "kubectl",
            &args_vec(&["get", "pods"]),
            DelayedAuthoritySource::TypedVerb,
        )
        .is_ok());

        for (binary, args) in [
            ("python3.12", args_vec(&["-c", "print(1)"])),
            ("java", args_vec(&["-jar", "app.jar"])),
            ("dotnet", args_vec(&["app.dll"])),
            ("deno", args_vec(&["run", "app.ts"])),
            ("bun", args_vec(&["run", "app.ts"])),
            ("git", args_vec(&["-c", "alias.run=!helper", "run"])),
            ("timeout", args_vec(&["1", "true"])),
            ("fixturectl", args_vec(&["status"])),
            ("kubectl", args_vec(&["get", "pods"])),
            ("jq", args_vec(&["-f", "/tmp/filter"])),
            ("curl", args_vec(&["--config", "/tmp/curlrc"])),
            (
                "ssh",
                args_vec(&["-o", "ProxyCommand=helper", "host", "id"]),
            ),
            ("test", args_vec(&["-f", "/tmp/marker"])),
            (
                "systemctl",
                args_vec(&["--host=other", "stop", "fixture.service"]),
            ),
            (
                "systemctl",
                args_vec(&["stop", "--host=other", "fixture.service"]),
            ),
            ("systemctl", args_vec(&["reset-failed"])),
            ("systemctl", args_vec(&["stop", "fixture*"])),
        ] {
            assert!(
                validate_durable_process_authority(binary, &args).is_err(),
                "{binary} {args:?} must fail closed across an approval gap"
            );
        }
    }

    #[test]
    fn local_file_authority_requires_a_typed_command() {
        assert!(command_uses_untyped_local_file_authority(
            "kubectl",
            &args_vec(&["create", "configmap", "fixture", "--from-file=/etc/shadow"]),
        ));
        assert!(command_uses_untyped_local_file_authority(
            "kubectl",
            &args_vec(&["cp", "/etc/shadow", "pod:/tmp/input"]),
        ));
        assert!(command_uses_untyped_local_file_authority(
            "kubectl",
            &args_vec(&["kustomize", "./overlay"]),
        ));
        assert!(command_uses_untyped_local_file_authority(
            "kubectl",
            &args_vec(&["get", "pods", "-o", "jsonpath-file=/etc/shadow"]),
        ));
        assert!(command_uses_untyped_local_file_authority(
            "ansible-playbook",
            &args_vec(&["site.yml", "--check"]),
        ));
        assert!(command_uses_untyped_local_file_authority(
            "helm",
            &args_vec(&["install", "fixture", "repo/chart"]),
        ));
        assert!(!command_uses_untyped_local_file_authority(
            "kubectl",
            &args_vec(&["get", "pods"]),
        ));
        assert!(!command_uses_untyped_local_file_authority(
            "kubectl",
            &args_vec(&["apply", "-f", "-"]),
        ));

        let playbook = native_absolute_fixture_path("site.yml");
        let playbook_yaml = serialized_yaml_inline(&playbook);
        let constrained = VerbCatalog::from_yaml(&format!(
            r#"
verbs:
  - name: inspect-fixed-playbook
    binary: ansible-playbook
    args: ["--syntax-check", {}]
    consequence: reversible
    coverage:
      - name: syntax
        action: evaluate
        required_args: ["--syntax-check"]
"#,
            playbook_yaml
        ))
        .unwrap();
        let matches = constrained.match_command_all(
            "ansible-playbook",
            &args_vec(&["--syntax-check", &playbook]),
        );
        assert!(matches[0].local_file_authorized);
    }

    #[cfg(unix)]
    #[test]
    fn primary_file_commands_use_closed_canonical_operand_grammars() {
        for (binary, args) in [
            ("cat", args_vec(&["state.db"])),
            ("tail", args_vec(&["-n", "20", "authority.hmac"])),
        ] {
            assert!(
                command_uses_untyped_local_file_authority(binary, &args),
                "{binary} {args:?} must not receive evaluator-only file authority"
            );
            let yaml = format!(
                "verbs:\n  - name: reject-relative-{binary}\n    binary: {binary}\n    args: [{}]\n    consequence: reversible\n",
                args.iter()
                    .map(|argument| format!("{argument:?}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let error = VerbCatalog::from_yaml(&yaml)
                .expect_err("relative primary file operands must fail static validation");
            assert!(format!("{error:#}").contains("absolute path"));
        }

        let canonical = "/var/lib/guard/state.db";
        for (binary, args) in [
            ("cat", args_vec(&[canonical])),
            ("tail", args_vec(&["-n", "20", canonical])),
            ("df", args_vec(&["-h", canonical])),
            ("ls", args_vec(&["-la", canonical])),
            ("hostname", args_vec(&["--file", canonical])),
        ] {
            let paths = operator_authority_paths(binary, &args, &HashMap::new()).unwrap();
            assert_eq!(paths, vec![PathBuf::from(canonical)]);
        }

        assert!(operator_authority_paths(
            "cat",
            &args_vec(&["/var/lib/guard/../guard/state.db"]),
            &HashMap::new(),
        )
        .is_err());
        assert!(validate_runtime_option_authority(
            "cat",
            &args_vec(&["--future-input=/var/lib/guard/state.db"]),
        )
        .is_err());
        for binary in ["cat", "df", "hostname", "ls", "tail"] {
            assert!(
                validate_runtime_option_authority(binary, &args_vec(&["--guard-unknown"])).is_err(),
                "{binary} must fail closed on an unknown option"
            );
        }
        assert!(command_uses_untyped_local_file_authority("ls", &[]));

        for binary in ["ip", "rm", "touch"] {
            assert!(authorized_executable_profile(binary).is_none());
            assert!(validate_durable_process_authority(binary, &[]).is_err());
        }
    }

    #[test]
    fn ip_monitor_file_fails_closed_without_a_complete_object_grammar() {
        assert!(authorized_executable_profile("ip").is_none());
        for arguments in [
            args_vec(&["monitor", "file", "/var/lib/guard/events.bin"]),
            args_vec(&["monitor", "file", "state.db"]),
        ] {
            assert!(
                command_uses_untyped_local_file_authority("ip", &arguments),
                "evaluator-only ip authority must fail closed for {arguments:?}"
            );
            assert!(
                validate_durable_process_authority("ip", &arguments).is_err(),
                "raw delayed ip authority must fail closed for {arguments:?}"
            );
            assert!(
                delayed_authority_plan("ip", &arguments, DelayedAuthoritySource::TypedVerb,)
                    .is_err(),
                "typed delayed ip authority must fail closed for {arguments:?}"
            );
        }
    }

    #[test]
    fn tool_configuration_exposes_transitive_authority_paths() {
        let directory = tempfile::tempdir().unwrap();
        let certificate_authority = directory.path().join("cluster-ca.pem");
        let client_certificate = directory.path().join("client.pem");
        let client_key = directory.path().join("client.key");
        let token_file = directory.path().join("token");
        let exec_command = directory.path().join("credential-helper");
        let kubeconfig = directory.path().join("config");
        std::fs::write(
            &kubeconfig,
            format!(
                "clusters:\n  - cluster:\n      certificate-authority: {}\nusers:\n  - user:\n      client-certificate: {}\n      client-key: {}\n      tokenFile: {}\n      exec:\n        command: {}\n",
                certificate_authority.display(),
                client_certificate.display(),
                client_key.display(),
                token_file.display(),
                exec_command.display(),
            ),
        )
        .unwrap();
        let paths = transitive_operator_authority_paths(
            "kubectl",
            &args_vec(&["--kubeconfig", kubeconfig.to_str().unwrap(), "get", "pods"]),
            &HashMap::new(),
            None,
        )
        .unwrap()
        .into_iter()
        .collect::<BTreeSet<_>>();
        for expected in [
            certificate_authority,
            client_certificate,
            client_key,
            token_file,
            exec_command,
        ] {
            assert!(paths.contains(&expected));
        }

        let plugins = directory.path().join("plugins");
        let private_key = directory.path().join("ssh-key");
        let become_password_helper = directory.path().join("become-password-helper");
        let connection_password_helper = directory.path().join("connection-password-helper#v1");
        let vault_identity_helper = directory.path().join("vault-identity-helper");
        let ansible_config = directory.path().join("ansible.cfg");
        std::fs::write(
            &ansible_config,
            format!(
                "[defaults]\nstrategy_plugins = {}\nprivate_key_file = {}\nbecome_password_file = {} ; packaged helper\nconnection_password_file = {}\nvault_identity_list = production@{}\n",
                plugins.display(),
                private_key.display(),
                become_password_helper.display(),
                connection_password_helper.display(),
                vault_identity_helper.display(),
            ),
        )
        .unwrap();
        let paths = transitive_operator_authority_paths(
            "ansible-playbook",
            &args_vec(&["/srv/automation/site.yml", "--check"]),
            &HashMap::from([(
                "ANSIBLE_CONFIG".to_string(),
                ansible_config.to_string_lossy().into_owned(),
            )]),
            None,
        )
        .unwrap();
        for expected in [
            plugins,
            private_key,
            become_password_helper,
            connection_password_helper,
            vault_identity_helper,
        ] {
            assert!(paths.contains(&expected));
        }

        std::fs::write(
            &ansible_config,
            "[defaults]\nstrategy_plugins = relative/plugins\n",
        )
        .unwrap();
        assert!(transitive_operator_authority_paths(
            "ansible-playbook",
            &args_vec(&["/srv/automation/site.yml", "--check"]),
            &HashMap::from([(
                "ANSIBLE_CONFIG".to_string(),
                ansible_config.to_string_lossy().into_owned(),
            )]),
            None,
        )
        .is_err());
    }

    #[cfg(windows)]
    #[test]
    fn mixed_case_windows_environment_still_binds_transitive_authority() {
        let directory = tempfile::tempdir().unwrap();
        let credential_helper = directory.path().join("credential-helper.exe");
        let kubeconfig = directory.path().join("config");
        std::fs::write(
            &kubeconfig,
            format!(
                "users:\n  - user:\n      exec:\n        command: {}\n",
                credential_helper.display()
            ),
        )
        .unwrap();
        let kubectl_paths = transitive_operator_authority_paths(
            "kubectl",
            &args_vec(&["get", "pods"]),
            &HashMap::from([(
                "kubecOnFig".to_string(),
                kubeconfig.to_string_lossy().into_owned(),
            )]),
            None,
        )
        .unwrap();
        assert!(kubectl_paths.contains(&credential_helper));

        let strategy_plugins = directory.path().join("strategy-plugins");
        let ansible_config = directory.path().join("ansible.cfg");
        std::fs::write(
            &ansible_config,
            format!(
                "[defaults]\nstrategy_plugins = {}\n",
                strategy_plugins.display()
            ),
        )
        .unwrap();
        let ansible_paths = transitive_operator_authority_paths(
            "ansible-playbook",
            &args_vec(&["C:\\automation\\site.yml", "--check"]),
            &HashMap::from([(
                "ansible_Config".to_string(),
                ansible_config.to_string_lossy().into_owned(),
            )]),
            None,
        )
        .unwrap();
        assert!(ansible_paths.contains(&strategy_plugins));
    }

    #[test]
    fn ansible_config_rejects_non_empty_shell_bearing_authority() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("ansible.cfg");
        let environment = HashMap::from([(
            "ANSIBLE_CONFIG".to_string(),
            config.to_string_lossy().into_owned(),
        )]);

        for key in [
            "ssh_args",
            "ssh_common_args",
            "ssh_extra_args",
            "scp_extra_args",
            "sftp_extra_args",
        ] {
            for value in [
                "-o ProxyCommand=/srv/guard/helper".to_string(),
                "\n  -o ProxyCommand=/srv/guard/helper".to_string(),
            ] {
                std::fs::write(&config, format!("[defaults]\n{key} = {value}\n")).unwrap();
                let error = transitive_operator_authority_paths(
                    "ansible-playbook",
                    &args_vec(&["/srv/automation/site.yml"]),
                    &environment,
                    None,
                )
                .expect_err("shell-bearing Ansible configuration must fail closed");
                assert!(error.to_string().contains(key), "got: {error}");
            }
        }
    }

    #[test]
    fn ansible_config_rejects_authority_path_continuations() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("ansible.cfg");
        std::fs::write(&config, "[defaults]\nlibrary =\n  /tmp/plugins\n").unwrap();
        let environment = HashMap::from([(
            "ANSIBLE_CONFIG".to_string(),
            config.to_string_lossy().into_owned(),
        )]);
        let error = transitive_operator_authority_paths(
            "ansible-playbook",
            &args_vec(&["/srv/automation/site.yml"]),
            &environment,
            None,
        )
        .expect_err("continued authority paths must fail closed");
        assert!(error.to_string().contains("indented continuation"));
    }

    #[test]
    fn ansible_command_rejects_secondary_ssh_authority() {
        let generic_coverage = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: generic-ansible-check
    binary: ansible
    consequence: reversible
    trusted: true
    coverage:
      - name: check
        action: preauthorized
        required_args: ["--check"]
"#,
        )
        .expect("generic Ansible coverage is valid without SSH transport authority");
        for option in ANSIBLE_REJECTED_SECONDARY_AUTHORITY_OPTIONS {
            for arguments in [
                format!("[\"{option}=ProxyCommand=/srv/guard/helper\", \"all\", \"--check\"]"),
                format!("[\"{option}\", \"ProxyCommand=/srv/guard/helper\", \"all\", \"--check\"]"),
            ] {
                let error = VerbCatalog::from_yaml(&format!(
                    "verbs:\n  - name: reject-{}\n    binary: ansible\n    args: {arguments}\n    consequence: reversible\n",
                    option.trim_start_matches("--").replace('-', "_")
                ))
                .expect_err("Ansible SSH transport authority must fail closed");
                assert!(error.to_string().contains(option), "got: {error}");
            }
            for args in [
                args_vec(&[
                    &format!("{option}=ProxyCommand=/srv/guard/helper"),
                    "all",
                    "--check",
                ]),
                args_vec(&[option, "ProxyCommand=/srv/guard/helper", "all", "--check"]),
            ] {
                assert!(generic_coverage
                    .match_command_all("ansible", &args)
                    .is_empty());
            }
        }

        // Ansible accepts these unique prefixes. They must select the same
        // protected authority as their full spelling in exact verbs and
        // generic coverage.
        for (abbreviation, full_option) in [
            ("--ssh-a", "--ssh-args"),
            ("--ssh-c", "--ssh-common-args"),
            ("--ssh-common-a", "--ssh-common-args"),
            ("--ssh-e", "--ssh-extra-args"),
            ("--ssh-extra-a", "--ssh-extra-args"),
            ("--scp-e", "--scp-extra-args"),
            ("--scp-extra-a", "--scp-extra-args"),
            ("--sftp-e", "--sftp-extra-args"),
            ("--sftp-extra-a", "--sftp-extra-args"),
            ("--private-k", "--private-key"),
        ] {
            assert_eq!(resolve_ansible_long_option(abbreviation), Some(full_option));
            let error = VerbCatalog::from_yaml(&format!(
                "verbs:\n  - name: reject-{}\n    binary: ansible\n    args: [\"{abbreviation}\", \"ProxyCommand=/srv/guard/helper\", \"all\", \"--check\"]\n    consequence: reversible\n",
                full_option.trim_start_matches("--").replace('-', "_")
            ))
            .expect_err("a dangerous Ansible option abbreviation must fail closed");
            assert!(error.to_string().contains(abbreviation), "got: {error}");
            assert!(generic_coverage
                .match_command_all(
                    "ansible",
                    &args_vec(&[
                        abbreviation,
                        "ProxyCommand=/srv/guard/helper",
                        "all",
                        "--check",
                    ]),
                )
                .is_empty());
            let runtime_args = args_vec(&[abbreviation, "/srv/guard/authority", "all", "--check"]);
            assert!(validate_runtime_option_authority("ansible", &runtime_args).is_err());
            assert!(command_uses_untyped_local_file_authority(
                "ansible",
                &runtime_args
            ));
        }

        // These spellings do not select one of the protected options. `--ssh-`
        // is ambiguous, and the other name is unrelated to the known grammar.
        for option in ["--ssh-", "--ssh-control-path"] {
            assert_eq!(resolve_ansible_long_option(option), None);
            VerbCatalog::from_yaml(&format!(
                "verbs:\n  - name: accept-{}\n    binary: ansible\n    args: [\"{option}\", \"value\", \"all\", \"--check\"]\n    consequence: reversible\n",
                option.trim_start_matches("--").replace('-', "_")
            ))
            .expect("an unrelated or ambiguous option must not be treated as SSH authority");
            assert!(!generic_coverage
                .match_command_all("ansible", &args_vec(&[option, "value", "all", "--check"]))
                .is_empty());
        }
    }

    #[test]
    fn ansible_interactive_password_flags_are_boolean_and_fail_closed() {
        let arguments = args_vec(&["-J", "/srv/automation/site.yml"]);
        assert_eq!(
            ansible_playbook_paths(&arguments),
            vec![(1, "/srv/automation/site.yml")],
            "-J is a boolean prompt flag, not a file-valued option"
        );

        for option in ANSIBLE_INTERACTIVE_FLAGS {
            let arguments = args_vec(&[option, "/srv/automation/site.yml"]);
            let error = validate_runtime_option_authority("ansible-playbook", &arguments)
                .expect_err("interactive credential prompting must fail closed");
            assert!(error.to_string().contains("interactive credential"));

            let yaml = format!(
                "verbs:\n  - name: reject-interactive-password\n    binary: ansible-playbook\n    args: [\"{option}\", \"/srv/automation/site.yml\"]\n    consequence: reversible\n"
            );
            assert!(VerbCatalog::from_yaml(&yaml).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn file_arguments_require_absolute_paths_only_in_known_file_positions() {
        let relative_forward = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: apply-manifest
    binary: kubectl
    args: ["apply", "-f", "manifests/app.yaml"]
    consequence: irreversible
"#,
        )
        .unwrap_err();
        assert!(
            relative_forward
                .to_string()
                .contains("must be one absolute path"),
            "got: {relative_forward}"
        );

        let relative_revert = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: apply-playbook
    binary: ansible-playbook
    args: ["/srv/guard/playbooks/apply.yaml", "-i", "/srv/guard/inventory/production"]
    consequence: recoverable
    revert:
      binary: ansible-playbook
      args: ["rollback.yaml", "-i", "production"]
"#,
        )
        .unwrap_err();
        assert!(relative_revert.to_string().contains("revert command"));

        let relative_parameter = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: apply-selected-manifest
    binary: kubectl
    args: ["apply", "-f", "{path}"]
    params:
      path: { pattern: "^[A-Za-z0-9._/-]+$" }
    consequence: irreversible
"#,
        )
        .unwrap_err();
        assert!(
            relative_parameter
                .to_string()
                .contains("literal or finite enumerated operator path"),
            "got: {relative_parameter}"
        );

        assert!(VerbCatalog::from_yaml(
            r#"
verbs:
  - name: create-selected-secret
    binary: kubectl
    args: ["create", "secret", "generic", "fixture", "--from-file=payload={path}"]
    params:
      path: { pattern: "^[A-Za-z0-9._/-]+$" }
    consequence: irreversible
"#,
        )
        .is_err());

        let vault_source_parameter = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: check-vault-source
    binary: ansible-playbook
    args: ["--vault-id=production@{source}", "/srv/automation/site.yml", "--check"]
    params:
      source: { pattern: "^(prompt)$" }
    consequence: reversible
"#,
        )
        .expect("a finite prompt-only vault source is non-executable");
        assert!(vault_source_parameter
            .render("check-vault-source", &params(&[("source", "prompt")]),)
            .is_ok());
        let parameterized_vault_client = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: reject-selected-vault-client
    binary: ansible-playbook
    args: ["--vault-id=production@{source}", "/srv/automation/site.yml", "--check"]
    params:
      source: { pattern: "^(prompt|/srv/automation/vault-client)$" }
    consequence: reversible
"#,
        )
        .unwrap_err();
        assert!(parameterized_vault_client
            .to_string()
            .contains("enumerates a value that is not"));
        assert!(VerbCatalog::from_yaml(
            r#"
verbs:
  - name: check-fixed-vault-client
    binary: ansible-playbook
    args: ["--vault-id=production@/srv/automation/vault-client", "/srv/automation/site.yml", "--check"]
    consequence: reversible
"#,
        )
        .is_ok());

        let fixed_post_renderer = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: render-with-filter
    binary: helm
    args: ["template", "fixture", "repo/chart", "--post-renderer=/srv/automation/renderer"]
    consequence: reversible
"#,
        )
        .expect("a fixed post-renderer is operator-reviewed executable authority");
        assert!(fixed_post_renderer
            .render("render-with-filter", &BTreeMap::new())
            .is_ok());
        let dynamic_post_renderer = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: render-with-dynamic-filter
    binary: helm
    args: ["template", "fixture", "repo/chart", "--post-renderer={renderer}"]
    params:
      renderer: { pattern: "^[A-Za-z0-9._/-]+$" }
    consequence: reversible
"#,
        )
        .unwrap_err();
        assert!(dynamic_post_renderer
            .to_string()
            .contains("operator-authored literal"));
        let path_resolved_post_renderer = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: render-with-path-filter
    binary: helm
    args: ["template", "fixture", "repo/chart", "--post-renderer=renderer"]
    consequence: reversible
"#,
        )
        .unwrap_err();
        assert!(path_resolved_post_renderer
            .to_string()
            .contains("operator-fixed absolute path"));

        let remote_manifest = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: apply-remote-manifest
    binary: kubectl
    args: ["apply", "--filename=https://example.invalid/manifest.yaml"]
    consequence: irreversible
"#,
        )
        .unwrap_err();
        assert!(remote_manifest.to_string().contains("absolute path"));

        let exact_kubeconfig = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: inspect-with-kubeconfig
    binary: kubectl
    args: ["--kubeconfig", "{kubeconfig}", "get", "pods"]
    params:
      kubeconfig: { pattern: "^/etc/guard/kubeconfig$" }
    consequence: reversible
"#,
        )
        .expect("one exact absolute kubeconfig is a valid file parameter");
        let rendered = exact_kubeconfig
            .render(
                "inspect-with-kubeconfig",
                &params(&[("kubeconfig", "/etc/guard/kubeconfig")]),
            )
            .unwrap();
        assert_eq!(rendered.args[1], "/etc/guard/kubeconfig");
        assert!(VerbCatalog::from_yaml(
            r#"
verbs:
  - name: inspect-with-fixed-kubeconfig
    binary: kubectl
    args: ["--kubeconfig", "/etc/guard/kubeconfig", "get", "pods"]
    consequence: reversible
"#,
        )
        .is_ok());
        let broad_kubeconfig = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: inspect-with-broad-kubeconfig
    binary: kubectl
    args: ["--kubeconfig", "{kubeconfig}", "get", "pods"]
    params:
      kubeconfig: { pattern: "^/srv/[^[:space:]]+$" }
    consequence: reversible
"#,
        )
        .unwrap_err();
        assert!(broad_kubeconfig
            .to_string()
            .contains("operator-selected absolute path"));

        let mixed_exact_paths = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: inspect-with-mixed-kubeconfig
    binary: kubectl
    args: ["--kubeconfig", "{kubeconfig}", "get", "pods"]
    params:
      kubeconfig: { pattern: "^(/etc/guard/kubeconfig|kubeconfig)$" }
    consequence: reversible
"#,
        )
        .unwrap_err();
        assert!(mixed_exact_paths
            .to_string()
            .contains("operator-selected absolute path"));

        let inline_inventory = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: check-inline-inventory
    binary: ansible-playbook
    args: ["-i", "{inventory}", "/srv/automation/site.yml", "--check"]
    params:
      inventory: { pattern: '^(localhost,|web\.example,)$' }
    consequence: reversible
"#,
        )
        .expect("Ansible inline inventories are not caller-relative files");
        assert!(inline_inventory
            .render(
                "check-inline-inventory",
                &params(&[("inventory", "localhost,")]),
            )
            .is_ok());

        let dynamic_vault_client = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: check-selected-vault-client
    binary: ansible
    args: ["--vault-id=production@{source}", "all", "--check"]
    params:
      source: { pattern: "^/srv/automation/[^[:space:]]+$" }
    consequence: reversible
"#,
        )
        .unwrap_err();
        assert!(dynamic_vault_client
            .to_string()
            .contains("must enumerate non-executable values"));

        let dynamic_playbook = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: check-selected-playbook
    binary: ansible-playbook
    args: ["{playbook}", "--check"]
    params:
      playbook: { pattern: "^/srv/automation/(site|audit)[.]yml$" }
    consequence: reversible
"#,
        )
        .unwrap_err();
        assert!(dynamic_playbook
            .to_string()
            .contains("operator-fixed absolute path"));
        let generic_playbook = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: check-any-playbook
    binary: ansible-playbook
    consequence: reversible
    trusted: true
    coverage:
      - name: check
        action: preauthorized
        required_args: ["--check"]
"#,
        )
        .unwrap_err();
        assert!(generic_playbook
            .to_string()
            .contains("operator-fixed playbook"));

        let generic_ansible_coverage = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: check-ansible-options
    binary: ansible
    consequence: reversible
    trusted: true
    coverage:
      - name: check
        action: preauthorized
        required_args: ["--check"]
"#,
        )
        .unwrap();
        for relative_inventory in [
            "-i./inventory",
            "--inventory-file=inventory",
            "-vi./inventory",
            "-Ci/tmp/inventory",
            "-CM/tmp/modules",
            "--inventory-f=inventory",
            "--private-k=key",
            "--module-path=./modules",
            "-M./modules",
            "--extra-vars=@./vars.yml",
            "-ve@./vars.yml",
            "--vault-id=dev@./vault-client",
            "-J./vault-password",
            "-J=./vault-password",
            "-vJ./vault-password",
        ] {
            assert!(generic_ansible_coverage
                .match_command_all(
                    "ansible",
                    &args_vec(&[relative_inventory, "/srv/automation/site.yml", "--check",]),
                )
                .is_empty());
        }
        for inline_inventory in ["-ilocalhost,", "--inventory=localhost,"] {
            assert!(generic_ansible_coverage
                .match_command_all(
                    "ansible",
                    &args_vec(&[inline_inventory, "/srv/automation/site.yml", "--check"]),
                )
                .is_empty());
        }
        assert!(generic_ansible_coverage
            .match_command_all(
                "ansible",
                &args_vec(&[
                    "--inventory-file",
                    "localhost,",
                    "/srv/automation/site.yml",
                    "--check",
                ]),
            )
            .is_empty());
        let constrained_inline_inventory = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: check-bounded-inline-inventory
    binary: ansible
    consequence: reversible
    trusted: true
    coverage:
      - name: check
        action: preauthorized
        required_args: ["--check"]
        inventory:
          options: ["-i", "--inventory"]
          values: ["localhost,"]
"#,
        )
        .unwrap();
        assert!(!constrained_inline_inventory
            .match_command_all(
                "ansible",
                &args_vec(&["--inventory=localhost,", "all", "--check"]),
            )
            .is_empty());
        assert!(constrained_inline_inventory
            .match_command_all(
                "ansible",
                &args_vec(&["--inventory=attacker-host,", "all", "--check"]),
            )
            .is_empty());
        assert!(constrained_inline_inventory
            .match_command_all(
                "ansible",
                &args_vec(&[
                    "--inventory=localhost,",
                    "--inventory-file=attacker-host,",
                    "all",
                    "--check",
                ]),
            )
            .is_empty());
        for operator_selected_extra_vars in [
            "--extra-vars=@/srv/automation/vars.yml",
            "--extra-vars=deployment_environment=production",
        ] {
            assert!(generic_ansible_coverage
                .match_command_all(
                    "ansible",
                    &args_vec(&[
                        operator_selected_extra_vars,
                        "/srv/automation/site.yml",
                        "--check",
                    ]),
                )
                .is_empty());
        }
        assert!(!generic_ansible_coverage
            .match_command_all(
                "ansible",
                &args_vec(&[
                    "--vault-id=dev@prompt",
                    "/srv/automation/site.yml",
                    "--check",
                ]),
            )
            .is_empty());
        VerbCatalog::from_yaml(
            r#"
verbs:
  - name: check-with-fixed-extra-vars
    binary: ansible-playbook
    args: ["--extra-vars=@/srv/automation/vars.yml", "/srv/automation/site.yml", "--check"]
    consequence: reversible
"#,
        )
        .expect("fixed Ansible extra vars remain explicit operator authority");
        for executable_source in [
            "--module-path=/srv/automation/modules:/opt/ansible/modules",
            "-M/srv/automation/modules:/opt/ansible/modules",
            "--vault-id=dev@/srv/automation/vault-client",
        ] {
            assert!(generic_ansible_coverage
                .match_command_all(
                    "ansible",
                    &args_vec(&[executable_source, "/srv/automation/site.yml", "--check"]),
                )
                .is_empty());
        }
        for (option, value) in [
            ("--private-key", "/srv/automation/id_ed25519"),
            ("--key-file", "/srv/automation/id_ed25519"),
            ("--become-password-file", "/srv/automation/become-password"),
            (
                "--connection-password-file",
                "/srv/automation/connection-password",
            ),
            ("--vault-pass-file", "/srv/automation/vault-password"),
            ("--playbook-dir", "/srv/automation"),
        ] {
            assert!(generic_ansible_coverage
                .match_command_all(
                    "ansible",
                    &args_vec(&[option, value, "relative-site.yml", "--check"]),
                )
                .is_empty());
        }
        VerbCatalog::from_yaml(
            r#"
verbs:
  - name: check-with-fixed-private-key
    binary: ansible
    args: ["--private-key=/srv/automation/id_ed25519", "all", "--check"]
    consequence: reversible
"#,
        )
        .expect("a fixed private key path remains explicit operator authority");
        assert!(generic_ansible_coverage
            .match_command_all(
                "ansible",
                &args_vec(&[
                    "-i/srv/automation/inventory",
                    "/srv/automation/site.yml",
                    "--check",
                ]),
            )
            .is_empty());
        assert!(generic_ansible_coverage
            .match_command_all(
                "ansible",
                &args_vec(&[
                    "--ssh-common-args=ProxyCommand=/srv/automation/proxy",
                    "/srv/automation/site.yml",
                    "--check",
                ]),
            )
            .is_empty());
        let fixed_ssh_transport = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: check-through-fixed-proxy
    binary: ansible-playbook
    args: ["--ssh-common-args=ProxyCommand=/srv/automation/proxy", "/srv/automation/site.yml", "--check"]
    consequence: reversible
"#,
        )
        .expect_err("an exact template cannot select SSH transport authority");
        assert!(fixed_ssh_transport
            .to_string()
            .contains("--ssh-common-args"));
        let fixed_connection_coverage = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: check-with-fixed-connection
    binary: ansible
    consequence: reversible
    trusted: true
    coverage:
      - name: local
        action: preauthorized
        required_args: ["--check"]
        options:
          - options: ["-c", "--connection"]
            values: ["local"]
            required: true
"#,
        )
        .unwrap();
        assert!(!fixed_connection_coverage
            .match_command_all(
                "ansible",
                &args_vec(&["all", "--connection", "local", "--check"]),
            )
            .is_empty());
        assert!(fixed_connection_coverage
            .match_command_all(
                "ansible",
                &args_vec(&["all", "--connection", "ssh", "local", "--check"]),
            )
            .is_empty());
        for args in [
            args_vec(&["all", "-ucaller", "--check"]),
            args_vec(&["all", "--user=caller", "--check"]),
            args_vec(&["all", "-u", "caller", "--check"]),
        ] {
            assert!(generic_ansible_coverage
                .match_command_all("ansible", &args)
                .is_empty());
        }
        for become_flag in ["-b", "--become"] {
            assert!(generic_ansible_coverage
                .match_command_all("ansible", &args_vec(&["all", "--check", become_flag]))
                .is_empty());
        }
        VerbCatalog::from_yaml(
            r#"
verbs:
  - name: fixed-remote-user
    binary: ansible
    args: ["all", "--user=deploy", "--check"]
    consequence: reversible
"#,
        )
        .expect("an exact template may select one operator-fixed Ansible remote user");
        VerbCatalog::from_yaml(
            r#"
verbs:
  - name: fixed-become
    binary: ansible
    args: ["all", "--check", "--become"]
    consequence: reversible
"#,
        )
        .expect("an exact template may enable privilege escalation explicitly");
        assert!(VerbCatalog::from_yaml(
            r#"
verbs:
  - name: dynamic-remote-user
    binary: ansible
    args: ["all", "--user={remote_user}", "--check"]
    params:
      remote_user: { pattern: "^[a-z]+$" }
    consequence: reversible
"#,
        )
        .is_err());

        for tree_output in [
            args_vec(&["all", "--tree", "/srv/automation/results", "--check"]),
            args_vec(&["all", "--tree=/srv/automation/results", "--check"]),
            args_vec(&["all", "-t/srv/automation/results", "--check"]),
        ] {
            assert!(generic_ansible_coverage
                .match_command_all("ansible", &tree_output)
                .is_empty());
        }
        for tree_template in [
            r#"
verbs:
  - name: ansible-tree-split
    binary: ansible
    args: ["all", "--tree", "/srv/automation/results"]
    consequence: reversible
"#,
            r#"
verbs:
  - name: ansible-tree-attached
    binary: ansible
    args: ["all", "--tree=/srv/automation/results"]
    consequence: reversible
"#,
        ] {
            assert!(VerbCatalog::from_yaml(tree_template).is_err());
        }

        let generic_kubectl_coverage = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: apply-kustomization
    binary: kubectl
    consequence: irreversible
    trusted: true
    coverage:
      - name: apply
        action: preauthorized
        command_path: ["apply"]
        required_args: ["apply"]
"#,
        )
        .unwrap();
        for relative_kustomization in ["-k.", "-k=.", "--kustomize=."] {
            assert!(generic_kubectl_coverage
                .match_command_all("kubectl", &args_vec(&["apply", relative_kustomization]),)
                .is_empty());
        }
        for relative_manifest in [
            "-f=./manifest.yaml",
            "--filename=./manifest.yaml",
            "-f=/srv/automation/one.yaml,./two.yaml",
        ] {
            assert!(generic_kubectl_coverage
                .match_command_all("kubectl", &args_vec(&["apply", relative_manifest]),)
                .is_empty());
        }
        assert!(!generic_kubectl_coverage
            .match_command_all("kubectl", &args_vec(&["apply", "-f=-"]),)
            .is_empty());
        assert!(generic_kubectl_coverage
            .match_command_all(
                "kubectl",
                &args_vec(&["apply", "--filename=https://example.invalid/manifest.yaml"]),
            )
            .is_empty());
        assert!(generic_kubectl_coverage
            .match_command_all(
                "kubectl",
                &args_vec(&["exec", "pod/fixture", "--", "helper", "apply"]),
            )
            .is_empty());
        let generic_kustomize_coverage = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: render-kustomization
    binary: kubectl
    consequence: reversible
    trusted: true
    coverage:
      - name: render
        action: preauthorized
        command_path: ["kustomize"]
        required_args: ["kustomize"]
"#,
        )
        .unwrap();
        for forbidden in [
            "--load-restrictor=LoadRestrictionsNone",
            "--enable-alpha-plugins",
            "--network",
            "--enable-helm",
        ] {
            assert!(generic_kustomize_coverage
                .match_command_all(
                    "kubectl",
                    &args_vec(&["kustomize", "/srv/automation/overlay", forbidden]),
                )
                .is_empty());
        }
        assert!(generic_kustomize_coverage
            .match_command_all(
                "kubectl",
                &args_vec(&[
                    "kustomize",
                    "/srv/automation/overlay",
                    "--output=rendered.yaml",
                ]),
            )
            .is_empty());
        assert!(generic_kustomize_coverage
            .match_command_all(
                "kubectl",
                &args_vec(&[
                    "kustomize",
                    "/srv/automation/overlay",
                    "--output=/srv/automation/rendered.yaml",
                ]),
            )
            .is_empty());
        assert!(VerbCatalog::from_yaml(
            r#"
verbs:
  - name: reject-static-kustomize-output
    binary: kubectl
    args: ["kustomize", "/srv/automation/overlay", "--output=/srv/automation/rendered.yaml"]
    consequence: reversible
"#,
        )
        .is_err());
        VerbCatalog::from_yaml(
            r#"
verbs:
  - name: render-with-fixed-helm
    binary: kubectl
    args: ["kustomize", "/srv/automation/overlay", "--enable-helm", "--helm-command=/srv/automation/helm"]
    consequence: reversible
"#,
        )
        .expect("an exact template may select one operator-fixed Helm executable");
        assert!(generic_kubectl_coverage
            .match_command_all(
                "kubectl",
                &args_vec(&["caller-installed-plugin", "--dangerous"]),
            )
            .is_empty());
        for implicit_authority in [
            "--server=https://caller.invalid",
            "-shttps://caller.invalid",
            "--context=caller",
            "--user=caller",
            "--insecure-skip-tls-verify",
            "--token=credential",
        ] {
            assert!(generic_kubectl_coverage
                .match_command_all("kubectl", &args_vec(&[implicit_authority, "get", "pods"]),)
                .is_empty());
        }
        assert!(generic_kubectl_coverage
            .match_command_all(
                "kubectl",
                &args_vec(&[
                    "config",
                    "set-credentials",
                    "fixture",
                    "--exec-command=/srv/automation/plugin",
                ]),
            )
            .is_empty());
        VerbCatalog::from_yaml(
            r#"
verbs:
  - name: fixed-kubectl-endpoint
    binary: kubectl
    args: ["--server=https://cluster.example.invalid", "--context=production", "get", "pods"]
    consequence: reversible
"#,
        )
        .expect("exact endpoint and identity selectors are operator authority");
        let constrained_kubectl_authority = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: bounded-kubectl-authority
    binary: kubectl
    consequence: reversible
    trusted: true
    coverage:
      - name: production-read
        action: preauthorized
        command_path: ["get"]
        required_args: ["get", "pods"]
        options:
          - options: ["-s", "--server"]
            values: ["https://cluster.example.invalid"]
            required: true
          - options: ["--context"]
            values: ["production"]
            required: true
          - options: ["--namespace"]
            values: ["default"]
            required: true
"#,
        )
        .unwrap();
        assert!(!constrained_kubectl_authority
            .match_command_all(
                "kubectl",
                &args_vec(&[
                    "-shttps://cluster.example.invalid",
                    "--context",
                    "production",
                    "get",
                    "pods",
                    "--namespace",
                    "default",
                ]),
            )
            .is_empty());
        for endpoint in [
            args_vec(&[
                "-s",
                "https://cluster.example.invalid",
                "--context",
                "production",
                "get",
                "pods",
                "--namespace",
                "default",
            ]),
            args_vec(&[
                "-s=https://cluster.example.invalid",
                "--context",
                "production",
                "get",
                "pods",
                "--namespace",
                "default",
            ]),
        ] {
            assert!(!constrained_kubectl_authority
                .match_command_all("kubectl", &endpoint)
                .is_empty());
        }
        assert!(constrained_kubectl_authority
            .match_command_all(
                "kubectl",
                &args_vec(&[
                    "-shttps://cluster.example.invalid",
                    "--context",
                    "default",
                    "get",
                    "pods",
                    "--namespace",
                    "production",
                ]),
            )
            .is_empty());
        for unsafe_catalog in [
            r#"
verbs:
  - name: dynamic-kubectl-endpoint
    binary: kubectl
    args: ["--server={server}", "get", "pods"]
    params:
      server: { pattern: "^https://[a-z.]+$" }
    consequence: reversible
"#,
            r#"
verbs:
  - name: kubectl-argv-credential
    binary: kubectl
    args: ["--token=credential", "get", "pods"]
    consequence: reversible
"#,
            r#"
verbs:
  - name: kubectl-unknown-global
    binary: kubectl
    args: ["--future-option=value", "get", "pods"]
    consequence: reversible
"#,
            r#"
verbs:
  - name: kubectl-exec-credential-plugin
    binary: kubectl
    args: ["config", "set-credentials", "fixture", "--exec-command=/srv/automation/plugin", "--exec-arg=login", "--exec-env=MODE=production"]
    consequence: irreversible
"#,
            r#"
verbs:
  - name: kubectl-auth-provider-credential
    binary: kubectl
    args: ["config", "set-credentials", "fixture", "--auth-provider-arg=client-secret=credential"]
    consequence: irreversible
"#,
        ] {
            assert!(VerbCatalog::from_yaml(unsafe_catalog).is_err());
        }
        assert!(VerbCatalog::from_yaml(
            r#"
verbs:
  - name: reject-kubectl-plugin
    binary: kubectl
    args: ["caller-installed-plugin", "--dangerous"]
    consequence: irreversible
"#,
        )
        .is_err());
        let generic_kubectl_patch_coverage = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: patch-resource
    binary: kubectl
    consequence: irreversible
    trusted: true
    coverage:
      - name: patch
        action: preauthorized
        command_path: ["patch"]
        required_args: ["patch"]
"#,
        )
        .unwrap();
        assert!(generic_kubectl_patch_coverage
            .match_command_all(
                "kubectl",
                &args_vec(&["patch", "deployment/app", "--patch-file=patch.json"]),
            )
            .is_empty());
        assert!(generic_kubectl_patch_coverage
            .match_command_all(
                "kubectl",
                &args_vec(&[
                    "patch",
                    "deployment/app",
                    "--patch-file=/srv/automation/patch.json",
                ]),
            )
            .is_empty());

        let generic_kubectl_file_coverage = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: create-file-backed-resource
    binary: kubectl
    consequence: irreversible
    trusted: true
    coverage:
      - name: create
        action: preauthorized
        command_path: ["create"]
        required_args: ["create"]
"#,
        )
        .unwrap();
        for relative_file in [
            "--from-file=payload=./payload",
            "--from-env-file=./vars.env",
            "--cert=./tls.crt",
            "--key=./tls.key",
        ] {
            assert!(generic_kubectl_file_coverage
                .match_command_all(
                    "kubectl",
                    &args_vec(&["create", "secret", "generic", "fixture", relative_file]),
                )
                .is_empty());
        }
        assert!(generic_kubectl_file_coverage
            .match_command_all(
                "kubectl",
                &args_vec(&[
                    "create",
                    "secret",
                    "generic",
                    "fixture",
                    "--from-file",
                    "payload=./payload",
                ]),
            )
            .is_empty());
        for absolute_file in [
            "--from-file=payload=/srv/automation/payload",
            "--from-env-file=/srv/automation/vars.env",
            "--cert=/srv/automation/tls.crt",
            "--key=/srv/automation/tls.key",
        ] {
            assert!(generic_kubectl_file_coverage
                .match_command_all(
                    "kubectl",
                    &args_vec(&["create", "secret", "generic", "fixture", absolute_file]),
                )
                .is_empty());
        }

        let generic_kubectl_kustomize_coverage = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: render-kustomization
    binary: kubectl
    consequence: reversible
    trusted: true
    coverage:
      - name: render
        action: preauthorized
        command_path: ["kustomize"]
        required_args: ["kustomize"]
"#,
        )
        .unwrap();
        assert!(generic_kubectl_kustomize_coverage
            .match_command_all(
                "kubectl",
                &args_vec(&["kustomize", "./overlays/production"])
            )
            .is_empty());
        assert!(generic_kubectl_kustomize_coverage
            .match_command_all(
                "kubectl",
                &args_vec(&["kustomize", "/srv/automation/overlays/production"]),
            )
            .is_empty());
        assert!(generic_kubectl_kustomize_coverage
            .match_command_all(
                "kubectl",
                &args_vec(&["kustomize", "https://example.invalid/overlays/production",]),
            )
            .is_empty());
        assert!(generic_kubectl_kustomize_coverage
            .match_command_all("kubectl", &args_vec(&["get", "pods", "kustomize"]),)
            .is_empty());

        let generic_kubectl_cp_coverage = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: copy-file
    binary: kubectl
    consequence: irreversible
    trusted: true
    coverage:
      - name: cp
        action: preauthorized
        command_path: ["cp"]
        required_args: ["cp"]
"#,
        )
        .unwrap();
        assert!(generic_kubectl_cp_coverage
            .match_command_all(
                "kubectl",
                &args_vec(&["cp", "../../sensitive", "pod:/tmp/sensitive"]),
            )
            .is_empty());
        assert!(generic_kubectl_cp_coverage
            .match_command_all(
                "kubectl",
                &args_vec(&["cp", "/srv/automation/input", "pod:/tmp/input"]),
            )
            .is_empty());
        assert!(VerbCatalog::from_yaml(
            r#"
verbs:
  - name: copy-from-pod
    binary: kubectl
    args: ["cp", "pod:/tmp/output", "/srv/automation/output"]
    consequence: reversible
"#,
        )
        .is_err());

        let generic_kubectl_output_coverage = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: inspect-output
    binary: kubectl
    consequence: reversible
    trusted: true
    coverage:
      - name: get
        action: preauthorized
        command_path: ["get"]
        required_args: ["get"]
"#,
        )
        .unwrap();
        for relative_output in [
            args_vec(&[
                "get",
                "pods",
                "-o",
                "go-template-file",
                "--template=./template",
            ]),
            args_vec(&["get", "pods", "-o=custom-columns-file=./columns"]),
        ] {
            assert!(generic_kubectl_output_coverage
                .match_command_all("kubectl", &relative_output)
                .is_empty());
        }
        for absolute_output in [
            args_vec(&[
                "get",
                "pods",
                "-o",
                "go-template-file",
                "--template=/srv/automation/template",
            ]),
            args_vec(&[
                "get",
                "pods",
                "-o=custom-columns-file=/srv/automation/columns",
            ]),
        ] {
            assert!(generic_kubectl_output_coverage
                .match_command_all("kubectl", &absolute_output)
                .is_empty());
        }
        let generic_cluster_dump = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: cluster-dump
    binary: kubectl
    consequence: irreversible
    trusted: true
    coverage:
      - name: dump
        action: preauthorized
        command_path: ["cluster-info", "dump"]
        required_args: ["cluster-info", "dump"]
"#,
        )
        .unwrap();
        assert!(generic_cluster_dump
            .match_command_all(
                "kubectl",
                &args_vec(&["cluster-info", "dump", "--output-directory=./dump",]),
            )
            .is_empty());
        assert!(generic_cluster_dump
            .match_command_all(
                "kubectl",
                &args_vec(&[
                    "cluster-info",
                    "dump",
                    "--output-directory=/srv/automation/dump",
                ]),
            )
            .is_empty());
        assert!(!generic_cluster_dump
            .match_command_all(
                "kubectl",
                &args_vec(&["cluster-info", "dump", "--output-directory=-"]),
            )
            .is_empty());

        let mut cluster_info = synth_verb("kubectl", None, false, "cluster-info");
        cluster_info.args = args_vec(&["cluster-info"]);
        assert!(synthesized_access_is_statically_read_only(&cluster_info));
        cluster_info.args.push("dump".to_string());
        assert!(!synthesized_access_is_statically_read_only(&cluster_info));

        let generic_kubectl_profile_coverage = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: profile-read
    binary: kubectl
    consequence: reversible
    trusted: true
    coverage:
      - name: get
        action: preauthorized
        command_path: ["get"]
        required_args: ["get"]
"#,
        )
        .unwrap();
        for unsafe_profile in [
            args_vec(&["get", "pods", "--profile=cpu"]),
            args_vec(&[
                "get",
                "pods",
                "--profile=cpu",
                "--profile-output=./profile.pprof",
            ]),
        ] {
            assert!(generic_kubectl_profile_coverage
                .match_command_all("kubectl", &unsafe_profile)
                .is_empty());
        }
        assert!(generic_kubectl_profile_coverage
            .match_command_all(
                "kubectl",
                &args_vec(&[
                    "get",
                    "pods",
                    "--profile=cpu",
                    "--profile-output=/srv/automation/profile.pprof",
                ]),
            )
            .is_empty());
        assert!(!generic_kubectl_profile_coverage
            .match_command_all("kubectl", &args_vec(&["get", "pods", "--profile=none"]),)
            .is_empty());

        let generic_kubectl_exec_coverage = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: exec-helper
    binary: kubectl
    consequence: irreversible
    trusted: true
    coverage:
      - name: exec
        action: preauthorized
        command_path: ["exec"]
        required_args: ["exec"]
"#,
        )
        .unwrap();
        assert!(!generic_kubectl_exec_coverage
            .match_command_all(
                "kubectl",
                &args_vec(&[
                    "exec",
                    "deploy/tool",
                    "--",
                    "helper",
                    "--from-file=./remote-input",
                    "--token=remote-command-data",
                    "kustomize",
                    "./remote-directory",
                ]),
            )
            .is_empty());

        let generic_helm_coverage = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: helm-file-backed-operation
    binary: helm
    consequence: reversible
    trusted: true
    coverage:
      - name: list
        action: preauthorized
        command_path: ["list"]
"#,
        )
        .unwrap();
        assert!(generic_helm_coverage
            .match_command_all("helm", &args_vec(&["caller-installed-plugin", "run"]))
            .is_empty());
        for implicit_authority in [
            "--kube-apiserver=https://caller.invalid",
            "--kube-context=caller",
            "--kube-as-user=caller",
            "--kube-insecure-skip-tls-verify",
            "--kube-token=credential",
            "--key=caller-signing-key",
        ] {
            assert!(generic_helm_coverage
                .match_command_all("helm", &args_vec(&[implicit_authority, "list"]),)
                .is_empty());
        }
        VerbCatalog::from_yaml(
            r#"
verbs:
  - name: fixed-helm-endpoint
    binary: helm
    args: ["--kube-apiserver=https://cluster.example.invalid", "--kube-context=production", "list"]
    consequence: reversible
"#,
        )
        .expect("exact Helm endpoint and identity selectors are operator authority");
        for unsafe_catalog in [
            r#"
verbs:
  - name: dynamic-helm-endpoint
    binary: helm
    args: ["--kube-apiserver={server}", "list"]
    params:
      server: { pattern: "^https://[a-z.]+$" }
    consequence: reversible
"#,
            r#"
verbs:
  - name: helm-argv-credential
    binary: helm
    args: ["--kube-token=credential", "list"]
    consequence: reversible
"#,
            r#"
verbs:
  - name: helm-unknown-global
    binary: helm
    args: ["--future-option=value", "list"]
    consequence: reversible
"#,
            r#"
verbs:
  - name: dynamic-signing-key
    binary: helm
    args: ["package", "/srv/automation/chart", "--sign", "--key={key}"]
    params:
      key: { pattern: "^[a-z]+$" }
    consequence: reversible
"#,
        ] {
            assert!(VerbCatalog::from_yaml(unsafe_catalog).is_err());
        }
        assert!(VerbCatalog::from_yaml(
            r#"
verbs:
  - name: reject-helm-plugin
    binary: helm
    args: ["caller-installed-plugin", "run"]
    consequence: irreversible
"#,
        )
        .is_err());
        for relative_file in [
            "--ca-file=./ca.pem",
            "--cert-file=./client.pem",
            "--key-file=./client.key",
            "--keyring=./pubring.gpg",
            "--set-file=payload=./values.txt",
            "--set-file=first=/srv/first,second=./second",
            "--post-renderer=./renderer",
            "--output-dir=./rendered",
            "-f=./values.yaml",
        ] {
            assert!(generic_helm_coverage
                .match_command_all("helm", &args_vec(&["pull", "repo/chart", relative_file]))
                .is_empty());
        }
        assert!(generic_helm_coverage
            .match_command_all("helm", &args_vec(&["verify", "./chart-1.0.0.tgz"]),)
            .is_empty());
        assert!(generic_helm_coverage
            .match_command_all("helm", &args_vec(&["install", "fixture", "./chart"]))
            .is_empty());
        for fixed_credential in [
            "--ca-file=/srv/automation/ca.pem",
            "--cert-file=/srv/automation/client.pem",
            "--key-file=/srv/automation/client.key",
            "--keyring=/srv/automation/pubring.gpg",
        ] {
            assert!(generic_helm_coverage
                .match_command_all("helm", &args_vec(&["pull", "repo/chart", fixed_credential]),)
                .is_empty());
        }
        assert!(generic_helm_coverage
            .match_command_all(
                "helm",
                &args_vec(&[
                    "pull",
                    "repo/chart",
                    "--set-file=payload=/srv/automation/values.txt",
                ]),
            )
            .is_empty());
        assert!(generic_helm_coverage
            .match_command_all(
                "helm",
                &args_vec(&[
                    "pull",
                    "repo/chart",
                    "--output-dir=/srv/automation/rendered",
                ]),
            )
            .is_empty());
        assert!(generic_helm_coverage
            .match_command_all(
                "helm",
                &args_vec(&["package", "/srv/automation/chart", "-d=/srv/automation/out"]),
            )
            .is_empty());
        assert!(generic_helm_coverage
            .match_command_all(
                "helm",
                &args_vec(&["repo", "index", "/srv/automation/repository"]),
            )
            .is_empty());
        assert!(VerbCatalog::from_yaml(
            r#"
verbs:
  - name: index-repository
    binary: helm
    args: ["repo", "index", "/srv/automation/repository"]
    consequence: reversible
"#,
        )
        .is_err());
        assert!(VerbCatalog::from_yaml(
            r#"
verbs:
  - name: pull-with-fixed-credentials
    binary: helm
    args: ["pull", "repo/chart", "--cert-file=/srv/automation/client.pem", "--key-file=/srv/automation/client.key"]
    consequence: reversible
"#,
        )
        .is_err());
        for renderer in [
            "--post-renderer=/srv/automation/renderer",
            "--post-renderer=renderer",
        ] {
            assert!(generic_helm_coverage
                .match_command_all(
                    "helm",
                    &args_vec(&["template", "fixture", "repo/chart", renderer]),
                )
                .is_empty());
        }
        assert!(generic_helm_coverage
            .match_command_all(
                "helm",
                &args_vec(&["verify", "/srv/automation/chart-1.0.0.tgz"]),
            )
            .is_empty());
        assert!(generic_helm_coverage
            .match_command_all(
                "helm",
                &args_vec(&["install", "fixture", "/srv/automation/chart"]),
            )
            .is_empty());
        assert!(VerbCatalog::from_yaml(
            r#"
verbs:
  - name: broad-render
    binary: helm
    consequence: reversible
    trusted: true
    coverage:
      - name: template
        action: preauthorized
        command_path: ["template"]
"#,
        )
        .unwrap_err()
        .to_string()
        .contains("requires an exact argv template"));

        for kuberc in ["--kuberc=preferences.yaml", "--kuberc=./preferences.yaml"] {
            assert!(generic_kubectl_patch_coverage
                .match_command_all("kubectl", &args_vec(&["patch", "deployment/app", kuberc]),)
                .is_empty());
        }
        assert!(generic_kubectl_patch_coverage
            .match_command_all(
                "kubectl",
                &args_vec(&["patch", "deployment/app", "--kuberc=/etc/guard/kuberc.yaml",]),
            )
            .is_empty());
        VerbCatalog::from_yaml(
            r#"
verbs:
  - name: patch-with-fixed-kuberc
    binary: kubectl
    args: ["patch", "deployment/app", "--kuberc=/etc/guard/kuberc.yaml"]
    consequence: irreversible
"#,
        )
        .expect("an exact kuberc remains explicit operator authority");
        assert!(generic_kubectl_coverage
            .match_command_all(
                "kubectl",
                &args_vec(&["apply", "-k/srv/automation/kustomization"]),
            )
            .is_empty());

        let relative_coverage = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: inspect-inventory
    binary: ansible
    consequence: reversible
    trusted: true
    coverage:
      - name: bounded
        action: preauthorized
        inventory:
          options: ["-i", "--inventory"]
          values: ["inventory/production"]
"#,
        )
        .unwrap_err();
        assert!(relative_coverage
            .to_string()
            .contains("inventory value must be an absolute path"));

        let portable = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: apply-selected-manifest
    binary: kubectl
    args: ["apply", "-f", "{path}"]
    params:
      path: { pattern: "^(/srv/guard/manifests/app\\.yaml|/srv/guard/manifests/audit\\.yaml)$" }
    consequence: irreversible
  - name: inspect-controller
    binary: kubectl
    args: ["exec", "deploy/tools", "--", "ceph", "status"]
    consequence: reversible
"#,
        )
        .expect("absolute file operands and fixed non-path resource tokens remain valid");
        assert_eq!(portable.names().len(), 2);
    }

    #[test]
    fn single_argv_parameters_render_bounded_jsonpath_and_field_selectors() {
        let catalog = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: inspect-pods
    binary: kubectl
    args: ["get", "pods", "-o", "jsonpath={jsonpath}", "--field-selector", "{selector}"]
    params:
      jsonpath:
        pattern: '^\{\.metadata\.name\} \{\.status\.phase\}$'
        value_type: single_argv
        max_length: 96
      selector:
        pattern: '^status\.phase=Running, metadata\.name=api$'
        value_type: single_argv
        max_length: 96
    consequence: reversible
"#,
        )
        .unwrap();
        let verb = catalog.get("inspect-pods").unwrap();
        validate_synthesized_safety(verb).unwrap();
        let params = BTreeMap::from([
            (
                "jsonpath".to_string(),
                "{.metadata.name} {.status.phase}".to_string(),
            ),
            (
                "selector".to_string(),
                "status.phase=Running, metadata.name=api".to_string(),
            ),
        ]);
        let rendered = catalog.render("inspect-pods", &params).unwrap();
        assert_eq!(
            rendered.args[3],
            "jsonpath={.metadata.name} {.status.phase}"
        );
        assert_eq!(rendered.args[5], "status.phase=Running, metadata.name=api");
        assert_eq!(rendered.args.len(), 6, "spaces must not split argv");
        assert_eq!(verb.finite_parameter_sets().unwrap().len(), 1);

        let encoded = serde_yaml_ng::to_string(verb).unwrap();
        assert!(encoded.contains("value_type: single_argv"));
        assert!(encoded.contains("max_length: 96"));
    }

    #[test]
    fn single_argv_parameters_reject_shell_controls_and_require_a_bound() {
        let dangerous = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: inspect-pods
    binary: kubectl
    args: ["get", "pods", "--field-selector", "{selector}"]
    params:
      selector:
        pattern: '^[a-z; ]{1,32}$'
        value_type: single_argv
        max_length: 32
    consequence: reversible
"#,
        )
        .unwrap();
        let error =
            validate_synthesized_safety(dangerous.get("inspect-pods").unwrap()).unwrap_err();
        assert!(error.to_string().contains("shell control"), "got: {error}");

        let missing_bound = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: inspect-pods
    binary: kubectl
    args: ["get", "pods", "--field-selector", "{selector}"]
    params:
      selector:
        pattern: '^status\.phase=Running$'
        value_type: single_argv
    consequence: reversible
"#,
        )
        .unwrap_err();
        assert!(
            format!("{missing_bound:#}").contains("requires a positive max_length"),
            "got: {missing_bound:#}"
        );
    }

    #[test]
    fn generated_access_promotion_derives_consequence_from_command_shape() {
        let mut catalog = VerbCatalog::default();
        let candidate = |name: &str, binary: &str, args: &[&str], consequence| {
            let mut verb = synth_verb(binary, None, false, name);
            verb.args = args
                .iter()
                .map(|argument| (*argument).to_string())
                .collect();
            verb.baseline = false;
            verb.consequence = consequence;
            canonical_generated_access_verb(verb)
        };

        let cases = [
            (
                candidate(
                    "kubectl-delete",
                    "kubectl",
                    &["delete", "pod", "fixture"],
                    Reversibility::Reversible,
                ),
                Reversibility::Irreversible,
            ),
            (
                candidate(
                    "systemctl-stop",
                    "systemctl",
                    &["stop", "fixture.service"],
                    Reversibility::Reversible,
                ),
                Reversibility::Irreversible,
            ),
            (
                candidate(
                    "kubectl-get",
                    "kubectl",
                    &["get", "pods"],
                    Reversibility::Irreversible,
                ),
                Reversibility::Reversible,
            ),
            (
                candidate(
                    "uptime-pretty",
                    "uptime",
                    &["-p"],
                    Reversibility::Irreversible,
                ),
                Reversibility::Reversible,
            ),
        ];
        for (candidate, expected) in cases {
            let candidate = catalog.canonical_generated_access_verb(candidate).unwrap();
            let name = candidate.name.clone();
            catalog.upsert_access_verb(candidate).unwrap();
            let installed = catalog.get(&name).unwrap();
            assert!(installed.trusted);
            assert_eq!(installed.consequence, expected);
        }
    }

    const TOOLBOX_CATALOG_YAML: &str = r#"
verbs:
  - name: toolbox-ceph-read
    binary: kubectl
    args: ["-n", "rook-ceph", "exec", "deploy/rook-ceph-tools", "--", "ceph", "{command}"]
    params:
      command: { pattern: "^(status|df|health)$" }
    consequence: reversible
    trusted: true
"#;

    fn toolbox_wrapper(pattern: &str) -> Verb {
        let mut wrapper = synth_verb("kubectl", None, false, "access-generated-ceph-read");
        wrapper.baseline = false;
        wrapper.args = args_vec(&[
            "-n",
            "rook-ceph",
            "exec",
            "deploy/rook-ceph-tools",
            "--",
            "ceph",
            "{query}",
        ]);
        wrapper.params.insert(
            "query".to_string(),
            ParamSpec {
                pattern: pattern.to_string(),
                required: true,
                default: None,
                allow_dash: false,
            },
        );
        wrapper.consequence = Reversibility::Irreversible;
        canonical_generated_access_verb(wrapper)
    }

    #[test]
    fn generated_access_matcher_inherits_exact_catalog_consequence() {
        let mut catalog = VerbCatalog::from_yaml(TOOLBOX_CATALOG_YAML).unwrap();
        let wrapper = toolbox_wrapper("^(status|df)$");
        let wrapper = catalog.canonical_generated_access_verb(wrapper).unwrap();
        let name = wrapper.name.clone();
        catalog.upsert_access_verb(wrapper).unwrap();
        assert_eq!(
            catalog.get(&name).unwrap().consequence,
            Reversibility::Reversible,
            "every admitted command reverse-matches the reversible catalog verb"
        );
    }

    #[test]
    fn generated_access_rejects_a_forged_consequence_after_normalization() {
        let mut verb = synth_verb("kubectl", None, false, "access-generated-fixture");
        verb.baseline = false;
        verb.args = args_vec(&["get", "pods"]);
        verb.consequence = Reversibility::Irreversible;
        verb.name = generated_access_verb_name(&verb);
        let mut serialized = serde_json::to_value(canonical_generated_access_verb(verb)).unwrap();
        serialized["consequence"] = serde_json::json!("irreversible");
        assert!(parse_normalized_generated_access_verb(&serialized)
            .unwrap_err()
            .to_string()
            .contains("locally derived matcher consequence"));

        let mut destructive = synth_verb("kubectl", None, false, "access-generated-fixture");
        destructive.baseline = false;
        destructive.args = args_vec(&["delete", "pods"]);
        destructive.consequence = Reversibility::Reversible;
        destructive.name = generated_access_verb_name(&destructive);
        let mut serialized =
            serde_json::to_value(canonical_generated_access_verb(destructive)).unwrap();
        serialized["consequence"] = serde_json::json!("reversible");
        assert!(parse_normalized_generated_access_verb(&serialized)
            .unwrap_err()
            .to_string()
            .contains("locally derived matcher consequence"));
    }

    #[test]
    fn generated_access_identity_converges_when_all_provenance_fields_vary() {
        let mut first = synth_verb("fixturectl", None, false, "access-generated-fixture");
        first.baseline = false;
        first.args = args_vec(&["inspect", "{item}"]);
        first.params.insert(
            "item".to_string(),
            ParamSpec {
                pattern: "^[a-z]+$".to_string(),
                required: true,
                default: None,
                allow_dash: false,
            },
        );
        let mut second = first.clone();
        for (verb, source, evidence, regime, prompt, model, dimension, generated_unix) in [
            (
                &mut first,
                "source-one",
                "evidence-one",
                "regime-one",
                "prompt-one",
                "model-one",
                "dimension-one",
                1,
            ),
            (
                &mut second,
                "source-two",
                "evidence-two",
                "regime-two",
                "prompt-two",
                "model-two",
                "dimension-two",
                2,
            ),
        ] {
            verb.coverage = vec![VerbCoverageCell {
                name: "item".to_string(),
                action: CoverageAction::Evaluate,
                command_path: Vec::new(),
                required_args: Vec::new(),
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
                    source: source.to_string(),
                    evidence: vec![evidence.to_string()],
                    regime_stamp: regime.to_string(),
                    prompt_stamp: prompt.to_string(),
                    model_stamp: model.to_string(),
                    generated_unix,
                    probes: vec![CoverageProbe {
                        dimension: dimension.to_string(),
                        args: args_vec(&["inspect", "item"]),
                        expected_match: true,
                        observed_match: true,
                    }],
                    observation_replays: Vec::new(),
                }),
            }];
            verb.consequence = Reversibility::Irreversible;
            verb.name = generated_access_verb_name(verb);
        }
        let first = canonical_generated_access_verb(first);
        let second = canonical_generated_access_verb(second);
        assert_eq!(
            generated_access_matcher_shape(&first),
            generated_access_matcher_shape(&second)
        );
        assert_eq!(
            generated_access_verb_name(&first),
            generated_access_verb_name(&second)
        );
        assert_eq!(
            generated_access_matcher_digest(&generated_access_matcher_shape(&first)),
            generated_access_matcher_digest(&generated_access_matcher_shape(&second))
        );
        assert_eq!(first.consequence, second.consequence);
    }

    #[test]
    fn generated_access_matcher_with_mutating_shape_stays_irreversible() {
        // A kubectl exec wrapper is not one of the statically proven read-only
        // shapes, so the local consequence remains fail-closed regardless of
        // the operator catalog's unrelated coverage.
        let mut catalog = VerbCatalog::from_yaml(TOOLBOX_CATALOG_YAML).unwrap();
        let wrapper = toolbox_wrapper("^(status|osd-purge)$");
        let wrapper = catalog.canonical_generated_access_verb(wrapper).unwrap();
        let name = wrapper.name.clone();
        catalog.upsert_access_verb(wrapper).unwrap();
        assert_eq!(
            catalog.get(&name).unwrap().consequence,
            Reversibility::Irreversible
        );

        // The same rule applies to a free-text parameter.
        let mut catalog = VerbCatalog::from_yaml(TOOLBOX_CATALOG_YAML).unwrap();
        let wrapper = toolbox_wrapper("^[a-z]+$");
        let wrapper = catalog.canonical_generated_access_verb(wrapper).unwrap();
        let name = wrapper.name.clone();
        catalog.upsert_access_verb(wrapper).unwrap();
        assert_eq!(
            catalog.get(&name).unwrap().consequence,
            Reversibility::Irreversible
        );
    }

    #[test]
    fn typed_match_features_exclude_observed_argument_values() {
        let catalog = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: api-read
    binary: apictl
    consequence: reversible
    coverage:
      - name: target
        action: evaluate
        required_args: ["get"]
        min_args: 3
        max_args: 3
        target:
          position: 2
          values: ["fixture-bearer-value"]
"#,
        )
        .unwrap();
        let fixture_value = "fixture-bearer-value";
        let matches =
            catalog.match_command_all("apictl", &args_vec(&["get", "resource", fixture_value]));

        assert_eq!(matches.len(), 1);
        assert!(matches[0].features.contains("target:position:2"));
        assert!(!matches[0].features.iter().any(|feature| {
            feature.contains("allowed=")
                || feature.contains("observed=")
                || feature.contains(fixture_value)
        }));
    }

    #[test]
    fn catalog_platform_is_enforced_by_production_loading() {
        let incompatible = if cfg!(windows) { "unix" } else { "windows" };
        let incompatible_catalog = format!(
            "platform: {incompatible}\nverbs:\n  - name: inspect\n    binary: true\n    consequence: reversible\n"
        );
        let error = VerbCatalog::from_yaml(&incompatible_catalog).unwrap_err();
        assert!(error.to_string().contains("verb catalog targets platform"));
        let lint = VerbCatalog::lint_yaml(&incompatible_catalog);
        assert_eq!(lint.findings.len(), 1);
        assert!(lint.findings[0]
            .message
            .contains("verb catalog targets platform"));

        let compatible = if cfg!(windows) { "windows" } else { "unix" };
        VerbCatalog::from_yaml(&format!(
            "platform: {compatible}\nverbs:\n  - name: inspect\n    binary: true\n    consequence: reversible\n"
        ))
        .expect("catalog for the running platform loads");
    }

    #[test]
    fn example_verb_catalogs_parse_and_validate() {
        // Guards against example/doc drift: every shipped examples/verbs*.yaml
        // must actually load (anchored patterns, declared placeholders, no
        // duplicate names) -- the same check `guard server start --verbs`
        // performs at startup.
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
        let mut checked = 0;
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy();
            if name.starts_with("verbs") && name.ends_with(".yaml") {
                let yaml = std::fs::read_to_string(&path).unwrap();
                let document: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).unwrap();
                let platform = document
                    .as_mapping()
                    .and_then(|mapping| mapping.get("platform"))
                    .and_then(serde_yaml_ng::Value::as_str);
                match VerbCatalog::from_yaml(&yaml) {
                    Ok(_) => {}
                    Err(error)
                        if platform.is_some_and(|platform| {
                            (platform == "unix" && cfg!(windows))
                                || (platform == "windows" && cfg!(unix))
                        }) && error.to_string().contains("verb catalog targets platform") => {}
                    Err(error) => panic!("{} failed to load: {error}", path.display()),
                }
                checked += 1;
            }
        }
        assert!(
            checked >= 3,
            "expected to find the shipped verbs*.yaml examples"
        );
    }

    #[test]
    fn append_handles_empty_inline_and_trailing_key_catalogs() {
        let v = synth_verb(
            "fixturectl",
            Some("^(zones|networks)$"),
            false,
            "fixture-list",
        );
        let seeds = [
            "verbs: []\n",
            "verbs:\n  - name: a\n    binary: echo\n    consequence: reversible\n",
            "verbs:\n  - name: a\n    binary: echo\n    consequence: reversible\ndefaults:\n  timeout: 30\n",
        ];
        for seed in seeds {
            let dir = crate::learned_rules::authority_tempdir();
            let path = dir.path().join("verbs.yaml");
            crate::learned_rules::write_authority_file(&path, seed).unwrap();
            let mut cat = VerbCatalog::load(&path).unwrap();
            cat.append_verb(&v)
                .unwrap_or_else(|e| panic!("append failed for seed {seed:?}: {e}"));
            let reloaded = VerbCatalog::load(&path).unwrap();
            assert!(
                reloaded.names().contains(&"fixture-list".to_string()),
                "seed {seed:?} should gain the verb"
            );
        }
    }

    #[test]
    fn match_command_reverse_matches_a_raw_command_against_a_template() {
        let cat = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: k-get-pods
    binary: kubectl
    args: ["get", "pods", "-n", "{namespace}"]
    params:
      namespace: { pattern: "^(foo|bar)$" }
    consequence: reversible
    trusted: true
"#,
        )
        .unwrap();

        let r = cat
            .match_command("kubectl", &args_vec(&["get", "pods", "-n", "foo"]))
            .expect("should reverse-match");
        assert_eq!(r.name, "k-get-pods");
        assert_eq!(r.params.get("namespace").map(String::as_str), Some("foo"));
        assert!(r.trusted);

        // An enumerated-out-of-range value unifies positionally but fails
        // the param's pattern at render time -- `match_command` must treat
        // that as no match, not a match with an invalid binding.
        assert!(cat
            .match_command("kubectl", &args_vec(&["get", "pods", "-n", "prod"]))
            .is_none());

        // Wrong arity, wrong literal token, and wrong binary all fail to
        // unify at all.
        assert!(cat
            .match_command("kubectl", &args_vec(&["get", "pods"]))
            .is_none());
        assert!(cat
            .match_command("kubectl", &args_vec(&["delete", "pods", "-n", "foo"]))
            .is_none());
        assert!(cat
            .match_command("helm", &args_vec(&["get", "pods", "-n", "foo"]))
            .is_none());
    }

    #[test]
    fn match_command_rejects_duplicate_option_and_flag_bypass_attempts() {
        let cat = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: checked-helm-upgrade
    binary: helm
    args: ["upgrade", "--install", "{release}", "{chart}", "--namespace", "{namespace}", "--dry-run", "--diff"]
    params:
      release: { pattern: "^[a-z0-9-]+$" }
      chart: { pattern: "^[a-z0-9./-]+$" }
      namespace: { pattern: "^staging$" }
    consequence: reversible
    trusted: true
"#,
        )
        .unwrap();

        assert!(cat
            .match_command(
                "helm",
                &args_vec(&[
                    "upgrade",
                    "--install",
                    "grafana",
                    "./charts/grafana",
                    "--namespace",
                    "staging",
                    "--dry-run",
                    "--diff",
                ]),
            )
            .is_some());

        assert!(
            cat.match_command(
                "helm",
                &args_vec(&[
                    "upgrade",
                    "--install",
                    "grafana",
                    "./charts/grafana",
                    "--namespace",
                    "staging",
                    "--dry-run",
                    "--dry-run=false",
                    "--diff",
                ]),
            )
            .is_none(),
            "the typed argv template must not accept duplicate/equivalent option overrides"
        );
        assert!(
            cat.match_command(
                "helm",
                &args_vec(&[
                    "upgrade",
                    "--install",
                    "--atomic",
                    "grafana",
                    "./charts/grafana",
                    "--namespace",
                    "staging",
                    "--dry-run",
                    "--diff",
                ]),
            )
            .is_none(),
            "a flag inserted where a parameter belongs must fail the parameter schema"
        );
        assert!(
            cat.match_command(
                "helm",
                &args_vec(&[
                    "upgrade",
                    "--install",
                    "grafana",
                    "./charts/grafana",
                    "--namespace",
                    "prod",
                    "--dry-run",
                    "--diff",
                ]),
            )
            .is_none(),
            "target limits belong in the verb parameter pattern"
        );
    }

    #[test]
    fn match_command_tries_verbs_in_name_order_and_skips_non_matching_ones() {
        let cat = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: a-unrelated
    binary: kubectl
    args: ["delete", "pods"]
    consequence: irreversible
  - name: b-get-pods
    binary: kubectl
    args: ["get", "pods"]
    consequence: reversible
    trusted: true
"#,
        )
        .unwrap();
        let r = cat
            .match_command("kubectl", &args_vec(&["get", "pods"]))
            .expect("should match the second verb, not the first");
        assert_eq!(r.name, "b-get-pods");
    }

    #[test]
    fn match_command_rejects_path_qualified_spoof_like_binary_matching_does() {
        let cat = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: k-get-pods
    binary: kubectl
    args: ["get", "pods"]
    consequence: reversible
    trusted: true
"#,
        )
        .unwrap();
        assert!(cat
            .match_command("kubectl", &args_vec(&["get", "pods"]))
            .is_some());
        assert!(cat
            .match_command("/tmp/evil/kubectl", &args_vec(&["get", "pods"]))
            .is_none());
        assert!(cat
            .match_command("KUBECTL.EXE", &args_vec(&["get", "pods"]))
            .is_some());
    }

    #[test]
    fn match_args_template_extracts_single_placeholder_with_prefix_and_suffix() {
        let templates = vec!["café-{n}-suffix".to_string()];
        let observed = args_vec(&["café-7-suffix"]);
        let captured = match_args_template(&templates, &observed).unwrap();
        assert_eq!(captured.get("n").map(String::as_str), Some("7"));

        // A value not honoring the literal prefix/suffix does not unify.
        assert!(match_args_template(&templates, &args_vec(&["nope"])).is_none());
    }

    #[test]
    fn match_args_template_requires_consistent_value_for_a_repeated_name() {
        let templates = vec!["{x}".to_string(), "{x}".to_string()];
        assert!(match_args_template(&templates, &args_vec(&["a", "a"])).is_some());
        assert!(match_args_template(&templates, &args_vec(&["a", "b"])).is_none());
    }

    #[test]
    fn match_args_template_declines_a_token_with_multiple_placeholders() {
        let templates = vec!["{a}-{b}".to_string()];
        // Ambiguous split point: not reverse-matchable, even though it would
        // still be invocable via an explicit `--verb` call.
        assert!(match_args_template(&templates, &args_vec(&["x-y"])).is_none());
    }

    #[test]
    fn match_args_template_requires_exact_arity() {
        let templates = vec!["a".to_string(), "b".to_string()];
        assert!(match_args_template(&templates, &args_vec(&["a"])).is_none());
        assert!(match_args_template(&templates, &args_vec(&["a", "b", "c"])).is_none());
    }

    #[test]
    fn typed_coverage_matches_conjunctive_command_dimensions() {
        let inventory = if cfg!(windows) {
            r"C:\guard\inventory\prod"
        } else {
            "/srv/guard/inventory/prod"
        };
        let catalog = format!(
            r#"
verbs:
  - name: ansible-check
    binary: ansible
    consequence: reversible
    trusted: true
    coverage:
      - name: bounded-check
        action: preauthorized
        required_args: ["--check"]
        forbidden_args: ["--diff=false"]
        options:
          - options: ["-m", "--module-name"]
            values: ["ping"]
        target:
          position: 0
          values: ["web"]
        inventory:
          options: ["-i", "--inventory"]
          values: ['{inventory}']
        namespace:
          options: ["--namespace"]
          values: ["prod"]
        fanout:
          options: ["--limit"]
          max: 2
"#,
        );
        let cat = VerbCatalog::from_yaml(&catalog).unwrap();

        let matching = args_vec(&[
            "web",
            "-m",
            "ping",
            "-i",
            inventory,
            "--namespace=prod",
            "--limit",
            "one,two",
            "--check",
        ]);
        let matches = cat.match_command_all("ansible", &matching);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rendered.name, "ansible-check");
        assert_eq!(matches[0].cell, "bounded-check");
        assert_eq!(matches[0].action, CoverageAction::Preauthorized);

        let without_check = matching
            .iter()
            .filter(|arg| arg.as_str() != "--check")
            .cloned()
            .collect::<Vec<_>>();
        assert!(cat.match_command_all("ansible", &without_check).is_empty());

        let inventory_option = format!("--inventory={inventory}");
        let too_many = args_vec(&[
            "web",
            "--module-name=ping",
            &inventory_option,
            "--namespace=prod",
            "--limit=one,two,three",
            "--check",
        ]);
        assert!(cat.match_command_all("ansible", &too_many).is_empty());

        let duplicate_selector = args_vec(&[
            "web",
            "-m",
            "ping",
            "-i",
            inventory,
            "--namespace",
            "prod",
            "--limit=one",
            "--limit",
            "two",
            "--check",
        ]);
        assert!(cat
            .match_command_all("ansible", &duplicate_selector)
            .is_empty());

        let missing_value = args_vec(&[
            "web",
            "-m",
            "ping",
            "-i",
            inventory,
            "--namespace",
            "prod",
            "--limit",
            "--check",
        ]);
        assert!(cat.match_command_all("ansible", &missing_value).is_empty());
    }

    #[test]
    fn protected_preauthorization_requires_a_parsed_command_path() {
        let error = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: broad-read
    binary: kubectl
    consequence: reversible
    trusted: true
    coverage:
      - name: get
        action: preauthorized
        required_args: ["get"]
"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("must declare command_path"));
    }

    #[test]
    fn unmatched_coverage_cell_does_not_deny_its_complement() {
        let cat = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: check-only
    binary: ansible
    consequence: reversible
    trusted: true
    coverage:
      - name: check
        action: preauthorized
        required_args: ["--check"]
"#,
        )
        .unwrap();

        let apply = args_vec(&["all"]);
        assert!(cat.match_command_all("ansible", &apply).is_empty());
    }

    #[test]
    fn caller_environment_requires_explicit_typed_cell_authority() {
        let approved_config = native_absolute_fixture_path("ansible.cfg");
        let approved_config_yaml = serialized_yaml_inline(&approved_config);
        let cat = VerbCatalog::from_yaml(&format!(
            r#"
verbs:
  - name: ansible-check
    binary: ansible
    consequence: reversible
    trusted: true
    coverage:
      - name: check
        action: preauthorized
        required_args: ["--check"]
        environment:
          - name: ANSIBLE_CONFIG
            values: [{}]
"#,
            approved_config_yaml
        ))
        .unwrap();
        let command = args_vec(&["all", "--check"]);
        let mut plain = BTreeMap::new();
        plain.insert("ANSIBLE_CONFIG".to_string(), approved_config);
        let matches = cat.match_command_all_with_environment(
            "ansible",
            &command,
            &plain,
            &BTreeMap::new(),
            &BTreeMap::new(),
        );
        assert!(matches[0].environment_authorized);

        plain.insert(
            "ANSIBLE_CONFIG".to_string(),
            native_absolute_fixture_path("caller-controlled.cfg"),
        );
        let matches = cat.match_command_all_with_environment(
            "ansible",
            &command,
            &plain,
            &BTreeMap::new(),
            &BTreeMap::new(),
        );
        assert!(!matches[0].environment_authorized);

        let mut unexpected = BTreeMap::new();
        unexpected.insert("EXTRA".to_string(), "value".to_string());
        let matches = cat.match_command_all_with_environment(
            "ansible",
            &command,
            &unexpected,
            &BTreeMap::new(),
            &BTreeMap::new(),
        );
        assert!(!matches[0].environment_authorized);
    }

    #[test]
    fn environment_patterns_must_be_anchored() {
        let error = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: unsafe-env
    binary: ansible
    consequence: reversible
    trusted: true
    coverage:
      - name: check
        action: preauthorized
        required_args: ["--check"]
        environment:
          - name: ANSIBLE_CONFIG
            pattern: "/srv/.*"
"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("must be fully anchored"));

        let vault_identity_error = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: unsafe-vault-identities
    binary: ansible
    consequence: reversible
    trusted: true
    coverage:
      - name: check
        action: preauthorized
        required_args: ["--check"]
        environment:
          - name: ANSIBLE_VAULT_IDENTITY_LIST
            pattern: "^.+$"
"#,
        )
        .unwrap_err();
        assert!(vault_identity_error.to_string().contains("operator-fixed"));

        let secret_config_error = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: unsafe-secret-config
    binary: ansible
    consequence: reversible
    trusted: true
    coverage:
      - name: check
        action: preauthorized
        required_args: ["--check"]
        environment:
          - name: ANSIBLE_CONFIG
            source: secret-file
            values: ["ansible/config"]
"#,
        )
        .unwrap_err();
        assert!(secret_config_error
            .to_string()
            .contains("requires a plain fixed path"));

        VerbCatalog::from_yaml(
            r#"
verbs:
  - name: private-key-secret-file
    binary: ansible
    consequence: reversible
    trusted: true
    coverage:
      - name: check
        action: preauthorized
        required_args: ["--check"]
        environment:
          - name: ANSIBLE_PRIVATE_KEY_FILE
            source: secret-file
            values: ["ansible/private-key"]
"#,
        )
        .expect("a fixed daemon-created private-key file is typed credential authority");

        let ssh_executable = native_absolute_fixture_path("ssh");
        let ssh_executable_yaml = serialized_yaml_inline(&ssh_executable);
        VerbCatalog::from_yaml(&format!(
            r#"
verbs:
  - name: fixed-ansible-ssh
    binary: ansible
    consequence: reversible
    trusted: true
    coverage:
      - name: check
        action: preauthorized
        required_args: ["--check"]
        environment:
          - name: ANSIBLE_SSH_EXECUTABLE
            values: [{}]
"#,
            ssh_executable_yaml
        ))
        .expect("an exact Ansible executable path is typed authority");

        let tool_path = serialized_yaml_inline(&native_absolute_fixture_path("tool"));
        for name in [
            "ANSIBLE_SSH_ARGS",
            "ANSIBLE_UNKNOWN_PLUGIN_SELECTOR",
            "UNCLASSIFIED_TOOL_SETTING",
        ] {
            let yaml = format!(
                "verbs:\n  - name: unsafe-ansible-env\n    binary: ansible\n    consequence: reversible\n    trusted: true\n    coverage:\n      - name: check\n        action: preauthorized\n        required_args: [\"--check\"]\n        environment:\n          - name: {name}\n            values: [{tool_path}]\n"
            );
            let error = VerbCatalog::from_yaml(&yaml).unwrap_err();
            assert!(error.to_string().contains("cannot be preauthorized"));
        }
    }

    #[test]
    fn collect_all_order_is_independent_of_yaml_declaration_order() {
        let first = r#"
verbs:
  - name: broad
    binary: kubectl
    consequence: reversible
    trusted: true
    coverage:
      - name: reads
        action: preauthorized
        command_path: ["get"]
        required_args: ["get"]
  - name: narrow
    binary: kubectl
    consequence: reversible
    coverage:
      - name: namespace
        action: evaluate
        required_args: ["get"]
        namespace:
          options: ["-n", "--namespace"]
          values: ["prod"]
"#;
        let second = r#"
verbs:
  - name: narrow
    binary: kubectl
    consequence: reversible
    coverage:
      - name: namespace
        action: evaluate
        required_args: ["get"]
        namespace:
          options: ["-n", "--namespace"]
          values: ["prod"]
  - name: broad
    binary: kubectl
    consequence: reversible
    trusted: true
    coverage:
      - name: reads
        action: preauthorized
        command_path: ["get"]
        required_args: ["get"]
"#;
        let command = args_vec(&["get", "pods", "--namespace=prod"]);
        let summarize = |catalog: VerbCatalog| {
            catalog
                .match_command_all("kubectl", &command)
                .into_iter()
                .map(|matched| (matched.rendered.name, matched.cell, matched.action))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            summarize(VerbCatalog::from_yaml(first).unwrap()),
            summarize(VerbCatalog::from_yaml(second).unwrap())
        );
    }

    #[test]
    fn auto_promoted_coverage_cannot_mint_override_marker() {
        let err = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: generated-deny
    binary: kubectl
    consequence: reversible
    trusted: true
    auto_promoted: true
    coverage:
      - name: deletes
        action: deny
        required_args: ["delete"]
        override_marker: operator:delete
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("may not mint override markers"));
    }

    #[test]
    fn auto_promoted_verb_cannot_authorize_caller_environment() {
        let approved_config = serialized_yaml_inline(&native_absolute_fixture_path("ansible.cfg"));
        let error = VerbCatalog::from_yaml(&format!(
            r#"
verbs:
  - name: generated-check
    binary: ansible
    consequence: reversible
    trusted: true
    auto_promoted: true
    coverage:
      - name: check
        action: preauthorized
        required_args: ["--check"]
        environment:
          - name: ANSIBLE_CONFIG
            values: [{}]
"#,
            approved_config
        ))
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("may not authorize caller environment bindings"));
    }

    #[test]
    fn auto_promoted_verb_rejects_literal_sensitive_authority() {
        let value = ["q", "7"].concat();
        let yaml = format!(
            r#"
verbs:
  - name: generated-auth
    binary: redis-cli
    args: ["-a", "{value}"]
    consequence: reversible
    trusted: true
    auto_promoted: true
"#
        );
        let error = VerbCatalog::from_yaml(&yaml).unwrap_err();
        assert!(error.to_string().contains("literal credential argv"));
    }

    #[test]
    fn forged_auto_promoted_consequence_is_rejected_at_catalog_load() {
        let error = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: generated-delete
    binary: kubectl
    args: ["delete", "pods"]
    consequence: reversible
    trusted: true
    auto_promoted: true
    promotion_stamp: test-stamp
    coverage:
      - name: evidence-backed
        action: preauthorized
        required_args: ["delete", "pods"]
"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("consequence does not match"));
    }

    #[test]
    fn forged_auto_promoted_parameter_cannot_smuggle_a_mutating_subcommand() {
        let error = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: generated-pod-read
    binary: kubectl
    args: ["--namespace", "get", "{operation}", "pods", "--all"]
    params:
      operation:
        pattern: "^(delete)$"
        required: true
    consequence: reversible
    trusted: true
    auto_promoted: true
    promotion_stamp: test-stamp
"#,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("selects unknown kubectl subcommand"));
    }

    #[test]
    fn auto_promoted_safe_finite_parameter_commands_remain_valid() {
        let catalog = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: generated-pod-read
    binary: kubectl
    args: ["get", "pods", "--namespace", "{namespace}"]
    params:
      namespace:
        pattern: "^(dev|staging)$"
        required: true
    consequence: reversible
    trusted: true
    auto_promoted: true
    promotion_stamp: test-stamp
"#,
        )
        .unwrap();
        assert!(catalog.get("generated-pod-read").is_some());
    }

    #[test]
    fn auto_promoted_spaced_promql_values_render_reverse_match_and_reload() {
        let api_query = r#"sum(rate(http_requests_total{job="api"}[5m])) by (job)"#;
        let worker_query = r#"sum(rate(http_requests_total{job="worker"}[5m])) by (job)"#;
        let pattern = format!(
            "^({}|{})$",
            regex::escape(api_query),
            regex::escape(worker_query)
        );
        let mut verb = synth_verb("kubectl", None, true, "generated-prom-query");
        verb.args = args_vec(&["get", "pods", "--field-selector", "{query}"]);
        verb.params.insert(
            "query".to_string(),
            ParamSpec::bounded_single_argv(
                pattern,
                api_query.chars().count().max(worker_query.chars().count()),
                false,
            ),
        );
        verb.auto_promoted = true;
        verb.promotion_stamp = Some("test-stamp".to_string());

        let evidence = vec![
            args_vec(&["get", "pods", "--field-selector", api_query]),
            args_vec(&["get", "pods", "--field-selector", worker_query]),
        ];
        validate_auto_promoted_verb_safety(&verb, &evidence).unwrap();

        let yaml = serde_yaml_ng::to_string(&CatalogFile {
            platform: None,
            verbs: vec![verb],
        })
        .unwrap();
        assert!(yaml.contains("value_type: single_argv"));
        assert!(yaml.contains("max_length:"));
        let catalog = VerbCatalog::from_yaml(&yaml).unwrap();
        let rendered = catalog
            .render("generated-prom-query", &params(&[("query", api_query)]))
            .unwrap();
        assert_eq!(rendered.args, evidence[0]);
        assert_eq!(
            catalog.match_command_all("kubectl", &rendered.args).len(),
            1,
            "the reloaded matcher must reverse-match one spaced argv element"
        );
        let outside = args_vec(&[
            "get",
            "pods",
            "--field-selector",
            r#"sum(rate(http_requests_total[5m])) by (job)"#,
        ]);
        assert!(catalog.match_command_all("kubectl", &outside).is_empty());
    }

    #[test]
    fn auto_promoted_spaced_values_reject_shell_controls_and_unbounded_text() {
        let spaced_query = r#"sum(rate(http_requests_total[5m])) by (job)"#;
        let mut unsafe_verb = synth_verb("kubectl", None, true, "generated-prom-query");
        unsafe_verb.args = args_vec(&["get", "pods", "--field-selector", "{query}"]);
        unsafe_verb.params.insert(
            "query".to_string(),
            ParamSpec {
                pattern: format!("^({})$", regex::escape(spaced_query)),
                required: true,
                default: None,
                allow_dash: false,
            },
        );
        unsafe_verb.auto_promoted = true;
        unsafe_verb.promotion_stamp = Some("test-stamp".to_string());
        let error = validate_auto_promoted_verb_safety(
            &unsafe_verb,
            &[args_vec(&["get", "pods", "--field-selector", spaced_query])],
        )
        .unwrap_err();
        assert!(error.to_string().contains("single_argv"), "got: {error}");

        let unsafe_query = r#"sum(rate(http_requests_total[5m])) by (job); delete"#;
        unsafe_verb.params.insert(
            "query".to_string(),
            ParamSpec::bounded_single_argv(
                format!("^({})$", regex::escape(unsafe_query)),
                unsafe_query.chars().count(),
                false,
            ),
        );
        let error = validate_auto_promoted_verb_safety(
            &unsafe_verb,
            &[args_vec(&["get", "pods", "--field-selector", unsafe_query])],
        )
        .unwrap_err();
        assert!(error.to_string().contains("shell control"), "got: {error}");

        unsafe_verb.params.insert(
            "query".to_string(),
            ParamSpec::bounded_single_argv("^.+$".to_string(), 4096, false),
        );
        let error = validate_auto_promoted_verb_safety(&unsafe_verb, &[]).unwrap_err();
        assert!(error.to_string().contains("too permissive"), "got: {error}");
    }

    #[test]
    fn forged_auto_promoted_broad_regex_is_rejected_at_catalog_load() {
        let error = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: generated-prod-get
    binary: kubectl
    args: ["get", "pods", "{target}"]
    params:
      target:
        pattern: "^prod-[a-z]+$"
        required: true
    consequence: reversible
    trusted: true
    auto_promoted: true
    promotion_stamp: test-stamp
"#,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("finite plain literal alternation"));
    }

    #[test]
    fn forged_auto_promoted_regex_escape_is_rejected_at_catalog_load() {
        let error = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: generated-digit-get
    binary: kubectl
    args: ["get", "pods", "{target}"]
    params:
      target:
        pattern: '^(\d)$'
        required: true
    consequence: reversible
    trusted: true
    auto_promoted: true
    promotion_stamp: test-stamp
"#,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("generator-canonical exact pattern"));
    }

    #[test]
    fn cwd_coverage_matches_only_the_operator_approved_canonical_directory() {
        let root = crate::learned_rules::authority_tempdir();
        let root = root.path().canonicalize().unwrap();
        let other = crate::learned_rules::authority_tempdir();
        let root_yaml = serde_yaml_ng::to_string(&root.to_string_lossy().to_string()).unwrap();
        let yaml = format!(
            r#"
verbs:
  - name: project-status
    binary: true
    consequence: reversible
    trusted: true
    coverage:
      - name: project-root
        action: preauthorized
        cwd: {}
"#,
            root_yaml.trim()
        );
        let catalog = VerbCatalog::from_yaml(&yaml).unwrap();
        let empty = BTreeMap::new();

        assert_eq!(
            catalog
                .match_command_all_with_environment_and_cwd(
                    "true",
                    &[],
                    &empty,
                    &empty,
                    &empty,
                    Some(&root),
                )
                .len(),
            1
        );
        assert!(catalog
            .match_command_all_with_environment_and_cwd(
                "true",
                &[],
                &empty,
                &empty,
                &empty,
                Some(other.path()),
            )
            .is_empty());
        assert!(catalog.match_command_all("true", &[]).is_empty());

        let unbound = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: unbound-status
    binary: true
    consequence: reversible
    trusted: true
    coverage:
      - name: status
        action: preauthorized
"#,
        )
        .unwrap();
        assert!(unbound
            .match_command_all_with_environment_and_cwd(
                "true",
                &[],
                &empty,
                &empty,
                &empty,
                Some(&root),
            )
            .is_empty());

        let exact = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: exact-status
    binary: true
    consequence: reversible
    trusted: true
"#,
        )
        .unwrap();
        assert!(exact
            .match_command_all_with_environment_and_cwd(
                "true",
                &[],
                &empty,
                &empty,
                &empty,
                Some(&root),
            )
            .is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn cwd_coverage_rejects_a_symlink_instead_of_approving_its_target() {
        let parent = crate::learned_rules::authority_tempdir();
        let project = parent.path().join("project");
        let alias = parent.path().join("project-link");
        std::fs::create_dir(&project).unwrap();
        std::os::unix::fs::symlink(&project, &alias).unwrap();
        let yaml = format!(
            r#"
verbs:
  - name: project-status
    binary: true
    consequence: reversible
    trusted: true
    coverage:
      - name: project-root
        action: preauthorized
        cwd: "{}"
"#,
            alias.display()
        );

        let error = VerbCatalog::from_yaml(&yaml).unwrap_err();
        assert!(error.to_string().contains("is not canonical"), "{error:#}");
    }

    #[test]
    fn operator_baseline_denies_are_normalized_sticky() {
        let catalog = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: operator-boundary
    binary: kubectl
    consequence: irreversible
    coverage:
      - name: destructive
        action: deny
        required_args: ["delete"]
"#,
        )
        .unwrap();
        let verb = catalog.get("operator-boundary").unwrap();
        assert!(verb.coverage[0].sticky);

        let mut programmatic = verb.clone();
        programmatic.name = "unsafe-boundary".to_string();
        programmatic.coverage[0].sticky = false;
        assert!(catalog
            .validate_candidate(&programmatic)
            .unwrap_err()
            .to_string()
            .contains("baseline deny coverage must be sticky"));
    }

    #[test]
    fn operator_catalog_cannot_occupy_saved_grant_namespace() {
        let error = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: grant-collision-generated
    binary: "true"
    consequence: reversible
"#,
        )
        .expect_err("reserved namespace must fail");
        assert!(error.to_string().contains("reserved saved-grant namespace"));
    }

    #[test]
    fn operator_catalog_cannot_occupy_generated_access_namespace() {
        let error = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: access-generated-collision
    binary: "true"
    consequence: reversible
"#,
        )
        .expect_err("reserved namespace must fail");
        assert!(error
            .to_string()
            .contains("reserved generated-access namespace"));
    }

    #[test]
    fn hot_reload_preserves_daemon_owned_coverage() {
        let dir = crate::learned_rules::authority_tempdir();
        let path = dir.path().join("verbs.yaml");
        crate::learned_rules::write_authority_file(
            &path,
            "verbs:\n  - name: operator-one\n    binary: uptime\n    consequence: reversible\n",
        )
        .unwrap();
        let mut catalog = VerbCatalog::load(&path).unwrap();

        let mut saved = synth_verb("fixturectl", Some("^zones$"), false, "grant-live");
        saved.name = "grant-live".to_string();
        catalog.upsert_saved_grant_verb(saved).unwrap();
        let mut access = synth_verb(
            "fixturectl",
            Some("^networks$"),
            false,
            "access-generated-live",
        );
        access.name = "access-generated-live".to_string();
        access.baseline = false;
        access = canonical_generated_access_verb(access);
        let access_name = access.name.clone();
        catalog.upsert_access_verb(access).unwrap();

        crate::learned_rules::write_authority_file(
            &path,
            "verbs:\n  - name: operator-two\n    binary: hostname\n    consequence: reversible\n",
        )
        .unwrap();
        catalog.mtime = None;
        assert!(catalog.reload_if_stale().unwrap());
        assert!(catalog.get("operator-one").is_none());
        assert!(catalog.get("operator-two").is_some());
        assert!(catalog.get("grant-live").is_some());
        assert!(catalog
            .get(&access_name)
            .is_some_and(|verb| verb.trusted && !verb.baseline));
    }

    fn canonical_generated_access_verb(mut verb: Verb) -> Verb {
        verb.name = generated_access_verb_name(&verb);
        verb
    }

    fn args_vec(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn unused_declared_parameter_is_rejected_at_load() {
        let yaml = r#"
verbs:
  - name: show-unit-status
    binary: systemctl
    args: ["status"]
    params:
      op: { pattern: "^(start|stop)$" }
    consequence: reversible
"#;
        let error = VerbCatalog::from_yaml(yaml).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("declares parameter 'op' but no template references {op}"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn parameter_referenced_only_by_the_revert_template_is_used() {
        let yaml = r#"
verbs:
  - name: scale-deployment
    binary: kubectl
    args: ["scale", "deployment/{name}", "--replicas=2", "-n", "fixture"]
    params:
      name: { pattern: "^[a-z-]+$" }
      context: { pattern: "^(fixture|staging)$", required: false, default: "fixture" }
    consequence: recoverable
    revert: { binary: kubectl, args: ["--context", "{context}", "scale", "deployment/{name}", "--replicas=1", "-n", "fixture"] }
"#;
        assert!(VerbCatalog::from_yaml(yaml).is_ok());
    }

    #[test]
    fn generated_access_normalization_rejects_rollback_only_parameters() {
        let mut verb = synth_verb("kubectl", None, false, "access-generated-fixture");
        verb.baseline = false;
        verb.args = args_vec(&["annotate", "pod/example"]);
        verb.params.insert(
            "overwrite".to_string(),
            ParamSpec {
                pattern: "^(true|false)$".to_string(),
                required: false,
                default: Some("true".to_string()),
                allow_dash: false,
            },
        );
        verb.revert = Some(VerbCommand {
            binary: "kubectl".to_string(),
            args: args_vec(&["annotate", "pod/example", "--overwrite={overwrite}"]),
        });
        assert!(normalize_generated_access_verb(verb).is_err());
    }

    #[test]
    fn generated_access_normalization_rejects_unknown_forward_placeholders() {
        let mut verb = synth_verb("kubectl", None, false, "access-generated-fixture");
        verb.baseline = false;
        verb.args = args_vec(&["apply", "-f", "{manifest}"]);
        assert!(normalize_generated_access_verb(verb).is_err());
    }

    #[test]
    fn generated_access_normalization_rejects_sensitive_literals_without_echoing_them() {
        let sensitive = ["sk-", &"Ab1".repeat(8)].concat();
        let mut argument = synth_verb("fixturectl", None, false, "access-generated-fixture");
        argument.baseline = false;
        argument.args = vec![sensitive.clone()];
        let argument_error = normalize_generated_access_verb(argument).unwrap_err();
        assert!(!argument_error.to_string().contains(&sensitive));

        let mut binary = synth_verb("fixturectl", None, false, "access-generated-fixture");
        binary.baseline = false;
        binary.binary = sensitive.clone();
        let binary_error = normalize_generated_access_verb(binary).unwrap_err();
        assert!(!binary_error.to_string().contains(&sensitive));
    }

    #[test]
    fn generated_access_normalization_rejects_sensitive_parameter_authority() {
        let value = ["q", "7"].concat();

        let mut default = synth_verb("fixturectl", None, false, "access-generated-fixture");
        default.baseline = false;
        default.args = vec!["inspect".to_string(), "{password}".to_string()];
        default.params.insert(
            "password".to_string(),
            ParamSpec {
                pattern: "^[a-z0-9]+$".to_string(),
                required: false,
                default: Some(value.clone()),
                allow_dash: false,
            },
        );
        let error = normalize_generated_access_verb(default).unwrap_err();
        assert!(error.to_string().contains("sensitive authority metadata"));
        assert!(!error.to_string().contains(&value));

        let mut pattern = synth_verb("fixturectl", None, false, "access-generated-fixture");
        pattern.baseline = false;
        pattern.args = vec!["inspect".to_string(), "{target}".to_string()];
        pattern.params.insert(
            "target".to_string(),
            ParamSpec {
                pattern: format!("^--password={value}$"),
                required: true,
                default: None,
                allow_dash: true,
            },
        );
        let error = normalize_generated_access_verb(pattern).unwrap_err();
        assert!(error.to_string().contains("sensitive authority metadata"));
        assert!(!error.to_string().contains(&value));
    }

    #[test]
    fn generated_access_normalization_rejects_sensitive_constraint_values() {
        let value = ["q", "7"].concat();
        let mut verb = synth_verb("fixturectl", None, false, "access-generated-fixture");
        verb.baseline = false;
        verb.args = vec!["inspect".to_string()];
        verb.coverage.push(VerbCoverageCell {
            name: "bounded".to_string(),
            action: CoverageAction::Evaluate,
            command_path: Vec::new(),
            required_args: Vec::new(),
            forbidden_args: Vec::new(),
            min_args: None,
            max_args: None,
            options: vec![ValueConstraint {
                options: vec!["--password".to_string()],
                position: None,
                values: vec![value.clone()],
                allow_dash: false,
                required: true,
                allow_multiple: false,
            }],
            target: None,
            inventory: None,
            namespace: None,
            fanout: None,
            cwd: None,
            environment: Vec::new(),
            override_marker: None,
            sticky: false,
            provenance: None,
        });
        let error = normalize_generated_access_verb(verb).unwrap_err();
        assert!(error.to_string().contains("sensitive authority metadata"));
        assert!(!error.to_string().contains(&value));
    }

    #[test]
    fn sensitive_generated_defaults_cannot_install_or_render() {
        let value = ["q", "7"].concat();
        let mut verb = synth_verb("fixturectl", None, false, "access-generated-fixture");
        verb.baseline = false;
        verb.args = vec!["inspect".to_string(), "{password}".to_string()];
        verb.params.insert(
            "password".to_string(),
            ParamSpec {
                pattern: "^[a-z0-9]+$".to_string(),
                required: false,
                default: Some(value.clone()),
                allow_dash: false,
            },
        );
        verb.name = generated_access_verb_name(&verb);
        let name = verb.name.clone();
        let mut catalog = VerbCatalog::empty();
        let error = catalog.upsert_access_verb(verb).unwrap_err();
        assert!(!error.to_string().contains(&value));
        assert!(catalog.render(&name, &BTreeMap::new()).is_err());
    }

    #[test]
    fn generated_access_reclassifies_concrete_parameter_argv_before_use() {
        fn install(
            binary: &str,
            templates: Vec<String>,
            params: BTreeMap<String, ParamSpec>,
        ) -> (VerbCatalog, String) {
            let mut verb = synth_verb(binary, None, false, "access-generated-fixture");
            verb.baseline = false;
            verb.args = templates;
            verb.params = params;
            verb.consequence = canonical_generated_access_consequence(&verb);
            verb.name = generated_access_verb_name(&verb);
            let name = verb.name.clone();
            let mut catalog = VerbCatalog::empty();
            catalog.upsert_access_verb(verb).unwrap();
            (catalog, name)
        }
        fn spec(pattern: &str, allow_dash: bool) -> ParamSpec {
            ParamSpec {
                pattern: pattern.to_string(),
                required: true,
                default: None,
                allow_dash,
            }
        }

        let value = ["q", "7"].concat();
        let (split_catalog, split_name) = install(
            "fixturectl",
            args_vec(&["{option}", "{operand}"]),
            BTreeMap::from([
                ("option".to_string(), spec("^--[a-z]{8}$", true)),
                ("operand".to_string(), spec("^[a-z0-9]{2}$", false)),
            ]),
        );
        let split_params = BTreeMap::from([
            ("option".to_string(), "--password".to_string()),
            ("operand".to_string(), value.clone()),
        ]);
        assert!(split_catalog.render(&split_name, &split_params).is_err());
        assert!(split_catalog
            .match_command("fixturectl", &["--password".to_string(), value.clone()])
            .is_none());
        let benign_params = BTreeMap::from([
            ("option".to_string(), "--endpoint".to_string()),
            ("operand".to_string(), value.clone()),
        ]);
        assert!(split_catalog.render(&split_name, &benign_params).is_ok());

        let binary = "fixturectl";
        let argument = format!("--password={value}");
        let (catalog, name) = install(
            binary,
            args_vec(&["{argument}"]),
            BTreeMap::from([(
                "argument".to_string(),
                spec("^--[a-z]{8}=[a-z0-9]{2}$", true),
            )]),
        );
        let params = BTreeMap::from([("argument".to_string(), argument.clone())]);
        assert!(catalog.render(&name, &params).is_err());
        assert!(catalog.match_command(binary, &[argument]).is_none());

        // Exercise the MySQL short-password detector below catalog admission.
        // MySQL itself remains unprofiled and cannot enter executable authority.
        let mysql_argument = format!("-p{value}");
        let mut mysql = synth_verb("mysql", None, false, "access-generated-fixture");
        mysql.baseline = false;
        mysql.args = args_vec(&["{argument}"]);
        mysql.params =
            BTreeMap::from([("argument".to_string(), spec("^-[a-z][a-z0-9]{2}$", true))]);
        mysql.name = generated_access_verb_name(&mysql);
        let mysql_name = mysql.name.clone();
        let mut mysql_render_catalog = VerbCatalog::empty();
        mysql_render_catalog.verbs.insert(mysql_name.clone(), mysql);
        let mysql_params = BTreeMap::from([("argument".to_string(), mysql_argument.clone())]);
        assert!(mysql_render_catalog
            .render(&mysql_name, &mysql_params)
            .is_err());
        assert!(mysql_render_catalog
            .match_command("mysql", &[mysql_argument])
            .is_none());
    }

    #[test]
    fn generated_access_rejects_sensitive_provenance_stamps() {
        let value = ["q", "7"].concat();
        for stamp in ["source", "evidence", "regime", "prompt", "model"] {
            let mut verb = synth_verb("fixturectl", None, false, "access-generated-fixture");
            verb.baseline = false;
            verb.args = args_vec(&["status"]);
            verb.coverage = vec![VerbCoverageCell {
                name: "exact".to_string(),
                action: CoverageAction::Evaluate,
                command_path: Vec::new(),
                required_args: Vec::new(),
                forbidden_args: Vec::new(),
                min_args: Some(1),
                max_args: Some(1),
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
                    source: if stamp == "source" {
                        format!("password={value}")
                    } else {
                        "fixture".to_string()
                    },
                    evidence: (stamp == "evidence")
                        .then(|| format!("password={value}"))
                        .into_iter()
                        .collect(),
                    regime_stamp: if stamp == "regime" {
                        format!("password={value}")
                    } else {
                        "safe-regime".to_string()
                    },
                    prompt_stamp: if stamp == "prompt" {
                        format!("password={value}")
                    } else {
                        "safe-prompt".to_string()
                    },
                    model_stamp: if stamp == "model" {
                        format!("password={value}")
                    } else {
                        "safe-model".to_string()
                    },
                    generated_unix: 1,
                    probes: Vec::new(),
                    observation_replays: Vec::new(),
                }),
            }];
            let error = normalize_generated_access_verb(verb).unwrap_err();
            assert!(!error.to_string().contains(&value));
        }
    }

    #[test]
    fn generated_access_normalization_preserves_argv_elements_exactly() {
        let mut verb = synth_verb("ansible", None, false, "access-generated-fixture");
        verb.baseline = false;
        verb.consequence = Reversibility::Irreversible;
        verb.args = vec![
            "host".to_string(),
            "-m".to_string(),
            "shell".to_string(),
            "-a".to_string(),
            "echo one \"two\" \\ three, UTF-8 π".to_string(),
        ];
        let normalized =
            canonical_generated_access_verb(normalize_generated_access_verb(verb).unwrap());
        let mut catalog = VerbCatalog::empty();
        catalog.upsert_access_verb(normalized).unwrap();
        let original = vec![
            "host".to_string(),
            "-m".to_string(),
            "shell".to_string(),
            "-a".to_string(),
            "echo one \"two\" \\ three, UTF-8 π".to_string(),
        ];
        assert_eq!(catalog.match_command_all("ansible", &original).len(), 1);
        assert!(catalog
            .match_command_all(
                "ansible",
                &original
                    .iter()
                    .flat_map(|arg| arg.split_whitespace().map(str::to_string))
                    .collect::<Vec<_>>(),
            )
            .is_empty());
    }

    #[test]
    fn gate_rejection_guidance_names_the_prose_change_per_failure_class() {
        let overbroad =
            validate_synthesized_safety(&synth_verb("uptime", Some("^.+$"), false, "x"))
                .unwrap_err()
                .to_string();
        assert_eq!(
            gate_rejection_guidance(&overbroad),
            Some("name the exact allowed values in your prompt so the parameter can be enumerated")
        );

        let mut chained = synth_verb("uptime", None, false, "x");
        chained.args = args_vec(&["-p", "&&", "reboot"]);
        let chained = validate_synthesized_safety(&chained)
            .unwrap_err()
            .to_string();
        assert_eq!(
            gate_rejection_guidance(&chained),
            Some("ask for a single command; chaining needs separate verbs")
        );

        let shell = validate_synthesized_safety(&synth_verb("bash", None, false, "x"))
            .unwrap_err()
            .to_string();
        assert_eq!(
            gate_rejection_guidance(&shell),
            Some("ask for an operation implemented by a profiled direct executable")
        );

        let mut interactive = synth_verb("kubectl", None, false, "x");
        interactive.args = args_vec(&["exec", "-it", "deploy/web"]);
        let interactive = validate_synthesized_safety(&interactive)
            .unwrap_err()
            .to_string();
        assert_eq!(
            gate_rejection_guidance(&interactive),
            Some("ask for non-interactive output, not a shell")
        );

        let unused = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: show-unit-status
    binary: systemctl
    args: ["status"]
    params:
      op: { pattern: "^(start|stop)$" }
    consequence: reversible
"#,
        )
        .unwrap_err()
        .to_string();
        assert_eq!(
            gate_rejection_guidance(&unused),
            Some("either mention where the value is used or drop it from the prompt")
        );

        assert_eq!(gate_rejection_guidance("the daemon has no LLM key"), None);
    }
}
#[cfg(test)]
mod asynchronous_adoption_tests {
    use super::*;
    use crate::learned_rules::{
        acquire_async_authority_use_lease, run_async_durable_store_operation,
    };
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::RwLock;

    #[test]
    fn delayed_refresh_cannot_restore_a_durably_deleted_verb() {
        let directory = crate::learned_rules::authority_tempdir();
        let path = directory.path().join("verbs.yaml");
        crate::learned_rules::write_authority_file(
            &path,
            r#"verbs:
  - name: inspect-object
    binary: fixturectl
    args: ["status"]
    consequence: reversible
"#,
        )
        .unwrap();
        let baseline = VerbCatalog::load(&path).unwrap();
        let delayed_refresh = baseline.clone();
        let mut current = baseline.clone();
        current.delete_verb("inspect-object").unwrap();

        assert!(current
            .adopt_async_result(&baseline, delayed_refresh)
            .is_err());
        assert!(current.get("inspect-object").is_none());
    }

    fn file_backed_catalog() -> (tempfile::TempDir, PathBuf, VerbCatalog) {
        let directory = crate::learned_rules::authority_tempdir();
        let path = directory.path().join("verbs.yaml");
        crate::learned_rules::write_authority_file(
            &path,
            r#"verbs:
  - name: inspect-object
    description: Inspect an object
    binary: fixturectl
    args: ["status"]
    consequence: reversible
"#,
        )
        .unwrap();
        let catalog = VerbCatalog::load(&path).unwrap();
        (directory, path, catalog)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn execution_lease_linearizes_against_external_verb_deletion() {
        let (_directory, path, catalog) = file_backed_catalog();
        let store = Arc::new(RwLock::new(catalog));
        let lease = acquire_async_authority_use_lease(&store, "verb execution test")
            .await
            .unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            let mut independent = VerbCatalog::load(&path).unwrap();
            independent.delete_verb("inspect-object").unwrap();
            send.send(()).unwrap();
        });

        assert!(receive.recv_timeout(Duration::from_millis(100)).is_err());
        assert!(lease.render("inspect-object", &BTreeMap::new()).is_ok());
        drop(lease);
        // Generous: this wait proves completion, not latency; slow Windows
        // runners exceed small bounds on the reload-and-delete round trip.
        receive.recv_timeout(Duration::from_secs(30)).unwrap();
        writer.join().unwrap();

        assert!(
            acquire_async_authority_use_lease(&store, "stale verb execution")
                .await
                .is_err()
        );
        run_async_durable_store_operation(&store, "verb refresh test", |candidate| {
            *candidate = candidate.refreshed_copy()?;
            Ok(())
        })
        .await
        .unwrap();
        assert!(store.read().await.get("inspect-object").is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn execution_lease_linearizes_against_external_verb_amendment() {
        let (_directory, path, catalog) = file_backed_catalog();
        let original_digest = catalog.verb_definition_digest("inspect-object").unwrap();
        let store = Arc::new(RwLock::new(catalog));
        let lease = acquire_async_authority_use_lease(&store, "verb execution test")
            .await
            .unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            let mut independent = VerbCatalog::load(&path).unwrap();
            let mut replacement = independent.get("inspect-object").unwrap().clone();
            replacement.description = "Inspect one object safely".to_string();
            independent
                .amend_verb_if_digest("inspect-object", &original_digest, &replacement)
                .unwrap();
            send.send(()).unwrap();
        });

        assert!(receive.recv_timeout(Duration::from_millis(100)).is_err());
        assert_eq!(
            lease
                .get("inspect-object")
                .map(|verb| verb.description.as_str()),
            Some("Inspect an object")
        );
        drop(lease);
        // This proves completion after lease release, not latency. Keep the
        // deadlock bound generous for filesystem work on loaded runners.
        receive.recv_timeout(Duration::from_secs(30)).unwrap();
        writer.join().unwrap();

        assert!(
            acquire_async_authority_use_lease(&store, "stale verb execution")
                .await
                .is_err()
        );
    }
}
