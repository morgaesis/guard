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
//! The catalog is the "slow clock": it is a file only an operator-owned
//! deployment path controls; agents cannot add or change verbs at runtime. A trusted verb may
//! skip the LLM evaluator entirely (a deterministic allow path, like a static
//! policy allow), since its shape is already operator-reviewed.

use super::coverage::reversibility_rank;
use super::Reversibility;
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
use std::collections::{BTreeMap, BTreeSet};
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
    /// When true the rendered command skips the LLM evaluator (deterministic
    /// allow). The reversibility class still drives the gate.
    #[serde(default, skip_serializing_if = "is_false")]
    pub trusted: bool,
    /// Extra context appended to the LLM system prompt when this verb IS
    /// evaluated (untrusted verbs only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_context: Option<String>,
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

#[derive(Debug, Serialize, Deserialize)]
struct CatalogFile {
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
    pub trusted: bool,
    pub prompt_context: Option<String>,
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

/// An operator-authored catalog of verbs plus a content version used to void
/// approvals when the catalog changes.
#[derive(Debug, Clone, Default)]
pub struct VerbCatalog {
    verbs: BTreeMap<String, Verb>,
    version: u64,
    path: Option<PathBuf>,
    mtime: Option<SystemTime>,
    snapshot: Option<LearningFileSnapshot>,
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
        let mut verbs = BTreeMap::new();
        let mut repaired = false;
        for mut verb in file.verbs {
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
            if is_synthesized_verb(&verb) {
                let original = serde_json::to_value(&verb)?;
                verb = canonicalize_generated_authority_envelope(verb)?;
                repaired |= original != serde_json::to_value(&verb)?;
            }
            normalize_operator_boundaries(&mut verb);
            validate_verb(&verb)?;
            if verb.auto_promoted {
                validate_auto_promoted_verb_durable_safety(&verb)?;
            }
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
        let runtime_verbs = self
            .verbs
            .values()
            .filter(|verb| {
                verb.name.starts_with("grant-") || verb.name.starts_with("access-generated-")
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut reloaded = Self::load(&path)?;
        for mut verb in runtime_verbs {
            if verb.name.starts_with("grant-") {
                reloaded.upsert_saved_grant_verb(verb)?;
            } else {
                // Approved generated coverage is trusted only in memory. Demote
                // it back to its validated proposal form before reinstalling it.
                verb.trusted = false;
                reloaded.upsert_access_verb(verb)?;
            }
        }
        *self = reloaded;
        Ok(true)
    }

    #[doc(hidden)]
    pub fn refreshed_copy(&self) -> Result<Self> {
        let Some(path) = self.path.clone() else {
            return Ok(self.clone());
        };
        let runtime_verbs = self
            .verbs
            .values()
            .filter(|verb| reserved_verb_name(&verb.name))
            .cloned()
            .collect::<Vec<_>>();
        let mut reloaded = Self::load(&path)?;
        for mut verb in runtime_verbs {
            if verb.name.starts_with("grant-") {
                reloaded.upsert_saved_grant_verb(verb)?;
            } else {
                verb.trusted = false;
                reloaded.upsert_access_verb(verb)?;
            }
        }
        Ok(reloaded)
    }

    #[doc(hidden)]
    pub fn adopt_refreshed_file_authority(&mut self, mut refreshed: Self) -> Result<()> {
        refreshed.verbs.retain(|name, _| !reserved_verb_name(name));
        for mut verb in self
            .verbs
            .values()
            .filter(|verb| reserved_verb_name(&verb.name))
            .cloned()
        {
            if verb.name.starts_with("grant-") {
                refreshed.upsert_saved_grant_verb(verb)?;
            } else {
                verb.trusted = false;
                refreshed.upsert_access_verb(verb)?;
            }
        }
        *self = refreshed;
        Ok(())
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
            trusted: verb.trusted,
            prompt_context: verb.prompt_context.clone(),
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

            if verb.coverage.is_empty() {
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
                });
                continue;
            }

            for cell in &verb.coverage {
                if let Some((features, specificity)) = coverage_cell_matches(cell, args, cwd) {
                    matches.push(CoverageMatch {
                        rendered: rendered.clone(),
                        cell: cell.name.clone(),
                        action: cell.action,
                        override_marker: cell.override_marker.clone(),
                        sticky: cell.sticky,
                        features,
                        specificity,
                        environment_authorized: environment_is_authorized(
                            cell,
                            plain,
                            secrets,
                            secret_files,
                        ),
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
    /// file, then reload so the in-memory catalog (and its content version)
    /// reflect the write. Requires the catalog to be file-backed. Nothing is
    /// written if validation fails.
    pub fn append_verb(&mut self, verb: &Verb) -> Result<()> {
        let canonical;
        let verb = if is_synthesized_verb(verb) {
            canonical = canonicalize_generated_authority_envelope(verb.clone())?;
            &canonical
        } else {
            verb
        };
        self.validate_candidate(verb)?;
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
        let new_content = compose_appended_catalog(&existing, verb)?;
        // Validate the COMBINED catalog in memory BEFORE touching the file, so a
        // bad or duplicate verb can never corrupt the catalog on disk.
        let (validated, canonical) = Self::from_yaml_with_repair(&new_content)
            .context("appending this verb would make the catalog invalid")?;
        let durable_content = canonical.as_deref().unwrap_or(&new_content);
        let outcome =
            write_learning_file_atomically_for_locked_snapshot(&path, &snapshot, durable_content)?;
        let (committed, warning) = outcome.into_parts();
        // Adopt the already-validated content rather than re-reading the file: a
        // post-write reload failure would otherwise report an error to the
        // operator even though the write landed, desyncing memory from disk.
        self.verbs = validated.verbs;
        self.version = validated.version;
        self.mtime = committed.modified();
        self.snapshot = Some(committed);
        if let Some(error) = warning {
            tracing::warn!("catalog append committed with a durability warning: {error}");
        }
        Ok(())
    }

    /// Replace one operator-authored file verb only when its live definition
    /// still matches `expected_digest`. Validation and whole-catalog
    /// composition complete before the backing file is atomically replaced.
    /// The in-memory catalog adopts exactly that validated document after the
    /// durable replacement succeeds.
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
        let (mut validated, canonical) = Self::from_yaml_with_repair(&new_content)
            .context("amending this verb would make the catalog invalid")?;
        let durable_content = canonical.as_deref().unwrap_or(&new_content);

        let runtime_verbs = self
            .verbs
            .values()
            .filter(|verb| reserved_verb_name(&verb.name))
            .cloned()
            .collect::<Vec<_>>();
        for mut verb in runtime_verbs {
            if verb.name.starts_with("grant-") {
                validated.upsert_saved_grant_verb(verb)?;
            } else {
                verb.trusted = false;
                validated.upsert_access_verb(verb)?;
            }
        }
        // Every fallible catalog adoption step completes before the durable
        // rewrite. After this point, success requires only the atomic file
        // replacement and assigning the already validated state.
        let outcome = atomic_replace_if_unchanged(&path, &snapshot, durable_content.as_bytes())?;
        let (committed, warning) = outcome.into_parts();
        validated.path = Some(path.clone());
        validated.mtime = committed.modified();
        validated.snapshot = Some(committed);
        *self = validated;
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
        if name.starts_with("grant-") {
            bail!(
                "saved-grant coverage cannot be deleted directly; use `guard access revoke <session-or-agent>`"
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
        let (validated, canonical) = Self::from_yaml_with_repair(&new_content)
            .context("deleting this verb would make the catalog invalid")?;
        let durable_content = canonical.as_deref().unwrap_or(&new_content);
        let outcome =
            write_learning_file_atomically_for_locked_snapshot(&path, &snapshot, durable_content)?;
        let (committed, warning) = outcome.into_parts();
        self.verbs = validated.verbs;
        self.version = validated.version;
        self.mtime = committed.modified();
        self.snapshot = Some(committed);
        if let Some(error) = warning {
            tracing::warn!("catalog deletion committed with a durability warning: {error}");
        }
        Ok(verb)
    }

    fn refresh_version(&mut self) -> Result<()> {
        let yaml = serde_yaml_ng::to_string(&CatalogFile {
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

/// Binaries a synthesized verb may not use: shells and interpreters where a
/// single argument can carry an arbitrary command, which would defeat the
/// catalog's "no shell" guarantee. An operator who genuinely needs one authors
/// the verb by hand (this gate applies only to LLM-synthesized verbs).
const SYNTH_BINARY_DENYLIST: &[&str] = &[
    "sh",
    "bash",
    "dash",
    "zsh",
    "ash",
    "ksh",
    "csh",
    "tcsh",
    "fish",
    "busybox",
    "cmd",
    "command",
    "powershell",
    "pwsh",
    "wscript",
    "cscript",
    "mshta",
    "env",
    "xargs",
    "find",
    "awk",
    "gawk",
    "sed",
    "perl",
    "python",
    "python2",
    "python3",
    "ruby",
    "node",
    "nodejs",
    "php",
    "lua",
    "tclsh",
    "expect",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "telnet",
    "ssh",
    "scp",
    "sftp",
];

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

/// The binary's match key: basename, lowercased, with a `.exe` suffix stripped.
fn binary_match_key(binary: &str) -> String {
    let base = binary.rsplit(['/', '\\']).next().unwrap_or(binary);
    let base = base
        .strip_suffix(".exe")
        .or_else(|| base.strip_suffix(".EXE"))
        .unwrap_or(base);
    base.to_ascii_lowercase()
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
    binary_match_key(observed) == binary_match_key(verb_binary)
}

fn legacy_template_features(args: &[String]) -> BTreeSet<String> {
    args.iter()
        .enumerate()
        .map(|(index, arg)| format!("template:{index}:{arg}"))
        .collect()
}

fn coverage_cell_matches(
    cell: &VerbCoverageCell,
    args: &[String],
    cwd: Option<&Path>,
) -> Option<(BTreeSet<String>, CoverageSpecificity)> {
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

fn environment_is_authorized(
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
            })
        })
    })
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
        for (index, arg) in args.iter().enumerate() {
            for option in &constraint.options {
                if arg == option {
                    found.push(args.get(index + 1)?.clone());
                } else if let Some(value) = arg.strip_prefix(&format!("{option}=")) {
                    found.push(value.to_string());
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

    let binary = binary_match_key(&verb.binary);
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
        "kubectl" => matches!(
            operation.as_str(),
            "api-resources"
                | "api-versions"
                | "cluster-info"
                | "describe"
                | "explain"
                | "get"
                | "logs"
                | "version"
        ),
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

/// Reject a shell/interpreter binary (see `SYNTH_BINARY_DENYLIST`): one
/// argument to these could carry an arbitrary command, defeating the
/// catalog's "no shell" guarantee. Shared by both synthesis paths below.
fn validate_binary_not_shell(binary: &str, context: &str) -> Result<()> {
    let key = binary_match_key(binary);
    if SYNTH_BINARY_DENYLIST.contains(&key.as_str()) {
        bail!(
            "{context} binary '{}' is a shell/interpreter and is not allowed (one argument could \
             carry an arbitrary command); author such a verb by hand if you truly need it",
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

fn path_is_absolute(value: &str) -> bool {
    value.starts_with('/')
        || value.starts_with("\\\\")
        || value
            .as_bytes()
            .get(1..3)
            .is_some_and(|bytes| bytes[0] == b':' && matches!(bytes[1], b'/' | b'\\'))
}

fn validate_absolute_file_template(
    verb: &Verb,
    template: &str,
    command_label: &str,
    position: &str,
) -> Result<()> {
    if path_is_absolute(template) {
        return Ok(());
    }
    let names = placeholders(template);
    if names.len() == 1 && template == format!("{{{}}}", names[0]) {
        let spec = verb.params.get(&names[0]).ok_or_else(|| {
            anyhow::anyhow!(
                "verb '{}' {command_label} file argument {position} references undeclared parameter '{}'",
                verb.name,
                names[0]
            )
        })?;
        let pattern = compile_anchored(spec.pattern_text()).with_context(|| {
            format!(
                "verb '{}' {command_label} file parameter '{}' has an invalid pattern",
                verb.name, names[0]
            )
        })?;
        let relative_canaries = [
            "inventory",
            "inventory/production",
            "manifest.yaml",
            "./manifest.yaml",
            "../manifest.yaml",
        ];
        let absolute_canaries = [
            "/srv/guard/manifest.yaml",
            "/srv/guard/manifests/manifest.yaml",
            r"C:\guard\manifest.yaml",
            r"\\server\share\manifest.yaml",
        ];
        if !relative_canaries
            .iter()
            .any(|value| pattern.is_match(value))
            && absolute_canaries
                .iter()
                .any(|value| pattern.is_match(value))
        {
            return Ok(());
        }
    }
    bail!(
        "verb '{}' {command_label} file argument {position} must be an absolute path, got {:?}",
        verb.name,
        template
    )
}

fn validate_known_file_arguments(
    verb: &Verb,
    binary: &str,
    args: &[String],
    command_label: &str,
) -> Result<()> {
    let binary = binary_match_key(binary);
    let file_options: &[&str] = match binary.as_str() {
        "ansible" | "ansible-playbook" => &[
            "-i",
            "--inventory",
            "--private-key",
            "--vault-password-file",
        ],
        "kubectl" => &["-f", "--filename", "--kubeconfig"],
        "helm" => &[
            "-f",
            "--values",
            "--kubeconfig",
            "--repository-config",
            "--registry-config",
        ],
        _ => &[],
    };
    for (index, argument) in args.iter().enumerate() {
        if file_options.contains(&argument.as_str()) {
            let value = args.get(index + 1).ok_or_else(|| {
                anyhow::anyhow!(
                    "verb '{}' {command_label} option '{}' requires an absolute file argument",
                    verb.name,
                    argument
                )
            })?;
            validate_absolute_file_template(
                verb,
                value,
                command_label,
                &format!("after {argument}"),
            )?;
        }
        for option in file_options {
            if let Some(value) = argument.strip_prefix(&format!("{option}=")) {
                validate_absolute_file_template(
                    verb,
                    value,
                    command_label,
                    &format!("in {option}=..."),
                )?;
            }
        }
    }

    if binary == "ansible-playbook" {
        const VALUE_OPTIONS: &[&str] = &[
            "-i",
            "--inventory",
            "-l",
            "--limit",
            "-e",
            "--extra-vars",
            "-t",
            "--tags",
            "--skip-tags",
            "--start-at-task",
            "--vault-id",
            "--vault-password-file",
            "--private-key",
            "-u",
            "--user",
            "-f",
            "--forks",
            "-M",
            "--module-path",
            "-c",
            "--connection",
            "-T",
            "--timeout",
            "--ssh-common-args",
            "--ssh-extra-args",
            "--sftp-extra-args",
            "--scp-extra-args",
            "--become-method",
            "--become-user",
        ];
        let mut skip_value = false;
        for argument in args {
            if skip_value {
                skip_value = false;
                continue;
            }
            if argument.starts_with('-') {
                skip_value = VALUE_OPTIONS.contains(&argument.as_str());
                continue;
            }
            validate_absolute_file_template(verb, argument, command_label, "playbook")?;
            break;
        }
    }
    Ok(())
}

fn validate_inventory_constraint_paths(
    verb: &Verb,
    cell: &VerbCoverageCell,
    constraint: &ValueConstraint,
) -> Result<()> {
    if !matches!(
        binary_match_key(&verb.binary).as_str(),
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
    if binary_match_key(binary) == "kubectl" {
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
    let binary_name = std::path::Path::new(&verb.binary)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(&verb.binary)
        .trim_end_matches(".exe")
        .to_ascii_lowercase();
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
            "is a shell/interpreter",
            "ask for non-interactive output, not a shell",
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
        validate_param_not_overbroad(pname, spec, "auto-promoted verb")?;
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
        if spec.value_type() != ParamValueType::Token {
            bail!(
                "auto-promoted verb '{}' durable parameter '{}' must use token semantics",
                verb.name,
                pname
            );
        }
        if !spec.required || spec.default.is_some() {
            bail!(
                "auto-promoted verb '{}' durable parameter '{}' must be required and have no default",
                verb.name,
                pname
            );
        }
        let literals = enumerate_pattern_literals(spec.pattern_text()).ok_or_else(|| {
            anyhow::anyhow!(
                "auto-promoted verb '{}' durable parameter '{}' must be a finite plain literal alternation",
                verb.name,
                pname
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
    validate_known_file_arguments(verb, &verb.binary, &verb.args, "forward command")?;
    if let Some(revert) = &verb.revert {
        validate_known_file_arguments(verb, &revert.binary, &revert.args, "revert command")?;
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
                if !name.is_empty() {
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
            let value = params.get(name).ok_or_else(|| {
                anyhow::anyhow!("verb '{}' missing value for '{{{}}}'", verb, name)
            })?;
            out.push_str(value);
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

    const YAML: &str = r#"
verbs:
  - name: restart-service
    description: Restart a systemd unit
    binary: systemctl
    args: ["restart", "{unit}"]
    params:
      unit: { pattern: "^[a-zA-Z0-9@._-]+$", required: true }
    consequence: recoverable
    revert: { binary: systemctl, args: ["stop", "{unit}"] }
    trusted: true
  - name: tail-log
    binary: tail
    args: ["-n", "{lines}", "{path}"]
    params:
      lines: { pattern: "^[0-9]{1,5}$" }
      path: { pattern: "^/var/log/[a-zA-Z0-9._/-]+$" }
    consequence: reversible
"#;

    fn params(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn catalog_status_hash_is_short_and_content_sensitive() {
        let first = VerbCatalog::from_yaml(YAML).unwrap();
        let changed = VerbCatalog::from_yaml(&YAML.replace("tail-log", "show-log")).unwrap();

        assert_eq!(first.short_hash().len(), 12);
        assert_ne!(first.short_hash(), changed.short_hash());
        assert_eq!(first.changed_unix(), None);
    }

    #[test]
    fn loads_and_renders_a_verb() {
        let cat = VerbCatalog::from_yaml(YAML).unwrap();
        assert_eq!(cat.names(), vec!["restart-service", "tail-log"]);
        let r = cat
            .render("restart-service", &params(&[("unit", "nginx")]))
            .unwrap();
        assert_eq!(r.binary, "systemctl");
        assert_eq!(r.args, vec!["restart", "nginx"]);
        assert_eq!(r.consequence, Reversibility::Recoverable);
        assert_eq!(
            r.revert,
            Some((
                "systemctl".to_string(),
                vec!["stop".to_string(), "nginx".to_string()]
            ))
        );
        assert!(r.trusted);
    }

    #[test]
    fn shell_metacharacters_are_inert_single_argv() {
        // A param that somehow matched would still render as ONE argv element.
        // Here the pattern rejects it outright.
        let cat = VerbCatalog::from_yaml(YAML).unwrap();
        let err = cat
            .render("restart-service", &params(&[("unit", "nginx; rm -rf /")]))
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
    fn unknown_param_rejected_at_render() {
        let cat = VerbCatalog::from_yaml(YAML).unwrap();
        let err = cat
            .render("tail-log", &params(&[("lines", "10"), ("bogus", "x")]))
            .unwrap_err();
        assert!(err.to_string().contains("no parameter"));
    }

    #[test]
    fn missing_required_param_rejected() {
        let cat = VerbCatalog::from_yaml(YAML).unwrap();
        let err = cat.render("restart-service", &params(&[])).unwrap_err();
        assert!(err.to_string().contains("requires parameter"));
    }

    #[test]
    fn version_changes_with_content() {
        let a = VerbCatalog::from_yaml(YAML).unwrap();
        let b = VerbCatalog::from_yaml(&format!("{}\n# edit", YAML)).unwrap();
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
            name: "cmk-list".to_string(),
            description: "Read-only CloudStack listing".to_string(),
            binary: "cmk".to_string(),
            args: vec!["list".to_string(), "{resource}".to_string()],
            baseline: true,
            coverage: Vec::new(),
            credential_plan: None,
            params: p,
            consequence: Reversibility::Reversible,
            revert: None,
            trusted: true,
            prompt_context: None,
            source_prose: Some("read-only cmk listing of zones, networks, vms".to_string()),
            evidence: Some("read-only; resource pinned to an allow-list; reversible".to_string()),
            auto_promoted: false,
            promotion_stamp: None,
        };
        cat.append_verb(&verb).unwrap();

        // Reload independently: persisted, provenance kept, pinning enforced.
        let reloaded = VerbCatalog::load(&path).unwrap();
        assert!(reloaded.names().contains(&"cmk-list".to_string()));
        assert!(reloaded.names().contains(&"existing".to_string()));
        let got = reloaded.get("cmk-list").unwrap();
        assert_eq!(
            got.source_prose.as_deref(),
            Some("read-only cmk listing of zones, networks, vms")
        );
        assert!(got.evidence.is_some());
        let r = reloaded
            .render("cmk-list", &params(&[("resource", "zones")]))
            .unwrap();
        assert_eq!(r.binary, "cmk");
        assert_eq!(r.args, vec!["list", "zones"]);
        assert!(reloaded
            .render("cmk-list", &params(&[("resource", "volumes")]))
            .is_err());
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
                trusted: false,
                prompt_context: None,
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
            trusted: false,
            prompt_context: None,
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
            trusted,
            prompt_context: None,
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
        let yaml = serde_yaml_ng::to_string(&CatalogFile { verbs: vec![verb] }).unwrap();
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
    fn immutable_catalog_rejects_required_repair_without_writing() {
        let value = ["q", "7"].concat();
        let mut verb = synth_verb("fixturectl", Some("^(status)$"), false, "inspect-fixture");
        verb.source_prose = Some(format!("password={value}"));
        let yaml = serde_yaml_ng::to_string(&CatalogFile { verbs: vec![verb] }).unwrap();
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

        let yaml = serde_yaml_ng::to_string(&CatalogFile { verbs: vec![verb] }).unwrap();
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

        let yaml = serde_yaml_ng::to_string(&CatalogFile { verbs: vec![verb] }).unwrap();
        assert!(VerbCatalog::from_yaml(&yaml).is_err());

        let unknown_nested = "verbs:\n  - name: safe\n    binary: true\n    consequence: reversible\n    future_metadata: true\n";
        assert!(VerbCatalog::from_yaml(unknown_nested).is_err());
        assert!(
            serde_yaml_ng::from_str::<FanoutConstraint>("max: 2\nfuture_metadata: true\n").is_err()
        );
    }

    #[test]
    fn synthesis_safety_gate_blocks_dangerous_shapes() {
        // shell / interpreter binaries (incl. path and .exe forms)
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
        assert!(
            validate_synthesized_safety(&synth_verb("rm", None, false, "delete-fixture")).is_err()
        );
        // over-broad / whitespace-admitting patterns
        assert!(validate_synthesized_safety(&synth_verb("cmk", Some("^.+$"), false, "x")).is_err());
        assert!(
            validate_synthesized_safety(&synth_verb("cmk", Some("^[a-z ]+$"), false, "x")).is_err()
        );
        // trusted synthesized verb
        assert!(
            validate_synthesized_safety(&synth_verb("cmk", Some("^zones$"), true, "x")).is_err()
        );
        // non-kebab name
        assert!(validate_synthesized_safety(&synth_verb(
            "cmk",
            Some("^zones$"),
            false,
            "Bad Name"
        ))
        .is_err());
        // good narrow read-only verbs pass
        assert!(validate_synthesized_safety(&synth_verb(
            "cmk",
            Some("^(zones|networks)$"),
            false,
            "cmk-list"
        ))
        .is_ok());
        assert!(validate_synthesized_safety(&synth_verb(
            "cmk",
            Some("^[a-f0-9-]{36}$"),
            false,
            "cmk-show"
        ))
        .is_ok());
        assert!(validate_synthesized_safety(&synth_verb(
            "kubectl",
            Some("^[a-z0-9-]{1,63}$"),
            false,
            "k-get"
        ))
        .is_ok());

        let mut generated_marker = synth_verb("kubectl", None, false, "k-check");
        generated_marker.coverage.push(VerbCoverageCell {
            name: "review".to_string(),
            action: CoverageAction::Evaluate,
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
        assert!(relative_forward
            .to_string()
            .contains("must be an absolute path"));

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
        assert!(relative_parameter
            .to_string()
            .contains("must be an absolute path"));

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
      path: { pattern: "^/srv/guard/manifests/[a-z0-9-]+\\.yaml$" }
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
                    "rustc-version",
                    "rustc",
                    &["--version"],
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
                VerbCatalog::from_yaml(&yaml)
                    .unwrap_or_else(|e| panic!("{} failed to load: {e}", path.display()));
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
        let v = synth_verb("cmk", Some("^(zones|networks)$"), false, "cmk-list");
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
                reloaded.names().contains(&"cmk-list".to_string()),
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
        let cat = VerbCatalog::from_yaml(
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
          values: ["/srv/guard/inventory/prod"]
        namespace:
          options: ["--namespace"]
          values: ["prod"]
        fanout:
          options: ["--limit"]
          max: 2
"#,
        )
        .unwrap();

        let matching = args_vec(&[
            "web",
            "-m",
            "ping",
            "-i",
            "/srv/guard/inventory/prod",
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

        let too_many = args_vec(&[
            "web",
            "--module-name=ping",
            "--inventory=/srv/guard/inventory/prod",
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
            "/srv/guard/inventory/prod",
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
            "/srv/guard/inventory/prod",
            "--namespace",
            "prod",
            "--limit",
            "--check",
        ]);
        assert!(cat.match_command_all("ansible", &missing_value).is_empty());
    }

    #[test]
    fn unmatched_coverage_cell_does_not_deny_its_complement() {
        let cat = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: check-only
    binary: ansible-playbook
    consequence: reversible
    trusted: true
    coverage:
      - name: check
        action: preauthorized
        required_args: ["--check"]
"#,
        )
        .unwrap();

        let apply = args_vec(&["site.yml"]);
        assert!(cat.match_command_all("ansible-playbook", &apply).is_empty());
    }

    #[test]
    fn caller_environment_requires_explicit_typed_cell_authority() {
        let cat = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: ansible-check
    binary: ansible-playbook
    consequence: reversible
    trusted: true
    coverage:
      - name: check
        action: preauthorized
        required_args: ["--check"]
        environment:
          - name: ANSIBLE_CONFIG
            values: ["/srv/automation/ansible.cfg"]
          - name: VAULT_PASSWORD
            source: secret
            values: ["ansible/vault-password"]
"#,
        )
        .unwrap();
        let command = args_vec(&["--check", "site.yml"]);
        let mut plain = BTreeMap::new();
        plain.insert(
            "ANSIBLE_CONFIG".to_string(),
            "/srv/automation/ansible.cfg".to_string(),
        );
        let mut secrets = BTreeMap::new();
        secrets.insert(
            "VAULT_PASSWORD".to_string(),
            "ansible/vault-password".to_string(),
        );
        let matches = cat.match_command_all_with_environment(
            "ansible-playbook",
            &command,
            &plain,
            &secrets,
            &BTreeMap::new(),
        );
        assert!(matches[0].environment_authorized);

        plain.insert(
            "ANSIBLE_CONFIG".to_string(),
            "/tmp/caller-controlled.cfg".to_string(),
        );
        let matches = cat.match_command_all_with_environment(
            "ansible-playbook",
            &command,
            &plain,
            &secrets,
            &BTreeMap::new(),
        );
        assert!(!matches[0].environment_authorized);

        let mut unexpected = BTreeMap::new();
        unexpected.insert("EXTRA".to_string(), "value".to_string());
        let matches = cat.match_command_all_with_environment(
            "ansible-playbook",
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
    binary: ansible-playbook
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
        let error = VerbCatalog::from_yaml(
            r#"
verbs:
  - name: generated-check
    binary: ansible-playbook
    consequence: reversible
    trusted: true
    auto_promoted: true
    coverage:
      - name: check
        action: preauthorized
        required_args: ["--check"]
        environment:
          - name: ANSIBLE_CONFIG
            values: ["/srv/automation/ansible.cfg"]
"#,
        )
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
            .contains("expands to a command that is not independently read-only"));
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
  - name: enable-unit
    binary: systemctl
    args: ["enable", "{unit}"]
    params:
      unit: { pattern: "^[a-z-]+$" }
      scope: { pattern: "^(user|system)$", required: false, default: "system" }
    consequence: recoverable
    revert: { binary: systemctl, args: ["disable", "--{scope}", "{unit}"] }
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

        for (binary, pattern, argument) in [
            (
                "fixturectl",
                "^--[a-z]{8}=[a-z0-9]{2}$",
                format!("--password={value}"),
            ),
            ("mysql", "^-[a-z][a-z0-9]{2}$", format!("-p{value}")),
        ] {
            let (catalog, name) = install(
                binary,
                args_vec(&["{argument}"]),
                BTreeMap::from([("argument".to_string(), spec(pattern, true))]),
            );
            let params = BTreeMap::from([("argument".to_string(), argument.clone())]);
            assert!(catalog.render(&name, &params).is_err());
            assert!(catalog.match_command(binary, &[argument]).is_none());
        }
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
            Some("ask for non-interactive output, not a shell")
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
        receive.recv_timeout(Duration::from_secs(2)).unwrap();
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
        receive.recv_timeout(Duration::from_secs(2)).unwrap();
        writer.join().unwrap();

        assert!(
            acquire_async_authority_use_lease(&store, "stale verb execution")
                .await
                .is_err()
        );
    }
}
