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
//! The catalog is the "slow clock": it is a file only the operator (daemon UID)
//! controls; agents cannot add or change verbs at runtime. A trusted verb may
//! skip the LLM evaluator entirely (a deterministic allow path, like a static
//! policy allow), since its shape is already operator-reviewed.

use super::Reversibility;
use anyhow::{bail, Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// A single parameter's validation rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamSpec {
    /// Fully-anchored regex (`^...$`) the value must match. Rejected at load if
    /// not anchored, so a permissive pattern cannot silently allow a substring
    /// with shell metacharacters or a value that gets reinterpreted as a flag.
    pub pattern: String,
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// Allow a rendered value to begin with `-`. Off by default so a value can
    /// never pass itself off as an option flag (e.g. `-o ProxyCommand=...`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_dash: bool,
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

/// A structured command template (binary + argv templates). No shell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerbCommand {
    pub binary: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
}

/// One catalog verb.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verb {
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    pub binary: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
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

#[derive(Debug, Deserialize)]
struct CatalogFile {
    #[serde(default)]
    verbs: Vec<Verb>,
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
    /// Validated params, recorded into the approval snapshot for the binding.
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
}

impl VerbCatalog {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn version(&self) -> u64 {
        self.version
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

    pub fn list(&self) -> Vec<Verb> {
        self.verbs.values().cloned().collect()
    }

    /// Parse and validate a catalog from YAML text. Validation rejects:
    /// duplicate names, non-anchored param patterns, invalid regexes, and
    /// template placeholders that reference an undeclared param.
    pub fn from_yaml(text: &str) -> Result<Self> {
        let file: CatalogFile =
            serde_yaml_ng::from_str(text).context("failed to parse verb catalog")?;
        let mut verbs = BTreeMap::new();
        for verb in file.verbs {
            validate_verb(&verb)?;
            if verbs.insert(verb.name.clone(), verb.clone()).is_some() {
                bail!("duplicate verb name: '{}'", verb.name);
            }
        }
        let mut hasher = DefaultHasher::new();
        text.hash(&mut hasher);
        Ok(Self {
            verbs,
            version: hasher.finish(),
            path: None,
            mtime: None,
        })
    }

    /// Load a catalog from a file, recording its path and mtime for reloads.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read verb catalog {}", path.display()))?;
        let mut catalog = Self::from_yaml(&text)?;
        catalog.path = Some(path.to_path_buf());
        catalog.mtime = std::fs::metadata(path).ok().and_then(|m| m.modified().ok());
        Ok(catalog)
    }

    /// Reload the catalog if its file changed on disk. Returns `Ok(true)` if it
    /// was reloaded. A parse error keeps the previous catalog and is reported.
    pub fn reload_if_stale(&mut self) -> Result<bool> {
        let Some(path) = self.path.clone() else {
            return Ok(false);
        };
        let current = std::fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok());
        if current == self.mtime {
            return Ok(false);
        }
        let reloaded = Self::load(&path)?;
        *self = reloaded;
        Ok(true)
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
            let re = compile_anchored(&spec.pattern)
                .with_context(|| format!("invalid pattern for param '{}'", pname))?;
            if !re.is_match(&value) {
                bail!(
                    "value for '{}' does not match required pattern {}",
                    pname,
                    spec.pattern
                );
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

        Ok(RenderedVerb {
            name: name.to_string(),
            binary,
            args,
            consequence: verb.consequence,
            revert,
            trusted: verb.trusted,
            prompt_context: verb.prompt_context.clone(),
            params: resolved,
            auto_promoted: verb.auto_promoted,
            promotion_stamp: verb.promotion_stamp.clone(),
        })
    }

    /// The backing catalog file, if this catalog was loaded from one.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Reverse-match a raw `(binary, args)` command against the catalog: does
    /// any verb's template unify with these concrete args? This lets a caller
    /// that runs a tool directly (`kubectl get pods -n foo`) pick up a
    /// matching verb's declared consequence class and trust the same way an
    /// explicit `--verb` invocation would, without naming the verb -- the
    /// mechanism that makes a catalog (hand-authored or auto-promoted) useful
    /// for transparently gating a high-volume tool a caller invokes normally.
    ///
    /// Verbs are tried in name order (deterministic, since names are unique)
    /// and the first template that both unifies with `args` AND passes full
    /// parameter validation (`render`) wins; a shape that unifies but fails a
    /// param's pattern is skipped, not treated as a match.
    pub fn match_command(&self, binary: &str, args: &[String]) -> Option<RenderedVerb> {
        for verb in self.verbs.values() {
            if !binary_names_match(binary, &verb.binary) {
                continue;
            }
            let Some(captured) = match_args_template(&verb.args, args) else {
                continue;
            };
            if let Ok(rendered) = self.render(&verb.name, &captured) {
                return Some(rendered);
            }
        }
        None
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
        self.validate_candidate(verb)?;
        let path = self.path.clone().ok_or_else(|| {
            anyhow::anyhow!("verb catalog is not backed by a file; cannot persist a new verb")
        })?;
        let existing = std::fs::read_to_string(&path).unwrap_or_default();
        let new_content = compose_appended_catalog(&existing, verb)?;
        // Validate the COMBINED catalog in memory BEFORE touching the file, so a
        // bad or duplicate verb can never corrupt the catalog on disk.
        let validated = Self::from_yaml(&new_content)
            .context("appending this verb would make the catalog invalid")?;
        std::fs::write(&path, &new_content)
            .with_context(|| format!("failed to write verb catalog {}", path.display()))?;
        // Adopt the already-validated content rather than re-reading the file: a
        // post-write reload failure would otherwise report an error to the
        // operator even though the write landed, desyncing memory from disk.
        self.verbs = validated.verbs;
        self.version = validated.version;
        self.mtime = std::fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok());
        Ok(())
    }
}

/// Compose the new catalog text by adding one verb to the top-level `verbs:`
/// sequence. Parses the existing catalog into the YAML model (tolerating a
/// leading UTF-8 BOM), pushes the verb, and re-serializes the whole document.
/// Re-serializing — rather than text-appending at EOF — handles a missing,
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
    let re =
        compile_anchored(&spec.pattern).with_context(|| format!("param '{}' pattern", pname))?;
    if let Some(canary) = OVERBROAD_CANARIES.iter().find(|c| re.is_match(c)) {
        bail!(
            "{context} parameter '{}' pattern {:?} is too permissive (it matches {:?}); a verb \
             parameter must be narrowly pinned and must not admit whitespace or shell metacharacters",
            pname,
            spec.pattern,
            canary
        );
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
    validate_binary_not_shell(&verb.binary, "synthesized verb")?;
    for (pname, spec) in &verb.params {
        validate_param_not_overbroad(pname, spec, "synthesized verb")?;
    }
    Ok(())
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
/// - A `Recoverable` verb must carry a `revert`, and the revert's binary is
///   held to the same shell/interpreter denylist as the forward command --
///   the auto-revert envelope is what makes trusting a recoverable shape
///   defensible, so an unverified or shell-based revert defeats the point.
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
    if !is_kebab_name(&verb.name) {
        bail!(
            "auto-promoted verb name '{}' must be kebab-case (^[a-z0-9][a-z0-9-]*$)",
            verb.name
        );
    }
    validate_binary_not_shell(&verb.binary, "auto-promoted verb")?;
    for (pname, spec) in &verb.params {
        validate_param_not_overbroad(pname, spec, "auto-promoted verb")?;
    }
    match verb.consequence {
        Reversibility::Recoverable => {
            let Some(revert) = &verb.revert else {
                bail!("a recoverable verb may not be auto-promoted without a validated revert");
            };
            validate_binary_not_shell(&revert.binary, "auto-promoted verb revert")?;
        }
        Reversibility::Reversible => {}
        Reversibility::Irreversible => unreachable!("rejected above"),
    }
    // Re-render every evidence sample against the verb's own template and
    // confirm it reproduces exactly that sample -- never trust that the
    // caller-supplied template and params actually correspond to the
    // evidence they were derived from.
    for sample in evidence {
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
    for (pname, spec) in &verb.params {
        if !(spec.pattern.starts_with('^') && spec.pattern.ends_with('$')) {
            bail!(
                "verb '{}' param '{}': pattern must be fully anchored (^...$), got {:?}",
                verb.name,
                pname,
                spec.pattern
            );
        }
        // Compile the anchored form so an invalid regex — or one whose
        // alternation would escape the anchors — is rejected at load time.
        compile_anchored(&spec.pattern).with_context(|| {
            format!(
                "verb '{}' param '{}' has an invalid regex",
                verb.name, pname
            )
        })?;
    }
    // Every placeholder referenced by the templates must be a declared param.
    let mut tokens: Vec<&String> = vec![&verb.binary];
    tokens.extend(verb.args.iter());
    if let Some(rev) = &verb.revert {
        tokens.push(&rev.binary);
        tokens.extend(rev.args.iter());
    }
    for tok in tokens {
        for placeholder in placeholders(tok) {
            if !verb.params.contains_key(&placeholder) {
                bail!(
                    "verb '{}' template references undeclared param '{{{}}}'",
                    verb.name,
                    placeholder
                );
            }
        }
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
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verbs.yaml");
        std::fs::write(
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
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verbs.yaml");
        let initial = "verbs:\n  - name: dup\n    binary: echo\n    consequence: reversible\n";
        std::fs::write(&path, initial).unwrap();
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
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verbs.yaml");
        // Seed with a leading UTF-8 BOM, as a Windows editor or PowerShell's
        // utf8 mode would write it.
        let seed =
            "\u{feff}verbs:\n  - name: existing\n    binary: echo\n    consequence: reversible\n";
        std::fs::write(&path, seed).unwrap();
        let mut cat = VerbCatalog::load(&path).unwrap();

        let v = Verb {
            name: "added".to_string(),
            description: String::new(),
            binary: "echo".to_string(),
            args: vec![],
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
                VerbCatalog::load(&path)
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
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("verbs.yaml");
            std::fs::write(&path, seed).unwrap();
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

    fn args_vec(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }
}
