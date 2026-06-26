//! Verb catalog: the operator-authored, typed, least-expressive interface that
//! agents call instead of raw shell.
//!
//! A verb names a fixed binary and an argv template with typed, pattern-validated
//! parameters. Rendering substitutes each `{param}` as exactly one argv element
//! (no shell, no word-splitting), so parameter injection is structurally
//! impossible. A verb declares its own reversibility class (which drives the
//! consequence gate) and, for recoverable verbs, a structured rollback template.
//!
//! The catalog is the "slow clock": it is a file only the operator (daemon UID)
//! controls; agents cannot add or change verbs at runtime. A trusted verb may
//! skip the LLM evaluator entirely (a deterministic allow path, like a static
//! policy allow), since its shape is already operator-reviewed.

use super::Reversibility;
use anyhow::{bail, Context, Result};
use regex::Regex;
use serde::Deserialize;
use std::collections::hash_map::DefaultHasher;
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// A single parameter's validation rule.
#[derive(Debug, Clone, Deserialize)]
pub struct ParamSpec {
    /// Fully-anchored regex (`^...$`) the value must match. Rejected at load if
    /// not anchored, so a permissive pattern cannot silently allow a substring
    /// with shell metacharacters or flag-injection.
    pub pattern: String,
    #[serde(default = "default_true")]
    pub required: bool,
    #[serde(default)]
    pub default: Option<String>,
    /// Allow a rendered value to begin with `-`. Off by default so a value can
    /// never be smuggled in as an option flag (e.g. `-o ProxyCommand=...`).
    #[serde(default)]
    pub allow_dash: bool,
}

fn default_true() -> bool {
    true
}

/// A structured command template (binary + argv templates). No shell.
#[derive(Debug, Clone, Deserialize)]
pub struct VerbCommand {
    pub binary: String,
    #[serde(default)]
    pub args: Vec<String>,
}

/// One catalog verb.
#[derive(Debug, Clone, Deserialize)]
pub struct Verb {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub binary: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub params: BTreeMap<String, ParamSpec>,
    pub consequence: Reversibility,
    #[serde(default)]
    pub revert: Option<VerbCommand>,
    /// When true the rendered command skips the LLM evaluator (deterministic
    /// allow). The reversibility class still drives the gate.
    #[serde(default)]
    pub trusted: bool,
    /// Extra context appended to the LLM system prompt when this verb IS
    /// evaluated (untrusted verbs only).
    #[serde(default)]
    pub prompt_context: Option<String>,
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
            serde_yaml::from_str(text).context("failed to parse verb catalog")?;
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
        })
    }
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
/// `^(?:...)$`, so a top-level alternation (e.g. `^[a-z]+$|x`) cannot smuggle an
/// unanchored branch that `is_match` would satisfy on a substring.
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
        // A value beginning with '-' must be refused (argv/flag injection).
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
}
