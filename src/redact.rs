use regex::Regex;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::{OnceLock, RwLock};

/// Hard resource limits for daemon-scoped exact literals. These bounds cap the
/// work of every prose scan and the carry retained by every stream redactor.
const MAX_TRUSTED_EXACT_SECRET_SCOPES: usize = 64;
const MAX_TRUSTED_EXACT_SECRET_ENTRIES: usize = 256;
const MAX_TRUSTED_EXACT_SECRET_BYTES: usize = 64 * 1024;
const MAX_TRUSTED_EXACT_SECRET_LITERAL_BYTES: usize = 4 * 1024;
const MAX_EXACT_REDACTION_INPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_EXACT_REDACTION_COMPARISONS: usize = 4 * 1024 * 1024 * 1024;

#[derive(Default)]
struct TrustedExactSecretRegistry {
    next_scope: u64,
    scopes: BTreeMap<u64, Vec<String>>,
    references: BTreeMap<String, usize>,
    total_bytes: usize,
}

fn trusted_exact_secrets() -> &'static RwLock<TrustedExactSecretRegistry> {
    static SECRETS: OnceLock<RwLock<TrustedExactSecretRegistry>> = OnceLock::new();
    SECRETS.get_or_init(|| RwLock::new(TrustedExactSecretRegistry::default()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedExactSecretLimitExceeded;

impl std::fmt::Display for TrustedExactSecretLimitExceeded {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("trusted exact-secret resource limit exceeded")
    }
}

impl std::error::Error for TrustedExactSecretLimitExceeded {}

/// Lifetime token for one bounded exact-secret set. Clones share ownership;
/// the plaintext leaves the process registry when the final owner is dropped.
#[derive(Clone, Default)]
pub struct TrustedExactSecretScope {
    _registration: Option<std::sync::Arc<TrustedExactSecretRegistration>>,
}

struct TrustedExactSecretRegistration {
    scope: u64,
}

impl Drop for TrustedExactSecretRegistration {
    fn drop(&mut self) {
        let mut registered = trusted_exact_secrets()
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(secrets) = registered.scopes.remove(&self.scope) {
            for secret in secrets {
                let remove = registered.references.get_mut(&secret).is_some_and(|count| {
                    *count -= 1;
                    *count == 0
                });
                if remove {
                    registered.references.remove(&secret);
                    registered.total_bytes = registered.total_bytes.saturating_sub(secret.len());
                }
            }
        }
    }
}

/// Register daemon-lifetime exact literals. Per-operation credentials stay in
/// the caller's explicit redaction context and are never registered here.
pub fn register_trusted_exact_secrets(
    secrets: &[String],
) -> Result<TrustedExactSecretScope, TrustedExactSecretLimitExceeded> {
    let mut scope_secrets = secrets
        .iter()
        .filter(|secret| !secret.is_empty())
        .cloned()
        .collect::<Vec<_>>();
    scope_secrets.sort();
    scope_secrets.dedup();
    if scope_secrets
        .iter()
        .any(|secret| secret.len() > MAX_TRUSTED_EXACT_SECRET_LITERAL_BYTES)
    {
        return Err(TrustedExactSecretLimitExceeded);
    }
    if scope_secrets.is_empty() {
        return Ok(TrustedExactSecretScope::default());
    }
    let mut registered = trusted_exact_secrets()
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let new_entries = scope_secrets
        .iter()
        .filter(|secret| !registered.references.contains_key(*secret))
        .count();
    let new_bytes = scope_secrets
        .iter()
        .filter(|secret| !registered.references.contains_key(*secret))
        .map(String::len)
        .sum::<usize>();
    if registered.scopes.len() >= MAX_TRUSTED_EXACT_SECRET_SCOPES
        || registered.references.len().saturating_add(new_entries)
            > MAX_TRUSTED_EXACT_SECRET_ENTRIES
        || registered.total_bytes.saturating_add(new_bytes) > MAX_TRUSTED_EXACT_SECRET_BYTES
    {
        return Err(TrustedExactSecretLimitExceeded);
    }
    let scope = registered.next_scope;
    let next_scope = registered
        .next_scope
        .checked_add(1)
        .ok_or(TrustedExactSecretLimitExceeded)?;
    registered.next_scope = next_scope;
    for secret in &scope_secrets {
        if !registered.references.contains_key(secret) {
            registered.total_bytes += secret.len();
        }
        *registered.references.entry(secret.clone()).or_default() += 1;
    }
    registered.scopes.insert(scope, scope_secrets);
    Ok(TrustedExactSecretScope {
        _registration: Some(std::sync::Arc::new(TrustedExactSecretRegistration {
            scope,
        })),
    })
}

fn with_registered_redaction_values<T>(operation: impl FnOnce(&[&str]) -> T) -> T {
    let mut references = trusted_exact_secrets()
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .references
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    references.sort_unstable_by_key(|secret| std::cmp::Reverse(secret.len()));
    let references = references.iter().map(String::as_str).collect::<Vec<_>>();
    operation(&references)
}

pub fn redact_registered_exact_secrets(text: &str) -> String {
    redact_exact_and_registered_secrets(text, &[])
}

pub fn redact_exact_and_registered_secrets(text: &str, secrets: &[&str]) -> String {
    with_registered_redaction_values(|registered| {
        let mut combined = secrets.to_vec();
        combined.extend_from_slice(registered);
        redact_exact_secrets(text, &combined)
    })
}

/// Render a command as one display line: the binary followed by its arguments,
/// space-separated. This is the single renderer for operator-facing and audit
/// surfaces (approval snapshots, session rules, audit records). It performs no
/// escaping or redaction. Callers with structured argv use
/// [`redact_command_line`] before flattening, and plain-text audit projections
/// use [`audit_escape`].
pub fn command_line(binary: &str, args: &[String]) -> String {
    if args.is_empty() {
        binary.to_string()
    } else {
        format!("{} {}", binary, args.join(" "))
    }
}

/// Escape a value for interpolation into a plain-text `[AUDIT]` line so one
/// logical audit record is always exactly one physical line. Without this, a
/// caller-controlled value containing a newline (argv, deny reason, path)
/// forges audit records: `\n[AUDIT] ALLOWED ...` in an argument becomes a
/// physical line that grep-based audit tooling cannot tell from a real one.
///
/// Semantics (Rust debug-style, injective): backslash doubles to `\\` so the
/// escaping stays unambiguous, `\n`/`\r`/`\t` use their mnemonic forms, and
/// every other control character (remaining C0, DEL, and C1) renders as
/// `\u{XX}`. All other characters, including non-ASCII text, pass through
/// unchanged. Returns the input unmodified (borrowed) when nothing needs
/// escaping. A structured audit sink can reuse this as its string-field
/// sanitizer.
pub fn audit_escape(value: &str) -> Cow<'_, str> {
    if !value.contains(|c: char| c == '\\' || c.is_control()) {
        return Cow::Borrowed(value);
    }
    let mut escaped = String::with_capacity(value.len() + 8);
    for c in value.chars() {
        match c {
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if c.is_control() => {
                use std::fmt::Write;
                let _ = write!(escaped, "\\u{{{:x}}}", c as u32);
            }
            c => escaped.push(c),
        }
    }
    Cow::Owned(escaped)
}

/// Value-shaped patterns that need no key-name context: recognizable token
/// formats and blobs. These run BEFORE the name-based pattern so that a
/// scheme-prefixed value (`Authorization: Bearer <token>`) is consumed as a
/// whole before the name-based pass sees the line.
fn redaction_patterns() -> &'static Vec<(Regex, &'static str)> {
    static PATTERNS: OnceLock<Vec<(Regex, &str)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            // PEM private key blocks
            (
                Regex::new(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----).*").unwrap(),
                "$1 [REDACTED]",
            ),
            // HTTP auth scheme tokens: `Bearer <token>` / `Basic <b64>`
            (
                Regex::new(r"(?i)\b(Bearer|Basic)[ \t]+[A-Za-z0-9._~+/=-]{16,}").unwrap(),
                "$1 [REDACTED]",
            ),
            // sk-* prefixed keys (OpenAI, Anthropic, Stripe, etc.)
            (Regex::new(r"sk-[A-Za-z0-9_-]{20,}").unwrap(), "[REDACTED]"),
            // AWS access key id
            (Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(), "[REDACTED]"),
            // URL userinfo passwords: `scheme://user:password@host`. The
            // password segment of a connection string (postgres://, redis://,
            // amqp://, https:// with basic auth) is a credential wherever it
            // appears; the username and host stay visible so the operator can
            // still tell which endpoint was addressed.
            (
                Regex::new(
                    r#"(?i)\b([a-z][a-z0-9+.-]{1,30}://[^/\s:@'"]{1,128}):([^@\s/'"]{1,256})@"#,
                )
                .unwrap(),
                "${1}:[REDACTED]@",
            ),
            // JWT tokens (eyJ header). The first-segment minimum of 8 admits
            // the shortest real headers (`{"alg":"none"}` encodes to 16
            // chars after `eyJ`) while the three-segment dot structure keeps
            // prose from matching.
            (
                Regex::new(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").unwrap(),
                "[REDACTED]",
            ),
            // Standalone long base64 blobs (lines of 40+ base64 chars, like encoded keys/certs)
            (
                Regex::new(r"(?m)^[A-Za-z0-9+/]{40,}={0,2}$").unwrap(),
                "[REDACTED]",
            ),
        ]
    })
}

/// Bare long URL-safe base64 runs (64+ chars), the shape of CloudStack
/// API/secret keys (86 chars) and similar opaque key material, wherever they
/// appear -- including positions with no `name=`/`name:` context at all
/// (table cells, bare `echo` output). The length threshold sits just above
/// the 63-char DNS-label ceiling so Kubernetes object names can never match.
fn bare_token_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"[A-Za-z0-9_-]{64,}").unwrap())
}

/// Redact bare long tokens, but only when the run looks like random key
/// material: it must mix upper case, lower case, and digits. This skips long
/// lowercase hex digests (sha256 sums), kebab-case slugs, and all-caps
/// identifiers, none of which are credentials. Random base64url of this
/// length fails the test with negligible probability (~2e-8 for 86 chars).
///
/// Deliberate limit: a bare single-case or hex-only credential (some
/// providers issue 64-hex tokens) is indistinguishable from a sha256 digest
/// without name context, and digests are pervasive in docker/git output --
/// so a bare one is not redacted here. The named, flow-style, and catch-all
/// passes still cover such a credential anywhere a key name or `NAME=` shape
/// accompanies it.
fn redact_bare_long_tokens(text: &str) -> String {
    if !bare_token_pattern().is_match(text) {
        return text.to_string();
    }
    bare_token_pattern()
        .replace_all(text, |caps: &regex::Captures| {
            let run = &caps[0];
            let has_lower = run.bytes().any(|b| b.is_ascii_lowercase());
            let has_upper = run.bytes().any(|b| b.is_ascii_uppercase());
            let has_digit = run.bytes().any(|b| b.is_ascii_digit());
            if has_lower && has_upper && has_digit {
                "[REDACTED]".to_string()
            } else {
                run.to_string()
            }
        })
        .to_string()
}

/// Secret-bearing key-name shape, shared by the name-based pass and the
/// flow-style name/value pass. KEY and PASS require a non-empty prefix: bare
/// `key:` and `pass:` fields are pervasive structural metadata (Kubernetes
/// selector/toleration `key:` entries, Docker JSON `"Key"` members, test
/// reports' `pass:`) and are never credentials by themselves. Bare `token:`,
/// `secret:`, `auth:`, and `cred(s):` DO match: an inline scalar under those
/// names is a credential often enough (docker `config.json` `"auth"`,
/// `token:` in kubeconfigs) that redaction wins the trade.
const SECRET_NAME_SUBPATTERN: &str = r"(?:[A-Za-z0-9_.-]*(?:TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|CREDENTIALS?|CREDS?|AUTHORIZATION|AUTH|BEARER)|[A-Za-z0-9_.-]+(?:KEY|PASS))";

fn secret_name_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(&format!(r"(?i)^(?:{SECRET_NAME_SUBPATTERN})$")).unwrap())
}

/// Value shape consumed after a secret-bearing name, in preference order: a
/// full double-quoted string (backslash escapes included), a full
/// single-quoted string (YAML `''` doubling included), an UNTERMINATED
/// quote consumed to end of line, or an unquoted run. Consuming quoted
/// values whole prevents a secret with spaces or escaped quotes from
/// leaking its tail (`password: "abc def"` must not become
/// `password: "[REDACTED] def"`), and the unterminated alternatives cover a
/// quoted multi-line value whose first line -- open quote, no close --
/// arrives alone through the per-line output path.
const SECRET_VALUE_SUBPATTERN: &str =
    r#"(?:"(?:\\.|[^"\\\n])*"|'(?:''|[^'\n])*'|"[^\n]*|'[^\n]*|[^"'\s}{,]+)"#;

/// Name-based secret redaction: a key name ending in a secret-bearing word,
/// followed by `=`/`:` (or their URL-encoded forms `%3D`/`%3A`, so query
/// strings in logged URLs cannot slip a value past the separator check),
/// has its value redacted regardless of the value's shape. Handles unquoted
/// env/CLI pairs (`MY_TOKEN=x`, `--api-key=x`), YAML (`password: x`), and
/// JSON with quoted names and values (`"apikey": "x",` -- the shape
/// CloudStack/cmk responses use).
fn named_secret_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(&format!(
            r#"(?i)(["']?)({name})(["']?\s*(?:[=:]|%3[dDaA])\s*)({value})"#,
            name = SECRET_NAME_SUBPATTERN,
            value = SECRET_VALUE_SUBPATTERN,
        ))
        .unwrap()
    })
}

/// Key names whose secret-word suffix is coincidental English, not a
/// credential: redacting their values would corrupt benign output. Checked
/// case-insensitively against the full captured name.
const NAMED_SECRET_STOPLIST: &[&str] = &[
    "monkey",
    "donkey",
    "turkey",
    "whiskey",
    "hockey",
    "jockey",
    "lackey",
    "hotkey",
    "turnkey",
    "low-key",
    "bypass",
    "compass",
    "overpass",
    "underpass",
    "sacred",
];

fn is_secret_bearing_name(name: &str) -> bool {
    secret_name_pattern().is_match(name)
        && !NAMED_SECRET_STOPLIST
            .iter()
            .any(|stop| name.eq_ignore_ascii_case(stop))
}

/// Replacement for a consumed value, preserving the value's quote style so
/// redacted JSON/YAML stays parseable (`"apikey": "[REDACTED]"`).
fn redacted_value_like(value: &str) -> &'static str {
    if value.starts_with('"') {
        "\"[REDACTED]\""
    } else if value.starts_with('\'') {
        "'[REDACTED]'"
    } else {
        "[REDACTED]"
    }
}

fn redact_named_secrets(text: &str) -> String {
    if !named_secret_pattern().is_match(text) {
        return text.to_string();
    }
    named_secret_pattern()
        .replace_all(text, |caps: &regex::Captures| {
            let name = &caps[2];
            if !is_secret_bearing_name(name) {
                caps[0].to_string()
            } else {
                format!(
                    "{}{}{}{}",
                    &caps[1],
                    &caps[2],
                    &caps[3],
                    redacted_value_like(&caps[4])
                )
            }
        })
        .to_string()
}

/// Flow-style / single-line JSON `name`/`value` pairs within one object:
/// `env: [{name: API_TOKEN, value: <generated>}]`,
/// `{"name": "DB_PASSWORD", "value": "<generated>"}`, the reversed member
/// order (`{value: <generated>, name: DB_PASSWORD}`), and pairs with intervening
/// members (`{name: DB_PASSWORD, optional: false, value: <generated>}`). The
/// stateful `name:`-then-`value:` pass only pairs across adjacent lines,
/// and the catch-all deliberately excludes the generic `value` key, so
/// without this a low-entropy secret in flow style leaks. The gap between
/// the two members may not cross `{`/`}` (stays inside one object) or a
/// newline. Only fires when the `name` member's value has a secret-bearing
/// shape.
/// Zero or more complete `key: value,` members between the correlated pair.
/// Structured (rather than a lazy any-character gap) so that a `value:`
/// embedded inside a sibling member's string literal
/// (`"description": "value: decoy"`) or a hyphenated sibling key
/// (`old-value:`) cannot take over the correlation and leave the real secret
/// member unredacted: the gap only advances over whole members, so the pair
/// keys can only match actual member keys. A gap member's value may be
/// empty (`optional: ,` -- YAML null shorthand); the value is optional in
/// the GAP grammar only, never in the correlated pair's value capture.
/// Nested object/array siblings are deliberately outside this grammar: they
/// break correlation, and such values are covered by the entropy-based
/// passes instead.
fn flow_member_gap() -> String {
    format!(
        r#"(?:\s*["']?[A-Za-z0-9_.-]+["']?\s*:\s*(?:{value}\s*)?,)*?"#,
        value = SECRET_VALUE_SUBPATTERN
    )
}

/// Anchor for the first key of a correlated pair: start of line or an
/// object/array/member boundary. Without it, `value` could anchor inside a
/// hyphenated key like `old-value` (`-` is a non-word char, so `\b` alone
/// does not prevent that).
const FLOW_KEY_ANCHOR: &str = r"(?:^|[{\[,])\s*";

fn flow_name_then_value_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(&format!(
            r#"(?im)({anchor}["']?name["']?\s*:\s*["']?)({name})(["']?\s*,{gap}\s*["']?value["']?\s*:\s*)({value})"#,
            anchor = FLOW_KEY_ANCHOR,
            name = SECRET_NAME_SUBPATTERN,
            gap = flow_member_gap(),
            value = SECRET_VALUE_SUBPATTERN,
        ))
        .unwrap()
    })
}

fn flow_value_then_name_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(&format!(
            r#"(?im)({anchor}["']?value["']?\s*:\s*)({value})(\s*,{gap}\s*["']?name["']?\s*:\s*["']?)({name})"#,
            anchor = FLOW_KEY_ANCHOR,
            name = SECRET_NAME_SUBPATTERN,
            gap = flow_member_gap(),
            value = SECRET_VALUE_SUBPATTERN,
        ))
        .unwrap()
    })
}

/// Apply one flow-pair pattern; `name_group`/`value_group` say which capture
/// holds the env-var name (stoplist-checked) and which holds the value to
/// redact. Contract: the pattern must expose exactly captures 1..=4 that
/// concatenate back to the whole match (the replacement loop below rebuilds
/// the match from them).
fn redact_flow_with(pattern: &Regex, text: &str, name_group: usize, value_group: usize) -> String {
    debug_assert_eq!(pattern.captures_len(), 5, "flow patterns expose 1..=4");
    if !pattern.is_match(text) {
        return text.to_string();
    }
    pattern
        .replace_all(text, |caps: &regex::Captures| {
            let name = &caps[name_group];
            if !is_secret_bearing_name(name) {
                return caps[0].to_string();
            }
            let mut out = String::new();
            for group in 1..=4 {
                if group == value_group {
                    out.push_str(redacted_value_like(&caps[group]));
                } else {
                    out.push_str(&caps[group]);
                }
            }
            out
        })
        .to_string()
}

fn redact_flow_name_values(text: &str) -> String {
    let forward = redact_flow_with(flow_name_then_value_pattern(), text, 2, 4);
    redact_flow_with(flow_value_then_name_pattern(), &forward, 4, 2)
}

/// Catch-all: `ANY_VAR=<high-entropy value>` (hex 20+, base64 24+, or
/// mixed-alnum 40+). Catches things like `X_CT0=9c52ab...`,
/// `SESSION_ID=a3f8b1...`, etc. -- secret-shaped values whose variable name
/// doesn't end in a TOKEN/KEY/SECRET/PASSWORD/CREDENTIAL/AUTH word, so the
/// name-based pass misses them. The name and value may each be quoted
/// (JSON), and the trailing group tolerates closing punctuation
/// (`"...",` / `"..."}`) so JSON object members match.
///
/// The trailing group matches end-of-line/end-of-string, not just a
/// following whitespace/quote char: every real call site strips the
/// line-terminating newline before this pattern ever runs (`ssh.rs` reads
/// lines via `BufReader`, `redact_output_text` splits on `.lines()`), so a
/// value that is the last token on a line -- the overwhelmingly common shape
/// for `KEY=value` output -- would otherwise never match.
fn catchall_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r#"(?im)(["']?)([A-Z_][A-Z0-9_]*)(["']?\s*[=:]\s*["']?)([0-9a-f]{20,}|[A-Za-z0-9+/]{24,}={0,2}|[A-Za-z0-9_-]{40,})(["']?[,;}\]]*(?:\s|$))"#).unwrap()
    })
}

/// Generic structural keys (YAML/JSON field names, not env-var-style secret
/// names) that the catch-all must not treat as "any var": their values are
/// often coincidentally hex/base64/UUID-shaped (git SHAs, resource IDs,
/// generation timestamps) without being secrets. `value`/`data` specifically
/// collide with the stateful, context-aware YAML name+value redaction
/// (`yaml_secret_name_pattern`/`yaml_value_pattern`), which already redacts
/// these correctly when the preceding `name:` line is secret-bearing; the
/// catch-all firing unconditionally on every `value:`/`data:` line would
/// both duplicate that and false-positive on non-secret values it can't see
/// the context for. Digest-style names (`sha`, `digest`, `commit`, ...) are
/// excluded for the same reason: their hex values are content addresses, not
/// credentials, and they are pervasive in JSON output from git tooling and
/// registries.
const CATCHALL_EXCLUDED_NAMES: &[&str] = &[
    "VALUE",
    "DATA",
    "NAME",
    "TYPE",
    "KIND",
    "ID",
    "SHA",
    "SHA1",
    "SHA256",
    "SHA512",
    "DIGEST",
    "COMMIT",
    "CHECKSUM",
    "FINGERPRINT",
    "ETAG",
    "REVISION",
];

/// Apply the catch-all pattern, skipping a match whose captured name is a
/// generic structural key (see `CATCHALL_EXCLUDED_NAMES`). The `regex` crate
/// has no lookahead, so the exclusion is a code-level check in the
/// replacement closure rather than part of the pattern itself.
fn redact_catchall(text: &str) -> String {
    if !catchall_pattern().is_match(text) {
        return text.to_string();
    }
    catchall_pattern()
        .replace_all(text, |caps: &regex::Captures| {
            let name = &caps[2];
            if CATCHALL_EXCLUDED_NAMES
                .iter()
                .any(|excluded| name.eq_ignore_ascii_case(excluded))
            {
                caps[0].to_string()
            } else {
                format!("{}{}{}[REDACTED]{}", &caps[1], &caps[2], &caps[3], &caps[5])
            }
        })
        .to_string()
}

fn yaml_secret_name_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(
            r#"(?i)^\s*[+-]?\s*-\s*name\s*:\s*["']?[^"'\n]*(TOKEN|KEY|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)[^"'\n]*["']?\s*$"#,
        )
        .unwrap()
    })
}

fn yaml_value_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r#"(?i)^(\s*[+-]?\s*(?:-\s*)?value\s*:\s*["']?)([^"'\n]*)(["']?\s*)$"#).unwrap()
    })
}

/// Apply redaction patterns to the given text, replacing sensitive values with [REDACTED].
///
/// Pass order matters: value-shaped patterns run first so a scheme-prefixed
/// token (`Bearer <token>`) is consumed whole; the name-based pass then
/// redacts anything a secret-bearing key name points at; the bare-token and
/// catch-all passes sweep up secret-shaped values with weak or no name
/// context.
pub fn redact_output(text: &str) -> String {
    let mut result = text.to_string();

    for (pattern, replacement) in redaction_patterns() {
        // is_match first: redaction runs per output line of every guarded
        // command, and most lines match nothing -- skip the allocation
        // replace_all + to_string would otherwise pay on every pass.
        if pattern.is_match(&result) {
            result = pattern.replace_all(&result, *replacement).to_string();
        }
    }

    let result = redact_flow_name_values(&result);
    let result = redact_named_secrets(&result);
    let result = redact_bare_long_tokens(&result);
    let result = redact_catchall(&result);
    redact_registered_exact_secrets(&result)
}

#[derive(Debug, Default)]
pub struct RedactionState {
    yaml_secret_value_pending: bool,
}

/// Redact one output line while preserving context from previous lines.
///
/// Kubernetes and Helm render environment variables as adjacent `name:` and
/// `value:` lines. The `value:` line alone is too generic to classify safely:
/// it may hold a git SHA, UUID, URL, or actual token. Stateful redaction only
/// masks the value when the preceding env var name is secret-bearing.
pub fn redact_output_with_state(line: &str, state: &mut RedactionState) -> String {
    let should_redact_yaml_value =
        state.yaml_secret_value_pending && yaml_value_pattern().is_match(line);

    let context_redacted = if should_redact_yaml_value {
        yaml_value_pattern()
            .replace(line, "${1}[REDACTED]${3}")
            .to_string()
    } else {
        line.to_string()
    };

    state.yaml_secret_value_pending = yaml_secret_name_pattern().is_match(line)
        || (state.yaml_secret_value_pending && line.trim().is_empty());

    redact_output(&context_redacted)
}

pub fn redact_output_text(text: &str) -> String {
    let had_trailing_newline = text.ends_with('\n');
    let exact_redacted = redact_registered_exact_secrets(text);
    let mut state = RedactionState::default();
    let mut redacted = exact_redacted
        .lines()
        .map(|line| redact_output_with_state(line, &mut state))
        .collect::<Vec<_>>()
        .join("\n");

    if had_trailing_newline {
        redacted.push('\n');
    }

    redacted
}

/// Whether free-form explanatory text contains a literal the shared output
/// redactor would replace. This is suitable for rejecting synthesized prose
/// that becomes authority, such as a learned regular expression.
pub fn text_contains_sensitive_literals(text: &str) -> bool {
    redact_output_text(text) != text
}

/// Whether a value becomes sensitive when interpreted under a field or
/// parameter name. This preserves the shared free-text classifier semantics
/// for low-entropy literals whose meaning comes from their named context.
pub fn named_value_contains_sensitive_literals(name: &str, value: &str) -> bool {
    let projection = format!("{name}={value}");
    redact_output_text(&projection) != projection
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OptionValueKind {
    Credential,
    NamedField,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OptionArity {
    Required,
    AttachedOnly,
}

struct BinaryOptionAlias {
    binaries: &'static [&'static str],
    required_subcommand: Option<&'static str>,
    options: &'static [&'static str],
    value_kind: OptionValueKind,
    arity: OptionArity,
}

struct BinaryValuelessOption {
    binaries: &'static [&'static str],
    required_subcommand: Option<&'static str>,
    options: &'static [&'static str],
}

struct DatabaseClientPasswordGrammar {
    binary: &'static str,
    attached_options: &'static [&'static str],
    valueless_options: &'static [&'static str],
}

const MYSQL_MFA_PASSWORD_OPTIONS: &[&str] = &[
    "-p",
    "--password",
    "--password1",
    "--password2",
    "--password3",
];

const MYSQL_MFA_VALUELESS_PASSWORD_OPTIONS: &[&str] = &[
    "-p",
    "--password",
    "--password1",
    "--password2",
    "--password3",
    "--skip-password",
    "--skip-password1",
    "--skip-password2",
    "--skip-password3",
];

const BASE_PASSWORD_OPTIONS: &[&str] = &["-p", "--password"];
const BASE_VALUELESS_PASSWORD_OPTIONS: &[&str] = &["-p", "--password", "--skip-password"];
const MYSQLSH_VALUELESS_PASSWORD_OPTIONS: &[&str] = &[
    "-p",
    "--password",
    "--password1",
    "--password2",
    "--password3",
    "--no-password",
];
const ACCESS_VALUELESS_PASSWORD_OPTIONS: &[&str] = &["-p", "--password"];
const MYSQL_CONFIG_EDITOR_PASSWORD_OPTIONS: &[&str] = &["-p", "--password"];

/// Official client password grammars. Optional password values use attached
/// syntax; a bare spelling prompts and never consumes the next operand.
const DATABASE_CLIENT_PASSWORD_GRAMMARS: &[DatabaseClientPasswordGrammar] = &[
    DatabaseClientPasswordGrammar {
        binary: "mysql",
        attached_options: MYSQL_MFA_PASSWORD_OPTIONS,
        valueless_options: MYSQL_MFA_VALUELESS_PASSWORD_OPTIONS,
    },
    DatabaseClientPasswordGrammar {
        binary: "mysqladmin",
        attached_options: MYSQL_MFA_PASSWORD_OPTIONS,
        valueless_options: MYSQL_MFA_VALUELESS_PASSWORD_OPTIONS,
    },
    DatabaseClientPasswordGrammar {
        binary: "mysqlcheck",
        attached_options: MYSQL_MFA_PASSWORD_OPTIONS,
        valueless_options: MYSQL_MFA_VALUELESS_PASSWORD_OPTIONS,
    },
    DatabaseClientPasswordGrammar {
        binary: "mysqldump",
        attached_options: MYSQL_MFA_PASSWORD_OPTIONS,
        valueless_options: MYSQL_MFA_VALUELESS_PASSWORD_OPTIONS,
    },
    DatabaseClientPasswordGrammar {
        binary: "mysqlimport",
        attached_options: MYSQL_MFA_PASSWORD_OPTIONS,
        valueless_options: MYSQL_MFA_VALUELESS_PASSWORD_OPTIONS,
    },
    DatabaseClientPasswordGrammar {
        binary: "mysqlpump",
        attached_options: MYSQL_MFA_PASSWORD_OPTIONS,
        valueless_options: MYSQL_MFA_VALUELESS_PASSWORD_OPTIONS,
    },
    DatabaseClientPasswordGrammar {
        binary: "mysqlshow",
        attached_options: MYSQL_MFA_PASSWORD_OPTIONS,
        valueless_options: MYSQL_MFA_VALUELESS_PASSWORD_OPTIONS,
    },
    DatabaseClientPasswordGrammar {
        binary: "mysqlslap",
        attached_options: MYSQL_MFA_PASSWORD_OPTIONS,
        valueless_options: MYSQL_MFA_VALUELESS_PASSWORD_OPTIONS,
    },
    DatabaseClientPasswordGrammar {
        binary: "mysqlsh",
        attached_options: MYSQL_MFA_PASSWORD_OPTIONS,
        valueless_options: MYSQLSH_VALUELESS_PASSWORD_OPTIONS,
    },
    DatabaseClientPasswordGrammar {
        binary: "mysqlbinlog",
        attached_options: BASE_PASSWORD_OPTIONS,
        valueless_options: BASE_VALUELESS_PASSWORD_OPTIONS,
    },
    DatabaseClientPasswordGrammar {
        binary: "mariadb",
        attached_options: BASE_PASSWORD_OPTIONS,
        valueless_options: BASE_VALUELESS_PASSWORD_OPTIONS,
    },
    DatabaseClientPasswordGrammar {
        binary: "mariadb-admin",
        attached_options: BASE_PASSWORD_OPTIONS,
        valueless_options: BASE_VALUELESS_PASSWORD_OPTIONS,
    },
    DatabaseClientPasswordGrammar {
        binary: "mariadb-binlog",
        attached_options: BASE_PASSWORD_OPTIONS,
        valueless_options: BASE_VALUELESS_PASSWORD_OPTIONS,
    },
    DatabaseClientPasswordGrammar {
        binary: "mariadb-check",
        attached_options: BASE_PASSWORD_OPTIONS,
        valueless_options: BASE_VALUELESS_PASSWORD_OPTIONS,
    },
    DatabaseClientPasswordGrammar {
        binary: "mariadb-dump",
        attached_options: BASE_PASSWORD_OPTIONS,
        valueless_options: BASE_VALUELESS_PASSWORD_OPTIONS,
    },
    DatabaseClientPasswordGrammar {
        binary: "mariadb-import",
        attached_options: BASE_PASSWORD_OPTIONS,
        valueless_options: BASE_VALUELESS_PASSWORD_OPTIONS,
    },
    DatabaseClientPasswordGrammar {
        binary: "mariadb-show",
        attached_options: BASE_PASSWORD_OPTIONS,
        valueless_options: BASE_VALUELESS_PASSWORD_OPTIONS,
    },
    DatabaseClientPasswordGrammar {
        binary: "mariadb-slap",
        attached_options: BASE_PASSWORD_OPTIONS,
        valueless_options: BASE_VALUELESS_PASSWORD_OPTIONS,
    },
    DatabaseClientPasswordGrammar {
        binary: "mariadb-access",
        attached_options: BASE_PASSWORD_OPTIONS,
        valueless_options: ACCESS_VALUELESS_PASSWORD_OPTIONS,
    },
    DatabaseClientPasswordGrammar {
        binary: "mysqlaccess",
        attached_options: BASE_PASSWORD_OPTIONS,
        valueless_options: ACCESS_VALUELESS_PASSWORD_OPTIONS,
    },
];

/// Opaque credential-taking options whose spelling does not carry enough
/// meaning for lexical classification. The table stays deliberately bounded:
/// aliases are binary-specific, and subcommand-specific where a short option
/// has a benign meaning elsewhere. SSH `-p` and Ansible `-a` are intentionally
/// absent because they carry a port and a module payload, respectively.
const BINARY_OPTION_ALIASES: &[BinaryOptionAlias] = &[
    BinaryOptionAlias {
        binaries: &["curl"],
        required_subcommand: None,
        options: &["-u", "--user", "--proxy-user"],
        value_kind: OptionValueKind::Credential,
        arity: OptionArity::Required,
    },
    BinaryOptionAlias {
        binaries: &["curl"],
        required_subcommand: None,
        options: &["-H", "--header", "--proxy-header"],
        value_kind: OptionValueKind::NamedField,
        arity: OptionArity::Required,
    },
    BinaryOptionAlias {
        binaries: &["http", "https"],
        required_subcommand: None,
        options: &["-a", "--auth"],
        value_kind: OptionValueKind::Credential,
        arity: OptionArity::Required,
    },
    BinaryOptionAlias {
        binaries: &["mariadb-access", "mysqlaccess"],
        required_subcommand: None,
        options: &["-P", "--spassword"],
        value_kind: OptionValueKind::Credential,
        arity: OptionArity::Required,
    },
    BinaryOptionAlias {
        binaries: &["redis-cli"],
        required_subcommand: None,
        options: &["-a"],
        value_kind: OptionValueKind::Credential,
        arity: OptionArity::Required,
    },
    BinaryOptionAlias {
        binaries: &["sshpass"],
        required_subcommand: None,
        options: &["-p"],
        value_kind: OptionValueKind::Credential,
        arity: OptionArity::Required,
    },
    BinaryOptionAlias {
        binaries: &["docker", "podman"],
        required_subcommand: Some("login"),
        options: &["-p"],
        value_kind: OptionValueKind::Credential,
        arity: OptionArity::Required,
    },
];

/// Secret-related options that acquire values outside argv, such as an
/// interactive prompt or stdin. They do not consume the following argument.
const BINARY_VALUELESS_OPTIONS: &[BinaryValuelessOption] = &[
    BinaryValuelessOption {
        binaries: &["ansible", "ansible-playbook", "ansible-galaxy"],
        required_subcommand: None,
        options: &[
            "-k",
            "-K",
            "--ask-pass",
            "--ask-become-pass",
            "--ask-vault-pass",
        ],
    },
    BinaryValuelessOption {
        binaries: &["docker", "podman"],
        required_subcommand: Some("login"),
        options: &["--password-stdin"],
    },
];

struct ParsedOption<'a> {
    name: &'a str,
    value_start: Option<usize>,
}

struct ClassifiedCommand {
    sensitive: bool,
    binary: String,
    args: Vec<String>,
}

pub const SENSITIVE_ARGV_REPLAY_GUIDANCE: &str =
    "command was not stored: replayable argv contains a literal credential; use managed --secret or --secret-file bindings";

fn parse_leading_option(argument: &str) -> Option<ParsedOption<'_>> {
    if !argument.starts_with('-') {
        return None;
    }
    let name_start = argument.len() - argument.trim_start_matches('-').len();
    if name_start == argument.len() {
        return None;
    }
    let suffix = &argument[name_start..];
    let delimiter = suffix
        .char_indices()
        .find(|(_, character)| matches!(character, '=' | ':') || character.is_control())
        .map(|(offset, _)| name_start + offset);
    let name_end = delimiter.unwrap_or(argument.len());
    Some(ParsedOption {
        name: &argument[..name_end],
        value_start: delimiter,
    })
}

fn strict_cli_secret_name(option: &str) -> bool {
    let name = option.trim_start_matches('-');
    is_secret_bearing_name(name)
        || ["key", "pass", "passphrase"]
            .iter()
            .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

fn binary_lookup_name(binary: &str) -> String {
    let basename = binary.rsplit(['/', '\\']).next().unwrap_or(binary);
    let lowercase = basename.to_ascii_lowercase();
    [".exe", ".cmd", ".bat", ".com"]
        .iter()
        .find_map(|suffix| lowercase.strip_suffix(suffix))
        .unwrap_or(&lowercase)
        .to_string()
}

fn container_subcommand<'a>(binary: &str, args: &'a [String]) -> Option<(usize, &'a str)> {
    const DOCKER_VALUE_OPTIONS: &[&str] = &[
        "--config",
        "-c",
        "--context",
        "-H",
        "--host",
        "-l",
        "--log-level",
        "--tlscacert",
        "--tlscert",
        "--tlskey",
    ];
    const PODMAN_VALUE_OPTIONS: &[&str] = &[
        "--cdi-spec-dir",
        "--cgroup-manager",
        "--config",
        "--conmon",
        "-c",
        "--connection",
        "--events-backend",
        "--hooks-dir",
        "--identity",
        "--imagestore",
        "--log-level",
        "--module",
        "--network-cmd-path",
        "--network-config-dir",
        "--out",
        "--root",
        "--runroot",
        "--runtime",
        "--runtime-flag",
        "--ssh",
        "--storage-driver",
        "--storage-opt",
        "--tls-ca",
        "--tls-cert",
        "--tls-details",
        "--tls-key",
        "--tmpdir",
        "--url",
        "--volumepath",
    ];
    let value_options = match binary {
        "docker" => DOCKER_VALUE_OPTIONS,
        "podman" => PODMAN_VALUE_OPTIONS,
        _ => return None,
    };
    let mut consumes_next = false;
    for (index, argument) in args.iter().enumerate() {
        if consumes_next {
            consumes_next = false;
            continue;
        }
        if argument == "--" {
            return args.get(index + 1).map(|value| (index + 1, value.as_str()));
        }
        if !argument.starts_with('-') {
            return Some((index, argument));
        }
        if value_options.contains(&argument.as_str()) {
            consumes_next = true;
            continue;
        }
        if value_options.iter().any(|option| {
            argument.strip_prefix(option).is_some_and(|suffix| {
                !suffix.is_empty()
                    && (option.len() == 2
                        || suffix.starts_with('=')
                        || suffix.starts_with(':')
                        || suffix.starts_with(char::is_control))
            })
        }) {
            continue;
        }
    }
    None
}

fn parsed_subcommand<'a>(binary: &str, args: &'a [String]) -> Option<(usize, &'a str)> {
    match binary_lookup_name(binary).as_str() {
        "docker" | "podman" => container_subcommand(&binary_lookup_name(binary), args),
        "mysql_config_editor" => mysql_config_editor_subcommand(args),
        _ => args
            .iter()
            .enumerate()
            .find(|(_, argument)| !argument.starts_with('-'))
            .map(|(index, argument)| (index, argument.as_str())),
    }
}

fn mysql_config_editor_subcommand(args: &[String]) -> Option<(usize, &str)> {
    const COMMANDS: &[&str] = &["help", "print", "remove", "reset", "set"];
    let mut short_debug_value = false;
    for (index, argument) in args.iter().enumerate() {
        if short_debug_value {
            short_debug_value = false;
            continue;
        }
        if argument == "-#" {
            short_debug_value = true;
            continue;
        }
        if argument.starts_with("-#") || argument.starts_with("--debug=") {
            continue;
        }
        if argument.starts_with('-') {
            continue;
        }
        return COMMANDS
            .contains(&argument.as_str())
            .then_some((index, argument.as_str()));
    }
    None
}

fn alias_context_matches(
    binary: &str,
    args: &[String],
    option_index: usize,
    binaries: &[&str],
    required_subcommand: Option<&str>,
) -> bool {
    let binary = binary_lookup_name(binary);
    binaries.contains(&binary.as_str())
        && required_subcommand.is_none_or(|required| {
            parsed_subcommand(&binary, args)
                .is_some_and(|(index, subcommand)| index < option_index && subcommand == required)
        })
}

fn database_client_password_grammar(
    binary: &str,
) -> Option<&'static DatabaseClientPasswordGrammar> {
    let binary = binary_lookup_name(binary);
    DATABASE_CLIENT_PASSWORD_GRAMMARS
        .iter()
        .find(|grammar| grammar.binary == binary.as_str())
}

fn parse_database_client_password_option<'a>(
    binary: &str,
    argument: &'a str,
) -> Option<ParsedOption<'a>> {
    if binary_lookup_name(binary) == "mysql_config_editor" {
        return parse_attached_password_option(MYSQL_CONFIG_EDITOR_PASSWORD_OPTIONS, argument);
    }
    let grammar = database_client_password_grammar(binary)?;
    parse_attached_password_option(grammar.attached_options, argument)
}

fn parse_attached_password_option<'a>(
    options: &[&str],
    argument: &'a str,
) -> Option<ParsedOption<'a>> {
    for option in options {
        if argument == *option {
            return Some(ParsedOption {
                name: argument,
                value_start: None,
            });
        }
        let Some(suffix) = argument.strip_prefix(option) else {
            continue;
        };
        let short_option = option.len() == 2 && option.starts_with('-');
        let separated_long = suffix
            .chars()
            .next()
            .is_some_and(|character| matches!(character, '=' | ':') || character.is_control());
        if !suffix.is_empty() && (short_option || separated_long) {
            return Some(ParsedOption {
                name: &argument[..option.len()],
                value_start: Some(option.len()),
            });
        }
    }
    None
}

fn parse_binary_alias_option<'a>(
    binary: &str,
    args: &[String],
    option_index: usize,
    argument: &'a str,
) -> Option<(ParsedOption<'a>, OptionValueKind, OptionArity)> {
    if let Some(option) = parse_database_client_password_option(binary, argument) {
        return Some((
            option,
            OptionValueKind::Credential,
            OptionArity::AttachedOnly,
        ));
    }
    for alias in BINARY_OPTION_ALIASES {
        if !alias_context_matches(
            binary,
            args,
            option_index,
            alias.binaries,
            alias.required_subcommand,
        ) {
            continue;
        }
        for option in alias.options {
            if argument == *option {
                return Some((
                    ParsedOption {
                        name: argument,
                        value_start: None,
                    },
                    alias.value_kind,
                    alias.arity,
                ));
            }
            let Some(suffix) = argument.strip_prefix(option) else {
                continue;
            };
            let short_alias = option.len() == 2 && option.starts_with('-');
            let separated_long = suffix
                .chars()
                .next()
                .is_some_and(|character| matches!(character, '=' | ':') || character.is_control());
            if !suffix.is_empty() && (short_alias || separated_long) {
                return Some((
                    ParsedOption {
                        name: option,
                        value_start: Some(option.len()),
                    },
                    alias.value_kind,
                    alias.arity,
                ));
            }
        }
    }
    None
}

fn is_known_valueless_option(
    binary: &str,
    args: &[String],
    option_index: usize,
    option: &ParsedOption<'_>,
) -> bool {
    option.value_start.is_none()
        && ((binary_lookup_name(binary) == "mysql_config_editor"
            && MYSQL_CONFIG_EDITOR_PASSWORD_OPTIONS.contains(&option.name)
            && parsed_subcommand(binary, args).is_some_and(|(subcommand_index, subcommand)| {
                subcommand_index < option_index && matches!(subcommand, "set" | "remove")
            }))
            || database_client_password_grammar(binary)
                .is_some_and(|grammar| grammar.valueless_options.contains(&option.name))
            || BINARY_VALUELESS_OPTIONS.iter().any(|rule| {
                alias_context_matches(
                    binary,
                    args,
                    option_index,
                    rule.binaries,
                    rule.required_subcommand,
                ) && rule.options.contains(&option.name)
            }))
}

fn named_secret_value_start(argument: &str) -> Option<usize> {
    let (index, _) = argument
        .char_indices()
        .find(|(_, character)| matches!(character, '=' | ':'))?;
    let name = argument[..index]
        .trim()
        .trim_matches(|character| matches!(character, '\'' | '"'));
    is_secret_bearing_name(name).then_some(index)
}

fn redact_suffix(argument: &str, value_start: usize) -> String {
    let separator = argument[value_start..].chars().next();
    match separator {
        Some(separator @ ('=' | ':')) => {
            format!("{}{}[REDACTED]", &argument[..value_start], separator)
        }
        _ => format!("{}=[REDACTED]", &argument[..value_start]),
    }
}

fn classify_command(binary: &str, args: &[String]) -> ClassifiedCommand {
    let redacted_binary = redact_output_text(binary);
    let mut sensitive = redacted_binary != binary;
    let mut redacted_args = Vec::with_capacity(args.len());
    let mut pending_value_kind = None;

    for (index, argument) in args.iter().enumerate() {
        if let Some(value_kind) = pending_value_kind.take() {
            let value_is_sensitive = value_kind == OptionValueKind::Credential
                || named_secret_value_start(argument).is_some();
            if value_is_sensitive {
                sensitive = true;
                redacted_args.push("[REDACTED]".to_string());
                continue;
            }
        }

        let parsed_alias = parse_binary_alias_option(binary, args, index, argument);
        let parsed_option = parsed_alias
            .as_ref()
            .map(|(option, _, _)| ParsedOption {
                name: option.name,
                value_start: option.value_start,
            })
            .or_else(|| parse_leading_option(argument));
        if let Some(option) = parsed_option {
            let value_kind = parsed_alias
                .as_ref()
                .map(|(_, value_kind, _)| *value_kind)
                .or_else(|| {
                    strict_cli_secret_name(option.name).then_some(OptionValueKind::Credential)
                });
            if let Some(value_kind) = value_kind {
                if is_known_valueless_option(binary, args, index, &option) {
                    let redacted = redact_output_text(argument);
                    sensitive |= redacted != *argument;
                    redacted_args.push(redacted);
                    continue;
                }
                if let Some(value_start) = option.value_start {
                    let delimiter = argument[value_start..]
                        .chars()
                        .next()
                        .expect("parsed option delimiter exists");
                    let suffix = &argument[value_start + delimiter.len_utf8()..];
                    if delimiter.is_control() {
                        sensitive = true;
                        redacted_args.push(redact_suffix(argument, value_start));
                        if index + 1 < args.len() {
                            pending_value_kind = Some(value_kind);
                        }
                        continue;
                    }
                    let value_is_sensitive = value_kind == OptionValueKind::Credential
                        || named_secret_value_start(suffix).is_some();
                    if value_is_sensitive {
                        sensitive = true;
                        redacted_args.push(redact_suffix(argument, value_start));
                        continue;
                    }
                } else if parsed_alias
                    .as_ref()
                    .is_none_or(|(_, _, arity)| *arity == OptionArity::Required)
                    && index + 1 < args.len()
                {
                    pending_value_kind = Some(value_kind);
                }
            }
        }

        if let Some(value_start) = named_secret_value_start(argument) {
            sensitive = true;
            redacted_args.push(redact_suffix(argument, value_start));
            continue;
        }

        let redacted = redact_output_text(argument);
        sensitive |= redacted != *argument;
        redacted_args.push(redacted);
    }

    ClassifiedCommand {
        sensitive,
        binary: redacted_binary,
        args: redacted_args,
    }
}

/// Whether an executable or literal argv vector contains credential material.
/// Classification happens on original argv elements so separators, adjacency,
/// and embedded control characters remain available to the classifier.
pub fn command_contains_sensitive_literals(binary: &str, args: &[String]) -> bool {
    classify_command(binary, args).sensitive
}

/// Conservatively classify a legacy space-joined argv tail. Both shell-style
/// and whitespace tokenization are checked because historical records did not
/// retain enough information to recover authoritative argv boundaries.
pub fn flattened_args_contain_sensitive_literals(binary: &str, flattened_args: &str) -> bool {
    let whitespace = flattened_args
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();
    if command_contains_sensitive_literals(binary, &whitespace) {
        return true;
    }
    shell_words::split(flattened_args)
        .ok()
        .is_some_and(|args| command_contains_sensitive_literals(binary, &args))
}

/// Conservatively classify a legacy flattened command. This is for purging
/// historical evidence only and never reconstructs matcher authority.
pub fn flattened_command_contains_sensitive_literals(command: &str) -> bool {
    fn classify(tokens: Vec<String>) -> bool {
        tokens
            .split_first()
            .is_some_and(|(binary, args)| command_contains_sensitive_literals(binary, args))
    }

    let whitespace = command
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();
    classify(whitespace) || shell_words::split(command).ok().is_some_and(classify)
}

/// Redact one structured command without discarding executable or argv
/// boundaries.
fn redact_command_argv(binary: &str, args: &[String]) -> (String, Vec<String>) {
    let command = classify_command(binary, args);
    (command.binary, command.args)
}

/// Render one command for display while retaining argv context during
/// redaction. This is display-only and never feeds matcher authority.
pub fn redact_command_line(binary: &str, args: &[String]) -> String {
    let (binary, args) = redact_command_argv(binary, args);
    command_line(&binary, &args)
}

/// Redact configured exact literals from one structured command in addition
/// to the shared argv-aware classifier. This explicit form is useful at
/// boundaries that receive a scoped secret set before daemon registration.
pub fn redact_command_line_with_exact_secrets(
    binary: &str,
    args: &[String],
    secrets: &[&str],
) -> String {
    let binary = redact_exact_and_registered_secrets(binary, secrets);
    let args = args
        .iter()
        .map(|argument| redact_exact_and_registered_secrets(argument, secrets))
        .collect::<Vec<_>>();
    redact_command_line(&binary, &args)
}

pub fn command_contains_exact_secrets(binary: &str, args: &[String], secrets: &[&str]) -> bool {
    secrets
        .iter()
        .copied()
        .filter(|secret| !secret.is_empty())
        .any(|secret| {
            binary.contains(secret) || args.iter().any(|argument| argument.contains(secret))
        })
}

pub fn json_contains_exact_secrets(value: &serde_json::Value, secrets: &[&str]) -> bool {
    match value {
        serde_json::Value::String(value) => {
            redact_registered_exact_secrets(value) != *value
                || secrets
                    .iter()
                    .copied()
                    .filter(|secret| !secret.is_empty())
                    .any(|secret| value.contains(secret))
        }
        serde_json::Value::Array(values) => values
            .iter()
            .any(|value| json_contains_exact_secrets(value, secrets)),
        serde_json::Value::Object(values) => values.iter().any(|(key, value)| {
            redact_registered_exact_secrets(key) != *key
                || secrets
                    .iter()
                    .copied()
                    .filter(|secret| !secret.is_empty())
                    .any(|secret| key.contains(secret))
                || json_contains_exact_secrets(value, secrets)
        }),
        _ => false,
    }
}

pub fn redact_json_exact_secrets(value: &mut serde_json::Value, secrets: &[&str]) {
    match value {
        serde_json::Value::String(value) => {
            *value = redact_exact_and_registered_secrets(value, secrets);
        }
        serde_json::Value::Array(values) => {
            for value in values {
                redact_json_exact_secrets(value, secrets);
            }
        }
        serde_json::Value::Object(values) => {
            let original = std::mem::take(values);
            for (key, mut value) in original {
                redact_json_exact_secrets(&mut value, secrets);
                let key = redact_exact_and_registered_secrets(&key, secrets);
                values.insert(key, value);
            }
        }
        _ => {}
    }
}

/// Derive command learning metadata without retaining the binary or literal argv.
///
/// Learning stores use the digest only to distinguish observations. It is not
/// matcher authority and cannot be reversed into the original arguments.
pub fn command_metadata(binary: &str, args: &[String]) -> String {
    use sha2::{Digest, Sha256};

    let encoded =
        serde_json::to_vec(&(binary, args)).expect("structured command metadata always serializes");
    format!(
        "[argv-sha256:{}]",
        Sha256::digest(encoded)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

/// Scrub a historical flattened command field without trying to recover argv
/// boundaries. Existing canonical metadata is left byte-for-byte unchanged.
pub fn scrub_flattened_command_metadata(value: &str) -> String {
    use sha2::{Digest, Sha256};

    static CANONICAL: OnceLock<Regex> = OnceLock::new();
    let canonical = CANONICAL.get_or_init(|| {
        Regex::new(r"^\[(?:argv|legacy-command)-sha256:[0-9a-f]{64}\]$")
            .expect("valid metadata regex")
    });
    if canonical.is_match(value) {
        return value.to_string();
    }
    format!(
        "[legacy-command-sha256:{}]",
        Sha256::digest(value.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

/// Redact exact secret values from output. This catches cases the regex patterns miss,
/// like bare `env` output or `echo $VAR` where there's no `KEY=` prefix.
pub fn redact_exact_secrets(text: &str, secrets: &[&str]) -> String {
    let mut result = text.to_string();
    let mut literals = secrets
        .iter()
        .copied()
        .filter(|secret| !secret.is_empty())
        .collect::<Vec<_>>();
    literals.sort_unstable_by_key(|secret| std::cmp::Reverse(secret.len()));
    literals.dedup();
    if text.len() > MAX_EXACT_REDACTION_INPUT_BYTES
        || literals.len().saturating_mul(text.len()) > MAX_EXACT_REDACTION_COMPARISONS
    {
        // The caller asked for exact redaction but the bounded synchronous
        // path cannot prove it within its work budget. Returning only a
        // marker is fail-closed and never exposes the unredacted input.
        return "[REDACTED]".to_string();
    }
    let marker = ["[REDACTED]", "[FILTERED]", "<hidden>", "***", ""]
        .into_iter()
        .find(|candidate| !literals.iter().any(|secret| candidate.contains(secret)))
        .expect("empty exact-redaction marker is always safe");
    for secret in literals {
        if result.contains(secret) {
            result = result.replace(secret, marker);
        }
    }
    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExactRedactionLimitExceeded;

/// Boundary-safe exact-byte redaction for streamed output. The redactor keeps
/// only the suffix that can still begin a configured literal, and enforces the
/// limit on emitted bytes after replacement expansion.
pub struct ExactSecretStreamRedactor {
    secrets: Vec<Vec<u8>>,
    marker: &'static [u8],
    carry: Vec<u8>,
    keep: usize,
    received: usize,
    emitted: usize,
    limit: usize,
    comparisons: usize,
}

impl ExactSecretStreamRedactor {
    pub fn new(
        secrets: impl IntoIterator<Item = Vec<u8>>,
        limit: usize,
    ) -> Result<Self, ExactRedactionLimitExceeded> {
        let mut secrets = secrets
            .into_iter()
            .filter(|secret| !secret.is_empty())
            .collect::<Vec<_>>();
        with_registered_redaction_values(|registered| {
            secrets.extend(registered.iter().map(|secret| secret.as_bytes().to_vec()));
        });
        secrets.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
        secrets.dedup();
        if secrets.len() > MAX_TRUSTED_EXACT_SECRET_ENTRIES
            || secrets
                .iter()
                .any(|secret| secret.len() > MAX_TRUSTED_EXACT_SECRET_LITERAL_BYTES)
            || secrets.iter().map(Vec::len).sum::<usize>() > MAX_TRUSTED_EXACT_SECRET_BYTES
        {
            return Err(ExactRedactionLimitExceeded);
        }
        let marker = [
            b"[REDACTED]".as_slice(),
            b"[FILTERED]".as_slice(),
            b"<hidden>".as_slice(),
            b"***".as_slice(),
            b"".as_slice(),
        ]
        .into_iter()
        .find(|candidate| {
            !secrets.iter().any(|secret| {
                !secret.is_empty()
                    && candidate
                        .windows(secret.len())
                        .any(|window| window == secret)
            })
        })
        .expect("empty exact-redaction marker is always safe");
        let keep = secrets
            .iter()
            .map(Vec::len)
            .max()
            .unwrap_or(1)
            .saturating_sub(1);
        Ok(Self {
            secrets,
            marker,
            carry: Vec::new(),
            keep,
            received: 0,
            emitted: 0,
            limit: limit.min(MAX_EXACT_REDACTION_INPUT_BYTES),
            comparisons: 0,
        })
    }

    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>, ExactRedactionLimitExceeded> {
        self.received = self
            .received
            .checked_add(chunk.len())
            .filter(|received| *received <= self.limit)
            .ok_or(ExactRedactionLimitExceeded)?;
        self.carry.extend_from_slice(chunk);
        let safe_end = self.carry.len().saturating_sub(self.keep);
        self.emit_through(safe_end)
    }

    pub fn finish(&mut self) -> Result<Vec<u8>, ExactRedactionLimitExceeded> {
        self.emit_through(self.carry.len())
    }

    fn emit_through(&mut self, safe_end: usize) -> Result<Vec<u8>, ExactRedactionLimitExceeded> {
        let mut output = Vec::new();
        let mut position = 0;
        while position < safe_end {
            self.comparisons = self
                .comparisons
                .checked_add(self.secrets.len())
                .filter(|comparisons| *comparisons <= MAX_EXACT_REDACTION_COMPARISONS)
                .ok_or(ExactRedactionLimitExceeded)?;
            let (replacement, consumed) = if let Some(secret) = self
                .secrets
                .iter()
                .find(|secret| self.carry[position..].starts_with(secret))
            {
                (self.marker, secret.len())
            } else {
                (&self.carry[position..position + 1], 1)
            };
            if self.emitted.saturating_add(replacement.len()) > self.limit {
                return Err(ExactRedactionLimitExceeded);
            }
            output.extend_from_slice(replacement);
            self.emitted += replacement.len();
            position += consumed;
        }
        self.carry.drain(..position);
        Ok(output)
    }

    pub fn redact_all(
        secrets: impl IntoIterator<Item = Vec<u8>>,
        bytes: &[u8],
        limit: usize,
    ) -> Result<Vec<u8>, ExactRedactionLimitExceeded> {
        let mut redactor = Self::new(secrets, limit)?;
        let mut output = redactor.push(bytes)?;
        output.extend_from_slice(&redactor.finish()?);
        Ok(output)
    }
}

#[cfg(test)]
mod tests;
