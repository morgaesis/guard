use regex::Regex;
use std::borrow::Cow;
use std::sync::OnceLock;

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
            if NAMED_SECRET_STOPLIST
                .iter()
                .any(|stop| name.eq_ignore_ascii_case(stop))
            {
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
/// `env: [{name: API_TOKEN, value: abc123}]`,
/// `{"name": "DB_PASSWORD", "value": "hunter2"}`, the reversed member order
/// (`{value: hunter2, name: DB_PASSWORD}`), and pairs with intervening
/// members (`{name: DB_PASSWORD, optional: false, value: hunter2}`). The
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
            if NAMED_SECRET_STOPLIST
                .iter()
                .any(|stop| name.eq_ignore_ascii_case(stop))
            {
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
    redact_catchall(&result)
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
    let mut state = RedactionState::default();
    let mut redacted = text
        .lines()
        .map(|line| redact_output_with_state(line, &mut state))
        .collect::<Vec<_>>()
        .join("\n");

    if had_trailing_newline {
        redacted.push('\n');
    }

    redacted
}

/// Redact exact secret values from output. This catches cases the regex patterns miss,
/// like bare `env` output or `echo $VAR` where there's no `KEY=` prefix.
pub fn redact_exact_secrets(text: &str, secrets: &[&str]) -> String {
    let mut result = text.to_string();
    for secret in secrets {
        if secret.len() >= 8 && result.contains(*secret) {
            result = result.replace(*secret, "[REDACTED]");
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_escape_passes_plain_text_through_borrowed() {
        assert!(matches!(
            audit_escape("git commit -m message"),
            Cow::Borrowed(_)
        ));
        assert_eq!(audit_escape("état café 日本語"), "état café 日本語");
    }

    #[test]
    fn audit_escape_keeps_one_record_on_one_line() {
        let escaped = audit_escape("x\n[AUDIT] ALLOWED forged");
        assert_eq!(escaped, "x\\n[AUDIT] ALLOWED forged");
        assert!(!escaped.contains('\n'));
        assert!(!escaped.contains('\r'));
    }

    #[test]
    fn audit_escape_covers_all_control_characters() {
        assert_eq!(audit_escape("a\tb\rc"), "a\\tb\\rc");
        assert_eq!(audit_escape("bell\u{7}del\u{7f}"), "bell\\u{7}del\\u{7f}");
        assert_eq!(audit_escape("c1\u{85}end"), "c1\\u{85}end");
        // Backslash doubles so escaped output is unambiguous: a literal
        // two-character "\n" in the input stays distinguishable from an
        // escaped newline.
        assert_eq!(audit_escape("literal\\n"), "literal\\\\n");
        for c in ('\u{0}'..='\u{9f}').filter(|c| c.is_control()) {
            let escaped = audit_escape(&c.to_string()).into_owned();
            assert!(
                escaped.chars().all(|c| !c.is_control()),
                "control {:?} survived as {:?}",
                c,
                escaped
            );
        }
    }

    #[test]
    fn test_redact_token_env_var() {
        let input = "MY_TOKEN=abc123secret";
        let output = redact_output(input);
        assert!(output.contains("[REDACTED]"), "got: {output}");
        assert!(!output.contains("abc123secret"), "got: {output}");
    }

    #[test]
    fn test_redact_password() {
        let input = "password=mysecretpassword";
        let output = redact_output(input);
        assert!(output.contains("[REDACTED]"), "got: {output}");
        assert!(!output.contains("mysecretpassword"), "got: {output}");
    }

    #[test]
    fn test_redact_bearer_token() {
        let input = "bearer: some_long_bearer_token_value";
        let output = redact_output(input);
        assert!(output.contains("[REDACTED]"), "got: {output}");
        assert!(
            !output.contains("some_long_bearer_token_value"),
            "got: {output}"
        );
    }

    #[test]
    fn test_redact_private_key() {
        let input = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpA...content...";
        let output = redact_output(input);
        assert!(output.contains("[REDACTED]"), "got: {output}");
    }

    #[test]
    fn test_redact_sk_key() {
        let input = "api_key: sk-abcdefghijklmnopqrstuvwxyz";
        let output = redact_output(input);
        assert!(output.contains("[REDACTED]"), "got: {output}");
        assert!(
            !output.contains("sk-abcdefghijklmnopqrstuvwxyz"),
            "got: {output}"
        );
    }

    #[test]
    fn test_redact_jwt() {
        let input = "token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let output = redact_output(input);
        assert!(output.contains("[REDACTED]"), "got: {output}");
        assert!(!output.contains("eyJhbGci"), "got: {output}");
    }

    #[test]
    fn test_no_redaction_needed() {
        let input = "total 48\ndrwxr-xr-x  5 user user 4096 Jan  1 00:00 .\n";
        let output = redact_output(input);
        assert_eq!(output, input);
    }

    #[test]
    fn test_redact_api_secret() {
        let input = "API_SECRET=verysecretvalue123";
        let output = redact_output(input);
        assert!(output.contains("[REDACTED]"), "got: {output}");
        assert!(!output.contains("verysecretvalue123"), "got: {output}");
    }

    // --- New tests for the gaps ---

    #[test]
    fn test_redact_hex_cookie_value() {
        // X_CT0=9c52ab235e556a3f... -- no KEY/TOKEN in name, but long hex value
        let input = "X_CT0=9c52ab235e556a3f8b1d2e4f6a7c9d0e1f2a3b4c5d6e7f \n";
        let output = redact_output(input);
        assert!(output.contains("[REDACTED]"), "got: {output}");
        assert!(
            !output.contains("9c52ab235e556a3f"),
            "hex value should be redacted, got: {output}"
        );
    }

    #[test]
    fn test_redact_hex_cookie_value_no_trailing_whitespace() {
        // Same value, but shaped exactly like the real call sites: no trailing
        // space/newline. ssh.rs reads lines via BufReader (newline stripped) and
        // redact_output_text splits on `.lines()` (also strips it) before this
        // pattern ever runs, so a value at end-of-line with no padding is the
        // realistic, common case -- not the exception.
        let input = "X_CT0=9c52ab235e556a3f8b1d2e4f6a7c9d0e1f2a3b4c5d6e7f";
        let output = redact_output(input);
        assert!(output.contains("[REDACTED]"), "got: {output}");
        assert!(
            !output.contains("9c52ab235e556a3f"),
            "hex value should be redacted even with no trailing whitespace, got: {output}"
        );
    }

    #[test]
    fn test_redact_base64_env_value() {
        // GITHUB_APP_KEY_B64=LS0tLS1CRUdJTi... -- KEY in name catches it,
        // but also test the base64 catch-all pattern
        let input = "SOME_CONFIG=LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ== \n";
        let output = redact_output(input);
        assert!(output.contains("[REDACTED]"), "got: {output}");
        assert!(
            !output.contains("LS0tLS1CRUdJTi"),
            "base64 value should be redacted, got: {output}"
        );
    }

    #[test]
    fn test_redact_standalone_base64_line() {
        // A line that's just a base64 blob (like a key file or cert body)
        let input = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVB";
        let output = redact_output(input);
        assert!(output.contains("[REDACTED]"), "got: {output}");
    }

    #[test]
    fn test_redact_session_id_hex() {
        let input = "SESSION_ID=a3f8b1c2d4e5f6a7b8c9d0e1f2a3b4c5 \n";
        let output = redact_output(input);
        assert!(output.contains("[REDACTED]"), "got: {output}");
    }

    #[test]
    fn test_redact_output_text_line_with_no_trailing_padding() {
        // Exercises the real call path (redact_output_text -> .lines() ->
        // redact_output_with_state -> redact_output), which is what strips the
        // newline before pattern 6 ever sees the text. A single-line value with
        // no trailing whitespace at all must still be redacted.
        let input = "SESSION_ID=a3f8b1c2d4e5f6a7b8c9d0e1f2a3b4c5";
        let output = redact_output_text(input);
        assert!(output.contains("[REDACTED]"), "got: {output}");
        assert!(
            !output.contains("a3f8b1c2d4e5f6a7b8c9d0e1f2a3b4c5"),
            "got: {output}"
        );
    }

    #[test]
    fn test_redact_kubernetes_yaml_value_token() {
        let input = r#"        - name: NETDATA_CLAIM_TOKEN
          value: "ExampleSyntheticTokenValue1234567890"
"#;
        let output = redact_output_text(input);
        assert!(output.contains("NETDATA_CLAIM_TOKEN"), "got: {output}");
        assert!(output.contains("value: \"[REDACTED]\""), "got: {output}");
        assert!(
            !output.contains("ExampleSyntheticTokenValue"),
            "got: {output}"
        );
    }

    #[test]
    fn test_do_not_redact_kubernetes_yaml_url_value() {
        let input = r#"        - name: NETDATA_CLAIM_URL
          value: "https://api.netdata.cloud"
"#;
        let output = redact_output_text(input);
        assert_eq!(output, input);
    }

    #[test]
    fn test_do_not_redact_kubernetes_yaml_git_sha_value() {
        let input = r#"        - name: APP_GIT_SHA
          value: "0123456789abcdef0123456789abcdef01234567"
"#;
        let output = redact_output_text(input);
        assert_eq!(output, input);
    }

    #[test]
    fn test_do_not_redact_kubernetes_yaml_uuid_value() {
        let input = r#"        - name: RESOURCE_UID
          value: "123e4567-e89b-12d3-a456-426614174000"
"#;
        let output = redact_output_text(input);
        assert_eq!(output, input);
    }

    #[test]
    fn test_redact_streaming_kubernetes_yaml_value_token() {
        let mut state = RedactionState::default();
        let name = redact_output_with_state("        - name: SERVICE_AUTH_TOKEN", &mut state);
        let value = redact_output_with_state(
            "          value: \"AnotherSyntheticTokenValue1234567890\"",
            &mut state,
        );

        assert_eq!(name, "        - name: SERVICE_AUTH_TOKEN");
        assert_eq!(value, "          value: \"[REDACTED]\"");
    }

    #[test]
    fn test_redact_cloudstack_json_apikey() {
        // The exact leak shape: cmk JSON output with a quoted compound key
        // name (no separator before "key") and a trailing comma.
        let input = r#"      "apikey": "dpFmM7VLB07-kQrfHXWLOsIqy1jvcPUFTzYdaUxKfrKPplbrLPGqrK_a2wRIzT3vFTdb3vCgMFuVJErzWa5S3g","#;
        let output = redact_output_text(input);
        assert!(output.contains("\"apikey\""), "got: {output}");
        assert!(!output.contains("dpFmM7VLB07"), "got: {output}");
        assert!(output.contains("[REDACTED]"), "got: {output}");
    }

    #[test]
    fn test_redact_cloudstack_json_secretkey() {
        let input = r#"      "secretkey": "yVdeOc2BpPsUtozcx13Mp96CyCJPKm9wZycmXgLA0uXSuT-kqrPWfblcJ0KHPUW9wgSekgBBB0uzsSopcgvHkQ""#;
        let output = redact_output_text(input);
        assert!(output.contains("\"secretkey\""), "got: {output}");
        assert!(!output.contains("yVdeOc2BpPsUtozcx13"), "got: {output}");
    }

    #[test]
    fn test_redact_json_quoted_token_short_value() {
        // Name-based redaction fires on the key name alone; the value does
        // not need to look high-entropy.
        let input = r#"{"token": "abc123def456"}"#;
        let output = redact_output_text(input);
        assert!(!output.contains("abc123def456"), "got: {output}");
        assert!(output.contains("[REDACTED]"), "got: {output}");
    }

    #[test]
    fn test_redact_unquoted_compound_apikey() {
        let input = "apikey = 0Xw9kQrfHXWLOsIqy1jv";
        let output = redact_output_text(input);
        assert!(!output.contains("0Xw9kQrf"), "got: {output}");
        assert!(output.contains("[REDACTED]"), "got: {output}");
    }

    #[test]
    fn test_stoplist_names_not_redacted() {
        let input = "monkey: banana\nbypass: true\nturkey: roasted\nhotkey: ctrl+c";
        let output = redact_output_text(input);
        assert_eq!(output, input, "stoplist names must not be redacted");
    }

    #[test]
    fn test_redact_catchall_json_trailing_comma() {
        let input = r#"  "CS_ENDPOINT_REF": "9c52ab235e556a3f8b1d2e4f6a7c9d0e","#;
        let output = redact_output_text(input);
        assert!(!output.contains("9c52ab235e556a3f"), "got: {output}");
        assert!(output.contains("[REDACTED]"), "got: {output}");
    }

    #[test]
    fn test_no_redact_json_git_sha() {
        let input = r#"  "sha": "0123456789abcdef0123456789abcdef01234567","#;
        let output = redact_output_text(input);
        assert_eq!(output, input, "digest-style names must not be redacted");
    }

    #[test]
    fn test_redact_bare_long_urlsafe_token() {
        // 86-char CloudStack-shaped key with no name context at all (table
        // cell, bare echo).
        let input = "| dpFmM7VLB07kQrfHXWLOsIqy1jvcPUFTzYdaUxKfrKPplbrLPGqrKa2wRIzT3vFTdb3vCgMFuVJErzWa5S3g |";
        let output = redact_output_text(input);
        assert!(!output.contains("dpFmM7VLB07"), "got: {output}");
        assert!(output.contains("[REDACTED]"), "got: {output}");
    }

    #[test]
    fn test_no_redact_long_lowercase_digest() {
        // 64-char lowercase hex (sha256sum output): a content address, not a
        // credential; the mixed-case gate must skip it.
        let input =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  guard.tar.gz";
        let output = redact_output_text(input);
        assert_eq!(output, input);
    }

    #[test]
    fn test_no_redact_long_kebab_slug() {
        let input = "refs/heads/feature/a-very-long-lowercase-branch-name-that-keeps-going-and-going-forever";
        let output = redact_output_text(input);
        assert_eq!(output, input);
    }

    #[test]
    fn test_redact_authorization_bearer_header() {
        let input = "Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz012345";
        let output = redact_output_text(input);
        assert!(!output.contains("ghp_abcdefghij"), "got: {output}");
        assert!(output.contains("[REDACTED]"), "got: {output}");
    }

    #[test]
    fn test_redact_basic_auth_header() {
        let input = "Authorization: Basic dXNlcjpodW50ZXIyaHVudGVyMg==";
        let output = redact_output_text(input);
        assert!(!output.contains("dXNlcjpodW50ZXIy"), "got: {output}");
        assert!(output.contains("[REDACTED]"), "got: {output}");
    }

    #[test]
    fn test_redact_aws_access_key_id() {
        let input = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE";
        let output = redact_output_text(input);
        assert!(!output.contains("AKIAIOSFODNN7EXAMPLE"), "got: {output}");
    }

    #[test]
    fn test_no_redact_bare_key_field_kubernetes_selector() {
        // Bare `key:` is structural metadata (selectors, tolerations), not a
        // credential; it must never be redacted.
        let input = "      - key: kubernetes.io/hostname\n        operator: In\n      - key: node-role.kubernetes.io/control-plane";
        let output = redact_output_text(input);
        assert_eq!(output, input);
    }

    #[test]
    fn test_no_redact_bare_key_field_docker_json() {
        let input = r#"  {"Key": "com.docker.compose.project", "Value": "guard"}"#;
        let output = redact_output_text(input);
        assert_eq!(output, input);
    }

    #[test]
    fn test_no_redact_bare_pass_field() {
        let input = "pass: true\nfail: 0";
        let output = redact_output_text(input);
        assert_eq!(output, input);
    }

    #[test]
    fn test_redact_flow_style_yaml_env_pair() {
        let input = "env: [{name: API_TOKEN, value: abc123def456}]";
        let output = redact_output_text(input);
        assert_eq!(output, "env: [{name: API_TOKEN, value: [REDACTED]}]");
    }

    #[test]
    fn test_redact_flow_style_json_env_pair() {
        let input = r#"{"name": "DB_PASSWORD", "value": "hunter2"}"#;
        let output = redact_output_text(input);
        assert_eq!(output, r#"{"name": "DB_PASSWORD", "value": "[REDACTED]"}"#);
    }

    #[test]
    fn test_no_redact_flow_style_non_secret_pair() {
        let input = "env: [{name: LOG_LEVEL, value: debug}]";
        let output = redact_output_text(input);
        assert_eq!(output, input);
    }

    #[test]
    fn test_redact_quoted_value_with_spaces_no_tail_leak() {
        let input = r#"password: "correct horse battery staple""#;
        let output = redact_output_text(input);
        assert!(!output.contains("horse"), "tail leaked: {output}");
        assert!(!output.contains("staple"), "tail leaked: {output}");
        assert!(output.contains("[REDACTED]"), "got: {output}");
    }

    #[test]
    fn test_redact_quoted_value_with_escaped_quote() {
        let input = r#""password": "ab\"cd efgh""#;
        let output = redact_output_text(input);
        assert!(!output.contains("efgh"), "tail leaked: {output}");
        assert!(output.contains("[REDACTED]"), "got: {output}");
    }

    #[test]
    fn test_redact_url_encoded_separator() {
        let input = "GET /cb?access_token%3Dsupersecretvalue123 HTTP/1.1";
        let output = redact_output_text(input);
        assert!(!output.contains("supersecretvalue123"), "got: {output}");
        assert!(output.contains("[REDACTED]"), "got: {output}");
    }

    #[test]
    fn test_redacted_json_stays_quoted() {
        let input = r#""secretkey": "yVdeOc2BpPsUtozcx13Mp96CyCJPKm9wZycmXgLA0uXSuT""#;
        let output = redact_output_text(input);
        assert!(
            output.contains(r#""secretkey": "[REDACTED]""#),
            "quote style must be preserved, got: {output}"
        );
    }

    #[test]
    fn test_redact_short_header_jwt() {
        // {"alg":"none"} encodes to a 16-char first segment after eyJ.
        let input = "token eyJhbGciOiJub25lIn0.eyJzdWIiOiJhIn0.x1y2z3";
        let output = redact_output_text(input);
        assert!(!output.contains("eyJhbGciOiJub25lIn0"), "got: {output}");
    }

    #[test]
    fn test_no_redact_ansible_status_line() {
        let input = "ok: [agents-k] => {\"changed\": false, \"ping\": \"pong\"}";
        let output = redact_output_text(input);
        assert_eq!(output, input);
    }

    #[test]
    fn test_redact_unterminated_quoted_value() {
        // First line of a quoted multi-line value: open quote, no close.
        let input = r#"password: "unterminated secret value"#;
        let output = redact_output_text(input);
        assert!(!output.contains("unterminated"), "got: {output}");
        assert!(!output.contains("secret value"), "got: {output}");
        assert!(output.contains("[REDACTED]"), "got: {output}");
    }

    #[test]
    fn test_redact_yaml_doubled_single_quote_value() {
        let input = "password: 'ab''cd efgh'";
        let output = redact_output_text(input);
        assert!(!output.contains("efgh"), "tail leaked: {output}");
        assert!(output.contains("[REDACTED]"), "got: {output}");
    }

    #[test]
    fn test_redact_flow_style_reversed_order() {
        let input = "{value: hunter2, name: DB_PASSWORD}";
        let output = redact_output_text(input);
        assert_eq!(output, "{value: [REDACTED], name: DB_PASSWORD}");
    }

    #[test]
    fn test_redact_flow_style_intervening_member() {
        let input = r#"{"name": "DB_PASSWORD", "optional": false, "value": "hunter2"}"#;
        let output = redact_output_text(input);
        assert_eq!(
            output,
            r#"{"name": "DB_PASSWORD", "optional": false, "value": "[REDACTED]"}"#
        );
    }

    #[test]
    fn test_flow_gap_not_hijacked_by_value_in_string_literal() {
        // `value:` inside a sibling member's string literal must not become
        // the correlation target; the REAL value member must be redacted.
        let input = r#"{"name":"DB_PASSWORD","description":"value: decoy","value":"hunter2"}"#;
        let output = redact_output_text(input);
        assert_eq!(
            output,
            r#"{"name":"DB_PASSWORD","description":"value: decoy","value":"[REDACTED]"}"#
        );
    }

    #[test]
    fn test_flow_gap_not_hijacked_by_hyphenated_sibling_key() {
        let input = "{name: DB_PASSWORD, old-value: decoy, value: hunter2}";
        let output = redact_output_text(input);
        assert_eq!(
            output,
            "{name: DB_PASSWORD, old-value: decoy, value: [REDACTED]}"
        );
    }

    #[test]
    fn test_flow_reversed_not_anchored_inside_hyphenated_key() {
        let input = "{old-value: decoy, value: hunter2, name: A_TOKEN}";
        let output = redact_output_text(input);
        assert_eq!(
            output,
            "{old-value: decoy, value: [REDACTED], name: A_TOKEN}"
        );
    }

    #[test]
    fn test_flow_gap_allows_empty_scalar_sibling() {
        // YAML null shorthand between the pair must not break correlation.
        let input = "{name: DB_PASSWORD, optional: , value: hunter2}";
        let output = redact_output_text(input);
        assert_eq!(output, "{name: DB_PASSWORD, optional: , value: [REDACTED]}");
    }

    #[test]
    fn test_no_redact_flow_style_intervening_non_secret() {
        let input = "{name: LOG_LEVEL, optional: false, value: debug}";
        let output = redact_output_text(input);
        assert_eq!(output, input);
    }

    #[test]
    fn test_redaction_is_idempotent() {
        let input = r#"      "apikey": "dpFmM7VLB07-kQrfHXWLOsIqy1jvcPUFTzYdaUxKfrKPplbrLPGqrK_a2wRIzT3vFTdb3vCgMFuVJErzWa5S3g","#;
        let once = redact_output_text(input);
        let twice = redact_output_text(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn test_no_false_positive_short_values() {
        // Short normal values should NOT be redacted
        let input = "HOME=/home/user \nPATH=/usr/bin \n";
        let output = redact_output(input);
        assert_eq!(output, input, "short values should not be redacted");
    }

    #[test]
    fn test_no_false_positive_numeric_values() {
        // Plain numbers shouldn't trigger
        let input = "PORT=8080 \nCOUNT=42 \n";
        let output = redact_output(input);
        assert_eq!(output, input, "numeric values should not be redacted");
    }
}
