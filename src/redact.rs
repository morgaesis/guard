use regex::Regex;
use std::sync::OnceLock;

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
            // JWT tokens (eyJ header)
            (
                Regex::new(r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").unwrap(),
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
/// length fails the test with negligible probability.
fn redact_bare_long_tokens(text: &str) -> String {
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

/// Name-based secret redaction: a key name ending in a secret-bearing word,
/// followed by `=` or `:`, has its value redacted regardless of the value's
/// shape. Handles unquoted env/CLI pairs (`MY_TOKEN=x`, `--api-key=x`), YAML
/// (`password: x`), and JSON with quoted names and values
/// (`"apikey": "x",` -- the shape CloudStack/cmk responses use).
fn named_secret_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(
            r#"(?i)(["']?)([A-Za-z0-9_.-]*(?:TOKEN|KEY|SECRET|PASSWORD|PASSWD|PASSPHRASE|PASS|CREDENTIALS?|CREDS?|AUTHORIZATION|AUTH|BEARER))(["']?\s*[=:]\s*["']?)([^"'\s}{,]+)"#,
        )
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

fn redact_named_secrets(text: &str) -> String {
    named_secret_pattern()
        .replace_all(text, |caps: &regex::Captures| {
            let name = &caps[2];
            if NAMED_SECRET_STOPLIST
                .iter()
                .any(|stop| name.eq_ignore_ascii_case(stop))
            {
                caps[0].to_string()
            } else {
                format!("{}{}{}[REDACTED]", &caps[1], &caps[2], &caps[3])
            }
        })
        .to_string()
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
        result = pattern.replace_all(&result, *replacement).to_string();
    }

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
        if secret.len() >= 8 && !secret.is_empty() {
            result = result.replace(*secret, "[REDACTED]");
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

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
