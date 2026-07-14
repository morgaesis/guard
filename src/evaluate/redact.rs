//! Pre-LLM redaction of secret-shaped text.

use regex::Regex;
use std::sync::OnceLock;

/// Credential/secret patterns redacted from command text BEFORE it is sent to
/// the LLM. The audit log still sees the original command — redaction is a
/// pre-LLM transform, not an output transform.
///
/// This list holds ONLY the LLM-path delta over the shared engine in
/// `crate::redact` (which `redact_for_llm` runs afterward): command text
/// arrives as one multi-line string, so PEM blocks need a dotall match
/// across lines, where the line-oriented output engine matches the header
/// line only. Named `KEY=value` pairs, provider key prefixes (`sk-*`,
/// `AKIA*`), JWTs, `Bearer`/`Basic` tokens, and high-entropy values are all
/// covered by the shared engine — do not re-add them here.
fn llm_redaction_patterns() -> &'static Vec<(Regex, &'static str)> {
    static P: OnceLock<Vec<(Regex, &str)>> = OnceLock::new();
    P.get_or_init(|| {
        vec![
            // PEM blocks (any type). Dotall via (?s).
            (
                Regex::new(r"(?s)-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----")
                    .expect("valid regex"),
                "[REDACTED]",
            ),
        ]
    })
}

/// Apply pre-LLM redaction to a command string.
///
/// Runs the LLM-specific patterns above, then the full output-redaction
/// engine, so both directions -- text entering a model and command output
/// leaving the daemon -- share one definition of "secret-shaped". Every
/// LLM request body builder routes its untrusted free text through this.
pub fn redact_for_llm(command: &str) -> String {
    let mut result = command.to_string();
    for (pattern, replacement) in llm_redaction_patterns() {
        if pattern.is_match(&result) {
            result = pattern.replace_all(&result, *replacement).to_string();
        }
    }
    crate::redact::redact_output_text(&result)
}

#[cfg(test)]
mod tests {
    use super::redact_for_llm;

    // --- Redaction tests ---

    #[test]
    fn test_redact_for_llm_openai_key() {
        let s = "curl -H 'Authorization: Bearer sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF'";
        let r = redact_for_llm(s);
        assert!(!r.contains("sk-abcdef"), "got: {r}");
        assert!(r.contains("[REDACTED]"));
    }

    #[test]
    fn test_redact_for_llm_openrouter_key() {
        let s = "echo sk-or-v1-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF0123456789";
        let r = redact_for_llm(s);
        assert!(!r.contains("sk-or-v1-abcdef"));
        assert!(r.contains("[REDACTED]"));
    }

    #[test]
    fn test_redact_for_llm_anthropic_key() {
        let s = "export KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF";
        let r = redact_for_llm(s);
        assert!(!r.contains("sk-ant-api03"));
        assert!(r.contains("[REDACTED]"));
    }

    #[test]
    fn test_redact_for_llm_aws_access_key_id() {
        let s = "aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE";
        let r = redact_for_llm(s);
        assert!(!r.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(r.contains("[REDACTED]"));
    }

    #[test]
    fn test_redact_for_llm_aws_secret_with_context() {
        // Only redact the 40-char base64 when paired with a `secret` context
        let s = "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let r = redact_for_llm(s);
        assert!(!r.contains("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
        assert!(r.contains("[REDACTED]"));
    }

    #[test]
    fn test_redact_for_llm_jwt() {
        let s = "curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'";
        let r = redact_for_llm(s);
        assert!(!r.contains("eyJhbGciOi"));
        assert!(r.contains("[REDACTED]"));
    }

    #[test]
    fn test_redact_for_llm_pem_block() {
        let s = "echo '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKC...\n-----END RSA PRIVATE KEY-----' > /tmp/k";
        let r = redact_for_llm(s);
        assert!(!r.contains("MIIEpAIBAAKC"));
        assert!(r.contains("[REDACTED]"));
    }

    #[test]
    fn test_redact_for_llm_bearer_standalone() {
        let s = "Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz012345";
        let r = redact_for_llm(s);
        assert!(!r.contains("ghp_abcdefghij"));
        assert!(r.contains("[REDACTED]"));
    }

    #[test]
    fn test_redact_for_llm_leaves_benign_text_alone() {
        let s = "ls -la /etc/passwd && cat /etc/hostname";
        let r = redact_for_llm(s);
        assert_eq!(r, s);
    }

    #[test]
    fn test_redact_for_llm_idempotent() {
        let s = "curl -H 'Authorization: Bearer sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF'";
        let r1 = redact_for_llm(s);
        let r2 = redact_for_llm(&r1);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_redact_for_llm_json_apikey() {
        // CloudStack/cmk response shape: quoted compound key name, quoted
        // value, trailing comma. Must never reach a model.
        let s = r#"echo '"apikey": "dpFmM7VLB07-kQrfHXWLOsIqy1jvcPUFTzYdaUxKfrKPplbrLPGqrK_a2wRIzT3vFTdb3vCgMFuVJErzWa5S3g",'"#;
        let r = redact_for_llm(s);
        assert!(!r.contains("dpFmM7VLB07"), "got: {r}");
        assert!(r.contains("[REDACTED]"), "got: {r}");
    }

    #[test]
    fn test_redact_for_llm_env_pair() {
        let s = "export MY_TOKEN=abc123secretvalue";
        let r = redact_for_llm(s);
        assert!(!r.contains("abc123secretvalue"), "got: {r}");
        assert!(r.contains("[REDACTED]"), "got: {r}");
    }

    #[test]
    fn test_redact_for_llm_hex_value_catchall() {
        let s = "curl -b 'X_CT0=9c52ab235e556a3f8b1d2e4f6a7c9d0e1f2a3b4c5d6e7f'";
        let r = redact_for_llm(s);
        assert!(!r.contains("9c52ab235e556a3f"), "got: {r}");
        assert!(r.contains("[REDACTED]"), "got: {r}");
    }
}
