//! Pre-LLM redaction of secret-shaped text.

use regex::Regex;
use std::sync::OnceLock;

/// Credential and secret patterns redacted from command text before it is sent
/// to the LLM. Audit and display projections use the shared structured and
/// free-text redactors at their own boundaries.
///
/// This list holds ONLY the LLM-path delta over the shared engine in
/// `crate::redact` (which `redact_for_llm` runs afterward): command text
/// arrives as one multi-line string, so PEM blocks need a dotall match
/// across lines, where the line-oriented output engine matches the header
/// line only. Named `KEY=value` pairs, provider key prefixes (`sk-*`,
/// `AKIA*`), JWTs, `Bearer`/`Basic` tokens, and high-entropy values are all
/// covered by the shared engine - do not re-add them here.
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

    fn repeated(character: char, length: usize) -> String {
        std::iter::repeat_n(character, length).collect()
    }

    fn provider_key(prefix: &str, body_length: usize) -> String {
        format!("{prefix}{}", repeated('A', body_length))
    }

    fn aws_access_key_id() -> String {
        format!("{}{}", ["AK", "IA"].concat(), repeated('A', 16))
    }

    fn jwt() -> String {
        [
            [["e", "y", "J"].concat(), repeated('A', 21)].concat(),
            repeated('B', 32),
            repeated('C', 24),
        ]
        .join(".")
    }

    fn pem_block() -> String {
        let begin = ["-----BEGIN ", "PRIVATE", " KEY-----"].concat();
        let end = ["-----END ", "PRIVATE", " KEY-----"].concat();
        format!("{begin}\n{}\n{end}", repeated('A', 64))
    }

    fn assert_redacted(input: &str) {
        let redacted = redact_for_llm(input);
        assert!(redacted.contains("[REDACTED]"), "got: {redacted}");
        assert!(
            !redacted.contains(input),
            "credential fixture remained visible"
        );
    }

    #[test]
    fn test_redact_for_llm_openai_key() {
        assert_redacted(&provider_key("sk-", 48));
    }

    #[test]
    fn test_redact_for_llm_openrouter_key() {
        assert_redacted(&provider_key("sk-or-v1-", 64));
    }

    #[test]
    fn test_redact_for_llm_anthropic_key() {
        assert_redacted(&provider_key(&["sk-ant-", "api03-"].concat(), 64));
    }

    #[test]
    fn test_redact_for_llm_aws_access_key_id() {
        assert_redacted(&aws_access_key_id());
    }

    #[test]
    fn test_redact_for_llm_aws_secret_with_context() {
        let secret = repeated('A', 40);
        assert_redacted(&format!("aws_secret_access_key={secret}"));
    }

    #[test]
    fn test_redact_for_llm_jwt() {
        assert_redacted(&jwt());
    }

    #[test]
    fn test_redact_for_llm_pem_block() {
        assert_redacted(&pem_block());
    }

    #[test]
    fn test_redact_for_llm_bearer_standalone() {
        assert_redacted(&format!("Bearer {}", repeated('A', 48)));
    }

    #[test]
    fn test_redact_for_llm_leaves_benign_text_alone() {
        let input = "kubectl get pods --namespace production";
        assert_eq!(redact_for_llm(input), input);
    }

    #[test]
    fn test_redact_for_llm_idempotent() {
        let input = format!("token={}", repeated('A', 48));
        let once = redact_for_llm(&input);
        assert_eq!(redact_for_llm(&once), once);
    }

    #[test]
    fn test_redact_for_llm_json_apikey() {
        assert_redacted(&format!(r#"{{"apikey":"{}"}}"#, repeated('A', 40)));
    }

    #[test]
    fn test_redact_for_llm_env_pair() {
        assert_redacted(&format!("API_TOKEN={}", repeated('A', 40)));
    }

    #[test]
    fn test_redact_for_llm_hex_value_catchall() {
        let value = std::iter::repeat_n("ab", 32).collect::<String>();
        assert_redacted(&value);
    }
}
