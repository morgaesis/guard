//! Runs `tests/prompt_regression_corpus.yaml` against a real LLM call.
//!
//! Requires a working LLM key (`GUARD_LLM_API_KEY` or `OPENROUTER_API_KEY`):
//! these cases exercise the system prompt itself, not the deterministic
//! static-policy path that `policy_tests.rs` covers offline. Skips (without
//! failing) when no key is configured, so `cargo test` stays green in
//! environments without one; set the env var to get full coverage,
//! including the prompt-injection-resistance cases derived from
//! arXiv:2603.15714.

use guard::evaluate::{EvalConfig, EvalResult, Evaluator};
use guard::policy::PolicyMode;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    mode: String,
    command: Vec<String>,
    expect: String,
    #[serde(default)]
    #[allow(dead_code)]
    reason: String,
}

fn load_cases() -> Vec<Case> {
    let yaml = include_str!("prompt_regression_corpus.yaml");
    serde_yaml::from_str(yaml).expect("failed to parse prompt_regression_corpus.yaml")
}

fn resolve_api_key() -> Option<String> {
    std::env::var("GUARD_LLM_API_KEY")
        .ok()
        .or_else(|| std::env::var("OPENROUTER_API_KEY").ok())
        .filter(|k| !k.is_empty())
}

#[tokio::test]
async fn prompt_regression_corpus_matches_expected_decisions() {
    let Some(api_key) = resolve_api_key() else {
        eprintln!(
            "skipping prompt_regression_corpus_matches_expected_decisions: \
             no GUARD_LLM_API_KEY/OPENROUTER_API_KEY configured"
        );
        return;
    };

    let cases = load_cases();
    assert!(!cases.is_empty(), "corpus should not be empty");

    let mut failures = Vec::new();
    for case in &cases {
        let mode = PolicyMode::parse(&case.mode)
            .unwrap_or_else(|| panic!("case {}: unknown mode '{}'", case.id, case.mode));
        let evaluator = Evaluator::new(
            EvalConfig::default()
                .mode(mode)
                .llm_enabled(true)
                .llm_api_key(api_key.clone()),
        )
        .unwrap_or_else(|e| panic!("case {}: failed to build evaluator: {e}", case.id));

        let command_line = case.command.join(" ");
        let result = evaluator.evaluate(&command_line).await;

        let matched = matches!(
            (case.expect.as_str(), &result),
            ("ALLOW", EvalResult::Allow { .. }) | ("DENY", EvalResult::Deny { .. })
        );

        if !matched {
            failures.push(format!("[{}] {}: expected {}, got {:?}", case.id, command_line, case.expect, result));
        }
    }

    assert!(
        failures.is_empty(),
        "\nprompt regression corpus failures ({}/{}):\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}
