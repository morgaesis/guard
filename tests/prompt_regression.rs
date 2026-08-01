//! Runs `tests/prompt_regression_corpus.yaml` against a real LLM call.
//!
//! Requires a working LLM key (`GUARD_LLM_API_KEY` or `OPENROUTER_API_KEY`):
//! these cases exercise the system prompt itself, not the deterministic
//! static-policy path that `policy_tests.rs` covers offline. Skips (without
//! failing) when no key is configured, so `cargo test` stays green in
//! environments without one; set the env var to get full coverage,
//! including the prompt-injection-resistance cases derived from
//! arXiv:2603.15714.
//!
//! Set `GUARD_PROMPT_REGRESSION=required` to turn the missing-key skip into
//! a hard failure. CI sets this so a lost or misconfigured secret surfaces
//! as a red run instead of a silent skip.

use guard::evaluate::{EvalConfig, EvalResult, EvalSource, Evaluator};
use guard::policy::PolicyMode;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    mode: String,
    command: Vec<String>,
    expect: String,
    #[serde(default)]
    #[allow(dead_code)]
    reason: String,
    #[serde(default = "one_sample")]
    samples: usize,
    #[serde(default)]
    max_risk_spread: Option<i32>,
    #[serde(default)]
    risk_not_greater_than: Option<String>,
}

fn one_sample() -> usize {
    1
}

fn load_cases() -> Vec<Case> {
    let yaml = include_str!("prompt_regression_corpus.yaml");
    serde_yaml_ng::from_str(yaml).expect("failed to parse prompt_regression_corpus.yaml")
}

fn resolve_api_key() -> Option<String> {
    std::env::var("GUARD_LLM_API_KEY")
        .ok()
        .or_else(|| std::env::var("OPENROUTER_API_KEY").ok())
        .filter(|k| !k.is_empty())
}

fn median(values: &[i32]) -> Option<i32> {
    if values.is_empty() {
        return None;
    }
    let mut ordered = values.to_vec();
    ordered.sort_unstable();
    Some(ordered[ordered.len() / 2])
}

#[test]
fn prompt_regression_risk_contracts_are_well_formed() {
    let cases = load_cases();
    let mut ids = HashSet::new();
    for case in &cases {
        assert!(
            ids.insert(case.id.as_str()),
            "duplicate case id: {}",
            case.id
        );
        assert!(case.samples > 0, "case {} has no samples", case.id);
        if let Some(spread) = case.max_risk_spread {
            assert!(
                (0..=10).contains(&spread),
                "case {} has invalid max_risk_spread {spread}",
                case.id
            );
        }
    }
    for case in &cases {
        if let Some(reference) = &case.risk_not_greater_than {
            let referenced = cases
                .iter()
                .find(|candidate| candidate.id == *reference)
                .unwrap_or_else(|| {
                    panic!(
                        "case {} references missing risk baseline {reference}",
                        case.id
                    )
                });
            assert_eq!(
                case.mode, referenced.mode,
                "risk comparison {} crosses policy modes",
                case.id
            );
        }
    }
}

#[tokio::test]
async fn prompt_regression_corpus_matches_expected_decisions() {
    let Some(api_key) = resolve_api_key() else {
        let required = std::env::var("GUARD_PROMPT_REGRESSION").is_ok_and(|v| v == "required");
        assert!(
            !required,
            "GUARD_PROMPT_REGRESSION=required but no GUARD_LLM_API_KEY/OPENROUTER_API_KEY \
             is configured; the prompt regression corpus cannot run"
        );
        eprintln!(
            "skipping prompt_regression_corpus_matches_expected_decisions: \
             no GUARD_LLM_API_KEY/OPENROUTER_API_KEY configured"
        );
        return;
    };

    let cases = load_cases();
    assert!(!cases.is_empty(), "corpus should not be empty");

    let mut failures = Vec::new();
    let mut observed_risks = HashMap::<String, Vec<i32>>::new();
    for case in &cases {
        let mode = PolicyMode::parse(&case.mode)
            .unwrap_or_else(|| panic!("case {}: unknown mode '{}'", case.id, case.mode));
        let evaluator = Evaluator::new(
            EvalConfig::default()
                .mode(mode)
                .llm_enabled(true)
                .cache_enabled(false)
                .llm_api_key(api_key.clone()),
        )
        .unwrap_or_else(|e| panic!("case {}: failed to build evaluator: {e}", case.id));

        let command_line = case.command.join(" ");
        for sample in 0..case.samples {
            let result = evaluator
                .evaluate_with_reevaluate(&command_line, None, sample > 0)
                .await;

            let matched = matches!(
                (case.expect.as_str(), &result),
                (
                    "ALLOW",
                    EvalResult::Allow {
                        source: EvalSource::Llm,
                        ..
                    }
                ) | (
                    "DENY",
                    EvalResult::Deny {
                        source: EvalSource::Llm,
                        ..
                    }
                )
            );

            if !matched {
                failures.push(format!(
                    "[{} sample {}] {}: expected {}, got {:?}",
                    case.id,
                    sample + 1,
                    command_line,
                    case.expect,
                    result
                ));
            }
            if let Some(risk) = result.risk() {
                observed_risks
                    .entry(case.id.clone())
                    .or_default()
                    .push(risk);
            } else if case.max_risk_spread.is_some() || case.risk_not_greater_than.is_some() {
                failures.push(format!(
                    "[{} sample {}] response omitted the risk required by this contract",
                    case.id,
                    sample + 1
                ));
            }
        }
    }

    for case in &cases {
        let risks = observed_risks
            .get(&case.id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        if let Some(max_spread) = case.max_risk_spread {
            if risks.len() == case.samples {
                let low = risks.iter().min().copied().unwrap();
                let high = risks.iter().max().copied().unwrap();
                if high - low > max_spread {
                    failures.push(format!(
                        "[{}] risk samples {risks:?} exceed maximum spread {max_spread}",
                        case.id
                    ));
                }
            }
        }
        if let Some(reference) = &case.risk_not_greater_than {
            let reference_risks = observed_risks
                .get(reference)
                .map(Vec::as_slice)
                .unwrap_or_default();
            if let (Some(actual), Some(baseline)) = (median(risks), median(reference_risks)) {
                if actual > baseline {
                    failures.push(format!(
                        "[{}] median risk {actual} exceeds {} median risk {baseline}; samples={risks:?}, baseline_samples={reference_risks:?}",
                        case.id, reference
                    ));
                }
            } else {
                failures.push(format!(
                    "[{}] risk comparison with {reference} lacks complete risk observations",
                    case.id
                ));
            }
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
