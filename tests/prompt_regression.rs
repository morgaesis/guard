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
    min_passes: Option<usize>,
    #[serde(default)]
    max_median_risk_deviation: Option<i32>,
    #[serde(default)]
    risk_not_greater_than: Option<String>,
}

fn one_sample() -> usize {
    1
}

impl Case {
    fn required_passes(&self) -> Result<usize, String> {
        if !(1..=9).contains(&self.samples) {
            return Err(format!("case {}: samples must be between 1 and 9", self.id));
        }
        let required = self.min_passes.unwrap_or(self.samples);
        if required <= self.samples / 2 || required > self.samples {
            return Err(format!(
                "case {}: min_passes must be a strict majority, between {} and {}",
                self.id,
                self.samples / 2 + 1,
                self.samples
            ));
        }
        Ok(required)
    }
}

fn load_cases() -> Vec<Case> {
    let yaml = include_str!("prompt_regression_corpus.yaml");
    let cases: Vec<Case> =
        serde_yaml_ng::from_str(yaml).expect("failed to parse prompt_regression_corpus.yaml");
    for case in &cases {
        case.required_passes()
            .unwrap_or_else(|error| panic!("{error}"));
    }
    cases
}

async fn sample_case(evaluator: &Evaluator, case: &Case) -> Vec<EvalResult> {
    case.required_passes()
        .unwrap_or_else(|error| panic!("{error}"));
    let command_line = case.command.join(" ");
    let mut results = Vec::with_capacity(case.samples);
    for sample in 0..case.samples {
        results.push(
            evaluator
                .evaluate_with_reevaluate(&command_line, None, sample > 0)
                .await,
        );
    }
    results
}

fn assess_decisions(case: &Case, results: &[EvalResult]) -> (Vec<String>, Vec<i32>) {
    let required = case
        .required_passes()
        .unwrap_or_else(|error| panic!("{error}"));
    let mut failures = Vec::new();
    let mut risks = Vec::new();
    let mut matched = 0;
    let mut decisions = Vec::new();
    if results.len() != case.samples {
        failures.push(format!("[{}] incomplete sample batch", case.id));
    }
    for (sample, result) in results.iter().enumerate() {
        let decision = match result {
            EvalResult::Allow {
                source: EvalSource::Llm,
                ..
            } => "ALLOW",
            EvalResult::Deny {
                source: EvalSource::Llm,
                ..
            } => "DENY",
            EvalResult::Error(_) => "ERROR",
            _ => "NON_LLM",
        };
        decisions.push(decision);
        if matches!(decision, "ERROR" | "NON_LLM") {
            failures.push(format!(
                "[{} sample {}] expected a fresh LLM decision, got {decision}",
                case.id,
                sample + 1
            ));
        } else if decision == case.expect {
            matched += 1;
        }
        if let Some(risk) = result.risk() {
            risks.push(risk);
        } else if case.max_median_risk_deviation.is_some() || case.risk_not_greater_than.is_some() {
            failures.push(format!(
                "[{} sample {}] response omitted the risk required by this contract",
                case.id,
                sample + 1
            ));
        }
    }
    if matched < required {
        failures.push(format!(
            "[{}] expected {} in at least {required}/{} samples, matched {matched}; decisions={decisions:?}",
            case.id, case.expect, case.samples
        ));
    }
    (failures, risks)
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

fn median_absolute_deviation(values: &[i32]) -> Option<i32> {
    let value_median = median(values)?;
    let deviations = values
        .iter()
        .map(|value| (value - value_median).abs())
        .collect::<Vec<_>>();
    median(&deviations)
}

fn sampling_fixture() -> Case {
    serde_yaml_ng::from_str(
        "id: sampling-fixture\nmode: safe\ncommand: [fixturectl, status]\nexpect: ALLOW\nsamples: 3\nmin_passes: 2",
    )
    .unwrap()
}

fn decision_fixture(allow: bool, source: EvalSource, risk: Option<i32>) -> EvalResult {
    if allow {
        EvalResult::Allow {
            reason: "fixture decision".into(),
            source,
            risk,
            reversibility: None,
        }
    } else {
        EvalResult::Deny {
            reason: "fixture decision".into(),
            source,
            risk,
        }
    }
}

#[test]
fn decision_sampling_requires_a_bounded_strict_majority() {
    let mut case = sampling_fixture();
    for samples in 0..=10 {
        case.samples = samples;
        for required in 0..=11 {
            case.min_passes = Some(required);
            assert_eq!(
                case.required_passes().is_ok(),
                (1..=9).contains(&samples) && required > samples / 2 && required <= samples,
                "samples={samples}, min_passes={required}"
            );
        }
    }
    let default: Case = serde_yaml_ng::from_str(
        "id: default\nmode: safe\ncommand: [fixturectl, status]\nexpect: ALLOW",
    )
    .unwrap();
    assert_eq!(default.samples, 1);
    assert_eq!(default.required_passes().unwrap(), 1);
}

#[test]
fn decision_sampling_tolerates_only_the_configured_outliers() {
    let mut case = sampling_fixture();
    for allow in [true, false] {
        case.expect = if allow { "ALLOW" } else { "DENY" }.into();
        for outlier in 0..3 {
            let results = (0..3)
                .map(|index| {
                    decision_fixture(
                        if index == outlier { !allow } else { allow },
                        EvalSource::Llm,
                        Some(4),
                    )
                })
                .collect::<Vec<_>>();
            case.min_passes = Some(2);
            assert!(assess_decisions(&case, &results).0.is_empty());
            case.min_passes = None;
            let failures = assess_decisions(&case, &results).0;
            assert_eq!(failures.len(), 1);
            assert!(failures[0].contains("matched 2"));
        }
        case.min_passes = Some(2);
        let results = [
            decision_fixture(allow, EvalSource::Llm, Some(4)),
            decision_fixture(!allow, EvalSource::Llm, Some(4)),
            decision_fixture(!allow, EvalSource::Llm, Some(4)),
        ];
        assert_eq!(assess_decisions(&case, &results).0.len(), 1);
        assert!(!assess_decisions(&case, &results[..2]).0.is_empty());
    }
}

#[test]
fn decision_majorities_do_not_mask_errors_sources_or_missing_risks() {
    let mut case = sampling_fixture();
    for invalid in [
        EvalResult::Error("fixture provider failure".into()),
        decision_fixture(true, EvalSource::Cache, Some(1)),
        decision_fixture(true, EvalSource::StaticPolicy, Some(1)),
        decision_fixture(false, EvalSource::LearnedDeny, Some(1)),
    ] {
        let results = [
            decision_fixture(true, EvalSource::Llm, Some(1)),
            decision_fixture(true, EvalSource::Llm, Some(1)),
            invalid,
        ];
        let failures = assess_decisions(&case, &results).0;
        assert_eq!(failures.len(), 1);
        assert!(failures[0].contains("expected a fresh LLM decision"));
    }
    case.max_median_risk_deviation = Some(2);
    let mut results = vec![
        decision_fixture(true, EvalSource::Llm, Some(0)),
        decision_fixture(true, EvalSource::Llm, Some(5)),
        decision_fixture(false, EvalSource::Llm, None),
    ];
    assert!(assess_decisions(&case, &results).0[0].contains("omitted the risk"));
    results[2] = decision_fixture(false, EvalSource::Llm, Some(10));
    let (failures, risks) = assess_decisions(&case, &results);
    assert!(failures.is_empty());
    assert_eq!(risks, [0, 5, 10]);
    assert!(median_absolute_deviation(&risks).unwrap() > case.max_median_risk_deviation.unwrap());
}

#[tokio::test]
async fn decision_sampling_collects_fresh_http_votes_without_early_success() {
    use http_body_util::{BodyExt, Full};
    use hyper::{body::Bytes, server::conn::http1, service::service_fn, Response};
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;

    let case = sampling_fixture();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let evaluator = Evaluator::new(
        EvalConfig::default()
            .mode(PolicyMode::Safe)
            .cache_enabled(false)
            .llm_api_key("fixture-key".into())
            .llm_api_url(format!("http://{}", listener.local_addr().unwrap()))
            .llm_retries(0)
            .llm_timeout_secs(2),
    )
    .unwrap();
    let server = async {
        for decision in ["APPROVE", "APPROVE", "DENY"] {
            let (stream, _) = listener.accept().await.unwrap();
            http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(
                        move |request: hyper::Request<hyper::body::Incoming>| async move {
                            let body = request.into_body().collect().await.unwrap().to_bytes();
                            let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
                            assert!(request["messages"].as_array().is_some());
                            let body = serde_json::json!({
                                "choices": [{"message": {"tool_calls": [{
                                    "id": "fixture",
                                    "type": "function",
                                    "function": {
                                        "name": "decide",
                                        "arguments": serde_json::json!({
                                            "decision": decision,
                                            "reason": "fixture decision",
                                            "risk": 1
                                        }).to_string()
                                    }
                                }]}}]
                            })
                            .to_string();
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .header("Connection", "close")
                                    .body(Full::new(Bytes::from(body)))
                                    .unwrap(),
                            )
                        },
                    ),
                )
                .await
                .unwrap();
        }
    };
    let (_, results) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(server, sample_case(&evaluator, &case))
    })
    .await
    .expect("bounded sampling must collect exactly three provider responses");
    assert_eq!(results.len(), 3);
    assert!(results[0].is_allow() && results[1].is_allow() && results[2].is_deny());
    assert!(assess_decisions(&case, &results).0.is_empty());
}

#[test]
fn risk_stability_tolerates_one_outlier_but_rejects_dispersion() {
    assert_eq!(median_absolute_deviation(&[4, 4, 7]), Some(0));
    assert_eq!(median_absolute_deviation(&[6, 7, 4]), Some(1));
    assert_eq!(median_absolute_deviation(&[0, 5, 10]), Some(5));
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
        if let Some(deviation) = case.max_median_risk_deviation {
            assert!(
                (0..=10).contains(&deviation),
                "case {} has invalid max_median_risk_deviation {deviation}",
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
    let cases = load_cases();
    assert!(!cases.is_empty(), "corpus should not be empty");
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

    let mut failures = Vec::new();
    let mut observed_risks = HashMap::<String, Vec<i32>>::new();
    for case in &cases {
        let mode = PolicyMode::parse(&case.mode)
            .unwrap_or_else(|| panic!("case {}: unknown mode '{}'", case.id, case.mode));
        let mut eval_config = EvalConfig::default()
            .mode(mode)
            .llm_enabled(true)
            .cache_enabled(false)
            .llm_api_key(api_key.clone());
        // Honor the daemon's model/effort env vars so the corpus can be run
        // against a candidate model before changing the shipped default.
        if let Ok(model) = std::env::var("GUARD_LLM_MODEL") {
            if !model.is_empty() {
                eval_config = eval_config.llm_model(model);
            }
        }
        if let Ok(effort) = std::env::var("GUARD_LLM_REASONING_EFFORT") {
            if !effort.is_empty() {
                eval_config = eval_config.llm_reasoning_effort(effort);
            }
        }
        let evaluator = Evaluator::new(eval_config)
            .unwrap_or_else(|e| panic!("case {}: failed to build evaluator: {e}", case.id));

        let results = sample_case(&evaluator, case).await;
        let (case_failures, risks) = assess_decisions(case, &results);
        failures.extend(case_failures);
        observed_risks.insert(case.id.clone(), risks);
    }

    for case in &cases {
        let risks = observed_risks
            .get(&case.id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        if let Some(max_deviation) = case.max_median_risk_deviation {
            if risks.len() == case.samples {
                let median_deviation = median_absolute_deviation(risks).unwrap();
                if median_deviation > max_deviation {
                    failures.push(format!(
                        "[{}] risk samples {risks:?} have median absolute deviation {median_deviation}, exceeding {max_deviation}",
                        case.id,
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
