//! Verb-promotion confirmation: LLM vetting and naming of mechanically derived verb templates.

use super::client::truncate;
use super::redact::redact_for_llm;
use super::Evaluator;
use crate::gating::allow_promotion::{self, AllowPromotionOutcome};
use crate::gating::verb::{validate_auto_promoted_verb_safety, ParamSpec, Verb, VerbCommand};
use crate::gating::Reversibility;
use anyhow::{bail, Result};
use std::collections::BTreeMap;
use std::time::Duration;

/// System prompt for verb-promotion confirmation: the daemon has already
/// derived a candidate verb's binary, args template, parameter patterns, and
/// consequence class mechanically from repeated approvals -- every parameter
/// pattern is a plain alternation of the exact values actually observed, not
/// a regex you write. Your only job is to name it, describe it, judge
/// whether generalizing over the given varying positions is coherent for
/// this binary, and, for a recoverable shape, propose a structured revert.
pub(super) const SYSTEM_PROMPT_CONFIRM_VERB_PROMOTION: &str = "A guard daemon derived a candidate verb \
template mechanically from repeated LLM approvals of the same shape of command. The binary, the \
argv template, every parameter's exact allowed values, and the consequence class are already fixed \
and will NOT be changed by your answer -- you are not being asked to invent or widen a pattern. \
Decide only: (1) confident=true only if generalizing over the given varying argument position(s) is \
genuinely safe and coherent for this specific binary and subcommand regardless of which of the \
already-enumerated values is used (decline, confident=false, if the position could plausibly carry \
materially different risk depending on which enumerated value is present, e.g. a resource name where \
one value happens to be more sensitive than another); (2) a short kebab-case name and one-line \
description for the verb; (3) if -- and only if -- the shape is classified recoverable, a structured \
revert command (binary + argv template using the SAME {param} placeholders already in the forward \
template) that would undo the forward command's effect; leave revert unset for a reversible shape. \
Always answer by calling confirm_verb_promotion.";

impl Evaluator {
    pub fn allow_promotion_enabled(&self) -> bool {
        self.allow_promotion.is_some()
    }

    pub async fn allow_promotion_observation_count(&self) -> usize {
        match &self.allow_promotion {
            Some(store) => store.read().await.observation_count(),
            None => 0,
        }
    }

    /// Bookkeeping only: record one LLM approval against the auto-verb-
    /// promotion observation store (`gating::allow_promotion`). Returns an
    /// outcome flagging whether this bucket just crossed the promotion
    /// threshold; the caller (`server::maybe_promote_allow_verb`) decides
    /// whether to act on it via `try_confirm_verb_promotion`. Never grants or
    /// matches anything itself -- only appending the result to the verb
    /// catalog does that, which lives outside the `Evaluator`.
    pub async fn record_learned_approval_for_promotion(
        &self,
        binary: &str,
        args: &[String],
        command: &str,
        risk: Option<i32>,
        reversibility: Option<Reversibility>,
        reason: &str,
    ) -> Result<Option<AllowPromotionOutcome>> {
        let Some(store) = &self.allow_promotion else {
            return Ok(None);
        };
        let mut guard = store.write().await;
        guard.record_approval(binary, args, command, risk, reversibility, reason)
    }

    /// Permanently exclude `outcome`'s bucket from further promotion
    /// attempts. Called by `server::maybe_promote_allow_verb` once it has a
    /// definitive verdict (promoted, or failed for a reason the same
    /// evidence will reproduce identically) -- never for a merely-not-
    /// confident-yet or transiently-failed attempt, both of which should
    /// keep retrying. A no-op if promotion is disabled.
    pub async fn mark_allow_promotion_resolved(
        &self,
        outcome: &AllowPromotionOutcome,
    ) -> Result<()> {
        let Some(store) = &self.allow_promotion else {
            return Ok(());
        };
        let mut guard = store.write().await;
        guard.mark_resolved(
            &outcome.service,
            &outcome.binary,
            &outcome.subcommand,
            outcome.arity,
        )
    }

    /// Attempt to confirm and build a promotable verb from an outcome flagged
    /// `ready_to_synthesize`. The forward shape (binary, args template,
    /// parameter patterns, consequence class) is derived entirely from
    /// evidence in `gating::allow_promotion`, never from the model. A fully
    /// literal bucket (no varying position) needs no model judgment and is
    /// built directly. Otherwise the model is consulted once, purely to name
    /// the verb, write its description, confirm the generalization is
    /// coherent for this binary, and -- for a `Recoverable` outcome -- propose
    /// a revert. The result is re-validated from scratch by
    /// `validate_auto_promoted_verb_safety` regardless of what the model
    /// returned. Returns `Ok(None)` when the model declined or nothing
    /// changed (not an error: the bucket keeps accumulating for next time).
    pub async fn try_confirm_verb_promotion(
        &self,
        outcome: &AllowPromotionOutcome,
    ) -> Result<Option<Verb>> {
        let Some(slots) = allow_promotion::derive_template(&outcome.samples) else {
            return Ok(None);
        };
        let (args, params) = allow_promotion::build_args_and_params(&slots);
        let promotion_stamp = self.verb_promotion_stamp.clone();

        let verb = if allow_promotion::is_fully_literal(&slots) {
            let name = allow_promotion::choose_verb_name(
                None,
                &outcome.service,
                &outcome.subcommand,
                args.len(),
            );
            let description = format!(
                "Auto-promoted after {} identical, {} LLM approvals of `{} {}`.",
                outcome.approvals,
                outcome.class.as_str(),
                outcome.binary,
                outcome.subcommand
            );
            let evidence = format!(
                "auto-promoted: {} approvals, no varying argument position, max observed risk {}, \
                 last reason: {}",
                outcome.approvals, outcome.max_risk_seen, outcome.reason
            );
            allow_promotion::build_candidate_verb(
                &outcome.binary,
                name,
                description,
                args,
                params,
                outcome.class,
                None,
                evidence,
                promotion_stamp,
            )
        } else {
            if !self.llm_config.enabled {
                return Ok(None);
            }
            let Some(api_key) = self.llm_config.api_key.clone().filter(|k| !k.is_empty()) else {
                return Ok(None);
            };
            let api_url = self.llm_config.api_url();
            let model = self.llm_config.model();
            let body = build_confirm_verb_promotion_body(
                &model,
                &outcome.binary,
                &outcome.subcommand,
                &args,
                &params,
                outcome.class,
                &outcome.samples,
                &outcome.reason,
            );

            let attempts = self.llm_config.effective_retries().saturating_add(1).max(2);
            let mut confirmed = None;
            let mut last_err = String::new();
            for attempt in 1..=attempts {
                match self
                    .confirm_verb_promotion_once(&api_key, &api_url, &body)
                    .await
                {
                    Ok(result) => {
                        confirmed = result;
                        break;
                    }
                    Err(e) => {
                        last_err = e.to_string();
                        tracing::warn!(
                            "verb-promotion confirmation attempt {}/{} failed: {}",
                            attempt,
                            attempts,
                            last_err
                        );
                        if attempt < attempts {
                            tokio::time::sleep(Duration::from_millis(400)).await;
                        }
                    }
                }
            }
            let Some((name, description, revert, model_evidence)) = confirmed else {
                if !last_err.is_empty() {
                    tracing::warn!(
                        "verb-promotion confirmation failed after {attempts} attempts: {last_err}"
                    );
                }
                return Ok(None);
            };
            if outcome.class == Reversibility::Recoverable && revert.is_none() {
                // The model didn't propose a revert for a recoverable shape;
                // nothing safe to promote without one.
                return Ok(None);
            }
            // A reversible shape has no use for a revert (it executes
            // immediately regardless -- see `decide_gate`); discard one if
            // the model attached one anyway rather than trust it followed
            // the "leave revert unset" instruction.
            let revert = if outcome.class == Reversibility::Reversible {
                None
            } else {
                revert
            };
            let name = allow_promotion::choose_verb_name(
                Some(&name),
                &outcome.service,
                &outcome.subcommand,
                args.len(),
            );
            let evidence = format!(
                "{model_evidence} (max observed risk {})",
                outcome.max_risk_seen
            );
            allow_promotion::build_candidate_verb(
                &outcome.binary,
                name,
                description,
                args,
                params,
                outcome.class,
                revert,
                evidence,
                promotion_stamp,
            )
        };

        validate_auto_promoted_verb_safety(&verb, &outcome.samples)?;
        Ok(Some(verb))
    }

    async fn confirm_verb_promotion_once(
        &self,
        api_key: &str,
        api_url: &str,
        body: &serde_json::Value,
    ) -> Result<Option<(String, String, Option<VerbCommand>, String)>> {
        let response = self
            .http_client
            .post(api_url)
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(body)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("transport error: {e}"))?;
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| anyhow::anyhow!("read error: {e}"))?;
        if !status.is_success() {
            bail!("LLM call failed ({}): {}", status, truncate(&text, 200));
        }
        let parsed: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| anyhow::anyhow!("non-JSON response: {e}"))?;
        let args_str = parsed
            .pointer("/choices/0/message/tool_calls/0/function/arguments")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!("model did not return a confirm_verb_promotion tool call")
            })?;
        let args: serde_json::Value = serde_json::from_str(args_str)
            .map_err(|e| anyhow::anyhow!("tool-call arguments were not valid JSON: {e}"))?;
        let confident = args
            .get("confident")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !confident {
            return Ok(None);
        }
        let name = args
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let description = args
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let evidence = args
            .get("evidence")
            .and_then(|v| v.as_str())
            .unwrap_or("auto-promoted from repeated approvals")
            .to_string();
        let revert = args.get("revert").and_then(|r| {
            let binary = r.get("binary")?.as_str()?.to_string();
            let revert_args = r
                .get("args")
                .and_then(|a| a.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            Some(VerbCommand {
                binary,
                args: revert_args,
            })
        });
        Ok(Some((name, description, revert, evidence)))
    }
}

#[allow(clippy::too_many_arguments)]
fn build_confirm_verb_promotion_body(
    model: &str,
    binary: &str,
    subcommand: &str,
    args: &[String],
    params: &BTreeMap<String, ParamSpec>,
    consequence: Reversibility,
    samples: &[Vec<String>],
    last_reason: &str,
) -> serde_json::Value {
    let params_desc: String = params
        .iter()
        .map(|(name, spec)| format!("- {{{name}}}: allowed values pattern {}", spec.pattern))
        .collect::<Vec<_>>()
        .join("\n");
    let samples_desc: String = samples
        .iter()
        .map(|s| format!("- {binary} {}", s.join(" ")))
        .collect::<Vec<_>>()
        .join("\n");
    let user = format!(
        "Binary: {binary}\nSubcommand: {subcommand}\nDerived argv template: {binary} {}\n\
         Parameters (already fixed, for your information only):\n{params_desc}\n\
         Consequence class (already fixed): {}\nMost recent approval reason: {last_reason}\n\n\
         Approved example commands this template was derived from:\n{samples_desc}",
        args.join(" "),
        consequence.as_str()
    );
    let user = redact_for_llm(&user);
    serde_json::json!({
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT_CONFIRM_VERB_PROMOTION},
            {"role": "user", "content": user},
        ],
        "tools": [{
            "type": "function",
            "function": {
                "name": "confirm_verb_promotion",
                "description": "Confirm (or decline) promoting this mechanically-derived verb template, and name it.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "confident": {"type": "boolean", "description": "true only if generalizing over the given varying position(s) is safe for this binary regardless of which enumerated value is used"},
                        "name": {"type": "string", "description": "short kebab-case verb name"},
                        "description": {"type": "string"},
                        "revert": {
                            "type": "object",
                            "properties": {
                                "binary": {"type": "string"},
                                "args": {"type": "array", "items": {"type": "string"}}
                            },
                            "description": "required only when the consequence class is recoverable: the structured inverse, reusing the same {param} placeholders"
                        },
                        "evidence": {"type": "string", "description": "one sentence justifying this decision"}
                    },
                    "required": ["confident", "evidence"]
                }
            }
        }],
        "tool_choice": {"type": "function", "function": {"name": "confirm_verb_promotion"}}
    })
}

#[cfg(test)]
mod tests {
    use crate::evaluate::{EvalConfig, Evaluator};
    use crate::gating::allow_promotion::AllowPromotionOutcome;
    use crate::gating::Reversibility;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    #[tokio::test]
    async fn allow_promotion_observation_without_store_is_noop() {
        let evaluator = Evaluator::new(EvalConfig::default()).unwrap();
        assert!(!evaluator.allow_promotion_enabled());
        let outcome = evaluator
            .record_learned_approval_for_promotion(
                "kubectl",
                &["get".into(), "pods".into()],
                "kubectl get pods",
                Some(1),
                Some(Reversibility::Reversible),
                "ok",
            )
            .await
            .unwrap();
        assert!(outcome.is_none());
    }

    #[tokio::test]
    async fn mark_allow_promotion_resolved_without_store_is_noop() {
        let evaluator = Evaluator::new(EvalConfig::default()).unwrap();
        let outcome = allow_promotion_outcome(
            vec![vec!["get".to_string(), "pods".to_string()]],
            Reversibility::Reversible,
        );
        // No store configured: must not error just because there is nothing
        // to mark.
        evaluator
            .mark_allow_promotion_resolved(&outcome)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn mark_allow_promotion_resolved_permanently_excludes_the_bucket() {
        use crate::gating::allow_promotion::{AllowPromotionConfig, AllowPromotionStore};

        let temp = tempfile::tempdir().unwrap();
        let mut config = AllowPromotionConfig::new(temp.path().join("allow.yaml"));
        config.min_approvals = 2;
        let store = AllowPromotionStore::load(config).unwrap();
        let evaluator = Evaluator::new(
            EvalConfig::default()
                .llm_enabled(false)
                .allow_promotion(Arc::new(RwLock::new(store))),
        )
        .unwrap();

        let args = vec!["get".to_string(), "pods".to_string()];
        evaluator
            .record_learned_approval_for_promotion(
                "kubectl",
                &args,
                "kubectl get pods",
                Some(1),
                Some(Reversibility::Reversible),
                "ok",
            )
            .await
            .unwrap();
        let outcome = evaluator
            .record_learned_approval_for_promotion(
                "kubectl",
                &args,
                "kubectl get pods",
                Some(1),
                Some(Reversibility::Reversible),
                "ok",
            )
            .await
            .unwrap()
            .expect("second approval should produce an outcome");
        assert!(outcome.ready_to_synthesize);

        evaluator
            .mark_allow_promotion_resolved(&outcome)
            .await
            .unwrap();

        // A resolved bucket must never fire again, no matter how many more
        // approvals of the identical shape arrive.
        for _ in 0..5 {
            let outcome = evaluator
                .record_learned_approval_for_promotion(
                    "kubectl",
                    &args,
                    "kubectl get pods",
                    Some(1),
                    Some(Reversibility::Reversible),
                    "ok",
                )
                .await
                .unwrap()
                .unwrap();
            assert!(!outcome.ready_to_synthesize);
        }
    }

    fn allow_promotion_outcome(
        samples: Vec<Vec<String>>,
        class: Reversibility,
    ) -> AllowPromotionOutcome {
        let arity = samples.first().map(|s| s.len()).unwrap_or(0);
        AllowPromotionOutcome {
            service: "kubectl".to_string(),
            binary: "kubectl".to_string(),
            subcommand: "get".to_string(),
            arity,
            approvals: 5,
            required_approvals: 5,
            ready_to_synthesize: true,
            samples,
            class,
            max_risk_seen: 1,
            reason: "read-only".to_string(),
        }
    }

    #[tokio::test]
    async fn try_confirm_verb_promotion_literal_shape_needs_no_llm() {
        // No API key configured: if this needed an LLM call it would fail.
        // A fully literal bucket (identical evidence every time) must not
        // even attempt one.
        let evaluator = Evaluator::new(EvalConfig::default().llm_enabled(false)).unwrap();
        let outcome = allow_promotion_outcome(
            vec![
                vec!["get".to_string(), "pods".to_string()],
                vec!["get".to_string(), "pods".to_string()],
            ],
            Reversibility::Reversible,
        );
        let verb = evaluator
            .try_confirm_verb_promotion(&outcome)
            .await
            .unwrap()
            .expect("a literal shape should promote without any LLM call");
        assert!(verb.trusted);
        assert!(verb.auto_promoted);
        assert_eq!(verb.binary, "kubectl");
        assert_eq!(verb.args, vec!["get".to_string(), "pods".to_string()]);
        assert!(verb.params.is_empty());
        assert_eq!(
            verb.promotion_stamp.as_deref(),
            Some(evaluator.verb_promotion_stamp())
        );
    }

    #[tokio::test]
    async fn try_confirm_verb_promotion_parameterized_without_llm_key_declines() {
        // A varying position needs the model's judgment; with no API key
        // configured, this must decline gracefully (Ok(None)), not error.
        let evaluator = Evaluator::new(EvalConfig::default()).unwrap();
        let outcome = allow_promotion_outcome(
            vec![
                vec![
                    "get".to_string(),
                    "pods".to_string(),
                    "-n".to_string(),
                    "foo".to_string(),
                ],
                vec![
                    "get".to_string(),
                    "pods".to_string(),
                    "-n".to_string(),
                    "bar".to_string(),
                ],
            ],
            Reversibility::Reversible,
        );
        let result = evaluator
            .try_confirm_verb_promotion(&outcome)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn try_confirm_verb_promotion_recoverable_literal_without_revert_is_rejected() {
        // The literal-shape path never asks the model for a revert, so a
        // recoverable outcome with no varying position (and hence no chance
        // to obtain one) must fail the safety gate rather than promote an
        // unrevertible recoverable verb.
        let evaluator = Evaluator::new(EvalConfig::default().llm_enabled(false)).unwrap();
        let outcome = allow_promotion_outcome(
            vec![
                vec!["restart".to_string(), "nginx".to_string()],
                vec!["restart".to_string(), "nginx".to_string()],
            ],
            Reversibility::Recoverable,
        );
        let result = evaluator.try_confirm_verb_promotion(&outcome).await;
        assert!(
            result.is_err(),
            "a recoverable verb without a revert must be rejected, got {result:?}"
        );
    }
}
