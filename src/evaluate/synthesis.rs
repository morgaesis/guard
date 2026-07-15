//! Auxiliary LLM synthesis: verbs from operator prose and learned deny shapes.

use super::client::truncate;
use super::redact::redact_for_llm;
use super::Evaluator;
use crate::gating::deny_shape::DenyLearningOutcome;
use crate::gating::verb::Verb;
use anyhow::{bail, Result};
use std::time::Duration;

/// System guidance for `guard verb create --prompt` synthesis: turn operator
/// prose into exactly ONE least-privilege, typed verb. Conservative defaults
/// (read-only/reversible, narrow anchored patterns, no flag or shell
/// metacharacter reinterpretation).
const SYSTEM_PROMPT_CREATE_VERB: &str = r#"You translate an operator's plain-language request into exactly ONE guard verb:
a typed, least-privilege, fixed-binary command template an AI agent may invoke
instead of raw shell. Always answer by calling the create_verb function.

Rules:
- Pick the single most specific operation that satisfies the request.
- Every parameter `pattern` MUST be a fully anchored regex (^...$) and as NARROW
  as possible. If the request names specific resources (a VM id, a network, a
  profile), pin the pattern to exactly those values, e.g. ^(id-a|id-b)$ - never
  allow arbitrary values when specific ones were named.
- Use {param} placeholders in args; each renders as exactly ONE argv element.
  Never put shell operators, pipes, redirects, spaces-as-separators, or a second
  command in one arg. Never use sh -c / cmd /c / -c style interpreters.
- allow_dash MUST be false unless a value is legitimately a leading-dash token.
- consequence: "reversible" for read-only/list/get/idempotent; "recoverable"
  ONLY for a mutation with a clean structured inverse, and then ALSO provide a
  `revert`; "irreversible" for destruction or anything lacking a clean inverse.
- trusted: true only for clearly safe read-only operations; otherwise false so
  the LLM still evaluates the rendered command.
- Do not invent flags that print or redirect credentials or configuration.
- evidence: one or two sentences justifying the binary, params, patterns, and
  class as least-privilege."#;

impl Evaluator {
    pub fn deny_learning_enabled(&self) -> bool {
        self.deny_shapes.is_some()
    }

    pub async fn deny_shape_count(&self) -> usize {
        match &self.deny_shapes {
            Some(store) => store.read().await.shape_count(),
            None => 0,
        }
    }

    /// Bookkeeping only: record one LLM denial. Returns an outcome flagging
    /// whether this bucket just crossed the synthesis threshold; the caller
    /// (`server::maybe_promote_deny_shape`) decides whether to act on it via
    /// `try_promote_deny_shape`. Never grants or matches anything itself.
    pub async fn record_learned_denial(
        &self,
        binary: &str,
        args: &[String],
        command: &str,
        reason: &str,
    ) -> Result<Option<DenyLearningOutcome>> {
        let Some(store) = &self.deny_shapes else {
            return Ok(None);
        };
        let mut guard = store.write().await;
        guard.record_denial(binary, args, command, reason)
    }

    /// Attempt to synthesize and promote a deny shape from an outcome flagged
    /// `ready_to_synthesize`. Makes one LLM call, then validates the result
    /// through `validate_deny_shape_safety` before persisting -- the model's
    /// output is never trusted directly. Returns `Ok(true)` if a shape was
    /// promoted, `Ok(false)` if the model wasn't confident or nothing changed
    /// (not an error: the bucket keeps accumulating evidence for next time).
    pub async fn try_promote_deny_shape(&self, outcome: &DenyLearningOutcome) -> Result<bool> {
        let Some(store) = &self.deny_shapes else {
            return Ok(false);
        };
        if outcome.evidence_args.len() < 2 {
            // Nothing to generalize from yet; skip the LLM call entirely.
            return Ok(false);
        }
        let Some((args_pattern, evidence_note)) = self
            .synthesize_deny_shape(&outcome.binary, &outcome.evidence_args, &outcome.reason)
            .await?
        else {
            return Ok(false);
        };
        let mut guard = store.write().await;
        guard.promote_shape(
            &outcome.service,
            &outcome.binary,
            &args_pattern,
            &outcome.evidence_args,
            &evidence_note,
            outcome.denials,
        )?;
        Ok(true)
    }

    /// Synthesize one typed verb from operator prose (the `guard verb create
    /// --prompt` path). Reuses the daemon's own LLM client/key/model. Returns the
    /// model-produced verb; the caller stamps `source_prose` and validates it
    /// against the catalog before persisting. Operator-only at the RPC layer.
    pub async fn synthesize_verb(&self, prose: &str, binary_hint: Option<&str>) -> Result<Verb> {
        // Honor --no-llm: a daemon told not to talk to the model must not emit a
        // synthesis request just because a key happens to be configured.
        if !self.llm_config.enabled {
            bail!(
                "verb synthesis requires the LLM, which is disabled (--no-llm); \
                 re-enable the LLM to create verbs"
            );
        }
        let api_key = self
            .llm_config
            .api_key
            .clone()
            .filter(|k| !k.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "verb synthesis needs an LLM API key, but the daemon has none configured"
                )
            })?;
        let api_url = self.llm_config.api_url();
        let model = self.llm_config.model();
        let body = build_create_verb_body(&model, prose, binary_hint);

        // A small model occasionally omits a required field or returns
        // unparseable arguments; retry a few times before failing.
        let attempts = self.llm_config.effective_retries().saturating_add(1).max(2);
        let mut last_err = String::new();
        for attempt in 1..=attempts {
            match self.synthesize_verb_once(&api_key, &api_url, &body).await {
                Ok(verb) => return Ok(verb),
                Err(e) => {
                    last_err = e.to_string();
                    tracing::warn!(
                        "verb synthesis attempt {}/{} failed: {}",
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
        bail!("verb synthesis failed after {attempts} attempts: {last_err}")
    }

    /// One verb-synthesis round-trip: post the create_verb request and parse the
    /// forced tool call's arguments straight into a `Verb`.
    async fn synthesize_verb_once(
        &self,
        api_key: &str,
        api_url: &str,
        body: &serde_json::Value,
    ) -> Result<Verb> {
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
            .ok_or_else(|| anyhow::anyhow!("model did not return a create_verb tool call"))?;
        let args: serde_json::Value = serde_json::from_str(args_str)
            .map_err(|e| anyhow::anyhow!("tool-call arguments were not valid JSON: {e}"))?;
        let verb: Verb = serde_json::from_value(args)
            .map_err(|e| anyhow::anyhow!("model output did not match the verb schema: {e}"))?;
        Ok(verb)
    }

    /// Synthesize one deny shape from repeated denial evidence (the automatic
    /// half of `gating::deny_shape`). Reuses the daemon's own LLM client/key.
    /// Returns `Ok(None)` when the model isn't confident the evidence shares
    /// one shape -- the caller keeps accumulating rather than forcing a
    /// synthesis. The caller still re-validates the returned pattern from
    /// scratch (`validate_deny_shape_safety`); nothing here is trusted.
    async fn synthesize_deny_shape(
        &self,
        binary: &str,
        evidence: &[String],
        last_reason: &str,
    ) -> Result<Option<(String, String)>> {
        if !self.llm_config.enabled {
            return Ok(None);
        }
        let Some(api_key) = self.llm_config.api_key.clone().filter(|k| !k.is_empty()) else {
            return Ok(None);
        };
        let api_url = self.llm_config.api_url();
        let model = self.llm_config.model();
        let body = build_create_deny_shape_body(&model, binary, evidence, last_reason);

        let attempts = self.llm_config.effective_retries().saturating_add(1).max(2);
        let mut last_err = String::new();
        for attempt in 1..=attempts {
            match self
                .synthesize_deny_shape_once(&api_key, &api_url, &body)
                .await
            {
                Ok(result) => return Ok(result),
                Err(e) => {
                    last_err = e.to_string();
                    tracing::warn!(
                        "deny-shape synthesis attempt {}/{} failed: {}",
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
        tracing::warn!("deny-shape synthesis failed after {attempts} attempts: {last_err}");
        Ok(None)
    }

    async fn synthesize_deny_shape_once(
        &self,
        api_key: &str,
        api_url: &str,
        body: &serde_json::Value,
    ) -> Result<Option<(String, String)>> {
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
            .ok_or_else(|| anyhow::anyhow!("model did not return a create_deny_shape tool call"))?;
        let args: serde_json::Value = serde_json::from_str(args_str)
            .map_err(|e| anyhow::anyhow!("tool-call arguments were not valid JSON: {e}"))?;
        let confident = args
            .get("confident")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !confident {
            return Ok(None);
        }
        let args_pattern = args
            .get("args_pattern")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("model output missing args_pattern"))?
            .to_string();
        let evidence = args
            .get("evidence")
            .and_then(|v| v.as_str())
            .unwrap_or("auto-learned from repeated denials")
            .to_string();
        Ok(Some((args_pattern, evidence)))
    }
}

/// Build the function-calling body for verb synthesis: force a single
/// `create_verb` tool call whose arguments deserialize directly into a `Verb`.
fn build_create_verb_body(
    model: &str,
    prose: &str,
    binary_hint: Option<&str>,
) -> serde_json::Value {
    let user = match binary_hint {
        Some(b) => format!("Target binary: {b}\n\nOperator request:\n{prose}"),
        None => format!("Operator request:\n{prose}"),
    };
    let user = redact_for_llm(&user);
    serde_json::json!({
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT_CREATE_VERB},
            {"role": "user", "content": user},
        ],
        "tools": [{
            "type": "function",
            "function": {
                "name": "create_verb",
                "description": "Define exactly one typed guard verb that satisfies the operator request with least privilege.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "short kebab-case verb name"},
                        "description": {"type": "string"},
                        "binary": {"type": "string", "description": "the exact executable name, no path"},
                        "args": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "argv template; use {param} placeholders, one per argv element; no shell operators"
                        },
                        "params": {
                            "type": "object",
                            "description": "map of param name -> spec",
                            "additionalProperties": {
                                "type": "object",
                                "properties": {
                                    "pattern": {"type": "string", "description": "FULLY ANCHORED regex ^...$, as narrow as possible; pin to specific named values when the request names them"},
                                    "required": {"type": "boolean"},
                                    "allow_dash": {"type": "boolean"}
                                },
                                "required": ["pattern"]
                            }
                        },
                        "consequence": {"type": "string", "enum": ["reversible", "recoverable", "irreversible"]},
                        "revert": {
                            "type": "object",
                            "properties": {
                                "binary": {"type": "string"},
                                "args": {"type": "array", "items": {"type": "string"}}
                            },
                            "description": "required only for a recoverable verb: the structured inverse"
                        },
                        "trusted": {"type": "boolean", "description": "true only for clearly safe read-only operations"},
                        "evidence": {"type": "string", "description": "one or two sentences justifying this least-privilege shape"}
                    },
                    "required": ["name", "binary", "consequence", "evidence"]
                }
            }
        }],
        "tool_choice": {"type": "function", "function": {"name": "create_verb"}}
    })
}

/// System prompt for deny-shape synthesis: infer the minimal generalized
/// shape from repeated denial evidence, or decline if it doesn't clearly
/// generalize. Kept narrow on purpose -- unlike verb synthesis, there is no
/// human review before this pattern becomes an active fast path, so the
/// model is instructed to prefer declining (`confident: false`) over
/// guessing.
const SYSTEM_PROMPT_CREATE_DENY_SHAPE: &str = "You infer the minimal common shape from several \
argument strings that were all denied for the same binary. Each example below is quoted exactly \
as the regex must match it: no binary name, no leading or trailing space, no added punctuation. \
Produce a single fully-anchored regular expression (must start with ^ and end with $) that matches \
each quoted example verbatim and materially similar variants -- and nothing broader. Do not prepend \
`^\\s` or any other whitespace to the pattern; the match starts at the first character of the \
argument string itself. Only set confident=true if the examples clearly share one narrow shape. If \
they look unrelated, or generalizing would require matching a wide range of unrelated arguments, \
set confident=false and leave args_pattern empty. This pattern will become an automatic deny fast \
path with no human review, so err toward declining rather than guessing.";

fn build_create_deny_shape_body(
    model: &str,
    binary: &str,
    evidence: &[String],
    last_reason: &str,
) -> serde_json::Value {
    let examples: String = evidence
        .iter()
        .map(|e| format!("- {e:?}"))
        .collect::<Vec<_>>()
        .join("\n");
    let user = format!(
        "Binary: {binary}\nMost recent denial reason: {last_reason}\n\nDenied argument strings \
         (quoted exactly; match them without the surrounding quotes):\n{examples}"
    );
    let user = redact_for_llm(&user);
    serde_json::json!({
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT_CREATE_DENY_SHAPE},
            {"role": "user", "content": user},
        ],
        "tools": [{
            "type": "function",
            "function": {
                "name": "create_deny_shape",
                "description": "Infer the minimal generalized deny shape for these examples, or decline.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "args_pattern": {"type": "string", "description": "FULLY ANCHORED regex ^...$ over the space-joined argument string"},
                        "confident": {"type": "boolean", "description": "true only if the examples clearly share one narrow shape"},
                        "evidence": {"type": "string", "description": "one sentence justifying this shape"}
                    },
                    "required": ["confident", "evidence"]
                }
            }
        }],
        "tool_choice": {"type": "function", "function": {"name": "create_deny_shape"}}
    })
}

#[cfg(test)]
mod tests {
    use crate::evaluate::{EvalConfig, Evaluator};

    #[tokio::test]
    async fn deny_shape_observation_without_llm_key_does_not_error() {
        // Recording a denial and attempting promotion must be safe no-ops
        // when the LLM (needed for synthesis) has no API key configured --
        // mirrors record_learned_approval's graceful behavior on the allow
        // side.
        let evaluator = Evaluator::new(EvalConfig::default()).unwrap();
        assert!(!evaluator.deny_learning_enabled());
        let outcome = evaluator
            .record_learned_denial(
                "kubectl",
                &["get".into(), "pods".into()],
                "kubectl get pods",
                "no",
            )
            .await
            .unwrap();
        assert!(outcome.is_none());
    }
}
