//! Compiled-in system prompts and LLM request-body assembly for command evaluation.

/// Readonly mode system prompt (read-only-biased evaluation), compiled from
/// config/system-prompt-readonly.md. Override at runtime with
/// `--system-prompt <path>` or `~/.config/guard/system-prompt.txt`.
pub(super) const SYSTEM_PROMPT_READONLY: &str =
    include_str!("../../config/system-prompt-readonly.md");

/// SAFE mode prompt: allow almost everything, rely on env_clear + output redaction.
pub(super) const SYSTEM_PROMPT_SAFE: &str = include_str!("../../config/system-prompt-safe.md");

/// PARANOID mode prompt: block everything except basic read-only inspection.
pub(super) const SYSTEM_PROMPT_PARANOID: &str =
    include_str!("../../config/system-prompt-paranoid.md");

/// Consequence-classification appendix. Appended to whichever base prompt is
/// active only when `GateMode::Consequence` is enabled. It is purely additive:
/// it asks the model to classify the reversibility of commands it already
/// approves and never changes the approve/deny boundary the base prompt encodes.
pub(super) const SYSTEM_PROMPT_GATING: &str = include_str!("../../config/system-prompt-gating.md");

/// Completion budget sent as `max_completion_tokens`. Reasoning-capable
/// models spend hidden reasoning tokens from this same budget, so it is far
/// larger than the visible decision JSON needs; `max_tokens` is rejected
/// outright by several current models.
const DEFAULT_MAX_COMPLETION_TOKENS: u32 = 4096;

/// Build the OpenAI-compatible body for a function-calling request. The evaluator
/// defines exactly one tool, `decide`, with a strict schema, and forces the model
/// to call it via `tool_choice`. `api_url` selects the provider-appropriate
/// reasoning-control field (see `add_reasoning_controls`).
pub(super) fn build_function_call_body(
    api_url: &str,
    model: &str,
    system_prompt: &str,
    command: &str,
    gating: bool,
) -> serde_json::Value {
    let user_message = format!("Command: {}", command);
    let mut properties = serde_json::json!({
        "decision": {
            "type": "string",
            "enum": ["APPROVE", "DENY"],
            "description": "APPROVE if the command is allowed under the active mode policy, DENY if the active mode policy blocks it"
        },
        "reason": {
            "type": "string",
            "description": "Brief explanation of the decision (one sentence)"
        },
        "risk": {
            "type": "integer",
            "minimum": 0,
            "maximum": 10,
            "description": "Risk score from 0 (completely safe) to 10 (catastrophic)"
        }
    });
    let mut required = vec!["decision", "reason", "risk"];
    if gating {
        properties["reversibility"] = serde_json::json!({
            "type": "string",
            "enum": ["reversible", "recoverable", "irreversible"],
            "description": "For an APPROVE decision, how reversible the command's effect is. Does not change the decision; classify only commands you approve. When unsure pick the more destructive class."
        });
        required.push("reversibility");
    }
    let mut body = serde_json::json!({
        "model": model,
        "max_completion_tokens": DEFAULT_MAX_COMPLETION_TOKENS,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message}
        ],
        "tools": [{
            "type": "function",
            "function": {
                "name": "decide",
                "description": "Record the authorization decision for the command",
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                    "additionalProperties": false
                }
            }
        }],
        "tool_choice": {"type": "function", "function": {"name": "decide"}}
    });
    add_reasoning_controls(api_url, &mut body);
    body
}

/// Build the request body for the fallback path: tell the model to emit a bare
/// JSON object and parse it tolerantly. Used after a parse-error retry or when
/// the provider does not support function calling. No `response_format` is
/// sent: several routed models reject `json_object` mode, and the tolerant
/// parser plus the dual-shape fallback (`parse_decision_response`) already
/// absorb prose-wrapped output.
pub(super) fn build_json_response_body(
    api_url: &str,
    model: &str,
    system_prompt: &str,
    command: &str,
    gating: bool,
) -> serde_json::Value {
    let schema_hint = if gating {
        "{\"decision\": \"APPROVE\" or \"DENY\", \"reason\": \"brief\", \"risk\": 0-10, \"reversibility\": \"reversible\" or \"recoverable\" or \"irreversible\"}"
    } else {
        "{\"decision\": \"APPROVE\" or \"DENY\", \"reason\": \"brief\", \"risk\": 0-10}"
    };
    let user_message = format!(
        "Command: {}\n\nRespond with ONLY a JSON object matching this schema (no prose, no markdown):\n{}",
        command, schema_hint
    );
    let mut body = serde_json::json!({
        "model": model,
        "max_completion_tokens": DEFAULT_MAX_COMPLETION_TOKENS,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message}
        ]
    });
    add_reasoning_controls(api_url, &mut body);
    body
}

/// Ask the provider to spend as little hidden reasoning as possible: the
/// decision schema needs no chain of thought, and reasoning tokens both bill
/// and drain `max_completion_tokens`. OpenRouter uses a structured
/// `reasoning` object (`exclude` drops reasoning from the response);
/// OpenAI-compatible endpoints use the flat `reasoning_effort` field.
/// Non-reasoning models ignore the field on both paths.
fn add_reasoning_controls(api_url: &str, body: &mut serde_json::Value) {
    let Some(obj) = body.as_object_mut() else {
        return;
    };
    if api_url.contains("openrouter.ai") {
        obj.insert(
            "reasoning".to_string(),
            serde_json::json!({"effort": "minimal", "exclude": true}),
        );
    } else {
        obj.insert("reasoning_effort".to_string(), serde_json::json!("minimal"));
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_function_call_body, build_json_response_body, DEFAULT_MAX_COMPLETION_TOKENS,
    };
    use crate::evaluate::config::DEFAULT_API_URL;
    use crate::evaluate::{EvalConfig, Evaluator};
    use crate::gating::GateMode;

    // --- Consequence gating: classification plumbing ---

    const GATING_MARKER: &str = "Consequence classification (additional task)";

    #[test]
    fn gating_off_prompt_excludes_appendix() {
        let ev = Evaluator::new(EvalConfig::default().llm_enabled(false)).expect("build");
        assert_eq!(ev.gate_mode(), GateMode::Off);
        assert!(
            !ev.system_prompt.contains(GATING_MARKER),
            "gating-off prompt must be byte-identical to today's (no appendix)"
        );
    }

    #[test]
    fn gating_on_prompt_includes_appendix() {
        let ev = Evaluator::new(
            EvalConfig::default()
                .llm_enabled(false)
                .gate_mode(GateMode::Consequence),
        )
        .expect("build");
        assert_eq!(ev.gate_mode(), GateMode::Consequence);
        assert!(
            ev.system_prompt.contains(GATING_MARKER),
            "gating-on prompt must carry the classification appendix"
        );
    }

    #[test]
    fn schema_requires_reversibility_only_when_gating() {
        let off = build_function_call_body(DEFAULT_API_URL, "m", "sys", "ls", false);
        let req_off = &off["tools"][0]["function"]["parameters"]["required"];
        assert!(!req_off.to_string().contains("reversibility"));

        let on = build_function_call_body(DEFAULT_API_URL, "m", "sys", "ls", true);
        let req_on = &on["tools"][0]["function"]["parameters"]["required"];
        assert!(req_on.to_string().contains("reversibility"));
        assert!(
            on["tools"][0]["function"]["parameters"]["properties"]["reversibility"].is_object()
        );
    }

    #[test]
    fn test_chat_bodies_use_reasoning_compatible_token_budget() {
        let tool_body = build_function_call_body(DEFAULT_API_URL, "model", "system", "id", false);
        let json_body = build_json_response_body(DEFAULT_API_URL, "model", "system", "id", false);

        for body in [tool_body, json_body] {
            assert!(body.get("max_tokens").is_none());
            assert!(body.get("response_format").is_none());
            assert!(body.get("reasoning_effort").is_none());
            assert_eq!(
                body.get("max_completion_tokens").and_then(|v| v.as_u64()),
                Some(DEFAULT_MAX_COMPLETION_TOKENS as u64)
            );
            assert_eq!(
                body.pointer("/reasoning/effort").and_then(|v| v.as_str()),
                Some("minimal")
            );
        }
    }

    #[test]
    fn test_direct_openai_chat_body_uses_native_reasoning_effort() {
        let body = build_json_response_body(
            "https://api.openai.com/v1/chat/completions",
            "model",
            "system",
            "id",
            false,
        );
        assert!(body.get("reasoning").is_none());
        assert_eq!(
            body.get("reasoning_effort").and_then(|v| v.as_str()),
            Some("minimal")
        );
    }
}
