//! Tolerant parsing of provider responses into decisions.

use super::client::truncate;
use super::result::LlmResponse;
use crate::gating::Reversibility;
use anyhow::{bail, Context, Result};
use regex::Regex;
use std::sync::OnceLock;

/// Parse a provider response in the preferred mode, then fall back to the
/// other valid OpenAI-compatible shape. Some routers/models ignore the
/// request mode and return a tool call for a JSON request, or plain content
/// for a tool-call request.
pub fn parse_decision_response(
    parsed: &serde_json::Value,
    prefer_function_calling: bool,
) -> Result<LlmResponse> {
    let primary = if prefer_function_calling {
        parse_tool_call(parsed)
    } else {
        parse_json_content(parsed)
    };
    match primary {
        Ok(decision) => Ok(decision),
        Err(primary_err) => {
            let secondary = if prefer_function_calling {
                parse_json_content(parsed)
            } else {
                parse_tool_call(parsed)
            };
            secondary.with_context(|| {
                format!(
                    "primary response parser failed: {}; fallback parser also failed",
                    primary_err
                )
            })
        }
    }
}

/// Structural description of a response that failed to parse: key names,
/// counts, and kinds only - never message content, so a provider echo of the
/// (already redacted) command cannot ride an error string into logs.
pub fn response_shape_summary(parsed: &serde_json::Value) -> String {
    let top_keys = parsed
        .as_object()
        .map(|obj| obj.keys().cloned().collect::<Vec<_>>().join(","))
        .unwrap_or_else(|| "<non-object>".to_string());
    let choice_count = parsed
        .get("choices")
        .and_then(|v| v.as_array())
        .map(Vec::len)
        .unwrap_or(0);
    let finish_reason = parsed
        .pointer("/choices/0/finish_reason")
        .and_then(|v| v.as_str())
        .unwrap_or("<none>");
    let message_keys = parsed
        .pointer("/choices/0/message")
        .and_then(|v| v.as_object())
        .map(|obj| obj.keys().cloned().collect::<Vec<_>>().join(","))
        .unwrap_or_else(|| "<none>".to_string());
    let content_kind = match parsed.pointer("/choices/0/message/content") {
        Some(value) if value.is_null() => "null",
        Some(value) if value.is_string() => "string",
        Some(value) if value.is_array() => "array",
        Some(_) => "other",
        None => "missing",
    };
    let tool_call_count = parsed
        .pointer("/choices/0/message/tool_calls")
        .and_then(|v| v.as_array())
        .map(Vec::len)
        .unwrap_or(0);
    format!(
        "response_shape=top_keys:[{}] choices:{} finish_reason:{} message_keys:[{}] content:{} tool_calls:{}",
        top_keys, choice_count, finish_reason, message_keys, content_kind, tool_call_count
    )
}

/// Compact summary of a provider-embedded `error` object (an HTTP-200 body
/// carrying an error, common behind routers). Message text is truncated.
pub fn provider_error_summary(parsed: &serde_json::Value) -> String {
    let message = parsed
        .pointer("/error/message")
        .and_then(|v| v.as_str())
        .map(|message| truncate(message, 160))
        .unwrap_or_else(|| "provider returned an error object".to_string());
    let code = parsed
        .pointer("/error/code")
        .and_then(|v| v.as_str())
        .unwrap_or("<none>");
    let error_type = parsed
        .pointer("/error/type")
        .and_then(|v| v.as_str())
        .unwrap_or("<none>");
    format!("{} (code={}, type={})", message, code, error_type)
}

/// Parse a function-calling response: `choices[0].message.tool_calls[0].function.arguments`
/// is a JSON string that must match the `decide` schema.
fn parse_tool_call(parsed: &serde_json::Value) -> Result<LlmResponse> {
    let tool_calls = parsed
        .pointer("/choices/0/message/tool_calls")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("no tool_calls in response"))?;

    let tool_call = tool_calls
        .first()
        .ok_or_else(|| anyhow::anyhow!("empty tool_calls array"))?;

    let fn_name = tool_call
        .pointer("/function/name")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if fn_name != "decide" {
        bail!("unexpected tool call: {}", fn_name);
    }

    let args_str = tool_call
        .pointer("/function/arguments")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("no arguments in tool call"))?;

    // Tool-call arguments are always a JSON string in the OpenAI protocol; parse
    // strictly first, fall back to lax for small model deviations.
    let value: serde_json::Value = match serde_json::from_str(args_str) {
        Ok(v) => v,
        Err(_) => {
            let relaxed = lax_extract_json(args_str)?;
            serde_json::from_str(&relaxed)
                .with_context(|| format!("failed to parse tool arguments: {}", args_str))?
        }
    };

    decision_from_value(&value)
}

/// Parse a JSON-response-format message: `choices[0].message.content` should be
/// a JSON object, but small models often wrap it in markdown fences or prose,
/// and some providers return content as an array of typed parts.
fn parse_json_content(parsed: &serde_json::Value) -> Result<LlmResponse> {
    let content_value = parsed
        .pointer("/choices/0/message/content")
        .ok_or_else(|| anyhow::anyhow!("no content in response"))?;
    let content = message_content_to_text(content_value)?;

    if content.trim().is_empty() {
        bail!("empty content in response");
    }

    let extracted = lax_extract_json(&content)?;
    let value: serde_json::Value = serde_json::from_str(&extracted)
        .with_context(|| format!("failed to parse extracted JSON: {}", extracted))?;
    decision_from_value(&value)
}

/// Flatten a message `content` value to text: plain string, or an array of
/// parts holding text as bare strings, `{"text": ...}`, or `{"content": ...}`.
fn message_content_to_text(value: &serde_json::Value) -> Result<String> {
    if let Some(s) = value.as_str() {
        return Ok(s.to_string());
    }

    if let Some(parts) = value.as_array() {
        let mut text = String::new();
        for part in parts {
            if let Some(s) = part.as_str() {
                text.push_str(s);
                continue;
            }
            if let Some(s) = part.get("text").and_then(|v| v.as_str()) {
                text.push_str(s);
                continue;
            }
            if let Some(s) = part.get("content").and_then(|v| v.as_str()) {
                text.push_str(s);
            }
        }
        return Ok(text);
    }

    bail!("content was not text")
}

/// Build an LlmResponse from a parsed JSON value, accepting decision values
/// case-insensitively (APPROVE/approve/Approve → APPROVE) and coercing a
/// missing/invalid risk to 5.
fn decision_from_value(value: &serde_json::Value) -> Result<LlmResponse> {
    let decision_raw = value
        .get("decision")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing 'decision' field"))?;
    let decision = match decision_raw.trim().to_ascii_uppercase().as_str() {
        "APPROVE" => "APPROVE".to_string(),
        "DENY" => "DENY".to_string(),
        other => bail!("invalid decision value: '{}'", other),
    };

    let reason = value
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let risk = value.get("risk").and_then(|v| v.as_i64()).unwrap_or(5) as i32;

    // Reversibility is optional: present only when gating asked for it, and a
    // garbled value is tolerated as `None` so a small model's bad label fails
    // safe at the routing layer (None -> hold) rather than erroring the whole
    // evaluation.
    let reversibility = value
        .get("reversibility")
        .and_then(|v| v.as_str())
        .and_then(Reversibility::parse_lenient);

    Ok(LlmResponse {
        decision,
        reason,
        risk,
        reversibility,
    })
}

/// Lax JSON extractor: strips markdown fences, finds the first balanced `{...}`
/// substring, and patches common small-model mistakes (trailing commas, unquoted
/// keys) before attempting a permissive parse.
///
/// Returns a stringified JSON object that `serde_json::from_str` will accept, or
/// an error if no plausible object can be recovered.
fn lax_extract_json(text: &str) -> Result<String> {
    // 1. Strip markdown code fences.
    let stripped = strip_markdown_fences(text);

    // 2. Strict parse first.
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&stripped) {
        return serde_json::to_string(&v).map_err(|e| anyhow::anyhow!(e));
    }

    // 3. Find the first balanced {...} substring.
    let Some(candidate) = find_balanced_object(&stripped) else {
        bail!("no JSON object found in: {}", truncate(&stripped, 120));
    };

    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&candidate) {
        return serde_json::to_string(&v).map_err(|e| anyhow::anyhow!(e));
    }

    // 4. Permissive patches: strip trailing commas, quote bare keys.
    let patched = permissive_patch(&candidate);
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&patched) {
        return serde_json::to_string(&v).map_err(|e| anyhow::anyhow!(e));
    }

    bail!("could not recover JSON from: {}", truncate(&candidate, 120))
}

fn strip_markdown_fences(text: &str) -> String {
    let t = text.trim();
    if let Some(rest) = t.strip_prefix("```json") {
        return rest.trim_end_matches("```").trim().to_string();
    }
    if let Some(rest) = t.strip_prefix("```JSON") {
        return rest.trim_end_matches("```").trim().to_string();
    }
    if let Some(rest) = t.strip_prefix("```") {
        return rest.trim_end_matches("```").trim().to_string();
    }
    t.to_string()
}

/// Find the first `{` and walk forward matching braces (respecting string
/// boundaries) until the outermost brace is closed. Returns the inclusive slice.
fn find_balanced_object(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let start = bytes.iter().position(|&b| b == b'{')?;
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape = false;
    for (i, &b) in bytes.iter().enumerate().skip(start) {
        if in_string {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(text[start..=i].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

/// Patch common small-model JSON mistakes so serde_json can parse:
/// - Strip trailing commas before `}` or `]`
/// - Quote unquoted keys like `{decision: "APPROVE"}` → `{"decision": "APPROVE"}`
fn permissive_patch(text: &str) -> String {
    let (trailing_comma, unquoted_key) = permissive_patterns();
    let step1 = trailing_comma.replace_all(text, "$1");
    let step2 = unquoted_key.replace_all(&step1, r#"$1"$2":"#);
    step2.into_owned()
}

fn permissive_patterns() -> &'static (Regex, Regex) {
    static P: OnceLock<(Regex, Regex)> = OnceLock::new();
    P.get_or_init(|| {
        (
            Regex::new(r",(\s*[}\]])").expect("valid regex"),
            Regex::new(r"([\{,]\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:").expect("valid regex"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::{
        decision_from_value, lax_extract_json, parse_decision_response, parse_json_content,
        parse_tool_call, provider_error_summary, response_shape_summary,
    };
    use crate::gating::Reversibility;

    #[test]
    fn test_response_shape_summary_is_structural() {
        let resp: serde_json::Value = serde_json::from_str(
            r#"{"choices":[{"finish_reason":"length","message":{"role":"assistant","content":null}}],"usage":{"total_tokens":10}}"#,
        )
        .unwrap();
        let summary = response_shape_summary(&resp);
        assert!(summary.contains("finish_reason:length"));
        assert!(summary.contains("content:null"));
        assert!(summary.contains("tool_calls:0"));
        assert!(!summary.contains("assistant"));
    }

    #[test]
    fn test_provider_error_summary_is_bounded() {
        let resp: serde_json::Value = serde_json::from_str(
            r#"{"error":{"message":"Forbidden","code":"forbidden","type":"upstream_error"}}"#,
        )
        .unwrap();
        assert_eq!(
            provider_error_summary(&resp),
            "Forbidden (code=forbidden, type=upstream_error)"
        );
    }

    #[test]
    fn test_parse_decision_response_accepts_content_when_tool_call_expected() {
        let resp: serde_json::Value = serde_json::from_str(
            r#"{"choices":[{"message":{"content":"{\"decision\":\"APPROVE\",\"reason\":\"ok\",\"risk\":1}"}}]}"#,
        )
        .unwrap();
        let d = parse_decision_response(&resp, true).unwrap();
        assert_eq!(d.decision, "APPROVE");
    }

    #[test]
    fn test_parse_decision_response_accepts_tool_call_when_content_expected() {
        let resp: serde_json::Value = serde_json::from_str(
            r#"{
                "choices": [{
                    "message": {
                        "content": "",
                        "tool_calls": [{
                            "function": {
                                "name": "decide",
                                "arguments": "{\"decision\":\"APPROVE\",\"reason\":\"safe\",\"risk\":1}"
                            }
                        }]
                    }
                }]
            }"#,
        )
        .unwrap();
        let d = parse_decision_response(&resp, false).unwrap();
        assert_eq!(d.decision, "APPROVE");
    }

    #[test]
    fn test_parse_json_content_accepts_text_parts() {
        let resp: serde_json::Value = serde_json::from_str(
            r#"{"choices":[{"message":{"content":[{"type":"text","text":"{\"decision\":\"DENY\",\"reason\":\"bad\",\"risk\":9}"}]}}]}"#,
        )
        .unwrap();
        let d = parse_json_content(&resp).unwrap();
        assert_eq!(d.decision, "DENY");
    }

    #[test]
    fn decision_parses_reversibility_when_present() {
        let v = serde_json::json!({
            "decision": "APPROVE", "reason": "ok", "risk": 3, "reversibility": "recoverable"
        });
        let resp = decision_from_value(&v).unwrap();
        assert_eq!(resp.reversibility, Some(Reversibility::Recoverable));

        // Absent field -> None (gating off, or model omitted it).
        let v2 = serde_json::json!({"decision": "APPROVE", "reason": "ok", "risk": 1});
        assert_eq!(decision_from_value(&v2).unwrap().reversibility, None);

        // Garbled class -> None (fails safe at routing), decision still parses.
        let v3 = serde_json::json!({
            "decision": "APPROVE", "reason": "ok", "risk": 1, "reversibility": "?!"
        });
        let r3 = decision_from_value(&v3).unwrap();
        assert_eq!(r3.decision, "APPROVE");
        assert_eq!(r3.reversibility, None);
    }

    // --- Lax parser tests ---

    #[test]
    fn test_lax_extract_json_direct() {
        let s = r#"{"decision":"APPROVE","reason":"safe","risk":1}"#;
        let out = lax_extract_json(s).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["decision"], "APPROVE");
    }

    #[test]
    fn test_lax_extract_json_markdown_wrapped() {
        let s = "```json\n{\"decision\": \"DENY\", \"reason\": \"nope\", \"risk\": 9}\n```";
        let out = lax_extract_json(s).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["decision"], "DENY");
        assert_eq!(v["risk"], 9);
    }

    #[test]
    fn test_lax_extract_json_plain_fence() {
        let s = "```\n{\"decision\": \"APPROVE\", \"reason\": \"ok\", \"risk\": 2}\n```";
        let out = lax_extract_json(s).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["decision"], "APPROVE");
    }

    #[test]
    fn test_lax_extract_json_with_prose() {
        let s = r#"Sure! Here is the answer: {"decision": "DENY", "reason": "bad", "risk": 8} - hope that helps."#;
        let out = lax_extract_json(s).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["decision"], "DENY");
    }

    #[test]
    fn test_lax_extract_json_trailing_comma() {
        let s = r#"{"decision": "APPROVE", "reason": "ok", "risk": 1,}"#;
        let out = lax_extract_json(s).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["decision"], "APPROVE");
    }

    #[test]
    fn test_lax_extract_json_unquoted_keys() {
        let s = r#"{decision: "DENY", reason: "dangerous", risk: 10}"#;
        let out = lax_extract_json(s).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["decision"], "DENY");
        assert_eq!(v["risk"], 10);
    }

    #[test]
    fn test_lax_extract_json_nested_object_balanced() {
        // The outer braces contain a nested object; extractor must capture the
        // outermost balanced pair, not stop at the first `}`.
        let s = r#"{"decision": "APPROVE", "reason": "ok", "risk": 1, "meta": {"k": "v"}}"#;
        let out = lax_extract_json(s).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["decision"], "APPROVE");
    }

    #[test]
    fn test_lax_extract_json_invalid_errors() {
        assert!(lax_extract_json("not json at all, no braces").is_err());
    }

    #[test]
    fn test_decision_from_value_case_insensitive() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"decision":"approve","reason":"ok","risk":1}"#).unwrap();
        let d = decision_from_value(&v).unwrap();
        assert_eq!(d.decision, "APPROVE");

        let v: serde_json::Value =
            serde_json::from_str(r#"{"decision":"Deny","reason":"no","risk":9}"#).unwrap();
        let d = decision_from_value(&v).unwrap();
        assert_eq!(d.decision, "DENY");
    }

    #[test]
    fn test_decision_from_value_missing_risk() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"decision":"APPROVE","reason":"ok"}"#).unwrap();
        let d = decision_from_value(&v).unwrap();
        assert_eq!(d.risk, 5);
    }

    #[test]
    fn test_decision_from_value_rejects_garbage() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"decision":"MAYBE","reason":"hm","risk":3}"#).unwrap();
        assert!(decision_from_value(&v).is_err());
    }

    // --- Tool-call parser tests ---

    #[test]
    fn test_parse_tool_call_success() {
        let resp: serde_json::Value = serde_json::from_str(
            r#"{
                "choices": [{
                    "message": {
                        "tool_calls": [{
                            "id": "call_abc",
                            "type": "function",
                            "function": {
                                "name": "decide",
                                "arguments": "{\"decision\":\"APPROVE\",\"reason\":\"safe\",\"risk\":1}"
                            }
                        }]
                    }
                }]
            }"#,
        )
        .unwrap();
        let d = parse_tool_call(&resp).unwrap();
        assert_eq!(d.decision, "APPROVE");
        assert_eq!(d.risk, 1);
    }

    #[test]
    fn test_parse_tool_call_no_tool_calls() {
        let resp: serde_json::Value =
            serde_json::from_str(r#"{"choices":[{"message":{"content":"something"}}]}"#).unwrap();
        assert!(parse_tool_call(&resp).is_err());
    }

    #[test]
    fn test_parse_tool_call_wrong_function_name() {
        let resp: serde_json::Value = serde_json::from_str(
            r#"{
                "choices": [{
                    "message": {
                        "tool_calls": [{
                            "function": {"name": "other", "arguments": "{}"}
                        }]
                    }
                }]
            }"#,
        )
        .unwrap();
        assert!(parse_tool_call(&resp).is_err());
    }

    #[test]
    fn test_parse_json_content_success() {
        let resp: serde_json::Value = serde_json::from_str(
            r#"{"choices":[{"message":{"content":"{\"decision\":\"DENY\",\"reason\":\"bad\",\"risk\":9}"}}]}"#,
        )
        .unwrap();
        let d = parse_json_content(&resp).unwrap();
        assert_eq!(d.decision, "DENY");
    }

    #[test]
    fn test_parse_json_content_markdown_wrapped() {
        let resp: serde_json::Value = serde_json::from_str(
            r#"{"choices":[{"message":{"content":"```json\n{\"decision\":\"APPROVE\",\"reason\":\"ok\",\"risk\":2}\n```"}}]}"#,
        )
        .unwrap();
        let d = parse_json_content(&resp).unwrap();
        assert_eq!(d.decision, "APPROVE");
    }

    #[test]
    fn test_parse_json_content_empty() {
        let resp: serde_json::Value =
            serde_json::from_str(r#"{"choices":[{"message":{"content":""}}]}"#).unwrap();
        assert!(parse_json_content(&resp).is_err());
    }
}
