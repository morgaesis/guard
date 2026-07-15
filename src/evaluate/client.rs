//! HTTP transport to the LLM API: retry loop, fallback chain, attempt classification.

use super::config::DEFAULT_API_URL;
use super::parse::{parse_decision_response, provider_error_summary, response_shape_summary};
use super::prompt::{build_function_call_body, build_json_response_body};
use super::redact::redact_for_llm;
use super::result::{EvalResult, EvalSource, LlmResponse};
use super::Evaluator;
use anyhow::{Context, Result};
use std::time::Duration;

/// Per-attempt backoff schedule (seconds). Index = attempt number (0 = first retry).
/// The initial attempt is not delayed.
const BACKOFF_SECONDS: [f64; 3] = [0.5, 1.5, 4.5];

/// Classifies why a single LLM attempt failed, so the retry loop can decide
/// whether to retry at all and whether to downgrade from function-calling to
/// JSON-response-format prompting.
#[derive(Debug)]
enum AttemptError {
    /// 429 from the provider. Carries an optional Retry-After seconds value.
    RateLimited { retry_after: Option<u64> },
    /// Any 5xx from the provider.
    ServerError(String),
    /// Transport-level failure (DNS, TLS, connection reset, timeout).
    Transport(String),
    /// Response parsed but no usable content/tool-call was found, OR a
    /// tool-call's arguments JSON did not match our schema.
    ParseError(String),
    /// 4xx other than 429 (bad request, auth, model-not-found). Not retried.
    ClientError(String),
}

impl std::fmt::Display for AttemptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RateLimited { retry_after } => {
                write!(f, "rate_limited (retry_after={:?})", retry_after)
            }
            Self::ServerError(s) => write!(f, "server_error: {}", s),
            Self::Transport(s) => write!(f, "transport_error: {}", s),
            Self::ParseError(s) => write!(f, "parse_error: {}", s),
            Self::ClientError(s) => write!(f, "client_error: {}", s),
        }
    }
}

impl AttemptError {
    /// Retriable means "try again within the per-model budget". Client errors
    /// (401/403/404) are NOT retriable because retrying with the same key/model
    /// won't help.
    fn is_retriable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. }
                | Self::ServerError(_)
                | Self::Transport(_)
                | Self::ParseError(_)
        )
    }

    fn status_tag(&self) -> &'static str {
        match self {
            Self::RateLimited { .. } => "rate_limited",
            Self::ServerError(_) => "server_error",
            Self::Transport(_) => "transport_error",
            Self::ParseError(_) => "parse_error",
            Self::ClientError(_) => "client_error",
        }
    }
}

impl Evaluator {
    pub(super) async fn ping_llm(&self) -> Result<()> {
        let api_key = self
            .llm_config
            .api_key
            .as_ref()
            .context("API key required")?;

        let url = format!(
            "{}/models",
            self.llm_config
                .api_url
                .as_ref()
                .map(|u| u.trim_end_matches('/').to_string())
                .unwrap_or_else(|| DEFAULT_API_URL
                    .split('/')
                    .take(3)
                    .collect::<Vec<_>>()
                    .join("/"))
        );

        let response = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .timeout(Duration::from_secs(5))
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                tracing::debug!("LLM connectivity check passed");
                Ok(())
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                tracing::warn!("LLM API returned {}: {}", status, body);
                Ok(())
            }
            Err(e) => {
                tracing::warn!("LLM connectivity check failed: {}", e);
                Err(e.into())
            }
        }
    }

    /// Top-level LLM evaluation: walks the model-fallback chain and, per model,
    /// runs the retry loop. The LLM NEVER sees the unredacted command; only the
    /// caller's audit log does.
    #[tracing::instrument(skip(self, command, prompt_append), fields(command_len = command.len()))]
    pub(super) async fn evaluate_llm(
        &self,
        command: &str,
        prompt_append: Option<&str>,
    ) -> EvalResult {
        let api_key = match &self.llm_config.api_key {
            Some(k) => k.clone(),
            None => {
                return EvalResult::Error(
                    "LLM API key not configured; set GUARD_LLM_API_KEY (or OPENROUTER_API_KEY) in the daemon's environment"
                        .to_string(),
                );
            }
        };

        // Redact secret-shaped substrings BEFORE the command text enters any LLM
        // payload. The audit log, on the other hand, sees the original - that
        // happens in the caller's layer, not here.
        let redacted_command = redact_for_llm(command);
        if redacted_command != command {
            // debug, not info: with the broadened redaction surface this
            // fires on most commands carrying any high-entropy argument and
            // would dominate the journal on secret-heavy traffic.
            tracing::debug!("redacted secret-shaped content from LLM prompt");
        }

        let api_url = self.llm_config.api_url();
        let chain = self.llm_config.model_chain();

        // Build the per-call system prompt. Session-supplied context is
        // appended after the base prompt so the static guardrails still
        // anchor the evaluator.
        // Session context is caller-supplied free text; redact it like the
        // command itself before it enters the prompt.
        let system_prompt = match prompt_append {
            Some(extra) if !extra.trim().is_empty() => {
                format!(
                    "{}\n\nSession context:\n{}",
                    self.system_prompt,
                    redact_for_llm(extra)
                )
            }
            _ => self.system_prompt.clone(),
        };

        let mut last_error: Option<String> = None;
        for model in &chain {
            match self
                .evaluate_model(&api_key, &api_url, model, &redacted_command, &system_prompt)
                .await
            {
                Ok(decision) => {
                    if decision.decision.eq_ignore_ascii_case("APPROVE") {
                        return EvalResult::Allow {
                            reason: decision.reason,
                            source: EvalSource::Llm,
                            risk: Some(decision.risk),
                            // Carry the model's class through only when gating is
                            // on; off-mode allows stay unclassified.
                            reversibility: if self.gate_mode.is_on() {
                                decision.reversibility
                            } else {
                                None
                            },
                        };
                    } else {
                        return EvalResult::Deny {
                            reason: decision.reason,
                            source: EvalSource::Llm,
                            risk: Some(decision.risk),
                        };
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "model {} exhausted retry budget: {} - trying next in chain",
                        model,
                        e
                    );
                    last_error = Some(format!("{}: {}", model, e));
                }
            }
        }

        EvalResult::Error(
            last_error.unwrap_or_else(|| "LLM chain exhausted without result".to_string()),
        )
    }

    /// Runs one model through the full retry budget. Returns Ok(decision) on the
    /// first successful attempt, or Err once the budget is exhausted.
    #[tracing::instrument(skip(self, api_key, command, system_prompt), fields(model = %model))]
    async fn evaluate_model(
        &self,
        api_key: &str,
        api_url: &str,
        model: &str,
        command: &str,
        system_prompt: &str,
    ) -> Result<LlmResponse, AttemptError> {
        let max_retries = self.llm_config.effective_retries();
        // total attempts = 1 initial + max_retries
        let total_attempts = max_retries + 1;

        let mut last_err: Option<AttemptError> = None;
        for attempt in 0..total_attempts {
            // Decide mode: initial attempt uses function-calling; once a parse-error
            // retry happens we switch that model to JSON-response-format mode.
            let use_function_calling =
                attempt == 0 || !matches!(last_err, Some(AttemptError::ParseError(_)));

            // Backoff before retries (not before the first attempt).
            if attempt > 0 {
                // If the previous error was a 429 with Retry-After, prefer that.
                let delay = if let Some(AttemptError::RateLimited {
                    retry_after: Some(s),
                }) = &last_err
                {
                    Duration::from_secs(*s)
                } else {
                    let idx = ((attempt - 1) as usize).min(BACKOFF_SECONDS.len() - 1);
                    let base = BACKOFF_SECONDS[idx];
                    // Jitter: +/- 20%. rand::random() returns f64 in [0,1).
                    let r: f64 = rand::random();
                    let jitter = (r - 0.5) * 0.4;
                    Duration::from_secs_f64(base * (1.0 + jitter))
                };
                tokio::time::sleep(delay).await;
            }

            let attempt_num = attempt + 1;
            tracing::info!(
                model = %model,
                attempt = attempt_num,
                mode = if use_function_calling { "function_calling" } else { "json_format" },
                "LLM attempt start",
            );

            let result = self
                .one_attempt(
                    api_key,
                    api_url,
                    model,
                    command,
                    system_prompt,
                    use_function_calling,
                )
                .await;

            match result {
                Ok((decision, usage)) => {
                    log_usage(model, attempt_num, &usage, "ok");
                    tracing::info!(
                        model = %model,
                        attempt = attempt_num,
                        "LLM attempt succeeded"
                    );
                    return Ok(decision);
                }
                Err(e) => {
                    let status_tag = e.status_tag();
                    // Log failed attempt usage (zero tokens we know of; still visible in audit).
                    log_usage(model, attempt_num, &TokenUsage::default(), status_tag);
                    tracing::info!(
                        model = %model,
                        attempt = attempt_num,
                        "LLM attempt failed: {}",
                        e
                    );

                    if !e.is_retriable() || attempt_num == total_attempts {
                        return Err(e);
                    }
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| AttemptError::Transport("unknown failure".to_string())))
    }

    /// One HTTP round-trip to the provider. Returns the parsed decision on success,
    /// or a classified AttemptError.
    async fn one_attempt(
        &self,
        api_key: &str,
        api_url: &str,
        model: &str,
        command: &str,
        system_prompt: &str,
        use_function_calling: bool,
    ) -> Result<(LlmResponse, TokenUsage), AttemptError> {
        let gating = self.gate_mode.is_on();
        let body = if use_function_calling {
            build_function_call_body(api_url, model, system_prompt, command, gating)
        } else {
            build_json_response_body(api_url, model, system_prompt, command, gating)
        };

        tracing::debug!("LLM POST {}: model={}", api_url, model);

        let response = self
            .http_client
            .post(api_url)
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| AttemptError::Transport(e.to_string()))?;

        let status = response.status();

        // Extract Retry-After before consuming the body
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());

        let response_text = response
            .text()
            .await
            .map_err(|e| AttemptError::Transport(e.to_string()))?;

        if status.as_u16() == 429 {
            return Err(AttemptError::RateLimited { retry_after });
        }
        if status.is_server_error() {
            return Err(AttemptError::ServerError(format!(
                "{}: {}",
                status,
                truncate(&response_text, 200)
            )));
        }
        if status.is_client_error() {
            // A router that cannot satisfy forced tool calling for this model
            // reports it as a 4xx. Classify as ParseError, not ClientError:
            // the retry loop downgrades to JSON mode after a ParseError, so
            // the next attempt succeeds instead of burning the budget on an
            // unusable mode.
            if use_function_calling && response_text.to_ascii_lowercase().contains("tool_choice") {
                return Err(AttemptError::ParseError(format!(
                    "tool calling unsupported by provider: {}",
                    truncate(&response_text, 200)
                )));
            }
            return Err(AttemptError::ClientError(format!(
                "{}: {}",
                status,
                truncate(&response_text, 200)
            )));
        }
        if !status.is_success() {
            return Err(AttemptError::Transport(format!(
                "unexpected status {}: {}",
                status,
                truncate(&response_text, 200)
            )));
        }

        let parsed: serde_json::Value = serde_json::from_str(&response_text)
            .map_err(|e| AttemptError::ParseError(format!("non-JSON response: {}", e)))?;

        let usage = extract_usage(&parsed);

        // Routers commonly return HTTP 200 with an embedded error object.
        if parsed.get("error").is_some() {
            return Err(AttemptError::ClientError(provider_error_summary(&parsed)));
        }

        let decision = parse_decision_response(&parsed, use_function_calling).map_err(|e| {
            AttemptError::ParseError(format!("{}; {}", e, response_shape_summary(&parsed)))
        })?;

        Ok((decision, usage))
    }
}

/// Token usage metrics from the provider response.
#[derive(Debug, Clone, Copy, Default)]
struct TokenUsage {
    prompt: u64,
    completion: u64,
    total: u64,
}

fn extract_usage(parsed: &serde_json::Value) -> TokenUsage {
    let Some(usage) = parsed.get("usage") else {
        return TokenUsage::default();
    };
    TokenUsage {
        prompt: usage
            .get("prompt_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        completion: usage
            .get("completion_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        total: usage
            .get("total_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
    }
}

fn log_usage(model: &str, attempt: u32, usage: &TokenUsage, status: &str) {
    tracing::info!(
        "[LLM_USAGE] model={} attempt={} prompt_tokens={} completion_tokens={} total_tokens={} status={}",
        model,
        attempt,
        usage.prompt,
        usage.completion,
        usage.total,
        status,
    );
}

pub(super) fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        // Back up to a char boundary so slicing a multi-byte UTF-8 body (e.g. an
        // error page from the provider) cannot panic.
        let mut end = max;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &s[..end])
    }
}

#[cfg(test)]
mod tests {
    use crate::evaluate::{EvalConfig, EvalResult, Evaluator};

    // --- Retry loop tests using a mock HTTP server ---

    async fn mock_server_evaluator(port: u16, retries: u32, models: Vec<String>) -> Evaluator {
        let mut config = EvalConfig::default()
            .llm_api_key("test-key".to_string())
            .llm_api_url(format!("http://127.0.0.1:{}", port))
            .llm_timeout_secs(5)
            .llm_retries(retries);
        if !models.is_empty() {
            config = config.llm_models(models);
        }
        Evaluator::new(config).expect("evaluator")
    }

    /// A one-shot tokio-based HTTP mock. Serves a sequence of (status, body,
    /// content-type) tuples and then closes.
    async fn run_mock(
        listener: tokio::net::TcpListener,
        responses: Vec<(u16, String, Option<String>)>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut idx = 0;
        while idx < responses.len() {
            let (mut stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => return,
            };
            // Read request headers until CRLF CRLF, plus any content-length body.
            let mut buf = Vec::with_capacity(4096);
            let mut tmp = [0u8; 2048];
            while let Ok(n) = stream.read(&mut tmp).await {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&buf[..pos]);
                    let mut content_length = 0usize;
                    for line in headers.split("\r\n") {
                        if let Some(v) = line.strip_prefix("Content-Length: ") {
                            content_length = v.trim().parse().unwrap_or(0);
                        } else if let Some(v) = line.strip_prefix("content-length: ") {
                            content_length = v.trim().parse().unwrap_or(0);
                        }
                    }
                    let body_so_far = buf.len() - pos - 4;
                    if body_so_far >= content_length {
                        break;
                    }
                }
            }

            let (status, body, retry_after) = &responses[idx];
            idx += 1;
            let status_text = match status {
                200 => "OK",
                429 => "Too Many Requests",
                500 => "Internal Server Error",
                _ => "Status",
            };
            let mut resp = format!(
                "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
                status,
                status_text,
                body.len()
            );
            if let Some(ra) = retry_after {
                resp.push_str(&format!("Retry-After: {}\r\n", ra));
            }
            resp.push_str("Connection: close\r\n\r\n");
            resp.push_str(body);
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    fn tool_call_body(decision: &str) -> String {
        format!(
            r#"{{
                "choices": [{{
                    "message": {{
                        "tool_calls": [{{
                            "id": "c1",
                            "type": "function",
                            "function": {{
                                "name": "decide",
                                "arguments": "{{\"decision\":\"{}\",\"reason\":\"test\",\"risk\":1}}"
                            }}
                        }}]
                    }}
                }}],
                "usage": {{"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}
            }}"#,
            decision
        )
    }

    #[tokio::test]
    async fn test_retry_on_429_then_success() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let responses = vec![
            (
                429,
                r#"{"error":"rate limited"}"#.to_string(),
                Some("1".to_string()),
            ),
            (200, tool_call_body("APPROVE"), None),
        ];
        let mock = tokio::spawn(run_mock(listener, responses));

        let evaluator = mock_server_evaluator(port, 2, vec![]).await;
        let result = evaluator.evaluate_llm("id", None).await;
        assert!(result.is_allow(), "got: {}", result);
        let _ = mock.await;
    }

    #[tokio::test]
    async fn test_retry_on_429_with_non_numeric_retry_after() {
        // A Retry-After expressed as an HTTP-date (not delta-seconds) must not
        // break the wire path: it parses to None, the evaluator falls back to
        // its exponential backoff, and the retry still reaches success. Guards
        // against a regression that assumed Retry-After is always an integer.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let responses = vec![
            (
                429,
                r#"{"error":"rate limited"}"#.to_string(),
                Some("Wed, 21 Oct 2026 07:28:00 GMT".to_string()),
            ),
            (200, tool_call_body("APPROVE"), None),
        ];
        let mock = tokio::spawn(run_mock(listener, responses));

        let evaluator = mock_server_evaluator(port, 2, vec![]).await;
        let result = evaluator.evaluate_llm("id", None).await;
        assert!(result.is_allow(), "got: {}", result);
        let _ = mock.await;
    }

    #[tokio::test]
    async fn test_retry_on_500_then_success() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let responses = vec![
            (500, r#"{"error":"boom"}"#.to_string(), None),
            (200, tool_call_body("DENY"), None),
        ];
        let mock = tokio::spawn(run_mock(listener, responses));

        let evaluator = mock_server_evaluator(port, 2, vec![]).await;
        let result = evaluator.evaluate_llm("rm -rf /", None).await;
        assert!(result.is_deny(), "got: {}", result);
        let _ = mock.await;
    }

    #[tokio::test]
    async fn test_retry_exhausted_returns_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let responses = vec![
            (
                429,
                r#"{"error":"rate limited"}"#.to_string(),
                Some("1".to_string()),
            ),
            (
                429,
                r#"{"error":"rate limited"}"#.to_string(),
                Some("1".to_string()),
            ),
            (
                429,
                r#"{"error":"rate limited"}"#.to_string(),
                Some("1".to_string()),
            ),
        ];
        let mock = tokio::spawn(run_mock(listener, responses));

        let evaluator = mock_server_evaluator(port, 2, vec![]).await;
        let result = evaluator.evaluate_llm("id", None).await;
        assert!(result.is_error());
        assert!(
            result.reason().contains("rate_limited"),
            "got: {}",
            result.reason()
        );
        let _ = mock.await;
    }

    #[tokio::test]
    async fn test_fallback_chain_primary_fails_secondary_succeeds() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Primary fails all 3 attempts (500s), secondary succeeds on first attempt.
        let responses = vec![
            (500, r#"{"error":"boom"}"#.to_string(), None),
            (500, r#"{"error":"boom"}"#.to_string(), None),
            (500, r#"{"error":"boom"}"#.to_string(), None),
            (200, tool_call_body("APPROVE"), None),
        ];
        let mock = tokio::spawn(run_mock(listener, responses));

        let evaluator =
            mock_server_evaluator(port, 2, vec!["primary/m1".into(), "secondary/m2".into()]).await;
        let result = evaluator.evaluate_llm("id", None).await;
        assert!(result.is_allow(), "got: {}", result);
        let _ = mock.await;
    }

    #[tokio::test]
    async fn test_parse_error_switches_to_json_format_and_succeeds() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // First response: 200 but no tool_calls → ParseError.
        // Second response: 200 with content containing JSON.
        let bad_body = r#"{"choices":[{"message":{"content":"I cannot comply"}}]}"#.to_string();
        let good_body = r#"{"choices":[{"message":{"content":"{\"decision\":\"APPROVE\",\"reason\":\"ok\",\"risk\":1}"}}]}"#.to_string();
        let responses = vec![(200, bad_body, None), (200, good_body, None)];
        let mock = tokio::spawn(run_mock(listener, responses));

        let evaluator = mock_server_evaluator(port, 2, vec![]).await;
        let result = evaluator.evaluate_llm("id", None).await;
        assert!(result.is_allow(), "got: {}", result);
        let _ = mock.await;
    }

    #[tokio::test]
    async fn test_tool_choice_client_error_switches_to_json_format() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // First response: 404 refusing the forced tool_choice → downgraded to
        // ParseError so the retry uses JSON mode. Second response: success.
        let unsupported =
            r#"{"error":{"message":"No endpoints found that support the provided 'tool_choice' value"}}"#
                .to_string();
        let good_body = r#"{"choices":[{"message":{"content":"{\"decision\":\"APPROVE\",\"reason\":\"ok\",\"risk\":1}"}}]}"#.to_string();
        let responses = vec![(404, unsupported, None), (200, good_body, None)];
        let mock = tokio::spawn(run_mock(listener, responses));

        let evaluator = mock_server_evaluator(port, 2, vec![]).await;
        let result = evaluator.evaluate_llm("pwd", None).await;
        assert!(result.is_allow(), "got: {}", result);
        let _ = mock.await;
    }

    #[tokio::test]
    async fn test_embedded_provider_error_is_client_error_not_parse_noise() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // HTTP 200 with an embedded error object: classified ClientError
        // (non-retriable, so exactly one request), and the chain must surface
        // the provider message, not a "no tool_calls" parse error.
        let err_body =
            r#"{"error":{"message":"Forbidden","code":"forbidden","type":"upstream_error"}}"#
                .to_string();
        let responses = vec![(200, err_body, None)];
        let mock = tokio::spawn(run_mock(listener, responses));

        let evaluator = mock_server_evaluator(port, 0, vec![]).await;
        let result = evaluator.evaluate_llm("id", None).await;
        match result {
            EvalResult::Error(msg) => {
                assert!(msg.contains("Forbidden"), "got: {msg}");
            }
            other => panic!("expected Error, got {other}"),
        }
        let _ = mock.await;
    }
}
