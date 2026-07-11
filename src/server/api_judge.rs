use crate::evaluate::{redact_for_llm, EvalConfig, EvalResult, EvalSource, Evaluator, LlmConfig};
use anyhow::Result;
use async_trait::async_trait;
use guard::gating::api_promotion::{ApiPromotionOutcome, ApiPromotionStore};
use guard::gating::GateMode;
use guard::proxy::{ApiJudge, ApiJudgeVerdict, ApiRequestSummary};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

pub(crate) struct DaemonApiJudge {
    evaluator: Evaluator,
    api_promotion: Option<Arc<RwLock<ApiPromotionStore>>>,
}

impl DaemonApiJudge {
    pub(crate) fn build(
        llm: LlmConfig,
        cache_enabled: bool,
        cache_capacity: usize,
        cache_ttl: Duration,
        intent: Option<String>,
        api_promotion: Option<Arc<RwLock<ApiPromotionStore>>>,
    ) -> Result<Arc<dyn ApiJudge>> {
        let mut config = EvalConfig::default()
            .cache_enabled(cache_enabled)
            .cache_capacity(cache_capacity)
            .cache_ttl(cache_ttl)
            .gate_mode(GateMode::Consequence)
            .system_prompt_literal(api_judge_system_prompt(intent.as_deref()));
        config.llm = llm;
        Ok(Arc::new(Self {
            evaluator: Evaluator::new(config)?,
            api_promotion,
        }))
    }
}

#[async_trait]
impl ApiJudge for DaemonApiJudge {
    async fn judge(&self, summary: &ApiRequestSummary) -> ApiJudgeVerdict {
        if let Some(store) = &self.api_promotion {
            let hit = {
                let guard = store.read().await;
                guard.learned_deny(summary)
            };
            if let Some(hit) = hit {
                tracing::info!(
                    target: "guard::apiproxy",
                    "[AUDIT] API_LEARNED_DENY {} denials={}",
                    hit.shape.audit_label(),
                    hit.denials
                );
                return ApiJudgeVerdict::Deny {
                    reason: "API evaluator audit trail repeatedly denied this request shape"
                        .to_string(),
                };
            }

            if !summary.rarity {
                let hit = {
                    let guard = store.read().await;
                    guard.learned_allow(summary)
                };
                if let Some(hit) = hit {
                    tracing::info!(
                        target: "guard::apiproxy",
                        "[AUDIT] API_LEARNED_ALLOW {} approvals={} risk={} reversibility={}",
                        hit.shape.audit_label(),
                        hit.approvals,
                        hit.risk,
                        hit.reversibility
                    );
                    return ApiJudgeVerdict::Allow {
                        reason: "API evaluator approved request".to_string(),
                        risk: Some(hit.risk),
                        reversibility: Some(hit.reversibility),
                    };
                }
            }
        }

        match self.evaluator.evaluate(&summary.stable_text()).await {
            EvalResult::Allow {
                reason,
                source,
                risk,
                reversibility,
                ..
            } => {
                if source == EvalSource::Llm {
                    self.record_allow(summary, risk, reversibility, &reason)
                        .await;
                }
                ApiJudgeVerdict::Allow {
                    reason,
                    risk,
                    reversibility,
                }
            }
            EvalResult::Deny { reason, source, .. } => {
                if source == EvalSource::Llm {
                    self.record_deny(summary, &reason).await;
                }
                ApiJudgeVerdict::Deny { reason }
            }
            EvalResult::Error(error) => ApiJudgeVerdict::Error(error),
        }
    }
}

impl DaemonApiJudge {
    async fn record_allow(
        &self,
        summary: &ApiRequestSummary,
        risk: Option<i32>,
        reversibility: Option<guard::gating::Reversibility>,
        reason: &str,
    ) {
        let Some(store) = &self.api_promotion else {
            return;
        };
        let outcome = {
            let mut guard = store.write().await;
            guard.record_allow(summary, risk, reversibility, reason)
        };
        match outcome {
            Ok(Some(ApiPromotionOutcome::AllowPromoted {
                shape,
                approvals,
                risk,
                reversibility,
            })) => {
                tracing::info!(
                    target: "guard::apiproxy",
                    "[AUDIT] API_SHAPE_PROMOTED decision=allow {} approvals={} risk={} reversibility={}",
                    shape.audit_label(),
                    approvals,
                    risk,
                    reversibility
                );
            }
            Ok(Some(ApiPromotionOutcome::DenyLearned { .. })) => {}
            Ok(None) => {}
            Err(err) => tracing::warn!("failed to record API allow-shape observation: {}", err),
        }
    }

    async fn record_deny(&self, summary: &ApiRequestSummary, reason: &str) {
        let Some(store) = &self.api_promotion else {
            return;
        };
        let outcome = {
            let mut guard = store.write().await;
            guard.record_deny(summary, reason)
        };
        match outcome {
            Ok(Some(ApiPromotionOutcome::DenyLearned { shape, denials })) => {
                tracing::info!(
                    target: "guard::apiproxy",
                    "[AUDIT] API_SHAPE_PROMOTED decision=deny {} denials={}",
                    shape.audit_label(),
                    denials
                );
            }
            Ok(Some(ApiPromotionOutcome::AllowPromoted { .. })) => {}
            Ok(None) => {}
            Err(err) => tracing::warn!("failed to record API deny-shape observation: {}", err),
        }
    }
}

pub(crate) fn api_judge_system_prompt(intent: Option<&str>) -> String {
    let mut prompt = String::from(
        "You are guard's API operation evaluator. Decide whether one already-parsed API \
         operation is allowed for this proxy. Enforcement is live: there is no observe-only \
         mode, and uncertainty must move toward denial or operator hold.\n\n\
         Risk doctrine:\n\
         - Reads such as GET and HEAD are safe when they fit the proxy intent and do not \
         expose sensitive material.\n\
         - DELETE of durable state such as secrets, data stores, volumes, backups, or \
         namespaces is high risk and may be irreversible.\n\
         - DELETE of reprovisionable managed compute such as deployments, replicasets, \
         functions, or preview instances is moderate risk.\n\
         - PATCH and PUT are recoverable when prior state is readable and the request \
         includes a restore_prior_state revert marker.\n\
         - Unknown APIs, convention-breaking APIs, surprising subresources, and requests \
         outside the proxy intent should be judged cautiously.\n\
         - The request includes revert_constructible. Treat it as evidence of whether guard \
         can build an auto-revert for this exact operation.\n\
         - The request includes rarity. When true, this shape is statistically rare for this \
         proxy; weigh that against the proxy intent.\n\n\
         Approve only when the operation fits the proxy intent and the risk/reversibility \
         classification is coherent. Deny operations that do not fit. For operations that \
         might be acceptable only with operator scrutiny, approve with a high risk or \
         destructive reversibility class so the deterministic consequence gate holds it.",
    );
    if let Some(intent) = intent.map(str::trim).filter(|s| !s.is_empty()) {
        prompt.push_str("\n\nProxy intent:\n");
        prompt.push_str(&redact_for_llm(intent));
    }
    prompt
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard::proxy::RevertConstructible;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn api_judge_prompt_contains_intent() {
        let prompt = api_judge_system_prompt(Some("manage dev deployments"));
        assert!(prompt.contains("manage dev deployments"));
        assert!(prompt.contains("revert_constructible"));
    }

    #[test]
    fn request_summary_stable_text_contains_revert_marker() {
        let summary = ApiRequestSummary {
            protocol: "kubernetes".to_string(),
            verb: "patch".to_string(),
            path: "/apis/apps/v1/namespaces/dev/deployments/api".to_string(),
            redacted_query: String::new(),
            group: "apps".to_string(),
            version: "v1".to_string(),
            resource: "deployments".to_string(),
            subresource: None,
            namespace: Some("dev".to_string()),
            name: Some("api".to_string()),
            dry_run: false,
            redacted_body_shape: "{\"spec\":{\"replicas\":<number>}}".to_string(),
            revert_constructible: RevertConstructible::RestorePriorState,
            rarity: false,
        };
        assert!(summary
            .stable_text()
            .contains("revert_constructible: restore_prior_state"));
    }

    async fn run_llm_capture(
        listener: tokio::net::TcpListener,
        bodies: Arc<Mutex<Vec<String>>>,
        decision: &'static str,
        reason: &'static str,
        risk: i32,
        reversibility: Option<&'static str>,
    ) {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(stream) => stream,
                Err(_) => return,
            };
            let bodies = bodies.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
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
                        let body_start = pos + 4;
                        if buf.len() >= body_start + content_length {
                            let body = String::from_utf8_lossy(
                                &buf[body_start..body_start + content_length],
                            )
                            .to_string();
                            bodies.lock().unwrap().push(body);
                            break;
                        }
                    }
                }
                let mut args = serde_json::json!({
                    "decision": decision,
                    "reason": reason,
                    "risk": risk
                });
                if let Some(reversibility) = reversibility {
                    args["reversibility"] = serde_json::json!(reversibility);
                }
                let args = args.to_string();
                let body = serde_json::json!({
                    "choices": [{
                        "message": {
                            "tool_calls": [{
                                "id": "c1",
                                "type": "function",
                                "function": {
                                    "name": "decide",
                                    "arguments": args
                                }
                            }]
                        }
                    }],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
                })
                .to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    #[tokio::test]
    async fn daemon_api_judge_uses_intent_request_string_and_cache() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let bodies = Arc::new(Mutex::new(Vec::new()));
        tokio::spawn(run_llm_capture(
            listener,
            bodies.clone(),
            "APPROVE",
            "ok",
            1,
            Some("reversible"),
        ));

        let llm = LlmConfig {
            enabled: true,
            api_key: Some("test-key".to_string()),
            api_url: Some(url),
            model: Some("test-model".to_string()),
            models: Vec::new(),
            timeout_secs: 5,
            retries: 0,
        };
        let judge = DaemonApiJudge::build(
            llm,
            true,
            16,
            Duration::from_secs(60),
            Some("manage dev deployments".to_string()),
            None,
        )
        .expect("judge");
        let summary = ApiRequestSummary {
            protocol: "kubernetes".to_string(),
            verb: "patch".to_string(),
            path: "/apis/apps/v1/namespaces/dev/deployments/api".to_string(),
            redacted_query: String::new(),
            group: "apps".to_string(),
            version: "v1".to_string(),
            resource: "deployments".to_string(),
            subresource: None,
            namespace: Some("dev".to_string()),
            name: Some("api".to_string()),
            dry_run: false,
            redacted_body_shape: "{\"spec\":{\"replicas\":<number>}}".to_string(),
            revert_constructible: RevertConstructible::RestorePriorState,
            rarity: false,
        };

        assert!(matches!(
            judge.judge(&summary).await,
            ApiJudgeVerdict::Allow { .. }
        ));
        assert!(matches!(
            judge.judge(&summary).await,
            ApiJudgeVerdict::Allow { .. }
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;
        let bodies = bodies.lock().unwrap();
        assert_eq!(
            bodies.len(),
            1,
            "second identical request is served from cache"
        );
        let request: serde_json::Value = serde_json::from_str(&bodies[0]).unwrap();
        let system = request["messages"][0]["content"].as_str().unwrap();
        let user = request["messages"][1]["content"].as_str().unwrap();
        assert!(system.contains("manage dev deployments"));
        assert!(user.contains("revert_constructible: restore_prior_state"));
    }

    fn promotion_store(
        path: std::path::PathBuf,
        min_approvals: u32,
        min_denials: u32,
    ) -> Arc<RwLock<ApiPromotionStore>> {
        let mut config = guard::gating::api_promotion::ApiPromotionConfig::new(path);
        config.min_approvals = min_approvals;
        config.min_denials = min_denials;
        Arc::new(RwLock::new(ApiPromotionStore::load(config).unwrap()))
    }

    fn llm_config(url: String) -> LlmConfig {
        LlmConfig {
            enabled: true,
            api_key: Some("test-key".to_string()),
            api_url: Some(url),
            model: Some("test-model".to_string()),
            models: Vec::new(),
            timeout_secs: 5,
            retries: 0,
        }
    }

    fn api_summary(name: &str, rarity: bool) -> ApiRequestSummary {
        ApiRequestSummary {
            protocol: "kubernetes".to_string(),
            verb: "patch".to_string(),
            path: format!("/apis/apps/v1/namespaces/dev/deployments/{name}"),
            redacted_query: String::new(),
            group: "apps".to_string(),
            version: "v1".to_string(),
            resource: "deployments".to_string(),
            subresource: None,
            namespace: Some("dev".to_string()),
            name: Some(name.to_string()),
            dry_run: false,
            redacted_body_shape: "{\"spec\":{\"replicas\":<number>}}".to_string(),
            revert_constructible: RevertConstructible::RestorePriorState,
            rarity,
        }
    }

    #[tokio::test]
    async fn api_shape_allow_promotes_and_skips_llm_except_rarity() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let bodies = Arc::new(Mutex::new(Vec::new()));
        tokio::spawn(run_llm_capture(
            listener,
            bodies.clone(),
            "APPROVE",
            "recoverable with snapshot",
            6,
            Some("recoverable"),
        ));
        let temp = tempfile::tempdir().unwrap();
        let store = promotion_store(temp.path().join("api.yaml"), 5, 3);
        let judge = DaemonApiJudge::build(
            llm_config(url),
            false,
            16,
            Duration::from_secs(60),
            Some("manage dev deployments".to_string()),
            Some(store),
        )
        .expect("judge");

        for i in 0..5 {
            assert!(matches!(
                judge.judge(&api_summary(&format!("api-{i}"), false)).await,
                ApiJudgeVerdict::Allow {
                    risk: Some(6),
                    reversibility: Some(guard::gating::Reversibility::Recoverable),
                    ..
                }
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(bodies.lock().unwrap().len(), 5);

        assert!(matches!(
            judge.judge(&api_summary("api-sixth", false)).await,
            ApiJudgeVerdict::Allow {
                risk: Some(6),
                reversibility: Some(guard::gating::Reversibility::Recoverable),
                ..
            }
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            bodies.lock().unwrap().len(),
            5,
            "sixth non-rare request should use the learned allow"
        );

        assert!(matches!(
            judge.judge(&api_summary("api-rare", true)).await,
            ApiJudgeVerdict::Allow { .. }
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            bodies.lock().unwrap().len(),
            6,
            "rarity=true must force a real evaluator call"
        );
    }

    #[tokio::test]
    async fn api_shape_deny_learns_and_skips_llm_without_client_signal() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let bodies = Arc::new(Mutex::new(Vec::new()));
        tokio::spawn(run_llm_capture(
            listener,
            bodies.clone(),
            "DENY",
            "outside proxy intent",
            8,
            None,
        ));
        let temp = tempfile::tempdir().unwrap();
        let store = promotion_store(temp.path().join("api.yaml"), 5, 3);
        let judge = DaemonApiJudge::build(
            llm_config(url),
            false,
            16,
            Duration::from_secs(60),
            Some("manage dev deployments".to_string()),
            Some(store),
        )
        .expect("judge");

        for i in 0..3 {
            assert!(matches!(
                judge.judge(&api_summary(&format!("api-{i}"), false)).await,
                ApiJudgeVerdict::Deny { .. }
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(bodies.lock().unwrap().len(), 3);

        let verdict = judge.judge(&api_summary("api-fourth", false)).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            bodies.lock().unwrap().len(),
            3,
            "learned deny should skip the LLM"
        );
        let ApiJudgeVerdict::Deny { reason } = verdict else {
            panic!("expected deny");
        };
        for forbidden in ["promoted", "learned", "fast path"] {
            assert!(
                !reason.to_ascii_lowercase().contains(forbidden),
                "client-facing API denial exposed {forbidden}: {reason}"
            );
        }
    }
}
