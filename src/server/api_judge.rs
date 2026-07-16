use anyhow::Result;
use async_trait::async_trait;
use guard::evaluate::{redact_for_llm, EvalConfig, EvalResult, EvalSource, Evaluator, LlmConfig};
use guard::gating::api_promotion::{ApiCoverageProvenance, ApiPromotionOutcome, ApiPromotionStore};
use guard::gating::GateMode;
use guard::proxy::{ApiCoverageVerdict, ApiJudge, ApiJudgeVerdict, ApiRequestSummary};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;
use std::{collections::HashMap, fmt};
use tokio::sync::{RwLock, Semaphore};

/// Bumped when the API judge system prompt or the learning semantics change, so
/// a binary upgrade that alters the evaluator regime distrusts prior learned
/// shapes without a manual file edit.
const API_JUDGE_PROMPT_VERSION: u32 = 1;
const MAX_API_JUDGE_SCOPES: usize = 4096;

pub(crate) struct DaemonApiJudge {
    evaluator: Evaluator,
    api_promotion: Option<Arc<RwLock<ApiPromotionStore>>>,
    /// Fingerprint of the evaluator regime (prompt version, model, intent). A
    /// learned shape stamped with a different regime is not trusted.
    stamp: String,
    spend: Arc<ApiJudgeSpend>,
}

struct DaemonApiCoverageJudge {
    api_promotion: Arc<RwLock<ApiPromotionStore>>,
    stamp: String,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ApiJudgeSpendConfig {
    pub max_concurrency: usize,
    pub rate_per_minute: u32,
    pub burst: u32,
    pub error_threshold: u32,
    pub circuit_cooldown: Duration,
}

impl Default for ApiJudgeSpendConfig {
    fn default() -> Self {
        Self {
            max_concurrency: 4,
            rate_per_minute: 60,
            burst: 10,
            error_threshold: 3,
            circuit_cooldown: Duration::from_secs(60),
        }
    }
}

struct SpendState {
    tokens: f64,
    refilled_at: Instant,
    last_touched: Instant,
    concurrency: Arc<Semaphore>,
    consecutive_errors: u32,
    circuit_open_until: Option<Instant>,
}

pub(crate) struct ApiJudgeSpend {
    config: ApiJudgeSpendConfig,
    states: Mutex<HashMap<String, SpendState>>,
    concurrency: Arc<Semaphore>,
    baseline_concurrency: Arc<Semaphore>,
    attempted: AtomicU64,
    admitted: AtomicU64,
    rate_limited: AtomicU64,
    concurrency_limited: AtomicU64,
    evaluator_errors: AtomicU64,
    circuit_rejections: AtomicU64,
}

struct ApiJudgeSpendPermit {
    _global: tokio::sync::OwnedSemaphorePermit,
    _scope: tokio::sync::OwnedSemaphorePermit,
    _baseline: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl fmt::Debug for ApiJudgeSpendPermit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiJudgeSpendPermit")
            .finish_non_exhaustive()
    }
}

impl ApiJudgeSpend {
    pub(crate) fn new(config: ApiJudgeSpendConfig) -> Self {
        Self {
            states: Mutex::new(HashMap::new()),
            concurrency: Arc::new(Semaphore::new(config.max_concurrency.max(1))),
            // Baseline traffic may use every slot except the reserved session
            // slot. With a one-slot configuration, evaluator-routed work must
            // carry a live session attribution.
            baseline_concurrency: Arc::new(Semaphore::new(
                config.max_concurrency.saturating_sub(1),
            )),
            config,
            attempted: AtomicU64::new(0),
            admitted: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            concurrency_limited: AtomicU64::new(0),
            evaluator_errors: AtomicU64::new(0),
            circuit_rejections: AtomicU64::new(0),
        }
    }

    fn scope(endpoint: &str, session_fingerprint: Option<&str>) -> String {
        format!(
            "{}|{}",
            endpoint,
            session_fingerprint.unwrap_or("(baseline)")
        )
    }

    fn admit(
        &self,
        endpoint: &str,
        session_fingerprint: Option<&str>,
    ) -> Result<ApiJudgeSpendPermit, &'static str> {
        self.attempted.fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();
        let scope = Self::scope(endpoint, session_fingerprint);
        let scope_concurrency = {
            let mut states = self.states.lock().expect("API judge spend lock");
            if !states.contains_key(&scope) && states.len() >= MAX_API_JUDGE_SCOPES {
                if let Some(oldest) = states
                    .iter()
                    .filter(|(_, state)| Arc::strong_count(&state.concurrency) == 1)
                    .min_by_key(|(_, state)| state.last_touched)
                    .map(|(scope, _)| scope.clone())
                {
                    states.remove(&oldest);
                } else {
                    self.concurrency_limited.fetch_add(1, Ordering::Relaxed);
                    self.audit("scope_capacity");
                    return Err("API evaluator scope capacity reached");
                }
            }
            let per_scope = self.config.max_concurrency.saturating_sub(1).max(1);
            let state = states.entry(scope.clone()).or_insert_with(|| SpendState {
                tokens: f64::from(self.config.burst),
                refilled_at: now,
                last_touched: now,
                concurrency: Arc::new(Semaphore::new(per_scope)),
                consecutive_errors: 0,
                circuit_open_until: None,
            });
            state.last_touched = now;
            state.concurrency.clone()
        };
        let scope_permit = scope_concurrency.try_acquire_owned().map_err(|_| {
            self.concurrency_limited.fetch_add(1, Ordering::Relaxed);
            self.audit("scope_concurrency_limited");
            "API evaluator per-session concurrency limit reached"
        })?;
        let baseline = if session_fingerprint.is_none() {
            Some(
                self.baseline_concurrency
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| {
                        self.concurrency_limited.fetch_add(1, Ordering::Relaxed);
                        self.audit("baseline_reserve");
                        "API evaluator session reserve is unavailable to unattributed traffic"
                    })?,
            )
        } else {
            None
        };
        let global = self.concurrency.clone().try_acquire_owned().map_err(|_| {
            self.concurrency_limited.fetch_add(1, Ordering::Relaxed);
            self.audit("concurrency_limited");
            "API evaluator concurrency limit reached"
        })?;
        {
            let mut states = self.states.lock().expect("API judge spend lock");
            let state = states
                .get_mut(&scope)
                .expect("admitted API judge scope remains registered");
            state.last_touched = now;
            if state.circuit_open_until.is_some_and(|until| now < until) {
                self.circuit_rejections.fetch_add(1, Ordering::Relaxed);
                self.audit("circuit_open");
                return Err("API evaluator circuit is open");
            }
            state.circuit_open_until = None;
            let elapsed = now.duration_since(state.refilled_at).as_secs_f64();
            let refill = elapsed * f64::from(self.config.rate_per_minute) / 60.0;
            state.tokens = (state.tokens + refill).min(f64::from(self.config.burst));
            state.refilled_at = now;
            if state.tokens < 1.0 {
                self.rate_limited.fetch_add(1, Ordering::Relaxed);
                drop(states);
                self.audit("rate_limited");
                return Err("API evaluator rate limit reached");
            }
            state.tokens -= 1.0;
        }
        self.admitted.fetch_add(1, Ordering::Relaxed);
        Ok(ApiJudgeSpendPermit {
            _global: global,
            _scope: scope_permit,
            _baseline: baseline,
        })
    }

    fn complete(&self, endpoint: &str, session_fingerprint: Option<&str>, error: bool) {
        let scope = Self::scope(endpoint, session_fingerprint);
        let mut states = self.states.lock().expect("API judge spend lock");
        if !states.contains_key(&scope) && states.len() >= MAX_API_JUDGE_SCOPES {
            if let Some(oldest) = states
                .iter()
                .filter(|(_, state)| Arc::strong_count(&state.concurrency) == 1)
                .min_by_key(|(_, state)| state.last_touched)
                .map(|(scope, _)| scope.clone())
            {
                states.remove(&oldest);
            } else {
                tracing::warn!(target: "guard::audit", "[AUDIT] API_JUDGE_SPEND event=completion_scope_capacity");
                return;
            }
        }
        let now = Instant::now();
        let state = states.entry(scope).or_insert_with(|| SpendState {
            tokens: f64::from(self.config.burst),
            refilled_at: now,
            last_touched: now,
            concurrency: Arc::new(Semaphore::new(
                self.config.max_concurrency.saturating_sub(1).max(1),
            )),
            consecutive_errors: 0,
            circuit_open_until: None,
        });
        state.last_touched = now;
        if error {
            self.evaluator_errors.fetch_add(1, Ordering::Relaxed);
            state.consecutive_errors = state.consecutive_errors.saturating_add(1);
            if state.consecutive_errors >= self.config.error_threshold.max(1) {
                state.circuit_open_until = Some(now + self.config.circuit_cooldown);
            }
        } else {
            state.consecutive_errors = 0;
        }
        drop(states);
        self.audit(if error {
            "evaluator_error"
        } else {
            "completed"
        });
    }

    fn audit(&self, event: &str) {
        tracing::info!(target: "guard::audit",
            "[AUDIT] API_JUDGE_SPEND event={} attempted={} admitted={} rate_limited={} concurrency_limited={} evaluator_errors={} circuit_rejections={}",
            event,
            self.attempted.load(Ordering::Relaxed),
            self.admitted.load(Ordering::Relaxed),
            self.rate_limited.load(Ordering::Relaxed),
            self.concurrency_limited.load(Ordering::Relaxed),
            self.evaluator_errors.load(Ordering::Relaxed),
            self.circuit_rejections.load(Ordering::Relaxed),
        );
    }
}

impl DaemonApiJudge {
    pub(crate) fn build(
        llm: LlmConfig,
        cache_enabled: bool,
        cache_capacity: usize,
        cache_ttl: Duration,
        intent: Option<String>,
        api_promotion: Option<Arc<RwLock<ApiPromotionStore>>>,
        spend: Arc<ApiJudgeSpend>,
    ) -> Result<Arc<dyn ApiJudge>> {
        let stamp = regime_stamp(&llm, intent.as_deref());
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
            stamp,
            spend,
        }))
    }

    pub(crate) fn build_coverage_only(
        llm: &LlmConfig,
        intent: Option<&str>,
        api_promotion: Arc<RwLock<ApiPromotionStore>>,
    ) -> Arc<dyn ApiJudge> {
        Arc::new(DaemonApiCoverageJudge {
            api_promotion,
            stamp: regime_stamp(llm, intent),
        })
    }
}

async fn lookup_api_coverage(
    store: &Arc<RwLock<ApiPromotionStore>>,
    stamp: &str,
    summary: &ApiRequestSummary,
) -> ApiCoverageVerdict {
    let request_stamp = request_stamp(stamp, summary);
    let guard = store.read().await;
    if let Some(hit) = guard.learned_deny(summary, &request_stamp) {
        return ApiCoverageVerdict::Deny {
            reason: hit.reason,
            operator: hit.provenance == ApiCoverageProvenance::Operator,
        };
    }
    if !summary.rarity {
        if let Some(hit) = guard.learned_allow(summary, &request_stamp) {
            return ApiCoverageVerdict::Allow {
                risk: hit.risk,
                reversibility: hit.reversibility,
            };
        }
    }
    if summary.session_fingerprint.is_some() {
        let mut baseline = summary.clone();
        baseline.session_fingerprint = None;
        baseline.session_revision = None;
        baseline.session_intent = None;
        if let Some(hit) = guard.learned_deny(&baseline, stamp) {
            if hit.provenance == ApiCoverageProvenance::Operator {
                return ApiCoverageVerdict::Deny {
                    reason: hit.reason,
                    operator: true,
                };
            }
        }
    }
    ApiCoverageVerdict::None
}

fn request_stamp(stamp: &str, summary: &ApiRequestSummary) -> String {
    if summary.session_revision.is_none() && summary.session_intent.is_none() {
        return stamp.to_string();
    }
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(stamp.as_bytes());
    hasher.update([0u8]);
    hasher.update(summary.session_revision.as_deref().unwrap_or("").as_bytes());
    hasher.update([0u8]);
    hasher.update(summary.session_intent.as_deref().unwrap_or("").as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[async_trait]
impl ApiJudge for DaemonApiCoverageJudge {
    fn evaluator_enabled(&self) -> bool {
        false
    }

    async fn coverage(&self, summary: &ApiRequestSummary) -> ApiCoverageVerdict {
        lookup_api_coverage(&self.api_promotion, &self.stamp, summary).await
    }

    async fn judge(&self, _summary: &ApiRequestSummary) -> ApiJudgeVerdict {
        ApiJudgeVerdict::Error("API evaluator is disabled".to_string())
    }
}

/// A stable fingerprint of the evaluator regime: the prompt version, the model,
/// and the policy intent. Any change means prior learned shapes were produced
/// under different judgment and must be re-earned.
fn regime_stamp(llm: &LlmConfig, intent: Option<&str>) -> String {
    use sha2::{Digest, Sha256};
    let model = llm
        .model
        .clone()
        .or_else(|| llm.models.first().cloned())
        .unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(API_JUDGE_PROMPT_VERSION.to_le_bytes());
    hasher.update([0u8]);
    hasher.update(model.as_bytes());
    hasher.update([0u8]);
    hasher.update(intent.unwrap_or("").as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[async_trait]
impl ApiJudge for DaemonApiJudge {
    async fn coverage(&self, summary: &ApiRequestSummary) -> ApiCoverageVerdict {
        let Some(store) = &self.api_promotion else {
            return ApiCoverageVerdict::None;
        };
        lookup_api_coverage(store, &self.stamp, summary).await
    }

    async fn judge(&self, summary: &ApiRequestSummary) -> ApiJudgeVerdict {
        let request_stamp = self.request_stamp(summary);
        if let Some(store) = &self.api_promotion {
            let hit = {
                let guard = store.read().await;
                guard.learned_deny(summary, &request_stamp)
            };
            if let Some(hit) = hit {
                tracing::info!(
                    target: "guard::audit",
                    "[AUDIT] API_VERB_COVERAGE_HIT decision=deny scope={} {} denials={}",
                    if summary.session_fingerprint.is_some() { "session" } else { "global" },
                    hit.shape.audit_label(),
                    hit.denials
                );
                // Return the original denial reason verbatim so the client sees
                // exactly what a fresh evaluator denial would say. Disclosing
                // that this shape now skips the evaluator would tell an
                // adversarial client which requests bypass the model.
                return ApiJudgeVerdict::Deny { reason: hit.reason };
            }

            if !summary.rarity {
                let hit = {
                    let guard = store.read().await;
                    guard.learned_allow(summary, &request_stamp)
                };
                if let Some(hit) = hit {
                    tracing::info!(
                        target: "guard::audit",
                        "[AUDIT] API_VERB_COVERAGE_HIT decision=allow scope={} {} approvals={} risk={} reversibility={}",
                        if summary.session_fingerprint.is_some() { "session" } else { "global" },
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

            // Session coverage overlays generated global coverage. An
            // operator-authored global deny remains a floor; an evaluator-
            // generated global deny becomes evidence for a fresh session
            // evaluation. Global allows are never reused under different
            // session intent.
            if summary.session_fingerprint.is_some() {
                let mut baseline = summary.clone();
                baseline.session_fingerprint = None;
                baseline.session_revision = None;
                baseline.session_intent = None;
                let deny = {
                    let guard = store.read().await;
                    guard.learned_deny(&baseline, &self.stamp)
                };
                if let Some(hit) = deny {
                    if hit.provenance == ApiCoverageProvenance::Operator {
                        tracing::info!(target: "guard::audit",
                            "[AUDIT] API_VERB_COVERAGE_HIT decision=deny scope=global provenance=operator {} denials={}",
                            hit.shape.audit_label(), hit.denials);
                        return ApiJudgeVerdict::Deny { reason: hit.reason };
                    }
                    tracing::info!(target: "guard::audit",
                        "[AUDIT] API_VERB_COVERAGE_ESCALATE scope=session global_generated_deny=true {} denials={}",
                        hit.shape.audit_label(), hit.denials);
                }
            }
        }

        let _permit = match self
            .spend
            .admit(&summary.endpoint, summary.session_fingerprint.as_deref())
        {
            Ok(permit) => permit,
            Err(reason) => return ApiJudgeVerdict::Error(reason.to_string()),
        };
        let result = self.evaluator.evaluate(&summary.stable_text()).await;
        self.spend.complete(
            &summary.endpoint,
            summary.session_fingerprint.as_deref(),
            matches!(result, EvalResult::Error(_)),
        );
        match result {
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
    fn request_stamp(&self, summary: &ApiRequestSummary) -> String {
        request_stamp(&self.stamp, summary)
    }

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
            guard.record_allow(
                summary,
                risk,
                reversibility,
                reason,
                &self.request_stamp(summary),
            )
        };
        match outcome {
            Ok(Some(ApiPromotionOutcome::AllowPromoted {
                shape,
                approvals,
                risk,
                reversibility,
            })) => {
                tracing::info!(
                    target: "guard::audit",
                    "[AUDIT] API_VERB_COVERAGE_ACTIVATED decision=allow {} approvals={} risk={} reversibility={}",
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
            guard.record_deny(summary, reason, &self.request_stamp(summary))
        };
        match outcome {
            Ok(Some(ApiPromotionOutcome::DenyLearned { shape, denials })) => {
                tracing::info!(
                    target: "guard::audit",
                    "[AUDIT] API_VERB_COVERAGE_ACTIVATED decision=deny {} denials={}",
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
            authority_selectors: Default::default(),
            redacted_body_shape: "(no body)".to_string(),
            revert_constructible: RevertConstructible::RestorePriorState,
            rarity: false,
            endpoint: "default".to_string(),
            session_fingerprint: None,
            session_revision: None,
            session_intent: None,
            credential_ref: "upstream".to_string(),
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
            Arc::new(ApiJudgeSpend::new(ApiJudgeSpendConfig::default())),
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
            authority_selectors: Default::default(),
            redacted_body_shape: "{\"spec\":{\"replicas\":<number>}}".to_string(),
            revert_constructible: RevertConstructible::RestorePriorState,
            rarity: false,
            endpoint: "default".to_string(),
            session_fingerprint: None,
            session_revision: None,
            session_intent: None,
            credential_ref: "upstream".to_string(),
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
            authority_selectors: Default::default(),
            redacted_body_shape: "(no body)".to_string(),
            revert_constructible: RevertConstructible::RestorePriorState,
            rarity,
            endpoint: "default".to_string(),
            session_fingerprint: None,
            session_revision: None,
            session_intent: None,
            credential_ref: "upstream".to_string(),
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
            Arc::new(ApiJudgeSpend::new(ApiJudgeSpendConfig::default())),
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
            Arc::new(ApiJudgeSpend::new(ApiJudgeSpendConfig::default())),
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

    #[tokio::test]
    async fn session_intent_does_not_reuse_global_generated_allow() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let bodies = Arc::new(Mutex::new(Vec::new()));
        tokio::spawn(run_llm_capture(
            listener,
            bodies.clone(),
            "APPROVE",
            "session intent permits this request",
            1,
            Some("reversible"),
        ));
        let llm = llm_config(url);
        let stamp = regime_stamp(&llm, Some("global policy"));
        let temp = tempfile::tempdir().unwrap();
        let store = promotion_store(temp.path().join("api.yaml"), 2, 2);
        let global = api_summary("global", false);
        for _ in 0..2 {
            store
                .write()
                .await
                .record_allow(
                    &global,
                    Some(1),
                    Some(guard::gating::Reversibility::Reversible),
                    "global allow",
                    &stamp,
                )
                .unwrap();
        }
        let judge = DaemonApiJudge::build(
            llm,
            false,
            16,
            Duration::from_secs(60),
            Some("global policy".to_string()),
            Some(store),
            Arc::new(ApiJudgeSpend::new(ApiJudgeSpendConfig::default())),
        )
        .unwrap();
        let mut session = global;
        session.session_fingerprint = Some("session".to_string());
        session.session_intent = Some("manage only this session's deployments".to_string());

        assert!(matches!(
            judge.judge(&session).await,
            ApiJudgeVerdict::Allow { .. }
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            bodies.lock().unwrap().len(),
            1,
            "the session-specific request must be evaluated instead of using global allow coverage"
        );
    }

    #[tokio::test]
    async fn session_intent_evaluates_past_a_global_generated_deny() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let bodies = Arc::new(Mutex::new(Vec::new()));
        tokio::spawn(run_llm_capture(
            listener,
            bodies.clone(),
            "APPROVE",
            "session intent permits this request",
            1,
            Some("reversible"),
        ));
        let llm = llm_config(url);
        let stamp = regime_stamp(&llm, Some("global policy"));
        let temp = tempfile::tempdir().unwrap();
        let store = promotion_store(temp.path().join("api.yaml"), 2, 2);
        let global = api_summary("global", false);
        for _ in 0..2 {
            store
                .write()
                .await
                .record_deny(&global, "global generated deny", &stamp)
                .unwrap();
        }
        let judge = DaemonApiJudge::build(
            llm,
            false,
            16,
            Duration::from_secs(60),
            Some("global policy".to_string()),
            Some(store),
            Arc::new(ApiJudgeSpend::new(ApiJudgeSpendConfig::default())),
        )
        .unwrap();
        let mut session = global;
        session.session_fingerprint = Some("session".to_string());
        session.session_intent = Some("allow this scoped read".to_string());

        assert!(matches!(
            judge.judge(&session).await,
            ApiJudgeVerdict::Allow { .. }
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            bodies.lock().unwrap().len(),
            1,
            "a global evaluator-generated deny must escalate into the live session evaluator"
        );
    }

    #[test]
    fn spend_limits_concurrency_rate_and_opens_circuit() {
        let config = ApiJudgeSpendConfig {
            max_concurrency: 1,
            rate_per_minute: 1,
            burst: 2,
            error_threshold: 2,
            circuit_cooldown: Duration::from_secs(60),
        };
        let spend = ApiJudgeSpend::new(config);
        let first = spend
            .admit("endpoint", Some("session"))
            .expect("first call admitted");
        assert_eq!(
            spend.admit("endpoint", Some("session")).unwrap_err(),
            "API evaluator per-session concurrency limit reached"
        );
        drop(first);
        let second = spend
            .admit("endpoint", Some("session"))
            .expect("second token admitted");
        drop(second);
        assert_eq!(
            spend.admit("endpoint", Some("session")).unwrap_err(),
            "API evaluator rate limit reached"
        );

        let circuit = ApiJudgeSpend::new(ApiJudgeSpendConfig { burst: 4, ..config });
        circuit.complete("endpoint", Some("session"), true);
        circuit.complete("endpoint", Some("session"), true);
        assert_eq!(
            circuit.admit("endpoint", Some("session")).unwrap_err(),
            "API evaluator circuit is open"
        );
        assert_eq!(circuit.evaluator_errors.load(Ordering::Relaxed), 2);
        assert_eq!(circuit.circuit_rejections.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn spend_state_is_shared_across_endpoint_judges() {
        let spend = Arc::new(ApiJudgeSpend::new(ApiJudgeSpendConfig {
            max_concurrency: 1,
            ..ApiJudgeSpendConfig::default()
        }));
        let evaluator = || Evaluator::new(EvalConfig::default().llm_enabled(false)).unwrap();
        let first = DaemonApiJudge {
            evaluator: evaluator(),
            api_promotion: None,
            stamp: "first".to_string(),
            spend: spend.clone(),
        };
        let second = DaemonApiJudge {
            evaluator: evaluator(),
            api_promotion: None,
            stamp: "second".to_string(),
            spend,
        };

        let permit = first
            .spend
            .admit("first", Some("session-a"))
            .expect("first endpoint admitted");
        assert_eq!(
            second.spend.admit("second", Some("session-b")).unwrap_err(),
            "API evaluator concurrency limit reached"
        );
        drop(permit);
        assert_eq!(second.spend.attempted.load(Ordering::Relaxed), 2);
        assert_eq!(second.spend.admitted.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn baseline_traffic_cannot_consume_the_session_concurrency_reserve() {
        let spend = ApiJudgeSpend::new(ApiJudgeSpendConfig {
            max_concurrency: 2,
            ..ApiJudgeSpendConfig::default()
        });
        let baseline = spend
            .admit("endpoint-a", None)
            .expect("baseline slot admitted");
        assert_eq!(
            spend.admit("endpoint-b", None).unwrap_err(),
            "API evaluator session reserve is unavailable to unattributed traffic"
        );
        let session = spend
            .admit("endpoint-b", Some("session"))
            .expect("reserved session slot admitted");
        drop((baseline, session));
    }

    #[test]
    fn one_session_cannot_starve_a_peer_of_global_concurrency() {
        let spend = ApiJudgeSpend::new(ApiJudgeSpendConfig {
            max_concurrency: 4,
            ..ApiJudgeSpendConfig::default()
        });
        let first = spend.admit("endpoint", Some("greedy")).unwrap();
        let second = spend.admit("endpoint", Some("greedy")).unwrap();
        let third = spend.admit("endpoint", Some("greedy")).unwrap();
        assert_eq!(
            spend.admit("endpoint", Some("greedy")).unwrap_err(),
            "API evaluator per-session concurrency limit reached"
        );
        let peer = spend
            .admit("endpoint", Some("peer"))
            .expect("peer retains one global evaluator slot");
        drop((first, second, third, peer));
    }

    #[test]
    fn rate_and_circuit_state_are_partitioned_by_endpoint_and_session() {
        let spend = ApiJudgeSpend::new(ApiJudgeSpendConfig {
            max_concurrency: 4,
            rate_per_minute: 1,
            burst: 1,
            error_threshold: 1,
            circuit_cooldown: Duration::from_secs(60),
        });
        drop(spend.admit("a", None).expect("first baseline token"));
        assert_eq!(
            spend.admit("a", None).unwrap_err(),
            "API evaluator rate limit reached"
        );
        drop(spend.admit("b", None).expect("other endpoint token"));
        drop(
            spend
                .admit("a", Some("session-a"))
                .expect("session token partition"),
        );
        spend.complete("a", Some("session-a"), true);
        assert_eq!(
            spend.admit("a", Some("session-a")).unwrap_err(),
            "API evaluator circuit is open"
        );
        drop(
            spend
                .admit("a", Some("session-b"))
                .expect("other session circuit partition"),
        );
    }

    #[test]
    fn session_intent_changes_the_coverage_regime() {
        let judge = DaemonApiJudge {
            evaluator: Evaluator::new(EvalConfig::default().llm_enabled(false)).unwrap(),
            api_promotion: None,
            stamp: "base".to_string(),
            spend: Arc::new(ApiJudgeSpend::new(ApiJudgeSpendConfig::default())),
        };
        let mut first = api_summary("api", false);
        first.session_fingerprint = Some("session".to_string());
        first.session_intent = Some("inspect deployments".to_string());
        let mut edited = first.clone();
        edited.session_intent = Some("apply deployments".to_string());
        assert_ne!(judge.request_stamp(&first), judge.request_stamp(&edited));
    }

    #[test]
    fn session_revision_alone_changes_evaluator_and_cache_regime() {
        let judge = DaemonApiJudge {
            evaluator: Evaluator::new(EvalConfig::default().llm_enabled(false)).unwrap(),
            api_promotion: None,
            stamp: "base".to_string(),
            spend: Arc::new(ApiJudgeSpend::new(ApiJudgeSpendConfig::default())),
        };
        let mut first = api_summary("api", false);
        first.session_fingerprint = Some("session".to_string());
        first.session_revision = Some("revision-one".to_string());
        first.session_intent = Some("manage deployments".to_string());
        let unchanged = first.clone();
        let mut edited = first.clone();
        edited.session_revision = Some("revision-two".to_string());
        assert_eq!(judge.request_stamp(&first), judge.request_stamp(&unchanged));
        assert_eq!(first.stable_text(), unchanged.stable_text());
        assert_ne!(judge.request_stamp(&first), judge.request_stamp(&edited));
        assert_ne!(first.stable_text(), edited.stable_text());
    }
}
