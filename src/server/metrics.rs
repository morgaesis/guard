//! Read-only metrics and health surface for the daemon.
//!
//! The daemon is a long-running process with per-principal concurrency
//! semaphores and in-memory registries but no scrapeable telemetry. This module
//! adds an optional, off-by-default listener that exposes:
//!
//! - `GET /healthz` - 200 liveness;
//! - `GET /metrics` - Prometheus text exposition (no extra dependency, just
//!   formatted text);
//! - `GET /metrics.json` - the same numbers as JSON.
//!
//! # Source of truth
//!
//! Counters are derived from the same decision points that emit audit events:
//! [`Metrics`] implements [`guard::audit::EventObserver`], and the daemon
//! installs it as the process-global observer, so every event that is audited
//! is also counted at the one [`guard::audit::emit`] choke point. Gauges
//! (held-approval backlog, provisional backlog, concurrency in-flight) are read
//! from the live registries and semaphores at scrape time, off the request hot
//! path.
//!
//! # Non-leak invariant
//!
//! The surface exposes **zero** sensitive content: no command text, no
//! arguments, no secret names, no reasons, no argv. Every counter and gauge is a
//! fixed-shape number, and the only labels are compile-time constants
//! (`outcome="allowed"`, etc.). The observer receives only a typed
//! [`guard::audit::AuditKind`], never any free-text field, so no request detail
//! can reach the exposition. This is enforced by test.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use guard::audit::{AuditKind, EventObserver};
use guard::gating::provisional::ProvisionalStatus;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{header, Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;

use super::ServerState;

/// Bound the header section a single connection can force the server to buffer.
/// The metrics surface takes no request body, so this is the only input bound
/// needed beyond hyper's own limits.
const MAX_HTTP_HEADER_SECTION: usize = 16 * 1024;

/// Bound the time spent reading one request head so a stalled (slowloris-style)
/// connection cannot hold a task open indefinitely.
const HTTP_REQUEST_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Process-wide counters derived from the audit emission choke point. Every
/// field is a lock-free atomic; the hot path only ever performs one relaxed
/// increment, and the scrape path only performs relaxed loads. No command text,
/// argument, secret name, or reason is ever stored - only fixed-shape numeric
/// counters keyed by outcome.
#[derive(Default)]
pub(super) struct Metrics {
    // Command policy decisions by outcome.
    decisions_allowed: AtomicU64,
    decisions_denied: AtomicU64,
    decisions_held: AtomicU64,
    decisions_exec_failed: AtomicU64,
    // Consequence / auto-revert lifecycle.
    provisional_armed: AtomicU64,
    provisional_confirmed: AtomicU64,
    provisional_reverted: AtomicU64,
    revert_failed: AtomicU64,
    // Operator-approval resolution (a held command moving to a terminal state).
    approvals_approved: AtomicU64,
    approvals_denied: AtomicU64,
    approvals_expired: AtomicU64,
    // Secret resolution failures. No audit kind carries this outcome, so it is
    // incremented at the resolution call site (see `record_secret_resolution_failure`).
    secret_resolution_failures: AtomicU64,
    // Every audited event, regardless of kind.
    audit_events_total: AtomicU64,
}

/// A consistent read of every counter for rendering and tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct MetricsSnapshot {
    pub decisions_allowed: u64,
    pub decisions_denied: u64,
    pub decisions_held: u64,
    pub decisions_exec_failed: u64,
    pub provisional_armed: u64,
    pub provisional_confirmed: u64,
    pub provisional_reverted: u64,
    pub revert_failed: u64,
    pub approvals_approved: u64,
    pub approvals_denied: u64,
    pub approvals_expired: u64,
    pub secret_resolution_failures: u64,
    pub audit_events_total: u64,
}

impl Metrics {
    /// Record a secret-resolution failure. Incremented at the resolution call
    /// site because no [`AuditKind`] represents this outcome; a failed secret
    /// lookup denies the request without a distinct audit event.
    pub(super) fn record_secret_resolution_failure(&self) {
        self.secret_resolution_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            decisions_allowed: self.decisions_allowed.load(Ordering::Relaxed),
            decisions_denied: self.decisions_denied.load(Ordering::Relaxed),
            decisions_held: self.decisions_held.load(Ordering::Relaxed),
            decisions_exec_failed: self.decisions_exec_failed.load(Ordering::Relaxed),
            provisional_armed: self.provisional_armed.load(Ordering::Relaxed),
            provisional_confirmed: self.provisional_confirmed.load(Ordering::Relaxed),
            provisional_reverted: self.provisional_reverted.load(Ordering::Relaxed),
            revert_failed: self.revert_failed.load(Ordering::Relaxed),
            approvals_approved: self.approvals_approved.load(Ordering::Relaxed),
            approvals_denied: self.approvals_denied.load(Ordering::Relaxed),
            approvals_expired: self.approvals_expired.load(Ordering::Relaxed),
            secret_resolution_failures: self.secret_resolution_failures.load(Ordering::Relaxed),
            audit_events_total: self.audit_events_total.load(Ordering::Relaxed),
        }
    }
}

impl EventObserver for Metrics {
    fn observe(&self, kind: AuditKind) {
        self.audit_events_total.fetch_add(1, Ordering::Relaxed);
        let counter = match kind {
            AuditKind::Allowed => &self.decisions_allowed,
            AuditKind::Denied => &self.decisions_denied,
            AuditKind::Held => &self.decisions_held,
            AuditKind::ExecFailed => &self.decisions_exec_failed,
            AuditKind::Provisional => &self.provisional_armed,
            AuditKind::Confirm => &self.provisional_confirmed,
            AuditKind::Revert => &self.provisional_reverted,
            AuditKind::RevertFailed => &self.revert_failed,
            AuditKind::Approved | AuditKind::ApprovedExecuted => &self.approvals_approved,
            AuditKind::DeniedHold => &self.approvals_denied,
            AuditKind::ApprovalExpired => &self.approvals_expired,
            // Every other kind is captured only in the events total above.
            _ => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// Gauges read from the live registries and semaphores at scrape time.
struct Gauges {
    approvals_pending: u64,
    provisionals_armed: u64,
    provisionals_outstanding: u64,
    handler_in_flight: u64,
    handler_capacity: u64,
    evaluator_in_flight: u64,
    evaluator_capacity: u64,
    admission_active_principals: u64,
}

async fn read_gauges(state: &ServerState) -> Gauges {
    let approvals_pending = state
        .approvals
        .read()
        .await
        .list()
        .into_iter()
        .filter(|approval| approval.status.is_pending())
        .count() as u64;
    let provisionals = state.provisional.read().await.list();
    let provisionals_armed = provisionals
        .iter()
        .filter(|row| row.status == ProvisionalStatus::Armed)
        .count() as u64;
    let provisionals_outstanding = provisionals
        .iter()
        .filter(|row| row.status.is_outstanding())
        .count() as u64;
    let concurrency = state.command_admission.concurrency_gauges();
    Gauges {
        approvals_pending,
        provisionals_armed,
        provisionals_outstanding,
        handler_in_flight: concurrency
            .handler_capacity
            .saturating_sub(concurrency.handler_available),
        handler_capacity: concurrency.handler_capacity,
        evaluator_in_flight: concurrency
            .evaluator_capacity
            .saturating_sub(concurrency.evaluator_available),
        evaluator_capacity: concurrency.evaluator_capacity,
        admission_active_principals: concurrency.active_principal_scopes,
    }
}

/// Render the Prometheus text exposition. Every metric carries a `# HELP` and
/// `# TYPE` line; labels are compile-time constants only.
async fn render_prometheus(state: &ServerState) -> String {
    let counters = state.metrics.snapshot();
    let gauges = read_gauges(state).await;
    let admission = state.command_admission.snapshot();
    let mut out = String::with_capacity(4096);

    out.push_str("# HELP guard_decisions_total Command policy decisions by outcome.\n");
    out.push_str("# TYPE guard_decisions_total counter\n");
    let _ = std::fmt::Write::write_fmt(
        &mut out,
        format_args!(
            "guard_decisions_total{{outcome=\"allowed\"}} {}\n\
             guard_decisions_total{{outcome=\"denied\"}} {}\n\
             guard_decisions_total{{outcome=\"held\"}} {}\n\
             guard_decisions_total{{outcome=\"exec_failed\"}} {}\n",
            counters.decisions_allowed,
            counters.decisions_denied,
            counters.decisions_held,
            counters.decisions_exec_failed,
        ),
    );

    metric(
        &mut out,
        "guard_provisional_armed_total",
        "counter",
        "Consequence-gated commands armed behind an auto-revert envelope.",
        counters.provisional_armed,
    );
    metric(
        &mut out,
        "guard_provisional_confirmed_total",
        "counter",
        "Provisional executions the operator confirmed (kept).",
        counters.provisional_confirmed,
    );
    metric(
        &mut out,
        "guard_provisional_reverted_total",
        "counter",
        "Provisional executions rolled back by the auto-revert.",
        counters.provisional_reverted,
    );
    metric(
        &mut out,
        "guard_revert_failed_total",
        "counter",
        "Auto-reverts that were attempted but failed.",
        counters.revert_failed,
    );
    metric(
        &mut out,
        "guard_approvals_approved_total",
        "counter",
        "Held commands an operator approved.",
        counters.approvals_approved,
    );
    metric(
        &mut out,
        "guard_approvals_denied_total",
        "counter",
        "Held commands an operator denied.",
        counters.approvals_denied,
    );
    metric(
        &mut out,
        "guard_approvals_expired_total",
        "counter",
        "Held commands that expired with no operator decision (fail-closed).",
        counters.approvals_expired,
    );
    metric(
        &mut out,
        "guard_secret_resolution_failures_total",
        "counter",
        "Requested secret injections that could not be resolved.",
        counters.secret_resolution_failures,
    );
    metric(
        &mut out,
        "guard_audit_events_total",
        "counter",
        "Total audit events emitted through the daemon.",
        counters.audit_events_total,
    );

    metric(
        &mut out,
        "guard_approvals_pending",
        "gauge",
        "Held approvals currently awaiting an operator decision.",
        gauges.approvals_pending,
    );
    metric(
        &mut out,
        "guard_provisionals_armed",
        "gauge",
        "Provisional executions currently inside their auto-revert window.",
        gauges.provisionals_armed,
    );
    metric(
        &mut out,
        "guard_provisionals_outstanding",
        "gauge",
        "Provisional executions still needing attention (armed, reverting, failed, or awaiting a decision).",
        gauges.provisionals_outstanding,
    );
    metric(
        &mut out,
        "guard_handler_in_flight",
        "gauge",
        "Command handler permits currently in use across all principals.",
        gauges.handler_in_flight,
    );
    metric(
        &mut out,
        "guard_handler_capacity",
        "gauge",
        "Global command handler concurrency capacity.",
        gauges.handler_capacity,
    );
    metric(
        &mut out,
        "guard_evaluator_in_flight",
        "gauge",
        "Evaluator permits currently in use across all principals.",
        gauges.evaluator_in_flight,
    );
    metric(
        &mut out,
        "guard_evaluator_capacity",
        "gauge",
        "Global evaluator concurrency capacity.",
        gauges.evaluator_capacity,
    );
    metric(
        &mut out,
        "guard_admission_active_principals",
        "gauge",
        "Distinct principals with live admission state.",
        gauges.admission_active_principals,
    );

    // Admission-control telemetry (evaluator call and error counts) sourced
    // from the existing per-daemon admission counters.
    metric(
        &mut out,
        "guard_evaluator_attempted_total",
        "counter",
        "Evaluator admissions attempted.",
        admission.evaluator_attempted,
    );
    metric(
        &mut out,
        "guard_evaluator_admitted_total",
        "counter",
        "Evaluator admissions granted.",
        admission.evaluator_admitted,
    );
    metric(
        &mut out,
        "guard_evaluator_errors_total",
        "counter",
        "Evaluator calls that returned a provider error.",
        admission.evaluator_errors,
    );
    metric(
        &mut out,
        "guard_evaluator_rate_limited_total",
        "counter",
        "Evaluator admissions refused by the per-principal rate limit.",
        admission.evaluator_rate_limited,
    );
    metric(
        &mut out,
        "guard_evaluator_circuit_rejections_total",
        "counter",
        "Evaluator admissions refused by an open circuit breaker.",
        admission.evaluator_circuit_rejections,
    );
    metric(
        &mut out,
        "guard_handler_rejected_total",
        "counter",
        "Command handler admissions refused (concurrency or capacity).",
        admission.handler_rejected,
    );

    out
}

fn metric(out: &mut String, name: &str, kind: &str, help: &str, value: u64) {
    let _ = std::fmt::Write::write_fmt(
        out,
        format_args!("# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"),
    );
}

/// Render the same numbers as JSON for callers that prefer structured output.
async fn render_json(state: &ServerState) -> String {
    let counters = state.metrics.snapshot();
    let gauges = read_gauges(state).await;
    let admission = state.command_admission.snapshot();
    let value = serde_json::json!({
        "decisions": {
            "allowed": counters.decisions_allowed,
            "denied": counters.decisions_denied,
            "held": counters.decisions_held,
            "exec_failed": counters.decisions_exec_failed,
        },
        "provisional": {
            "armed_total": counters.provisional_armed,
            "confirmed_total": counters.provisional_confirmed,
            "reverted_total": counters.provisional_reverted,
            "revert_failed_total": counters.revert_failed,
            "armed": gauges.provisionals_armed,
            "outstanding": gauges.provisionals_outstanding,
        },
        "approvals": {
            "approved_total": counters.approvals_approved,
            "denied_total": counters.approvals_denied,
            "expired_total": counters.approvals_expired,
            "pending": gauges.approvals_pending,
        },
        "secret_resolution_failures_total": counters.secret_resolution_failures,
        "audit_events_total": counters.audit_events_total,
        "concurrency": {
            "handler_in_flight": gauges.handler_in_flight,
            "handler_capacity": gauges.handler_capacity,
            "evaluator_in_flight": gauges.evaluator_in_flight,
            "evaluator_capacity": gauges.evaluator_capacity,
            "active_principals": gauges.admission_active_principals,
        },
        "admission": {
            "evaluator_attempted_total": admission.evaluator_attempted,
            "evaluator_admitted_total": admission.evaluator_admitted,
            "evaluator_errors_total": admission.evaluator_errors,
            "evaluator_rate_limited_total": admission.evaluator_rate_limited,
            "evaluator_circuit_rejections_total": admission.evaluator_circuit_rejections,
            "handler_rejected_total": admission.handler_rejected,
        },
    });
    serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string())
}

/// Serve one metrics/health request. Only `GET` is accepted; unknown paths 404.
/// No request body is ever read, so there is no body-size or injection surface.
async fn handle_request(
    request: Request<hyper::body::Incoming>,
    state: &ServerState,
) -> Response<Full<Bytes>> {
    if request.method() != Method::GET {
        return text_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "text/plain; charset=utf-8",
            "method not allowed; GET a metrics or health endpoint\n",
        );
    }
    match request.uri().path() {
        "/healthz" | "/health" => {
            text_response(StatusCode::OK, "text/plain; charset=utf-8", "ok\n")
        }
        "/metrics" => text_response(
            StatusCode::OK,
            "text/plain; version=0.0.4; charset=utf-8",
            &render_prometheus(state).await,
        ),
        "/metrics.json" => text_response(
            StatusCode::OK,
            "application/json",
            &render_json(state).await,
        ),
        _ => text_response(
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            "not found; try /healthz, /metrics, or /metrics.json\n",
        ),
    }
}

fn text_response(status: StatusCode, content_type: &str, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .body(Full::new(Bytes::from(body.to_owned())))
        .expect("static response parts are valid")
}

/// Serve the metrics/health surface on an already-bound listener. Returns only
/// on a fatal accept error, mirroring the other daemon listeners.
pub(super) async fn serve(listener: TcpListener, state: ServerState) -> Result<()> {
    let state = Arc::new(state);
    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(error = %error, "metrics listener accept failed");
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            let service = service_fn(move |request| {
                let state = state.clone();
                async move { Ok::<_, std::convert::Infallible>(handle_request(request, &state).await) }
            });
            let mut builder = auto::Builder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(HTTP_REQUEST_READ_TIMEOUT)
                .max_buf_size(MAX_HTTP_HEADER_SECTION);
            if let Err(error) = builder
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                tracing::debug!(error = %error, "metrics connection ended with error");
            }
        });
    }
}

/// Bind the metrics/health listener. A bind failure is returned to the caller
/// so an explicitly requested listener refuses to start loudly.
pub(super) async fn bind(addr: SocketAddr) -> Result<TcpListener> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind metrics/health listener on {addr}"))?;
    let bound = listener.local_addr().unwrap_or(addr);
    if !bound.ip().is_loopback() {
        tracing::warn!(
            address = %bound,
            "metrics/health listener bound to a non-loopback address; it exposes only coarse \
             counters and is unauthenticated. Bind it to 127.0.0.1 or a trusted network only."
        );
    }
    tracing::info!(address = %bound, "metrics/health listener listening");
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::tests::config_for_proposal_test;
    use crate::server::ServerContext;
    use guard::audit::AuditEvent;
    use std::sync::OnceLock;

    /// A `ServerContext` whose `state.metrics` is the process-global audit
    /// observer, so events emitted through it are counted deterministically
    /// regardless of test ordering. The observer is installed once per test
    /// binary; the returned context reuses that same `Arc`.
    fn observer_backed_context() -> ServerContext {
        static SHARED: OnceLock<Arc<Metrics>> = OnceLock::new();
        let shared = SHARED
            .get_or_init(|| {
                let metrics = Arc::new(Metrics::default());
                guard::audit::install_event_observer(metrics.clone());
                metrics
            })
            .clone();
        let mut ctx = config_for_proposal_test();
        ctx.state.metrics = shared;
        ctx
    }

    #[test]
    fn counters_increment_by_outcome() {
        let metrics = Metrics::default();
        metrics.observe(AuditKind::Allowed);
        metrics.observe(AuditKind::Allowed);
        metrics.observe(AuditKind::Denied);
        metrics.observe(AuditKind::Held);
        metrics.observe(AuditKind::ExecFailed);
        metrics.observe(AuditKind::Provisional);
        metrics.observe(AuditKind::Confirm);
        metrics.observe(AuditKind::Revert);
        metrics.observe(AuditKind::RevertFailed);
        metrics.observe(AuditKind::Approved);
        metrics.observe(AuditKind::DeniedHold);
        metrics.observe(AuditKind::ApprovalExpired);
        // A kind with no dedicated counter still lands in the events total.
        metrics.observe(AuditKind::SessionGrant);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.decisions_allowed, 2);
        assert_eq!(snapshot.decisions_denied, 1);
        assert_eq!(snapshot.decisions_held, 1);
        assert_eq!(snapshot.decisions_exec_failed, 1);
        assert_eq!(snapshot.provisional_armed, 1);
        assert_eq!(snapshot.provisional_confirmed, 1);
        assert_eq!(snapshot.provisional_reverted, 1);
        assert_eq!(snapshot.revert_failed, 1);
        assert_eq!(snapshot.approvals_approved, 1);
        assert_eq!(snapshot.approvals_denied, 1);
        assert_eq!(snapshot.approvals_expired, 1);
        assert_eq!(snapshot.audit_events_total, 13);
    }

    #[tokio::test]
    async fn healthz_returns_200() {
        let ctx = observer_backed_context();
        let response = handle_get("/healthz", &ctx.state).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics_is_valid_prometheus_with_expected_names() {
        let ctx = observer_backed_context();
        ctx.state.metrics.observe(AuditKind::Allowed);
        let body = render_prometheus(&ctx.state).await;

        for name in [
            "guard_decisions_total",
            "guard_approvals_pending",
            "guard_provisionals_armed",
            "guard_handler_capacity",
            "guard_evaluator_capacity",
            "guard_audit_events_total",
        ] {
            assert!(body.contains(name), "missing metric {name} in:\n{body}");
        }
        // The labelled counter families must render `# TYPE` before samples.
        assert!(body.contains("# TYPE guard_decisions_total counter"));
        assert!(body.contains("guard_decisions_total{outcome=\"allowed\"}"));

        // Every non-comment, non-blank line must be `name value` or
        // `name{labels} value` - i.e. exactly one trailing numeric field.
        for line in body.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let value = line.rsplit(' ').next().expect("a sample line has a value");
            assert!(
                value.parse::<u64>().is_ok(),
                "sample line is not `name value`: {line}"
            );
        }
    }

    #[tokio::test]
    async fn unknown_path_and_non_get_are_rejected() {
        let ctx = observer_backed_context();
        assert_eq!(
            handle_get("/nope", &ctx.state).await.status(),
            StatusCode::NOT_FOUND
        );
    }

    /// Non-leak invariant: driving a denied secret-ish argv through the audit
    /// choke point counts the denial but never lets any of that text reach the
    /// `/metrics` or `/metrics.json` exposition.
    #[tokio::test]
    async fn scrape_never_leaks_command_or_secret_text() {
        let ctx = observer_backed_context();
        let before = ctx.state.metrics.snapshot();

        let secret_argv = "SUPERSECRET-TOKEN-9f3ac1";
        let _ = ctx.emit_audit(
            AuditEvent::new(AuditKind::Denied)
                .caller("uid=1000")
                .cmd(format!("cat /proc/self/environ {secret_argv}"))
                .reason(format!("credential preflight denied: {secret_argv}")),
        );

        let after = ctx.state.metrics.snapshot();
        assert!(
            after.decisions_denied > before.decisions_denied,
            "the denial must be counted at the audit choke point"
        );

        let prometheus = render_prometheus(&ctx.state).await;
        let json = render_json(&ctx.state).await;
        assert!(
            !prometheus.contains(secret_argv),
            "prometheus exposition leaked request text:\n{prometheus}"
        );
        assert!(
            !json.contains(secret_argv),
            "json exposition leaked request text:\n{json}"
        );
        assert!(!prometheus.contains("/proc/self/environ"));
        assert!(!json.contains("/proc/self/environ"));
    }

    /// Route through the same match the hyper service uses, without needing to
    /// forge an `Incoming` body.
    async fn handle_get(path: &str, state: &ServerState) -> Response<Full<Bytes>> {
        match path {
            "/healthz" | "/health" => {
                text_response(StatusCode::OK, "text/plain; charset=utf-8", "ok\n")
            }
            "/metrics" => text_response(
                StatusCode::OK,
                "text/plain; version=0.0.4; charset=utf-8",
                &render_prometheus(state).await,
            ),
            "/metrics.json" => text_response(
                StatusCode::OK,
                "application/json",
                &render_json(state).await,
            ),
            _ => text_response(
                StatusCode::NOT_FOUND,
                "text/plain; charset=utf-8",
                "not found\n",
            ),
        }
    }
}
