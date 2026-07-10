//! The TLS-terminating proxy server loop. Accepts the agent's brokered
//! connection, terminates TLS with the ephemeral leaf, parses each request into
//! an [`ApiOp`] via the attached [`ProtocolConfig`], applies the operator
//! [`ApiPolicy`], and either rejects it at the proxy (deny/hold) or
//! re-originates it to the real apiserver with the operator's credentials.
//! Secret reads are buffered, JSON-parsed, and redacted before the response
//! reaches the client; everything else streams through. Every
//! protocol-specific question (parsing, outright denials, redaction, revert
//! synthesis) routes through the [`ProtocolConfig`], so a different protocol
//! swaps in by constructing the proxy with a different config.
//!
//! A recoverable write the policy allows is wrapped in an auto-revert envelope
//! when the daemon's consequence gate is active: the proxy snapshots the prior
//! object (or notes the created one) and hands a synthesized revert to the
//! [`GateSink`], so the operator's `guard confirm` keeps it and the sweeper rolls
//! it back otherwise. Interactive subresources (`exec`/`attach`/`portforward`)
//! and Secret `watch`es are denied: their streams cannot be redacted or gated
//! per object.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use futures::TryStreamExt;
use http_body_util::{combinators::BoxBody, BodyExt, Full, Limited, StreamBody};
use hyper::body::{Bytes, Frame, Incoming};
use hyper::service::service_fn;
use hyper::{header, HeaderMap, Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;

use super::gate::{ApiMutation, GateSink, HoldDecision};
use super::k8s::{ApiOp, Verb};
use super::k8s_protocol::KubernetesProtocol;
use super::policy::{ApiAction, ApiPolicy};
use super::protocol::ProtocolConfig;
use super::tls::ProxyTls;
use super::upstream::Upstream;

/// Cap on a forwarded request body. Manifests are small; this bounds memory and
/// denies an oversized body from a misbehaving client.
const MAX_REQ_BODY: usize = 16 * 1024 * 1024;

/// How often the policy file is checked for changes (the operator "slow clock").
const POLICY_RELOAD_SECS: u64 = 5;

type ProxyBody = BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

/// A configured Kubernetes API proxy: TLS identity, upstream connection, and the
/// hot-reloaded operator policy. Hosted by the daemon alongside the gate socket.
pub struct KubeProxy {
    listen: SocketAddr,
    proxy_url: String,
    tls: ProxyTls,
    upstream: Upstream,
    /// Answers every protocol-specific question; the loop itself is
    /// protocol-agnostic.
    protocol: Arc<dyn ProtocolConfig>,
    policy: Arc<RwLock<ApiPolicy>>,
    policy_path: Option<PathBuf>,
    /// The operator's real kubeconfig path, used by the daemon to build the
    /// `kubectl` revert when an auto-revert envelope fires.
    real_kubeconfig: PathBuf,
    /// Bridge to the daemon's consequence machinery, attached before serving.
    /// When present, recoverable writes are wrapped in an auto-revert envelope.
    gate: OnceLock<Arc<dyn GateSink>>,
    /// Resources this proxy forwarded a create for (and armed an auto-revert on),
    /// mapped to the revert handle. This is evidence-based provenance: a later
    /// delete of a resource in this set is guard's own creation being cleaned up
    /// (e.g. a Helm post-install hook deleting its check resource), so it is
    /// contained rather than an unrecorded destructive delete. Entries are scoped
    /// to the creating connection and removed when their revert resolves.
    created: Mutex<CreatedRegistry>,
    /// Monotonic per-connection id, assigned in the accept loop, so a created
    /// resource's provenance is scoped to the connection that created it.
    next_conn: AtomicU64,
}

/// Identity of a resource the proxy tracks as guard-created, for delete
/// provenance matching.
///
/// The `conn` field scopes provenance to the connection that created the
/// resource. The proxy authenticates no caller -- its brokered kubeconfig is
/// credential-free (`with_no_client_auth`) -- so a single TLS/HTTP connection is
/// the finest caller identity available. A delete arriving on a different
/// connection than the create never matches, so one agent cannot use provenance
/// to bypass policy and delete a resource another agent created. Kubernetes
/// clients (client-go, used by kubectl/helm) negotiate HTTP/2 and multiplex a
/// process's whole session over one connection, so a legitimate same-process
/// create-then-delete (e.g. a Helm post-install hook) still matches.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CreatedKey {
    conn: u64,
    group: String,
    resource: String,
    namespace: Option<String>,
    name: String,
}

/// Tracks resources the proxy forwarded a create for (and armed an auto-revert
/// on), each mapped to its auto-revert handle. Pure: no clock, no I/O.
#[derive(Debug, Default)]
struct CreatedRegistry {
    items: HashMap<CreatedKey, String>,
}

impl CreatedRegistry {
    /// Record a created resource against its auto-revert handle.
    fn remember(&mut self, key: CreatedKey, handle: String) {
        self.items.insert(key, handle);
    }

    /// Consume and return the auto-revert handle for a created resource, if the
    /// delete's key (connection included) matches a recorded create. Consuming
    /// ensures a resource is only ever contained-deleted once.
    fn take(&mut self, key: &CreatedKey) -> Option<String> {
        self.items.remove(key)
    }

    /// Drop any provenance entry whose auto-revert resolved (confirmed or
    /// reverted). Without this a create record would live for the rest of the
    /// process, so a delete of a same-named resource an operator later recreated
    /// outside guard would still match a stale entry and bypass policy.
    fn forget_by_handle(&mut self, handle: &str) {
        self.items.retain(|_, h| h != handle);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.items.len()
    }
}

impl KubeProxy {
    /// Assemble a Kubernetes proxy. `policy_path` (when set) is hot-reloaded
    /// while serving; when unset, `policy` is used as-is (typically a
    /// default-deny).
    pub fn new(
        listen: SocketAddr,
        tls: ProxyTls,
        upstream: Upstream,
        policy: ApiPolicy,
        policy_path: Option<PathBuf>,
        real_kubeconfig: PathBuf,
    ) -> Self {
        Self::with_protocol(
            Arc::new(KubernetesProtocol),
            listen,
            tls,
            upstream,
            policy,
            policy_path,
            real_kubeconfig,
        )
    }

    /// Assemble a proxy over an explicit protocol plug-in. The gating spine
    /// (policy, hold/approval, auto-revert, provenance) is shared; only the
    /// protocol's own classification differs.
    pub fn with_protocol(
        protocol: Arc<dyn ProtocolConfig>,
        listen: SocketAddr,
        tls: ProxyTls,
        upstream: Upstream,
        policy: ApiPolicy,
        policy_path: Option<PathBuf>,
        real_kubeconfig: PathBuf,
    ) -> Self {
        let proxy_url = format!("https://127.0.0.1:{}", listen.port());
        Self {
            listen,
            proxy_url,
            tls,
            upstream,
            protocol,
            policy: Arc::new(RwLock::new(policy)),
            policy_path,
            real_kubeconfig,
            gate: OnceLock::new(),
            created: Mutex::new(CreatedRegistry::default()),
            next_conn: AtomicU64::new(1),
        }
    }

    /// Drop provenance for a resolved auto-revert. Called by the daemon when a
    /// proxy-armed create-revert is confirmed or reverted, so a create record
    /// cannot outlive the revert window it was tied to.
    pub fn forget_created_by_handle(&self, handle: &str) {
        self.created.lock().unwrap().forget_by_handle(handle);
    }

    /// Attach the daemon's consequence bridge before serving. Idempotent; a
    /// second call is ignored.
    pub fn attach_gate(&self, sink: Arc<dyn GateSink>) {
        let _ = self.gate.set(sink);
    }

    /// The operator's real kubeconfig path (for building reverts).
    pub fn real_kubeconfig(&self) -> &std::path::Path {
        &self.real_kubeconfig
    }

    pub fn listen(&self) -> SocketAddr {
        self.listen
    }

    /// The loopback URL agents put in their brokered kubeconfig.
    pub fn proxy_url(&self) -> &str {
        &self.proxy_url
    }

    /// The agent-facing brokered kubeconfig (points at the proxy, no credential).
    pub fn brokered_kubeconfig(&self) -> String {
        super::kubeconfig::brokered_kubeconfig(&self.proxy_url, &self.tls.ca_data_b64())
    }

    /// Accept loop: terminate TLS and serve each connection. Returns only on a
    /// fatal bind error, so the daemon's listener supervision restarts the
    /// process the same way the gate socket does.
    pub async fn serve(self: Arc<Self>) -> Result<()> {
        let listener = TcpListener::bind(self.listen)
            .await
            .with_context(|| format!("bind kube-proxy listener on {}", self.listen))?;
        let acceptor = TlsAcceptor::from(self.tls.server_config());
        tracing::info!(
            "guard kube-proxy listening on https://{} -> {}",
            self.listen,
            self.upstream.base()
        );

        if let Some(path) = self.policy_path.clone() {
            let policy = self.policy.clone();
            tokio::spawn(async move { policy_reloader(path, policy).await });
        }

        loop {
            let (tcp, _peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!("kube-proxy accept error: {}", e);
                    continue;
                }
            };
            let acceptor = acceptor.clone();
            let me = self.clone();
            // A per-connection id scopes delete provenance to the connection that
            // created a resource (the proxy authenticates no caller).
            let conn_id = self.next_conn.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(tcp).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!("kube-proxy TLS handshake failed: {}", e);
                        return;
                    }
                };
                let io = TokioIo::new(tls_stream);
                let svc = service_fn(move |req| {
                    let me = me.clone();
                    async move { Ok::<_, std::convert::Infallible>(me.route(req, conn_id).await) }
                });
                if let Err(e) = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await
                {
                    tracing::debug!("kube-proxy connection error: {}", e);
                }
            });
        }
    }

    /// Classify and dispatch one request. Always returns a response (never errors
    /// the connection); upstream and policy failures become HTTP status bodies.
    async fn route(&self, req: Request<Incoming>, conn_id: u64) -> Response<ProxyBody> {
        let method = req.method().clone();
        let path = req.uri().path().to_string();
        let query = req.uri().query().unwrap_or("").to_string();

        // The gate must classify exactly the path the upstream will serve.
        // Re-origination normalizes dot segments (including their
        // percent-encoded forms) and an upstream router may decode encoded
        // separators, so such a path would be gated as one request and served
        // as another; reject it before parsing.
        if path_alters_on_forward(&path) {
            return status_resp(
                StatusCode::FORBIDDEN,
                "guard kube-proxy: path with dot segments or encoded separators is not forwarded",
                "Forbidden",
            );
        }

        let Some(op) = self.protocol.parse_op(method.as_str(), &path, &query) else {
            // Non-resource paths: discovery, /version, /openapi, /healthz. Clients
            // need these. Allow safe reads; block anything else.
            if method == Method::GET || method == Method::HEAD {
                return self.forward(req, &path, &query, false, None, conn_id).await;
            }
            return status_resp(
                StatusCode::FORBIDDEN,
                "guard kube-proxy: non-resource write blocked",
                "Forbidden",
            );
        };

        // Operations the protocol never forwards regardless of policy: streams
        // the request-level gate cannot inspect or redact per object.
        if let Some(reason) = self.protocol.deny_outright(&op) {
            return status_resp(StatusCode::FORBIDDEN, &reason, "Forbidden");
        }

        let label = format!("{} {}", op.verb.as_str(), path);

        // A delete of a resource guard itself created (and is still tracking for
        // auto-revert) in this process is contained cleanup — e.g. a Helm
        // post-install hook deleting its own check resource. Allow it and cancel
        // the now-moot create-revert, rather than holding or denying it like an
        // unrecorded destructive delete. Provenance is evidence-based: only a
        // resource the proxy forwarded a create for matches, so deletes of
        // resources with no creation record keep the strict policy handling.
        if op.verb == Verb::Delete && op.subresource.is_none() {
            if let Some(handle) = self.take_created_provenance(&op, conn_id) {
                tracing::info!(
                    target: "guard::kubeproxy",
                    "ALLOW {} (contained: guard-created this session, resolving auto-revert {})",
                    label,
                    handle
                );
                if let Some(gate) = self.gate.get() {
                    gate.resolve(&handle).await;
                }
                return self
                    .forward(req, &path, &query, false, Some(op), conn_id)
                    .await;
            }
        }

        let decision = self.policy.read().await.decide(&op);
        match decision.action {
            ApiAction::Deny => {
                tracing::info!(target: "guard::kubeproxy", "DENY {} ({})", label, decision.reason);
                status_resp(
                    StatusCode::FORBIDDEN,
                    &format!("guard kube-proxy denied {label}: {}", decision.reason),
                    "Forbidden",
                )
            }
            ApiAction::Hold => {
                // The request is parked here, still buffered, while the daemon
                // queues it for the operator (`guard approvals` / `guard approve`).
                // Only an explicit approval forwards it; a deny, expiry, capacity
                // refusal, or a proxy running without the daemon's consequence
                // gate all fail closed to a 403.
                let Some(gate) = self.gate.get() else {
                    tracing::info!(
                        target: "guard::kubeproxy",
                        "HOLD {} denied: no approval queue (--gate consequence is not active)",
                        label
                    );
                    return status_resp(
                        StatusCode::FORBIDDEN,
                        &format!(
                            "guard kube-proxy: {label} requires operator approval, but the daemon \
                             is running without --gate consequence (no approval queue); denied"
                        ),
                        "Forbidden",
                    );
                };
                tracing::info!(target: "guard::kubeproxy", "HOLD {} ({})", label, decision.reason);
                match gate.hold_request(&label, &decision.reason).await {
                    HoldDecision::Approved { handle } => {
                        // Redaction follows the protocol's classification, not
                        // the rule flag: a secret-material read that passes the
                        // gate (allowed or operator-approved) is always
                        // redacted, so no policy wording can leak values.
                        let redact = self.protocol.redactable_read(&op);
                        tracing::info!(
                            target: "guard::kubeproxy",
                            "ALLOW {} (operator approved hold {}){}",
                            label,
                            handle,
                            if redact { " (redacting)" } else { "" }
                        );
                        self.forward(req, &path, &query, redact, Some(op), conn_id)
                            .await
                    }
                    HoldDecision::Denied { reason } => {
                        tracing::info!(target: "guard::kubeproxy", "DENY {} (held: {})", label, reason);
                        status_resp(
                            StatusCode::FORBIDDEN,
                            &format!(
                                "guard kube-proxy: {label} held for operator approval: {reason}"
                            ),
                            "Forbidden",
                        )
                    }
                }
            }
            ApiAction::Allow => {
                let redact = self.protocol.redactable_read(&op);
                tracing::info!(target: "guard::kubeproxy", "ALLOW {}{}", label, if redact { " (redacting)" } else { "" });
                self.forward(req, &path, &query, redact, Some(op), conn_id)
                    .await
            }
        }
    }

    async fn forward(
        &self,
        req: Request<Incoming>,
        path: &str,
        query: &str,
        redact: bool,
        op: Option<ApiOp>,
        conn_id: u64,
    ) -> Response<ProxyBody> {
        match self
            .forward_inner(req, path, query, redact, op, conn_id)
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                tracing::warn!(target: "guard::kubeproxy", "upstream error for {path}: {e:#}");
                status_resp(
                    StatusCode::BAD_GATEWAY,
                    &format!("guard kube-proxy: upstream error: {e}"),
                    "InternalError",
                )
            }
        }
    }

    async fn forward_inner(
        &self,
        req: Request<Incoming>,
        path: &str,
        query: &str,
        redact: bool,
        op: Option<ApiOp>,
        conn_id: u64,
    ) -> Result<Response<ProxyBody>> {
        let (parts, body) = req.into_parts();

        let collected = Limited::new(body, MAX_REQ_BODY)
            .collect()
            .await
            .map_err(|e| anyhow!("read request body (limit {MAX_REQ_BODY}): {e}"))?
            .to_bytes();

        // A recoverable write we will wrap in an auto-revert envelope: fetch
        // the prior object first (when the protocol wants a restore-style
        // revert), then forward, then arm.
        let track_write = op
            .as_ref()
            .is_some_and(|o| self.gate.get().is_some() && self.protocol.tracks_write(o));
        let snapshot = if track_write && self.protocol.wants_prior_snapshot(op.as_ref().unwrap()) {
            self.fetch_prior_object(path).await
        } else {
            None
        };

        let url = if query.is_empty() {
            format!("{}{}", self.upstream.base(), path)
        } else {
            format!("{}{}?{}", self.upstream.base(), path, query)
        };

        let mut rb = self.upstream.client().request(parts.method.clone(), &url);
        for (name, value) in parts.headers.iter() {
            if is_hop_by_hop(name)
                || name == header::HOST
                || name == header::AUTHORIZATION
                || name == header::COOKIE
                || name == header::CONTENT_LENGTH
                || is_identity_header(name)
            {
                continue;
            }
            // For a redacted Secret read we force JSON so the body is parseable;
            // drop the client's Accept and set our own below.
            if redact && name == header::ACCEPT {
                continue;
            }
            rb = rb.header(name, value);
        }
        if redact {
            rb = rb.header(header::ACCEPT, "application/json");
        }
        if let Some(token) = self.upstream.bearer() {
            rb = rb.bearer_auth(token);
        } else if let Some((user, pass)) = self.upstream.basic_auth() {
            rb = rb.basic_auth(user, Some(pass));
        }
        if !collected.is_empty() {
            rb = rb.body(collected);
        }

        let upstream_resp = rb.send().await.context("forward to apiserver")?;
        let status = upstream_resp.status();
        let upstream_headers = upstream_resp.headers().clone();

        let mut builder = Response::builder().status(status);
        if let Some(hdrs) = builder.headers_mut() {
            for (name, value) in upstream_headers.iter() {
                // Strip hop-by-hop and framing headers; hyper re-frames the body.
                if is_hop_by_hop(name)
                    || name == header::CONTENT_LENGTH
                    || name == header::TRANSFER_ENCODING
                {
                    continue;
                }
                hdrs.append(name, value.clone());
            }
        }

        // A Secret read must never reach the raw-stream path below with values
        // intact. Redact a successful JSON body; buffer and pass through a
        // non-success body (a Status error carries no Secret values); fail closed
        // on a successful body whose content-type we cannot parse and redact.
        if redact {
            if !status.is_success() {
                let bytes = upstream_resp
                    .bytes()
                    .await
                    .context("read Secret error response")?;
                return Ok(builder
                    .body(full_body(bytes))
                    .expect("build Secret error response"));
            }
            if !is_json(&upstream_headers) {
                return Ok(status_resp(
                    StatusCode::BAD_GATEWAY,
                    "guard kube-proxy: refusing to stream a non-JSON Secret response unredacted",
                    "InternalError",
                ));
            }
            let bytes = upstream_resp
                .bytes()
                .await
                .context("read Secret response for redaction")?;
            let mut value: serde_json::Value = match serde_json::from_slice(&bytes) {
                Ok(v) => v,
                // Fail closed: never pass an unparsed Secret body through.
                Err(_) => {
                    return Ok(status_resp(
                        StatusCode::BAD_GATEWAY,
                        "guard kube-proxy: could not parse Secret response for redaction",
                        "InternalError",
                    ));
                }
            };
            let n = self.protocol.redact_response(&mut value);
            tracing::info!(target: "guard::kubeproxy", "redacted {n} Secret object(s) on {path}");
            let out = serde_json::to_vec(&value).context("re-serialize redacted Secret")?;
            return Ok(builder
                .body(full_body(Bytes::from(out)))
                .expect("build redacted response"));
        }

        // A tracked write: buffer the (small) object response, arm an auto-revert
        // on success, and return the body. Writes are not streamed.
        if track_write {
            let bytes = upstream_resp.bytes().await.context("read write response")?;
            if status.is_success() {
                if let Some(o) = op.as_ref() {
                    self.arm_write_revert(o, snapshot, &bytes, conn_id).await;
                }
            }
            return Ok(builder
                .body(full_body(bytes))
                .expect("build write response"));
        }

        // Stream the response body through unchanged (lists, gets, watches).
        let stream = upstream_resp
            .bytes_stream()
            .map_ok(Frame::data)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>);
        let body = StreamBody::new(stream).boxed();
        Ok(builder.body(body).expect("build streamed response"))
    }

    /// Fetch the current object at `path` before a mutation, so the protocol
    /// can build a restore-style revert from it. Returns the raw body; `None`
    /// if the fetch failed (the protocol then synthesizes a
    /// delete-the-created-object revert instead).
    async fn fetch_prior_object(&self, path: &str) -> Option<Vec<u8>> {
        let url = format!("{}{}", self.upstream.base(), path);
        let mut rb = self
            .upstream
            .client()
            .get(&url)
            .header(header::ACCEPT, "application/json");
        if let Some(token) = self.upstream.bearer() {
            rb = rb.bearer_auth(token);
        } else if let Some((user, pass)) = self.upstream.basic_auth() {
            rb = rb.basic_auth(user, Some(pass));
        }
        let resp = rb.send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        resp.bytes().await.ok().map(|b| b.to_vec())
    }

    /// Arm an auto-revert envelope for a tracked write the proxy just
    /// forwarded, using the protocol's revert plan.
    async fn arm_write_revert(
        &self,
        op: &ApiOp,
        snapshot: Option<Vec<u8>>,
        response_body: &[u8],
        conn_id: u64,
    ) {
        let Some(gate) = self.gate.get() else {
            return;
        };
        let plan = match self
            .protocol
            .plan_revert(op, snapshot.as_deref(), response_body)
        {
            Ok(plan) => plan,
            // The write is already live; a failed plan only means no auto-revert.
            Err(reason) => {
                tracing::warn!(target: "guard::kubeproxy", "{reason}");
                return;
            }
        };
        let created_key = plan.created.map(|c| CreatedKey {
            conn: conn_id,
            group: c.group,
            resource: c.resource,
            namespace: c.namespace,
            name: c.name,
        });
        let label = plan.label;
        match gate
            .arm_revert(ApiMutation {
                label: label.clone(),
                revert: plan.revert,
            })
            .await
        {
            Some(handle) => {
                // Record provenance for a created object so a later delete of it
                // is recognized as guard's own contained cleanup.
                if let Some(key) = created_key {
                    self.created.lock().unwrap().remember(key, handle.clone());
                }
                tracing::info!(target: "guard::kubeproxy", "armed auto-revert {handle} for {label}")
            }
            None => tracing::warn!(
                target: "guard::kubeproxy",
                "could not arm auto-revert for {label} (capacity)"
            ),
        }
    }

    /// If this delete targets a resource the proxy forwarded a create for in
    /// this process, remove and return its auto-revert handle — evidence the
    /// delete is guard's own creation being cleaned up. Consumes the record so a
    /// resource is only ever contained-deleted once.
    fn take_created_provenance(&self, op: &ApiOp, conn_id: u64) -> Option<String> {
        let name = op.name.clone()?;
        let key = CreatedKey {
            conn: conn_id,
            group: op.group.clone(),
            resource: op.resource.clone(),
            namespace: op.namespace.clone(),
            name,
        };
        self.created.lock().unwrap().take(&key)
    }
}

/// Build a Kubernetes `Status` error body so clients (kubectl/helm) surface a
/// clean message instead of a transport error.
fn status_resp(code: StatusCode, message: &str, reason: &str) -> Response<ProxyBody> {
    let status = serde_json::json!({
        "kind": "Status",
        "apiVersion": "v1",
        "metadata": {},
        "status": "Failure",
        "message": message,
        "reason": reason,
        "code": code.as_u16(),
    });
    let body = full_body(Bytes::from(status.to_string()));
    Response::builder()
        .status(code)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .expect("build status response")
}

fn full_body(bytes: Bytes) -> ProxyBody {
    Full::new(bytes).map_err(|never| match never {}).boxed()
}

/// True when forwarding `path` verbatim could change its meaning between the
/// gate and the upstream: `.`/`..` segments and their percent-encoded forms
/// (URL normalization in the forwarding client collapses them), and encoded
/// path separators or NULs (`%2f`, `%5c`, `%00`, raw `\`) an upstream router
/// may decode into extra segments the gate never saw.
fn path_alters_on_forward(path: &str) -> bool {
    path.split('/').any(|seg| {
        let s = seg.to_ascii_lowercase();
        s == "."
            || s == ".."
            || s.contains('\\')
            || s.contains("%2e")
            || s.contains("%2f")
            || s.contains("%5c")
            || s.contains("%00")
    })
}

/// RFC 7230 hop-by-hop headers, which must not be forwarded by a proxy.
fn is_hop_by_hop(name: &header::HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Headers that carry or override the request's authenticated identity. The
/// brokered client authenticates as nothing (its kubeconfig has no
/// credential); the daemon's own upstream credential is what actually talks
/// to the apiserver. If that credential holds the Kubernetes `impersonate`
/// RBAC verb -- a common grant for admin/CI service accounts -- forwarding
/// these headers verbatim would let the agent re-author the request under an
/// arbitrary user/group/serviceaccount, authorized against the impersonated
/// identity rather than the operator's, bypassing ApiPolicy entirely (it only
/// evaluates verb/resource/namespace, never identity). `X-Remote-*` are the
/// equivalent front-proxy identity headers for aggregated API servers; strip
/// them for the same reason, though they only take effect where the apiserver
/// already trusts this proxy's client certificate.
fn is_identity_header(name: &header::HeaderName) -> bool {
    let s = name.as_str();
    s.starts_with("impersonate-") || s.starts_with("x-remote-")
}

fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.trim_start().starts_with("application/json"))
        .unwrap_or(false)
}

/// Reload the policy file when its mtime changes (the operator slow clock). A
/// parse error keeps the last good policy in force and is logged.
async fn policy_reloader(path: PathBuf, policy: Arc<RwLock<ApiPolicy>>) {
    let mut last = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
    loop {
        tokio::time::sleep(Duration::from_secs(POLICY_RELOAD_SECS)).await;
        let modified = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
        if modified == last {
            continue;
        }
        last = modified;
        match ApiPolicy::load_file(&path) {
            Ok(p) => {
                *policy.write().await = p;
                tracing::info!(target: "guard::kubeproxy", "reloaded api-policy from {}", path.display());
            }
            Err(e) => {
                tracing::error!(
                    target: "guard::kubeproxy",
                    "api-policy reload failed ({}); keeping previous policy: {e}",
                    path.display()
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn created_key(conn: u64, name: &str) -> CreatedKey {
        CreatedKey {
            conn,
            group: String::new(),
            resource: "configmaps".to_string(),
            namespace: Some("dev".to_string()),
            name: name.to_string(),
        }
    }

    #[test]
    fn provenance_is_scoped_to_the_creating_connection() {
        // Caller A (connection 1) creates a resource; the proxy records its
        // auto-revert handle keyed to that connection.
        let mut reg = CreatedRegistry::default();
        reg.remember(created_key(1, "foo"), "handle-A".to_string());

        // Caller B on a different connection deletes the same
        // group/resource/namespace/name: no provenance match, so the delete
        // falls through to normal (strict) policy instead of the bypass.
        assert_eq!(reg.take(&created_key(2, "foo")), None);
        assert_eq!(
            reg.len(),
            1,
            "a non-matching take must not consume the entry"
        );

        // Caller A deleting its own creation still matches and is contained.
        assert_eq!(
            reg.take(&created_key(1, "foo")),
            Some("handle-A".to_string())
        );
        assert_eq!(reg.len(), 0, "a matching take consumes the entry once");
    }

    #[test]
    fn provenance_is_dropped_when_its_revert_resolves() {
        let mut reg = CreatedRegistry::default();
        reg.remember(created_key(1, "foo"), "handle-A".to_string());

        // The create's auto-revert resolves (operator confirm, or auto/manual
        // revert): the daemon drops the provenance by handle.
        reg.forget_by_handle("handle-A");
        assert_eq!(reg.len(), 0);

        // A later delete of a same-named resource (e.g. one an operator recreated
        // outside guard) no longer matches the stale entry and goes through
        // normal policy.
        assert_eq!(reg.take(&created_key(1, "foo")), None);
    }

    fn test_proxy() -> KubeProxy {
        let yaml = "apiVersion: v1\n\
             kind: Config\n\
             current-context: ctx\n\
             clusters: [{name: c, cluster: {server: \"https://x:6443\"}}]\n\
             contexts: [{name: ctx, context: {cluster: c, user: u}}]\n\
             users: [{name: u, user: {token: t}}]\n";
        let upstream = Upstream::from_kubeconfig_str(yaml, None).expect("upstream");
        let tls = ProxyTls::generate().expect("tls");
        KubeProxy::new(
            "127.0.0.1:0".parse().unwrap(),
            tls,
            upstream,
            ApiPolicy::deny_all(),
            None,
            PathBuf::from("/nonexistent/kubeconfig"),
        )
    }

    fn delete_op(name: &str) -> ApiOp {
        ApiOp {
            verb: Verb::Delete,
            group: String::new(),
            version: "v1".to_string(),
            resource: "configmaps".to_string(),
            subresource: None,
            namespace: Some("dev".to_string()),
            name: Some(name.to_string()),
            dry_run: false,
        }
    }

    #[test]
    fn take_created_provenance_matches_only_the_creating_connection() {
        let proxy = test_proxy();
        proxy
            .created
            .lock()
            .unwrap()
            .remember(created_key(1, "foo"), "h1".to_string());

        let op = delete_op("foo");
        // A delete on a different connection does not match.
        assert_eq!(proxy.take_created_provenance(&op, 2), None);
        // The creating connection matches and consumes the record.
        assert_eq!(
            proxy.take_created_provenance(&op, 1),
            Some("h1".to_string())
        );
        assert_eq!(proxy.take_created_provenance(&op, 1), None);
    }

    #[test]
    fn hostile_paths_are_rejected_before_forwarding() {
        for p in [
            "/repos/o/r/../../user",
            "/api/v1/namespaces/p/../../secrets",
            "/repos/o/r/%2e%2e/%2e%2e/user",
            "/repos/o/r/%2E%2E/admin",
            "/repos/o%2Fr/issues",
            "/v9/projects/prj%5Cx/env",
            "/a/%00/b",
            "/a/b\\c",
            "/.",
        ] {
            assert!(path_alters_on_forward(p), "{p} must be rejected");
        }
        for p in [
            "/api/v1/namespaces/prod/configmaps/app.config",
            "/repos/octo/hello.world/issues/42",
            "/v9/projects/prj_123/env",
            "/repos/o/r/contents/docs/...spread.md",
        ] {
            assert!(!path_alters_on_forward(p), "{p} must pass");
        }
    }

    #[test]
    fn forget_created_by_handle_clears_public_provenance() {
        let proxy = test_proxy();
        proxy
            .created
            .lock()
            .unwrap()
            .remember(created_key(1, "foo"), "h1".to_string());

        proxy.forget_created_by_handle("h1");

        assert_eq!(proxy.take_created_provenance(&delete_op("foo"), 1), None);
    }
}
