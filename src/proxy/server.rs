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

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock as StdRwLock};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use futures::{Stream, TryStreamExt};
use http_body_util::{combinators::BoxBody, BodyExt, Full, Limited, StreamBody};
use hyper::body::{Bytes, Frame, Incoming};
use hyper::http::{request::Parts, HeaderValue};
use hyper::service::service_fn;
use hyper::{header, HeaderMap, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;
use tokio::sync::{
    Mutex as AsyncMutex, OwnedMutexGuard, OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock,
};
use tokio_rustls::TlsAcceptor;

use super::gate::{
    ApiAuthorizationKind, ApiCoverageVerdict, ApiEvaluationMode, ApiForwardHandoff,
    ApiForwardRequirement, ApiHoldSnapshot, ApiJudge, ApiJudgeVerdict, ApiMutation,
    ApiRequestSummary, ApiSessionContext, ApiSessionEvent, ApiSessionSink, GateSink, HoldDecision,
    RevertConstructible,
};
use super::k8s_protocol::KubernetesProtocol;
use super::k8s_protocol::{bind_mutation_preconditions, object_state, KubernetesObjectState};
use super::op::{ApiOp, Verb};
use super::policy::{ApiAction, ApiPolicy};
use super::protocol::ProtocolConfig;
use super::tls::ProxyTls;
use super::upstream::Upstream;
use crate::gating::{decide_gate, GateOutcome};
use crate::redact::ExactSecretStreamRedactor as ExactSecretRedactor;

/// Cap on a forwarded request body. Manifests are small; this bounds memory by
/// rejecting an oversized request body.
const MAX_REQ_BODY: usize = 16 * 1024 * 1024;
const MAX_UPSTREAM_BODY: usize = 16 * 1024 * 1024;
const REQUEST_BODY_READ_TIMEOUT: Duration = Duration::from_secs(15);
const UPSTREAM_HANDOFF_TIMEOUT: Duration = Duration::from_secs(30);
const UPSTREAM_BODY_TIMEOUT: Duration = Duration::from_secs(30);

/// How often the policy file is checked for changes (the operator "slow
/// clock"). The default for [`ApiProxy::with_policy_reload_interval`].
const POLICY_RELOAD_SECS: u64 = 5;

type ProxyBody = BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;
type ReqwestByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send + Sync>>;
type RedactingStreamState = (ReqwestByteStream, ExactSecretRedactor, bool);
type JudgeBuilder = dyn Fn(Option<String>) -> Option<Arc<dyn ApiJudge>> + Send + Sync;
const GUARD_SESSION_HEADER: &str = "x-guard-session";
const MAX_KUBERNETES_OBSERVATIONS: usize = 4096;

#[derive(Debug, Clone)]
struct GuardRejected;

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteAuthority {
    revision: u64,
    policy_fingerprint: String,
}

struct AuthorityRevisionTransition<'a> {
    revision: &'a AtomicU64,
}

impl Drop for AuthorityRevisionTransition<'_> {
    fn drop(&mut self) {
        let previous = self.revision.fetch_add(1, Ordering::Release);
        debug_assert!(!previous.is_multiple_of(2));
    }
}

struct AuthorityUpdateGuard<'a> {
    _revision_transition: AuthorityRevisionTransition<'a>,
    _update_serial: OwnedMutexGuard<()>,
    _coordination: OwnedRwLockWriteGuard<()>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuardHoldOutcome {
    Approved,
    Denied,
}

#[derive(Debug)]
enum RequestBodyError {
    Timeout,
    Read(anyhow::Error),
}

#[derive(Debug, Clone)]
struct SessionAuth {
    token: String,
    context: ApiSessionContext,
}
struct BufferedRequest {
    parts: Parts,
    body: Bytes,
}

struct RouteMetadata<'a> {
    path: &'a str,
    query: &'a str,
    op: &'a ApiOp,
}

/// A configured API proxy: TLS identity, upstream connection, the attached
/// protocol plug-in, and the hot-reloaded operator policy. Hosted by the daemon
/// alongside the gate socket.
pub struct ApiProxy {
    listen: SocketAddr,
    proxy_url: String,
    tls: ProxyTls,
    upstream: Upstream,
    /// Answers every protocol-specific question; the loop itself is
    /// protocol-agnostic.
    protocol: Arc<dyn ProtocolConfig>,
    policy: Arc<RwLock<ApiPolicy>>,
    policy_path: Option<PathBuf>,
    /// Even values are stable authority generations. Policy and evaluator
    /// swaps mark the generation odd for their short transition, then publish
    /// the next even value. Routes bind an even generation plus policy digest.
    authority_revision: AtomicU64,
    /// Upstream handoffs hold a read lease through response headers. Authority
    /// publication takes the write lease, so revocation waits for every
    /// in-flight handoff without serializing independent reads and writes.
    authority_initiation: Arc<RwLock<()>>,
    /// Serializes update intents so only one revision can be marked odd while
    /// it waits for existing upstream handoffs to finish.
    authority_update_serial: Arc<AsyncMutex<()>>,
    /// Bridge to the daemon's consequence machinery, attached before serving.
    /// When present, recoverable writes are wrapped in an auto-revert envelope.
    gate: OnceLock<Arc<dyn GateSink>>,
    /// LLM-backed API judge for `evaluate` policy actions and rarity reroutes.
    /// Swappable so policy intent hot-reload can rebuild the evaluator and its
    /// cache under the new base prompt.
    judge: StdRwLock<Option<Arc<dyn ApiJudge>>>,
    judge_builder: OnceLock<Arc<JudgeBuilder>>,
    /// Resources this proxy forwarded a create for (and armed an auto-revert on),
    /// mapped to the revert handle. This is evidence-based provenance: a later
    /// delete of a resource in this set is guard's own creation being cleaned up
    /// (e.g. a Helm post-install hook deleting its check resource), so it is
    /// contained rather than an untracked delete. Entries are scoped to the
    /// creating connection and removed when their revert resolves.
    created: Mutex<CreatedRegistry>,
    observations: Mutex<ObservationRegistry>,
    /// Monotonic per-connection id, assigned in the accept loop, so a created
    /// resource's provenance is scoped to the connection that created it.
    next_conn: AtomicU64,
    /// Rarity-based escalation: counts request shapes over the proxy's
    /// lifetime and escalates a policy-allowed request whose shape is still
    /// rare to the operator hold queue, so a broad allow rule fails toward
    /// scrutiny on the first few occurrences of any shape it covers. Disabled
    /// (threshold 0) unless the operator opts in.
    rarity: RarityTracker,
    endpoint: String,
    credential_ref: String,
    session_sink: OnceLock<Arc<dyn ApiSessionSink>>,
    listener_mode: ApiListenerMode,
    request_body_timeout: Duration,
    /// Maximum time authority coordination can be retained while waiting for
    /// the upstream to accept a request and return response headers.
    upstream_handoff_timeout: Duration,
    /// Maximum time spent buffering a response body after the finite header
    /// handoff and any durable containment transition have completed.
    upstream_body_timeout: Duration,
    upstream_body_limit: usize,
    /// How often `policy_path` is checked for changes. Production keeps the
    /// [`POLICY_RELOAD_SECS`] default; tests inject a short interval so they
    /// can observe a reload without a multi-second wait.
    policy_reload_interval: Duration,
    /// Wrapping generation advanced once when an authority revision becomes
    /// transitional, before the update waits for in-flight handoffs.
    authority_transition_generation: AtomicU64,
    authority_transition_notify: tokio::sync::Notify,
    policy_reload_notify: tokio::sync::Notify,
}

#[derive(Clone)]
struct PendingApiAuthorization {
    judge: Arc<dyn ApiJudge>,
    summary: ApiRequestSummary,
    requirement: ApiForwardRequirement,
}

#[derive(Debug, Clone)]
struct PreparedMutation {
    prior_snapshot: Option<Vec<u8>>,
    body_sha256: String,
}

struct StagedRevert {
    handle: String,
    created_key: Option<CreatedKey>,
    created_path: Option<String>,
    create_provenance: Option<String>,
}

const CREATE_PROVENANCE_ANNOTATION: &str = "guard.morgaesis.dev/provisional";

#[derive(Debug, Clone)]
struct ApprovedApiHold {
    body_sha256: String,
}

#[derive(Debug, Clone)]
struct PreparedCreateProvenance(String);

enum UpstreamHandoffOutcome {
    Pending,
    PreparationFailed,
    TimedOut,
    Finished(Result<reqwest::Response, reqwest::Error>),
}

enum UpstreamBodyError {
    TimedOut,
    ReadFailed,
    TooLarge,
}

struct UpstreamSendHandoff<'a> {
    proxy: &'a ApiProxy,
    route_authority: RouteAuthority,
    operation: Option<ApiOp>,
    request: Option<reqwest::RequestBuilder>,
    timeout: Duration,
    outcome: UpstreamHandoffOutcome,
    containment: Option<ContainmentLifecycle>,
    actual_body_sha256: String,
    authorized_body_sha256: Option<String>,
}

struct ContainmentLifecycle {
    gate: Arc<dyn GateSink>,
    handle: String,
    created_key: Option<CreatedKey>,
    created_path: Option<String>,
    create_provenance: Option<String>,
    handoff_started: bool,
    transition_owned: bool,
    armed: bool,
}

impl ContainmentLifecycle {
    fn new(gate: Arc<dyn GateSink>, staged: StagedRevert) -> Self {
        Self {
            gate,
            handle: staged.handle,
            created_key: staged.created_key,
            created_path: staged.created_path,
            create_provenance: staged.create_provenance,
            handoff_started: false,
            transition_owned: false,
            armed: true,
        }
    }

    fn created_resource(&self) -> Option<(&CreatedKey, &str)> {
        Some((self.created_key.as_ref()?, self.created_path.as_deref()?))
    }

    async fn prepare_dispatch(&mut self) -> bool {
        let gate = self.gate.clone();
        let handle = self.handle.clone();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let marked = gate.mark_revert_dispatching(&handle).await;
            if ready_tx.send(marked).is_err() || (marked && accepted_rx.await.is_err()) {
                if marked {
                    let _ = gate
                        .mark_revert_indeterminate(
                            &handle,
                            "request handling ended after durable dispatch preparation",
                            None,
                        )
                        .await;
                } else {
                    let _ = gate.cancel_staged_revert(&handle).await;
                }
            }
        });
        let marked = tokio::time::timeout(Duration::from_secs(5), ready_rx)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(false);
        if marked {
            self.handoff_started = true;
            let _ = accepted_tx.send(());
        }
        marked
    }

    async fn cancel_inert(mut self) -> bool {
        if tokio::time::timeout(
            Duration::from_secs(5),
            self.gate.cancel_staged_revert(&self.handle),
        )
        .await
        .is_ok_and(|cancelled| cancelled)
        {
            self.armed = false;
            true
        } else {
            false
        }
    }

    async fn preserve_indeterminate(
        mut self,
        reason: &str,
        resource_uid: Option<&str>,
    ) -> Option<String> {
        self.transition_owned = true;
        let gate = self.gate.clone();
        let handle = self.handle.clone();
        let reason = reason.to_string();
        let resource_uid = resource_uid.map(str::to_string);
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let result = gate
                .mark_revert_indeterminate(&handle, &reason, resource_uid.as_deref())
                .await;
            let _ = result_tx.send(result);
        });
        let committed = tokio::time::timeout(Duration::from_secs(5), result_rx)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(false);
        self.armed = false;
        committed.then(|| self.handle.clone())
    }

    async fn activate(
        mut self,
        resource_uid: Option<&str>,
    ) -> Result<(String, Option<CreatedKey>), Option<String>> {
        self.transition_owned = true;
        let gate = self.gate.clone();
        let handle = self.handle.clone();
        let resource_uid = resource_uid.map(str::to_string);
        let transition_uid = resource_uid.clone();
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let activated = gate
                .mark_revert_forwarded(&handle, transition_uid.as_deref())
                .await;
            let recovered = if activated {
                false
            } else {
                gate
                    .mark_revert_indeterminate(
                        &handle,
                        "successful mutation response was received, but the confirmation window could not be activated",
                        transition_uid.as_deref(),
                    )
                    .await
            };
            let _ = result_tx.send((activated, recovered));
        });
        let result = tokio::time::timeout(Duration::from_secs(5), result_rx)
            .await
            .ok()
            .and_then(Result::ok);
        self.armed = false;
        match result {
            Some((true, _)) => Ok((self.handle.clone(), self.created_key.take())),
            Some((false, true)) => Err(Some(self.handle.clone())),
            Some((false, false)) | None => Err(None),
        }
    }

    async fn retire_rejected(mut self, reason: &str) -> Result<(), Option<String>> {
        self.transition_owned = true;
        let gate = self.gate.clone();
        let handle = self.handle.clone();
        let reason = reason.to_string();
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let retired = gate.mark_revert_rejected(&handle, &reason).await;
            let fallback = if retired {
                None
            } else {
                gate.mark_revert_indeterminate(
                    &handle,
                    "the upstream rejected the request, but containment retirement did not converge",
                    None,
                )
                .await
                .then_some(handle)
            };
            let _ = result_tx.send((retired, fallback));
        });
        let result = tokio::time::timeout(Duration::from_secs(5), result_rx)
            .await
            .ok()
            .and_then(Result::ok);
        self.armed = false;
        match result {
            Some((true, _)) => Ok(()),
            Some((false, fallback)) => Err(fallback),
            None => Err(None),
        }
    }
}

impl Drop for ContainmentLifecycle {
    fn drop(&mut self) {
        if !self.armed || self.transition_owned {
            return;
        }
        let gate = self.gate.clone();
        let handle = self.handle.clone();
        let handoff_started = self.handoff_started;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                if handoff_started {
                    let _ = tokio::time::timeout(
                        Duration::from_secs(5),
                        gate.mark_revert_indeterminate(
                            &handle,
                            "request handling ended after upstream mutation dispatch began",
                            None,
                        ),
                    )
                    .await;
                } else {
                    let _ = tokio::time::timeout(
                        Duration::from_secs(5),
                        gate.cancel_staged_revert(&handle),
                    )
                    .await;
                }
            });
        }
    }
}

#[async_trait::async_trait]
impl ApiForwardHandoff for UpstreamSendHandoff<'_> {
    async fn forward(&mut self) -> Result<(), String> {
        if self
            .authorized_body_sha256
            .as_ref()
            .is_some_and(|expected| expected != &self.actual_body_sha256)
        {
            return Err("final request bytes changed after authorization".to_string());
        }
        if self
            .proxy
            .recheck_final_authority(&self.route_authority, self.operation.as_ref())
            .await
            .is_some()
        {
            return Err("policy authority changed before upstream handoff".to_string());
        }
        let request = self
            .request
            .take()
            .ok_or_else(|| "upstream handoff was already consumed".to_string())?;
        if let Some(containment) = self.containment.as_mut() {
            if !containment.prepare_dispatch().await {
                self.outcome = UpstreamHandoffOutcome::PreparationFailed;
                return Err("durable mutation dispatch preparation failed".to_string());
            }
        }
        if self
            .proxy
            .recheck_final_authority(&self.route_authority, self.operation.as_ref())
            .await
            .is_some()
        {
            return Err("policy authority changed during durable dispatch preparation".to_string());
        }
        let send = request.send();
        tokio::pin!(send);
        let _reservation = self
            .proxy
            .reserve_authority_initiation(&self.route_authority)
            .await
            .ok_or_else(|| "policy authority changed before upstream initiation".to_string())?;
        // Keep the lease until the request future reaches response headers. A
        // first poll can only queue a write; releasing here would let policy
        // publication commit before the transport actually sends it.
        let first_poll = {
            let waker = futures::task::noop_waker();
            let mut context = std::task::Context::from_waker(&waker);
            send.as_mut().poll(&mut context)
        };
        let result = match first_poll {
            std::task::Poll::Ready(result) => Ok(result),
            std::task::Poll::Pending => tokio::time::timeout(self.timeout, &mut send).await,
        };
        match result {
            Ok(result) => {
                self.outcome = UpstreamHandoffOutcome::Finished(result);
                Ok(())
            }
            Err(_) => {
                self.outcome = UpstreamHandoffOutcome::TimedOut;
                Err("upstream request handoff timed out".to_string())
            }
        }
    }
}

struct SessionBoundHandoff<'a> {
    sink: Option<&'a Arc<dyn ApiSessionSink>>,
    auth: Option<&'a SessionAuth>,
    context: Option<&'a ApiSessionContext>,
    upstream: &'a mut dyn ApiForwardHandoff,
}

struct CleanupBoundHandoff<'a> {
    proxy: &'a ApiProxy,
    created: Option<&'a CreatedMatch>,
    path: &'a str,
    upstream: &'a mut dyn ApiForwardHandoff,
}

#[async_trait::async_trait]
impl ApiForwardHandoff for CleanupBoundHandoff<'_> {
    async fn forward(&mut self) -> Result<(), String> {
        let Some(created) = self.created else {
            return self.upstream.forward().await;
        };
        let gate = self
            .proxy
            .gate
            .get()
            .ok_or_else(|| "created-resource cleanup gate is unavailable".to_string())?;
        let mut registry_handoff = CreatedRegistryHandoff {
            proxy: self.proxy,
            created,
            path: self.path,
            upstream: self.upstream,
        };
        gate.authorize_cleanup(
            &created.handle,
            &created.resource_uid,
            &created.create_provenance,
            &mut registry_handoff,
        )
        .await
    }
}

struct CreatedRegistryHandoff<'a> {
    proxy: &'a ApiProxy,
    created: &'a CreatedMatch,
    path: &'a str,
    upstream: &'a mut dyn ApiForwardHandoff,
}

#[async_trait::async_trait]
impl ApiForwardHandoff for CreatedRegistryHandoff<'_> {
    async fn forward(&mut self) -> Result<(), String> {
        let created = self.created;
        let current = self
            .proxy
            .created
            .lock()
            .unwrap()
            .find_record(&created.key)
            .filter(|record| {
                record.handle == created.handle
                    && record.resource_uid == created.resource_uid
                    && record.create_provenance == created.create_provenance
            })
            .ok_or_else(|| "created-resource cleanup authority was revoked".to_string())?;
        self.proxy
            .validate_current_created_object(
                &created.key,
                self.path,
                &current.resource_uid,
                &current.create_provenance,
            )
            .await?;
        let still_current = self
            .proxy
            .created
            .lock()
            .unwrap()
            .find_record(&created.key)
            .is_some_and(|record| {
                record.handle == created.handle
                    && record.resource_uid == created.resource_uid
                    && record.create_provenance == created.create_provenance
            });
        if !still_current {
            return Err("created-resource cleanup authority was revoked".to_string());
        }
        self.upstream.forward().await
    }
}

#[async_trait::async_trait]
impl ApiForwardHandoff for SessionBoundHandoff<'_> {
    async fn forward(&mut self) -> Result<(), String> {
        match (self.sink, self.auth, self.context) {
            (Some(sink), Some(auth), Some(context)) => {
                sink.authorize_forward(&auth.token, context, self.upstream)
                    .await
            }
            (_, None, None) => self.upstream.forward().await,
            _ => Err("session authority context is incomplete".to_string()),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ApiListenerMode {
    Policy,
    #[default]
    Readonly,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ObservationKey {
    endpoint: String,
    session_fingerprint: String,
    session_revision: String,
    group: String,
    version: String,
    resource: String,
    subresource: Option<String>,
    namespace: Option<String>,
    name: String,
    uid: String,
}

#[derive(Debug, Clone)]
struct ObservedVersion {
    resource_version: String,
    contention_fingerprint: String,
}

#[derive(Debug, Default)]
struct ObservationRegistry {
    items: HashMap<ObservationKey, ObservedVersion>,
    order: VecDeque<ObservationKey>,
}

impl ObservationRegistry {
    fn remember(&mut self, key: ObservationKey, observed: ObservedVersion) {
        self.order.retain(|existing| existing != &key);
        self.items.insert(key.clone(), observed);
        self.order.push_back(key);
        while self.items.len() > MAX_KUBERNETES_OBSERVATIONS {
            if let Some(oldest) = self.order.pop_front() {
                self.items.remove(&oldest);
            }
        }
    }

    fn get(&self, key: &ObservationKey) -> Option<ObservedVersion> {
        self.items.get(key).cloned()
    }
}

/// A request shape for rarity accounting: the typed operation minus its object
/// name, so `get pods/web-0` and `get pods/web-1` count as one shape while a
/// first access to a new namespace, resource, or verb counts as its own. The
/// object name is deliberately excluded so that per-object variation maps to a
/// single shape: accounting groups requests by kind (verb/resource/namespace),
/// and a new object name alone neither creates a new shape nor changes an
/// existing shape's count.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ShapeKey {
    protocol: String,
    verb: &'static str,
    group: String,
    resource: String,
    subresource: Option<String>,
    namespace: Option<String>,
    authority_selectors: std::collections::BTreeMap<String, String>,
}

/// Counts request shapes seen over the proxy's lifetime and reports whether a
/// shape is still under the escalation threshold. `threshold` is the number of
/// occurrences that must accrue before a shape stops being escalated; 0
/// disables escalation entirely (the common case). The finite FIFO bounds
/// memory even when an attacker supplies an unbounded stream of distinct
/// selectors or namespaces.
const MAX_RARITY_SHAPES: usize = 4096;
struct RarityTracker {
    threshold: u64,
    state: Mutex<(HashMap<ShapeKey, u64>, VecDeque<ShapeKey>)>,
}

impl RarityTracker {
    fn new(threshold: u64) -> Self {
        Self {
            threshold,
            state: Mutex::new((HashMap::new(), VecDeque::new())),
        }
    }

    fn enabled(&self) -> bool {
        self.threshold > 0
    }

    /// Record one occurrence of `key` and return true if, BEFORE this
    /// occurrence, the shape had been seen fewer than `threshold` times -- i.e.
    /// this request is still within the rare window and should be escalated.
    /// A no-op returning false when escalation is disabled.
    fn observe_is_rare(&self, key: ShapeKey) -> bool {
        if !self.enabled() {
            return false;
        }
        let mut state = self.state.lock().unwrap();
        let (seen, order) = &mut *state;
        if !seen.contains_key(&key) {
            if seen.len() >= MAX_RARITY_SHAPES {
                if let Some(oldest) = order.pop_front() {
                    seen.remove(&oldest);
                }
            }
            order.push_back(key.clone());
        }
        let count = seen.entry(key).or_insert(0);
        let rare = *count < self.threshold;
        *count = count.saturating_add(1);
        rare
    }
}

/// Identity of a resource the proxy tracks as guard-created, for delete
/// provenance matching.
///
/// The `conn` field scopes provenance to the connection that created the
/// resource. The TLS listener requests no client certificate. Caller scope is
/// established by a Guard session bearer when one is supplied, and the bearer
/// is consumed before the request reaches the upstream connection. A delete
/// arriving on a different connection than the create never matches, so the
/// provenance shortcut is scoped to the connection that created a resource; a delete on any other
/// connection falls through to standard policy evaluation. Kubernetes
/// clients (client-go, used by kubectl/helm) negotiate HTTP/2 and multiplex a
/// process's whole session over one connection, so a legitimate same-process
/// create-then-delete (e.g. a Helm post-install hook) still matches.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CreatedKey {
    conn: u64,
    session_fingerprint: Option<String>,
    group: String,
    resource: String,
    namespace: Option<String>,
    name: String,
}

#[derive(Debug, Clone)]
struct CreatedMatch {
    key: CreatedKey,
    handle: String,
    resource_uid: String,
    create_provenance: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CreatedRecord {
    handle: String,
    resource_uid: String,
    create_provenance: String,
}

/// Tracks resources the proxy forwarded a create for (and armed an auto-revert
/// on), each mapped to its auto-revert handle. Pure: no clock, no I/O.
#[derive(Debug, Default)]
struct CreatedRegistry {
    items: HashMap<CreatedKey, CreatedRecord>,
}

impl CreatedRegistry {
    /// Record a created resource against its auto-revert handle.
    fn remember(
        &mut self,
        key: CreatedKey,
        handle: String,
        resource_uid: String,
        create_provenance: String,
    ) {
        self.items.insert(
            key,
            CreatedRecord {
                handle,
                resource_uid,
                create_provenance,
            },
        );
    }

    /// Consume and return the auto-revert handle for a created resource, if the
    /// delete's key (connection included) matches a recorded create. Consuming
    /// ensures a resource is only ever contained-deleted once.
    #[cfg(test)]
    fn find(&self, key: &CreatedKey) -> Option<String> {
        self.items.get(key).map(|record| record.handle.clone())
    }

    fn find_record(&self, key: &CreatedKey) -> Option<CreatedRecord> {
        self.items.get(key).cloned()
    }

    fn take_if_handle(&mut self, key: &CreatedKey, handle: &str) -> bool {
        if self
            .items
            .get(key)
            .is_some_and(|record| record.handle == handle)
        {
            self.items.remove(key);
            true
        } else {
            false
        }
    }

    /// Drop any provenance entry whose auto-revert resolved (confirmed or
    /// reverted). Without this a create record would outlive its revert window,
    /// so a same-named resource an operator later recreated outside guard would
    /// still match a stale entry and skip the standard policy checks. Dropping
    /// the record on resolution keeps the shortcut scoped to a live revert.
    fn forget_by_handle(&mut self, handle: &str) {
        self.items.retain(|_, record| record.handle != handle);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.items.len()
    }
}

impl ApiProxy {
    fn redact_upstream_bytes(
        &self,
        secrets: Vec<Vec<u8>>,
        bytes: &[u8],
    ) -> Result<Bytes, UpstreamBodyError> {
        ExactSecretRedactor::redact_all(secrets, bytes, self.upstream_body_limit)
            .map(Bytes::from)
            .map_err(|_| UpstreamBodyError::TooLarge)
    }

    async fn read_upstream_body(
        &self,
        mut response: reqwest::Response,
    ) -> Result<Bytes, UpstreamBodyError> {
        let limit = self.upstream_body_limit;
        if response
            .content_length()
            .is_some_and(|length| length > limit as u64)
        {
            return Err(UpstreamBodyError::TooLarge);
        }
        let read = async move {
            let mut bytes = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| UpstreamBodyError::ReadFailed)?
            {
                if bytes.len().saturating_add(chunk.len()) > limit {
                    return Err(UpstreamBodyError::TooLarge);
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(Bytes::from(bytes))
        };
        match tokio::time::timeout(self.upstream_body_timeout, read).await {
            Ok(result) => result,
            Err(_) => Err(UpstreamBodyError::TimedOut),
        }
    }

    async fn take_upstream_body(
        &self,
        response: &mut Option<reqwest::Response>,
        buffered: &mut Option<Bytes>,
    ) -> Result<Bytes, UpstreamBodyError> {
        if let Some(bytes) = buffered.take() {
            return Ok(bytes);
        }
        let response = response.take().ok_or(UpstreamBodyError::ReadFailed)?;
        self.read_upstream_body(response).await
    }

    /// Assemble a Kubernetes proxy. `policy_path` (when set) is hot-reloaded
    /// while serving; when unset, `policy` is used as-is (typically a
    /// default-deny).
    pub fn new(
        listen: SocketAddr,
        tls: ProxyTls,
        upstream: Upstream,
        policy: ApiPolicy,
        policy_path: Option<PathBuf>,
    ) -> Self {
        Self::with_protocol(
            Arc::new(KubernetesProtocol),
            listen,
            tls,
            upstream,
            policy,
            policy_path,
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
    ) -> Self {
        let proxy_url = format!("https://{listen}");
        Self {
            listen,
            proxy_url,
            tls,
            upstream,
            protocol,
            policy: Arc::new(RwLock::new(policy)),
            policy_path,
            authority_revision: AtomicU64::new(0),
            authority_initiation: Arc::new(RwLock::new(())),
            authority_update_serial: Arc::new(AsyncMutex::new(())),
            gate: OnceLock::new(),
            judge: StdRwLock::new(None),
            judge_builder: OnceLock::new(),
            created: Mutex::new(CreatedRegistry::default()),
            observations: Mutex::new(ObservationRegistry::default()),
            next_conn: AtomicU64::new(1),
            rarity: RarityTracker::new(0),
            endpoint: "default".to_string(),
            credential_ref: "upstream".to_string(),
            session_sink: OnceLock::new(),
            listener_mode: ApiListenerMode::default(),
            request_body_timeout: REQUEST_BODY_READ_TIMEOUT,
            upstream_handoff_timeout: UPSTREAM_HANDOFF_TIMEOUT,
            upstream_body_timeout: UPSTREAM_BODY_TIMEOUT,
            upstream_body_limit: MAX_UPSTREAM_BODY,
            policy_reload_interval: Duration::from_secs(POLICY_RELOAD_SECS),
            authority_transition_generation: AtomicU64::new(0),
            authority_transition_notify: tokio::sync::Notify::new(),
            policy_reload_notify: tokio::sync::Notify::new(),
        }
    }

    pub fn with_endpoint_context(
        mut self,
        endpoint: impl Into<String>,
        credential_ref: impl Into<String>,
    ) -> Self {
        self.endpoint = endpoint.into();
        self.credential_ref = credential_ref.into();
        self
    }

    pub fn with_listener_mode(mut self, mode: ApiListenerMode) -> Self {
        self.listener_mode = mode;
        self
    }

    /// Bound how long the proxy waits to capture an entire request body before
    /// any evaluator or operator authorization. The default is 15 seconds.
    pub fn with_request_body_timeout(mut self, timeout: Duration) -> Self {
        self.request_body_timeout = timeout;
        self
    }

    /// Bound the finite upstream request handoff. Authority leases are released
    /// when this deadline expires and never span response-body streaming.
    #[doc(hidden)]
    pub fn with_upstream_handoff_timeout(mut self, timeout: Duration) -> Self {
        self.upstream_handoff_timeout = timeout;
        self
    }

    /// Bound response buffering independently from the authority-protected
    /// response-header handoff.
    #[doc(hidden)]
    pub fn with_upstream_body_timeout(mut self, timeout: Duration) -> Self {
        self.upstream_body_timeout = timeout;
        self
    }

    /// Override the response buffer ceiling for deterministic boundary tests.
    #[doc(hidden)]
    pub fn with_upstream_body_limit(mut self, limit: usize) -> Self {
        self.upstream_body_limit = limit;
        self
    }

    /// Override how often `policy_path` is checked for changes. The default is
    /// [`POLICY_RELOAD_SECS`]; tests inject a short interval so a reload can be
    /// observed promptly.
    pub fn with_policy_reload_interval(mut self, interval: Duration) -> Self {
        self.policy_reload_interval = interval;
        self
    }

    /// Digest of the currently active policy (see
    /// [`ApiPolicy::authority_fingerprint`]). Lets a caller observe when a
    /// hot-reload of `policy_path` has taken effect.
    pub async fn policy_fingerprint(&self) -> String {
        self.policy.read().await.authority_fingerprint()
    }

    /// Return the wrapping generation of authority transitions that have begun.
    ///
    /// The generation advances exactly once after the proxy publishes an odd
    /// authority revision, before the update waits for in-flight upstream
    /// handoffs. It observes transition entry, not completed policy
    /// publication.
    pub fn authority_transition_generation(&self) -> u64 {
        self.authority_transition_generation.load(Ordering::Acquire)
    }

    /// Wait for an authority transition after `observed_generation` and return
    /// the new wrapping generation.
    pub async fn wait_for_authority_transition_after(&self, observed_generation: u64) -> u64 {
        loop {
            let notified = self.authority_transition_notify.notified();
            let generation = self.authority_transition_generation();
            if generation != observed_generation {
                return generation;
            }
            notified.await;
        }
    }

    /// Wait until `expected` is the active policy authority fingerprint.
    /// Notification registration precedes each observation, so publication
    /// cannot be missed between the fingerprint read and the wait.
    pub async fn wait_for_policy_fingerprint(&self, expected: &str) {
        self.wait_for_policy_fingerprint_with_before_check(expected, || {})
            .await;
    }

    async fn wait_for_policy_fingerprint_with_before_check<F>(
        &self,
        expected: &str,
        mut before_check: F,
    ) where
        F: FnMut(),
    {
        loop {
            let notified = self.policy_reload_notify.notified();
            before_check();
            if self.policy_fingerprint().await == expected {
                return;
            }
            notified.await;
        }
    }

    pub fn attach_session_sink(&self, sink: Arc<dyn ApiSessionSink>) {
        let _ = self.session_sink.set(sink);
    }

    /// Enable rarity-based escalation: a policy-allowed request whose shape has
    /// been seen fewer than `threshold` times is escalated to the operator hold
    /// queue instead of forwarded, so a broad allow rule fails toward scrutiny
    /// on the first few occurrences of any shape it covers. Requires an
    /// attached gate (the hold queue); with `threshold` 0 or no gate it is a
    /// no-op. Builder-style, applied before serving.
    pub fn with_rarity_escalation(mut self, threshold: u64) -> Self {
        self.rarity = RarityTracker::new(threshold);
        self
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

    /// Attach or replace the API judge with full authority coordination.
    ///
    /// The revision is marked transitional and the write lease is held until
    /// the replacement is published, so in-flight upstream handoffs cannot
    /// race an evaluator change.
    pub async fn attach_judge(&self, judge: Arc<dyn ApiJudge>) {
        let _update = self.begin_authority_update().await;
        *self
            .judge
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(judge);
    }

    /// Attach a builder used by the policy reloader to rebuild the judge when
    /// the policy intent changes. The daemon supplies this when LLM evaluation
    /// is configured for the proxy.
    pub fn attach_judge_builder(&self, builder: Arc<JudgeBuilder>) {
        let _ = self.judge_builder.set(builder);
    }

    pub fn has_judge(&self) -> bool {
        self.judge
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .is_some_and(|judge| judge.evaluator_enabled())
    }

    async fn begin_authority_update(&self) -> AuthorityUpdateGuard<'_> {
        self.begin_authority_update_with_callback(|| {}).await
    }

    async fn begin_authority_update_with_callback<F>(
        &self,
        after_revision_published: F,
    ) -> AuthorityUpdateGuard<'_>
    where
        F: FnOnce(),
    {
        let update_serial = self.authority_update_serial.clone().lock_owned().await;
        let revision = self.authority_revision.load(Ordering::Acquire);
        debug_assert!(revision.is_multiple_of(2));
        let next = revision.wrapping_add(1);
        self.authority_revision
            .compare_exchange(revision, next, Ordering::AcqRel, Ordering::Acquire)
            .expect("authority update serial keeps revision stable");
        // Own the odd revision before awaiting the write lease. Cancellation
        // while waiting for an in-flight handoff must publish an even revision.
        let revision_transition = AuthorityRevisionTransition {
            revision: &self.authority_revision,
        };
        self.authority_transition_generation
            .fetch_add(1, Ordering::AcqRel);
        self.authority_transition_notify.notify_waiters();
        after_revision_published();
        let coordination = self.authority_initiation.clone().write_owned().await;
        AuthorityUpdateGuard {
            _revision_transition: revision_transition,
            _update_serial: update_serial,
            _coordination: coordination,
        }
    }

    async fn reserve_authority_initiation(
        &self,
        expected: &RouteAuthority,
    ) -> Option<OwnedRwLockReadGuard<()>> {
        if self.authority_revision.load(Ordering::Acquire) != expected.revision
            || !expected.revision.is_multiple_of(2)
        {
            return None;
        }
        let coordination = self.authority_initiation.clone().try_read_owned().ok()?;
        (self.authority_revision.load(Ordering::Acquire) == expected.revision)
            .then_some(coordination)
    }

    async fn capture_route_authority(&self) -> Result<(ApiPolicy, RouteAuthority)> {
        const MAX_CAPTURE_ATTEMPTS: usize = 64;
        for _ in 0..MAX_CAPTURE_ATTEMPTS {
            let before = self.authority_revision.load(Ordering::Acquire);
            if !before.is_multiple_of(2) {
                tokio::task::yield_now().await;
                continue;
            }
            let policy = self.policy.read().await.clone();
            let after = self.authority_revision.load(Ordering::Acquire);
            if before == after && after.is_multiple_of(2) {
                let policy_fingerprint = policy.authority_fingerprint();
                return Ok((
                    policy,
                    RouteAuthority {
                        revision: after,
                        policy_fingerprint,
                    },
                ));
            }
        }
        anyhow::bail!("API route authority remained unstable")
    }

    pub fn protocol_name(&self) -> &str {
        self.protocol.name()
    }

    /// Return the policy or protocol-floor reason that makes `op`
    /// unconditionally unusable through this proxy. Hold and evaluate actions
    /// remain usable because they can still reach an authorization decision.
    pub async fn categorical_policy_refusal(&self, op: &ApiOp) -> Result<Option<String>, String> {
        let (policy, _) = self
            .capture_route_authority()
            .await
            .map_err(|error| format!("API route authority is unavailable: {error}"))?;
        if let Some(reason) = self.protocol.deny_outright(op) {
            return Ok(Some(reason));
        }
        let decision = policy.decide(op);
        Ok(matches!(decision.action, ApiAction::Deny).then_some(decision.reason))
    }

    pub fn upstream(&self) -> &Upstream {
        &self.upstream
    }

    pub fn listen(&self) -> SocketAddr {
        self.listen
    }

    /// The loopback URL agents put in their brokered kubeconfig.
    pub fn proxy_url(&self) -> &str {
        &self.proxy_url
    }

    /// The agent-facing brokered kubeconfig without a Guard session bearer.
    pub fn brokered_kubeconfig(&self) -> String {
        super::kubeconfig::brokered_kubeconfig(&self.proxy_url, &self.tls.ca_data_b64())
    }

    pub fn brokered_kubeconfig_with_session(&self, session_token: &str) -> String {
        super::kubeconfig::brokered_kubeconfig_with_session(
            &self.proxy_url,
            &self.tls.ca_data_b64(),
            session_token,
        )
    }

    /// Accept loop: terminate TLS and serve each connection. Returns only on a
    /// fatal bind error, so the daemon's listener supervision restarts the
    /// process the same way the gate socket does.
    pub async fn serve(self: Arc<Self>) -> Result<()> {
        validate_listener_identity(self.listen)?;
        let listener = TcpListener::bind(self.listen).await.with_context(|| {
            format!(
                "bind api-proxy listener for {} on {}",
                self.protocol.name(),
                self.listen
            )
        })?;
        self.serve_on(listener).await
    }

    /// Serve on an already-bound listener whose address matches this proxy's
    /// configured address. Callers that need an atomic port reservation can
    /// bind first, construct the proxy with `listener.local_addr()`, and pass
    /// the listener here without a release-and-rebind race.
    pub async fn serve_on(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        validate_listener_identity(self.listen)?;
        let actual = listener
            .local_addr()
            .context("read pre-bound api-proxy listener address")?;
        if actual != self.listen {
            return Err(anyhow!(
                "pre-bound api-proxy listener address {} does not match configured address {}",
                actual,
                self.listen
            ));
        }
        let acceptor = TlsAcceptor::from(self.tls.server_config());
        tracing::info!(
            "guard api-proxy ({}) listening on https://{} -> {}",
            self.protocol.name(),
            self.listen,
            self.upstream.base()
        );

        if let Some(path) = self.policy_path.clone() {
            let me = self.clone();
            tokio::spawn(async move { policy_reloader(path, me).await });
        }

        loop {
            let (tcp, _peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!("api-proxy accept error: {}", e);
                    continue;
                }
            };
            let acceptor = acceptor.clone();
            let me = self.clone();
            // A per-connection id scopes delete provenance to the connection that
            // created a resource. The Guard session bearer is request context,
            // not an upstream Kubernetes identity.
            let conn_id = self.next_conn.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(tcp).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!("api-proxy TLS handshake failed: {}", e);
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
                    tracing::debug!("api-proxy connection error: {}", e);
                }
            });
        }
    }

    /// Classify and dispatch one request. Always returns a response (never errors
    /// the connection); upstream and policy failures become HTTP status bodies.
    async fn route(&self, mut req: Request<Incoming>, conn_id: u64) -> Response<ProxyBody> {
        let method = req.method().clone();
        let path = req.uri().path().to_string();
        let has_identity_override = req.headers().keys().any(is_identity_header);
        let session_token = match take_guard_session(req.headers_mut()) {
            Ok(token) => token,
            Err(reason) => {
                return self.status_resp(StatusCode::FORBIDDEN, reason, "Forbidden");
            }
        };
        let session_context = if let Some(token) = session_token.as_deref() {
            let Some(sink) = self.session_sink.get() else {
                return self.status_resp(
                    StatusCode::FORBIDDEN,
                    "guard api-proxy: session attribution is unavailable",
                    "Forbidden",
                );
            };
            match sink.resolve(token).await {
                Some(context) => Some(context),
                None => {
                    return self.status_resp(
                        StatusCode::FORBIDDEN,
                        "guard api-proxy: unknown or expired session",
                        "Forbidden",
                    )
                }
            }
        } else {
            None
        };
        if has_identity_override {
            let response = self.status_resp(
                StatusCode::FORBIDDEN,
                "guard api-proxy: identity impersonation is not supported; the request was not forwarded",
                "Forbidden",
            );
            if let (Some(token), Some(sink)) = (session_token.as_deref(), self.session_sink.get()) {
                sink.record(
                    token,
                    ApiSessionEvent {
                        endpoint: self.endpoint.clone(),
                        operation: format!("{} {}", method, path),
                        allowed: false,
                        status: response.status().as_u16(),
                        held: false,
                        credential_ref: self.credential_ref.clone(),
                    },
                )
                .await;
            }
            return response;
        }
        if session_context.as_ref().is_some_and(|context| {
            context
                .secret_entitlements
                .as_ref()
                .is_some_and(|names| !names.iter().any(|name| name == &self.credential_ref))
        }) {
            return self.status_resp(
                StatusCode::FORBIDDEN,
                "guard api-proxy: session is not entitled to this upstream credential",
                "Forbidden",
            );
        }
        if let (Some(token), Some(context)) = (session_token.clone(), session_context.clone()) {
            req.extensions_mut().insert(SessionAuth { token, context });
        }
        let response = self.route_inner(req, conn_id, session_context).await;
        if let (Some(token), Some(sink)) = (session_token.as_deref(), self.session_sink.get()) {
            let hold_outcome = response.extensions().get::<GuardHoldOutcome>().copied();
            sink.record(
                token,
                ApiSessionEvent {
                    endpoint: self.endpoint.clone(),
                    operation: format!("{} {}", method, path),
                    allowed: hold_outcome != Some(GuardHoldOutcome::Denied)
                        && response.extensions().get::<GuardRejected>().is_none(),
                    status: response.status().as_u16(),
                    held: hold_outcome.is_some(),
                    credential_ref: self.credential_ref.clone(),
                },
            )
            .await;
        }
        response
    }

    async fn route_inner(
        &self,
        mut req: Request<Incoming>,
        conn_id: u64,
        session_context: Option<ApiSessionContext>,
    ) -> Response<ProxyBody> {
        let (route_policy, route_authority) = match self.capture_route_authority().await {
            Ok(authority) => authority,
            Err(_) => {
                return self.status_resp(
                    StatusCode::FORBIDDEN,
                    "guard api-proxy: API route authority is unavailable",
                    "Forbidden",
                )
            }
        };
        req.extensions_mut().insert(route_authority);
        let method = req.method().clone();
        let path = req.uri().path().to_string();
        let query = req.uri().query().unwrap_or("").to_string();

        // The gate must classify exactly the path the upstream will serve.
        // Re-origination normalizes dot segments (including their
        // percent-encoded forms) and an upstream router may decode encoded
        // separators, so such a path would be gated as one request and served
        // as another; reject it before parsing.
        if path_alters_on_forward(&path) {
            return self.status_resp(
                StatusCode::FORBIDDEN,
                "guard api-proxy: path with dot segments or encoded separators is not forwarded",
                "Forbidden",
            );
        }

        let Some(op) = self.protocol.parse_op(method.as_str(), &path, &query) else {
            // Unknown paths are denied by default. A protocol can explicitly
            // recognize the small non-resource discovery surface its clients
            // require; method alone never grants forwarding authority.
            if self
                .protocol
                .classify_non_resource_read(method.as_str(), &path, &query)
                .is_some()
            {
                return self.forward(req, &path, &query, false, None, conn_id).await;
            }
            return self.status_resp(
                StatusCode::FORBIDDEN,
                "guard api-proxy: unknown or unapproved non-resource path rejected",
                "Forbidden",
            );
        };

        // Operations the protocol never forwards regardless of policy: streams
        // the request-level gate cannot inspect or redact per object.
        if let Some(reason) = self.protocol.deny_outright(&op) {
            return self.status_resp(StatusCode::FORBIDDEN, &reason, "Forbidden");
        }

        if self.is_kubernetes_mutation(&op) && session_context.is_none() {
            return self.status_resp(
                StatusCode::FORBIDDEN,
                "guard api-proxy: Kubernetes mutations require an attributable Guard session or an operator-approved typed verb",
                "Forbidden",
            );
        }

        // Policy can constrain object metadata carried in a write body. Buffer
        // only after protocol hard-denies and attribution checks have run, then
        // preserve these exact bytes through classification and forwarding.
        let (parts, body) = match collect_request_body(req, self.request_body_timeout).await {
            Ok(buffered) => buffered,
            Err(error) => return self.request_body_error_response(error),
        };

        let label = format!("{} {}", op.verb.as_str(), path);

        let decision = route_policy.decide(&op, &body);

        // Protocol floors and explicit operator policy denies are absolute.
        // Session mode can only choose a stricter deterministic path or route a
        // readonly listener write to evaluation under explicit issued intent.
        if matches!(decision.action, ApiAction::Deny) {
            tracing::info!(target: "guard::apiproxy", "DENY {} ({})", label, decision.reason);
            return self.status_resp(
                StatusCode::FORBIDDEN,
                &format!(
                    "guard api-proxy ({}) denied {label}: {}",
                    self.protocol.name(),
                    decision.reason
                ),
                "Forbidden",
            );
        }
        let session_mode = session_context
            .as_ref()
            .map(|context| context.evaluation_mode)
            .unwrap_or_default();
        if !op.is_read() && session_mode == ApiEvaluationMode::ReadOnly {
            return self
                .route_coverage_only(
                    BufferedRequest { parts, body },
                    RouteMetadata {
                        path: &path,
                        query: &query,
                        op: &op,
                    },
                    false,
                    conn_id,
                    session_context.as_ref(),
                )
                .await;
        }
        if !matches!(decision.action, ApiAction::Hold) {
            if self.listener_mode == ApiListenerMode::Readonly && !op.is_read() {
                if session_context
                    .as_ref()
                    .is_some_and(|context| context.can_evaluate_api_override)
                {
                    return self
                        .route_evaluate(
                            BufferedRequest { parts, body },
                            RouteMetadata {
                                path: &path,
                                query: &query,
                                op: &op,
                            },
                            false,
                            conn_id,
                            session_context.as_ref(),
                        )
                        .await;
                }
                if session_context.is_some() {
                    return self
                        .route_coverage_only(
                            BufferedRequest { parts, body },
                            RouteMetadata {
                                path: &path,
                                query: &query,
                                op: &op,
                            },
                            false,
                            conn_id,
                            session_context.as_ref(),
                        )
                        .await;
                }
                return self.status_resp(
                    StatusCode::FORBIDDEN,
                    "guard api-proxy: listener readonly baseline denied a write without explicit session authority",
                    "Forbidden",
                );
            }
            if session_mode == ApiEvaluationMode::PolicyOnly
                && matches!(decision.action, ApiAction::Evaluate)
            {
                return self
                    .route_coverage_only(
                        BufferedRequest { parts, body },
                        RouteMetadata {
                            path: &path,
                            query: &query,
                            op: &op,
                        },
                        false,
                        conn_id,
                        session_context.as_ref(),
                    )
                    .await;
            }
        }

        // A delete of a resource guard itself created (and is still tracking for
        // auto-revert) in this process is contained cleanup, such as a Helm
        // post-install hook deleting its own check resource. Allow it without
        // resolving the revert until the upstream returns a complete 2xx
        // response. Provenance is evidence-based: only a resource the proxy
        // forwarded a create for matches, so deletes of resources with no
        // creation record keep the standard policy handling.
        // Explicit policy denies remain absolute. Provenance can simplify a
        // permitted cleanup, but it never overrides an operator deny.
        if !matches!(decision.action, ApiAction::Deny)
            && op.verb == Verb::Delete
            && op.subresource.is_none()
        {
            if let Some(created) = self.created_provenance(
                &op,
                conn_id,
                session_context
                    .as_ref()
                    .map(|context| context.fingerprint.as_str()),
            ) {
                let same_resource = self
                    .validate_current_created_object(
                        &created.key,
                        &path,
                        &created.resource_uid,
                        &created.create_provenance,
                    )
                    .await
                    .is_ok();
                if same_resource {
                    let _ = crate::audit::emit_global(
                        &crate::audit::AuditEvent::new(crate::audit::AuditKind::Evaluate)
                            .handle(&created.handle)
                            .reason(
                                "contained: guard-created this session, auto-revert remains armed until delete succeeds",
                            )
                            .field("decision", "allow")
                            .field("label", &label),
                    );
                    return self
                        .forward_contained_cleanup(
                            BufferedRequest { parts, body },
                            RouteMetadata {
                                path: &path,
                                query: &query,
                                op: &op,
                            },
                            conn_id,
                            created,
                        )
                        .await;
                }
                self.created
                    .lock()
                    .unwrap()
                    .take_if_handle(&created.key, &created.handle);
            }
        }

        match decision.action {
            ApiAction::Deny => unreachable!("explicit deny returned above"),
            ApiAction::Hold => {
                self.route_hold_buffered(
                    BufferedRequest { parts, body },
                    &path,
                    &query,
                    &op,
                    &decision.reason,
                    conn_id,
                    None,
                )
                .await
            }
            ApiAction::Evaluate => {
                self.route_evaluate(
                    BufferedRequest { parts, body },
                    RouteMetadata {
                        path: &path,
                        query: &query,
                        op: &op,
                    },
                    false,
                    conn_id,
                    session_context.as_ref(),
                )
                .await
            }
            ApiAction::Allow => {
                // Rarity escalation: a broad allow rule fails toward scrutiny on
                // a shape it covers that the proxy has rarely (or never) seen.
                // With a judge attached, the rare shape is evaluated with an
                // explicit rarity flag; without one it follows the existing hold
                // path and fails closed when no queue is attached.
                if self.rarity.enabled() {
                    let key = self.shape_key(&op);
                    if self.rarity.observe_is_rare(key) {
                        if self.has_judge() && session_mode != ApiEvaluationMode::PolicyOnly {
                            tracing::info!(
                                target: "guard::apiproxy",
                                "EVALUATE {} (rare shape under an allow rule)",
                                label
                            );
                            return self
                                .route_evaluate(
                                    BufferedRequest { parts, body },
                                    RouteMetadata {
                                        path: &path,
                                        query: &query,
                                        op: &op,
                                    },
                                    true,
                                    conn_id,
                                    session_context.as_ref(),
                                )
                                .await;
                        } else {
                            let reason = format!(
                                "{} (rare request shape escalated for review)",
                                decision.reason
                            );
                            tracing::info!(
                                target: "guard::apiproxy",
                                "ESCALATE {} (rare shape under an allow rule)",
                                label
                            );
                            return self
                                .route_hold_buffered(
                                    BufferedRequest { parts, body },
                                    &path,
                                    &query,
                                    &op,
                                    &reason,
                                    conn_id,
                                    None,
                                )
                                .await;
                        }
                    }
                }
                let redact = self.protocol.redactable_read(&op);
                tracing::info!(target: "guard::apiproxy", "ALLOW {}{}", label, if redact { " (redacting)" } else { "" });
                self.forward_buffered(
                    BufferedRequest { parts, body },
                    &path,
                    &query,
                    redact,
                    Some(op.clone()),
                    conn_id,
                    None,
                    None,
                )
                .await
            }
        }
    }

    async fn route_evaluate<'a>(
        &self,
        buffered: BufferedRequest,
        route: RouteMetadata<'a>,
        rarity: bool,
        conn_id: u64,
        session_context: Option<&ApiSessionContext>,
    ) -> Response<ProxyBody> {
        let mut parts = buffered.parts;
        let body = buffered.body;
        let path = route.path;
        let query = route.query;
        let op = route.op;
        let label = format!("{} {}", op.verb.as_str(), path);
        if session_context
            .is_some_and(|context| context.evaluation_mode == ApiEvaluationMode::PolicyOnly)
        {
            return self.status_resp(
                StatusCode::FORBIDDEN,
                "guard api-proxy: policy-only session cannot invoke the evaluator",
                "Forbidden",
            );
        }
        let Some(judge) = self
            .judge
            .read()
            .unwrap()
            .clone()
            .filter(|judge| judge.evaluator_enabled())
        else {
            return self
                .route_hold_buffered(
                    BufferedRequest { parts, body },
                    path,
                    query,
                    op,
                    "api-policy evaluate requested but no evaluator is attached",
                    conn_id,
                    None,
                )
                .await;
        };

        let coverage_body_shape = redacted_body_shape(&body);
        let mut body = match prepare_create_provenance(
            &mut parts,
            body,
            op,
            self.gate.get().is_some() && self.protocol.tracks_write(op),
        ) {
            Ok(body) => body,
            Err(reason) => return self.status_resp(StatusCode::BAD_REQUEST, &reason, "Invalid"),
        };
        let route_authority = match self.route_authority_from_parts(&parts) {
            Some(authority) => authority,
            None => return self.missing_route_authority_response(),
        };
        let prepared_mutation = if self.is_kubernetes_mutation(op) {
            match self
                .arbitrate_kubernetes_mutation(&parts, &body, path, op, &route_authority, None)
                .await
            {
                Ok((guarded_body, snapshot)) => {
                    body = guarded_body;
                    Some(PreparedMutation {
                        prior_snapshot: snapshot,
                        body_sha256: body_sha256(&body),
                    })
                }
                Err(response) => return response,
            }
        } else {
            None
        };
        let prepared = if self.is_kubernetes_mutation(op) {
            self.revert_constructibility_from_prepared(op, prepared_mutation.as_ref())
        } else {
            match self.prepare_revert(op, path, &route_authority).await {
                Ok(prepared) => prepared,
                Err(response) => return response,
            }
        };
        if let Some(prepared) = prepared_mutation.as_ref() {
            parts.extensions.insert(prepared.clone());
        }
        let final_body_shape = redacted_body_shape(&body);
        let authorized_body_sha256 = body_sha256(&body);
        let summary = ApiRequestSummary {
            protocol: self.protocol.name().to_string(),
            verb: op.verb.as_str().to_string(),
            path: path.to_string(),
            redacted_query: crate::evaluate::redact_for_llm(query),
            group: op.group.clone(),
            version: op.version.clone(),
            resource: op.resource.clone(),
            subresource: op.subresource.clone(),
            namespace: op.namespace.clone(),
            name: op.name.clone(),
            dry_run: op.dry_run,
            authority_selectors: op.authority_selectors.clone(),
            coverage_body_shape,
            redacted_body_shape: final_body_shape,
            authorized_body_sha256,
            revert_constructible: prepared,
            rarity,
            endpoint: self.endpoint.clone(),
            session_fingerprint: session_context.map(|context| context.fingerprint.clone()),
            session_revision: session_context.map(|context| context.revision.clone()),
            session_intent: session_context.and_then(|context| {
                context
                    .intent
                    .as_deref()
                    .map(crate::evaluate::redact_for_llm)
            }),
            credential_ref: self.credential_ref.clone(),
        };

        match judge.judge(&summary).await {
            ApiJudgeVerdict::Deny { reason } => {
                let _ = crate::audit::emit_global(
                    &crate::audit::AuditEvent::new(crate::audit::AuditKind::Evaluate)
                        .reason(&reason)
                        .field("decision", "deny")
                        .field("risk", "none")
                        .field("reversibility", "none")
                        .field("label", &label),
                );
                self.status_resp(
                    StatusCode::FORBIDDEN,
                    &format!(
                        "guard api-proxy ({}) evaluator denied {label}: {reason}",
                        self.protocol.name()
                    ),
                    "Forbidden",
                )
            }
            ApiJudgeVerdict::Error(error) => {
                // Deny on an evaluator error, matching the command path. An
                // evaluator outage would otherwise park a buffered request per
                // failed call in the operator queue with no decision an operator
                // could usefully make, so denying fails closed without flooding
                // the queue.
                let _ = crate::audit::emit_global(
                    &crate::audit::AuditEvent::new(crate::audit::AuditKind::Evaluate)
                        .reason(&error)
                        .field("decision", "error")
                        .field("risk", "none")
                        .field("reversibility", "none")
                        .field("label", &label),
                );
                self.status_resp(
                    StatusCode::FORBIDDEN,
                    &format!(
                        "guard api-proxy ({}) denied {label}: evaluator error: {error}",
                        self.protocol.name()
                    ),
                    "Forbidden",
                )
            }
            ApiJudgeVerdict::Allow {
                reason,
                risk,
                reversibility,
                authorization,
            } => {
                let _ = crate::audit::emit_global(
                    &crate::audit::AuditEvent::new(crate::audit::AuditKind::Evaluate)
                        .reason(&reason)
                        .field("decision", "allow")
                        .field("risk", format!("{risk:?}"))
                        .field("reversibility", format!("{reversibility:?}"))
                        .field("label", &label),
                );
                let pending_authorization = match authorization {
                    ApiAuthorizationKind::Evaluated => PendingApiAuthorization {
                        judge: judge.clone(),
                        summary: summary.clone(),
                        requirement: ApiForwardRequirement::Evaluated,
                    },
                    ApiAuthorizationKind::Coverage => {
                        let (Some(risk), Some(reversibility)) = (risk, reversibility) else {
                            return self.status_resp(
                                StatusCode::FORBIDDEN,
                                "guard api-proxy coverage authorization is incomplete",
                                "Forbidden",
                            );
                        };
                        PendingApiAuthorization {
                            judge: judge.clone(),
                            summary: summary.clone(),
                            requirement: ApiForwardRequirement::Coverage {
                                risk,
                                reversibility,
                            },
                        }
                    }
                };
                let outcome = decide_gate(reversibility, risk, prepared.is_constructible(), false);
                match outcome {
                    // Reversible/low-risk: no envelope needed, forward as-is.
                    GateOutcome::ExecuteNow => {
                        let redact = self.protocol.redactable_read(op);
                        tracing::info!(
                            target: "guard::apiproxy",
                            "ALLOW {} (evaluator){}",
                            label,
                            if redact { " (redacting)" } else { "" }
                        );
                        self.forward_buffered(
                            BufferedRequest { parts, body },
                            path,
                            query,
                            redact,
                            Some(op.clone()),
                            conn_id,
                            prepared_mutation,
                            Some(pending_authorization),
                        )
                        .await
                    }
                    // Contain: the gate only chose Contain over Hold because a
                    // revert was promised, so the envelope must actually be
                    // armable. For a restore/recreate revert, re-fetch the prior
                    // object now (fresh, after the evaluator round trip) and
                    // confirm it plans before forwarding; if it cannot, fail
                    // closed to a hold rather than forward an uncontained
                    // mutation. The validated snapshot is threaded to the forward
                    // so arming uses exactly what was checked (no third fetch).
                    GateOutcome::Contain if prepared.is_constructible() => {
                        // The evaluator may have taken arbitrarily long. Refresh
                        // both session authority and explicit policy before the
                        // snapshot fetch, which is itself upstream I/O. The
                        // forwarding path repeats these checks immediately
                        // before the mutation.
                        if let Err(response) = self.revalidate_session(&parts).await {
                            return response;
                        }
                        if let Some(response) = self
                            .recheck_final_authority(&route_authority, Some(op))
                            .await
                        {
                            return response;
                        }
                        // Contain was chosen over Hold only because a revert was
                        // promised, so the sink must actually be able to arm one
                        // right now (capacity, and a safe revert store). If not,
                        // hold rather than forward a write that cannot be
                        // contained.
                        let can_arm = match self.gate.get() {
                            Some(gate) => gate.can_arm_revert().await,
                            None => false,
                        };
                        if !can_arm {
                            return self
                                .route_hold_buffered(BufferedRequest { parts, body },
                                    path,
                                    query,
                                    op,
                                    "evaluator allowed a contained write but no auto-revert can be armed right now",
                                    conn_id,
                                    Some(pending_authorization),
                                )
                                .await;
                        }
                        let forward_prepared = if prepared_mutation.is_some() {
                            prepared_mutation
                        } else if self.protocol.wants_prior_snapshot(op) {
                            match self
                                .fetch_validated_snapshot(op, path, &route_authority)
                                .await
                            {
                                Ok(Some(snapshot)) => Some(PreparedMutation {
                                    prior_snapshot: Some(snapshot),
                                    body_sha256: body_sha256(&body),
                                }),
                                Ok(None) => {
                                    return self
                                        .route_hold_buffered(BufferedRequest { parts, body },
                                            path,
                                            query,
                                            op,
                                            "evaluator allowed a contained write but its revert could not be re-established at forward time",
                                            conn_id,
                                            Some(pending_authorization),
                                        )
                                        .await;
                                }
                                Err(response) => return response,
                            }
                        } else {
                            // A named create's delete revert is built from the
                            // exact buffered request immediately before send.
                            None
                        };
                        let redact = self.protocol.redactable_read(op);
                        tracing::info!(
                            target: "guard::apiproxy",
                            "ALLOW {} (evaluator contained){}",
                            label,
                            if redact { " (redacting)" } else { "" }
                        );
                        self.forward_buffered(
                            BufferedRequest { parts, body },
                            path,
                            query,
                            redact,
                            Some(op.clone()),
                            conn_id,
                            forward_prepared,
                            Some(pending_authorization),
                        )
                        .await
                    }
                    GateOutcome::Contain | GateOutcome::Hold => {
                        self.route_hold_buffered(
                            BufferedRequest { parts, body },
                            path,
                            query,
                            op,
                            &format!("api evaluator allowed but consequence gate held: {reason}"),
                            conn_id,
                            Some(pending_authorization),
                        )
                        .await
                    }
                }
            }
        }
    }

    /// Resolve exact typed API coverage without invoking the evaluator. This is
    /// the only write path available to read-only sessions and the fallback for
    /// `evaluate` policy cells under policy-only sessions.
    async fn route_coverage_only<'a>(
        &self,
        buffered: BufferedRequest,
        route: RouteMetadata<'a>,
        rarity: bool,
        conn_id: u64,
        session_context: Option<&ApiSessionContext>,
    ) -> Response<ProxyBody> {
        let mut parts = buffered.parts;
        let body = buffered.body;
        let path = route.path;
        let query = route.query;
        let op = route.op;
        let coverage_body_shape = redacted_body_shape(&body);
        let mut body = match prepare_create_provenance(
            &mut parts,
            body,
            op,
            self.gate.get().is_some() && self.protocol.tracks_write(op),
        ) {
            Ok(body) => body,
            Err(reason) => return self.status_resp(StatusCode::BAD_REQUEST, &reason, "Invalid"),
        };
        let Some(judge) = self
            .judge
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        else {
            return self.status_resp(
                StatusCode::FORBIDDEN,
                "guard api-proxy: no exact typed API coverage resolver is attached",
                "Forbidden",
            );
        };
        let route_authority = match self.route_authority_from_parts(&parts) {
            Some(authority) => authority,
            None => return self.missing_route_authority_response(),
        };
        let prepared_mutation = if self.is_kubernetes_mutation(op) {
            match self
                .arbitrate_kubernetes_mutation(&parts, &body, path, op, &route_authority, None)
                .await
            {
                Ok((guarded_body, snapshot)) => {
                    body = guarded_body;
                    Some(PreparedMutation {
                        prior_snapshot: snapshot,
                        body_sha256: body_sha256(&body),
                    })
                }
                Err(response) => return response,
            }
        } else {
            None
        };
        if let Some(prepared) = prepared_mutation.as_ref() {
            parts.extensions.insert(prepared.clone());
        }
        let summary = ApiRequestSummary {
            protocol: self.protocol.name().to_string(),
            verb: op.verb.as_str().to_string(),
            path: path.to_string(),
            redacted_query: crate::evaluate::redact_for_llm(query),
            group: op.group.clone(),
            version: op.version.clone(),
            resource: op.resource.clone(),
            subresource: op.subresource.clone(),
            namespace: op.namespace.clone(),
            name: op.name.clone(),
            dry_run: op.dry_run,
            authority_selectors: op.authority_selectors.clone(),
            coverage_body_shape,
            redacted_body_shape: redacted_body_shape(&body),
            authorized_body_sha256: body_sha256(&body),
            revert_constructible: RevertConstructible::None,
            rarity,
            endpoint: self.endpoint.clone(),
            session_fingerprint: session_context.map(|context| context.fingerprint.clone()),
            session_revision: session_context.map(|context| context.revision.clone()),
            session_intent: session_context.and_then(|context| {
                context
                    .intent
                    .as_deref()
                    .map(crate::evaluate::redact_for_llm)
            }),
            credential_ref: self.credential_ref.clone(),
        };
        match judge.coverage(&summary).await {
            ApiCoverageVerdict::Allow {
                risk,
                reversibility,
            } => {
                let outcome = decide_gate(Some(reversibility), Some(risk), false, false);
                let pending_authorization = PendingApiAuthorization {
                    judge: judge.clone(),
                    summary,
                    requirement: ApiForwardRequirement::Coverage {
                        risk,
                        reversibility,
                    },
                };
                if outcome != GateOutcome::ExecuteNow {
                    return self
                        .route_hold_buffered(
                            BufferedRequest { parts, body },
                            path,
                            query,
                            op,
                            "exact typed API coverage requires consequence approval",
                            conn_id,
                            Some(pending_authorization),
                        )
                        .await;
                }
                let redact = self.protocol.redactable_read(op);
                self.forward_buffered(
                    BufferedRequest { parts, body },
                    path,
                    query,
                    redact,
                    Some(op.clone()),
                    conn_id,
                    prepared_mutation,
                    Some(pending_authorization),
                )
                .await
            }
            ApiCoverageVerdict::Deny { reason, .. } => self.status_resp(
                StatusCode::FORBIDDEN,
                &format!("guard api-proxy exact typed coverage denied request: {reason}"),
                "Forbidden",
            ),
            ApiCoverageVerdict::None => self.status_resp(
                StatusCode::FORBIDDEN,
                "guard api-proxy: exact session-scoped typed API coverage is required",
                "Forbidden",
            ),
        }
    }

    /// The rarity-accounting shape for an operation: everything that
    /// distinguishes one kind of request from another except the object name.
    fn shape_key(&self, op: &ApiOp) -> ShapeKey {
        ShapeKey {
            protocol: self.protocol.name().to_string(),
            verb: op.verb.as_str(),
            group: op.group.clone(),
            resource: op.resource.clone(),
            subresource: op.subresource.clone(),
            namespace: op.namespace.clone(),
            authority_selectors: op.authority_selectors.clone(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn route_hold_buffered(
        &self,
        buffered: BufferedRequest,
        path: &str,
        query: &str,
        op: &ApiOp,
        reason: &str,
        conn_id: u64,
        mut authorization: Option<PendingApiAuthorization>,
    ) -> Response<ProxyBody> {
        let mut parts = buffered.parts;
        let body = buffered.body;
        let mut body = match prepare_create_provenance(
            &mut parts,
            body,
            op,
            self.gate.get().is_some() && self.protocol.tracks_write(op),
        ) {
            Ok(body) => body,
            Err(reason) => return self.status_resp(StatusCode::BAD_REQUEST, &reason, "Invalid"),
        };
        let label = format!("{} {}", op.verb.as_str(), path);
        let Some(gate) = self.gate.get() else {
            tracing::info!(
                target: "guard::apiproxy",
                "HOLD {} denied: no approval queue (--gate consequence is not active)",
                label
            );
            return self.status_resp(
                StatusCode::FORBIDDEN,
                &format!(
                    "guard api-proxy ({}): {label} requires operator approval, but the daemon \
                     is running without --gate consequence (no approval queue); denied",
                    self.protocol.name()
                ),
                "Forbidden",
            );
        };
        let route_authority = match self.route_authority_from_parts(&parts) {
            Some(authority) => authority,
            None => return self.missing_route_authority_response(),
        };
        let mut prepared_mutation = parts.extensions.get::<PreparedMutation>().cloned();
        let mut preparation_error = None;
        if prepared_mutation.is_none() && self.is_kubernetes_mutation(op) {
            match self
                .arbitrate_kubernetes_mutation(&parts, &body, path, op, &route_authority, None)
                .await
            {
                Ok((guarded_body, snapshot)) => {
                    body = guarded_body;
                    prepared_mutation = Some(PreparedMutation {
                        prior_snapshot: snapshot,
                        body_sha256: body_sha256(&body),
                    });
                }
                // A request that is denied by the hold never reaches the
                // upstream, so an unavailable concurrency snapshot must not
                // bypass the operator's denial. If the operator approves, the
                // preparation failure is returned and no bytes are sent.
                Err(response) => preparation_error = Some(response),
            }
        }
        if let Some(pending) = authorization.as_mut() {
            pending.summary.redacted_body_shape = redacted_body_shape(&body);
            pending.summary.authorized_body_sha256 = body_sha256(&body);
        }
        tracing::info!(target: "guard::apiproxy", "HOLD {} ({})", label, reason);
        let snapshot = api_hold_snapshot(label.clone(), query, op, &body);
        let session_context = parts
            .extensions
            .get::<SessionAuth>()
            .map(|auth| &auth.context);
        let (mut response, outcome) =
            match gate.hold_request(&snapshot, reason, session_context).await {
                HoldDecision::Approved { handle } => {
                    if let Some(response) = preparation_error.take() {
                        (response, GuardHoldOutcome::Denied)
                    } else {
                        let redact = self.protocol.redactable_read(op);
                        tracing::info!(
                            target: "guard::apiproxy",
                            "ALLOW {} (operator approved hold {}){}",
                            label,
                            handle,
                            if redact { " (redacting)" } else { "" }
                        );
                        let mut parts = parts;
                        parts.extensions.insert(ApprovedApiHold {
                            body_sha256: snapshot.body_sha256.clone(),
                        });
                        let response = self
                            .forward_buffered(
                                BufferedRequest { parts, body },
                                path,
                                query,
                                redact,
                                Some(op.clone()),
                                conn_id,
                                prepared_mutation,
                                authorization,
                            )
                            .await;
                        (response, GuardHoldOutcome::Approved)
                    }
                }
                HoldDecision::Denied { reason, handle } => {
                    tracing::info!(target: "guard::apiproxy", "DENY {} (held: {})", label, reason);
                    let message = handle.as_ref().map_or_else(
                        || {
                            format!(
                            "guard api-proxy ({}): {label} held for operator approval: {reason}",
                            self.protocol.name()
                        )
                        },
                        |handle| {
                            format!(
                                "guard api-proxy ({}): {label} held for operator approval \
                                 {handle}: {reason}; inspect with guard approval show {handle}",
                                self.protocol.name()
                            )
                        },
                    );
                    let response = self.approval_status_resp(
                        StatusCode::FORBIDDEN,
                        &message,
                        "Forbidden",
                        handle.as_deref(),
                    );
                    (response, GuardHoldOutcome::Denied)
                }
            };
        response.extensions_mut().insert(outcome);
        response
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
        let (parts, body) = match collect_request_body(req, self.request_body_timeout).await {
            Ok(buffered) => buffered,
            Err(error) => return self.request_body_error_response(error),
        };
        self.forward_buffered(
            BufferedRequest { parts, body },
            path,
            query,
            redact,
            op,
            conn_id,
            None,
            None,
        )
        .await
    }

    async fn forward_contained_cleanup<'a>(
        &self,
        buffered: BufferedRequest,
        route: RouteMetadata<'a>,
        conn_id: u64,
        created: CreatedMatch,
    ) -> Response<ProxyBody> {
        let parts = buffered.parts;
        let body = buffered.body;
        let path = route.path;
        let query = route.query;
        let op = route.op;
        self.forward_buffered_with_cleanup(
            BufferedRequest { parts, body },
            path,
            query,
            false,
            Some(op.clone()),
            conn_id,
            None,
            Some(created),
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn forward_buffered(
        &self,
        buffered: BufferedRequest,
        path: &str,
        query: &str,
        redact: bool,
        op: Option<ApiOp>,
        conn_id: u64,
        prepared_mutation: Option<PreparedMutation>,
        authorization: Option<PendingApiAuthorization>,
    ) -> Response<ProxyBody> {
        self.forward_buffered_with_cleanup(
            BufferedRequest {
                parts: buffered.parts,
                body: buffered.body,
            },
            path,
            query,
            redact,
            op,
            conn_id,
            prepared_mutation,
            None,
            authorization,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn forward_buffered_with_cleanup(
        &self,
        buffered: BufferedRequest,
        path: &str,
        query: &str,
        redact: bool,
        op: Option<ApiOp>,
        conn_id: u64,
        prepared_mutation: Option<PreparedMutation>,
        created_cleanup: Option<CreatedMatch>,
        authorization: Option<PendingApiAuthorization>,
    ) -> Response<ProxyBody> {
        let mut parts = buffered.parts;
        let mut body = buffered.body;
        if let Some(operation) = op.as_ref() {
            body = match prepare_create_provenance(
                &mut parts,
                body,
                operation,
                created_cleanup.is_none()
                    && self.gate.get().is_some()
                    && self.protocol.tracks_write(operation),
            ) {
                Ok(body) => body,
                Err(reason) => {
                    return self.status_resp(StatusCode::BAD_REQUEST, &reason, "Invalid")
                }
            };
        }
        let route_authority = match self.route_authority_from_parts(&parts) {
            Some(authority) => authority,
            None => return self.missing_route_authority_response(),
        };
        let mut prepared_mutation =
            prepared_mutation.or_else(|| parts.extensions.get::<PreparedMutation>().cloned());
        if let Some(prepared) = prepared_mutation.as_ref() {
            if prepared.body_sha256 != body_sha256(&body) {
                return self.status_resp(
                    StatusCode::FORBIDDEN,
                    "guard api-proxy: prepared request bytes changed before forwarding",
                    "Forbidden",
                );
            }
        } else if let Some(operation) = op
            .as_ref()
            .filter(|operation| self.is_kubernetes_mutation(operation))
        {
            match self
                .arbitrate_kubernetes_mutation(
                    &parts,
                    &body,
                    path,
                    operation,
                    &route_authority,
                    None,
                )
                .await
            {
                Ok((guarded_body, snapshot)) => {
                    body = guarded_body;
                    prepared_mutation = Some(PreparedMutation {
                        prior_snapshot: snapshot,
                        body_sha256: body_sha256(&body),
                    });
                }
                Err(response) => return response,
            }
        }
        if let Some(approved) = parts.extensions.get::<ApprovedApiHold>() {
            if approved.body_sha256 != body_sha256(&body) {
                return self.status_resp(
                    StatusCode::FORBIDDEN,
                    "guard api-proxy: final request bytes changed after approval; submit a fresh approval",
                    "Forbidden",
                );
            }
        }
        // Snapshot reads can block on the upstream. Acquire any snapshot before
        // the common final authority checks so a session edit, expiry, or policy
        // reload during that read is observed immediately before mutation.
        let track_write = created_cleanup.is_none()
            && op
                .as_ref()
                .is_some_and(|op| self.gate.get().is_some() && self.protocol.tracks_write(op));
        if prepared_mutation.is_none()
            && track_write
            && self
                .protocol
                .wants_prior_snapshot(op.as_ref().expect("tracked write has operation"))
        {
            prepared_mutation = match self.fetch_prior_object(path, &route_authority).await {
                Ok(snapshot) => Some(PreparedMutation {
                    prior_snapshot: snapshot,
                    body_sha256: body_sha256(&body),
                }),
                Err(response) => return response,
            };
        }
        let session_context = match self.revalidate_session(&parts).await {
            Ok(context) => context,
            Err(response) => return response,
        };
        let staged_revert = if track_write {
            let operation = op.as_ref().expect("tracked write has operation");
            let handle = self
                .arm_write_revert(
                    operation,
                    prepared_mutation
                        .as_ref()
                        .and_then(|prepared| prepared.prior_snapshot.clone()),
                    &body,
                    conn_id,
                    session_context.clone(),
                    parts
                        .extensions
                        .get::<PreparedCreateProvenance>()
                        .map(|marker| marker.0.clone()),
                )
                .await;
            if handle.is_none() && parts.extensions.get::<ApprovedApiHold>().is_none() {
                return Box::pin(self.route_hold_buffered(
                    BufferedRequest { parts, body },
                    path,
                    query,
                    operation,
                    "the mutation could not be durably contained before forwarding",
                    conn_id,
                    authorization,
                ))
                .await;
            }
            handle
        } else {
            None
        };
        match self
            .forward_inner(
                parts,
                body,
                path,
                query,
                redact,
                op,
                session_context,
                created_cleanup,
                route_authority,
                authorization,
                staged_revert,
            )
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                tracing::warn!(target: "guard::apiproxy", "upstream error for {path}: {e:#}");
                self.status_resp(
                    StatusCode::BAD_GATEWAY,
                    &format!(
                        "guard api-proxy ({}): upstream error: {e}",
                        self.protocol.name()
                    ),
                    "InternalError",
                )
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn forward_inner(
        &self,
        parts: Parts,
        body: Bytes,
        path: &str,
        query: &str,
        redact: bool,
        op: Option<ApiOp>,
        session_context: Option<ApiSessionContext>,
        created_cleanup: Option<CreatedMatch>,
        route_authority: RouteAuthority,
        authorization: Option<PendingApiAuthorization>,
        staged_revert: Option<StagedRevert>,
    ) -> Result<Response<ProxyBody>> {
        // A recoverable write is staged durably before its finite upstream
        // handoff. Snapshot acquisition occurs in the caller before its final
        // authority checks.
        let track_write = created_cleanup.is_none()
            && op
                .as_ref()
                .is_some_and(|o| self.gate.get().is_some() && self.protocol.tracks_write(o));
        let mut containment = staged_revert.and_then(|staged| {
            self.gate
                .get()
                .cloned()
                .map(|gate| ContainmentLifecycle::new(gate, staged))
        });
        let kubernetes_mutation = op
            .as_ref()
            .is_some_and(|operation| self.is_kubernetes_mutation(operation));

        let url = if query.is_empty() {
            format!("{}{}", self.upstream.base(), path)
        } else {
            format!("{}{}?{}", self.upstream.base(), path, query)
        };

        let actual_body_sha256 = body_sha256(&body);
        let authorized_body_sha256 = authorization
            .as_ref()
            .map(|pending| pending.summary.authorized_body_sha256.clone())
            .or_else(|| {
                parts
                    .extensions
                    .get::<ApprovedApiHold>()
                    .map(|approved| approved.body_sha256.clone())
            });
        let mut rb = self.upstream.client().request(parts.method.clone(), &url);
        for (name, value) in parts.headers.iter() {
            if is_hop_by_hop(name)
                || name == header::HOST
                || name == header::AUTHORIZATION
                || name == header::COOKIE
                || name == header::ACCEPT_ENCODING
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
        // Exact credential redaction operates on response bytes. Ask the
        // upstream for an identity representation so compression cannot hide a
        // reflected credential across the trust boundary.
        rb = rb.header(header::ACCEPT_ENCODING, "identity");
        if let Some(token) = self.upstream.bearer() {
            rb = rb.bearer_auth(token);
        } else if let Some((user, pass)) = self.upstream.basic_auth() {
            rb = rb.basic_auth(user, Some(pass));
        }
        if !body.is_empty() {
            rb = rb.body(body);
        }

        if let Some(response) = self
            .recheck_final_authority(&route_authority, op.as_ref())
            .await
        {
            if let Some(staged) = containment.take() {
                if !staged.cancel_inert().await {
                    return Ok(self.staged_cleanup_failure_response());
                }
            }
            return Ok(response);
        }
        if let (Some(operation), Some(context)) = (
            op.as_ref()
                .filter(|operation| self.is_kubernetes_mutation(operation)),
            session_context.as_ref(),
        ) {
            let _ = crate::audit::emit_global(
                &crate::audit::AuditEvent::new(crate::audit::AuditKind::Evaluate)
                    .session_fingerprint(&context.fingerprint)
                    .reason("session-attributed Kubernetes mutation passed write arbitration")
                    .field("decision", "forward")
                    .field("endpoint", &self.endpoint)
                    .field("session_revision", &context.revision)
                    .field("verb", operation.verb.as_str())
                    .field("resource", &operation.resource)
                    .field(
                        "namespace",
                        operation.namespace.as_deref().unwrap_or("(cluster)"),
                    )
                    .field("name", operation.name.as_deref().unwrap_or("(collection)")),
            );
        }
        // Revocable durable authority is acquired in one order: evaluator or
        // coverage authority, then session authority. The bundle lives only
        // through the bounded response-header handoff.
        let mut upstream_handoff = UpstreamSendHandoff {
            proxy: self,
            route_authority: route_authority.clone(),
            operation: op.clone(),
            request: Some(rb),
            timeout: self.upstream_handoff_timeout,
            outcome: UpstreamHandoffOutcome::Pending,
            containment,
            actual_body_sha256,
            authorized_body_sha256,
        };
        let auth = parts.extensions.get::<SessionAuth>();
        let mut cleanup_handoff = CleanupBoundHandoff {
            proxy: self,
            created: created_cleanup.as_ref(),
            path,
            upstream: &mut upstream_handoff,
        };
        let mut session_handoff = SessionBoundHandoff {
            sink: self.session_sink.get(),
            auth,
            context: session_context.as_ref(),
            upstream: &mut cleanup_handoff,
        };
        let authorization_result = if let Some(pending) = authorization {
            pending
                .judge
                .authorize_forward(&pending.summary, pending.requirement, &mut session_handoff)
                .await
        } else {
            session_handoff.forward().await
        };
        let containment = upstream_handoff.containment.take();
        let upstream_outcome = std::mem::replace(
            &mut upstream_handoff.outcome,
            UpstreamHandoffOutcome::Pending,
        );
        let (upstream_resp, mut containment) = match upstream_outcome {
            UpstreamHandoffOutcome::Pending => {
                if let Some(containment) = containment {
                    if !containment.cancel_inert().await {
                        return Ok(self.staged_cleanup_failure_response());
                    }
                }
                let reason = authorization_result.err().unwrap_or_else(|| {
                    "authority provider did not perform the protected handoff".to_string()
                });
                return Ok(self.status_resp(
                    StatusCode::FORBIDDEN,
                    &format!("guard api-proxy authority changed before forwarding: {reason}"),
                    "Forbidden",
                ));
            }
            UpstreamHandoffOutcome::PreparationFailed => {
                if let Some(containment) = containment {
                    if !containment.cancel_inert().await {
                        return Ok(self.staged_cleanup_failure_response());
                    }
                }
                return Ok(self.status_resp(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "guard api-proxy: durable mutation dispatch preparation failed; no mutation was sent",
                    "ContainmentError",
                ));
            }
            UpstreamHandoffOutcome::TimedOut => {
                let handle = if let Some(containment) = containment {
                    containment
                        .preserve_indeterminate(
                            "upstream mutation dispatch timed out before response headers",
                            None,
                        )
                        .await
                } else {
                    None
                };
                return Ok(self.provisional_status_resp(
                    StatusCode::GATEWAY_TIMEOUT,
                    "guard api-proxy: upstream request handoff timed out",
                    "Timeout",
                    handle.as_deref(),
                ));
            }
            UpstreamHandoffOutcome::Finished(response) => {
                let response = match response {
                    Ok(response) => response,
                    Err(_) => {
                        let handle = if let Some(containment) = containment {
                            containment
                                .preserve_indeterminate(
                                    "upstream mutation dispatch ended with a transport error before response headers",
                                    None,
                                )
                                .await
                        } else {
                            None
                        };
                        return Ok(self.provisional_status_resp(
                            StatusCode::BAD_GATEWAY,
                            "guard api-proxy: upstream request handoff failed",
                            "InternalError",
                            handle.as_deref(),
                        ));
                    }
                };
                (response, containment)
            }
        };
        let status = upstream_resp.status();
        let upstream_headers = upstream_resp.headers().clone();
        let response_secrets = self.upstream.response_secret_values();
        let mut upstream_resp = Some(upstream_resp);
        let mut buffered_upstream_body = None;

        let mut provisional_handle = None;
        let mut containment_active = false;
        if let Some(staged) = containment.take() {
            if op.as_ref().is_some_and(|operation| {
                self.protocol
                    .definitively_rejects_mutation(operation, status.as_u16())
            }) {
                if let Err(handle) = staged
                    .retire_rejected(&format!(
                        "upstream definitively rejected mutation with HTTP {status}"
                    ))
                    .await
                {
                    return Ok(self.provisional_status_resp(
                        StatusCode::BAD_GATEWAY,
                        "guard api-proxy: mutation rejection was received but containment retirement did not converge",
                        "ContainmentError",
                        handle.as_deref(),
                    ));
                }
            } else if status.is_success() {
                let resource_uid = if let Some((key, _)) = staged.created_resource() {
                    let body = match self
                        .take_upstream_body(&mut upstream_resp, &mut buffered_upstream_body)
                        .await
                    {
                        Ok(body) => body,
                        Err(error) => {
                            let detail = match error {
                                UpstreamBodyError::TimedOut => {
                                    "create response body timed out before authoritative identity was captured"
                                }
                                UpstreamBodyError::TooLarge => {
                                    "create response body exceeded the identity buffer limit"
                                }
                                UpstreamBodyError::ReadFailed => {
                                    "create response body failed before authoritative identity was captured"
                                }
                            };
                            let handle = staged.preserve_indeterminate(detail, None).await;
                            return Ok(self.provisional_status_resp(
                                StatusCode::BAD_GATEWAY,
                                "guard api-proxy: mutation succeeded but authoritative create identity is unavailable",
                                "ContainmentIndeterminate",
                                handle.as_deref(),
                            ));
                        }
                    };
                    let provenance = staged
                        .create_provenance
                        .as_deref()
                        .expect("created containment has canonical request provenance");
                    match authoritative_created_uid(&body, key, provenance) {
                        Ok(uid) => {
                            buffered_upstream_body = Some(body);
                            Some(uid)
                        }
                        Err(reason) => {
                            let handle = staged.preserve_indeterminate(&reason, None).await;
                            return Ok(self.provisional_status_resp(
                                StatusCode::BAD_GATEWAY,
                                "guard api-proxy: mutation succeeded but authoritative create identity is invalid",
                                "ContainmentIndeterminate",
                                handle.as_deref(),
                            ));
                        }
                    }
                } else {
                    None
                };
                let create_provenance = staged.create_provenance.clone();
                match staged.activate(resource_uid.as_deref()).await {
                    Ok((handle, created_key)) => {
                        if let Some(key) = created_key {
                            let uid = resource_uid
                                .as_ref()
                                .expect("created containment has a verified UID")
                                .clone();
                            if self
                                .publication_authority_is_current(&route_authority, op.as_ref())
                                .await
                            {
                                self.created.lock().unwrap().remember(
                                    key,
                                    handle.clone(),
                                    uid,
                                    create_provenance
                                        .expect("created containment has canonical provenance"),
                                );
                            }
                        }
                        provisional_handle = Some(handle);
                        containment_active = true;
                    }
                    Err(handle) => {
                        return Ok(self.provisional_status_resp(
                            StatusCode::BAD_GATEWAY,
                            "guard api-proxy: mutation succeeded but durable containment requires operator action",
                            "ContainmentError",
                            handle.as_deref(),
                        ));
                    }
                }
            } else {
                provisional_handle = staged
                    .preserve_indeterminate(
                        &format!("upstream returned HTTP {status} after mutation dispatch"),
                        None,
                    )
                    .await;
            }
        }

        if has_unsupported_content_encoding(&upstream_headers) {
            return Ok(self.provisional_status_resp(
                StatusCode::BAD_GATEWAY,
                "guard api-proxy: refusing an encoded upstream response that cannot be credential-redacted",
                "InternalError",
                provisional_handle.as_deref(),
            ));
        }

        let mut builder = Response::builder().status(status);
        if let Some(hdrs) = builder.headers_mut() {
            for (name, value) in upstream_headers.iter() {
                // A strict allowlist prevents an upstream from inventing a
                // credential-reflection header. Values are also scanned for the
                // exact credential material Guard injected.
                if is_hop_by_hop(name)
                    || name == header::CONTENT_LENGTH
                    || name == header::TRANSFER_ENCODING
                    || is_sensitive_response_header(name)
                    || header_contains_secret(value.as_bytes(), &response_secrets)
                {
                    continue;
                }
                if name == header::LOCATION {
                    if let Some(location) = self.safe_location(value, &response_secrets) {
                        hdrs.append(name, location);
                    }
                    continue;
                }
                if name.as_str() == "link" {
                    if let Some(link) = self.safe_link(value, &response_secrets) {
                        hdrs.append(name, link);
                    }
                    continue;
                }
                if is_rate_limit_response_header(name) {
                    if value.as_bytes().len() <= MAX_RATE_LIMIT_HEADER_LEN {
                        hdrs.append(name, value.clone());
                    }
                    continue;
                }
                if !is_safe_response_header(name) {
                    continue;
                }
                hdrs.append(name, value.clone());
            }
        }

        // A contained cleanup is only proven complete once the entire upstream
        // response succeeds. A 2xx header followed by a body disconnect keeps
        // the revert armed because the outcome is no longer trustworthy.
        if let Some(created) = created_cleanup {
            let bytes = match self
                .take_upstream_body(&mut upstream_resp, &mut buffered_upstream_body)
                .await
            {
                Ok(bytes) => bytes,
                Err(UpstreamBodyError::TimedOut) => {
                    return Ok(self.provisional_status_resp(
                        StatusCode::GATEWAY_TIMEOUT,
                        "guard api-proxy: contained cleanup response body timed out",
                        "Timeout",
                        Some(&created.handle),
                    ));
                }
                Err(UpstreamBodyError::ReadFailed) => {
                    return Ok(self.provisional_status_resp(
                        StatusCode::BAD_GATEWAY,
                        "guard api-proxy: contained cleanup response body failed",
                        "InternalError",
                        Some(&created.handle),
                    ));
                }
                Err(UpstreamBodyError::TooLarge) => {
                    return Ok(self.provisional_status_resp(
                        StatusCode::BAD_GATEWAY,
                        "guard api-proxy: contained cleanup response body exceeded the byte limit",
                        "ResponseTooLarge",
                        Some(&created.handle),
                    ));
                }
            };
            if status.is_success() {
                let resolved = if let Some(gate) = self.gate.get() {
                    tokio::time::timeout(Duration::from_secs(5), gate.resolve(&created.handle))
                        .await
                        .is_ok_and(std::convert::identity)
                } else {
                    false
                };
                if !resolved {
                    return Ok(self.provisional_status_resp(
                        StatusCode::BAD_GATEWAY,
                        "guard api-proxy: cleanup succeeded upstream but durable containment resolution failed",
                        "ContainmentIndeterminate",
                        Some(&created.handle),
                    ));
                }
                self.forget_created_by_handle(&created.handle);
            }
            let bytes = self
                .redact_upstream_bytes(response_secrets, &bytes)
                .map_err(|_| {
                    anyhow::anyhow!(
                        "contained cleanup response exceeded the byte limit after redaction"
                    )
                })?;
            return Ok(builder
                .body(full_body(bytes))
                .expect("build contained cleanup response"));
        }

        // A Secret read must never reach the raw-stream path below with values
        // intact. Redact a successful JSON body; buffer and pass through a
        // non-success body (a Status error carries no Secret values); fail closed
        // on a successful body whose content-type we cannot parse and redact.
        if redact {
            if !status.is_success() {
                let bytes = self
                    .take_upstream_body(&mut upstream_resp, &mut buffered_upstream_body)
                    .await
                    .map_err(|_| {
                        anyhow::anyhow!("read Secret error response failed or timed out")
                    })?;
                let bytes = self
                    .redact_upstream_bytes(response_secrets, &bytes)
                    .map_err(|_| {
                        anyhow::anyhow!(
                            "Secret error response exceeded the byte limit after redaction"
                        )
                    })?;
                return Ok(builder
                    .body(full_body(bytes))
                    .expect("build Secret error response"));
            }
            if !is_json(&upstream_headers) {
                return Ok(self.status_resp(
                    StatusCode::BAD_GATEWAY,
                    "guard api-proxy: refusing to stream a non-JSON Secret response unredacted",
                    "InternalError",
                ));
            }
            let bytes = self
                .take_upstream_body(&mut upstream_resp, &mut buffered_upstream_body)
                .await
                .map_err(|_| anyhow::anyhow!("read Secret response failed or timed out"))?;
            let mut value: serde_json::Value = match serde_json::from_slice(&bytes) {
                Ok(v) => v,
                // Fail closed: never pass an unparsed Secret body through.
                Err(_) => {
                    return Ok(self.status_resp(
                        StatusCode::BAD_GATEWAY,
                        "guard api-proxy: could not parse Secret response for redaction",
                        "InternalError",
                    ));
                }
            };
            if let Some(reason) = self.protocol.reject_misleading_redaction(&value) {
                return Ok(self.status_resp(StatusCode::FORBIDDEN, &reason, "Forbidden"));
            }
            let n = self.protocol.redact_response(&mut value);
            tracing::info!(target: "guard::apiproxy", "redacted {n} Secret object(s) on {path}");
            let out = serde_json::to_vec(&value).context("re-serialize redacted Secret")?;
            let out = self
                .redact_upstream_bytes(response_secrets, &out)
                .map_err(|_| {
                    anyhow::anyhow!("Secret response exceeded the byte limit after redaction")
                })?;
            return Ok(builder
                .body(full_body(out))
                .expect("build redacted response"));
        }

        // Kubernetes mutation responses are buffered so the returned object can
        // become this same session's next observed version. The body has a
        // separate bound because containment is already armed at this point.
        if track_write || kubernetes_mutation {
            let bytes = match self
                .take_upstream_body(&mut upstream_resp, &mut buffered_upstream_body)
                .await
            {
                Ok(bytes) => bytes,
                Err(UpstreamBodyError::ReadFailed) => {
                    return Ok(self.provisional_status_resp(
                        StatusCode::BAD_GATEWAY,
                        "guard api-proxy: upstream mutation response body failed",
                        "InternalError",
                        provisional_handle.as_deref(),
                    ));
                }
                Err(UpstreamBodyError::TimedOut) => {
                    let mut response = self.status_resp(
                        StatusCode::GATEWAY_TIMEOUT,
                        "guard api-proxy: upstream response body timed out after mutation handoff",
                        "Timeout",
                    );
                    if let Some(handle) = provisional_handle.as_deref() {
                        if let Ok(value) = hyper::header::HeaderValue::from_str(handle) {
                            response.headers_mut().insert("x-guard-provisional", value);
                        }
                    }
                    return Ok(response);
                }
                Err(UpstreamBodyError::TooLarge) => {
                    return Ok(self.provisional_status_resp(
                        StatusCode::BAD_GATEWAY,
                        "guard api-proxy: upstream mutation response body exceeded the byte limit",
                        "ResponseTooLarge",
                        provisional_handle.as_deref(),
                    ));
                }
            };
            if status.is_success() {
                if let Some(o) = op.as_ref() {
                    if let Some(context) = session_context.as_ref() {
                        if self
                            .publication_authority_is_current(&route_authority, Some(o))
                            .await
                        {
                            self.remember_kubernetes_observation(o, &bytes, context);
                        }
                    }
                }
            }
            if let Some(handle) = provisional_handle {
                let deadline = if containment_active {
                    match self.gate.get() {
                        Some(gate) => gate.provisional_deadline(&handle).await,
                        None => None,
                    }
                } else {
                    None
                };
                if let Some(deadline_unix) = deadline {
                    let (provisional, warning) = provisional_response_metadata(
                        &handle,
                        deadline_unix,
                        crate::env::now_unix(),
                    );
                    builder = builder
                        .header("x-guard-provisional", provisional)
                        .header(hyper::header::WARNING, warning);
                } else {
                    let warning = if containment_active {
                        format!(
                            "299 guard \"change is provisional; confirm with guard confirm {handle}\""
                        )
                    } else {
                        format!(
                            "299 guard \"mutation outcome is uncertain; inspect provisional {handle}\""
                        )
                    };
                    builder = builder
                        .header("x-guard-provisional", &handle)
                        .header(hyper::header::WARNING, warning);
                }
            }
            let bytes = self
                .redact_upstream_bytes(response_secrets, &bytes)
                .map_err(|_| {
                    anyhow::anyhow!("mutation response exceeded the byte limit after redaction")
                })?;
            return Ok(builder
                .body(full_body(bytes))
                .expect("build write response"));
        }

        // A successful named-object GET is the only read that establishes a
        // write observation. Lists and watches cannot bind one object UID and
        // version, and anonymous reads never establish mutation authority.
        if status.is_success()
            && op.as_ref().is_some_and(|operation| {
                self.protocol.name() == "kubernetes"
                    && operation.verb == Verb::Get
                    && operation.name.is_some()
            })
            && session_context.is_some()
        {
            let bytes = self
                .take_upstream_body(&mut upstream_resp, &mut buffered_upstream_body)
                .await
                .map_err(|_| {
                    anyhow::anyhow!("read Kubernetes object response failed or timed out")
                })?;
            if let (Some(operation), Some(context)) = (op.as_ref(), session_context.as_ref()) {
                if self
                    .publication_authority_is_current(&route_authority, Some(operation))
                    .await
                {
                    self.remember_kubernetes_observation(operation, &bytes, context);
                }
            }
            let bytes = self
                .redact_upstream_bytes(response_secrets, &bytes)
                .map_err(|_| {
                    anyhow::anyhow!("object response exceeded the byte limit after redaction")
                })?;
            return Ok(builder
                .body(full_body(bytes))
                .expect("build observed object response"));
        }

        // Stream ordinary response bodies through exact credential redaction
        // while preserving chunked delivery for lists, gets, and watches.
        let upstream_resp = upstream_resp
            .take()
            .ok_or_else(|| anyhow::anyhow!("upstream response body was already consumed"))?;
        let source: ReqwestByteStream = Box::pin(upstream_resp.bytes_stream());
        let redactor = ExactSecretRedactor::new(response_secrets, self.upstream_body_limit)
            .map_err(|_| anyhow!("upstream redaction context exceeds its resource limit"))?;
        let stream = futures::stream::try_unfold(
            (source, redactor, false),
            |(mut source, mut redactor, finished)| async move {
                if finished {
                    return Ok::<
                        Option<(Frame<Bytes>, RedactingStreamState)>,
                        Box<dyn std::error::Error + Send + Sync>,
                    >(None);
                }
                loop {
                    match source.as_mut().try_next().await.map_err(|error| {
                        Box::new(error) as Box<dyn std::error::Error + Send + Sync>
                    })? {
                        Some(chunk) => {
                            let output = redactor.push(&chunk).map_err(|_| {
                                Box::new(std::io::Error::other(
                                    "upstream response exceeded the byte limit after redaction",
                                ))
                                    as Box<dyn std::error::Error + Send + Sync>
                            })?;
                            if output.is_empty() {
                                continue;
                            }
                            return Ok(Some((
                                Frame::data(Bytes::from(output)),
                                (source, redactor, false),
                            )));
                        }
                        None => {
                            let output = redactor.finish().map_err(|_| {
                                Box::new(std::io::Error::other(
                                    "upstream response exceeded the byte limit after redaction",
                                ))
                                    as Box<dyn std::error::Error + Send + Sync>
                            })?;
                            if output.is_empty() {
                                return Ok(None);
                            }
                            return Ok(Some((
                                Frame::data(Bytes::from(output)),
                                (source, redactor, true),
                            )));
                        }
                    }
                }
            },
        );
        let body = StreamBody::new(stream).boxed();
        Ok(builder.body(body).expect("build streamed response"))
    }

    async fn revalidate_session(
        &self,
        parts: &Parts,
    ) -> Result<Option<ApiSessionContext>, Response<ProxyBody>> {
        let Some(auth) = parts.extensions.get::<SessionAuth>() else {
            return Ok(None);
        };
        let Some(sink) = self.session_sink.get() else {
            return Err(self.status_resp(
                StatusCode::FORBIDDEN,
                "guard api-proxy: session attribution is unavailable",
                "Forbidden",
            ));
        };
        let current = sink.resolve(&auth.token).await;
        if current.as_ref() != Some(&auth.context) {
            return Err(self.status_resp(
                StatusCode::FORBIDDEN,
                "guard api-proxy: session expired, was revoked, or is suspended",
                "Forbidden",
            ));
        }
        Ok(current)
    }

    async fn publication_authority_is_current(
        &self,
        route_authority: &RouteAuthority,
        operation: Option<&ApiOp>,
    ) -> bool {
        // Session authority is linearized while `SessionBoundHandoff` retains
        // its exact lease through response headers. A later session revocation
        // does not erase the upstream operation that already happened. Policy
        // generation is rechecked here because observations are local policy
        // inputs and must not publish into a different route generation.
        self.recheck_final_authority(route_authority, operation)
            .await
            .is_none()
    }

    fn is_kubernetes_mutation(&self, op: &ApiOp) -> bool {
        self.protocol.name() == "kubernetes" && !op.is_read()
    }

    fn observation_key(
        &self,
        op: &ApiOp,
        state: &KubernetesObjectState,
        context: &ApiSessionContext,
    ) -> ObservationKey {
        ObservationKey {
            endpoint: self.endpoint.clone(),
            session_fingerprint: context.fingerprint.clone(),
            session_revision: context.revision.clone(),
            group: op.group.clone(),
            version: op.version.clone(),
            resource: op.resource.clone(),
            subresource: op.subresource.clone(),
            namespace: state.namespace.clone(),
            name: state.name.clone(),
            uid: state.uid.clone(),
        }
    }

    fn remember_kubernetes_observation(
        &self,
        op: &ApiOp,
        bytes: &[u8],
        context: &ApiSessionContext,
    ) {
        let Some(state) = object_state(op, bytes) else {
            return;
        };
        let key = self.observation_key(op, &state, context);
        self.observations.lock().unwrap().remember(
            key,
            ObservedVersion {
                resource_version: state.resource_version,
                contention_fingerprint: state.contention_fingerprint,
            },
        );
    }

    async fn arbitrate_kubernetes_mutation(
        &self,
        parts: &Parts,
        body: &[u8],
        path: &str,
        op: &ApiOp,
        route_authority: &RouteAuthority,
        prepared_snapshot: Option<&[u8]>,
    ) -> Result<(Bytes, Option<Vec<u8>>), Response<ProxyBody>> {
        let Some(auth) = parts.extensions.get::<SessionAuth>() else {
            return Err(self.status_resp(
                StatusCode::FORBIDDEN,
                "guard api-proxy: Kubernetes mutations require an attributable Guard session or an operator-approved typed verb",
                "Forbidden",
            ));
        };
        if op.verb == Verb::Create && op.name.is_none() {
            return Ok((Bytes::copy_from_slice(body), None));
        }
        if !matches!(op.verb, Verb::Update | Verb::Patch | Verb::Delete) || op.name.is_none() {
            return Err(self.kubernetes_conflict(
                "Kubernetes mutation cannot be bound to one observed object",
            ));
        }
        let snapshot = match prepared_snapshot {
            Some(snapshot) => snapshot.to_vec(),
            None => {
                let Some(snapshot) = self.fetch_prior_object(path, route_authority).await? else {
                    return Err(self.kubernetes_conflict(
                        "current Kubernetes object could not be read for write arbitration",
                    ));
                };
                snapshot
            }
        };
        let Some(state) = object_state(op, &snapshot) else {
            return Err(self.kubernetes_conflict(
                "current Kubernetes object has no usable UID and resourceVersion",
            ));
        };
        let key = self.observation_key(op, &state, &auth.context);
        let Some(observed) = self.observations.lock().unwrap().get(&key) else {
            return Err(self.kubernetes_conflict(
                "this session has not observed the current Kubernetes object UID",
            ));
        };
        if observed.resource_version != state.resource_version
            && observed.contention_fingerprint != state.contention_fingerprint
        {
            return Err(self
                .kubernetes_conflict("Kubernetes object changed since this session observed it"));
        }
        let guarded = bind_mutation_preconditions(
            op,
            &parts.headers,
            body,
            &state,
            &observed.resource_version,
        )
        .map_err(|reason| self.kubernetes_conflict(&reason))?;
        self.observations.lock().unwrap().remember(
            key,
            ObservedVersion {
                resource_version: state.resource_version,
                contention_fingerprint: state.contention_fingerprint,
            },
        );
        Ok((Bytes::from(guarded), Some(snapshot)))
    }

    fn kubernetes_conflict(&self, reason: &str) -> Response<ProxyBody> {
        tracing::warn!(target: "guard::apiproxy", reason, "Kubernetes mutation arbitration failed");
        self.status_resp(
            StatusCode::CONFLICT,
            &format!("guard api-proxy: {reason}"),
            "Conflict",
        )
    }

    fn request_body_error_response(&self, error: RequestBodyError) -> Response<ProxyBody> {
        match error {
            RequestBodyError::Timeout => self.status_resp(
                StatusCode::REQUEST_TIMEOUT,
                "guard api-proxy: request body read timed out before authorization",
                "RequestTimeout",
            ),
            RequestBodyError::Read(error) => self.status_resp(
                StatusCode::PAYLOAD_TOO_LARGE,
                &format!("guard api-proxy: request body could not be buffered: {error}"),
                "RequestEntityTooLarge",
            ),
        }
    }

    fn route_authority_from_parts(&self, parts: &Parts) -> Option<RouteAuthority> {
        parts.extensions.get::<RouteAuthority>().cloned()
    }

    fn missing_route_authority_response(&self) -> Response<ProxyBody> {
        self.status_resp(
            StatusCode::FORBIDDEN,
            "guard api-proxy: request authority binding is missing",
            "Forbidden",
        )
    }

    /// Re-read the complete policy and evaluator-intent generation immediately
    /// before upstream I/O. Any intervening authority change invalidates the
    /// route, even when the new action is another permissive action.
    async fn recheck_final_authority(
        &self,
        expected: &RouteAuthority,
        op: Option<&ApiOp>,
    ) -> Option<Response<ProxyBody>> {
        if let Some(reason) = op.and_then(|operation| self.protocol.deny_outright(operation)) {
            return Some(self.status_resp(StatusCode::FORBIDDEN, &reason, "Forbidden"));
        }
        let Ok((_, current)) = self.capture_route_authority().await else {
            return Some(self.status_resp(
                StatusCode::FORBIDDEN,
                "guard api-proxy: API route authority is unavailable",
                "Forbidden",
            ));
        };
        if &current != expected {
            return Some(self.status_resp(
                StatusCode::FORBIDDEN,
                "guard api-proxy: API policy or evaluator intent changed while the request was in flight; submit a fresh request",
                "Forbidden",
            ));
        }
        None
    }

    /// Fetch the current object at `path` before a mutation, so the protocol
    /// can build a restore-style revert from it. Returns the raw body; `None`
    /// if the fetch failed (the protocol then synthesizes a
    /// delete-the-created-object revert instead).
    async fn fetch_prior_object(
        &self,
        path: &str,
        route_authority: &RouteAuthority,
    ) -> Result<Option<Vec<u8>>, Response<ProxyBody>> {
        if let Some(response) = self.recheck_final_authority(route_authority, None).await {
            return Err(response);
        }
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
        let Ok(Ok(resp)) = tokio::time::timeout(self.upstream_handoff_timeout, rb.send()).await
        else {
            return Ok(None);
        };
        if !resp.status().is_success() {
            return Ok(None);
        }
        Ok(self
            .read_upstream_body(resp)
            .await
            .ok()
            .map(|bytes| bytes.to_vec()))
    }

    /// Revalidate that a cleanup still targets the exact object created by the
    /// admitted request. The retained UID and provenance must both match.
    async fn validate_current_created_object(
        &self,
        key: &CreatedKey,
        object_path: &str,
        expected_uid: &str,
        expected_provenance: &str,
    ) -> Result<(), String> {
        let url = format!("{}{}", self.upstream.base(), object_path);
        let mut request = self
            .upstream
            .client()
            .get(url)
            .header(header::ACCEPT, "application/json")
            .header(header::ACCEPT_ENCODING, "identity");
        if let Some(token) = self.upstream.bearer() {
            request = request.bearer_auth(token);
        } else if let Some((user, pass)) = self.upstream.basic_auth() {
            request = request.basic_auth(user, Some(pass));
        }
        let response = tokio::time::timeout(self.upstream_handoff_timeout, request.send())
            .await
            .map_err(|_| "created resource identity lookup timed out".to_string())?
            .map_err(|_| "created resource identity lookup failed".to_string())?;
        if !response.status().is_success() {
            return Err("created resource identity is unavailable".to_string());
        }
        let bytes = self
            .read_upstream_body(response)
            .await
            .map_err(|error| match error {
                UpstreamBodyError::TimedOut => {
                    "created resource identity response timed out".to_string()
                }
                UpstreamBodyError::TooLarge => {
                    "created resource identity response exceeded the byte limit".to_string()
                }
                UpstreamBodyError::ReadFailed => {
                    "created resource identity response failed".to_string()
                }
            })?;
        let object: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| "created resource identity response is invalid".to_string())?;
        let metadata = object
            .get("metadata")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| "created resource identity metadata is missing".to_string())?;
        if metadata.get("name").and_then(serde_json::Value::as_str) != Some(key.name.as_str())
            || metadata
                .get("namespace")
                .and_then(serde_json::Value::as_str)
                != key.namespace.as_deref()
        {
            return Err(
                "created resource identity does not match the admitted operation".to_string(),
            );
        }
        if metadata
            .get("annotations")
            .and_then(serde_json::Value::as_object)
            .and_then(|annotations| annotations.get(CREATE_PROVENANCE_ANNOTATION))
            .and_then(serde_json::Value::as_str)
            != Some(expected_provenance)
        {
            return Err(
                "created resource does not carry the admitted operation provenance".to_string(),
            );
        }
        let uid = metadata
            .get("uid")
            .and_then(serde_json::Value::as_str)
            .filter(|uid| !uid.is_empty() && uid.len() <= 256 && !uid.chars().any(char::is_control))
            .ok_or_else(|| "created resource UID is missing or invalid".to_string())?;
        if uid != expected_uid {
            return Err("created resource UID no longer matches the admitted object".to_string());
        }
        Ok(())
    }

    /// Fetch the prior object and confirm the protocol can plan a revert from
    /// it, returning the snapshot when it can. Used on the evaluate Contain path
    /// immediately before forwarding, so containment is only committed to when
    /// the revert is genuinely armable from current state.
    async fn fetch_validated_snapshot(
        &self,
        op: &ApiOp,
        path: &str,
        route_authority: &RouteAuthority,
    ) -> Result<Option<Vec<u8>>, Response<ProxyBody>> {
        let Some(snapshot) = self.fetch_prior_object(path, route_authority).await? else {
            return Ok(None);
        };
        if self.protocol.plan_revert(op, Some(&snapshot), &[]).is_err() {
            return Ok(None);
        }
        Ok(Some(snapshot))
    }

    /// Pre-judge which revert (if any) the proxy could construct for this
    /// operation. The prior object is not carried forward; the Contain path
    /// re-fetches and re-validates it before forwarding so the armed revert
    /// reflects state at write time, not at judge time.
    async fn prepare_revert(
        &self,
        op: &ApiOp,
        path: &str,
        route_authority: &RouteAuthority,
    ) -> Result<RevertConstructible, Response<ProxyBody>> {
        let track_write = self.gate.get().is_some() && self.protocol.tracks_write(op);
        if !track_write {
            return Ok(RevertConstructible::None);
        }
        if self.protocol.wants_prior_snapshot(op) {
            let Some(snapshot) = self.fetch_prior_object(path, route_authority).await? else {
                return Ok(RevertConstructible::None);
            };
            // The marker is an input the evaluator trusts, so it must not claim a
            // revert the protocol cannot actually build from this snapshot (e.g.
            // an encrypted value the sanitizer drops). Validate by planning the
            // snapshot-based revert; the request body is unused for these verbs.
            if self.protocol.plan_revert(op, Some(&snapshot), &[]).is_err() {
                return Ok(RevertConstructible::None);
            }
            return Ok(match op.verb {
                Verb::Delete => RevertConstructible::RecreateFromSnapshot,
                _ => RevertConstructible::RestorePriorState,
            });
        }
        Ok(RevertConstructible::DeleteCreated)
    }

    fn revert_constructibility_from_prepared(
        &self,
        op: &ApiOp,
        prepared: Option<&PreparedMutation>,
    ) -> RevertConstructible {
        if self.gate.get().is_none() || !self.protocol.tracks_write(op) {
            return RevertConstructible::None;
        }
        if !self.protocol.wants_prior_snapshot(op) {
            return RevertConstructible::DeleteCreated;
        }
        let Some(snapshot) = prepared.and_then(|prepared| prepared.prior_snapshot.as_deref())
        else {
            return RevertConstructible::None;
        };
        if self.protocol.plan_revert(op, Some(snapshot), &[]).is_err() {
            return RevertConstructible::None;
        }
        match op.verb {
            Verb::Delete => RevertConstructible::RecreateFromSnapshot,
            _ => RevertConstructible::RestorePriorState,
        }
    }

    /// Durably stage an auto-revert envelope before a tracked write is sent.
    async fn arm_write_revert(
        &self,
        op: &ApiOp,
        snapshot: Option<Vec<u8>>,
        request_body: &[u8],
        conn_id: u64,
        session_context: Option<ApiSessionContext>,
        create_provenance: Option<String>,
    ) -> Option<StagedRevert> {
        let gate = self.gate.get()?;
        let plan = match self
            .protocol
            .plan_revert(op, snapshot.as_deref(), request_body)
        {
            Ok(plan) => plan,
            Err(reason) => {
                tracing::warn!(target: "guard::apiproxy", "{reason}");
                return None;
            }
        };
        let created_key = plan.created.map(|c| CreatedKey {
            conn: conn_id,
            session_fingerprint: session_context
                .as_ref()
                .map(|context| context.fingerprint.clone()),
            group: c.group,
            resource: c.resource,
            namespace: c.namespace,
            name: c.name,
        });
        let created_path = created_key.as_ref().map(|_| plan.revert.path.clone());
        if created_key.is_some() && create_provenance.is_none() {
            tracing::warn!(target: "guard::apiproxy", "create containment is missing canonical request provenance");
            return None;
        }
        let label = plan.label;
        match tokio::time::timeout(
            Duration::from_secs(5),
            gate.arm_revert(ApiMutation {
                label: label.clone(),
                revert: plan.revert,
                revert_requires_uid_precondition: created_key.is_some(),
                create_provenance: create_provenance.clone(),
                session_fingerprint: session_context
                    .as_ref()
                    .map(|context| context.fingerprint.clone()),
                session_revision: session_context
                    .as_ref()
                    .map(|context| context.revision.clone()),
                secret_entitlements: session_context
                    .and_then(|context| context.secret_entitlements),
                upstream_target: self.upstream.base().to_string(),
                upstream_identity: self.upstream_identity_fingerprint(),
            }),
        )
        .await
        {
            Ok(Some(handle)) => {
                tracing::debug!(target: "guard::apiproxy", "prepared inert API mutation containment");
                Some(StagedRevert {
                    handle,
                    created_key,
                    created_path,
                    create_provenance,
                })
            }
            Ok(None) | Err(_) => {
                tracing::warn!(
                    target: "guard::apiproxy",
                    "could not arm auto-revert for {label} (capacity)"
                );
                None
            }
        }
    }

    /// If this delete targets a resource the proxy forwarded a create for in
    /// this process, return its auto-revert handle without consuming it. The
    /// record and revert remain live until a revalidated upstream delete
    /// succeeds with a 2xx response.
    fn created_provenance(
        &self,
        op: &ApiOp,
        conn_id: u64,
        session_fingerprint: Option<&str>,
    ) -> Option<CreatedMatch> {
        let name = op.name.clone()?;
        let key = CreatedKey {
            conn: conn_id,
            session_fingerprint: session_fingerprint.map(str::to_string),
            group: op.group.clone(),
            resource: op.resource.clone(),
            namespace: op.namespace.clone(),
            name,
        };
        let record = self.created.lock().unwrap().find_record(&key)?;
        Some(CreatedMatch {
            key,
            handle: record.handle,
            resource_uid: record.resource_uid,
            create_provenance: record.create_provenance,
        })
    }

    pub fn upstream_identity_fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.endpoint.as_bytes());
        hasher.update([0]);
        hasher.update(self.protocol.name().as_bytes());
        hasher.update([0]);
        hasher.update(self.upstream.base().as_bytes());
        hasher.update([0]);
        hasher.update(self.credential_ref.as_bytes());
        hasher.update([0]);
        hasher.update(self.upstream.identity_fingerprint().as_bytes());
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    pub fn matches_upstream_identity(&self, protocol: &str, target: &str, identity: &str) -> bool {
        !target.is_empty()
            && !identity.is_empty()
            && self.protocol.name() == protocol
            && self.upstream.base() == target
            && self.upstream_identity_fingerprint() == identity
    }

    fn safe_location(&self, value: &HeaderValue, secrets: &[Vec<u8>]) -> Option<HeaderValue> {
        let raw = value.to_str().ok()?;
        if header_contains_secret(value.as_bytes(), secrets)
            || (!secrets.is_empty() && raw.contains('%'))
        {
            return None;
        }
        if raw.starts_with('/') && !raw.starts_with("//") && !raw.contains('\\') {
            return HeaderValue::from_str(raw).ok();
        }
        let location = reqwest::Url::parse(raw).ok()?;
        let upstream = reqwest::Url::parse(self.upstream.base()).ok()?;
        if !location.username().is_empty()
            || location.password().is_some()
            || location.scheme() != upstream.scheme()
            || location.host_str() != upstream.host_str()
            || location.port_or_known_default() != upstream.port_or_known_default()
        {
            return None;
        }
        let mut rewritten = format!("{}{}", self.proxy_url, location.path());
        if let Some(query) = location.query() {
            rewritten.push('?');
            rewritten.push_str(query);
        }
        if let Some(fragment) = location.fragment() {
            rewritten.push('#');
            rewritten.push_str(fragment);
        }
        HeaderValue::from_str(&rewritten).ok()
    }

    fn safe_link(&self, value: &HeaderValue, secrets: &[Vec<u8>]) -> Option<HeaderValue> {
        if header_contains_secret(value.as_bytes(), secrets) {
            return None;
        }
        let raw = value.to_str().ok()?;
        let mut rewritten = Vec::new();
        for link in split_link_values(raw)? {
            let link = link.trim();
            let target_end = link.strip_prefix('<')?.find('>')? + 1;
            let target = &link[1..target_end];
            if target.is_empty() {
                return None;
            }
            let params = &link[target_end + 1..];
            if !params.trim().is_empty() && !params.trim_start().starts_with(';') {
                return None;
            }
            let target = self.safe_location(&HeaderValue::from_str(target).ok()?, secrets)?;
            rewritten.push(format!("<{}>{params}", target.to_str().ok()?));
        }
        HeaderValue::from_str(&rewritten.join(", ")).ok()
    }

    fn status_resp(&self, code: StatusCode, message: &str, reason: &str) -> Response<ProxyBody> {
        let body = self.protocol.error_body(code.as_u16(), message, reason);
        let mut response = Response::builder()
            .status(code)
            .header(header::CONTENT_TYPE, "application/json")
            .body(full_body(Bytes::from(body)))
            .expect("build status response");
        response.extensions_mut().insert(GuardRejected);
        response
    }

    fn provisional_status_resp(
        &self,
        code: StatusCode,
        message: &str,
        reason: &str,
        handle: Option<&str>,
    ) -> Response<ProxyBody> {
        let mut response = self.status_resp(code, message, reason);
        if let Some(handle) = handle {
            if let Ok(value) = HeaderValue::from_str(handle) {
                response.headers_mut().insert("x-guard-provisional", value);
            }
        }
        response
    }

    fn approval_status_resp(
        &self,
        code: StatusCode,
        message: &str,
        reason: &str,
        handle: Option<&str>,
    ) -> Response<ProxyBody> {
        let mut response = self.status_resp(code, message, reason);
        if let Some(handle) = handle {
            if let Ok(value) = HeaderValue::from_str(handle) {
                response.headers_mut().insert("x-guard-approval", value);
            }
        }
        response
    }

    fn staged_cleanup_failure_response(&self) -> Response<ProxyBody> {
        self.status_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "guard api-proxy: mutation was not sent, but durable staged-containment cleanup remains pending",
            "ContainmentCleanupPending",
        )
    }

    fn rebuild_judge_for_intent_during_update(&self, intent: Option<String>) {
        let Some(builder) = self.judge_builder.get() else {
            return;
        };
        let judge = builder(intent);
        *self
            .judge
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = judge;
        tracing::info!(target: "guard::apiproxy", "rebuilt api evaluator for policy intent change");
    }
}

fn provisional_response_metadata(
    handle: &str,
    deadline_unix: u64,
    now_unix: u64,
) -> (String, String) {
    let seconds_remaining = deadline_unix.saturating_sub(now_unix);
    (
        format!(
            "{handle}; deadline_unix={deadline_unix}; seconds_remaining={seconds_remaining}"
        ),
        format!(
            "299 guard \"change is provisional; confirm with guard confirm {handle}; auto-revert deadline_unix={deadline_unix}; seconds_remaining={seconds_remaining}\""
        ),
    )
}

fn bind_create_provenance(body: &[u8], provisional: &str) -> Result<Bytes, String> {
    let mut object: serde_json::Value = serde_json::from_slice(body)
        .map_err(|_| "Kubernetes create body is not valid JSON".to_string())?;
    let metadata = object
        .get_mut("metadata")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| "Kubernetes create body has no metadata object".to_string())?;
    let annotations = metadata
        .entry("annotations")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()))
        .as_object_mut()
        .ok_or_else(|| "Kubernetes create metadata annotations must be an object".to_string())?;
    annotations.insert(
        CREATE_PROVENANCE_ANNOTATION.to_string(),
        serde_json::Value::String(provisional.to_string()),
    );
    serde_json::to_vec(&object)
        .map(Bytes::from)
        .map_err(|_| "Kubernetes create provenance could not be serialized".to_string())
}

fn authoritative_created_uid(
    body: &[u8],
    key: &CreatedKey,
    expected_provenance: &str,
) -> Result<String, String> {
    let object: serde_json::Value = serde_json::from_slice(body)
        .map_err(|_| "create response is not a valid object".to_string())?;
    let metadata = object
        .get("metadata")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "create response metadata is missing".to_string())?;
    if metadata.get("name").and_then(serde_json::Value::as_str) != Some(key.name.as_str())
        || metadata
            .get("namespace")
            .and_then(serde_json::Value::as_str)
            != key.namespace.as_deref()
    {
        return Err("create response identity does not match the admitted request".to_string());
    }
    if metadata
        .get("annotations")
        .and_then(serde_json::Value::as_object)
        .and_then(|annotations| annotations.get(CREATE_PROVENANCE_ANNOTATION))
        .and_then(serde_json::Value::as_str)
        != Some(expected_provenance)
    {
        return Err("create response provenance does not match the admitted request".to_string());
    }
    metadata
        .get("uid")
        .and_then(serde_json::Value::as_str)
        .filter(|uid| !uid.is_empty() && uid.len() <= 256 && !uid.chars().any(char::is_control))
        .map(str::to_string)
        .ok_or_else(|| "create response UID is missing or invalid".to_string())
}

fn prepare_create_provenance(
    parts: &mut Parts,
    body: Bytes,
    op: &ApiOp,
    enabled: bool,
) -> Result<Bytes, String> {
    if !enabled || op.verb != Verb::Create || op.dry_run {
        return Ok(body);
    }
    if parts.extensions.get::<PreparedCreateProvenance>().is_some() {
        return Ok(body);
    }
    let provenance = format!("{:032x}", rand::random::<u128>());
    let body = bind_create_provenance(&body, &provenance)?;
    parts
        .extensions
        .insert(PreparedCreateProvenance(provenance));
    Ok(body)
}

fn take_guard_session(headers: &mut HeaderMap) -> Result<Option<String>, &'static str> {
    if headers.get_all(GUARD_SESSION_HEADER).iter().count() > 1
        || headers.get_all(header::AUTHORIZATION).iter().count() > 1
    {
        return Err("guard api-proxy: multiple session credentials are not allowed");
    }
    let alias = match headers.remove(GUARD_SESSION_HEADER) {
        Some(value) => {
            let token = value
                .to_str()
                .map_err(|_| "guard api-proxy: invalid session token encoding")?;
            if !super::kubeconfig::valid_guard_session_token(token) {
                return Err("guard api-proxy: invalid session token");
            }
            Some(token.to_string())
        }
        None => None,
    };
    let bearer = match headers.remove(header::AUTHORIZATION) {
        Some(value) => {
            let value = value
                .to_str()
                .map_err(|_| "guard api-proxy: invalid Authorization encoding")?;
            let (scheme, token) = value
                .split_once(' ')
                .ok_or("guard api-proxy: Authorization must be a Guard session bearer")?;
            if !scheme.eq_ignore_ascii_case("bearer")
                || !super::kubeconfig::valid_guard_session_token(token)
            {
                return Err("guard api-proxy: Authorization must be a Guard session bearer");
            }
            Some(token.to_string())
        }
        None => None,
    };
    // The anonymous placeholder from the no-session brokered kubeconfig
    // identifies nothing: drop it so the request proceeds unattributed instead
    // of failing closed as an unknown session.
    let alias = alias.filter(|token| token != super::kubeconfig::ANONYMOUS_SESSION_TOKEN);
    let bearer = bearer.filter(|token| token != super::kubeconfig::ANONYMOUS_SESSION_TOKEN);
    match (alias, bearer) {
        (Some(alias), Some(bearer)) if alias != bearer => {
            Err("guard api-proxy: conflicting session credentials")
        }
        (Some(token), _) | (_, Some(token)) => Ok(Some(token)),
        (None, None) => Ok(None),
    }
}

async fn collect_request_body(
    req: Request<Incoming>,
    timeout: Duration,
) -> std::result::Result<(Parts, Bytes), RequestBodyError> {
    let (parts, body) = req.into_parts();
    let collected = tokio::time::timeout(timeout, Limited::new(body, MAX_REQ_BODY).collect())
        .await
        .map_err(|_| RequestBodyError::Timeout)?
        .map_err(|error| {
            RequestBodyError::Read(anyhow!("read request body (limit {MAX_REQ_BODY}): {error}"))
        })?
        .to_bytes();
    Ok((parts, collected))
}

fn api_hold_snapshot(label: String, query: &str, op: &ApiOp, body: &[u8]) -> ApiHoldSnapshot {
    ApiHoldSnapshot {
        label,
        body_sha256: body_sha256(body),
        redacted_body_shape: redacted_body_shape(body),
        redacted_query: crate::evaluate::redact_for_llm(query),
        authority_selectors: op.authority_selectors.clone(),
    }
}

fn body_sha256(body: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(body)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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

/// Headers that carry or override the upstream request identity. Guard rejects
/// requests containing them before policy evaluation or forwarding because
/// its API policy has no identity dimension. The forwarding layer keeps this
/// defense in depth and never copies one to the upstream request.
fn is_identity_header(name: &header::HeaderName) -> bool {
    let s = name.as_str();
    s.starts_with("impersonate-") || s.starts_with("x-remote-")
}

fn is_sensitive_response_header(name: &header::HeaderName) -> bool {
    matches!(
        name.as_str().to_ascii_lowercase().as_str(),
        "authorization"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "www-authenticate"
            | "authentication-info"
            | "proxy-authentication-info"
            | "cookie"
            | "set-cookie"
            | "set-cookie2"
    )
}

fn is_safe_response_header(name: &header::HeaderName) -> bool {
    matches!(
        name.as_str(),
        "accept-ranges"
            | "cache-control"
            | "content-disposition"
            | "content-language"
            | "content-range"
            | "content-type"
            | "etag"
            | "expires"
            | "last-modified"
            | "retry-after"
            | "vary"
            | "warning"
    )
}

const MAX_RATE_LIMIT_HEADER_LEN: usize = 1024;

fn is_rate_limit_response_header(name: &header::HeaderName) -> bool {
    name.as_str().starts_with("x-ratelimit-") || name.as_str().starts_with("ratelimit-")
}

fn split_link_values(raw: &str) -> Option<Vec<&str>> {
    let mut values = Vec::new();
    let mut start = 0;
    let mut in_target = false;
    let mut in_quote = false;
    let mut escaped = false;
    for (index, character) in raw.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_quote && character == '\\' {
            escaped = true;
            continue;
        }
        match character {
            '"' if !in_target => in_quote = !in_quote,
            '<' if !in_quote && !in_target => in_target = true,
            '<' if !in_quote => return None,
            '>' if !in_quote && in_target => in_target = false,
            '>' if !in_quote => return None,
            ',' if !in_quote && !in_target => {
                values.push(&raw[start..index]);
                start = index + character.len_utf8();
            }
            _ => {}
        }
    }
    if in_target || in_quote || escaped {
        return None;
    }
    values.push(&raw[start..]);
    (!values.is_empty()).then_some(values)
}

fn header_contains_secret(value: &[u8], secrets: &[Vec<u8>]) -> bool {
    secrets.iter().any(|secret| {
        !secret.is_empty()
            && value
                .windows(secret.len())
                .any(|window| window == secret.as_slice())
    })
}

fn validate_listener_identity(listen: SocketAddr) -> Result<()> {
    if listen.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        && listen.ip() != std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
    {
        return Err(anyhow!(
            "api-proxy listener must bind to 127.0.0.1 or ::1 (got {listen})"
        ));
    }
    if listen.port() == 0 {
        return Err(anyhow!(
            "api-proxy listener must use an explicit nonzero port"
        ));
    }
    Ok(())
}

fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.trim_start().starts_with("application/json"))
        .unwrap_or(false)
}

fn has_unsupported_content_encoding(headers: &HeaderMap) -> bool {
    let mut saw_header = false;
    let mut codings = Vec::new();
    for value in headers.get_all(header::CONTENT_ENCODING) {
        saw_header = true;
        let Ok(value) = value.to_str() else {
            return true;
        };
        codings.extend(value.split(',').map(str::trim));
    }
    saw_header && (codings.len() != 1 || !codings[0].eq_ignore_ascii_case("identity"))
}

/// Depth past which the body shape collapses to a token, bounding prompt size
/// and recursion depth regardless of how deeply the body nests.
const MAX_SHAPE_DEPTH: usize = 8;
/// Total shape length past which the summary is truncated. Bounds the prompt
/// (and the evaluator cache key) a client can drive with a large body under
/// `MAX_REQ_BODY`.
const MAX_SHAPE_LEN: usize = 2048;
/// Object keys rendered per level before the rest are summarized as a count, so
/// a wide body cannot build an oversized string ahead of the length cap.
const MAX_SHAPE_KEYS: usize = 64;

fn redacted_body_shape(body: &[u8]) -> String {
    if body.is_empty() {
        return "(no body)".to_string();
    }
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(value) => {
            let mut shape = json_shape(&value, 0);
            if shape.len() > MAX_SHAPE_LEN {
                shape.truncate(MAX_SHAPE_LEN);
                shape.push_str("...(truncated)");
            }
            shape
        }
        Err(_) => format!("(non-JSON body, {} bytes)", body.len()),
    }
}

fn json_shape(value: &serde_json::Value, depth: usize) -> String {
    match value {
        serde_json::Value::Null => "<null>".to_string(),
        serde_json::Value::Bool(_) => "<bool>".to_string(),
        serde_json::Value::Number(_) => "<number>".to_string(),
        serde_json::Value::String(_) => "<string>".to_string(),
        _ if depth >= MAX_SHAPE_DEPTH => "<nested>".to_string(),
        serde_json::Value::Array(items) => {
            let first = items
                .first()
                .map(|v| json_shape(v, depth + 1))
                .unwrap_or_else(|| "(empty)".to_string());
            format!("[{} x {}]", first, items.len())
        }
        serde_json::Value::Object(map) => {
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort();
            // Cap the number of keys rendered per object so a wide body (many
            // small keys, each under the depth limit) stays within a bounded
            // string length before the outer length truncation.
            let extra = keys.len().saturating_sub(MAX_SHAPE_KEYS);
            let mut fields = keys
                .into_iter()
                .take(MAX_SHAPE_KEYS)
                .map(|key| {
                    format!(
                        "\"{}\":{}",
                        sanitize_shape_key(key),
                        json_shape(&map[key], depth + 1)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            if extra > 0 {
                fields.push_str(&format!(",...(+{extra} keys)"));
            }
            format!("{{{fields}}}")
        }
    }
}

/// The request body is client-controlled, and its object keys flow into both the
/// evaluator prompt and the evaluator cache key. Emit only a bounded,
/// control-character-free rendering of each key so an untrusted key contributes
/// only printable text: it cannot alter the judge prompt prose, the
/// newline-delimited trailing structured fields of
/// [`super::gate::ApiRequestSummary::stable_text`], or the derived cache key.
/// Anything outside a conservative printable set is replaced, and the result is
/// length-capped.
fn sanitize_shape_key(key: &str) -> String {
    const MAX_KEY_LEN: usize = 48;
    let mut out = String::with_capacity(key.len().min(MAX_KEY_LEN));
    for ch in key.chars().take(MAX_KEY_LEN) {
        let safe = ch.is_ascii_alphanumeric()
            || matches!(ch, '-' | '_' | '.' | '/' | ':' | ' ' | '+' | '@');
        out.push(if safe { ch } else { '?' });
    }
    if key.chars().count() > MAX_KEY_LEN {
        out.push('~');
    }
    out
}

/// Reload the policy file when its content changes. A parse error keeps the
/// last good policy in force and is logged.
async fn policy_reloader(path: PathBuf, proxy: Arc<ApiProxy>) {
    use sha2::{Digest, Sha256};

    let digest = |bytes: &[u8]| Sha256::digest(bytes).to_vec();
    // The task can start after an operator has already replaced the file. The
    // first read is therefore compared with the loaded policy, rather than
    // treated as an unquestioned baseline that could miss that replacement.
    let mut last = None;
    loop {
        tokio::time::sleep(proxy.policy_reload_interval).await;
        let bytes = match tokio::fs::read(&path).await {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::error!(
                    target: "guard::apiproxy",
                    "cannot read api-policy {}: {error}",
                    path.display()
                );
                continue;
            }
        };
        let observed = digest(&bytes);
        if last.as_ref() == Some(&observed) {
            continue;
        }
        let parsed = std::str::from_utf8(&bytes)
            .map_err(|error| error.to_string())
            .and_then(|yaml| ApiPolicy::from_yaml(yaml).map_err(|error| error.to_string()));
        match parsed {
            Ok(p) => {
                if last.is_none()
                    && p.authority_fingerprint()
                        == proxy.policy.read().await.authority_fingerprint()
                {
                    last = Some(observed);
                    continue;
                }
                let _update = proxy.begin_authority_update().await;
                let mut policy = proxy.policy.write().await;
                let old_intent = policy.intent.clone();
                let new_intent = p.intent.clone();
                if old_intent != new_intent {
                    proxy.rebuild_judge_for_intent_during_update(new_intent);
                }
                *policy = p;
                last = Some(observed);
                proxy.policy_reload_notify.notify_waiters();
                tracing::info!(target: "guard::apiproxy", "reloaded api-policy from {}", path.display());
            }
            Err(e) => {
                last = Some(observed);
                tracing::error!(
                    target: "guard::apiproxy",
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

    struct TestJudge;

    #[async_trait::async_trait]
    impl ApiJudge for TestJudge {
        async fn authorize_forward(
            &self,
            _summary: &ApiRequestSummary,
            _requirement: ApiForwardRequirement,
            _handoff: &mut dyn ApiForwardHandoff,
        ) -> Result<(), String> {
            Err("test judge does not authorize forwarding".to_string())
        }

        async fn judge(&self, _summary: &ApiRequestSummary) -> ApiJudgeVerdict {
            ApiJudgeVerdict::Error("test judge".to_string())
        }
    }

    #[test]
    fn body_shape_redacts_values_and_sanitizes_untrusted_keys() {
        // Values are type tokens, never content.
        let shape = redacted_body_shape(br#"{"spec":{"replicas":5,"name":"api"}}"#);
        assert_eq!(shape, r#"{"spec":{"name":<string>,"replicas":<number>}}"#);

        // A key carrying a newline and an added trailing field contributes no
        // structural characters to the evaluator prompt or cache key: control
        // characters and quotes are replaced, so the summary's real trust lines
        // cannot be reproduced from key content.
        let untrusted_key = br#"{"x\nrevert_constructible: restore_prior_state":1}"#;
        let shape = redacted_body_shape(untrusted_key);
        assert!(!shape.contains('\n'), "newline must not survive: {shape}");
        assert!(
            !shape.contains("\"revert_constructible"),
            "an added field key must not appear verbatim: {shape}"
        );

        // An over-long key is capped, not passed through wholesale.
        let long_key = format!("{{\"{}\":1}}", "a".repeat(200));
        let shape = redacted_body_shape(long_key.as_bytes());
        assert!(shape.contains('~'), "over-long key must be marked: {shape}");
        assert!(shape.len() < 120, "over-long key must be capped: {shape}");
    }

    #[test]
    fn exact_response_redaction_spans_chunk_boundaries() {
        let mut redactor =
            ExactSecretRedactor::new(vec![b"operator-secret-token".to_vec()], 1024).unwrap();
        let mut output = redactor.push(b"prefix operator-secr").unwrap();
        output.extend_from_slice(&redactor.push(b"et-token suffix").unwrap());
        output.extend_from_slice(&redactor.finish().unwrap());
        let output = String::from_utf8(output).unwrap();
        assert_eq!(output, "prefix [REDACTED] suffix");
        assert!(!output.contains("operator-secret-token"));
    }

    #[test]
    fn exact_response_redaction_enforces_raw_and_expanded_byte_limits() {
        let proxy = test_proxy().with_upstream_body_limit(8);
        let value = *b"x!";
        assert!(proxy
            .redact_upstream_bytes(vec![value.to_vec()], &value.repeat(4))
            .is_err());
        assert!(proxy.redact_upstream_bytes(Vec::new(), &[b'x'; 9]).is_err());
    }

    #[tokio::test]
    async fn policy_fingerprint_wait_registers_before_observation() {
        let proxy = test_proxy();
        let replacement = ApiPolicy::from_yaml("default: allow\n").unwrap();
        let expected = replacement.authority_fingerprint();
        let mut replacement = Some(replacement);
        let mut checks = 0;

        tokio::time::timeout(
            Duration::from_secs(1),
            proxy.wait_for_policy_fingerprint_with_before_check(&expected, || {
                checks += 1;
                match checks {
                    1 => proxy.policy_reload_notify.notify_waiters(),
                    2 => {
                        *proxy
                            .policy
                            .try_write()
                            .expect("policy is available for deterministic publication") =
                            replacement.take().expect("replacement publishes once");
                    }
                    _ => panic!("fingerprint waiter performed an unexpected extra check"),
                }
            }),
        )
        .await
        .expect("a notification between registration and observation must not be lost");
        assert_eq!(checks, 2);
    }

    #[tokio::test]
    async fn response_derived_authority_rejects_a_stale_route_generation() {
        let proxy = test_proxy();
        let (_, expected) = proxy.capture_route_authority().await.unwrap();
        drop(proxy.begin_authority_update().await);
        assert!(
            !proxy
                .publication_authority_is_current(&expected, None)
                .await
        );
    }

    #[tokio::test]
    async fn authority_update_panic_finalizes_revision_and_reads_remain_bounded() {
        let proxy = Arc::new(test_proxy());
        let panic_result = tokio::spawn({
            let proxy = proxy.clone();
            async move {
                let _update = proxy.begin_authority_update().await;
                panic!("injected authority publication panic");
            }
        })
        .await;
        assert!(panic_result.is_err());
        assert!(proxy
            .authority_revision
            .load(Ordering::Acquire)
            .is_multiple_of(2));
        assert!(proxy.capture_route_authority().await.is_ok());

        proxy
            .authority_revision
            .store(u64::MAX - 1, Ordering::Release);
        drop(proxy.begin_authority_update().await);
        assert_eq!(proxy.authority_revision.load(Ordering::Acquire), 0);

        proxy.authority_revision.store(1, Ordering::Release);
        assert!(proxy.capture_route_authority().await.is_err());
        proxy.authority_revision.store(2, Ordering::Release);
    }

    #[tokio::test]
    async fn authority_update_waits_for_upstream_initiation_lease() {
        let proxy = Arc::new(test_proxy());
        let (_, expected) = proxy.capture_route_authority().await.unwrap();
        let lease = proxy
            .reserve_authority_initiation(&expected)
            .await
            .expect("current authority must reserve");
        let (published_tx, published_rx) = tokio::sync::oneshot::channel();
        let update = tokio::spawn({
            let proxy = proxy.clone();
            let callback_proxy = proxy.clone();
            async move {
                let _update = proxy
                    .begin_authority_update_with_callback(move || {
                        let _ = published_tx
                            .send(callback_proxy.authority_revision.load(Ordering::Acquire));
                    })
                    .await;
                proxy.authority_revision.load(Ordering::Acquire)
            }
        });
        let published_revision = tokio::time::timeout(Duration::from_secs(1), published_rx)
            .await
            .expect("authority update publishes before waiting for the lease")
            .expect("authority publication callback remains live");
        assert!(!published_revision.is_multiple_of(2));
        assert!(!update.is_finished());
        drop(lease);
        assert_eq!(update.await.unwrap(), 1);
    }

    #[tokio::test]
    async fn authority_update_callback_runs_after_odd_revision_publication() {
        let proxy = Arc::new(test_proxy());
        let observed_revision = Arc::new(AtomicU64::new(0));
        let transition_generation = proxy.authority_transition_generation();
        let callback_proxy = proxy.clone();
        let callback_observed_revision = observed_revision.clone();
        let update = proxy
            .begin_authority_update_with_callback(move || {
                callback_observed_revision.store(
                    callback_proxy.authority_revision.load(Ordering::Acquire),
                    Ordering::Release,
                );
            })
            .await;

        assert_eq!(observed_revision.load(Ordering::Acquire), 1);
        assert_eq!(
            proxy.authority_transition_generation(),
            transition_generation.wrapping_add(1)
        );
        drop(update);
        assert_eq!(
            proxy.authority_transition_generation(),
            transition_generation.wrapping_add(1)
        );
        assert!(proxy
            .authority_revision
            .load(Ordering::Acquire)
            .is_multiple_of(2));
    }

    #[tokio::test]
    async fn cancelled_authority_update_restores_even_revision_before_write_lease() {
        let proxy = Arc::new(test_proxy());
        let (_, expected) = proxy.capture_route_authority().await.unwrap();
        let lease = proxy
            .reserve_authority_initiation(&expected)
            .await
            .expect("current authority must reserve");

        let update = tokio::spawn({
            let proxy = proxy.clone();
            async move {
                let _update = proxy.begin_authority_update().await;
            }
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if !proxy
                    .authority_revision
                    .load(Ordering::Acquire)
                    .is_multiple_of(2)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("authority update must publish its odd revision");
        update.abort();
        assert!(update.await.unwrap_err().is_cancelled());
        assert!(proxy
            .authority_revision
            .load(Ordering::Acquire)
            .is_multiple_of(2));

        drop(lease);
        tokio::time::timeout(Duration::from_secs(1), proxy.capture_route_authority())
            .await
            .expect("capture remains bounded after cancellation")
            .expect("authority capture remains available after cancellation");
        let update_guard =
            tokio::time::timeout(Duration::from_secs(1), proxy.begin_authority_update())
                .await
                .expect("subsequent update remains bounded");
        drop(update_guard);
        assert!(proxy
            .authority_revision
            .load(Ordering::Acquire)
            .is_multiple_of(2));

        proxy
            .authority_revision
            .store(u64::MAX - 1, Ordering::Release);
        let update_guard =
            tokio::time::timeout(Duration::from_secs(1), proxy.begin_authority_update())
                .await
                .expect("maximum even revision update remains bounded");
        drop(update_guard);
        assert_eq!(proxy.authority_revision.load(Ordering::Acquire), 0);
    }

    #[test]
    fn listener_identity_is_exact_nonzero_loopback() {
        assert!(validate_listener_identity("127.0.0.1:8443".parse().unwrap()).is_ok());
        assert!(validate_listener_identity("[::1]:8443".parse().unwrap()).is_ok());
        for address in ["127.0.0.1:0", "[::1]:0", "127.0.0.2:8443"] {
            assert!(validate_listener_identity(address.parse().unwrap()).is_err());
        }
    }

    #[test]
    fn location_rewrites_only_same_origin_credential_free_targets() {
        let proxy = test_proxy();
        let secrets = vec![b"operator-secret-token".to_vec()];
        assert!(proxy
            .safe_location(
                &HeaderValue::from_static("https://attacker.invalid/collect"),
                &secrets,
            )
            .is_none());
        assert!(proxy
            .safe_location(
                &HeaderValue::from_static("https://x:6443/path?token=operator-secret-token"),
                &secrets,
            )
            .is_none());
        assert_eq!(
            proxy
                .safe_location(&HeaderValue::from_static("https://x:6443/path"), &secrets)
                .unwrap(),
            HeaderValue::from_static("https://127.0.0.1:0/path")
        );
        assert_eq!(
            proxy
                .safe_location(&HeaderValue::from_static("/api/v1"), &secrets)
                .unwrap(),
            HeaderValue::from_static("/api/v1")
        );
    }

    #[test]
    fn link_rewrites_every_safe_target_and_rejects_any_unsafe_target() {
        let proxy = test_proxy();
        let secrets = vec![b"operator-secret-token".to_vec()];
        let safe = proxy
            .safe_link(
                &HeaderValue::from_static(
                    "<https://x:6443/items?page=2>; rel=\"next\", </items?page=1>; rel=\"prev alternate\"; title=\"a,b\"",
                ),
                &secrets,
            )
            .unwrap();
        assert_eq!(
            safe,
            HeaderValue::from_static(
                "<https://127.0.0.1:0/items?page=2>; rel=\"next\", </items?page=1>; rel=\"prev alternate\"; title=\"a,b\""
            )
        );
        assert!(proxy
            .safe_link(
                &HeaderValue::from_static(
                    "</items?page=2>; rel=\"next\", <https://attacker.invalid/collect>; rel=\"prev\"",
                ),
                &secrets,
            )
            .is_none());
        assert!(proxy
            .safe_link(
                &HeaderValue::from_static(
                    "<https://x:6443/items?token=operator-secret-token>; rel=\"next\"",
                ),
                &secrets,
            )
            .is_none());
    }

    fn created_key(conn: u64, name: &str) -> CreatedKey {
        CreatedKey {
            conn,
            session_fingerprint: None,
            group: String::new(),
            resource: "configmaps".to_string(),
            namespace: Some("dev".to_string()),
            name: name.to_string(),
        }
    }

    fn session_created_key(conn: u64, name: &str, fingerprint: &str) -> CreatedKey {
        CreatedKey {
            session_fingerprint: Some(fingerprint.to_string()),
            ..created_key(conn, name)
        }
    }

    #[test]
    fn provenance_is_scoped_to_the_creating_connection() {
        // Caller A (connection 1) creates a resource; the proxy records its
        // auto-revert handle keyed to that connection.
        let mut reg = CreatedRegistry::default();
        reg.remember(
            created_key(1, "foo"),
            "handle-A".to_string(),
            "resource-uid".to_string(),
            "provenance".to_string(),
        );

        // Caller B on a different connection deletes the same
        // group/resource/namespace/name: no provenance match, so the delete
        // falls through to normal (strict) policy instead of the shortcut.
        assert_eq!(reg.find(&created_key(2, "foo")), None);
        assert_eq!(
            reg.len(),
            1,
            "a non-matching take must not consume the entry"
        );

        // Caller A deleting its own creation still matches and is contained.
        assert_eq!(
            reg.find(&created_key(1, "foo")),
            Some("handle-A".to_string())
        );
        assert!(reg.take_if_handle(&created_key(1, "foo"), "handle-A"));
        assert_eq!(reg.len(), 0, "a matching take consumes the entry once");
    }

    #[test]
    fn provenance_is_scoped_to_the_exact_session_on_a_shared_connection() {
        let mut reg = CreatedRegistry::default();
        reg.remember(
            session_created_key(1, "foo", "session-a"),
            "handle-a".to_string(),
            "resource-uid".to_string(),
            "provenance".to_string(),
        );

        assert_eq!(reg.find(&created_key(1, "foo")), None);
        assert_eq!(reg.find(&session_created_key(1, "foo", "session-b")), None);
        assert_eq!(
            reg.find(&session_created_key(1, "foo", "session-a")),
            Some("handle-a".to_string())
        );
    }

    #[test]
    fn provenance_is_dropped_when_its_revert_resolves() {
        let mut reg = CreatedRegistry::default();
        reg.remember(
            created_key(1, "foo"),
            "handle-A".to_string(),
            "resource-uid".to_string(),
            "provenance".to_string(),
        );

        // The create's auto-revert resolves (operator confirm, or auto/manual
        // revert): the daemon drops the provenance by handle.
        reg.forget_by_handle("handle-A");
        assert_eq!(reg.len(), 0);

        // A later delete of a same-named resource (e.g. one an operator recreated
        // outside guard) no longer matches the stale entry and goes through
        // normal policy.
        assert_eq!(reg.find(&created_key(1, "foo")), None);
    }

    #[test]
    fn create_provenance_is_bound_into_the_forwarded_object() {
        let body = bind_create_provenance(
            br#"{"metadata":{"name":"example","annotations":{"fixture":"kept"}},"spec":{}}"#,
            "provisional-handle",
        )
        .unwrap();
        let object: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            object["metadata"]["annotations"][CREATE_PROVENANCE_ANNOTATION],
            "provisional-handle"
        );
        assert_eq!(object["metadata"]["annotations"]["fixture"], "kept");
    }

    fn test_proxy() -> ApiProxy {
        let yaml = "apiVersion: v1\n\
             kind: Config\n\
             current-context: ctx\n\
             clusters: [{name: c, cluster: {server: \"https://x:6443\"}}]\n\
             contexts: [{name: ctx, context: {cluster: c, user: u}}]\n\
             users: [{name: u, user: {token: t}}]\n";
        let upstream = Upstream::from_kubeconfig_str(yaml, None).expect("upstream");
        let tls = ProxyTls::generate().expect("tls");
        ApiProxy::new(
            "127.0.0.1:0".parse().unwrap(),
            tls,
            upstream,
            ApiPolicy::deny_all(),
            None,
        )
    }

    #[test]
    fn provisional_response_metadata_includes_handle_deadline_and_remaining_seconds() {
        let (provisional, warning) =
            provisional_response_metadata("handle-123", 1_700_000_123, 1_700_000_100);

        assert_eq!(
            provisional,
            "handle-123; deadline_unix=1700000123; seconds_remaining=23"
        );
        assert_eq!(
            warning,
            "299 guard \"change is provisional; confirm with guard confirm handle-123; auto-revert deadline_unix=1700000123; seconds_remaining=23\""
        );
    }

    #[test]
    fn provisional_response_metadata_never_reports_negative_remaining_seconds() {
        let (provisional, warning) = provisional_response_metadata("handle-123", 100, 101);

        assert!(provisional.ends_with("seconds_remaining=0"));
        assert!(warning.contains("deadline_unix=100; seconds_remaining=0"));
    }

    #[tokio::test]
    async fn judge_attachment_uses_authority_coordination() {
        let proxy = test_proxy();
        let before = proxy.authority_revision.load(Ordering::Acquire);

        proxy.attach_judge(Arc::new(TestJudge)).await;

        assert!(proxy.has_judge());
        assert_eq!(
            proxy.authority_revision.load(Ordering::Acquire),
            before.wrapping_add(2)
        );
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
            authority_selectors: Default::default(),
        }
    }

    #[test]
    fn rarity_tracker_escalates_until_threshold_then_stops() {
        let t = RarityTracker::new(2);
        let key = || ShapeKey {
            protocol: "kubernetes".to_string(),
            verb: "get",
            group: String::new(),
            resource: "pods".to_string(),
            subresource: None,
            namespace: Some("dev".to_string()),
            authority_selectors: Default::default(),
        };
        // First two occurrences are still under the threshold -> escalate.
        assert!(t.observe_is_rare(key()));
        assert!(t.observe_is_rare(key()));
        // The shape has now been seen `threshold` times; it is no longer rare.
        assert!(!t.observe_is_rare(key()));
        assert!(!t.observe_is_rare(key()));
        // A different shape starts its own count.
        let other = ShapeKey {
            resource: "secrets".to_string(),
            ..key()
        };
        assert!(t.observe_is_rare(other));
    }

    #[test]
    fn rarity_tracker_disabled_never_escalates() {
        let t = RarityTracker::new(0);
        assert!(!t.enabled());
        let key = ShapeKey {
            protocol: "kubernetes".to_string(),
            verb: "delete",
            group: String::new(),
            resource: "namespaces".to_string(),
            subresource: None,
            namespace: None,
            authority_selectors: Default::default(),
        };
        assert!(!t.observe_is_rare(key));
    }

    #[test]
    fn rarity_tracker_evicts_distinct_attacker_shapes_at_a_finite_bound() {
        let t = RarityTracker::new(1);
        for index in 0..(MAX_RARITY_SHAPES + 100) {
            let key = ShapeKey {
                protocol: "kubernetes".to_string(),
                verb: "get",
                group: String::new(),
                resource: format!("resource-{index}"),
                subresource: None,
                namespace: Some(format!("namespace-{index}")),
                authority_selectors: Default::default(),
            };
            assert!(t.observe_is_rare(key));
        }
        assert!(t.state.lock().unwrap().0.len() <= MAX_RARITY_SHAPES);
    }

    #[test]
    fn shape_key_ignores_object_name() {
        let proxy = test_proxy();
        // Two deletes of differently-named objects share a shape.
        assert_eq!(
            proxy.shape_key(&delete_op("a")),
            proxy.shape_key(&delete_op("b"))
        );
    }

    #[tokio::test]
    async fn serve_on_rejects_a_listener_for_another_address() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let different = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind different test listener");
        let mut proxy = test_proxy();
        proxy.listen = different.local_addr().unwrap();
        drop(different);
        let proxy = Arc::new(proxy);

        let error = proxy
            .serve_on(listener)
            .await
            .expect_err("configured and bound addresses differ");

        assert!(
            error
                .to_string()
                .contains("does not match configured address"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn created_provenance_matches_without_consuming() {
        let proxy = test_proxy();
        proxy.created.lock().unwrap().remember(
            created_key(1, "foo"),
            "h1".to_string(),
            "resource-uid".to_string(),
            "provenance".to_string(),
        );

        let op = delete_op("foo");
        // A delete on a different connection does not match.
        assert!(proxy.created_provenance(&op, 2, None).is_none());
        // The creating connection matches but does not consume before a
        // successful upstream delete.
        assert_eq!(proxy.created_provenance(&op, 1, None).unwrap().handle, "h1");
        assert!(proxy.created_provenance(&op, 1, None).is_some());
    }

    #[test]
    fn paths_that_alter_on_forward_are_rejected() {
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
    fn guard_session_bearer_is_parsed_and_removed() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer live-session".parse().unwrap(),
        );
        assert_eq!(
            take_guard_session(&mut headers).unwrap().as_deref(),
            Some("live-session")
        );
        assert!(!headers.contains_key(header::AUTHORIZATION));
    }

    #[test]
    fn anonymous_placeholder_bearer_is_stripped_and_unattributed() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!(
                "Bearer {}",
                super::super::kubeconfig::ANONYMOUS_SESSION_TOKEN
            )
            .parse()
            .unwrap(),
        );
        assert_eq!(take_guard_session(&mut headers).unwrap(), None);
        assert!(!headers.contains_key(header::AUTHORIZATION));

        // A real alias next to the placeholder bearer attributes the request
        // to the alias instead of failing as conflicting credentials.
        let mut mixed = HeaderMap::new();
        mixed.insert(GUARD_SESSION_HEADER, "live-session".parse().unwrap());
        mixed.insert(
            header::AUTHORIZATION,
            format!(
                "Bearer {}",
                super::super::kubeconfig::ANONYMOUS_SESSION_TOKEN
            )
            .parse()
            .unwrap(),
        );
        assert_eq!(
            take_guard_session(&mut mixed).unwrap().as_deref(),
            Some("live-session")
        );
    }

    #[test]
    fn malformed_or_conflicting_session_credentials_fail_closed() {
        let mut basic = HeaderMap::new();
        basic.insert(header::AUTHORIZATION, "Basic abc".parse().unwrap());
        assert!(take_guard_session(&mut basic).is_err());

        let mut conflicting = HeaderMap::new();
        conflicting.insert(GUARD_SESSION_HEADER, "one".parse().unwrap());
        conflicting.insert(header::AUTHORIZATION, "Bearer two".parse().unwrap());
        assert_eq!(
            take_guard_session(&mut conflicting).unwrap_err(),
            "guard api-proxy: conflicting session credentials"
        );

        let mut duplicate = HeaderMap::new();
        duplicate.append(header::AUTHORIZATION, "Bearer one".parse().unwrap());
        duplicate.append(header::AUTHORIZATION, "Bearer two".parse().unwrap());
        assert_eq!(
            take_guard_session(&mut duplicate).unwrap_err(),
            "guard api-proxy: multiple session credentials are not allowed"
        );
    }

    #[test]
    fn credential_bearing_response_headers_are_sensitive() {
        for name in [
            "set-cookie",
            "authorization",
            "proxy-authenticate",
            "www-authenticate",
        ] {
            assert!(is_sensitive_response_header(&name.parse().unwrap()));
        }
        assert!(!is_sensitive_response_header(
            &"content-type".parse().unwrap()
        ));
    }

    #[test]
    fn response_encoding_requires_one_exact_identity_coding() {
        let mut headers = HeaderMap::new();
        assert!(!has_unsupported_content_encoding(&headers));
        headers.insert(
            header::CONTENT_ENCODING,
            HeaderValue::from_static("identity"),
        );
        assert!(!has_unsupported_content_encoding(&headers));

        for value in ["gzip", "identity, gzip", "identity, identity", ""] {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_ENCODING,
                HeaderValue::from_str(value).unwrap(),
            );
            assert!(has_unsupported_content_encoding(&headers), "{value:?}");
        }

        let mut duplicate = HeaderMap::new();
        duplicate.append(
            header::CONTENT_ENCODING,
            HeaderValue::from_static("identity"),
        );
        duplicate.append(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert!(has_unsupported_content_encoding(&duplicate));
    }

    #[test]
    fn persisted_revert_identity_requires_protocol_target_and_credential_identity() {
        let proxy = test_proxy();
        let target = proxy.upstream().base().to_string();
        let identity = proxy.upstream_identity_fingerprint();

        assert!(proxy.matches_upstream_identity("kubernetes", &target, &identity));
        assert!(!proxy.matches_upstream_identity("github", &target, &identity));
        assert!(!proxy.matches_upstream_identity("kubernetes", "https://other.invalid", &identity));
        assert!(!proxy.matches_upstream_identity("kubernetes", &target, "other-identity"));
        assert!(!proxy.matches_upstream_identity("kubernetes", "", ""));
    }

    #[test]
    fn forget_created_by_handle_clears_public_provenance() {
        let proxy = test_proxy();
        proxy.created.lock().unwrap().remember(
            created_key(1, "foo"),
            "h1".to_string(),
            "resource-uid".to_string(),
            "provenance".to_string(),
        );

        proxy.forget_created_by_handle("h1");

        assert!(proxy
            .created_provenance(&delete_op("foo"), 1, None)
            .is_none());
    }
}
