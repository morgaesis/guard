//! Bridge from the API proxy to the daemon's consequence machinery.
//!
//! When the proxy forwards a recoverable write, it captures what is needed to
//! undo it (the prior object, or the identity of a created one) and hands it to
//! a [`GateSink`]. The daemon implements the sink by arming a `Provisional` in
//! the shared registry with an API-revert request, so the existing auto-revert
//! sweeper and `guard confirm`/`guard provisionals` apply unchanged. Keeping the
//! sink a trait keeps the proxy (lib) free of the daemon's persistence types.

use crate::gating::Reversibility;
use async_trait::async_trait;

/// How to undo a recoverable API mutation via an HTTP request through the upstream.
/// This is protocol-generic; the protocol builds the full request plan including path.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HttpRevert {
    /// HTTP method (GET, POST, PUT, DELETE, etc.)
    pub method: String,
    /// Full request path (protocol-specific; does not include base URL)
    pub path: String,
    /// Optional request body
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Vec<u8>>,
}

/// A recoverable mutation to wrap in an auto-revert envelope.
#[derive(Debug, Clone)]
pub struct ApiMutation {
    /// Human label for the audit log and `guard provisionals`, e.g.
    /// `patch deployments/api in dev`.
    pub label: String,
    /// The HTTP request that undoes the mutation, executed through the
    /// protocol's upstream with the daemon's credential.
    pub revert: HttpRevert,
    /// Session authority that allowed the mutation, represented only by its
    /// audit fingerprint.
    pub session_fingerprint: Option<String>,
    /// Issued-session authority captured immediately before the upstream
    /// mutation. Reverts retain the immutable revision and secret selectors so
    /// they remain constrained to the authority that admitted the write.
    pub session_revision: Option<String>,
    pub secret_entitlements: Option<Vec<String>>,
    /// Canonical upstream target and a secret-free identity fingerprint. A
    /// persisted revert only runs through the exact same endpoint identity.
    pub upstream_target: String,
    pub upstream_identity: String,
}

/// Operator decision on a held API request.
#[derive(Debug, Clone)]
pub enum HoldDecision {
    /// The operator approved the exact held request; the proxy forwards it.
    /// Carries the approval handle for the audit trail.
    Approved { handle: String },
    /// Denied, expired, or never enqueued (capacity, no queue). The proxy
    /// returns the reason to the client and forwards nothing.
    Denied { reason: String },
}

/// Implemented by the daemon to arm the proxy's synthesized reverts in its
/// consequence machinery.
#[async_trait]
pub trait GateSink: Send + Sync {
    /// Arm an auto-revert envelope around a mutation the proxy already applied.
    /// Returns the provisional handle, or `None` if the daemon declined (e.g.
    /// the outstanding-provisional cap is hit). The proxy proceeds regardless —
    /// the mutation is already live; `None` only means it will not auto-revert.
    async fn arm_revert(&self, mutation: ApiMutation) -> Option<String>;

    /// Whether the sink could arm a revert right now (capacity available, and a
    /// body-bearing revert can be persisted safely). The proxy consults this on
    /// the evaluate path before forwarding a write it would only forward
    /// *because* a revert was promised, so it can hold rather than forward a
    /// write it cannot contain. Default: assume it can, for sinks that always
    /// accept a revert. Best-effort: a race between this check and `arm_revert`
    /// is possible, but this closes the common deterministic gaps (no capacity,
    /// no safe revert directory).
    async fn can_arm_revert(&self) -> bool {
        true
    }

    /// Resolve an auto-revert armed under `handle` because the object it would
    /// undo is already gone by the workload's own action — a resource guard
    /// created earlier in the session that the workload has now deleted (e.g. a
    /// Helm post-install hook removing its own check resource). Cancels the
    /// pending revert so the sweeper does not later try to delete an object that
    /// no longer exists. Default: no-op, for sinks that do not track reverts.
    async fn resolve(&self, _handle: &str) {}

    /// Enqueue a policy-held API request for operator approval and wait for the
    /// decision. The request stays buffered in the proxy while the operator
    /// reviews it (`guard approvals` / `guard approve` / `guard deny`); only an
    /// explicit approval releases it, and an unattended hold expires to a
    /// denial. Default: fail closed, for sinks with no approval queue.
    async fn hold_request(
        &self,
        _label: &str,
        _reason: &str,
        _session_context: Option<&ApiSessionContext>,
    ) -> HoldDecision {
        HoldDecision::Denied {
            reason: "no operator-approval queue is attached to this proxy".to_string(),
        }
    }
}

/// Whether the proxy can construct an auto-revert for this exact request before
/// asking the evaluator. This is an input to judgment, not a model output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevertConstructible {
    /// A prior object was fetched and can be PUT-restored after update/patch.
    RestorePriorState,
    /// A successful create response should identify the object to delete.
    DeleteCreated,
    /// A prior object was fetched and can be POST-recreated after delete.
    RecreateFromSnapshot,
    /// No faithful auto-revert is available for this operation.
    None,
}

impl RevertConstructible {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RestorePriorState => "restore_prior_state",
            Self::DeleteCreated => "delete_created",
            Self::RecreateFromSnapshot => "recreate_from_snapshot",
            Self::None => "none",
        }
    }

    pub fn is_constructible(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Stable, redacted request facts sent to an API judge. Values that may carry
/// secrets are summarized or redacted before this struct is built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiRequestSummary {
    pub protocol: String,
    pub verb: String,
    pub path: String,
    pub redacted_query: String,
    pub group: String,
    pub version: String,
    pub resource: String,
    pub subresource: Option<String>,
    pub namespace: Option<String>,
    pub name: Option<String>,
    pub dry_run: bool,
    pub redacted_body_shape: String,
    pub revert_constructible: RevertConstructible,
    pub rarity: bool,
    pub endpoint: String,
    pub session_fingerprint: Option<String>,
    pub session_intent: Option<String>,
    pub credential_ref: String,
}

impl ApiRequestSummary {
    /// Stable text used as the evaluator command string. Do not pass these
    /// fields via a per-request prompt append, because the evaluator cache keys
    /// on this exact string.
    pub fn stable_text(&self) -> String {
        format!(
            concat!(
                "API operation request\n",
                "protocol: {}\n",
                "verb: {}\n",
                "path: {}\n",
                "query: {}\n",
                "group: {}\n",
                "version: {}\n",
                "resource: {}\n",
                "subresource: {}\n",
                "namespace: {}\n",
                "name: {}\n",
                "dry_run: {}\n",
                "body_shape: {}\n",
                "revert_constructible: {}\n",
                "rarity: {}",
                "\nendpoint: {}\nsession: {}\nsession_intent: {}\ncredential_ref: {}"
            ),
            self.protocol,
            self.verb,
            self.path,
            if self.redacted_query.is_empty() {
                "(none)"
            } else {
                &self.redacted_query
            },
            if self.group.is_empty() {
                "(core)"
            } else {
                &self.group
            },
            self.version,
            self.resource,
            self.subresource.as_deref().unwrap_or("(none)"),
            self.namespace.as_deref().unwrap_or("(cluster)"),
            self.name.as_deref().unwrap_or("(none)"),
            self.dry_run,
            self.redacted_body_shape,
            self.revert_constructible.as_str(),
            self.rarity,
            self.endpoint,
            self.session_fingerprint.as_deref().unwrap_or("(none)"),
            self.session_intent.as_deref().unwrap_or("(none)"),
            self.credential_ref,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiSessionContext {
    pub fingerprint: String,
    /// Complete effective revision of the issued authority. This changes for
    /// every scope edit, not only prompt or expiry changes.
    pub revision: String,
    /// Saved-grant secret selectors. `None` means an unrestricted legacy or
    /// ad-hoc session, while `Some([])` entitles no upstream credential.
    pub secret_entitlements: Option<Vec<String>>,
    pub intent: Option<String>,
    pub can_override_baseline: bool,
}

#[derive(Debug, Clone)]
pub struct ApiSessionEvent {
    pub endpoint: String,
    pub operation: String,
    pub allowed: bool,
    pub status: u16,
    pub held: bool,
    pub credential_ref: String,
}

#[async_trait]
pub trait ApiSessionSink: Send + Sync {
    async fn resolve(&self, token: &str) -> Option<ApiSessionContext>;
    async fn record(&self, token: &str, event: ApiSessionEvent);
}

/// API evaluator verdict. An allow is still routed through `decide_gate`; it is
/// never a direct bypass of the deterministic consequence floor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiJudgeVerdict {
    Allow {
        reason: String,
        risk: Option<i32>,
        reversibility: Option<Reversibility>,
    },
    Deny {
        reason: String,
    },
    Error(String),
}

#[async_trait]
pub trait ApiJudge: Send + Sync {
    async fn judge(&self, summary: &ApiRequestSummary) -> ApiJudgeVerdict;
}
