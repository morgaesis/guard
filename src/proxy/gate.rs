//! Bridge from the API proxy to the daemon's consequence machinery.
//!
//! When the proxy forwards a recoverable write, it captures what is needed to
//! undo it (the prior object, or the identity of a created one) and hands it to
//! a [`GateSink`]. The daemon implements the sink by arming a `Provisional` in
//! the shared registry with an API-revert request, so the existing auto-revert
//! sweeper and `guard confirm`/`guard provisionals` apply unchanged. Keeping the
//! sink a trait keeps the proxy (lib) free of the daemon's persistence types.

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
    async fn hold_request(&self, _label: &str, _reason: &str) -> HoldDecision {
        HoldDecision::Denied {
            reason: "no operator-approval queue is attached to this proxy".to_string(),
        }
    }
}
