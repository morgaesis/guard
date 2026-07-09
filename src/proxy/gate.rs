//! Bridge from the API proxy to the daemon's consequence machinery.
//!
//! When the proxy forwards a recoverable write, it captures what is needed to
//! undo it (the prior object, or the identity of a created one) and hands it to
//! a [`GateSink`]. The daemon implements the sink by arming a `Provisional` in
//! the shared registry with a `kubectl`-based revert, so the existing auto-revert
//! sweeper and `guard confirm`/`guard provisionals` apply unchanged. Keeping the
//! sink a trait keeps the proxy (lib) free of the daemon's persistence types.

use async_trait::async_trait;

/// How to undo a recoverable API mutation the proxy just forwarded.
#[derive(Debug, Clone)]
pub enum ApiRevert {
    /// Restore a prior object captured before an update/patch. The daemon writes
    /// the JSON to a file and reverts with `kubectl replace -f <file>`. The proxy
    /// strips `resourceVersion` first so the replace is unconditional.
    Restore { object_json: Vec<u8> },
    /// Delete an object the request created. The daemon reverts with
    /// `kubectl delete <resource>[.group] <name> [-n <ns>]`.
    DeleteCreated {
        group: String,
        resource: String,
        name: String,
        namespace: Option<String>,
    },
}

/// A recoverable mutation to wrap in an auto-revert envelope.
#[derive(Debug, Clone)]
pub struct ApiMutation {
    /// Human label for the audit log and `guard provisionals`, e.g.
    /// `patch deployments/api in dev`.
    pub label: String,
    pub revert: ApiRevert,
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
