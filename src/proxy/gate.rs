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

/// Implemented by the daemon to arm the proxy's synthesized reverts in its
/// consequence machinery.
#[async_trait]
pub trait GateSink: Send + Sync {
    /// Arm an auto-revert envelope around a mutation the proxy already applied.
    /// Returns the provisional handle, or `None` if the daemon declined (e.g.
    /// the outstanding-provisional cap is hit). The proxy proceeds regardless —
    /// the mutation is already live; `None` only means it will not auto-revert.
    async fn arm_revert(&self, mutation: ApiMutation) -> Option<String>;
}
