//! The protocol plug-in surface for the REST proxy. A [`ProtocolConfig`]
//! answers every protocol-specific question the server loop asks: how a request
//! line parses into a typed [`ApiOp`], which operations are never forwarded
//! regardless of policy, which reads carry secret material that must be
//! redacted, and how to build the revert for a tracked write. The server loop
//! itself (TLS termination, policy matching, the hold/approval flow, auto-revert
//! arming, created-object provenance) is protocol-agnostic; a new protocol plugs
//! in by implementing this trait, with Kubernetes
//! ([`super::k8s_protocol::KubernetesProtocol`]) as the reference
//! implementation.

use super::gate::HttpRevert;
use super::op::ApiOp;
use hyper::http::HeaderName;

/// Identity of an object a tracked write created. The proxy records it (scoped
/// to the creating connection) so a later delete of the same object is
/// recognized as contained cleanup rather than an unrecorded destructive
/// delete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedIdentity {
    pub group: String,
    pub resource: String,
    pub namespace: Option<String>,
    pub name: String,
}

/// The revert plan for a tracked write the proxy just forwarded.
#[derive(Debug, Clone)]
pub struct PlannedRevert {
    /// Human label for the audit log and `guard provisionals`, e.g.
    /// `patch deployments/api in dev`.
    pub label: String,
    pub revert: HttpRevert,
    /// Set when the write created a new object; the proxy records it for
    /// delete-provenance matching.
    pub created: Option<CreatedIdentity>,
}

/// One protocol's contribution to the proxy: pure classification and revert
/// synthesis over parsed operations. Implementations hold no I/O; the server
/// owns the sockets, the upstream client, the policy, and the gate.
pub trait ProtocolConfig: Send + Sync {
    /// Short protocol name, e.g. `kubernetes`.
    fn name(&self) -> &str;

    /// Parse a request line into a typed operation. `path` is the URL path (no
    /// query), `query` the raw query string. `None` means the path carries no
    /// object to gate (discovery, health, version); the server forwards safe
    /// reads of those and blocks everything else.
    fn parse_op(&self, method: &str, path: &str, query: &str) -> Option<ApiOp>;

    /// The client-facing reason an operation is denied regardless of policy —
    /// streams the request-level gate cannot inspect or redact per object.
    /// `None` leaves the decision to policy.
    fn deny_outright(&self, op: &ApiOp) -> Option<String>;

    /// Whether this operation reads secret material, so an allowed response is
    /// redacted when the policy decision asks for it.
    fn redactable_read(&self, op: &ApiOp) -> bool;

    /// Redact secret material from a response body, in place. Returns the
    /// number of objects redacted.
    fn redact_response(&self, value: &mut serde_json::Value) -> usize;

    /// Explicit exception for a credential-shaped upstream response header.
    /// The safe default strips every such header at the trust boundary.
    fn allow_sensitive_response_header(&self, _name: &HeaderName) -> bool {
        false
    }

    /// Client-facing error body for proxy-generated denials and upstream
    /// failures. Kubernetes overrides this with a `Status`; other protocols use
    /// plain JSON.
    fn error_body(&self, code: u16, message: &str, reason: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "error": message,
            "reason": reason,
            "code": code,
        }))
        .expect("proxy error JSON serialization is infallible")
    }

    /// Whether a successful write of this operation is wrapped in an
    /// auto-revert envelope when the consequence gate is active.
    fn tracks_write(&self, op: &ApiOp) -> bool;

    /// Whether the server should fetch the object's current state before
    /// forwarding a tracked write, so [`Self::plan_revert`] can build a
    /// restore-style revert from it.
    fn wants_prior_snapshot(&self, op: &ApiOp) -> bool;

    /// Build the revert for a tracked write that succeeded upstream.
    /// `prior_object` is the raw body of the pre-write fetch (when one was
    /// taken); `response` is the upstream response body. `Err` carries the
    /// reason no revert could be built, which the server logs — the write is
    /// already live either way, so an `Err` only means it will not auto-revert.
    fn plan_revert(
        &self,
        op: &ApiOp,
        prior_object: Option<&[u8]>,
        response: &[u8],
    ) -> Result<PlannedRevert, String>;
}
