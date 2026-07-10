//! The Kubernetes [`ProtocolConfig`] — the reference protocol plug-in.
//! Delegates parsing and Secret redaction to the pure functions in
//! [`super::k8s`] and keeps every Kubernetes-specific judgment (interactive
//! subresources, Secret stream semantics, dry-run writes, `resourceVersion`
//! stripping, `kubectl`-shaped reverts) out of the protocol-agnostic server
//! loop.

use serde_json::Value;

use super::gate::ApiRevert;
use super::k8s::{self, ApiOp, Verb};
use super::protocol::{CreatedIdentity, PlannedRevert, ProtocolConfig};
use crate::gating::Reversibility;

/// Stateless: all Kubernetes awareness is in the pure functions it delegates
/// to, so the protocol is a unit value.
#[derive(Debug, Clone, Copy, Default)]
pub struct KubernetesProtocol;

impl ProtocolConfig for KubernetesProtocol {
    fn name(&self) -> &str {
        "kubernetes"
    }

    fn parse_op(&self, method: &str, path: &str, query: &str) -> Option<ApiOp> {
        k8s::parse_api_op(method, path, query)
    }

    fn deny_outright(&self, op: &ApiOp) -> Option<String> {
        // Interactive subresources carry an opaque byte stream the request-level
        // gate cannot inspect, so they are denied outright in phase 1. `proxy`
        // is in the same class: it forwards an arbitrary HTTP request (any
        // method, any path) to the target Pod/Service/Node endpoint -- for a
        // Node that reaches the kubelet API, which itself exposes `exec`, `run`,
        // `portForward`, and `logs`. A get/list/watch ApiPolicy allow rule has
        // no visibility into the forwarded request, so it would silently approve
        // far more reach than it appears to. `ephemeralcontainers` is in the
        // same class: a PATCH/PUT adds a container to a running pod, which gives
        // the same in-container reach as `exec`. It is denied regardless of
        // policy, not left to a `pods` write rule that cannot see what it grants.
        if let Some(sub) = op.subresource.as_deref() {
            if matches!(
                sub,
                "exec" | "attach" | "portforward" | "proxy" | "ephemeralcontainers"
            ) {
                return Some(format!(
                    "guard kube-proxy: subresource '{sub}' is not permitted"
                ));
            }
        }

        // A Secret watch streams object events we cannot redact in phase 1, so it
        // would leak values: deny it regardless of policy.
        if op.is_secrets() && op.verb == Verb::Watch {
            return Some("guard kube-proxy: watching Secret values is not permitted".to_string());
        }

        None
    }

    fn redactable_read(&self, op: &ApiOp) -> bool {
        op.is_secrets() && op.is_read()
    }

    fn redact_response(&self, value: &mut Value) -> usize {
        k8s::redact_secret_response(value)
    }

    /// Only bare-resource recoverable writes are tracked: a subresource write is
    /// a different object shape than its parent, so a create-provenance record
    /// for it would let an eviction (`pods/{n}/eviction`) masquerade as a pod
    /// create and launder a later delete through the contained-delete path,
    /// and a `Restore` of a `scale`/`status` object does not round-trip
    /// through the daemon's `kubectl replace` revert.
    fn tracks_write(&self, op: &ApiOp) -> bool {
        !op.dry_run
            && op.subresource.is_none()
            && op.reversibility() == Some(Reversibility::Recoverable)
            && matches!(op.verb, Verb::Create | Verb::Update | Verb::Patch)
    }

    fn wants_prior_snapshot(&self, op: &ApiOp) -> bool {
        matches!(op.verb, Verb::Update | Verb::Patch) && op.name.is_some()
    }

    /// An update/patch with a usable prior state reverts by restoring it; a
    /// create (or a write whose prior state could not be captured) reverts by
    /// deleting the possibly server-named object from the response.
    fn plan_revert(
        &self,
        op: &ApiOp,
        prior_object: Option<&[u8]>,
        response: &[u8],
    ) -> Result<PlannedRevert, String> {
        if let Some(snap) = prior_object.and_then(sanitize_prior_object) {
            let name = op.name.clone().unwrap_or_default();
            return Ok(PlannedRevert {
                label: revert_label(op, &name),
                revert: ApiRevert::Restore { object_json: snap },
                created: None,
            });
        }

        let value: Value = serde_json::from_slice(response).map_err(|_| {
            "allowed write but response was unparsable; no auto-revert armed".to_string()
        })?;
        let Some(name) = value
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(|n| n.as_str())
        else {
            return Err(
                "allowed create but response carried no object name; no auto-revert armed"
                    .to_string(),
            );
        };
        let namespace = value
            .get("metadata")
            .and_then(|m| m.get("namespace"))
            .and_then(|n| n.as_str())
            .map(String::from)
            .or_else(|| op.namespace.clone());
        Ok(PlannedRevert {
            label: revert_label(op, name),
            revert: ApiRevert::DeleteCreated {
                group: op.group.clone(),
                resource: op.resource.clone(),
                name: name.to_string(),
                namespace: namespace.clone(),
            },
            created: Some(CreatedIdentity {
                group: op.group.clone(),
                resource: op.resource.clone(),
                namespace,
                name: name.to_string(),
            }),
        })
    }
}

/// Audit label for a tracked write, e.g. `patch deployments/api in dev`.
fn revert_label(op: &ApiOp, name: &str) -> String {
    let ns = op.namespace.as_deref().unwrap_or("(cluster)");
    format!("{} {}/{} in {}", op.verb.as_str(), op.resource, name, ns)
}

/// Strip `resourceVersion` and `managedFields` from a prior-object fetch so
/// the daemon's `kubectl replace` revert is unconditional. `None` if the body
/// is not parseable JSON (the caller then falls back to a
/// delete-the-created-object revert built from the write response).
fn sanitize_prior_object(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut value: Value = serde_json::from_slice(bytes).ok()?;
    if let Some(meta) = value.get_mut("metadata").and_then(|m| m.as_object_mut()) {
        meta.remove("resourceVersion");
        meta.remove("managedFields");
    }
    serde_json::to_vec(&value).ok()
}

#[cfg(test)]
mod tests {
    use super::super::k8s::parse_api_op;
    use super::*;

    fn op(method: &str, path: &str) -> ApiOp {
        parse_api_op(method, path, "").expect("should parse")
    }

    fn op_q(method: &str, path: &str, query: &str) -> ApiOp {
        parse_api_op(method, path, query).expect("should parse")
    }

    #[test]
    fn interactive_subresources_and_secret_watch_are_denied_outright() {
        let p = KubernetesProtocol;
        for sub in ["exec", "attach", "portforward", "proxy"] {
            let o = op("POST", &format!("/api/v1/namespaces/d/pods/web-0/{sub}"));
            let reason = p.deny_outright(&o).expect("denied");
            assert!(reason.contains(sub));
        }
        let ec = op(
            "PATCH",
            "/api/v1/namespaces/d/pods/web-0/ephemeralcontainers",
        );
        assert!(p.deny_outright(&ec).is_some());

        let watch = op_q("GET", "/api/v1/namespaces/d/secrets", "watch=true");
        assert!(p.deny_outright(&watch).is_some());

        // Ordinary reads and bare writes are left to policy.
        assert!(p
            .deny_outright(&op("GET", "/api/v1/namespaces/d/pods"))
            .is_none());
        assert!(p
            .deny_outright(&op_q(
                "GET",
                "/api/v1/namespaces/d/configmaps",
                "watch=true"
            ))
            .is_none());
    }

    #[test]
    fn only_secret_reads_are_redactable() {
        let p = KubernetesProtocol;
        assert!(p.redactable_read(&op("GET", "/api/v1/namespaces/d/secrets/s")));
        assert!(p.redactable_read(&op("GET", "/api/v1/namespaces/d/secrets")));
        assert!(!p.redactable_read(&op("GET", "/api/v1/namespaces/d/configmaps/c")));
        assert!(!p.redactable_read(&op("POST", "/api/v1/namespaces/d/secrets")));
    }

    #[test]
    fn tracked_writes_are_bare_recoverable_mutations() {
        let p = KubernetesProtocol;
        assert!(p.tracks_write(&op("POST", "/api/v1/namespaces/d/configmaps")));
        assert!(p.tracks_write(&op("PUT", "/api/v1/namespaces/d/configmaps/c")));
        assert!(p.tracks_write(&op("PATCH", "/api/v1/namespaces/d/configmaps/c")));
        // Reads, deletes, dry-runs, and subresource writes are not tracked.
        assert!(!p.tracks_write(&op("GET", "/api/v1/namespaces/d/configmaps/c")));
        assert!(!p.tracks_write(&op("DELETE", "/api/v1/namespaces/d/configmaps/c")));
        assert!(!p.tracks_write(&op_q(
            "POST",
            "/api/v1/namespaces/d/configmaps",
            "dryRun=All"
        )));
        assert!(!p.tracks_write(&op(
            "PATCH",
            "/apis/apps/v1/namespaces/d/deployments/api/scale"
        )));
    }

    #[test]
    fn prior_snapshot_only_for_named_update_or_patch() {
        let p = KubernetesProtocol;
        assert!(p.wants_prior_snapshot(&op("PUT", "/api/v1/namespaces/d/configmaps/c")));
        assert!(p.wants_prior_snapshot(&op("PATCH", "/api/v1/namespaces/d/configmaps/c")));
        assert!(!p.wants_prior_snapshot(&op("POST", "/api/v1/namespaces/d/configmaps")));
    }

    #[test]
    fn plan_revert_restores_sanitized_prior_object() {
        let p = KubernetesProtocol;
        let o = op("PATCH", "/api/v1/namespaces/dev/configmaps/app");
        let prior = serde_json::json!({
            "kind": "ConfigMap",
            "metadata": {"name": "app", "resourceVersion": "42", "managedFields": []},
            "data": {"k": "old"}
        })
        .to_string();
        let plan = p
            .plan_revert(&o, Some(prior.as_bytes()), b"{}")
            .expect("plan");
        assert_eq!(plan.label, "patch configmaps/app in dev");
        assert!(plan.created.is_none());
        let ApiRevert::Restore { object_json } = plan.revert else {
            panic!("expected a restore revert");
        };
        let v: Value = serde_json::from_slice(&object_json).unwrap();
        assert!(v["metadata"].get("resourceVersion").is_none());
        assert!(v["metadata"].get("managedFields").is_none());
        assert_eq!(v["data"]["k"], "old");
    }

    #[test]
    fn plan_revert_deletes_created_object_and_records_identity() {
        let p = KubernetesProtocol;
        let o = op("POST", "/api/v1/namespaces/dev/configmaps");
        // The apiserver may name the object (generateName); the response wins.
        let resp = serde_json::json!({
            "kind": "ConfigMap",
            "metadata": {"name": "app-x7k2", "namespace": "dev"}
        })
        .to_string();
        let plan = p.plan_revert(&o, None, resp.as_bytes()).expect("plan");
        assert_eq!(plan.label, "create configmaps/app-x7k2 in dev");
        let ApiRevert::DeleteCreated {
            group,
            resource,
            name,
            namespace,
        } = plan.revert
        else {
            panic!("expected a delete-created revert");
        };
        assert_eq!(group, "");
        assert_eq!(resource, "configmaps");
        assert_eq!(name, "app-x7k2");
        assert_eq!(namespace.as_deref(), Some("dev"));
        let created = plan.created.expect("created identity recorded");
        assert_eq!(created.name, "app-x7k2");
        assert_eq!(created.namespace.as_deref(), Some("dev"));
    }

    #[test]
    fn plan_revert_falls_back_to_delete_when_prior_is_unparsable() {
        // An unparsable prior fetch cannot back a restore; the revert degrades
        // to deleting the object named in the write response.
        let p = KubernetesProtocol;
        let o = op("PUT", "/api/v1/namespaces/dev/configmaps/app");
        let resp = serde_json::json!({"metadata": {"name": "app", "namespace": "dev"}}).to_string();
        let plan = p
            .plan_revert(&o, Some(b"not-json"), resp.as_bytes())
            .expect("plan");
        assert!(matches!(plan.revert, ApiRevert::DeleteCreated { .. }));
    }

    #[test]
    fn plan_revert_fails_without_a_usable_response() {
        let p = KubernetesProtocol;
        let o = op("POST", "/api/v1/namespaces/dev/configmaps");
        assert!(p.plan_revert(&o, None, b"not-json").is_err());
        assert!(p.plan_revert(&o, None, b"{\"metadata\":{}}").is_err());
    }
}
