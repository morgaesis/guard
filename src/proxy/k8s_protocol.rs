//! The Kubernetes [`ProtocolConfig`] — the reference protocol plug-in.
//! Delegates parsing and Secret redaction to the pure functions in
//! [`super::k8s`] and keeps every Kubernetes-specific judgment (interactive
//! subresources, Secret stream semantics, dry-run writes, Kubernetes metadata
//! stripping, and revert request shapes) out of the protocol-agnostic server
//! loop.

use serde_json::Value;

use super::gate::HttpRevert;
use super::k8s;
use super::op::{ApiOp, Verb};
use super::protocol::{CreatedIdentity, PlannedRevert, ProtocolConfig};

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
                    "guard api-proxy: kubernetes subresource '{sub}' is not permitted"
                ));
            }
        }

        // A Secret watch streams object events we cannot redact in phase 1, so it
        // would leak values: deny it regardless of policy.
        if op.is_secrets() && op.verb == Verb::Watch {
            return Some(
                "guard api-proxy: watching kubernetes Secret values is not permitted".to_string(),
            );
        }

        None
    }

    fn redactable_read(&self, op: &ApiOp) -> bool {
        op.is_secrets() && op.is_read()
    }

    fn redact_response(&self, value: &mut Value) -> usize {
        k8s::redact_secret_response(value)
    }

    fn error_body(&self, code: u16, message: &str, reason: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "kind": "Status",
            "apiVersion": "v1",
            "metadata": {},
            "status": "Failure",
            "message": message,
            "reason": reason,
            "code": code,
        }))
        .expect("Kubernetes Status JSON serialization is infallible")
    }

    /// Only bare-resource writes with faithful HTTP reverts are tracked: a subresource write is
    /// a different object shape than its parent, so a create-provenance record
    /// for it would let an eviction (`pods/{n}/eviction`) masquerade as a pod
    /// create and launder a later delete through the contained-delete path.
    fn tracks_write(&self, op: &ApiOp) -> bool {
        !op.dry_run
            && op.subresource.is_none()
            && matches!(
                op.verb,
                Verb::Create | Verb::Update | Verb::Patch | Verb::Delete
            )
    }

    fn wants_prior_snapshot(&self, op: &ApiOp) -> bool {
        matches!(op.verb, Verb::Update | Verb::Patch | Verb::Delete) && op.name.is_some()
    }

    /// An update/patch with a usable prior state reverts by PUT-restoring it, a
    /// delete reverts by POST-recreating the sanitized prior object, and a
    /// create reverts by deleting the possibly server-named object from the
    /// response.
    fn plan_revert(
        &self,
        op: &ApiOp,
        prior_object: Option<&[u8]>,
        response: &[u8],
    ) -> Result<PlannedRevert, String> {
        match op.verb {
            Verb::Update | Verb::Patch => {
                let snap = sanitize_prior_object(
                    prior_object.ok_or_else(|| {
                        "allowed restore-style write but prior snapshot fetch failed; no auto-revert armed"
                            .to_string()
                    })?,
                )?;
                let name = op.name.clone().unwrap_or_default();
                return Ok(PlannedRevert {
                    label: revert_label(op, &name),
                    revert: HttpRevert {
                        method: "PUT".to_string(),
                        path: build_object_path(op, &name),
                        body: Some(snap),
                    },
                    created: None,
                });
            }
            Verb::Delete => {
                let snap = sanitize_prior_object(prior_object.ok_or_else(|| {
                    "allowed delete but prior snapshot fetch failed; no auto-revert armed"
                        .to_string()
                })?)?;
                let name = op.name.clone().unwrap_or_default();
                return Ok(PlannedRevert {
                    label: revert_label(op, &name),
                    revert: HttpRevert {
                        method: "POST".to_string(),
                        path: build_collection_path(op),
                        body: Some(snap),
                    },
                    created: None,
                });
            }
            Verb::Create => {}
            _ => return Err("operation has no Kubernetes HTTP revert".to_string()),
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
            revert: HttpRevert {
                method: "DELETE".to_string(),
                path: build_object_path_with_namespace(op, namespace.as_deref(), name),
                // Background cascade matches the kubectl delete default, so a
                // reverted create cleans up dependents the same way an operator
                // delete would.
                body: Some(delete_options_background()),
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

/// A `DeleteOptions` body requesting background cascading deletion.
fn delete_options_background() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "kind": "DeleteOptions",
        "apiVersion": "v1",
        "propagationPolicy": "Background",
    }))
    .expect("serialize DeleteOptions")
}

/// Audit label for a tracked write, e.g. `patch deployments/api in dev`.
fn revert_label(op: &ApiOp, name: &str) -> String {
    let ns = op.namespace.as_deref().unwrap_or("(cluster)");
    format!("{} {}/{} in {}", op.verb.as_str(), op.resource, name, ns)
}

/// Build the Kubernetes API path for an object.
fn build_object_path(op: &ApiOp, name: &str) -> String {
    build_object_path_with_namespace(op, op.namespace.as_deref(), name)
}

fn build_object_path_with_namespace(op: &ApiOp, namespace: Option<&str>, name: &str) -> String {
    format!(
        "{}/{}",
        build_collection_path_with_namespace(op, namespace),
        name
    )
}

fn build_collection_path(op: &ApiOp) -> String {
    build_collection_path_with_namespace(op, op.namespace.as_deref())
}

fn build_collection_path_with_namespace(op: &ApiOp, namespace: Option<&str>) -> String {
    let mut path = if op.group.is_empty() {
        format!("/api/{}", op.version)
    } else {
        format!("/apis/{}/{}", op.group, op.version)
    };
    if let Some(ns) = namespace {
        path.push_str("/namespaces/");
        path.push_str(ns);
    }
    path.push('/');
    path.push_str(&op.resource);
    path
}

/// Strip server-owned metadata from a prior-object fetch so an HTTP restore can
/// be accepted as a fresh update/create. Returns an error if the body is not
/// parseable JSON.
fn sanitize_prior_object(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut value: Value = serde_json::from_slice(bytes)
        .map_err(|_| "prior snapshot was unparsable; no auto-revert armed".to_string())?;
    if let Some(meta) = value.get_mut("metadata").and_then(|m| m.as_object_mut()) {
        meta.remove("resourceVersion");
        meta.remove("uid");
        meta.remove("creationTimestamp");
        meta.remove("generation");
        meta.remove("selfLink");
        meta.remove("managedFields");
        // Recreated objects must not inherit owner references to deleted or
        // mismatched owners; stale references can make garbage collection remove
        // the restore immediately.
        meta.remove("ownerReferences");
    }
    if let Some(map) = value.as_object_mut() {
        map.remove("status");
    }
    serde_json::to_vec(&value).map_err(|_| "serialize sanitized snapshot".to_string())
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
    fn tracks_bare_writes_with_faithful_reverts() {
        let p = KubernetesProtocol;
        assert!(p.tracks_write(&op("POST", "/api/v1/namespaces/d/pods")));
        assert!(p.tracks_write(&op("PUT", "/api/v1/namespaces/d/pods/web")));
        assert!(p.tracks_write(&op("PATCH", "/api/v1/namespaces/d/configmaps/cfg")));
        assert!(p.tracks_write(&op("DELETE", "/api/v1/namespaces/d/pods/web")));

        // Subresource writes and dry-runs are not tracked
        let sub = op_q(
            "PATCH",
            "/api/v1/namespaces/d/pods/web/status",
            "dryRun=All",
        );
        assert!(!p.tracks_write(&sub));
    }

    #[test]
    fn snapshots_taken_for_restore_style_reverts_on_named_objects() {
        let p = KubernetesProtocol;
        assert!(p.wants_prior_snapshot(&op("PUT", "/api/v1/namespaces/d/pods/web")));
        assert!(p.wants_prior_snapshot(&op("PATCH", "/api/v1/namespaces/d/configmaps/cfg")));
        assert!(p.wants_prior_snapshot(&op("DELETE", "/api/v1/namespaces/d/pods/web")));
        assert!(!p.wants_prior_snapshot(&op("POST", "/api/v1/namespaces/d/pods")));
    }

    #[test]
    fn update_with_no_prior_snapshot_has_no_revert() {
        // A PUT/PATCH whose prior object could not be read (a create-shaped PUT,
        // or a transient GET failure) has no faithful revert: deleting the
        // object could destroy state that existed before the write. plan_revert
        // returns Err rather than synthesizing an unsafe delete, so the write
        // is judged as not-constructible and forwards only under an explicit
        // policy allow, never inside a bogus containment envelope.
        let p = KubernetesProtocol;
        let put = op("PUT", "/api/v1/namespaces/dev/configmaps/new");
        assert!(p
            .plan_revert(&put, None, b"{\"metadata\":{\"name\":\"new\"}}")
            .is_err());
        let patch = op("PATCH", "/apis/apps/v1/namespaces/dev/deployments/api");
        assert!(p.plan_revert(&patch, None, b"{}").is_err());
    }

    #[test]
    fn delete_restore_recreates_sanitized_prior_object_with_post() {
        let p = KubernetesProtocol;
        let o = op("DELETE", "/apis/apps/v1/namespaces/dev/deployments/api");
        let prior = serde_json::json!({
            "kind": "Deployment",
            "apiVersion": "apps/v1",
            "metadata": {
                "name": "api",
                "namespace": "dev",
                "resourceVersion": "42",
                "uid": "abc",
                "creationTimestamp": "2026-01-01T00:00:00Z",
                "generation": 9,
                "selfLink": "/old",
                "managedFields": [],
                "ownerReferences": [{"name": "gone"}]
            },
            "spec": {"replicas": 2},
            "status": {"readyReplicas": 2}
        })
        .to_string();
        let plan = p
            .plan_revert(&o, Some(prior.as_bytes()), b"{}")
            .expect("delete restore plan");
        assert_eq!(plan.label, "delete deployments/api in dev");
        assert_eq!(plan.revert.method, "POST");
        assert_eq!(plan.revert.path, "/apis/apps/v1/namespaces/dev/deployments");
        let body: Value = serde_json::from_slice(&plan.revert.body.unwrap()).unwrap();
        let meta = body["metadata"].as_object().unwrap();
        for stripped in [
            "resourceVersion",
            "uid",
            "creationTimestamp",
            "generation",
            "selfLink",
            "managedFields",
            "ownerReferences",
        ] {
            assert!(
                meta.get(stripped).is_none(),
                "{stripped} should be stripped"
            );
        }
        assert!(body.get("status").is_none());
        assert_eq!(body["spec"]["replicas"], 2);
    }

    #[test]
    fn restore_style_reverts_fail_without_snapshot() {
        let p = KubernetesProtocol;
        assert!(p
            .plan_revert(
                &op("PATCH", "/api/v1/namespaces/dev/configmaps/app"),
                None,
                br#"{"metadata":{"name":"app"}}"#
            )
            .is_err());
        assert!(p
            .plan_revert(
                &op("DELETE", "/api/v1/namespaces/dev/configmaps/app"),
                None,
                b"{}"
            )
            .is_err());
    }
}
