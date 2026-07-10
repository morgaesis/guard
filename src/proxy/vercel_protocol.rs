//! Example Vercel REST [`ProtocolConfig`]: a third protocol shape through the
//! shared proxy loop. Illustrative, not a production integration: everything
//! under a `/v{n}/` version prefix parses into the shared [`ApiOp`] (so an
//! unmodeled write falls to policy default-deny rather than slipping past as a
//! non-resource path), project environment variables are value-bearing on read
//! and therefore redacted, deployment log streams are denied outright, and no
//! revert is constructible (see [`ProtocolConfig::plan_revert`] below).

use serde_json::Value;

use super::op::{ApiOp, Verb};
use super::protocol::{PlannedRevert, ProtocolConfig};

/// Stateless, like the Kubernetes reference implementation.
#[derive(Debug, Clone, Copy, Default)]
pub struct VercelProtocol;

/// `v1`, `v9`, `v13`, … — every Vercel REST route is version-prefixed.
fn is_api_version(seg: &str) -> bool {
    let mut chars = seg.chars();
    matches!(chars.next(), Some('v') | Some('V'))
        && chars.as_str().chars().all(|c| c.is_ascii_digit())
        && seg.len() > 1
}

impl ProtocolConfig for VercelProtocol {
    fn name(&self) -> &str {
        "vercel"
    }

    /// The version prefix and resource tokens match case-insensitively and the
    /// resource is lowercased in the op, so case variation cannot dodge a
    /// policy rule; project and object identifiers keep their case. Vercel's
    /// query parameters (`teamId`, `follow`, …) never change what a request
    /// is, so the query is ignored for classification.
    fn parse_op(&self, method: &str, path: &str, _query: &str) -> Option<ApiOp> {
        let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segs.len() < 2 || !is_api_version(segs[0]) {
            return None; // /login, /.well-known, and anything un-versioned
        }
        let version = segs[0].to_ascii_lowercase();
        let rest = &segs[1..];
        let head = rest[0].to_ascii_lowercase();

        // Project-nested collections: /v{n}/projects/{project}/{resource}[/…].
        // The project is the namespace, so one policy rule scopes env-var or
        // domain access per project the way a Kubernetes rule scopes per
        // namespace.
        let (namespace, resource, name, subresource) = if head == "projects" && rest.len() >= 3 {
            (
                Some(rest[1].to_string()),
                rest[2].to_ascii_lowercase(),
                rest.get(3).map(|s| s.to_string()),
                join_tail(rest, 4),
            )
        } else {
            // Top-level collections: /v{n}/{resource}[/{id}][/{deeper…}].
            // Deeper segments become one subresource string, so a write there
            // is authorized only by a policy rule naming it (fail-safe).
            (
                None,
                head,
                rest.get(1).map(|s| s.to_string()),
                join_tail(rest, 2),
            )
        };

        let verb = match method.to_ascii_uppercase().as_str() {
            "GET" | "HEAD" => {
                if name.is_some() {
                    Verb::Get
                } else {
                    Verb::List
                }
            }
            "POST" => Verb::Create,
            "PUT" => Verb::Update,
            "PATCH" => Verb::Patch,
            "DELETE" => {
                if name.is_some() {
                    Verb::Delete
                } else {
                    Verb::DeleteCollection
                }
            }
            _ => Verb::Unknown,
        };

        Some(ApiOp {
            verb,
            group: "vercel".to_string(),
            version,
            resource,
            subresource,
            namespace,
            name,
            dry_run: false,
        })
    }

    fn deny_outright(&self, op: &ApiOp) -> Option<String> {
        // Deployment build/runtime log streams echo whatever the build printed
        // -- routinely including env values -- and arrive as a line stream
        // (`?follow` long-polls it) that cannot be redacted per object: the
        // Vercel analogue of a Secret watch, denied regardless of policy.
        if op.resource == "deployments"
            && op
                .subresource
                .as_deref()
                .and_then(|s| s.split('/').next())
                .is_some_and(|first| first == "events" || first == "logs")
        {
            return Some(
                "guard vercel-proxy: deployment log/event streams are not permitted".to_string(),
            );
        }
        None
    }

    /// Env-var reads return plaintext values for plain and decrypted
    /// variables, so they are the redaction target; env writes and project
    /// deletes stay policy-gated (the operator can still hold or allow them,
    /// as with Kubernetes Secret writes).
    fn redactable_read(&self, op: &ApiOp) -> bool {
        op.is_read() && op.resource == "env"
    }

    fn redact_response(&self, value: &mut Value) -> usize {
        if let Some(items) = value.get_mut("envs").and_then(Value::as_array_mut) {
            let mut n = 0;
            for item in items.iter_mut() {
                if strip_env_value(item) {
                    n += 1;
                }
            }
            n
        } else if strip_env_value(value) {
            1
        } else {
            0
        }
    }

    /// No Vercel write is tracked: `ApiRevert` reverts execute as `kubectl`
    /// commands in the daemon sink, so no revert is constructible for this
    /// protocol. Revert synthesis for non-Kubernetes protocols is what a
    /// daemon-side protocol-generic revert runner unlocks.
    fn tracks_write(&self, _op: &ApiOp) -> bool {
        false
    }

    fn wants_prior_snapshot(&self, _op: &ApiOp) -> bool {
        false
    }

    fn plan_revert(
        &self,
        _op: &ApiOp,
        _prior_object: Option<&[u8]>,
        _response: &[u8],
    ) -> Result<PlannedRevert, String> {
        Err("vercel: no constructible revert for this protocol yet (ApiRevert reverts execute as kubectl commands in the daemon sink)".to_string())
    }
}

/// Join `rest[from..]` into one subresource string, `None` when empty.
fn join_tail(rest: &[&str], from: usize) -> Option<String> {
    if rest.len() > from {
        Some(rest[from..].join("/"))
    } else {
        None
    }
}

/// Remove the value from a single env-var object, keeping `key`, ids, and
/// targets so listings still identify what exists.
fn strip_env_value(obj: &mut Value) -> bool {
    let Some(map) = obj.as_object_mut() else {
        return false;
    };
    map.remove("value").is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(method: &str, path: &str) -> ApiOp {
        VercelProtocol
            .parse_op(method, path, "")
            .expect("should parse")
    }

    #[test]
    fn versioned_collections_parse() {
        let o = op("GET", "/v9/projects/prj_123");
        assert_eq!(o.verb, Verb::Get);
        assert_eq!(o.group, "vercel");
        assert_eq!(o.version, "v9");
        assert_eq!(o.resource, "projects");
        assert_eq!(o.name.as_deref(), Some("prj_123"));
        assert_eq!(o.namespace, None);

        let env = op("GET", "/v9/projects/prj_123/env");
        assert_eq!(env.verb, Verb::List);
        assert_eq!(env.resource, "env");
        assert_eq!(env.namespace.as_deref(), Some("prj_123"));

        let one = op("GET", "/v9/projects/prj_123/env/abc123");
        assert_eq!(one.verb, Verb::Get);
        assert_eq!(one.name.as_deref(), Some("abc123"));

        let del = op("DELETE", "/v9/projects/prj_123");
        assert_eq!(del.verb, Verb::Delete);
    }

    #[test]
    fn case_varied_routes_still_classify() {
        let o = op("GET", "/V9/PROJECTS/prj_123/ENV");
        assert_eq!(o.version, "v9");
        assert_eq!(o.resource, "env");
        assert_eq!(o.namespace.as_deref(), Some("prj_123"));
    }

    #[test]
    fn unversioned_paths_are_none() {
        for p in ["/", "/login", "/api/user", "/version", "/vx/projects"] {
            assert!(
                VercelProtocol.parse_op("GET", p, "").is_none(),
                "{p} should not parse"
            );
        }
    }

    #[test]
    fn deployment_streams_deny_outright() {
        let p = VercelProtocol;
        assert!(p
            .deny_outright(&op("GET", "/v6/deployments/dpl_1/events"))
            .is_some());
        assert!(p
            .deny_outright(&op("GET", "/v2/deployments/dpl_1/logs/build"))
            .is_some());
        // The deployment object itself and env reads are left to policy.
        assert!(p
            .deny_outright(&op("GET", "/v6/deployments/dpl_1"))
            .is_none());
        assert!(p
            .deny_outright(&op("GET", "/v9/projects/prj/env"))
            .is_none());
    }

    #[test]
    fn env_reads_redact_values() {
        let p = VercelProtocol;
        assert!(p.redactable_read(&op("GET", "/v9/projects/prj/env")));
        assert!(!p.redactable_read(&op("POST", "/v9/projects/prj/env")));
        assert!(!p.redactable_read(&op("GET", "/v9/projects/prj/domains")));

        let mut list = serde_json::json!({
            "envs": [
                {"key": "DATABASE_URL", "value": "postgres://leak", "target": ["production"]},
                {"key": "PUBLIC_FLAG", "value": "on"}
            ]
        });
        assert_eq!(p.redact_response(&mut list), 2);
        assert_eq!(list["envs"][0]["key"], "DATABASE_URL");
        assert!(list["envs"][0].get("value").is_none());
        assert_eq!(list["envs"][0]["target"][0], "production");

        let mut one = serde_json::json!({"key": "K", "value": "v", "id": "abc"});
        assert_eq!(p.redact_response(&mut one), 1);
        assert!(one.get("value").is_none());
        assert_eq!(one["id"], "abc");
    }

    #[test]
    fn no_write_is_tracked_and_no_revert_is_constructible() {
        let p = VercelProtocol;
        let o = op("PATCH", "/v9/projects/prj_123");
        assert!(!p.tracks_write(&o));
        assert!(!p.wants_prior_snapshot(&o));
        assert!(p.plan_revert(&o, None, b"{}").is_err());
    }
}
