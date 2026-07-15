//! Example Vercel REST [`ProtocolConfig`]: a third protocol shape through the
//! shared proxy loop. Illustrative, not a production integration: everything
//! under a `/v{n}/` version prefix parses into the shared [`ApiOp`] (so an
//! unmodeled write falls to policy default-deny rather than slipping past as a
//! non-resource path), project environment variables are value-bearing on read
//! and therefore redacted, deployment log streams are denied outright, and
//! env-var deletes can be restored from a pre-delete snapshot.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use super::gate::HttpRevert;
use super::op::{ApiOp, Verb};
use super::protocol::{PlannedRevert, ProtocolConfig};

/// Stateless, like the Kubernetes reference implementation.
#[derive(Debug, Clone, Copy, Default)]
pub struct VercelProtocol;

/// `v1`, `v9`, `v13`, … - every Vercel REST route is version-prefixed.
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
    /// `teamId` selects the tenant whose authority is exercised and therefore
    /// participates in typed coverage. Presentation-only parameters such as
    /// `follow`, pagination, and output formatting do not.
    fn parse_op(&self, method: &str, path: &str, query: &str) -> Option<ApiOp> {
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
            authority_selectors: vercel_authority_selectors(query),
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

    fn tracks_write(&self, op: &ApiOp) -> bool {
        op.verb == Verb::Delete
            && op.resource == "env"
            && op.subresource.is_none()
            && op.namespace.is_some()
            && op.name.is_some()
    }

    fn wants_prior_snapshot(&self, op: &ApiOp) -> bool {
        self.tracks_write(op)
    }

    fn plan_revert(
        &self,
        op: &ApiOp,
        prior_object: Option<&[u8]>,
        _response: &[u8],
    ) -> Result<PlannedRevert, String> {
        if !self.tracks_write(op) {
            return Err("vercel: no faithful API revert for this operation".to_string());
        }
        let body = prior_object
            .and_then(sanitize_env_snapshot)
            .ok_or_else(|| {
                "vercel: env-var delete snapshot could not be fetched or parsed; no auto-revert armed"
                    .to_string()
            })?;
        let project = op.namespace.as_deref().ok_or_else(|| {
            "vercel: env-var delete has no project namespace; no auto-revert armed".to_string()
        })?;
        let name = op.name.as_deref().ok_or_else(|| {
            "vercel: env-var delete has no env id; no auto-revert armed".to_string()
        })?;
        Ok(PlannedRevert {
            label: format!("delete env/{name} in {project}"),
            revert: HttpRevert {
                method: "POST".to_string(),
                path: format!("/{}/projects/{project}/env", op.version),
                body: Some(body),
            },
            created: None,
        })
    }
}

fn vercel_authority_selectors(query: &str) -> BTreeMap<String, String> {
    let values = query
        .split('&')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            key.eq_ignore_ascii_case("teamId")
                .then(|| canonical_selector_value(value))
        })
        .collect::<Vec<_>>();
    if values.is_empty() {
        return BTreeMap::new();
    }
    let mut selectors = BTreeMap::new();
    selectors.insert("teamId".to_string(), values.join(","));
    selectors
}

fn canonical_selector_value(raw: &str) -> String {
    let decoded = percent_decode(raw).unwrap_or_else(|| raw.as_bytes().to_vec());
    if !decoded.is_empty()
        && decoded.len() <= 128
        && decoded
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
    {
        return String::from_utf8(decoded).expect("validated selector is ASCII");
    }
    let digest = Sha256::digest(&decoded);
    format!(
        "sha256:{}",
        digest[..16]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn percent_decode(value: &str) -> Option<Vec<u8>> {
    fn hex(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                output.push(hex(bytes[index + 1])? * 16 + hex(bytes[index + 2])?);
                index += 3;
            }
            b'%' => return None,
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    Some(output)
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

fn sanitize_env_snapshot(bytes: &[u8]) -> Option<Vec<u8>> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    let map = value.as_object()?;
    let mut out = serde_json::Map::new();
    for field in ["key", "value", "target", "type", "gitBranch", "comment"] {
        if let Some(v) = map.get(field) {
            out.insert(field.to_string(), v.clone());
        }
    }
    if !out.contains_key("key") || !out.contains_key("value") {
        return None;
    }
    serde_json::to_vec(&Value::Object(out)).ok()
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
    fn tenant_selector_is_canonical_and_presentation_query_is_excluded() {
        let first = VercelProtocol
            .parse_op(
                "GET",
                "/v9/projects/prj_123",
                "teamId=team_a&follow=true&page=2",
            )
            .unwrap();
        let same = VercelProtocol
            .parse_op("GET", "/v9/projects/prj_123", "teamid=team_a&follow=false")
            .unwrap();
        let other = VercelProtocol
            .parse_op("GET", "/v9/projects/prj_123", "teamId=team_b")
            .unwrap();
        assert_eq!(first.authority_selectors, same.authority_selectors);
        assert_ne!(first.authority_selectors, other.authority_selectors);
        assert_eq!(
            first.authority_selectors.get("teamId"),
            Some(&"team_a".to_string())
        );
        assert_eq!(first.authority_selectors.len(), 1);
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
    fn only_env_deletes_are_tracked_and_recreated() {
        let p = VercelProtocol;
        let project = op("PATCH", "/v9/projects/prj_123");
        assert!(!p.tracks_write(&project));
        assert!(!p.wants_prior_snapshot(&project));
        assert!(p.plan_revert(&project, None, b"{}").is_err());

        let env = op("DELETE", "/v9/projects/prj_123/env/env_abc");
        assert!(p.tracks_write(&env));
        assert!(p.wants_prior_snapshot(&env));
        let snapshot = serde_json::json!({
            "id": "env_abc",
            "key": "DATABASE_URL",
            "value": "postgres://example",
            "target": ["production"],
            "type": "encrypted",
            "createdAt": 123
        })
        .to_string();
        let plan = p
            .plan_revert(&env, Some(snapshot.as_bytes()), b"{}")
            .expect("env restore plan");
        assert_eq!(plan.label, "delete env/env_abc in prj_123");
        assert_eq!(plan.revert.method, "POST");
        assert_eq!(plan.revert.path, "/v9/projects/prj_123/env");
        let body: Value = serde_json::from_slice(&plan.revert.body.unwrap()).unwrap();
        assert_eq!(body["key"], "DATABASE_URL");
        assert_eq!(body["value"], "postgres://example");
        assert_eq!(body["target"][0], "production");
        assert!(body.get("id").is_none());
        assert!(body.get("createdAt").is_none());
    }
}
