//! Parse a Kubernetes API request (method + path + query) into a typed
//! [`ApiOp`], classify its consequence, and redact Secret values from a response
//! body. Pure and deterministic — no I/O, no TLS — so the whole k8s-awareness of
//! the proxy is unit-tested here.

use crate::gating::Reversibility;
use serde_json::Value;

/// The API verb, derived from the HTTP method and whether the request targets a
/// named object, a collection, or a watch stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Get,
    List,
    Watch,
    Create,
    Update,
    Patch,
    Delete,
    DeleteCollection,
    /// A method the proxy does not model (e.g. an HTTP method the apiserver does
    /// not use for REST). Classified as uncertain so the gate holds.
    Unknown,
}

impl Verb {
    pub fn as_str(self) -> &'static str {
        match self {
            Verb::Get => "get",
            Verb::List => "list",
            Verb::Watch => "watch",
            Verb::Create => "create",
            Verb::Update => "update",
            Verb::Patch => "patch",
            Verb::Delete => "delete",
            Verb::DeleteCollection => "deletecollection",
            Verb::Unknown => "unknown",
        }
    }

    /// A read does not mutate cluster state.
    pub fn is_read(self) -> bool {
        matches!(self, Verb::Get | Verb::List | Verb::Watch)
    }

    /// Map the verb to a consequence class for the gate. Reads are reversible,
    /// writes recoverable, deletes irreversible; an unmodeled verb is uncertain
    /// (`None`) so the gate holds.
    pub fn reversibility(self) -> Option<Reversibility> {
        match self {
            Verb::Get | Verb::List | Verb::Watch => Some(Reversibility::Reversible),
            Verb::Create | Verb::Update | Verb::Patch => Some(Reversibility::Recoverable),
            Verb::Delete | Verb::DeleteCollection => Some(Reversibility::Irreversible),
            Verb::Unknown => None,
        }
    }
}

/// A parsed Kubernetes API operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiOp {
    pub verb: Verb,
    /// API group; empty string for the core (`/api`) group.
    pub group: String,
    pub version: String,
    /// Resource type, e.g. `pods`, `secrets`, `deployments`.
    pub resource: String,
    /// Subresource, e.g. `log`, `status`, `exec`, `scale`, `portforward`.
    pub subresource: Option<String>,
    /// Namespace for a namespaced request; `None` for cluster-scoped or
    /// all-namespaces collections.
    pub namespace: Option<String>,
    /// Object name for a named request; `None` for a collection.
    pub name: Option<String>,
    /// `?dryRun=` was set, so the apiserver will not persist the change.
    pub dry_run: bool,
}

impl ApiOp {
    pub fn is_read(&self) -> bool {
        self.verb.is_read()
    }

    pub fn reversibility(&self) -> Option<Reversibility> {
        // A dry-run write persists nothing, so it is effectively a read.
        if self.dry_run && !self.verb.is_read() {
            return Some(Reversibility::Reversible);
        }
        self.verb.reversibility()
    }

    /// Whether this op targets the `secrets` resource (core group), whose
    /// response values are redacted on reads.
    pub fn is_secrets(&self) -> bool {
        self.group.is_empty() && self.resource == "secrets"
    }

    /// `group/version` or just `version` for the core group, for display/policy.
    pub fn group_version(&self) -> String {
        if self.group.is_empty() {
            self.version.clone()
        } else {
            format!("{}/{}", self.group, self.version)
        }
    }
}

/// Parse a request line into an [`ApiOp`]. `path` is the URL path (no query),
/// `query` is the raw query string (without the leading `?`). Returns `None` for
/// non-resource paths (`/`, `/healthz`, `/version`, `/openapi/v2`, discovery
/// roots) that carry no object to gate.
pub fn parse_api_op(method: &str, path: &str, query: &str) -> Option<ApiOp> {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if segs.is_empty() {
        return None;
    }

    // Group/version prefix: `/api/{version}/…` (core) or `/apis/{group}/{version}/…`.
    let (group, version, rest): (String, String, &[&str]) = match segs[0] {
        "api" => {
            if segs.len() < 2 {
                return None; // /api discovery root
            }
            (String::new(), segs[1].to_string(), &segs[2..])
        }
        "apis" => {
            if segs.len() < 3 {
                return None; // /apis or /apis/{group} discovery root
            }
            (segs[1].to_string(), segs[2].to_string(), &segs[3..])
        }
        _ => return None, // /healthz, /version, /openapi, /metrics, …
    };

    if rest.is_empty() {
        return None; // group/version discovery root, no resource
    }

    // Resolve namespace, then the resource/name/subresource tail.
    let (namespace, tail): (Option<String>, &[&str]) = if rest[0] == "namespaces" {
        match rest.len() {
            // `…/namespaces` — the namespaces resource collection (cluster-scoped).
            1 => (None, rest),
            // `…/namespaces/{name}` — a single namespace object (cluster-scoped).
            2 => (None, rest),
            // `…/namespaces/{ns}/{resource}[/…]` — namespaced request.
            _ => (Some(rest[1].to_string()), &rest[2..]),
        }
    } else {
        (None, rest)
    };

    let resource = tail.first()?.to_string();
    let name = tail.get(1).map(|s| s.to_string());
    let subresource = tail.get(2).map(|s| s.to_string());

    let dry_run = query_has(query, "dryRun");
    let watching = query_flag(query, "watch");

    let verb = match method.to_ascii_uppercase().as_str() {
        "GET" | "HEAD" => {
            if watching {
                Verb::Watch
            } else if name.is_some() {
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
        group,
        version,
        resource,
        subresource,
        namespace,
        name,
        dry_run,
    })
}

/// True if `key` appears as a query parameter (any value).
fn query_has(query: &str, key: &str) -> bool {
    query
        .split('&')
        .any(|kv| kv == key || kv.split('=').next() == Some(key))
}

/// True if `key` is present and not falsey (`watch`, `watch=true`, `watch=1`).
fn query_flag(query: &str, key: &str) -> bool {
    for kv in query.split('&') {
        let mut it = kv.splitn(2, '=');
        if it.next() == Some(key) {
            return match it.next() {
                None | Some("") | Some("true") | Some("1") => true,
                Some("false") | Some("0") => false,
                Some(_) => true,
            };
        }
    }
    false
}

/// Redact secret material from a Secret or SecretList response body, in place.
/// Strips `data` and `stringData` from the object (or from every item of a
/// list), leaving metadata, type, and structure intact. Returns the number of
/// objects redacted. The caller decides to invoke this based on the request
/// resource, so it does not depend on the body's `kind`.
pub fn redact_secret_response(value: &mut Value) -> usize {
    if let Some(items) = value.get_mut("items").and_then(Value::as_array_mut) {
        let mut n = 0;
        for item in items.iter_mut() {
            if strip_secret_fields(item) {
                n += 1;
            }
        }
        n
    } else if strip_secret_fields(value) {
        1
    } else {
        0
    }
}

/// Remove `data` and `stringData` from a single object. Returns true if either
/// was present.
fn strip_secret_fields(obj: &mut Value) -> bool {
    let Some(map) = obj.as_object_mut() else {
        return false;
    };
    let had_data = map.remove("data").is_some();
    let had_string = map.remove("stringData").is_some();
    had_data || had_string
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(method: &str, path: &str) -> ApiOp {
        parse_api_op(method, path, "").expect("should parse")
    }

    #[test]
    fn core_namespaced_collection_is_list() {
        let o = op("GET", "/api/v1/namespaces/prod/pods");
        assert_eq!(o.verb, Verb::List);
        assert_eq!(o.group, "");
        assert_eq!(o.version, "v1");
        assert_eq!(o.resource, "pods");
        assert_eq!(o.namespace.as_deref(), Some("prod"));
        assert_eq!(o.name, None);
        assert!(o.is_read());
    }

    #[test]
    fn core_namespaced_named_is_get() {
        let o = op("GET", "/api/v1/namespaces/prod/pods/web-0");
        assert_eq!(o.verb, Verb::Get);
        assert_eq!(o.name.as_deref(), Some("web-0"));
        assert_eq!(o.subresource, None);
    }

    #[test]
    fn subresource_is_parsed() {
        let o = op("GET", "/api/v1/namespaces/prod/pods/web-0/log");
        assert_eq!(o.verb, Verb::Get);
        assert_eq!(o.name.as_deref(), Some("web-0"));
        assert_eq!(o.subresource.as_deref(), Some("log"));
    }

    #[test]
    fn named_group_deployment() {
        let o = op("GET", "/apis/apps/v1/namespaces/prod/deployments/api");
        assert_eq!(o.group, "apps");
        assert_eq!(o.version, "v1");
        assert_eq!(o.resource, "deployments");
        assert_eq!(o.namespace.as_deref(), Some("prod"));
        assert_eq!(o.name.as_deref(), Some("api"));
    }

    #[test]
    fn all_namespaces_list() {
        // No /namespaces/ segment: a cluster-wide list of a namespaced resource.
        let o = op("GET", "/api/v1/pods");
        assert_eq!(o.verb, Verb::List);
        assert_eq!(o.namespace, None);
        assert_eq!(o.resource, "pods");
    }

    #[test]
    fn cluster_scoped_node() {
        let o = op("GET", "/api/v1/nodes/node-1");
        assert_eq!(o.verb, Verb::Get);
        assert_eq!(o.namespace, None);
        assert_eq!(o.resource, "nodes");
        assert_eq!(o.name.as_deref(), Some("node-1"));
    }

    #[test]
    fn namespaces_collection_and_instance() {
        let coll = op("GET", "/api/v1/namespaces");
        assert_eq!(coll.resource, "namespaces");
        assert_eq!(coll.verb, Verb::List);
        assert_eq!(coll.namespace, None);
        assert_eq!(coll.name, None);

        let inst = op("GET", "/api/v1/namespaces/prod");
        assert_eq!(inst.resource, "namespaces");
        assert_eq!(inst.verb, Verb::Get);
        assert_eq!(inst.namespace, None);
        assert_eq!(inst.name.as_deref(), Some("prod"));

        let del = op("DELETE", "/api/v1/namespaces/prod");
        assert_eq!(del.verb, Verb::Delete);
        assert_eq!(del.name.as_deref(), Some("prod"));
    }

    #[test]
    fn verbs_by_method() {
        assert_eq!(op("POST", "/api/v1/namespaces/p/pods").verb, Verb::Create);
        assert_eq!(op("PUT", "/api/v1/namespaces/p/pods/x").verb, Verb::Update);
        assert_eq!(op("PATCH", "/api/v1/namespaces/p/pods/x").verb, Verb::Patch);
        assert_eq!(
            op("DELETE", "/api/v1/namespaces/p/pods/x").verb,
            Verb::Delete
        );
        assert_eq!(
            op("DELETE", "/api/v1/namespaces/p/pods").verb,
            Verb::DeleteCollection
        );
    }

    #[test]
    fn watch_query_is_watch_verb() {
        let o = parse_api_op("GET", "/api/v1/namespaces/p/pods", "watch=true").unwrap();
        assert_eq!(o.verb, Verb::Watch);
        assert!(o.is_read());
        let o2 = parse_api_op(
            "GET",
            "/api/v1/namespaces/p/pods",
            "watch=1&timeoutSeconds=9",
        )
        .unwrap();
        assert_eq!(o2.verb, Verb::Watch);
        let not = parse_api_op("GET", "/api/v1/namespaces/p/pods", "watch=false").unwrap();
        assert_eq!(not.verb, Verb::List);
    }

    #[test]
    fn dry_run_write_is_reversible() {
        let o = parse_api_op("POST", "/api/v1/namespaces/p/pods", "dryRun=All").unwrap();
        assert_eq!(o.verb, Verb::Create);
        assert!(o.dry_run);
        assert_eq!(o.reversibility(), Some(Reversibility::Reversible));
        // A non-dry-run create is recoverable.
        let live = op("POST", "/api/v1/namespaces/p/pods");
        assert_eq!(live.reversibility(), Some(Reversibility::Recoverable));
    }

    #[test]
    fn reversibility_classes() {
        assert_eq!(
            op("GET", "/api/v1/nodes").reversibility(),
            Some(Reversibility::Reversible)
        );
        assert_eq!(
            op("PATCH", "/apis/apps/v1/namespaces/p/deployments/d").reversibility(),
            Some(Reversibility::Recoverable)
        );
        assert_eq!(
            op("DELETE", "/api/v1/namespaces/p/pods/x").reversibility(),
            Some(Reversibility::Irreversible)
        );
    }

    #[test]
    fn non_resource_paths_are_none() {
        for p in [
            "/",
            "/healthz",
            "/version",
            "/openapi/v2",
            "/api",
            "/apis",
            "/apis/apps/v1",
            "/metrics",
        ] {
            assert!(parse_api_op("GET", p, "").is_none(), "{p} should not parse");
        }
    }

    #[test]
    fn secrets_detection() {
        assert!(op("GET", "/api/v1/namespaces/p/secrets/s").is_secrets());
        assert!(!op("GET", "/api/v1/namespaces/p/configmaps/c").is_secrets());
    }

    #[test]
    fn redact_single_secret() {
        let mut v: Value = serde_json::json!({
            "kind": "Secret",
            "metadata": {"name": "db", "namespace": "prod"},
            "type": "Opaque",
            "data": {"password": "c2VjcmV0"},
            "stringData": {"note": "plain"}
        });
        let n = redact_secret_response(&mut v);
        assert_eq!(n, 1);
        assert!(v.get("data").is_none());
        assert!(v.get("stringData").is_none());
        // Metadata and type survive.
        assert_eq!(v["metadata"]["name"], "db");
        assert_eq!(v["type"], "Opaque");
    }

    #[test]
    fn redact_secret_list() {
        let mut v: Value = serde_json::json!({
            "kind": "SecretList",
            "items": [
                {"metadata": {"name": "a"}, "data": {"k": "dg=="}},
                {"metadata": {"name": "b"}, "data": {"k": "dg=="}},
                {"metadata": {"name": "c"}}
            ]
        });
        let n = redact_secret_response(&mut v);
        assert_eq!(n, 2, "two of three items carried data");
        for item in v["items"].as_array().unwrap() {
            assert!(item.get("data").is_none());
            assert!(item["metadata"]["name"].is_string());
        }
    }
}
