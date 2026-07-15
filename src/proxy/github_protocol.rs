//! Example GitHub REST v3 [`ProtocolConfig`]: a second protocol shape through
//! the shared proxy loop, proving the plug-in surface generalizes past
//! Kubernetes. Illustrative, not a production integration: repository- and
//! organization-scoped collections parse into the shared [`ApiOp`], credential
//! stores are write-denied outright, secrets-like reads are redacted, and label
//! deletes can be restored from a pre-delete snapshot.

use serde_json::Value;

use super::gate::HttpRevert;
use super::op::{ApiOp, Verb};
use super::protocol::{PlannedRevert, ProtocolConfig};

/// Stateless, like the Kubernetes reference implementation.
#[derive(Debug, Clone, Copy, Default)]
pub struct GithubProtocol;

/// Tool prefixes whose `secrets` collection is a credential store, at both
/// repository and organization scope (`/repos/{o}/{r}/actions/secrets/…`,
/// `/orgs/{org}/actions/secrets/…`). All map to resource `secrets`.
fn is_secret_store_prefix(seg: &str) -> bool {
    seg.eq_ignore_ascii_case("actions")
        || seg.eq_ignore_ascii_case("dependabot")
        || seg.eq_ignore_ascii_case("codespaces")
}

impl ProtocolConfig for GithubProtocol {
    fn name(&self) -> &str {
        "github"
    }

    /// Route literals are matched case-insensitively and the resource is
    /// lowercased in the op, so a case-varied path (`/REPOS/o/r/ISSUES`)
    /// cannot dodge a policy rule while still routing upstream; owner, repo,
    /// and object names keep their case. GitHub has no verb-changing query
    /// parameters, so the query is ignored for classification.
    fn parse_op(&self, method: &str, path: &str, _query: &str) -> Option<ApiOp> {
        let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segs.is_empty() {
            return None;
        }

        // Scope prefix: /repos/{owner}/{repo}/…, /orgs/{org}/…, /user[s]/….
        let head = segs[0].to_ascii_lowercase();
        let (namespace, scope_name, tail): (Option<String>, Option<String>, &[&str]) =
            match head.as_str() {
                "repos" if segs.len() >= 3 => {
                    let ns = format!("{}/{}", segs[1], segs[2]);
                    (Some(ns.clone()), Some(ns), &segs[3..])
                }
                "orgs" if segs.len() >= 2 => (
                    Some(segs[1].to_string()),
                    Some(segs[1].to_string()),
                    &segs[2..],
                ),
                // /users/{username}[/…]: another account's public surface.
                "users" if segs.len() >= 2 => (None, Some(segs[1].to_string()), &segs[1..]),
                // /user[/…]: the authenticated account object.
                "user" => (None, None, &segs[1..]),
                _ => return None, // /rate_limit, /meta, /search, /gists, …
            };

        let (resource, name, subresource): (String, Option<String>, Option<String>) =
            if head == "user" {
                // The account object; anything deeper (`/user/repos`) is a
                // read-shaped subresource of it.
                ("user".to_string(), None, join_tail(tail, 0))
            } else if head == "users" {
                ("users".to_string(), scope_name, join_tail(tail, 1))
            } else if tail.is_empty() {
                // The scope object itself: /repos/{owner}/{repo} or /orgs/{org}.
                (head.clone(), scope_name, None)
            } else if tail.len() >= 2
                && is_secret_store_prefix(tail[0])
                && tail[1].eq_ignore_ascii_case("secrets")
            {
                // Credential stores: actions/dependabot/codespaces secrets all
                // collapse to resource `secrets` so one policy rule (and the
                // outright write denial) covers every store.
                (
                    "secrets".to_string(),
                    tail.get(2).map(|s| s.to_string()),
                    join_tail(tail, 3),
                )
            } else if tail[0].eq_ignore_ascii_case("contents") {
                // /contents/{path…}: the file path is one object name of
                // arbitrary depth, so a write to a nested file is a bare
                // `contents` write, not an unreviewable subresource chain.
                (
                    "contents".to_string(),
                    if tail.len() > 1 {
                        Some(tail[1..].join("/"))
                    } else {
                        None
                    },
                    None,
                )
            } else {
                // Generic collection: /…/{resource}[/{id}][/{deeper…}]. Deeper
                // segments become one subresource string, so a write there is
                // authorized only by a policy rule naming it (fail-safe).
                (
                    tail[0].to_ascii_lowercase(),
                    tail.get(1).map(|s| s.to_string()),
                    join_tail(tail, 2),
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
            group: "github".to_string(),
            version: "v3".to_string(),
            resource,
            subresource,
            namespace,
            name,
            dry_run: false,
            authority_selectors: Default::default(),
        })
    }

    fn deny_outright(&self, op: &ApiOp) -> Option<String> {
        // A credential-store write mints or overwrites a secret the proxy can
        // never read back (the API stores values write-only), so there is no
        // snapshot, no revert, and no later audit of what was planted: denied
        // regardless of policy. The subresource check covers the same write
        // re-entered through a nested route (environment secrets,
        // `/repos/{o}/{r}/environments/{env}/secrets/{name}`), which would
        // otherwise present itself to policy as an `environments` write.
        if !op.is_read() {
            let in_secrets_store = op.resource == "secrets"
                || op
                    .subresource
                    .as_deref()
                    .is_some_and(|s| s.split('/').any(|seg| seg.eq_ignore_ascii_case("secrets")));
            if in_secrets_store {
                return Some(
                    "guard github-proxy: writing to a secrets store is not permitted".to_string(),
                );
            }
        }

        // Repository archives are a bulk source-exfiltration stream (a binary
        // tarball the response gate cannot inspect or redact per object), the
        // GitHub analogue of a Secret watch: denied regardless of policy.
        if op.resource == "tarball" || op.resource == "zipball" {
            return Some(
                "guard github-proxy: repository archive downloads are not permitted".to_string(),
            );
        }

        None
    }

    fn redactable_read(&self, op: &ApiOp) -> bool {
        op.is_read() && op.resource == "secrets"
    }

    /// Strip value-bearing fields from a secrets response, keeping names and
    /// metadata so inventory listings still work. The API itself returns no
    /// plaintext values, but the proxy does not trust the upstream shape:
    /// whatever value-like field appears is removed.
    fn redact_response(&self, value: &mut Value) -> usize {
        if let Some(items) = value.get_mut("secrets").and_then(Value::as_array_mut) {
            let mut n = 0;
            for item in items.iter_mut() {
                if strip_value_fields(item) {
                    n += 1;
                }
            }
            n
        } else if strip_value_fields(value) {
            1
        } else {
            0
        }
    }

    fn tracks_write(&self, op: &ApiOp) -> bool {
        op.verb == Verb::Delete
            && op.resource == "labels"
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
            return Err("github: no faithful API revert for this operation".to_string());
        }
        let body = prior_object
            .and_then(sanitize_label_snapshot)
            .ok_or_else(|| {
                "github: label delete snapshot could not be fetched or parsed; no auto-revert armed"
                    .to_string()
            })?;
        let namespace = op.namespace.as_deref().ok_or_else(|| {
            "github: label delete has no repository namespace; no auto-revert armed".to_string()
        })?;
        let name = op.name.as_deref().ok_or_else(|| {
            "github: label delete has no label name; no auto-revert armed".to_string()
        })?;
        Ok(PlannedRevert {
            label: format!("delete labels/{name} in {namespace}"),
            revert: HttpRevert {
                method: "POST".to_string(),
                path: format!("/repos/{namespace}/labels"),
                body: Some(body),
            },
            created: None,
        })
    }
}

/// Join `tail[from..]` into one subresource string, `None` when empty.
fn join_tail(tail: &[&str], from: usize) -> Option<String> {
    if tail.len() > from {
        Some(tail[from..].join("/"))
    } else {
        None
    }
}

/// Remove value-bearing fields from a single object. `key` is included because
/// the secrets public-key endpoint returns the encryption key material under
/// it; `key_id` and names survive.
fn strip_value_fields(obj: &mut Value) -> bool {
    let Some(map) = obj.as_object_mut() else {
        return false;
    };
    // Every field is removed; no short-circuit on the first hit.
    let mut hit = false;
    for f in ["value", "encrypted_value", "plaintext_value", "key"] {
        hit |= map.remove(f).is_some();
    }
    hit
}

fn sanitize_label_snapshot(bytes: &[u8]) -> Option<Vec<u8>> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    let name = value.get("name")?.clone();
    let color = value.get("color")?.clone();
    let mut out = serde_json::Map::new();
    out.insert("name".to_string(), name);
    out.insert("color".to_string(), color);
    if let Some(description) = value.get("description") {
        out.insert("description".to_string(), description.clone());
    }
    serde_json::to_vec(&Value::Object(out)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(method: &str, path: &str) -> ApiOp {
        GithubProtocol
            .parse_op(method, path, "")
            .expect("should parse")
    }

    #[test]
    fn repo_scoped_collections_parse() {
        let o = op("GET", "/repos/octo/hello/issues/42");
        assert_eq!(o.verb, Verb::Get);
        assert_eq!(o.group, "github");
        assert_eq!(o.resource, "issues");
        assert_eq!(o.namespace.as_deref(), Some("octo/hello"));
        assert_eq!(o.name.as_deref(), Some("42"));

        let list = op("GET", "/repos/octo/hello/pulls");
        assert_eq!(list.verb, Verb::List);
        assert_eq!(list.name, None);

        let repo = op("DELETE", "/repos/octo/hello");
        assert_eq!(repo.verb, Verb::Delete);
        assert_eq!(repo.resource, "repos");
        assert_eq!(repo.name.as_deref(), Some("octo/hello"));
    }

    #[test]
    fn secret_stores_collapse_to_secrets_resource() {
        for prefix in ["actions", "dependabot", "codespaces"] {
            let o = op("GET", &format!("/repos/o/r/{prefix}/secrets/DEPLOY"));
            assert_eq!(o.resource, "secrets", "{prefix} store maps to secrets");
            assert_eq!(o.name.as_deref(), Some("DEPLOY"));
        }
        let org = op("PUT", "/orgs/acme/actions/secrets/TOKEN");
        assert_eq!(org.resource, "secrets");
        assert_eq!(org.namespace.as_deref(), Some("acme"));
    }

    #[test]
    fn contents_path_is_one_object_name() {
        let o = op("PUT", "/repos/o/r/contents/docs/sub/file.md");
        assert_eq!(o.verb, Verb::Update);
        assert_eq!(o.resource, "contents");
        assert_eq!(o.name.as_deref(), Some("docs/sub/file.md"));
        assert_eq!(o.subresource, None);
    }

    #[test]
    fn case_varied_routes_still_classify() {
        let o = op("GET", "/REPOS/octo/hello/ISSUES/42");
        assert_eq!(o.resource, "issues");
        assert_eq!(o.namespace.as_deref(), Some("octo/hello"));
        let s = op("PUT", "/repos/o/r/ACTIONS/SECRETS/X");
        assert_eq!(s.resource, "secrets");
    }

    #[test]
    fn unmodeled_roots_are_none() {
        for p in ["/", "/rate_limit", "/meta", "/search/code", "/gists/abc"] {
            assert!(
                GithubProtocol.parse_op("GET", p, "").is_none(),
                "{p} should not parse"
            );
        }
    }

    #[test]
    fn secrets_writes_and_archives_deny_outright() {
        let p = GithubProtocol;
        assert!(p
            .deny_outright(&op("PUT", "/repos/o/r/actions/secrets/DEPLOY"))
            .is_some());
        assert!(p
            .deny_outright(&op("DELETE", "/orgs/acme/dependabot/secrets/T"))
            .is_some());
        // Disguised through a nested route: an `environments` write whose
        // deeper path re-enters a secrets collection.
        assert!(p
            .deny_outright(&op("PUT", "/repos/o/r/environments/prod/secrets/T"))
            .is_some());
        assert!(p
            .deny_outright(&op("GET", "/repos/o/r/tarball/main"))
            .is_some());
        assert!(p
            .deny_outright(&op("GET", "/repos/o/r/zipball/main"))
            .is_some());
        // Reads of secrets metadata and ordinary writes are left to policy.
        assert!(p
            .deny_outright(&op("GET", "/repos/o/r/actions/secrets"))
            .is_none());
        assert!(p.deny_outright(&op("POST", "/repos/o/r/issues")).is_none());
    }

    #[test]
    fn secrets_reads_redact_value_fields() {
        let p = GithubProtocol;
        assert!(p.redactable_read(&op("GET", "/repos/o/r/actions/secrets")));
        assert!(!p.redactable_read(&op("GET", "/repos/o/r/issues")));

        let mut list = serde_json::json!({
            "total_count": 2,
            "secrets": [
                {"name": "A", "created_at": "t", "value": "leak"},
                {"name": "B", "encrypted_value": "leak2"}
            ]
        });
        assert_eq!(p.redact_response(&mut list), 2);
        assert_eq!(list["total_count"], 2);
        assert_eq!(list["secrets"][0]["name"], "A");
        assert!(list["secrets"][0].get("value").is_none());
        assert!(list["secrets"][1].get("encrypted_value").is_none());

        let mut pk = serde_json::json!({"key_id": "1", "key": "base64material"});
        assert_eq!(p.redact_response(&mut pk), 1);
        assert_eq!(pk["key_id"], "1");
        assert!(pk.get("key").is_none());
    }

    #[test]
    fn only_label_deletes_are_tracked_and_recreated() {
        let p = GithubProtocol;
        let issue = op("PATCH", "/repos/o/r/issues/42");
        assert!(!p.tracks_write(&issue));
        assert!(!p.wants_prior_snapshot(&issue));
        assert!(p.plan_revert(&issue, None, b"{}").is_err());

        let label = op("DELETE", "/repos/o/r/labels/bug");
        assert!(p.tracks_write(&label));
        assert!(p.wants_prior_snapshot(&label));
        let snapshot = serde_json::json!({
            "id": 1,
            "url": "https://api.github.com/repos/o/r/labels/bug",
            "name": "bug",
            "color": "d73a4a",
            "description": "Something is not working"
        })
        .to_string();
        let plan = p
            .plan_revert(&label, Some(snapshot.as_bytes()), b"{}")
            .expect("label restore plan");
        assert_eq!(plan.label, "delete labels/bug in o/r");
        assert_eq!(plan.revert.method, "POST");
        assert_eq!(plan.revert.path, "/repos/o/r/labels");
        let body: Value = serde_json::from_slice(&plan.revert.body.unwrap()).unwrap();
        assert_eq!(body["name"], "bug");
        assert_eq!(body["color"], "d73a4a");
        assert_eq!(body["description"], "Something is not working");
        assert!(body.get("id").is_none());
    }
}
