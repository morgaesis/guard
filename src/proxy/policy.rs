//! Operator-authored policy over Kubernetes API operations — the proxy's "slow
//! clock", analogous to the verb catalog. Only the operator edits it; agents
//! cannot. Rules match an [`ApiOp`] by verb/resource/namespace/subresource and
//! yield an action (allow, deny, hold) plus, for allowed reads, whether to
//! redact secret values from the response. A write to a subresource is
//! authorized only by a rule that names it. Default is fail-safe deny.

use super::k8s::ApiOp;
use serde::{Deserialize, Serialize};

/// What to do with a matched request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiAction {
    /// Forward the request to the apiserver.
    Allow,
    /// Reject at the proxy; the apiserver is never contacted.
    Deny,
    /// Hold for operator approval before the request reaches the apiserver.
    Hold,
}

fn any_glob() -> Vec<String> {
    vec!["*".to_string()]
}

fn default_deny() -> ApiAction {
    ApiAction::Deny
}

/// One operator-authored rule. Empty lists default to `["*"]` (match any).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiRule {
    /// Verbs matched: `get`, `list`, `watch`, `create`, `update`, `patch`,
    /// `delete`, `deletecollection`, or `*`.
    #[serde(default = "any_glob")]
    pub verbs: Vec<String>,
    /// Resources matched: `pods`, `secrets`, `deployments`, …, or `*`.
    #[serde(default = "any_glob")]
    pub resources: Vec<String>,
    /// Namespaces matched, or `*`. A cluster-scoped request matches only `*`.
    #[serde(default = "any_glob")]
    pub namespaces: Vec<String>,
    /// Write subresources this rule authorizes, e.g. `scale`, `eviction`,
    /// `status`. Empty (the default) means the rule covers only the bare
    /// resource: a write to a subresource is never authorized by a plain
    /// resource rule, because a write subresource can carry effects the parent
    /// verb does not model (evicting a pod, adding an ephemeral container,
    /// issuing a token). Read subresources (`log`, a `status` GET) are always
    /// covered by a matching read rule and do not need listing here. `*` allows
    /// any write subresource on the matched resource.
    #[serde(default)]
    pub subresources: Vec<String>,
    pub action: ApiAction,
    /// For an allowed read of a Secret, strip `data`/`stringData` from the
    /// response so values never reach the client.
    #[serde(default)]
    pub redact_secrets: bool,
    /// Optional human label, surfaced in the decision reason.
    #[serde(default)]
    pub description: Option<String>,
}

impl ApiRule {
    fn matches(&self, op: &ApiOp) -> bool {
        glob_any(&self.verbs, op.verb.as_str())
            && glob_any(&self.resources, &op.resource)
            && namespace_matches(&self.namespaces, op.namespace.as_deref())
            && self.subresource_matches(op)
    }

    /// A write to a subresource is authorized only when the rule names that
    /// subresource, so a bare `pods`/`patch` rule cannot silently cover
    /// `pods/ephemeralcontainers` or `pods/eviction`. Bare-resource requests and
    /// read subresources are unaffected.
    fn subresource_matches(&self, op: &ApiOp) -> bool {
        match op.subresource.as_deref() {
            None => true,
            Some(_) if op.is_read() => true,
            Some(sub) => glob_any(&self.subresources, sub),
        }
    }
}

/// The full operator policy.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiPolicy {
    #[serde(default)]
    pub rules: Vec<ApiRule>,
    /// Action for a request that no rule matches. Fail-safe deny by default.
    #[serde(default = "default_deny")]
    pub default: ApiAction,
}

/// The resolved decision for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiDecision {
    pub action: ApiAction,
    pub redact_secrets: bool,
    pub reason: String,
}

impl ApiPolicy {
    /// An empty, fail-safe (default-deny) policy.
    pub fn deny_all() -> Self {
        Self {
            rules: Vec::new(),
            default: ApiAction::Deny,
        }
    }

    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }

    pub fn load_file(path: &std::path::Path) -> std::io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Self::from_yaml(&text)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }

    /// First matching rule wins; otherwise the default action. Redaction is
    /// forced on for any Secret read regardless of the rule flag, so an operator
    /// cannot accidentally allow reading secret values by omitting the flag.
    pub fn decide(&self, op: &ApiOp) -> ApiDecision {
        let (action, mut redact, reason) =
            match self.rules.iter().enumerate().find(|(_, r)| r.matches(op)) {
                Some((i, r)) => {
                    let label = r
                        .description
                        .clone()
                        .unwrap_or_else(|| format!("api-policy rule #{i}"));
                    (r.action, r.redact_secrets, label)
                }
                None => (self.default, false, "api-policy default".to_string()),
            };
        // Reading secret values is never allowed to leak: force redaction on any
        // allowed Secret read, even if the matched rule did not set the flag.
        if matches!(action, ApiAction::Allow) && op.is_read() && op.is_secrets() {
            redact = true;
        }
        ApiDecision {
            action,
            redact_secrets: redact,
            reason,
        }
    }
}

/// Match `value` against a list of patterns. `*` matches anything; otherwise an
/// exact, case-sensitive match.
fn glob_any(patterns: &[String], value: &str) -> bool {
    patterns.iter().any(|p| p == "*" || p == value)
}

/// A namespaced request matches `*` or its exact namespace; a cluster-scoped
/// request (no namespace) matches only `*`.
fn namespace_matches(patterns: &[String], ns: Option<&str>) -> bool {
    match ns {
        Some(n) => patterns.iter().any(|p| p == "*" || p == n),
        None => patterns.iter().any(|p| p == "*"),
    }
}

#[cfg(test)]
mod tests {
    use super::super::k8s::parse_api_op;
    use super::*;

    fn op(method: &str, path: &str) -> ApiOp {
        parse_api_op(method, path, "").unwrap()
    }

    fn policy(yaml: &str) -> ApiPolicy {
        ApiPolicy::from_yaml(yaml).expect("valid policy")
    }

    #[test]
    fn default_is_deny() {
        let p = ApiPolicy::deny_all();
        assert_eq!(p.decide(&op("GET", "/api/v1/pods")).action, ApiAction::Deny);
    }

    #[test]
    fn first_match_wins() {
        let p = policy(
            r#"
default: deny
rules:
  - verbs: [get, list]
    resources: ["*"]
    action: allow
  - verbs: [delete]
    resources: ["*"]
    action: hold
"#,
        );
        assert_eq!(
            p.decide(&op("GET", "/api/v1/namespaces/d/pods")).action,
            ApiAction::Allow
        );
        assert_eq!(
            p.decide(&op("DELETE", "/api/v1/namespaces/d/pods/x"))
                .action,
            ApiAction::Hold
        );
        assert_eq!(
            p.decide(&op("POST", "/api/v1/namespaces/d/pods")).action,
            ApiAction::Deny,
            "unmatched create falls to default deny"
        );
    }

    #[test]
    fn write_subresource_not_covered_by_bare_resource_rule() {
        // A plain pods write rule must not authorize ephemeralcontainers (code
        // execution) or eviction (pod termination) writes.
        let p = policy(
            r#"
default: deny
rules:
  - verbs: [create, update, patch]
    resources: [pods]
    namespaces: [dev]
    action: allow
"#,
        );
        assert_eq!(
            p.decide(&op(
                "PATCH",
                "/api/v1/namespaces/dev/pods/web-0/ephemeralcontainers"
            ))
            .action,
            ApiAction::Deny,
            "ephemeralcontainers write is not covered by a pods write rule"
        );
        assert_eq!(
            p.decide(&op("POST", "/api/v1/namespaces/dev/pods/web-0/eviction"))
                .action,
            ApiAction::Deny,
            "eviction write is not covered by a pods write rule"
        );
        // The bare pods write still works.
        assert_eq!(
            p.decide(&op("POST", "/api/v1/namespaces/dev/pods")).action,
            ApiAction::Allow
        );
    }

    #[test]
    fn read_subresource_covered_by_resource_read_rule() {
        // Reading logs/status under a resource read rule keeps working; only
        // write subresources need an explicit grant.
        let p = policy(
            r#"
default: deny
rules:
  - verbs: [get, list, watch]
    resources: [pods]
    namespaces: [dev]
    action: allow
"#,
        );
        assert_eq!(
            p.decide(&op("GET", "/api/v1/namespaces/dev/pods/web-0/log"))
                .action,
            ApiAction::Allow
        );
        assert_eq!(
            p.decide(&op("GET", "/api/v1/namespaces/dev/pods/web-0/status"))
                .action,
            ApiAction::Allow
        );
    }

    #[test]
    fn write_subresource_allowed_when_named() {
        let p = policy(
            r#"
default: deny
rules:
  - verbs: [update, patch]
    resources: [deployments]
    namespaces: [dev]
    subresources: [scale]
    action: allow
"#,
        );
        assert_eq!(
            p.decide(&op(
                "PATCH",
                "/apis/apps/v1/namespaces/dev/deployments/api/scale"
            ))
            .action,
            ApiAction::Allow
        );
        // A different subresource is still not covered.
        assert_eq!(
            p.decide(&op(
                "PATCH",
                "/apis/apps/v1/namespaces/dev/deployments/api/status"
            ))
            .action,
            ApiAction::Deny
        );
    }

    #[test]
    fn namespace_scoping() {
        let p = policy(
            r#"
default: deny
rules:
  - verbs: ["*"]
    resources: ["*"]
    namespaces: [dev, staging]
    action: allow
"#,
        );
        assert_eq!(
            p.decide(&op("GET", "/api/v1/namespaces/dev/pods")).action,
            ApiAction::Allow
        );
        assert_eq!(
            p.decide(&op("GET", "/api/v1/namespaces/prod/pods")).action,
            ApiAction::Deny,
            "prod is outside the allowed namespaces"
        );
        // A cluster-scoped node list does not match namespace-scoped rules.
        assert_eq!(
            p.decide(&op("GET", "/api/v1/nodes")).action,
            ApiAction::Deny
        );
    }

    #[test]
    fn secret_reads_force_redaction_even_without_flag() {
        let p = policy(
            r#"
default: deny
rules:
  - verbs: [get, list]
    resources: ["*"]
    action: allow
"#,
        );
        let d = p.decide(&op("GET", "/api/v1/namespaces/p/secrets/db"));
        assert_eq!(d.action, ApiAction::Allow);
        assert!(
            d.redact_secrets,
            "an allowed Secret read must force redaction"
        );
        // A non-secret read is not redacted.
        let cm = p.decide(&op("GET", "/api/v1/namespaces/p/configmaps/c"));
        assert!(!cm.redact_secrets);
    }

    #[test]
    fn shipped_example_policy_parses_and_behaves() {
        let p = ApiPolicy::from_yaml(include_str!("../../examples/api-policy.yaml"))
            .expect("examples/api-policy.yaml must parse");
        // Reads are allowed and secret values redacted.
        let read = p.decide(&op("GET", "/api/v1/namespaces/p/secrets/s"));
        assert_eq!(read.action, ApiAction::Allow);
        assert!(read.redact_secrets);
        // Writes allowed in a non-production namespace, denied in production.
        assert_eq!(
            p.decide(&op("POST", "/api/v1/namespaces/dev/pods")).action,
            ApiAction::Allow
        );
        assert_eq!(
            p.decide(&op("POST", "/api/v1/namespaces/prod/pods")).action,
            ApiAction::Deny
        );
        // Namespace deletion and other deletes are held for approval.
        assert_eq!(
            p.decide(&op("DELETE", "/api/v1/namespaces/prod")).action,
            ApiAction::Hold
        );
        assert_eq!(
            p.decide(&op("DELETE", "/api/v1/namespaces/dev/pods/x"))
                .action,
            ApiAction::Hold
        );
    }

    #[test]
    fn description_surfaces_in_reason() {
        let p = policy(
            r#"
default: deny
rules:
  - verbs: [delete]
    resources: [namespaces]
    action: hold
    description: "namespace deletion needs sign-off"
"#,
        );
        let d = p.decide(&op("DELETE", "/api/v1/namespaces/prod"));
        assert_eq!(d.action, ApiAction::Hold);
        assert_eq!(d.reason, "namespace deletion needs sign-off");
    }
}
