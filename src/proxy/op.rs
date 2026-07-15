//! The protocol-neutral operation vocabulary of the REST proxy: a typed
//! [`ApiOp`] (verb, group/version, resource, subresource, namespace, name) and
//! its consequence classification. Every [`super::protocol::ProtocolConfig`]
//! parses its own wire shape into this vocabulary, so the policy and server
//! layers match one operation type regardless of protocol. Pure data — no I/O,
//! no parsing; each protocol owns its own request parsing.

use crate::gating::Reversibility;
use std::collections::BTreeMap;

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
    /// A method the proxy does not model (e.g. an HTTP method the upstream does
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

    /// A read does not mutate upstream state.
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

/// A parsed API operation. The field vocabulary follows the Kubernetes REST
/// shape (group/version/resource/namespace); other protocols map their own
/// scoping into it (e.g. a repository or project identifier becomes the
/// namespace).
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
    /// `?dryRun=` was set, so the upstream will not persist the change.
    pub dry_run: bool,
    /// Protocol-defined query parameters that change the upstream authority
    /// scope. Values are canonical, credential-safe identifiers. Presentation
    /// parameters stay out of this map so pagination and output formatting do
    /// not fragment typed coverage.
    pub authority_selectors: BTreeMap<String, String>,
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
