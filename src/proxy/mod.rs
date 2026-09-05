//! Kubernetes API proxy: gate in-process API clients at the API boundary instead
//! of the command boundary.
//!
//! `guard run kubectl …` is gated at the command boundary, but tools that drive
//! the Kubernetes API in-process (helm via client-go, terraform's k8s provider,
//! k9s, any client library) never spawn a gated command - the command gate sees
//! one opaque invocation. This subsystem lets the daemon terminate the client's
//! TLS connection, parse each API request into a typed [`op::ApiOp`], apply
//! operator-authored [`policy`], redact Secret values from responses, and
//! re-originate the request to the real apiserver with the real credentials the
//! daemon holds. The agent's brokered kubeconfig (see [`kubeconfig`]) carries no
//! upstream credential and authenticates with a generated proxy transport
//! bearer. A live Guard session bearer may replace it. The proxy consumes
//! either without forwarding, and the config points only at the proxy.
//!
//! The modules here are pure and unit-tested: the protocol-neutral operation
//! vocabulary ([`op`]), request parsing/classification ([`k8s`]), the operator
//! policy model ([`policy`]), and brokered-kubeconfig generation/validation
//! ([`kubeconfig`]). The TLS-terminating server loop that wires them to a live
//! apiserver builds on top of these, asking every protocol-specific question
//! through the [`protocol::ProtocolConfig`] plug-in surface; [`k8s_protocol`]
//! is the Kubernetes reference implementation, and `github_protocol`/
//! `vercel_protocol` are example configs proving the surface generalizes.

use std::net::IpAddr;

mod client_config;
pub mod gate;
pub mod github_protocol;
pub mod k8s;
pub mod k8s_protocol;
pub mod kubeconfig;
pub mod op;
pub mod policy;
pub mod protocol;
pub mod server;
pub mod tls;
pub mod upstream;
pub mod vercel_protocol;

pub use client_config::{
    brokered_client_config, validate_brokered_client_config, ClientConfigError,
};
pub use gate::{
    ApiAuthorizationKind, ApiCoverageVerdict, ApiEvaluationMode, ApiForwardHandoff,
    ApiForwardRequirement, ApiHoldSnapshot, ApiJudge, ApiJudgeVerdict, ApiMutation,
    ApiRequestSummary, ApiSessionContext, ApiSessionEvent, ApiSessionSink, GateSink, HoldDecision,
    HttpRevert, RevertConstructible,
};
pub use github_protocol::GithubProtocol;
pub use k8s_protocol::KubernetesProtocol;
pub use kubeconfig::{
    brokered_kubeconfig, brokered_kubeconfig_with_session, valid_guard_session_token,
    validate_brokered_kubeconfig, validate_brokered_kubeconfig_matches,
    validate_brokered_kubeconfig_with_session, BrokerError,
};
pub use op::ApiOp;
pub use policy::{ApiAction, ApiPolicy, ApiRule};
pub use protocol::{CreatedIdentity, NonResourceRead, PlannedRevert, ProtocolConfig};
pub use server::{ApiListenerMode, ApiProxy};
pub use tls::ProxyTls;
pub use upstream::{Upstream, UpstreamAuth};
pub use vercel_protocol::VercelProtocol;

/// Validate the shared network boundary for every generated proxy-client
/// document. Keeping this rule protocol-neutral prevents one client format from
/// drifting into a broader endpoint contract than another.
pub(crate) fn validate_brokered_proxy_origin(value: &str) -> Result<(), String> {
    let endpoint = reqwest::Url::parse(value)
        .map_err(|error| format!("proxy endpoint is invalid: {error}"))?;
    let loopback = endpoint
        .host_str()
        .and_then(|host| host.parse::<IpAddr>().ok())
        .is_some_and(|address| address.is_loopback());
    if endpoint.scheme() != "https"
        || !loopback
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.port().is_none()
        || endpoint.path() != "/"
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(
            "proxy endpoint must be a credential-free loopback HTTPS origin with an explicit port"
                .to_string(),
        );
    }
    Ok(())
}
