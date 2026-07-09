//! Kubernetes API proxy: gate in-process API clients at the API boundary instead
//! of the command boundary.
//!
//! `guard run kubectl …` is gated at the command boundary, but tools that drive
//! the Kubernetes API in-process (helm via client-go, terraform's k8s provider,
//! k9s, any client library) never spawn a gated command — the command gate sees
//! one opaque invocation. This subsystem lets the daemon terminate the client's
//! TLS connection, parse each API request into a typed [`k8s::ApiOp`], apply
//! operator-authored [`policy`], redact Secret values from responses, and
//! re-originate the request to the real apiserver with the real credentials the
//! daemon holds. The agent's brokered kubeconfig (see [`kubeconfig`]) carries no
//! credential and points only at the proxy, so the proxy is the sole path to the
//! cluster.
//!
//! The modules here are pure and unit-tested: request parsing/classification
//! ([`k8s`]), the operator policy model ([`policy`]), and brokered-kubeconfig
//! generation/validation ([`kubeconfig`]). The TLS-terminating server loop that
//! wires them to a live apiserver builds on top of these.

pub mod gate;
pub mod k8s;
pub mod kubeconfig;
pub mod policy;
pub mod server;
pub mod tls;
pub mod upstream;

pub use gate::{ApiMutation, ApiRevert, GateSink, HoldDecision};
pub use k8s::{ApiOp, Verb};
pub use kubeconfig::{brokered_kubeconfig, validate_brokered_kubeconfig, BrokerError};
pub use policy::{ApiAction, ApiPolicy, ApiRule};
pub use server::KubeProxy;
pub use tls::ProxyTls;
pub use upstream::Upstream;
