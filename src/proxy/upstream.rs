//! Upstream connection to the real API. For Kubernetes it is built from the
//! operator's kubeconfig, resolving a single auth method by precedence
//! (bearer-token, then client-certificate, then HTTP basic); `exec` and
//! `auth-provider` credential plugins are rejected because the proxy cannot run
//! them and a brokered client that could would reach the apiserver around the
//! gate. Other protocols build from a base URL plus an optional bearer token.
//! The daemon holds these upstream credentials. A brokered config carries no
//! upstream credential, though it may carry a Guard session bearer that the
//! proxy consumes, so the proxy is the sole path to the upstream.

use std::path::Path;

use anyhow::{bail, Context, Result};
use base64::Engine;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct KubeConfig {
    #[serde(default)]
    clusters: Vec<NamedCluster>,
    #[serde(default)]
    contexts: Vec<NamedContext>,
    #[serde(default)]
    users: Vec<NamedUser>,
    #[serde(rename = "current-context")]
    current_context: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NamedCluster {
    name: String,
    cluster: Cluster,
}

#[derive(Debug, Deserialize)]
struct Cluster {
    server: String,
    #[serde(rename = "certificate-authority-data")]
    ca_data: Option<String>,
    #[serde(rename = "certificate-authority")]
    ca_file: Option<String>,
    #[serde(rename = "insecure-skip-tls-verify", default)]
    insecure: bool,
}

#[derive(Debug, Deserialize)]
struct NamedContext {
    name: String,
    context: ContextSpec,
}

#[derive(Debug, Deserialize)]
struct ContextSpec {
    cluster: String,
    user: String,
}

#[derive(Debug, Deserialize)]
struct NamedUser {
    name: String,
    user: User,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct User {
    token: Option<String>,
    #[serde(rename = "tokenFile")]
    token_file: Option<String>,
    #[serde(rename = "client-certificate-data")]
    cert_data: Option<String>,
    #[serde(rename = "client-certificate")]
    cert_file: Option<String>,
    #[serde(rename = "client-key-data")]
    key_data: Option<String>,
    #[serde(rename = "client-key")]
    key_file: Option<String>,
    username: Option<String>,
    password: Option<String>,
    exec: Option<serde_yaml_ng::Value>,
    #[serde(rename = "auth-provider")]
    auth_provider: Option<serde_yaml_ng::Value>,
}

/// A configured connection to the real apiserver. Holds exactly one of the
/// operator's authentication methods (a bearer token, a client identity baked
/// into the TLS client, or HTTP basic auth); the proxy injects it when it
/// re-originates a request. Presenting more than one would make the apiserver
/// reject the identity, so [`Upstream::from_kubeconfig_str`] resolves a single
/// method by precedence.
pub struct Upstream {
    base: String,
    client: reqwest::Client,
    bearer: Option<String>,
    basic: Option<(String, String)>,
    identity_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamAuth {
    None,
    Bearer(String),
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose the operator's credentials in debug output.
        f.debug_struct("Upstream")
            .field("base", &self.base)
            .field("bearer", &self.bearer.as_ref().map(|_| "<redacted>"))
            .field("basic", &self.basic.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

impl Upstream {
    /// Build a generic upstream with public CA roots, no redirects, and an
    /// optional bearer token. Non-Kubernetes protocols use this path.
    pub fn from_base_url(base: &str, auth: UpstreamAuth) -> Result<Self> {
        let parsed = reqwest::Url::parse(base).context("parse upstream URL")?;
        match parsed.scheme() {
            "https" | "http" => {}
            other => bail!("unsupported upstream URL scheme '{other}'"),
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("build upstream TLS client")?;
        let bearer = match auth {
            UpstreamAuth::None => None,
            UpstreamAuth::Bearer(token) => Some(token),
        };
        let canonical_base = base.trim_end_matches('/').to_string();
        let identity_fingerprint = fingerprint_identity(
            &canonical_base,
            if let Some(token) = bearer.as_deref() {
                ("bearer", token.as_bytes())
            } else {
                ("none", &[])
            },
        );
        Ok(Self {
            base: canonical_base,
            client,
            bearer,
            basic: None,
            identity_fingerprint,
        })
    }

    /// Build an upstream from a kubeconfig file, selecting `context` (or the
    /// file's `current-context` when `None`).
    pub fn from_kubeconfig_file(path: &Path, context: Option<&str>) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read kubeconfig {}", path.display()))?;
        Self::from_kubeconfig_str(&text, context)
    }

    /// Build an upstream from kubeconfig YAML text.
    pub fn from_kubeconfig_str(text: &str, context: Option<&str>) -> Result<Self> {
        let cfg: KubeConfig = serde_yaml_ng::from_str(text).context("parse kubeconfig")?;

        let ctx_name = context
            .map(str::to_string)
            .or_else(|| cfg.current_context.clone())
            .context("kubeconfig has no current-context and no --kube-context was given")?;
        let ctx = cfg
            .contexts
            .iter()
            .find(|c| c.name == ctx_name)
            .with_context(|| format!("context '{ctx_name}' not found in kubeconfig"))?;
        let cluster = cfg
            .clusters
            .iter()
            .find(|c| c.name == ctx.context.cluster)
            .with_context(|| {
                format!("cluster '{}' not found in kubeconfig", ctx.context.cluster)
            })?;
        let user = cfg
            .users
            .iter()
            .find(|u| u.name == ctx.context.user)
            .map(|u| u.user.clone())
            .unwrap_or_default();

        if user.exec.is_some() {
            bail!(
                "kubeconfig user '{}' uses an exec credential plugin, which the proxy cannot broker",
                ctx.context.user
            );
        }
        if user.auth_provider.is_some() {
            bail!(
                "kubeconfig user '{}' uses an auth-provider plugin, which the proxy cannot broker",
                ctx.context.user
            );
        }

        let mut builder = reqwest::Client::builder()
            // The proxy is a transparent forwarder: it must not chase redirects
            // on the client's behalf or auto-decompress bodies it streams back.
            .redirect(reqwest::redirect::Policy::none());

        // Trust the real apiserver's CA.
        if let Some(ca_b64) = &cluster.cluster.ca_data {
            let pem = base64::engine::general_purpose::STANDARD
                .decode(ca_b64.as_bytes())
                .context("decode cluster certificate-authority-data")?;
            for cert in reqwest::Certificate::from_pem_bundle(&pem).context("parse cluster CA")? {
                builder = builder.add_root_certificate(cert);
            }
        } else if let Some(ca_path) = &cluster.cluster.ca_file {
            let pem = std::fs::read(ca_path)
                .with_context(|| format!("read certificate-authority {ca_path}"))?;
            for cert in reqwest::Certificate::from_pem_bundle(&pem).context("parse cluster CA")? {
                builder = builder.add_root_certificate(cert);
            }
        }
        if cluster.cluster.insecure {
            builder = builder.danger_accept_invalid_certs(true);
        }

        // Resolve exactly one authentication method. A kubeconfig user may carry
        // several (a client cert alongside basic auth, say); the apiserver rejects
        // an identity that presents more than one, so pick a single method by
        // precedence: bearer token, then client certificate, then basic auth. The
        // lower-precedence fields are dropped, not layered on top.
        let bearer = if let Some(t) = &user.token {
            Some(t.clone())
        } else if let Some(tf) = &user.token_file {
            Some(
                std::fs::read_to_string(tf)
                    .with_context(|| format!("read tokenFile {tf}"))?
                    .trim()
                    .to_string(),
            )
        } else {
            None
        };

        let cert_pem = read_pem(
            &user.cert_data,
            user.cert_file.as_deref(),
            "client-certificate",
        )?;
        let key_pem = read_pem(&user.key_data, user.key_file.as_deref(), "client-key")?;
        let client_identity = match (cert_pem.as_ref(), key_pem.as_ref()) {
            (Some(cert), Some(key)) => {
                let mut id = Vec::with_capacity(cert.len() + key.len() + 1);
                id.extend_from_slice(cert);
                id.push(b'\n');
                id.extend_from_slice(key);
                Some(reqwest::Identity::from_pem(&id).context("build client identity")?)
            }
            _ => None,
        };

        let basic = match (&user.username, &user.password) {
            (Some(u), p) => Some((u.clone(), p.clone().unwrap_or_default())),
            _ => None,
        };

        // Bind the single method to the client/request path. Attaching the client
        // certificate is a client-level decision, so only do it when the cert is
        // the elected method (a token takes precedence and stands alone).
        let selected_client_cert = bearer.is_none() && client_identity.is_some();
        let (bearer, basic) = if bearer.is_some() {
            (bearer, None)
        } else if client_identity.is_some() {
            (None, None)
        } else {
            (None, basic)
        };
        if let Some(identity) = client_identity {
            if bearer.is_none() && basic.is_none() {
                builder = builder.identity(identity);
            }
        }

        let client = builder.build().context("build upstream TLS client")?;
        let base = cluster.cluster.server.trim_end_matches('/').to_string();
        let identity_fingerprint = if let Some(token) = bearer.as_deref() {
            fingerprint_identity(&base, ("bearer", token.as_bytes()))
        } else if selected_client_cert {
            fingerprint_identity(
                &base,
                (
                    "client-certificate",
                    cert_pem.as_deref().unwrap_or_default(),
                ),
            )
        } else if let Some((username, _password)) = basic.as_ref() {
            // The username is the Basic-auth principal. Hashing the password
            // would persist an offline verifier in revert metadata.
            fingerprint_identity(&base, ("basic", username.as_bytes()))
        } else {
            fingerprint_identity(&base, ("none", &[]))
        };
        Ok(Self {
            base,
            client,
            bearer,
            basic,
            identity_fingerprint,
        })
    }

    /// Base apiserver URL (scheme://host:port), no trailing slash.
    pub fn base(&self) -> &str {
        &self.base
    }

    /// The TLS client carrying the operator's CA trust and client identity.
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// The operator's bearer token, injected on each forwarded request.
    pub fn bearer(&self) -> Option<&str> {
        self.bearer.as_deref()
    }

    /// The operator's HTTP basic-auth credential (`username`, `password`),
    /// injected on each forwarded request when no bearer token or client
    /// certificate is configured.
    pub fn basic_auth(&self) -> Option<(&str, &str)> {
        self.basic.as_ref().map(|(u, p)| (u.as_str(), p.as_str()))
    }

    /// Secret-free digest of the canonical target and selected upstream
    /// authentication identity. Credential values never leave this object.
    pub fn identity_fingerprint(&self) -> &str {
        &self.identity_fingerprint
    }

    /// Exact byte sequences derived from the authentication material this
    /// proxy injects. Response filtering uses them to prevent a cooperative or
    /// hostile upstream from reflecting daemon-held credentials to the client.
    pub fn response_secret_values(&self) -> Vec<Vec<u8>> {
        let mut values = Vec::new();
        if let Some(token) = self.bearer.as_deref() {
            if !token.is_empty() {
                values.push(token.as_bytes().to_vec());
                values.push(format!("Bearer {token}").into_bytes());
            }
        }
        if let Some((username, password)) = self.basic.as_ref() {
            let joined = format!("{username}:{password}");
            if !password.is_empty() {
                values.push(password.as_bytes().to_vec());
            }
            values.push(joined.as_bytes().to_vec());
            values.push(
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(joined.as_bytes())
                )
                .into_bytes(),
            );
        }
        values.sort();
        values.dedup();
        values
    }

    /// Produce a bounded, credential-safe diagnostic excerpt for persisted
    /// revert errors and audit messages.
    pub fn redact_error_excerpt(&self, bytes: &[u8], max_chars: usize) -> String {
        let mut text = String::from_utf8_lossy(bytes).to_string();
        for secret in self.response_secret_values() {
            if !secret.is_empty() {
                text = text.replace(&*String::from_utf8_lossy(&secret), "[REDACTED]");
            }
        }
        text = crate::redact::redact_output_text(&text);
        let mut excerpt = text.chars().take(max_chars).collect::<String>();
        if text.chars().count() > max_chars {
            excerpt.push('~');
        }
        excerpt
    }
}

fn fingerprint_identity(base: &str, auth: (&str, &[u8])) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(base.as_bytes());
    hasher.update([0]);
    hasher.update(auth.0.as_bytes());
    hasher.update([0]);
    hasher.update(auth.1);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Resolve a PEM field that may be inline base64 (`*-data`) or a file path.
fn read_pem(data_b64: &Option<String>, file: Option<&str>, what: &str) -> Result<Option<Vec<u8>>> {
    if let Some(b64) = data_b64 {
        let pem = base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .with_context(|| format!("decode {what}-data"))?;
        Ok(Some(pem))
    } else if let Some(path) = file {
        let pem = std::fs::read(path).with_context(|| format!("read {what} {path}"))?;
        Ok(Some(pem))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_token_context() {
        let yaml = r#"
apiVersion: v1
kind: Config
current-context: ctx
clusters:
  - name: c1
    cluster:
      server: https://api.example.test:6443/
      certificate-authority-data: ""
contexts:
  - name: ctx
    context: {cluster: c1, user: u1}
users:
  - name: u1
    user:
      token: brokered-secret-token
"#;
        // Empty CA data decodes to an empty bundle (no certs added) — fine for the
        // parse-level test; we only assert base/bearer resolution here.
        let up = Upstream::from_kubeconfig_str(yaml, None).expect("parse");
        assert_eq!(up.base(), "https://api.example.test:6443");
        assert_eq!(up.bearer(), Some("brokered-secret-token"));
        assert_eq!(up.identity_fingerprint().len(), 64);
        assert!(!up.identity_fingerprint().contains("brokered-secret-token"));
    }

    #[test]
    fn identity_fingerprint_changes_when_the_credential_rotates() {
        let first = Upstream::from_base_url(
            "https://api.example.test",
            UpstreamAuth::Bearer("token-one".to_string()),
        )
        .unwrap();
        let second = Upstream::from_base_url(
            "https://api.example.test",
            UpstreamAuth::Bearer("token-two".to_string()),
        )
        .unwrap();
        assert_ne!(first.identity_fingerprint(), second.identity_fingerprint());
    }

    #[test]
    fn revert_error_excerpt_is_bounded_and_redacts_injected_credentials() {
        let upstream = Upstream::from_base_url(
            "https://api.example.test",
            UpstreamAuth::Bearer("operator-secret-token".to_string()),
        )
        .unwrap();
        let body = format!(
            "upstream reflected Bearer operator-secret-token {}",
            "x".repeat(2000)
        );
        let excerpt = upstream.redact_error_excerpt(body.as_bytes(), 80);
        assert!(!excerpt.contains("operator-secret-token"));
        assert!(excerpt.contains("[REDACTED]"));
        assert!(excerpt.chars().count() <= 81);
    }

    #[test]
    fn explicit_context_overrides_current() {
        let yaml = r#"
apiVersion: v1
kind: Config
current-context: a
clusters:
  - {name: ca, cluster: {server: "https://a:6443"}}
  - {name: cb, cluster: {server: "https://b:6443"}}
contexts:
  - {name: a, context: {cluster: ca, user: ua}}
  - {name: b, context: {cluster: cb, user: ub}}
users:
  - {name: ua, user: {token: ta}}
  - {name: ub, user: {token: tb}}
"#;
        let up = Upstream::from_kubeconfig_str(yaml, Some("b")).unwrap();
        assert_eq!(up.base(), "https://b:6443");
        assert_eq!(up.bearer(), Some("tb"));
    }

    #[test]
    fn token_replaces_basic_auth() {
        // A user carrying basic-auth *and* a token must present exactly one
        // method upstream: the token wins and the basic-auth fields are dropped,
        // so the apiserver never sees `[token basicAuth]`.
        let yaml = r#"
apiVersion: v1
kind: Config
current-context: ctx
clusters: [{name: c, cluster: {server: "https://x:6443"}}]
contexts: [{name: ctx, context: {cluster: c, user: u}}]
users:
  - name: u
    user:
      username: admin
      password: hunter2
      token: brokered-secret-token
"#;
        let up = Upstream::from_kubeconfig_str(yaml, None).expect("parse");
        assert_eq!(up.bearer(), Some("brokered-secret-token"));
        assert_eq!(up.basic_auth(), None, "basic auth must be dropped");
    }

    #[test]
    fn basic_auth_without_token_is_used() {
        let yaml = r#"
apiVersion: v1
kind: Config
current-context: ctx
clusters: [{name: c, cluster: {server: "https://x:6443"}}]
contexts: [{name: ctx, context: {cluster: c, user: u}}]
users:
  - name: u
    user:
      username: admin
      password: hunter2
"#;
        let up = Upstream::from_kubeconfig_str(yaml, None).expect("parse");
        assert_eq!(up.bearer(), None);
        assert_eq!(up.basic_auth(), Some(("admin", "hunter2")));
    }

    #[test]
    fn rejects_exec_plugin() {
        let yaml = r#"
apiVersion: v1
kind: Config
current-context: ctx
clusters: [{name: c, cluster: {server: "https://x:6443"}}]
contexts: [{name: ctx, context: {cluster: c, user: u}}]
users:
  - name: u
    user:
      exec: {command: aws-iam-authenticator}
"#;
        let err = Upstream::from_kubeconfig_str(yaml, None).unwrap_err();
        assert!(err.to_string().contains("exec credential plugin"), "{err}");
    }

    #[test]
    fn missing_context_errors() {
        let yaml = r#"
apiVersion: v1
kind: Config
clusters: [{name: c, cluster: {server: "https://x:6443"}}]
contexts: [{name: ctx, context: {cluster: c, user: u}}]
users: [{name: u, user: {token: t}}]
"#;
        // No current-context and none supplied.
        let err = Upstream::from_kubeconfig_str(yaml, None).unwrap_err();
        assert!(err.to_string().contains("current-context"), "{err}");
    }

    /// A throwaway client certificate + key as base64-encoded PEM, for exercising
    /// the client-certificate precedence legs. rcgen is already a dependency (the
    /// proxy's own TLS material uses it), so this needs no fixture files.
    fn client_cert_key_b64() -> (String, String) {
        let key = rcgen::KeyPair::generate().expect("keypair");
        let params =
            rcgen::CertificateParams::new(vec!["test-client".to_string()]).expect("params");
        let cert = params.self_signed(&key).expect("self-sign");
        let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s.as_bytes());
        (b64(&cert.pem()), b64(&key.serialize_pem()))
    }

    #[test]
    fn token_takes_precedence_over_client_cert() {
        // A user carrying BOTH a bearer token and a (valid) client certificate
        // must resolve to the token alone: the certificate is not attached and no
        // basic auth is layered on, so the apiserver sees exactly one method.
        let (cert_b64, key_b64) = client_cert_key_b64();
        let yaml = format!(
            "apiVersion: v1\n\
             kind: Config\n\
             current-context: ctx\n\
             clusters: [{{name: c, cluster: {{server: \"https://x:6443\"}}}}]\n\
             contexts: [{{name: ctx, context: {{cluster: c, user: u}}}}]\n\
             users: [{{name: u, user: {{token: brokered-secret-token, client-certificate-data: {cert_b64}, client-key-data: {key_b64}}}}}]\n"
        );
        let up = Upstream::from_kubeconfig_str(&yaml, None).expect("parse");
        assert_eq!(up.bearer(), Some("brokered-secret-token"));
        assert_eq!(up.basic_auth(), None);
    }

    #[test]
    fn client_cert_takes_precedence_over_basic_auth() {
        // With no token, a user carrying BOTH a (valid) client certificate and
        // basic auth resolves to the certificate: basic auth is dropped, not
        // layered on top.
        let (cert_b64, key_b64) = client_cert_key_b64();
        let yaml = format!(
            "apiVersion: v1\n\
             kind: Config\n\
             current-context: ctx\n\
             clusters: [{{name: c, cluster: {{server: \"https://x:6443\"}}}}]\n\
             contexts: [{{name: ctx, context: {{cluster: c, user: u}}}}]\n\
             users: [{{name: u, user: {{username: admin, password: hunter2, client-certificate-data: {cert_b64}, client-key-data: {key_b64}}}}}]\n"
        );
        let up = Upstream::from_kubeconfig_str(&yaml, None).expect("parse");
        assert_eq!(up.bearer(), None);
        assert_eq!(
            up.basic_auth(),
            None,
            "basic auth must be dropped when a client certificate is elected"
        );
    }
}
