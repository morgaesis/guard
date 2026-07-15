//! Brokered kubeconfig: the agent-facing config the proxy hands out. It points
//! only at the proxy. The daemon holds the real upstream credentials and
//! injects them when it re-originates each request. A config may carry a Guard
//! session bearer, which the proxy consumes and never forwards. Generation and
//! validation live here; validation is the containment-critical check.

use std::fmt;

/// Credential-bearing fields under a kubeconfig `user`. Any of these would let
/// the agent mint real credentials and reach the apiserver around the proxy, so
/// a brokered config must contain none of them.
const FORBIDDEN_USER_FIELDS: &[&str] = &[
    "token",
    "tokenFile",
    "client-certificate",
    "client-certificate-data",
    "client-key",
    "client-key-data",
    "exec",
    "auth-provider",
    "username",
    "password",
];

/// Why a kubeconfig is not a safe brokered config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerError {
    /// The YAML could not be parsed.
    Parse(String),
    /// A user carries a credential-bearing field.
    Credential {
        user: String,
        field: String,
    },
    MissingSessionCredential,
    InvalidSessionCredential,
}

impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BrokerError::Parse(e) => write!(f, "could not parse kubeconfig: {e}"),
            BrokerError::Credential { user, field } => write!(
                f,
                "brokered kubeconfig must not carry an upstream or unexpected client credential, but user '{user}' has '{field}'"
            ),
            BrokerError::MissingSessionCredential => {
                write!(f, "brokered kubeconfig is missing its Guard session bearer")
            }
            BrokerError::InvalidSessionCredential => {
                write!(f, "Guard session bearer is not valid for an HTTP header")
            }
        }
    }
}

impl std::error::Error for BrokerError {}

/// Build a brokered kubeconfig pointing at `proxy_url`, trusting the proxy's CA
/// (`ca_data_b64`, the base64 of the CA's PEM), with an empty user. The
/// agent uses this verbatim; it cannot reach the real apiserver with it.
pub fn brokered_kubeconfig(proxy_url: &str, ca_data_b64: &str) -> String {
    brokered_kubeconfig_inner(proxy_url, ca_data_b64, None)
}

/// Build a brokered kubeconfig whose only client credential is a Guard session
/// bearer. It authenticates to the loopback proxy and is never forwarded to the
/// upstream API server.
pub fn brokered_kubeconfig_with_session(
    proxy_url: &str,
    ca_data_b64: &str,
    session_token: &str,
) -> String {
    brokered_kubeconfig_inner(proxy_url, ca_data_b64, Some(session_token))
}

fn brokered_kubeconfig_inner(
    proxy_url: &str,
    ca_data_b64: &str,
    session_token: Option<&str>,
) -> String {
    let user = session_token
        .map(|token| serde_json::json!({ "token": token }))
        .unwrap_or_else(|| serde_json::json!({}));
    let cfg = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [{
            "name": "guard-proxy",
            "cluster": {
                "server": proxy_url,
                "certificate-authority-data": ca_data_b64,
            },
        }],
        "contexts": [{
            "name": "guard-proxy",
            "context": { "cluster": "guard-proxy", "user": "guard-agent" },
        }],
        "current-context": "guard-proxy",
        "users": [{ "name": "guard-agent", "user": user }],
    });
    serde_yaml_ng::to_string(&cfg).expect("serialize brokered kubeconfig")
}

/// Validate that `yaml` is a brokered config carrying no credential: every user's
/// `user` map must be free of token/cert/key/exec/auth-provider/password fields.
/// This is the invariant that keeps the proxy the sole path to the cluster.
pub fn validate_brokered_kubeconfig(yaml: &str) -> Result<(), BrokerError> {
    validate_brokered_kubeconfig_inner(yaml, None)
}

/// Validate a brokered config that may contain exactly the supplied Guard
/// session bearer and no other credential-bearing field.
pub fn validate_brokered_kubeconfig_with_session(
    yaml: &str,
    session_token: &str,
) -> Result<(), BrokerError> {
    if !valid_guard_session_token(session_token) {
        return Err(BrokerError::InvalidSessionCredential);
    }
    validate_brokered_kubeconfig_inner(yaml, Some(session_token))
}

pub fn valid_guard_session_token(token: &str) -> bool {
    !token.is_empty() && token.len() <= 256 && token.bytes().all(|byte| matches!(byte, b'!'..=b'~'))
}

fn validate_brokered_kubeconfig_inner(
    yaml: &str,
    session_token: Option<&str>,
) -> Result<(), BrokerError> {
    let doc: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(yaml).map_err(|e| BrokerError::Parse(e.to_string()))?;

    let users = match doc.get("users").and_then(|u| u.as_sequence()) {
        Some(seq) => seq,
        None if session_token.is_some() => return Err(BrokerError::MissingSessionCredential),
        None => return Ok(()), // no users at all is valid
    };

    let mut found_session = false;
    for entry in users {
        let user_name = entry
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("<unnamed>")
            .to_string();
        let Some(user) = entry.get("user").and_then(|u| u.as_mapping()) else {
            continue; // `user: {}` or absent is valid
        };
        for (key, value) in user.iter() {
            if let Some(field) = key.as_str() {
                if FORBIDDEN_USER_FIELDS.contains(&field) {
                    if field == "token"
                        && session_token.is_some_and(|expected| value.as_str() == Some(expected))
                    {
                        found_session = true;
                        continue;
                    }
                    return Err(BrokerError::Credential {
                        user: user_name,
                        field: field.to_string(),
                    });
                }
            }
        }
    }
    if session_token.is_some() && !found_session {
        return Err(BrokerError::MissingSessionCredential);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_config_is_valid_and_credential_free() {
        let yaml = brokered_kubeconfig("https://127.0.0.1:8443", "QkFTRTY0Q0E=");
        validate_brokered_kubeconfig(&yaml).expect("generated config must validate");

        let doc: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).unwrap();
        // Server points at the proxy; CA present.
        assert_eq!(
            doc["clusters"][0]["cluster"]["server"].as_str(),
            Some("https://127.0.0.1:8443")
        );
        assert_eq!(
            doc["clusters"][0]["cluster"]["certificate-authority-data"].as_str(),
            Some("QkFTRTY0Q0E=")
        );
        // User is empty.
        assert!(doc["users"][0]["user"].as_mapping().unwrap().is_empty());
    }

    #[test]
    fn generated_session_config_accepts_only_the_guard_session_bearer() {
        let yaml = brokered_kubeconfig_with_session(
            "https://127.0.0.1:8443",
            "QkFTRTY0Q0E=",
            "guard-session",
        );
        validate_brokered_kubeconfig_with_session(&yaml, "guard-session").unwrap();
        assert!(validate_brokered_kubeconfig(&yaml).is_err());
        assert!(validate_brokered_kubeconfig_with_session(&yaml, "other-session").is_err());
        assert_eq!(
            validate_brokered_kubeconfig_with_session(&yaml, "invalid session").unwrap_err(),
            BrokerError::InvalidSessionCredential
        );
    }

    #[test]
    fn rejects_token() {
        let yaml = r#"
apiVersion: v1
kind: Config
clusters: [{name: c, cluster: {server: "https://x"}}]
users:
  - name: real
    user:
      token: "abc123"
"#;
        let err = validate_brokered_kubeconfig(yaml).unwrap_err();
        assert_eq!(
            err,
            BrokerError::Credential {
                user: "real".to_string(),
                field: "token".to_string()
            }
        );
    }

    #[test]
    fn rejects_exec_plugin() {
        let yaml = r#"
apiVersion: v1
kind: Config
users:
  - name: aws
    user:
      exec:
        command: aws-iam-authenticator
"#;
        let err = validate_brokered_kubeconfig(yaml).unwrap_err();
        assert!(matches!(err, BrokerError::Credential { field, .. } if field == "exec"));
    }

    #[test]
    fn rejects_client_cert_and_key() {
        for field in [
            "client-certificate-data",
            "client-key-data",
            "auth-provider",
        ] {
            let yaml = format!(
                "apiVersion: v1\nkind: Config\nusers:\n  - name: u\n    user:\n      {field}: x\n"
            );
            let err = validate_brokered_kubeconfig(&yaml).unwrap_err();
            assert!(
                matches!(err, BrokerError::Credential { field: f, .. } if f == field),
                "field {field} should be rejected"
            );
        }
    }

    #[test]
    fn empty_user_is_ok() {
        let yaml = "apiVersion: v1\nkind: Config\nusers:\n  - name: guard-agent\n    user: {}\n";
        assert!(validate_brokered_kubeconfig(yaml).is_ok());
    }

    #[test]
    fn malformed_yaml_is_parse_error() {
        let err = validate_brokered_kubeconfig("clusters: [unterminated").unwrap_err();
        assert!(matches!(err, BrokerError::Parse(_)));
    }
}
