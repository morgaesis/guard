//! Brokered kubeconfig: the agent-facing config the proxy hands out. It points
//! only at the proxy. The daemon holds the real upstream credentials and
//! injects them when it re-originates each request. Every config carries either
//! a proxy transport bearer or a Guard session bearer, which the proxy consumes
//! and never forwards. Generation and validation live here; validation is the
//! containment-critical check.

use std::fmt;

use serde::Deserialize;

/// Why a kubeconfig is not a safe brokered config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerError {
    /// The YAML could not be parsed.
    Parse(String),
    /// The document is not the exact closed brokered schema.
    Schema(String),
    MissingSessionCredential,
    InvalidSessionCredential,
    SessionCredentialMismatch,
}

impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BrokerError::Parse(e) => write!(f, "could not parse kubeconfig: {e}"),
            BrokerError::Schema(e) => write!(f, "brokered kubeconfig schema is invalid: {e}"),
            BrokerError::MissingSessionCredential => {
                write!(f, "brokered kubeconfig is missing its Guard session bearer")
            }
            BrokerError::InvalidSessionCredential => {
                write!(f, "Guard session bearer is not valid for an HTTP header")
            }
            BrokerError::SessionCredentialMismatch => {
                write!(
                    f,
                    "brokered kubeconfig carries a different Guard session bearer"
                )
            }
        }
    }
}

impl std::error::Error for BrokerError {}

/// Build a brokered kubeconfig pointing at `proxy_url`, trusting the proxy's CA
/// (`ca_data_b64`, the base64 of the CA's PEM), authenticated by one generated
/// proxy transport bearer. The client uses this verbatim; neither the bearer
/// nor the config can authenticate directly to the real API server.
pub fn brokered_kubeconfig(proxy_url: &str, ca_data_b64: &str, transport_bearer: &str) -> String {
    brokered_kubeconfig_inner(proxy_url, ca_data_b64, transport_bearer)
}

/// Build a brokered kubeconfig whose only client credential is a Guard session
/// bearer. It authenticates to the loopback proxy and is never forwarded to the
/// upstream API server.
pub fn brokered_kubeconfig_with_session(
    proxy_url: &str,
    ca_data_b64: &str,
    session_token: &str,
) -> String {
    brokered_kubeconfig_inner(proxy_url, ca_data_b64, session_token)
}

fn brokered_kubeconfig_inner(proxy_url: &str, ca_data_b64: &str, bearer: &str) -> String {
    // Client-go requires a user credential to avoid an interactive Basic-auth
    // prompt. This bearer authenticates only to the loopback Guard proxy.
    let user = serde_json::json!({ "token": bearer });
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokeredConfig {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    clusters: Vec<BrokeredClusterEntry>,
    contexts: Vec<BrokeredContextEntry>,
    #[serde(rename = "current-context")]
    current_context: String,
    users: Vec<BrokeredUserEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokeredClusterEntry {
    name: String,
    cluster: BrokeredCluster,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokeredCluster {
    server: String,
    #[serde(rename = "certificate-authority-data")]
    certificate_authority_data: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokeredContextEntry {
    name: String,
    context: BrokeredContext,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokeredContext {
    cluster: String,
    user: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokeredUserEntry {
    name: String,
    user: BrokeredUser,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokeredUser {
    token: Option<String>,
}

/// Validate the exact closed schema emitted by [`brokered_kubeconfig`]. The
/// sole endpoint must be loopback HTTPS, every object and field is singular and
/// named by Guard, and the sole bearer must be valid for an HTTP header.
pub fn validate_brokered_kubeconfig(yaml: &str) -> Result<(), BrokerError> {
    validate_brokered_kubeconfig_inner(yaml, None)
}

/// Validate a brokered config that contains exactly the supplied proxy or
/// Guard session bearer and no other credential-bearing field.
pub fn validate_brokered_kubeconfig_with_session(
    yaml: &str,
    session_token: &str,
) -> Result<(), BrokerError> {
    if !valid_guard_session_token(session_token) {
        return Err(BrokerError::InvalidSessionCredential);
    }
    validate_brokered_kubeconfig_inner(yaml, Some(session_token))
}

/// Validate the closed brokered schema and require the exact endpoint, CA, and
/// bearer emitted by one active Guard proxy. This is the fixed-child boundary:
/// a structurally valid document for any other proxy still carries authority.
pub fn validate_brokered_kubeconfig_matches(
    yaml: &str,
    expected_yaml: &str,
) -> Result<(), BrokerError> {
    validate_brokered_kubeconfig(yaml)?;
    validate_brokered_kubeconfig(expected_yaml)?;
    let actual: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(yaml).map_err(|error| BrokerError::Parse(error.to_string()))?;
    let expected: serde_yaml_ng::Value = serde_yaml_ng::from_str(expected_yaml)
        .map_err(|error| BrokerError::Parse(error.to_string()))?;
    if actual != expected {
        return Err(BrokerError::Schema(
            "endpoint, certificate authority, or bearer does not match an active Guard proxy"
                .to_string(),
        ));
    }
    Ok(())
}

pub fn valid_guard_session_token(token: &str) -> bool {
    !token.is_empty() && token.len() <= 256 && token.bytes().all(|byte| matches!(byte, b'!'..=b'~'))
}

fn validate_brokered_kubeconfig_inner(
    yaml: &str,
    session_token: Option<&str>,
) -> Result<(), BrokerError> {
    let document: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(yaml).map_err(|error| BrokerError::Parse(error.to_string()))?;
    let config: BrokeredConfig = serde_yaml_ng::from_value(document)
        .map_err(|error| BrokerError::Schema(error.to_string()))?;
    if config.api_version != "v1"
        || config.kind != "Config"
        || config.current_context != "guard-proxy"
        || config.clusters.len() != 1
        || config.contexts.len() != 1
        || config.users.len() != 1
    {
        return Err(BrokerError::Schema(
            "expected one Guard cluster, context, and user".to_string(),
        ));
    }

    let cluster = &config.clusters[0];
    let context = &config.contexts[0];
    let user = &config.users[0];
    if cluster.name != "guard-proxy"
        || context.name != "guard-proxy"
        || context.context.cluster != "guard-proxy"
        || context.context.user != "guard-agent"
        || user.name != "guard-agent"
    {
        return Err(BrokerError::Schema(
            "Guard object names and references must match the generated schema".to_string(),
        ));
    }
    super::validate_brokered_proxy_origin(&cluster.cluster.server).map_err(BrokerError::Schema)?;
    if cluster.cluster.certificate_authority_data.trim().is_empty() {
        return Err(BrokerError::Schema(
            "certificate authority data must not be empty".to_string(),
        ));
    }

    let Some(actual_token) = user.user.token.as_deref() else {
        return Err(if session_token.is_some() {
            BrokerError::MissingSessionCredential
        } else {
            BrokerError::Schema("the Guard user must carry a proxy bearer".to_string())
        });
    };
    if !valid_guard_session_token(actual_token) {
        return Err(BrokerError::InvalidSessionCredential);
    }
    if session_token.is_some_and(|expected| actual_token != expected) {
        return Err(BrokerError::SessionCredentialMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn fixture_marker(label: &str) -> String {
        format!("{label}-{:016x}", rand::random::<u64>())
    }

    fn fixture_ca_data() -> String {
        base64::engine::general_purpose::STANDARD.encode(fixture_marker("ca"))
    }

    fn generated_config() -> String {
        brokered_kubeconfig(
            "https://127.0.0.1:8443",
            &fixture_ca_data(),
            &fixture_marker("transport"),
        )
    }

    fn generated_document() -> serde_yaml_ng::Value {
        serde_yaml_ng::from_str(&generated_config()).unwrap()
    }

    #[test]
    fn generated_config_contains_only_the_proxy_transport_bearer() {
        let ca_data = fixture_ca_data();
        let transport = fixture_marker("transport");
        let yaml = brokered_kubeconfig("https://127.0.0.1:8443", &ca_data, &transport);
        validate_brokered_kubeconfig(&yaml).expect("generated config must validate");

        let doc: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).unwrap();
        // Server points at the proxy; CA present.
        assert_eq!(
            doc["clusters"][0]["cluster"]["server"].as_str(),
            Some("https://127.0.0.1:8443")
        );
        assert_eq!(
            doc["clusters"][0]["cluster"]["certificate-authority-data"].as_str(),
            Some(ca_data.as_str())
        );
        // The user carries only the generated proxy transport bearer, so
        // client-go sends the request instead of prompting for Basic auth.
        assert_eq!(
            doc["users"][0]["user"]["token"].as_str(),
            Some(transport.as_str())
        );
        // A session-expecting validation refuses a different bearer.
        assert!(
            validate_brokered_kubeconfig_with_session(&yaml, &fixture_marker("session")).is_err()
        );
    }

    #[test]
    fn generated_session_config_accepts_only_the_guard_session_bearer() {
        let session = fixture_marker("session");
        let yaml = brokered_kubeconfig_with_session(
            "https://127.0.0.1:8443",
            &fixture_ca_data(),
            &session,
        );
        validate_brokered_kubeconfig_with_session(&yaml, &session).unwrap();
        validate_brokered_kubeconfig(&yaml).unwrap();
        assert_eq!(
            validate_brokered_kubeconfig_with_session(&yaml, &fixture_marker("other")).unwrap_err(),
            BrokerError::SessionCredentialMismatch
        );
        let invalid_session = format!("{} invalid", fixture_marker("session"));
        assert_eq!(
            validate_brokered_kubeconfig_with_session(&yaml, &invalid_session).unwrap_err(),
            BrokerError::InvalidSessionCredential
        );
    }

    #[test]
    fn structural_validation_accepts_a_well_formed_guard_bearer() {
        let session = fixture_marker("session");
        let yaml = brokered_kubeconfig_with_session(
            "https://127.0.0.1:8443",
            &fixture_ca_data(),
            &session,
        );
        validate_brokered_kubeconfig(&yaml).unwrap();
    }

    #[test]
    fn rejects_every_alternate_user_credential_location() {
        for field in [
            "tokenFile",
            "client-certificate",
            "client-certificate-data",
            "client-key",
            "client-key-data",
            "exec",
            "auth-provider",
            "username",
            "password",
        ] {
            let mut document = generated_document();
            document["users"][0]["user"]
                .as_mapping_mut()
                .unwrap()
                .insert(
                    serde_yaml_ng::Value::String(field.to_string()),
                    serde_yaml_ng::Value::String(fixture_marker("credential")),
                );
            let yaml = serde_yaml_ng::to_string(&document).unwrap();
            assert!(
                validate_brokered_kubeconfig(&yaml).is_err(),
                "field {field}"
            );
        }
    }

    #[test]
    fn rejects_cluster_proxy_extensions_unknown_fields_and_url_userinfo() {
        for field in ["proxy-url", "extensions", "insecure-skip-tls-verify"] {
            let mut document = generated_document();
            document["clusters"][0]["cluster"]
                .as_mapping_mut()
                .unwrap()
                .insert(
                    serde_yaml_ng::Value::String(field.to_string()),
                    serde_yaml_ng::Value::String(fixture_marker("authority")),
                );
            let yaml = serde_yaml_ng::to_string(&document).unwrap();
            assert!(
                validate_brokered_kubeconfig(&yaml).is_err(),
                "field {field}"
            );
        }

        let mut document = generated_document();
        document["clusters"][0]["cluster"]["server"] = serde_yaml_ng::Value::String(format!(
            "https://{}@127.0.0.1:8443",
            fixture_marker("user")
        ));
        let yaml = serde_yaml_ng::to_string(&document).unwrap();
        assert!(validate_brokered_kubeconfig(&yaml).is_err());
    }

    #[test]
    fn rejects_top_level_extensions_extra_objects_and_empty_users() {
        let mut extensions = generated_document();
        extensions.as_mapping_mut().unwrap().insert(
            serde_yaml_ng::Value::String("extensions".to_string()),
            serde_yaml_ng::Value::Sequence(Vec::new()),
        );
        assert!(
            validate_brokered_kubeconfig(&serde_yaml_ng::to_string(&extensions).unwrap()).is_err()
        );

        for collection in ["clusters", "contexts", "users"] {
            let mut document = generated_document();
            let sequence = document[collection].as_sequence_mut().unwrap();
            sequence.push(sequence[0].clone());
            assert!(
                validate_brokered_kubeconfig(&serde_yaml_ng::to_string(&document).unwrap())
                    .is_err(),
                "collection {collection}"
            );
        }

        let mut empty_user = generated_document();
        empty_user["users"][0]["user"] =
            serde_yaml_ng::Value::Mapping(serde_yaml_ng::Mapping::new());
        let empty_user_yaml = serde_yaml_ng::to_string(&empty_user).unwrap();
        assert!(matches!(
            validate_brokered_kubeconfig(&empty_user_yaml),
            Err(BrokerError::Schema(_))
        ));
        assert_eq!(
            validate_brokered_kubeconfig_with_session(&empty_user_yaml, &fixture_marker("session"))
                .unwrap_err(),
            BrokerError::MissingSessionCredential
        );
    }

    #[test]
    fn exact_match_binds_endpoint_and_certificate_authority() {
        let expected = generated_config();
        validate_brokered_kubeconfig_matches(&expected, &expected).unwrap();

        for field in ["server", "certificate-authority-data"] {
            let mut document: serde_yaml_ng::Value = serde_yaml_ng::from_str(&expected).unwrap();
            document["clusters"][0]["cluster"][field] =
                serde_yaml_ng::Value::String(if field == "server" {
                    "https://127.0.0.1:9443".to_string()
                } else {
                    fixture_ca_data()
                });
            let yaml = serde_yaml_ng::to_string(&document).unwrap();
            assert!(validate_brokered_kubeconfig_matches(&yaml, &expected).is_err());
        }
    }

    #[test]
    fn malformed_yaml_is_parse_error() {
        let err = validate_brokered_kubeconfig("clusters: [unterminated").unwrap_err();
        assert!(matches!(err, BrokerError::Parse(_)));
    }

    #[test]
    fn well_formed_documents_with_the_wrong_shape_are_schema_errors() {
        let error = validate_brokered_kubeconfig("clusters: fixture").unwrap_err();
        assert!(matches!(error, BrokerError::Schema(_)));
    }
}
