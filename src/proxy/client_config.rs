//! Closed generic-client configuration for a loopback API proxy.
//!
//! The daemon emits this document for clients that cannot consume a
//! kubeconfig. It contains only the proxy origin, the generated proxy CA, and a
//! generated transport bearer that is valid only at the local proxy.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::kubeconfig::valid_guard_session_token;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokeredClientConfig {
    version: u8,
    base_url: String,
    certificate_authority_pem: String,
    authorization: BrokeredAuthorization,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokeredAuthorization {
    scheme: String,
    token: String,
}

/// Why a generic client configuration is not safe to hand to a worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientConfigError {
    Parse(String),
    Schema(String),
}

impl fmt::Display for ClientConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) => write!(formatter, "could not parse client config: {error}"),
            Self::Schema(error) => {
                write!(
                    formatter,
                    "brokered client config schema is invalid: {error}"
                )
            }
        }
    }
}

impl std::error::Error for ClientConfigError {}

/// Build the exact generic-client document emitted by the daemon.
pub fn brokered_client_config(
    proxy_url: &str,
    certificate_authority_pem: &str,
    transport_bearer: &str,
) -> String {
    serde_json::to_string_pretty(&BrokeredClientConfig {
        version: 1,
        base_url: proxy_url.to_string(),
        certificate_authority_pem: certificate_authority_pem.to_string(),
        authorization: BrokeredAuthorization {
            scheme: "Bearer".to_string(),
            token: transport_bearer.to_string(),
        },
    })
    .expect("serialize brokered client configuration")
}

/// Validate the exact closed schema emitted by [`brokered_client_config`].
pub fn validate_brokered_client_config(json: &str) -> Result<(), ClientConfigError> {
    let config: BrokeredClientConfig =
        serde_json::from_str(json).map_err(|error| ClientConfigError::Parse(error.to_string()))?;
    if config.version != 1 {
        return Err(ClientConfigError::Schema("version must be 1".to_string()));
    }
    super::validate_brokered_proxy_origin(&config.base_url).map_err(ClientConfigError::Schema)?;
    reqwest::Certificate::from_pem(config.certificate_authority_pem.as_bytes()).map_err(
        |error| ClientConfigError::Schema(format!("certificate authority PEM is invalid: {error}")),
    )?;
    if config.authorization.scheme != "Bearer" {
        return Err(ClientConfigError::Schema(
            "authorization scheme must be Bearer".to_string(),
        ));
    }
    if !valid_guard_session_token(&config.authorization.token) {
        return Err(ClientConfigError::Schema(
            "transport bearer is not valid for an HTTP header".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::tls::ProxyTls;

    fn generated_config() -> String {
        let tls = ProxyTls::generate().expect("generate test proxy CA");
        brokered_client_config(
            "https://127.0.0.1:8443",
            tls.ca_pem(),
            &format!("transport-{:016x}", rand::random::<u64>()),
        )
    }

    #[test]
    fn generated_document_matches_closed_schema() {
        validate_brokered_client_config(&generated_config()).unwrap();
    }

    #[test]
    fn rejects_unknown_fields() {
        let mut document: serde_json::Value = serde_json::from_str(&generated_config()).unwrap();
        document["credential_helper"] = serde_json::json!("external-command");
        assert!(validate_brokered_client_config(&document.to_string()).is_err());
    }

    #[test]
    fn rejects_non_loopback_origins() {
        let mut document: serde_json::Value = serde_json::from_str(&generated_config()).unwrap();
        document["base_url"] = serde_json::json!("https://example.com:8443");
        assert!(validate_brokered_client_config(&document.to_string()).is_err());
    }
}
