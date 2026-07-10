//! Secret backend backed by Infisical (HTTP API, Universal Auth).

use anyhow::{bail, Result};
use async_trait::async_trait;
use guard::principal::PrincipalKey;
use std::env;
use tokio::sync::RwLock;

use super::{warn_if_cleartext_url, SecretBackend};

/// Secret backend backed by Infisical (HTTP API, Universal Auth machine
/// identity).
///
/// Each principal maps to a secret folder at `/guard/<segment>`; the secret
/// key is the secret name within that folder (Infisical secret names cannot
/// contain `/`). Configuration comes from the `INFISICAL_*` environment.
///
/// Auth is Universal Auth: a client id/secret are exchanged for a short-lived
/// bearer access token, cached in `token` and refreshed once on a 401/403.
/// Secret values and the access token are never logged or placed in error
/// context.
pub struct InfisicalBackend {
    client: reqwest::Client,
    /// API base URL, no trailing slash (default `https://app.infisical.com`).
    url: String,
    client_id: String,
    client_secret: String,
    /// Infisical project (workspace) id.
    project_id: String,
    /// Infisical environment slug (default `prod`).
    environment: String,
    /// Cached bearer access token. Cleared and re-fetched once on a 401/403.
    token: RwLock<Option<String>>,
}

impl InfisicalBackend {
    /// Construct from the `INFISICAL_*` environment. Bails clearly if required
    /// configuration is missing. No secret material is included in error text.
    pub fn new() -> Result<Self> {
        let url = env::var("INFISICAL_API_URL")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "https://app.infisical.com".to_string())
            .trim_end_matches('/')
            .to_string();
        warn_if_cleartext_url(&url, "INFISICAL_API_URL");

        let client_id = env::var("INFISICAL_CLIENT_ID")
            .ok()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "INFISICAL_CLIENT_ID is not set; required for the infisical backend"
                )
            })?;
        let client_secret = env::var("INFISICAL_CLIENT_SECRET")
            .ok()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "INFISICAL_CLIENT_SECRET is not set; required for the infisical backend"
                )
            })?;
        let project_id = env::var("INFISICAL_PROJECT_ID")
            .ok()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "INFISICAL_PROJECT_ID is not set; required for the infisical backend"
                )
            })?;
        let environment = env::var("INFISICAL_ENVIRONMENT")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "prod".to_string());

        let client = reqwest::Client::builder().build().map_err(|e| {
            anyhow::anyhow!("failed to build HTTP client for infisical backend: {e}")
        })?;

        Ok(Self {
            client,
            url,
            client_id,
            client_secret,
            project_id,
            environment,
            token: RwLock::new(None),
        })
    }

    /// The per-principal secret folder path: `/guard/<segment>`.
    fn principal_path(&self, principal: &PrincipalKey) -> String {
        format!("/guard/{}", principal.segment())
    }

    /// Resolve a usable bearer access token, logging in on first use.
    async fn token(&self) -> Result<String> {
        if let Some(tok) = self.token.read().await.clone() {
            return Ok(tok);
        }
        self.authenticate().await
    }

    /// Perform Universal Auth login and cache the access token.
    async fn authenticate(&self) -> Result<String> {
        let url = format!("{}/api/v1/auth/universal-auth/login", self.url);
        let body = serde_json::json!({
            "clientId": self.client_id,
            "clientSecret": self.client_secret,
        });
        let resp = self.client.post(&url).json(&body).send().await?;
        if !resp.status().is_success() {
            // Body may echo submitted credentials; never include it.
            bail!(
                "infisical universal-auth login failed with status {}",
                resp.status()
            );
        }
        let json: serde_json::Value = resp.json().await?;
        let token = json
            .get("accessToken")
            .and_then(|t| t.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("infisical login response missing access token"))?;
        *self.token.write().await = Some(token.clone());
        Ok(token)
    }

    /// Clear the cached token so the next call re-authenticates.
    async fn clear_token(&self) {
        *self.token.write().await = None;
    }

    /// Issue an authenticated request built by `make`, retrying once after a
    /// fresh login on a 401/403. `make` receives the current bearer token and
    /// must produce a ready-to-send `RequestBuilder` with the auth header set.
    async fn send_authed<F>(&self, make: F) -> Result<reqwest::Response>
    where
        F: Fn(&str) -> reqwest::RequestBuilder,
    {
        let token = self.token().await?;
        let resp = make(&token).send().await?;
        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            self.clear_token().await;
            let token = self.authenticate().await?;
            let resp = make(&token).send().await?;
            return Ok(resp);
        }
        Ok(resp)
    }
}

#[async_trait]
impl SecretBackend for InfisicalBackend {
    fn name(&self) -> &str {
        "infisical"
    }

    async fn get(&self, principal: &PrincipalKey, key: &str) -> Result<Option<String>> {
        let secret_path = self.principal_path(principal);
        let url = format!("{}/api/v3/secrets/raw/{}", self.url, key);
        let resp = self
            .send_authed(|tok| {
                self.client.get(&url).bearer_auth(tok).query(&[
                    ("workspaceId", self.project_id.as_str()),
                    ("environment", self.environment.as_str()),
                    ("secretPath", secret_path.as_str()),
                ])
            })
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            bail!("infisical get failed with status {}", resp.status());
        }
        let json: serde_json::Value = resp.json().await?;
        let value = json
            .get("secret")
            .and_then(|s| s.get("secretValue"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        Ok(value)
    }

    async fn list(&self, principal: &PrincipalKey) -> Result<Vec<String>> {
        let secret_path = self.principal_path(principal);
        let url = format!("{}/api/v3/secrets/raw", self.url);
        let resp = self
            .send_authed(|tok| {
                self.client.get(&url).bearer_auth(tok).query(&[
                    ("workspaceId", self.project_id.as_str()),
                    ("environment", self.environment.as_str()),
                    ("secretPath", secret_path.as_str()),
                ])
            })
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(Vec::new());
        }
        if !resp.status().is_success() {
            bail!("infisical list failed with status {}", resp.status());
        }
        let json: serde_json::Value = resp.json().await?;
        let mut keys: Vec<String> = json
            .get("secrets")
            .and_then(|s| s.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|s| s.get("secretKey").and_then(|k| k.as_str()))
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default();
        keys.sort();
        keys.dedup();
        Ok(keys)
    }

    /// Infisical has no generic way to enumerate principal folders without
    /// knowing them in advance, so the aggregate admin view is best-effort and
    /// returns nothing (matching `EnvBackend`'s inability to recover every
    /// namespace). Per-caller `list`/`get` are unaffected.
    async fn list_all(&self) -> Result<Vec<(PrincipalKey, String)>> {
        Ok(Vec::new())
    }

    async fn set(&self, principal: &PrincipalKey, key: &str, value: &str) -> Result<()> {
        let secret_path = self.principal_path(principal);
        let url = format!("{}/api/v3/secrets/raw/{}", self.url, key);
        let body = serde_json::json!({
            "workspaceId": self.project_id,
            "environment": self.environment,
            "secretValue": value,
            "secretPath": secret_path,
        });
        let resp = self
            .send_authed(|tok| self.client.post(&url).bearer_auth(tok).json(&body))
            .await?;
        if resp.status().is_success() {
            return Ok(());
        }
        // Infisical returns 409 Conflict when creating a secret that already
        // exists. Fall back to an update via PATCH on that specific conflict
        // only -- treating every 4xx as "already exists" would retry (and
        // misreport) genuine errors like a bad request, an auth/permission
        // failure, or a validation error as if they were update conflicts,
        // hiding the real cause from whoever is debugging the failure.
        if resp.status() == reqwest::StatusCode::CONFLICT {
            let resp = self
                .send_authed(|tok| self.client.patch(&url).bearer_auth(tok).json(&body))
                .await?;
            if resp.status().is_success() {
                return Ok(());
            }
            // Neither request body nor response is included; both may carry the
            // secret value.
            bail!(
                "infisical set (update) failed with status {}",
                resp.status()
            );
        }
        bail!("infisical set failed with status {}", resp.status());
    }

    async fn delete(&self, principal: &PrincipalKey, key: &str) -> Result<()> {
        let secret_path = self.principal_path(principal);
        let url = format!("{}/api/v3/secrets/raw/{}", self.url, key);
        let body = serde_json::json!({
            "workspaceId": self.project_id,
            "environment": self.environment,
            "secretPath": secret_path,
        });
        let resp = self
            .send_authed(|tok| self.client.delete(&url).bearer_auth(tok).json(&body))
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND || resp.status().is_success() {
            return Ok(());
        }
        bail!("infisical delete failed with status {}", resp.status());
    }
}

#[cfg(test)]
mod tests {
    use super::InfisicalBackend;
    use guard::principal::PrincipalKey;
    use tokio::sync::RwLock;

    fn p(uid: u32) -> PrincipalKey {
        PrincipalKey::from_uid(uid)
    }

    fn infisical_test_backend() -> InfisicalBackend {
        InfisicalBackend {
            client: reqwest::Client::new(),
            url: "https://app.infisical.com".to_string(),
            client_id: "id".to_string(),
            client_secret: "secret".to_string(),
            project_id: "proj".to_string(),
            environment: "prod".to_string(),
            token: RwLock::new(None),
        }
    }

    #[test]
    fn infisical_principal_path_namespaces_by_uid() {
        let backend = infisical_test_backend();
        // uid 1000 -> secretPath /guard/u1000; the key is a separate secret name.
        assert_eq!(backend.principal_path(&p(1000)), "/guard/u1000");
        let sid = PrincipalKey::from_sid("S-1-5-21-1-2-3-1001");
        assert_eq!(backend.principal_path(&sid), "/guard/S_1_5_21_1_2_3_1001");
    }
}
