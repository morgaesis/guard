//! Secret backend backed by HashiCorp Vault (KV v2 over the HTTP API).

use anyhow::{bail, Result};
use async_trait::async_trait;
use guard::principal::PrincipalKey;
use std::env;
use tokio::sync::RwLock;

use super::{warn_if_cleartext_url, SecretBackend};

/// Secret backend backed by HashiCorp Vault (KV v2 engine over the HTTP API).
///
/// Secrets are stored per-principal at `guard/<segment>/<key>`, each as a KV v2
/// secret with a single field named `value`. Configuration comes from the
/// vendor-standard `VAULT_*` environment variables.
///
/// Auth uses either a static `VAULT_TOKEN` or AppRole login. The resolved
/// client token is cached in `token` and refreshed once on a 401/403; secret
/// values and the token itself are never logged or placed in error context.
pub struct VaultBackend {
    client: reqwest::Client,
    /// Base address, e.g. `https://vault.example.com:8200`, no trailing slash.
    addr: String,
    /// KV v2 mount point (default `secret`).
    mount: String,
    /// Optional Vault namespace sent as `X-Vault-Namespace`.
    namespace: Option<String>,
    /// How to obtain a client token.
    auth: VaultAuth,
    /// Cached client token. Cleared and re-fetched once on a 401/403.
    token: RwLock<Option<String>>,
}

/// How a [`VaultBackend`] obtains its client token.
enum VaultAuth {
    /// A static token used directly (`VAULT_TOKEN`).
    Token(String),
    /// AppRole login via `role_id` + `secret_id`.
    AppRole { role_id: String, secret_id: String },
}

impl VaultBackend {
    /// Construct from the `VAULT_*` environment. Bails clearly if required
    /// configuration is missing. No secret material is included in error text.
    pub fn new() -> Result<Self> {
        let addr = match env::var("VAULT_ADDR") {
            Ok(a) if !a.trim().is_empty() => a.trim_end_matches('/').to_string(),
            _ => bail!("VAULT_ADDR is not set; required for the vault backend"),
        };
        warn_if_cleartext_url(&addr, "VAULT_ADDR");

        let auth = match env::var("VAULT_TOKEN") {
            Ok(t) if !t.is_empty() => VaultAuth::Token(t),
            _ => {
                let role_id = env::var("VAULT_ROLE_ID").ok().filter(|s| !s.is_empty());
                let secret_id = env::var("VAULT_SECRET_ID").ok().filter(|s| !s.is_empty());
                match (role_id, secret_id) {
                    (Some(role_id), Some(secret_id)) => VaultAuth::AppRole { role_id, secret_id },
                    _ => bail!(
                        "vault backend requires VAULT_TOKEN, or both VAULT_ROLE_ID and VAULT_SECRET_ID for AppRole login"
                    ),
                }
            }
        };

        let mount = env::var("VAULT_KV_MOUNT")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "secret".to_string());

        let namespace = env::var("VAULT_NAMESPACE").ok().filter(|s| !s.is_empty());

        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build HTTP client for vault backend: {e}"))?;

        Ok(Self {
            client,
            addr,
            mount,
            namespace,
            auth,
            token: RwLock::new(None),
        })
    }

    /// The per-principal data path component: `guard/<segment>`.
    fn principal_path(&self, principal: &PrincipalKey) -> String {
        format!("guard/{}", principal.segment())
    }

    /// Apply the Vault namespace header when configured.
    fn with_namespace(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.namespace {
            Some(ns) => builder.header("X-Vault-Namespace", ns),
            None => builder,
        }
    }

    /// Resolve a usable client token, performing AppRole login on first use.
    async fn token(&self) -> Result<String> {
        if let Some(tok) = self.token.read().await.clone() {
            return Ok(tok);
        }
        self.authenticate().await
    }

    /// Obtain a fresh client token (static or via AppRole login) and cache it.
    async fn authenticate(&self) -> Result<String> {
        let token = match &self.auth {
            VaultAuth::Token(t) => t.clone(),
            VaultAuth::AppRole { role_id, secret_id } => {
                let url = format!("{}/v1/auth/approle/login", self.addr);
                let body = serde_json::json!({ "role_id": role_id, "secret_id": secret_id });
                let resp = self
                    .with_namespace(self.client.post(&url).json(&body))
                    .send()
                    .await?;
                if !resp.status().is_success() {
                    // Body may echo submitted credentials; never include it.
                    bail!("vault AppRole login failed with status {}", resp.status());
                }
                let json: serde_json::Value = resp.json().await?;
                json.get("auth")
                    .and_then(|a| a.get("client_token"))
                    .and_then(|t| t.as_str())
                    .map(|s| s.to_string())
                    .ok_or_else(|| {
                        anyhow::anyhow!("vault AppRole login response missing client token")
                    })?
            }
        };
        *self.token.write().await = Some(token.clone());
        Ok(token)
    }

    /// Clear the cached token so the next call re-authenticates.
    async fn clear_token(&self) {
        *self.token.write().await = None;
    }

    /// Issue an authenticated request built by `make`, retrying once after a
    /// fresh authentication on a 401/403. `make` receives the current token and
    /// must produce a ready-to-send `RequestBuilder` (namespace header applied).
    async fn send_authed<F>(&self, make: F) -> Result<reqwest::Response>
    where
        F: Fn(&str) -> reqwest::RequestBuilder,
    {
        let token = self.token().await?;
        let resp = self
            .with_namespace(make(&token).header("X-Vault-Token", &token))
            .send()
            .await?;
        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            self.clear_token().await;
            let token = self.authenticate().await?;
            let resp = self
                .with_namespace(make(&token).header("X-Vault-Token", &token))
                .send()
                .await?;
            return Ok(resp);
        }
        Ok(resp)
    }

    /// LIST the immediate keys under a KV v2 metadata path. A 404 yields an
    /// empty list. Returns the raw `.data.keys` entries (sub-folders end in `/`).
    async fn list_metadata(&self, path: &str) -> Result<Vec<String>> {
        let url = format!("{}/v1/{}/metadata/{}", self.addr, self.mount, path);
        let resp = self
            .send_authed(|_tok| {
                self.client
                    .request(reqwest::Method::from_bytes(b"LIST").unwrap(), &url)
            })
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(Vec::new());
        }
        if !resp.status().is_success() {
            bail!("vault LIST {} failed with status {}", path, resp.status());
        }
        let json: serde_json::Value = resp.json().await?;
        let keys = json
            .get("data")
            .and_then(|d| d.get("keys"))
            .and_then(|k| k.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        Ok(keys)
    }
}

#[async_trait]
impl SecretBackend for VaultBackend {
    fn name(&self) -> &str {
        "vault"
    }

    async fn get(&self, principal: &PrincipalKey, key: &str) -> Result<Option<String>> {
        let path = self.principal_path(principal);
        let url = format!("{}/v1/{}/data/{}/{}", self.addr, self.mount, path, key);
        let resp = self.send_authed(|_tok| self.client.get(&url)).await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            bail!("vault get failed with status {}", resp.status());
        }
        let json: serde_json::Value = resp.json().await?;
        let value = json
            .get("data")
            .and_then(|d| d.get("data"))
            .and_then(|d| d.get("value"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        Ok(value)
    }

    async fn list(&self, principal: &PrincipalKey) -> Result<Vec<String>> {
        let path = self.principal_path(principal);
        let mut keys: Vec<String> = self
            .list_metadata(&path)
            .await?
            .into_iter()
            // Drop sub-folder entries (KV v2 marks them with a trailing slash).
            .filter(|k| !k.ends_with('/'))
            .collect();
        keys.sort();
        keys.dedup();
        Ok(keys)
    }

    async fn list_all(&self) -> Result<Vec<(PrincipalKey, String)>> {
        // Enumerate principal segments under `guard/`, then keys under each.
        let segments = self.list_metadata("guard").await?;
        let mut out = Vec::new();
        for segment in segments {
            let segment = segment.trim_end_matches('/').to_string();
            if segment.is_empty() {
                continue;
            }
            let path = format!("guard/{}", segment);
            let keys = self.list_metadata(&path).await?;
            let principal = PrincipalKey::from_raw(segment);
            for key in keys {
                if key.ends_with('/') {
                    continue;
                }
                out.push((principal.clone(), key));
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    async fn set(&self, principal: &PrincipalKey, key: &str, value: &str) -> Result<()> {
        let path = self.principal_path(principal);
        let url = format!("{}/v1/{}/data/{}/{}", self.addr, self.mount, path, key);
        let body = serde_json::json!({ "data": { "value": value } });
        let resp = self
            .send_authed(|_tok| self.client.post(&url).json(&body))
            .await?;
        if !resp.status().is_success() {
            // The request body carries the secret value; never echo it.
            bail!("vault set failed with status {}", resp.status());
        }
        Ok(())
    }

    async fn delete(&self, principal: &PrincipalKey, key: &str) -> Result<()> {
        let path = self.principal_path(principal);
        // Delete all versions by removing the metadata.
        let url = format!("{}/v1/{}/metadata/{}/{}", self.addr, self.mount, path, key);
        let resp = self.send_authed(|_tok| self.client.delete(&url)).await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND || resp.status().is_success() {
            return Ok(());
        }
        bail!("vault delete failed with status {}", resp.status());
    }
}

#[cfg(test)]
mod tests {
    use super::{VaultAuth, VaultBackend};
    use guard::principal::PrincipalKey;
    use tokio::sync::RwLock;

    fn p(uid: u32) -> PrincipalKey {
        PrincipalKey::from_uid(uid)
    }

    /// A `VaultBackend` configured with arbitrary values, bypassing the
    /// environment so path construction can be unit-tested without network or
    /// config. The HTTP client is never used by these tests.
    fn vault_test_backend() -> VaultBackend {
        VaultBackend {
            client: reqwest::Client::new(),
            addr: "https://vault.example.com:8200".to_string(),
            mount: "secret".to_string(),
            namespace: None,
            auth: VaultAuth::Token("test-token".to_string()),
            token: RwLock::new(None),
        }
    }

    #[test]
    fn vault_principal_path_namespaces_by_uid() {
        let backend = vault_test_backend();
        // uid 1000 -> guard/u1000; the per-secret path appends the key.
        assert_eq!(backend.principal_path(&p(1000)), "guard/u1000");
        // A SID principal uses the path-safe segment form.
        let sid = PrincipalKey::from_sid("S-1-5-21-1-2-3-1001");
        assert_eq!(backend.principal_path(&sid), "guard/S_1_5_21_1_2_3_1001");
    }
}
