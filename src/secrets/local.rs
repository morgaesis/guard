//! Secret backend backed by a GPG-encrypted local YAML file.

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use guard::principal::PrincipalKey;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command as AsyncCommand;

use super::{legacy_sentinel, SecretBackend};

/// Filename for the local encrypted secrets file.
const SECRETS_FILE: &str = "secrets.yaml";

/// Secret backend backed by an encrypted YAML file.
/// The on-disk shape is `{ <principal>: { <key>: <value> } }`. For a Unix uid
/// the principal key is the bare decimal uid (`{ 1000: { ... } }`), exactly the
/// pre-principal layout, so existing files read with no migration; a Windows SID
/// principal is the SID string.
#[derive(Debug, Clone)]
pub struct LocalBackend {
    path: PathBuf,
    gpg_recipient: Option<String>,
}

/// In-memory namespaced store, keyed by the principal's raw string. A Unix uid
/// principal is its decimal string (`"1000"`); the on-disk YAML key is the bare
/// scalar `1000`, and an integer YAML key is normalized to this string form on
/// load, so legacy uid-keyed files round-trip.
type LocalStore = HashMap<String, HashMap<String, String>>;
type LegacyLocalStore = HashMap<String, String>;

enum LocalStoreVariant {
    Namespaced(LocalStore),
    Legacy(LegacyLocalStore),
}

/// Normalize a YAML mapping key (which may be an integer for legacy uid-keyed
/// files, or a string) to the principal's raw string form.
fn yaml_key_to_principal_string(value: &serde_yaml_ng::Value) -> Option<String> {
    match value {
        serde_yaml_ng::Value::String(s) => Some(s.clone()),
        serde_yaml_ng::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Parse decrypted secrets-file content into its store shape. A pure function
/// (no I/O, no GPG) so the namespaced/legacy detection logic is unit-testable
/// directly, independent of `LocalBackend`'s GPG-backed storage.
fn parse_store_variant(content: &str) -> Result<LocalStoreVariant> {
    // The namespaced shape is `{ <principal>: { <key>: <value> } }`. Parse
    // through `Value` so a legacy integer uid key (`1000:`) and a string
    // key (`"1000":` or a SID) both normalize to the principal raw string.
    if let Ok(serde_yaml_ng::Value::Mapping(map)) =
        serde_yaml_ng::from_str::<serde_yaml_ng::Value>(content)
    {
        let mut namespaced: LocalStore = HashMap::new();
        let mut all_namespaced = true;
        for (k, v) in &map {
            let (Some(principal), Ok(inner)) = (
                yaml_key_to_principal_string(k),
                serde_yaml_ng::from_value::<HashMap<String, String>>(v.clone()),
            ) else {
                all_namespaced = false;
                break;
            };
            namespaced.insert(principal, inner);
        }
        if all_namespaced {
            return Ok(LocalStoreVariant::Namespaced(namespaced));
        }
    }
    if let Ok(store) = serde_yaml_ng::from_str::<LegacyLocalStore>(content) {
        return Ok(LocalStoreVariant::Legacy(store));
    }
    bail!("content did not match either the namespaced or legacy secrets-file shape")
}

impl LocalBackend {
    pub fn new() -> Result<Self> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| anyhow::anyhow!("could not determine config directory"))?;
        let guard_dir = config_dir.join("guard");

        Ok(Self {
            path: guard_dir.join(SECRETS_FILE),
            gpg_recipient: None,
        })
    }

    pub fn with_gpg_recipient(mut self, recipient: String) -> Self {
        self.gpg_recipient = Some(recipient);
        self
    }

    fn encrypted_path(&self) -> PathBuf {
        PathBuf::from(format!("{}.gpg", self.path.display()))
    }

    async fn load_store_variant(&self) -> Result<LocalStoreVariant> {
        let encrypted = self.encrypted_path();

        if !encrypted.exists() {
            return Ok(LocalStoreVariant::Namespaced(HashMap::new()));
        }

        let output = if let Some(ref recipient) = self.gpg_recipient {
            AsyncCommand::new("gpg")
                .args(["--decrypt", "--recipient", recipient, "--quiet"])
                .arg(&encrypted)
                .output()
                .await?
        } else {
            AsyncCommand::new("gpg")
                .args(["--decrypt", "--quiet"])
                .arg(&encrypted)
                .output()
                .await?
        };

        if !output.status.success() {
            tracing::debug!("could not decrypt secrets file: {:?}", output.status);
            return Ok(LocalStoreVariant::Namespaced(HashMap::new()));
        }

        let content = String::from_utf8_lossy(&output.stdout);
        parse_store_variant(&content)
            .with_context(|| format!("failed to parse secrets file {}", encrypted.display()))
    }

    async fn save_store_variant(&self, secrets: &LocalStoreVariant) -> Result<()> {
        let parent = self.path.parent();
        if let Some(parent) = parent {
            fs::create_dir_all(parent)?;
        }

        let content = match secrets {
            LocalStoreVariant::Namespaced(store) => serde_yaml_ng::to_string(store)?,
            LocalStoreVariant::Legacy(store) => serde_yaml_ng::to_string(store)?,
        };

        if let Some(ref recipient) = self.gpg_recipient {
            let mut child = AsyncCommand::new("gpg")
                .args(["--encrypt", "--recipient", recipient, "--quiet", "-o"])
                .arg(self.encrypted_path())
                .stdin(Stdio::piped())
                .spawn()?;

            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(content.as_bytes()).await?;
                drop(stdin);
            }

            let status = child.wait().await?;
            if !status.success() {
                bail!("gpg encryption failed");
            }
        } else {
            let mut child = AsyncCommand::new("gpg")
                .args(["--symmetric", "--cipher-algo", "AES256", "--quiet", "-o"])
                .arg(self.encrypted_path())
                .stdin(Stdio::piped())
                .spawn()?;

            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(content.as_bytes()).await?;
                drop(stdin);
            }

            let status = child.wait().await?;
            if !status.success() {
                bail!("gpg symmetric encryption failed");
            }
        }

        Ok(())
    }
}

impl Default for LocalBackend {
    fn default() -> Self {
        Self::new().expect("could not create default LocalBackend")
    }
}

#[async_trait]
impl SecretBackend for LocalBackend {
    fn name(&self) -> &str {
        "local"
    }

    async fn get(&self, principal: &PrincipalKey, key: &str) -> Result<Option<String>> {
        let ns = principal.as_str();
        match self.load_store_variant().await? {
            LocalStoreVariant::Namespaced(store) => {
                Ok(store.get(ns).and_then(|m| m.get(key)).cloned())
            }
            // Surface the same migration-required error as set()/delete()
            // rather than a silent Ok(None): an unmigrated legacy store is
            // indistinguishable from "secret not found" otherwise, which can
            // make an operator believe a configured credential is simply
            // missing when it is actually still present but unreadable.
            LocalStoreVariant::Legacy(_) => bail!(
                "legacy flat local secret store detected; daemon migration is required before user-scoped reads"
            ),
        }
    }

    async fn list(&self, principal: &PrincipalKey) -> Result<Vec<String>> {
        let ns = principal.as_str();
        let mut keys: Vec<String> = match self.load_store_variant().await? {
            LocalStoreVariant::Namespaced(store) => store
                .get(ns)
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default(),
            LocalStoreVariant::Legacy(_) => bail!(
                "legacy flat local secret store detected; daemon migration is required before user-scoped reads"
            ),
        };
        keys.sort();
        keys.dedup();
        Ok(keys)
    }

    async fn list_all(&self) -> Result<Vec<(PrincipalKey, String)>> {
        let mut out: Vec<(PrincipalKey, String)> = match self.load_store_variant().await? {
            LocalStoreVariant::Namespaced(store) => store
                .iter()
                .flat_map(|(ns, m)| {
                    let principal = PrincipalKey::from_raw(ns.clone());
                    m.keys().map(move |k| (principal.clone(), k.clone()))
                })
                .collect(),
            LocalStoreVariant::Legacy(store) => store
                .keys()
                .cloned()
                .map(|k| (legacy_sentinel(), k))
                .collect(),
        };
        out.sort();
        out.dedup();
        Ok(out)
    }

    async fn set(&self, principal: &PrincipalKey, key: &str, value: &str) -> Result<()> {
        let ns = principal.as_str().to_string();
        match self.load_store_variant().await? {
            LocalStoreVariant::Namespaced(mut store) => {
                store
                    .entry(ns)
                    .or_default()
                    .insert(key.to_string(), value.to_string());
                self.save_store_variant(&LocalStoreVariant::Namespaced(store))
                    .await
            }
            LocalStoreVariant::Legacy(_) => bail!(
                "legacy flat local secret store detected; daemon migration is required before user-scoped writes"
            ),
        }
    }

    async fn delete(&self, principal: &PrincipalKey, key: &str) -> Result<()> {
        let ns = principal.as_str();
        match self.load_store_variant().await? {
            LocalStoreVariant::Namespaced(mut store) => {
                if let Some(m) = store.get_mut(ns) {
                    m.remove(key);
                    if m.is_empty() {
                        store.remove(ns);
                    }
                }
                self.save_store_variant(&LocalStoreVariant::Namespaced(store))
                    .await
            }
            LocalStoreVariant::Legacy(_) => bail!(
                "legacy flat local secret store detected; daemon migration is required before user-scoped deletes"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_store_variant, yaml_key_to_principal_string, LocalStoreVariant};
    use guard::principal::PrincipalKey;
    use std::collections::HashMap;

    #[test]
    fn parse_store_variant_detects_legacy_flat_shape() {
        // Prerequisite for the get()/set()/list()/delete() migration-required
        // check: a legacy flat `{ <key>: <value> }` file (no principal
        // namespacing) must parse as Legacy, not as an empty/partial
        // Namespaced store.
        let legacy = parse_store_variant("OPNSENSE_API_KEY: some-value\n").unwrap();
        assert!(
            matches!(legacy, LocalStoreVariant::Legacy(ref m) if m.get("OPNSENSE_API_KEY").map(String::as_str) == Some("some-value")),
            "expected a Legacy store"
        );

        let namespaced = parse_store_variant("1000:\n  OPNSENSE_API_KEY: some-value\n").unwrap();
        assert!(
            matches!(namespaced, LocalStoreVariant::Namespaced(ref m) if m.get("1000").and_then(|inner| inner.get("OPNSENSE_API_KEY")).map(String::as_str) == Some("some-value")),
            "expected a Namespaced store"
        );
    }

    #[test]
    fn local_store_yaml_key_normalizes_integer_uid_to_principal_string() {
        // A pre-principal `secrets.yaml` stores the bare integer uid as the
        // mapping key (`1000: { ... }`). The load path normalizes that integer
        // key to the uid principal's raw string, so the matching uid principal
        // reads its own namespace with no migration. A string SID key is
        // preserved verbatim.
        let legacy_int: serde_yaml_ng::Value =
            serde_yaml_ng::from_str("1000:\n  OPNSENSE_API_KEY: v\n").unwrap();
        let serde_yaml_ng::Value::Mapping(map) = legacy_int else {
            panic!("expected mapping");
        };
        let (int_key, inner) = map.iter().next().unwrap();
        assert_eq!(
            yaml_key_to_principal_string(int_key).as_deref(),
            Some(PrincipalKey::from_uid(1000).as_str())
        );
        // The inner map deserializes as the per-key value store.
        let inner: HashMap<String, String> = serde_yaml_ng::from_value(inner.clone()).unwrap();
        assert_eq!(inner.get("OPNSENSE_API_KEY").map(String::as_str), Some("v"));

        let sid_keyed: serde_yaml_ng::Value =
            serde_yaml_ng::from_str("S-1-5-21-1-2-3-1001:\n  WIN_KEY: v\n").unwrap();
        let serde_yaml_ng::Value::Mapping(map) = sid_keyed else {
            panic!("expected mapping");
        };
        let (sid_key, _) = map.iter().next().unwrap();
        assert_eq!(
            yaml_key_to_principal_string(sid_key).as_deref(),
            Some(PrincipalKey::from_sid("S-1-5-21-1-2-3-1001").as_str())
        );
    }
}
