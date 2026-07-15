use crate::secrets::SecretManager;
use anyhow::{Context, Result};
use guard::principal::PrincipalKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::SystemTime;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedToolEnv {
    pub env: HashMap<String, String>,
    /// Secret-store keys that contributed values to `env`. Values are never
    /// retained here, so callers can audit provenance without exposing them.
    pub secret_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserToolOverride {
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub env: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub secrets: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ToolConfig {
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub env: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub secrets: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub users: HashMap<String, UserToolOverride>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ToolConfigFile {
    #[serde(default)]
    pub tools: HashMap<String, ToolConfig>,
}

pub struct ToolRegistry {
    config: ToolConfigFile,
    path: PathBuf,
    last_modified: Option<SystemTime>,
}

impl ToolRegistry {
    pub fn config_path() -> Option<PathBuf> {
        dirs::config_dir().map(|p| p.join("guard").join("tools.yaml"))
    }

    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        if !path.exists() {
            return Ok(Self {
                config: ToolConfigFile::default(),
                path,
                last_modified: None,
            });
        }

        let mtime = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let config: ToolConfigFile = serde_yaml_ng::from_str(&content)
            .with_context(|| format!("failed to parse {}", path.display()))?;

        Ok(Self {
            config,
            path,
            last_modified: mtime,
        })
    }

    pub fn load_default() -> Result<Self> {
        let path = Self::config_path()
            .ok_or_else(|| anyhow::anyhow!("could not determine config directory"))?;
        Self::load(path)
    }

    pub fn empty() -> Self {
        let path = Self::config_path().unwrap_or_else(|| PathBuf::from("tools.yaml"));
        Self {
            config: ToolConfigFile::default(),
            path,
            last_modified: None,
        }
    }

    /// An empty registry watching a path that can never be a real operator
    /// config file. `empty()` deliberately watches the real
    /// `dirs::config_dir()` path (so a daemon that starts with a missing or
    /// broken config can still hot-reload once an operator fixes it), which
    /// makes it unsafe for tests: any test that reaches `reload_if_stale()`
    /// with a registry built via `empty()` reads the machine's real
    /// `~/.config/guard/tools.yaml` if one happens to exist, making the test
    /// depend on host state instead of its own fixtures.
    #[cfg(test)]
    pub(crate) fn isolated_for_tests() -> Self {
        let path = std::env::temp_dir().join(format!(
            "guard-test-tools-registry-{}-nonexistent.yaml",
            std::process::id()
        ));
        Self {
            config: ToolConfigFile::default(),
            path,
            last_modified: None,
        }
    }

    pub fn get(&self, tool: &str) -> Option<&ToolConfig> {
        self.config.tools.get(tool)
    }

    pub fn set(&mut self, tool: &str, config: ToolConfig) -> Result<()> {
        self.config.tools.insert(tool.to_string(), config);
        self.save()
    }

    pub fn remove(&mut self, tool: &str) -> Result<()> {
        self.config.tools.remove(tool);
        self.save()
    }

    pub fn list(&self) -> impl Iterator<Item = (&str, &ToolConfig)> {
        self.config.tools.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub fn reload_if_stale(&mut self) -> Result<bool> {
        let current_mtime = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok();

        let stale = match (self.last_modified, current_mtime) {
            (Some(old), Some(new)) => new > old,
            (None, Some(_)) => true, // file appeared
            _ => false,
        };

        if !stale {
            return Ok(false);
        }

        if !self.path.exists() {
            self.config = ToolConfigFile::default();
            self.last_modified = None;
            return Ok(true);
        }

        let content = std::fs::read_to_string(&self.path)?;
        self.config = serde_yaml_ng::from_str(&content)?;
        self.last_modified = current_mtime;
        Ok(true)
    }

    /// Resolve all environment variables for a tool: base env + secrets, then per-user overrides.
    /// Returns an empty map if the tool is not registered.
    /// Fails if a referenced secret key is not found in the store.
    ///
    /// `principal` is the identity whose secret namespace the resolver reads
    /// from (a Unix uid or a Windows SID). `user_key` (typically the same uid
    /// as a string, the SID string, or a TCP token label) picks per-user
    /// overrides out of the tool config file.
    pub async fn resolve_env(
        &self,
        tool: &str,
        secrets: &SecretManager,
        principal: Option<&PrincipalKey>,
        user_key: Option<&str>,
    ) -> Result<ResolvedToolEnv> {
        let Some(tool_config) = self.get(tool) else {
            return Ok(ResolvedToolEnv::default());
        };

        let mut env = tool_config.env.clone();
        let mut secret_sources = HashMap::new();

        for (env_var, secret_key) in &tool_config.secrets {
            let principal = principal.ok_or_else(|| {
                anyhow::anyhow!(
                    "tool config secret injection requires an authenticated local caller"
                )
            })?;
            let value = secrets
                .get(principal, secret_key)
                .await
                .with_context(|| format!("failed to read secret '{secret_key}'"))?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "secret not found: '{}' (required by tool '{}')",
                        secret_key,
                        tool
                    )
                })?;
            env.insert(env_var.clone(), value);
            secret_sources.insert(env_var.clone(), secret_key.clone());
        }

        if let Some(user_key) = user_key {
            if let Some(user_override) = tool_config.users.get(user_key) {
                for (k, v) in &user_override.env {
                    env.insert(k.clone(), v.clone());
                    secret_sources.remove(k);
                }
                for (env_var, secret_key) in &user_override.secrets {
                    let principal = principal.ok_or_else(|| {
                        anyhow::anyhow!(
                            "tool config secret injection requires an authenticated local caller"
                        )
                    })?;
                    let value = secrets
                        .get(principal, secret_key)
                        .await
                        .with_context(|| format!("failed to read secret '{secret_key}'"))?
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "secret not found: '{}' (required by tool '{}' for user '{}')",
                                secret_key,
                                tool,
                                user_key
                            )
                        })?;
                    env.insert(env_var.clone(), value);
                    secret_sources.insert(env_var.clone(), secret_key.clone());
                }
            }
        }

        let mut secret_refs: Vec<String> = secret_sources.into_values().collect();
        secret_refs.sort();
        secret_refs.dedup();
        Ok(ResolvedToolEnv { env, secret_refs })
    }

    fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = serde_yaml_ng::to_string(&self.config)?;
        std::fs::write(&self.path, content)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn load_empty_file() {
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "tools: {}\n").unwrap();
        let reg = ToolRegistry::load(tmp.path()).unwrap();
        assert!(reg.get("aws").is_none());
    }

    #[test]
    fn load_missing_file() {
        let reg = ToolRegistry::load("/tmp/nonexistent-guard-test.yaml").unwrap();
        assert!(reg.get("aws").is_none());
    }

    #[test]
    fn isolated_for_tests_never_watches_the_real_config_path() {
        let reg = ToolRegistry::isolated_for_tests();
        if let Some(real_path) = ToolRegistry::config_path() {
            assert_ne!(
                reg.path, real_path,
                "a test registry must never watch the operator's real tools.yaml"
            );
        }
        assert!(
            !reg.path.exists(),
            "the isolated path must not coincide with a file that actually exists"
        );
    }

    #[test]
    fn set_and_get() {
        let tmp = NamedTempFile::new().unwrap();
        let mut reg = ToolRegistry::load(tmp.path()).unwrap();

        let config = ToolConfig {
            env: HashMap::from([("FOO".into(), "bar".into())]),
            secrets: HashMap::from([("SECRET".into(), "my-key".into())]),
            ..Default::default()
        };
        reg.set("aws", config).unwrap();

        let loaded = ToolRegistry::load(tmp.path()).unwrap();
        let aws = loaded.get("aws").unwrap();
        assert_eq!(aws.env.get("FOO").unwrap(), "bar");
        assert_eq!(aws.secrets.get("SECRET").unwrap(), "my-key");
    }

    #[test]
    fn remove_tool() {
        let tmp = NamedTempFile::new().unwrap();
        let mut reg = ToolRegistry::load(tmp.path()).unwrap();

        reg.set(
            "aws",
            ToolConfig {
                env: HashMap::from([("X".into(), "1".into())]),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(reg.get("aws").is_some());

        reg.remove("aws").unwrap();
        assert!(reg.get("aws").is_none());

        let loaded = ToolRegistry::load(tmp.path()).unwrap();
        assert!(loaded.get("aws").is_none());
    }

    #[test]
    fn list_tools() {
        let tmp = NamedTempFile::new().unwrap();
        let mut reg = ToolRegistry::load(tmp.path()).unwrap();

        reg.set("aws", ToolConfig::default()).unwrap();
        reg.set("kubectl", ToolConfig::default()).unwrap();

        let names: Vec<&str> = reg.list().map(|(name, _)| name).collect();
        assert!(names.contains(&"aws"));
        assert!(names.contains(&"kubectl"));
    }

    #[test]
    fn reload_if_stale_detects_change() {
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "tools: {}\n").unwrap();

        let mut reg = ToolRegistry::load(tmp.path()).unwrap();
        assert!(reg.get("aws").is_none());

        // Modify the file
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::write(tmp.path(), "tools:\n  aws:\n    env:\n      FOO: bar\n").unwrap();

        let reloaded = reg.reload_if_stale().unwrap();
        assert!(reloaded);
        assert!(reg.get("aws").is_some());
    }

    #[test]
    fn parse_yaml_with_env_and_secrets() {
        let yaml = r#"
tools:
  aws:
    env:
      AWS_PROFILE: prod
      AWS_DEFAULT_REGION: us-east-1
    secrets:
      AWS_SECRET_ACCESS_KEY: my-aws-key
"#;
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), yaml).unwrap();

        let reg = ToolRegistry::load(tmp.path()).unwrap();
        let aws = reg.get("aws").unwrap();
        assert_eq!(aws.env.get("AWS_PROFILE").unwrap(), "prod");
        assert_eq!(
            aws.secrets.get("AWS_SECRET_ACCESS_KEY").unwrap(),
            "my-aws-key"
        );
    }

    #[tokio::test]
    async fn resolved_env_preserves_secret_key_provenance() {
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            "tools:\n  deploy:\n    secrets:\n      BASE_TOKEN: base/key\n      OVERRIDDEN: unused/key\n    users:\n      '424242':\n        env:\n          OVERRIDDEN: plain-value\n        secrets:\n          USER_TOKEN: user/key\n",
        )
        .unwrap();
        let registry = ToolRegistry::load(tmp.path()).unwrap();
        let manager = SecretManager::with_backend(crate::secrets::EnvBackend::default());
        let principal = PrincipalKey::from_uid(424242);
        manager
            .set(&principal, "base/key", "base-value")
            .await
            .unwrap();
        manager
            .set(&principal, "user/key", "user-value")
            .await
            .unwrap();
        manager
            .set(&principal, "unused/key", "unused-value")
            .await
            .unwrap();

        let resolved = registry
            .resolve_env("deploy", &manager, Some(&principal), Some("424242"))
            .await
            .unwrap();
        assert_eq!(resolved.env.get("BASE_TOKEN").unwrap(), "base-value");
        assert_eq!(resolved.env.get("USER_TOKEN").unwrap(), "user-value");
        assert_eq!(resolved.env.get("OVERRIDDEN").unwrap(), "plain-value");
        assert_eq!(resolved.secret_refs, vec!["base/key", "user/key"]);

        manager.delete(&principal, "base/key").await.unwrap();
        manager.delete(&principal, "user/key").await.unwrap();
        manager.delete(&principal, "unused/key").await.unwrap();
    }
}
