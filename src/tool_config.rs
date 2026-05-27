use crate::secrets::SecretManager;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

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

impl ToolConfig {
    pub fn is_empty(&self) -> bool {
        self.env.is_empty() && self.secrets.is_empty() && self.users.is_empty()
    }
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
        let config: ToolConfigFile = serde_yaml::from_str(&content)
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
        self.config = serde_yaml::from_str(&content)?;
        self.last_modified = current_mtime;
        Ok(true)
    }

    /// Resolve all environment variables for a tool: base env + secrets, then per-user overrides.
    /// Returns an empty map if the tool is not registered.
    /// Fails if a referenced secret key is not found in the store.
    ///
    /// `caller_uid` is the identity whose secret namespace the resolver
    /// reads from. `user_key` (typically the same UID as a string, or a
    /// TCP token label) picks per-user overrides out of the tool config
    /// file.
    pub async fn resolve_env(
        &self,
        tool: &str,
        secrets: &SecretManager,
        caller_uid: Option<u32>,
        user_key: Option<&str>,
    ) -> Result<HashMap<String, String>> {
        let Some(tool_config) = self.get(tool) else {
            return Ok(HashMap::new());
        };

        let mut env = tool_config.env.clone();

        for (env_var, secret_key) in &tool_config.secrets {
            let caller_uid = caller_uid.ok_or_else(|| {
                anyhow::anyhow!("tool config secret injection requires a unix socket caller")
            })?;
            let value = secrets
                .get(caller_uid, secret_key)
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
        }

        if let Some(user_key) = user_key {
            if let Some(user_override) = tool_config.users.get(user_key) {
                for (k, v) in &user_override.env {
                    env.insert(k.clone(), v.clone());
                }
                for (env_var, secret_key) in &user_override.secrets {
                    let caller_uid = caller_uid.ok_or_else(|| {
                        anyhow::anyhow!(
                            "tool config secret injection requires a unix socket caller"
                        )
                    })?;
                    let value = secrets
                        .get(caller_uid, secret_key)
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
                }
            }
        }

        Ok(env)
    }

    fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = serde_yaml::to_string(&self.config)?;
        std::fs::write(&self.path, content)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
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
}
