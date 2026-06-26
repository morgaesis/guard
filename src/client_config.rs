use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientConfig {
    pub server_socket: Option<String>,
    pub server_tcp_port: Option<u16>,
    pub auth_token: Option<String>,
    pub admin_token: Option<String>,
    pub default_user: Option<String>,
}

impl ClientConfig {
    /// Validate `XDG_CONFIG_HOME` before calling any path-resolving helper.
    ///
    /// The `dirs` crate silently falls back to `$HOME/.config` when
    /// `XDG_CONFIG_HOME` is set to a relative path. Anyone using this variable
    /// is opting into a non-default location, so ignoring it quietly can
    /// clobber the wrong file. Fail loudly instead.
    fn validate_xdg_config_home() -> Result<()> {
        match std::env::var("XDG_CONFIG_HOME") {
            Ok(value) if !value.is_empty() && !std::path::Path::new(&value).is_absolute() => {
                anyhow::bail!(
                    "XDG_CONFIG_HOME is set to a relative path ('{}'); the XDG base directory \
                     specification requires an absolute path. Set it to an absolute path or \
                     unset it to use the default.",
                    value
                );
            }
            _ => Ok(()),
        }
    }

    pub fn config_path() -> Result<Option<PathBuf>> {
        Self::validate_xdg_config_home()?;
        Ok(dirs::config_dir().map(|p| p.join("guard").join("client.yaml")))
    }

    pub fn load() -> Result<Self> {
        let path = Self::config_path()?
            .ok_or_else(|| anyhow::anyhow!("could not determine config directory"))?;

        if !path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(&path)?;
        let config: ClientConfig = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?
            .ok_or_else(|| anyhow::anyhow!("could not determine config directory"))?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content = serde_yaml::to_string(self)?;
        std::fs::write(&path, content)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Environment variables are process-global; serialize tests that touch them.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn relative_xdg_config_home_errors() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = std::env::var("XDG_CONFIG_HOME").ok();

        // SAFETY: serialized via ENV_LOCK for the test suite.
        std::env::set_var("XDG_CONFIG_HOME", ".cache/test-xdg");

        let load_err = ClientConfig::load().expect_err("load must error on relative path");
        assert!(
            load_err.to_string().contains("XDG_CONFIG_HOME"),
            "error should mention XDG_CONFIG_HOME: {load_err}"
        );
        assert!(
            load_err.to_string().contains("relative"),
            "error should call out the relative path: {load_err}"
        );

        let path_err =
            ClientConfig::config_path().expect_err("config_path must error on relative path");
        assert!(path_err.to_string().contains("XDG_CONFIG_HOME"));

        match previous {
            Some(val) => std::env::set_var("XDG_CONFIG_HOME", val),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
    }

    #[test]
    fn absolute_xdg_config_home_is_accepted() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = std::env::var("XDG_CONFIG_HOME").ok();

        let absolute = std::env::temp_dir().join("xdg-test-absolute");
        std::env::set_var("XDG_CONFIG_HOME", &absolute);

        let path = ClientConfig::config_path()
            .expect("config_path must accept absolute paths")
            .expect("dirs crate should return a directory");
        #[cfg(unix)]
        assert!(path.starts_with(&absolute));
        #[cfg(not(unix))]
        assert!(path.ends_with("guard/client.yaml") || path.ends_with("guard\\client.yaml"));

        match previous {
            Some(val) => std::env::set_var("XDG_CONFIG_HOME", val),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
    }

    #[test]
    fn unset_xdg_config_home_is_accepted() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = std::env::var("XDG_CONFIG_HOME").ok();

        std::env::remove_var("XDG_CONFIG_HOME");
        assert!(ClientConfig::validate_xdg_config_home().is_ok());

        if let Some(val) = previous {
            std::env::set_var("XDG_CONFIG_HOME", val);
        }
    }
}
