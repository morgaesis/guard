//! Secret backend backed by the unix `pass` password manager.

use anyhow::{bail, Result};
use async_trait::async_trait;
use guard::principal::PrincipalKey;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command as AsyncCommand;

use super::{legacy_sentinel, SecretBackend};

/// Directory within pass where secrets are stored. Entries live at
/// `guard/<segment>/<key>` (e.g. `guard/u<uid>/<key>`) so one user's secrets
/// cannot collide with another's.
const PASS_PREFIX: &str = "guard/";

type NamespacedSecretKey = (PrincipalKey, String);
type PassStoreEntries = (Vec<NamespacedSecretKey>, Vec<String>);

/// Secret backend backed by the unix `pass` password manager.
#[derive(Debug, Clone)]
pub struct PassBackend {
    store_dir: Option<PathBuf>,
}

impl PassBackend {
    /// Create a new PassBackend.
    ///
    pub fn new() -> Self {
        Self {
            store_dir: password_store_dir(),
        }
    }

    fn pass_path(&self, principal: &PrincipalKey, key: &str) -> String {
        format!("{}{}/{}", PASS_PREFIX, principal.segment(), key)
    }

    fn store_dir(&self) -> Option<&Path> {
        self.store_dir.as_deref()
    }

    async fn get_entry(&self, path: &str) -> Result<Option<String>> {
        let mut cmd = AsyncCommand::new("pass");
        cmd.arg("show").arg(path);
        if let Some(store_dir) = self.store_dir() {
            cmd.env("PASSWORD_STORE_DIR", store_dir);
        }
        let output = cmd.output().await?;

        if !output.status.success() {
            if output.status.code() == Some(1) {
                return Ok(None);
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("pass show {} failed: {}", path, stderr.trim());
        }

        Ok(Some(
            String::from_utf8_lossy(&output.stdout).trim().to_string(),
        ))
    }
}

fn password_store_dir() -> Option<PathBuf> {
    env::var_os("PASSWORD_STORE_DIR")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|home| home.join(".password-store")))
}

pub(super) fn pass_store_initialized() -> bool {
    password_store_dir()
        .map(|dir| dir.join(".gpg-id").is_file())
        .unwrap_or(false)
}

/// Recover the owning principal from a stored namespace segment. A `u<digits>`
/// segment is a Unix uid and round-trips exactly to `PrincipalKey::from_uid`.
/// Any other segment is a SID-derived segment (non-alphanumerics already
/// collapsed to `_`); it is wrapped verbatim as the principal. SID segments are
/// not perfectly invertible to the original SID, so the recovered principal is
/// a stable display/grouping label for the admin aggregate view; per-caller
/// `list`/`get`/`set`/`delete` never round-trip through this — they address the
/// store by the live caller's `segment()`, which is exact.
fn principal_from_segment(segment: &str) -> PrincipalKey {
    if let Some(uid_str) = segment.strip_prefix('u') {
        if !uid_str.is_empty() && uid_str.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(uid) = uid_str.parse::<u32>() {
                return PrincipalKey::from_uid(uid);
            }
        }
    }
    PrincipalKey::from_raw(segment)
}

fn collect_pass_entries(
    namespace_root: &Path,
    dir: &Path,
    namespaced: &mut Vec<NamespacedSecretKey>,
    legacy: &mut Vec<String>,
) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_pass_entries(namespace_root, &path, namespaced, legacy)?;
            continue;
        }
        if !file_type.is_file() || path.extension() != Some(OsStr::new("gpg")) {
            continue;
        }

        let rel = match path.strip_prefix(namespace_root) {
            Ok(rel) => rel,
            Err(_) => continue,
        };
        let components: Vec<String> = rel
            .iter()
            .map(|part| part.to_string_lossy().to_string())
            .collect();
        let mut key_parts = components.clone();
        let Some(last) = key_parts.last_mut() else {
            continue;
        };
        if let Some(stem) = last.strip_suffix(".gpg") {
            *last = stem.to_string();
        }
        // A namespaced entry lives under a per-principal segment directory
        // (`guard/<segment>/<key...>`, two-plus components). A bare file
        // directly under `guard/` is a pre-namespacing flat entry.
        if components.len() >= 2 {
            let principal = principal_from_segment(&components[0]);
            let key = key_parts[1..].join("/");
            if !key.is_empty() {
                namespaced.push((principal, key));
            }
            continue;
        }
        let key = key_parts.join("/");
        if !key.is_empty() {
            legacy.push(key);
        }
    }
    Ok(())
}

fn list_pass_store_entries(store_dir: &Path) -> Result<PassStoreEntries> {
    let namespace_root = store_dir.join(PASS_PREFIX.trim_end_matches('/'));
    if !namespace_root.exists() {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut namespaced = Vec::new();
    let mut legacy = Vec::new();
    collect_pass_entries(
        &namespace_root,
        &namespace_root,
        &mut namespaced,
        &mut legacy,
    )?;
    namespaced.sort();
    namespaced.dedup();
    legacy.sort();
    legacy.dedup();
    Ok((namespaced, legacy))
}

#[async_trait]
impl SecretBackend for PassBackend {
    fn name(&self) -> &str {
        "pass"
    }

    async fn get(&self, principal: &PrincipalKey, key: &str) -> Result<Option<String>> {
        self.get_entry(&self.pass_path(principal, key)).await
    }

    async fn list(&self, principal: &PrincipalKey) -> Result<Vec<String>> {
        let Some(store_dir) = self.store_dir() else {
            return Ok(Vec::new());
        };
        // Filter by storage segment, which is exact for the live caller even
        // when the recovered-from-disk principal is only a display label.
        let want = principal.segment();
        let (namespaced, _) = list_pass_store_entries(store_dir)?;
        let mut keys: Vec<String> = namespaced
            .into_iter()
            .filter_map(|(entry_principal, key)| {
                if entry_principal.segment() == want {
                    Some(key)
                } else {
                    None
                }
            })
            .collect();
        keys.sort();
        keys.dedup();
        Ok(keys)
    }

    async fn list_all(&self) -> Result<Vec<(PrincipalKey, String)>> {
        let Some(store_dir) = self.store_dir() else {
            return Ok(Vec::new());
        };
        let (mut namespaced, legacy) = list_pass_store_entries(store_dir)?;
        namespaced.extend(legacy.into_iter().map(|key| (legacy_sentinel(), key)));
        namespaced.sort();
        namespaced.dedup();
        Ok(namespaced)
    }

    async fn set(&self, principal: &PrincipalKey, key: &str, value: &str) -> Result<()> {
        let path = self.pass_path(principal, key);

        let mut cmd = AsyncCommand::new("pass");
        cmd.args(["insert", "--force", "--multiline", &path]);
        if let Some(store_dir) = self.store_dir() {
            cmd.env("PASSWORD_STORE_DIR", store_dir);
        }

        cmd.stdin(std::process::Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(value.as_bytes()).await?;
        }

        let output = child.wait_with_output().await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("pass insert {} failed: {}", path, stderr.trim());
        }

        Ok(())
    }

    async fn delete(&self, principal: &PrincipalKey, key: &str) -> Result<()> {
        let path = self.pass_path(principal, key);
        let mut cmd = AsyncCommand::new("pass");
        cmd.args(["rm", "-f", &path]);
        if let Some(store_dir) = self.store_dir() {
            cmd.env("PASSWORD_STORE_DIR", store_dir);
        }

        let output = cmd.output().await?;

        if !output.status.success() && output.status.code() != Some(1) {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("pass rm {} failed: {}", path, stderr.trim());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::list_pass_store_entries;
    use guard::principal::PrincipalKey;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn pass_store_listing_walks_principal_namespaces() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(".cache")
            .join(format!("pass-store-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("guard/u1000")).unwrap();
        fs::create_dir_all(root.join("guard/u1001/nested")).unwrap();
        // A SID-derived segment (the form `PrincipalKey::segment()` emits).
        fs::create_dir_all(root.join("guard/S_1_5_21_1_2_3_1001")).unwrap();
        fs::write(root.join("guard/u1000/OPNSENSE_API_KEY.gpg"), b"x").unwrap();
        fs::write(root.join("guard/u1001/nested/token.gpg"), b"y").unwrap();
        fs::write(root.join("guard/S_1_5_21_1_2_3_1001/WIN_KEY.gpg"), b"w").unwrap();
        fs::write(root.join("guard/LEGACY.gpg"), b"z").unwrap();
        fs::write(root.join("guard/.gpg-id"), b"test").unwrap();

        let (all, legacy) = list_pass_store_entries(&root).unwrap();
        // Entries are sorted lexically by principal string: the decimal uids
        // sort ahead of the `S`-prefixed SID segment.
        assert_eq!(
            all,
            vec![
                (PrincipalKey::from_uid(1000), "OPNSENSE_API_KEY".to_string()),
                (PrincipalKey::from_uid(1001), "nested/token".to_string()),
                (
                    PrincipalKey::from_raw("S_1_5_21_1_2_3_1001"),
                    "WIN_KEY".to_string()
                ),
            ]
        );
        assert_eq!(legacy, vec!["LEGACY".to_string()]);

        let _ = fs::remove_dir_all(&root);
    }
}
