//! Secret backend backed by environment variables.

use anyhow::Result;
use async_trait::async_trait;
use guard::principal::PrincipalKey;
use std::env;

use super::{legacy_sentinel, SecretBackend};

/// Prefix for environment variable secrets. Full form is
/// `GUARD_SECRET_<segment>_<KEY>` (e.g. `GUARD_SECRET_U<uid>_<KEY>`).
const ENV_PREFIX: &str = "GUARD_SECRET_";

/// Secret backend backed by environment variables. Layout is
/// `GUARD_SECRET_<SEGMENT>_<KEY>`; for a Unix uid the segment is `U<uid>`,
/// preserving the existing `GUARD_SECRET_U<uid>_<KEY>` form with no migration.
#[derive(Debug, Clone)]
pub struct EnvBackend {
    _priv: (),
}

impl EnvBackend {
    pub fn new() -> Self {
        Self { _priv: () }
    }

    /// The per-principal env segment. `PrincipalKey::segment()` yields `u<uid>`
    /// for a uid and an alphanumeric/`_` form for a SID; environment variable
    /// names are conventionally uppercase and case-sensitive, so the segment is
    /// uppercased. For a uid this is `U<uid>`, exactly the legacy layout.
    fn env_segment(principal: &PrincipalKey) -> String {
        principal.segment().to_ascii_uppercase()
    }

    fn env_key(principal: &PrincipalKey, secret_key: &str) -> String {
        format!(
            "{}{}_{}",
            ENV_PREFIX,
            Self::env_segment(principal),
            secret_key
        )
    }

    fn user_prefix(principal: &PrincipalKey) -> String {
        format!("{}{}_", ENV_PREFIX, Self::env_segment(principal))
    }
}

impl Default for EnvBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecretBackend for EnvBackend {
    fn name(&self) -> &str {
        "env"
    }

    async fn get(&self, principal: &PrincipalKey, key: &str) -> Result<Option<String>> {
        Ok(env::var(Self::env_key(principal, key)).ok())
    }

    async fn list(&self, principal: &PrincipalKey) -> Result<Vec<String>> {
        let prefix = Self::user_prefix(principal);
        let mut keys = Vec::new();
        for (env_key, _) in env::vars() {
            if let Some(key) = env_key.strip_prefix(&prefix) {
                keys.push(key.to_string());
            }
        }
        keys.sort();
        keys.dedup();
        Ok(keys)
    }

    async fn list_all(&self) -> Result<Vec<(PrincipalKey, String)>> {
        // The env layout has no unambiguous delimiter between a SID segment and
        // the key (both contain `_`), so the aggregate view recovers the uid
        // namespace (`U<digits>_<key>`) exactly and tags everything else as a
        // pre-namespacing flat entry. Per-caller `list`/`get` are unaffected:
        // they match the full `user_prefix`, which is exact for any principal.
        let mut out = Vec::new();
        for (env_key, _) in env::vars() {
            if let Some(rest) = env_key.strip_prefix(ENV_PREFIX) {
                if let Some(after_u) = rest.strip_prefix('U') {
                    if let Some((uid_str, key)) = after_u.split_once('_') {
                        if !uid_str.is_empty()
                            && uid_str.bytes().all(|b| b.is_ascii_digit())
                            && !key.is_empty()
                        {
                            if let Ok(uid) = uid_str.parse::<u32>() {
                                out.push((PrincipalKey::from_uid(uid), key.to_string()));
                                continue;
                            }
                        }
                    }
                }
                if !rest.is_empty() {
                    out.push((legacy_sentinel(), rest.to_string()));
                }
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    async fn set(&self, principal: &PrincipalKey, key: &str, value: &str) -> Result<()> {
        env::set_var(Self::env_key(principal, key), value);
        Ok(())
    }

    async fn delete(&self, principal: &PrincipalKey, key: &str) -> Result<()> {
        env::remove_var(Self::env_key(principal, key));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::EnvBackend;
    use crate::secrets::{legacy_sentinel, SecretBackend};
    use guard::principal::PrincipalKey;
    use std::env;

    fn p(uid: u32) -> PrincipalKey {
        PrincipalKey::from_uid(uid)
    }

    #[tokio::test]
    async fn env_backend_namespaces_by_uid() {
        let backend = EnvBackend::new();
        // The on-disk env layout is the uppercase `U<uid>` segment; a uid
        // principal's `segment()` (`u<uid>`) is uppercased to match it, so
        // existing `GUARD_SECRET_U<uid>_<KEY>` vars are read with no migration.
        env::set_var("GUARD_SECRET_U2000_EB_KEY", "v2000");
        env::set_var("GUARD_SECRET_U2001_EB_KEY", "v2001");

        assert_eq!(
            backend.get(&p(2000), "EB_KEY").await.unwrap(),
            Some("v2000".to_string())
        );
        assert_eq!(
            backend.get(&p(2001), "EB_KEY").await.unwrap(),
            Some("v2001".to_string())
        );

        let keys = backend.list(&p(2000)).await.unwrap();
        assert!(keys.contains(&"EB_KEY".to_string()));

        let all = backend.list_all().await.unwrap();
        assert!(all.contains(&(p(2000), "EB_KEY".to_string())));
        assert!(all.contains(&(p(2001), "EB_KEY".to_string())));

        env::remove_var("GUARD_SECRET_U2000_EB_KEY");
        env::remove_var("GUARD_SECRET_U2001_EB_KEY");
    }

    #[tokio::test]
    async fn env_backend_set_uses_legacy_uppercase_uid_layout() {
        // Writing through the principal API must produce exactly the historical
        // `GUARD_SECRET_U<uid>_<KEY>` variable so a uid namespace is wire- and
        // disk-compatible across the retype.
        let backend = EnvBackend::new();
        let key = format!("SETFMT_{}", std::process::id());
        backend.set(&p(4242), &key, "v").await.unwrap();
        let expected = format!("GUARD_SECRET_U4242_{key}");
        assert_eq!(env::var(&expected).ok(), Some("v".to_string()));
        backend.delete(&p(4242), &key).await.unwrap();
        assert!(env::var(&expected).is_err());
    }

    #[tokio::test]
    async fn env_backend_surfaces_legacy_flat_keys_only_via_admin_view() {
        let backend = EnvBackend::new();
        env::set_var("GUARD_SECRET_LEGACY_KEY", "legacy");

        assert_eq!(backend.get(&p(2000), "LEGACY_KEY").await.unwrap(), None);
        assert!(!backend
            .list(&p(2000))
            .await
            .unwrap()
            .contains(&"LEGACY_KEY".to_string()));
        assert!(backend
            .list_all()
            .await
            .unwrap()
            .contains(&(legacy_sentinel(), "LEGACY_KEY".to_string())));

        env::remove_var("GUARD_SECRET_LEGACY_KEY");
    }
}
