//! Secret broker for managing sensitive credentials across multiple backends.
//!
//! Secrets are stored per-principal: each caller has its own private namespace
//! keyed by key name. Two users can reuse the same key name (e.g.
//! `OPNSENSE_API_KEY`) without collision, and one user cannot read, list,
//! overwrite, or delete another user's secrets. The daemon principal has a
//! separate admin-only `list_all` entry point that returns the full
//! (principal, key) set for observability; it still cannot read another user's
//! values through the normal `get` path (which requires the owning principal).
//!
//! A principal is a [`PrincipalKey`]: a Unix uid string on Unix, a SID on
//! Windows. The per-principal storage segment is `PrincipalKey::segment()`,
//! which yields `u<uid>` for a uid (preserving the existing on-disk
//! `pass guard/u<uid>/...` and `secrets.yaml` `{<uid>: ...}` layout with no
//! migration) and a filesystem/env-safe form for SIDs.

use anyhow::Result;
use async_trait::async_trait;
use guard::principal::PrincipalKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

mod env;
mod infisical;
mod local;
mod pass;
mod vault;

pub use env::EnvBackend;
pub use infisical::InfisicalBackend;
pub use local::LocalBackend;
pub use pass::PassBackend;
pub use vault::VaultBackend;

/// Reserved principal used to tag entries recovered from the pre-namespacing
/// flat layout (`pass guard/<key>`, bare `GUARD_SECRET_<KEY>`, or a legacy flat
/// `secrets.yaml`). It is a non-colliding sentinel string: no real uid or SID
/// produces it, so it cannot be addressed as a normal namespace.
pub fn legacy_sentinel() -> PrincipalKey {
    PrincipalKey::from_raw("__legacy__")
}

/// Trait for secret storage backends.
///
/// Implementors must be safe to share across threads (Send + Sync).
#[async_trait]
pub trait SecretBackend: Send + Sync {
    /// Returns the backend name for logging/debugging.
    fn name(&self) -> &str;

    /// Retrieve a secret by (principal, key).
    async fn get(&self, principal: &PrincipalKey, key: &str) -> Result<Option<String>>;

    /// List secret keys owned by `principal`.
    async fn list(&self, principal: &PrincipalKey) -> Result<Vec<String>>;

    /// Admin view: list every (principal, key) pair in the store. The daemon
    /// uses this for its aggregate `secrets list`. Backends that cannot
    /// enumerate by principal (env backend) should still return everything
    /// they can recover.
    async fn list_all(&self) -> Result<Vec<(PrincipalKey, String)>>;

    /// Store a secret under `principal`.
    async fn set(&self, principal: &PrincipalKey, key: &str, value: &str) -> Result<()>;

    /// Delete a secret owned by `principal`.
    async fn delete(&self, principal: &PrincipalKey, key: &str) -> Result<()>;
}

// ---------------------------------------------------------------------------
// SecretManager
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
struct CacheKey {
    principal: PrincipalKey,
    key: String,
}

/// Manager for secret operations with a configurable backend.
#[derive(Clone)]
pub struct SecretManager {
    backend: Arc<dyn SecretBackend>,
    cache: Arc<RwLock<HashMap<CacheKey, String>>>,
    /// Bumped by every `set`/`delete`. `get()` captures this before its
    /// backend round-trip and only writes the result into the cache if it is
    /// unchanged afterward -- otherwise a concurrent delete/set raced the
    /// fetch and the read may already be stale, so caching it could
    /// resurrect a deleted secret or overwrite a fresher value indefinitely.
    epoch: Arc<std::sync::atomic::AtomicU64>,
}

impl std::fmt::Debug for SecretManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretManager")
            .field("backend_name", &self.backend.name())
            .finish()
    }
}

impl SecretManager {
    pub fn new(backend: Arc<dyn SecretBackend>) -> Self {
        Self {
            backend,
            cache: Arc::new(RwLock::new(HashMap::new())),
            epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    #[cfg(test)]
    pub fn with_backend<B: SecretBackend + 'static>(backend: B) -> Self {
        Self::new(Arc::new(backend))
    }

    pub fn backend_name(&self) -> &str {
        self.backend.name()
    }

    pub async fn get(&self, principal: &PrincipalKey, key: &str) -> Result<Option<String>> {
        let ck = CacheKey {
            principal: principal.clone(),
            key: key.to_string(),
        };
        {
            let cache = self.cache.read().await;
            if let Some(value) = cache.get(&ck) {
                return Ok(Some(value.clone()));
            }
        }

        let epoch_before = self.epoch.load(std::sync::atomic::Ordering::SeqCst);
        let value = self.backend.get(principal, key).await?;

        if let Some(ref v) = value {
            // A set()/delete() for ANY key that lands during this backend
            // round-trip bumps the epoch; skip caching rather than risk
            // resurrecting a value a concurrent delete just removed, or
            // overwriting a concurrent set's fresher value. The recheck
            // happens AFTER acquiring the write lock, not before: checking
            // first and then separately acquiring the lock would leave a
            // gap where a set()/delete() could bump the epoch and complete
            // its own (lock-protected) cache write in between, so this
            // get() would still insert a stale value once it finally got
            // the lock. set()/delete() bump the epoch before taking their
            // own write lock, so by the time this get() holds the lock, any
            // racing mutation that matters has already either bumped the
            // epoch (detected here) or not yet started (and will see this
            // insert and correctly overwrite/remove it in turn).
            let mut cache = self.cache.write().await;
            if self.epoch.load(std::sync::atomic::Ordering::SeqCst) == epoch_before {
                cache.insert(ck, v.clone());
            }
        }

        Ok(value)
    }

    pub async fn list(&self, principal: &PrincipalKey) -> Result<Vec<String>> {
        self.backend.list(principal).await
    }

    pub async fn list_all(&self) -> Result<Vec<(PrincipalKey, String)>> {
        self.backend.list_all().await
    }

    pub async fn set(&self, principal: &PrincipalKey, key: &str, value: &str) -> Result<()> {
        self.backend.set(principal, key, value).await?;
        self.epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut cache = self.cache.write().await;
        cache.insert(
            CacheKey {
                principal: principal.clone(),
                key: key.to_string(),
            },
            value.to_string(),
        );
        Ok(())
    }

    pub async fn delete(&self, principal: &PrincipalKey, key: &str) -> Result<()> {
        self.backend.delete(principal, key).await?;
        self.epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut cache = self.cache.write().await;
        cache.remove(&CacheKey {
            principal: principal.clone(),
            key: key.to_string(),
        });
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Backend selection
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendType {
    Pass,
    Env,
    Local,
    Vault,
    Infisical,
}

impl BackendType {
    pub fn as_str(&self) -> &'static str {
        match self {
            BackendType::Pass => "pass",
            BackendType::Env => "env",
            BackendType::Local => "local",
            BackendType::Vault => "vault",
            BackendType::Infisical => "infisical",
        }
    }

    pub fn build(&self) -> Result<Arc<dyn SecretBackend>> {
        match self {
            BackendType::Pass => Ok(Arc::new(PassBackend::new())),
            BackendType::Env => Ok(Arc::new(EnvBackend::new())),
            BackendType::Local => {
                let mut backend = LocalBackend::new()?;
                if let Some(recipient) = guard::env::guard_env("GPG_RECIPIENT") {
                    backend = backend.with_gpg_recipient(recipient);
                }
                Ok(Arc::new(backend))
            }
            BackendType::Vault => Ok(Arc::new(VaultBackend::new()?)),
            BackendType::Infisical => Ok(Arc::new(InfisicalBackend::new()?)),
        }
    }
}

impl std::str::FromStr for BackendType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pass" => Ok(BackendType::Pass),
            "env" => Ok(BackendType::Env),
            "local" => Ok(BackendType::Local),
            "vault" => Ok(BackendType::Vault),
            "infisical" => Ok(BackendType::Infisical),
            other => Err(format!(
                "unknown backend '{}'. Use: pass, env, local, vault, infisical",
                other
            )),
        }
    }
}

/// Warn when a backend base URL uses cleartext `http://` (other than loopback):
/// the auth token and secret values would traverse it unencrypted. reqwest still
/// validates TLS certificates by default, so this only flags an explicit
/// downgrade to http.
fn warn_if_cleartext_url(url: &str, var: &str) {
    let lower = url.to_ascii_lowercase();
    let loopback = lower.starts_with("http://127.0.0.1")
        || lower.starts_with("http://localhost")
        || lower.starts_with("http://[::1]");
    if lower.starts_with("http://") && !loopback {
        tracing::warn!(
            "{} uses cleartext http://; the auth token and secret values will be sent unencrypted. Use https://.",
            var
        );
    }
}

pub fn detect_backend() -> BackendType {
    if let Some(backend_str) = guard::env::guard_env("BACKEND") {
        if let Ok(backend) = backend_str.parse::<BackendType>() {
            return backend;
        }
    }

    if pass::pass_store_initialized() {
        return BackendType::Pass;
    }

    BackendType::Env
}

#[cfg(test)]
mod tests {
    use super::{BackendType, CacheKey, SecretBackend, SecretManager};
    use anyhow::Result;
    use async_trait::async_trait;
    use guard::principal::PrincipalKey;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    fn p(uid: u32) -> PrincipalKey {
        PrincipalKey::from_uid(uid)
    }

    #[derive(Debug, Default)]
    struct MockBackend {
        store: Mutex<HashMap<(PrincipalKey, String), String>>,
    }

    impl MockBackend {
        fn new() -> Self {
            Self {
                store: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl SecretBackend for MockBackend {
        fn name(&self) -> &str {
            "mock"
        }

        async fn get(&self, principal: &PrincipalKey, key: &str) -> Result<Option<String>> {
            let store = self.store.lock().unwrap();
            Ok(store.get(&(principal.clone(), key.to_string())).cloned())
        }

        async fn list(&self, principal: &PrincipalKey) -> Result<Vec<String>> {
            let store = self.store.lock().unwrap();
            Ok(store
                .keys()
                .filter(|(u, _)| u == principal)
                .map(|(_, k)| k.clone())
                .collect())
        }

        async fn list_all(&self) -> Result<Vec<(PrincipalKey, String)>> {
            let store = self.store.lock().unwrap();
            Ok(store.keys().cloned().collect())
        }

        async fn set(&self, principal: &PrincipalKey, key: &str, value: &str) -> Result<()> {
            let mut store = self.store.lock().unwrap();
            store.insert((principal.clone(), key.to_string()), value.to_string());
            Ok(())
        }

        async fn delete(&self, principal: &PrincipalKey, key: &str) -> Result<()> {
            let mut store = self.store.lock().unwrap();
            store.remove(&(principal.clone(), key.to_string()));
            Ok(())
        }
    }

    #[tokio::test]
    async fn secret_manager_per_user_basic() {
        let backend = Arc::new(MockBackend::new());
        let manager = SecretManager::new(backend);

        manager.set(&p(1000), "api_key", "alice-key").await.unwrap();
        manager.set(&p(1001), "api_key", "bob-key").await.unwrap();

        assert_eq!(
            manager.get(&p(1000), "api_key").await.unwrap(),
            Some("alice-key".to_string())
        );
        assert_eq!(
            manager.get(&p(1001), "api_key").await.unwrap(),
            Some("bob-key".to_string())
        );
        assert_eq!(manager.get(&p(1002), "api_key").await.unwrap(), None);

        let alice_keys = manager.list(&p(1000)).await.unwrap();
        assert_eq!(alice_keys, vec!["api_key".to_string()]);

        let all = manager.list_all().await.unwrap();
        assert_eq!(all.len(), 2);

        manager.delete(&p(1000), "api_key").await.unwrap();
        assert_eq!(manager.get(&p(1000), "api_key").await.unwrap(), None);
        // Bob's still there.
        assert_eq!(
            manager.get(&p(1001), "api_key").await.unwrap(),
            Some("bob-key".to_string())
        );
    }

    /// A backend whose `get()` captures the value, signals that it has
    /// started, then blocks until the test releases it before returning --
    /// letting a test deterministically interleave a `delete`/`set` in the
    /// middle of an in-flight `get`'s backend round-trip. Only the FIRST
    /// `get()` call is slow this way; subsequent calls (e.g. a test's
    /// post-race verification read) behave like a normal `MockBackend`.
    #[derive(Debug)]
    struct SlowGetBackend {
        inner: MockBackend,
        started: tokio::sync::Notify,
        proceed: tokio::sync::Notify,
        armed: std::sync::atomic::AtomicBool,
    }

    impl SlowGetBackend {
        fn new() -> Self {
            Self {
                inner: MockBackend::new(),
                started: tokio::sync::Notify::new(),
                proceed: tokio::sync::Notify::new(),
                armed: std::sync::atomic::AtomicBool::new(true),
            }
        }
    }

    #[async_trait]
    impl SecretBackend for SlowGetBackend {
        fn name(&self) -> &str {
            "slow-mock"
        }

        async fn get(&self, principal: &PrincipalKey, key: &str) -> Result<Option<String>> {
            let value = self.inner.get(principal, key).await?;
            let was_armed = self.armed.swap(false, std::sync::atomic::Ordering::SeqCst);
            if was_armed {
                self.started.notify_one();
                self.proceed.notified().await;
            }
            Ok(value)
        }

        async fn list(&self, principal: &PrincipalKey) -> Result<Vec<String>> {
            self.inner.list(principal).await
        }

        async fn list_all(&self) -> Result<Vec<(PrincipalKey, String)>> {
            self.inner.list_all().await
        }

        async fn set(&self, principal: &PrincipalKey, key: &str, value: &str) -> Result<()> {
            self.inner.set(principal, key, value).await
        }

        async fn delete(&self, principal: &PrincipalKey, key: &str) -> Result<()> {
            self.inner.delete(principal, key).await
        }
    }

    #[tokio::test]
    async fn concurrent_delete_during_get_does_not_resurrect_into_cache() {
        // Regression test: a get() in flight when a delete() for the same key
        // lands and fully completes must not insert the (now stale) value
        // into the cache afterward -- otherwise every later get() returns the
        // deleted secret out of cache until a restart.
        let backend = Arc::new(SlowGetBackend::new());
        backend.inner.store.lock().unwrap().insert(
            (p(1000), "api_key".to_string()),
            "soon-to-be-deleted".to_string(),
        );
        let manager = SecretManager::new(backend.clone());

        let get_manager = manager.clone();
        let get_task = tokio::spawn(async move { get_manager.get(&p(1000), "api_key").await });

        // Wait for the get() to have read the (still-present) value from the
        // backend and be parked before its cache-write.
        backend.started.notified().await;

        // A delete fully completes while the get() is still in flight.
        manager.delete(&p(1000), "api_key").await.unwrap();

        // Let the stale get() proceed and finish.
        backend.proceed.notify_one();
        let stale_read = get_task.await.unwrap().unwrap();
        assert_eq!(
            stale_read,
            Some("soon-to-be-deleted".to_string()),
            "the in-flight read itself should still observe the pre-delete value"
        );

        // The cache must NOT have been resurrected by the stale get()'s
        // late write: a fresh get() must reflect the delete, not the cache.
        assert_eq!(
            manager.get(&p(1000), "api_key").await.unwrap(),
            None,
            "delete must not be undone by a racing get()'s cache insert"
        );
    }

    #[tokio::test]
    async fn secret_manager_per_principal_isolates_sid_from_uid() {
        // A Windows SID principal and a Unix uid principal are distinct
        // namespaces even when a key name collides.
        let backend = Arc::new(MockBackend::new());
        let manager = SecretManager::new(backend);

        let sid = PrincipalKey::from_sid("S-1-5-21-1-2-3-1001");
        manager.set(&p(1000), "api_key", "unix-val").await.unwrap();
        manager.set(&sid, "api_key", "win-val").await.unwrap();

        assert_eq!(
            manager.get(&sid, "api_key").await.unwrap(),
            Some("win-val".to_string())
        );
        assert_eq!(
            manager.get(&p(1000), "api_key").await.unwrap(),
            Some("unix-val".to_string())
        );
        // The uid principal cannot see the SID's value and vice versa.
        assert_eq!(manager.list(&sid).await.unwrap(), vec!["api_key"]);
    }

    #[tokio::test]
    async fn secret_manager_cache_is_principal_keyed() {
        let backend = Arc::new(MockBackend::new());
        let manager = SecretManager::new(backend);

        manager.set(&p(1000), "k", "alice").await.unwrap();
        manager.set(&p(1001), "k", "bob").await.unwrap();

        // Populate cache
        let _ = manager.get(&p(1000), "k").await;
        let _ = manager.get(&p(1001), "k").await;

        let cache = manager.cache.read().await;
        let alice_ck = CacheKey {
            principal: p(1000),
            key: "k".into(),
        };
        let bob_ck = CacheKey {
            principal: p(1001),
            key: "k".into(),
        };
        assert_eq!(cache.get(&alice_ck).map(String::as_str), Some("alice"));
        assert_eq!(cache.get(&bob_ck).map(String::as_str), Some("bob"));
    }

    #[tokio::test]
    async fn backend_type_parsing() {
        assert_eq!("pass".parse::<BackendType>().unwrap(), BackendType::Pass);
        assert_eq!("env".parse::<BackendType>().unwrap(), BackendType::Env);
        assert_eq!("local".parse::<BackendType>().unwrap(), BackendType::Local);
        assert_eq!("PASS".parse::<BackendType>().unwrap(), BackendType::Pass);
        assert!("invalid".parse::<BackendType>().is_err());
    }

    #[test]
    fn backend_type_vault_infisical_round_trip() {
        // as_str/FromStr round-trip for the HTTP backends, including a
        // case-insensitive parse.
        assert_eq!("vault".parse::<BackendType>().unwrap(), BackendType::Vault);
        assert_eq!(
            "infisical".parse::<BackendType>().unwrap(),
            BackendType::Infisical
        );
        assert_eq!("VAULT".parse::<BackendType>().unwrap(), BackendType::Vault);
        assert_eq!(
            "Infisical".parse::<BackendType>().unwrap(),
            BackendType::Infisical
        );
        assert_eq!(BackendType::Vault.as_str(), "vault");
        assert_eq!(BackendType::Infisical.as_str(), "infisical");
        assert_eq!(
            BackendType::Vault.as_str().parse::<BackendType>().unwrap(),
            BackendType::Vault
        );
        assert_eq!(
            BackendType::Infisical
                .as_str()
                .parse::<BackendType>()
                .unwrap(),
            BackendType::Infisical
        );
    }

    #[test]
    fn backend_type_unknown_lists_all_five() {
        let err = "bogus".parse::<BackendType>().unwrap_err();
        for expected in ["pass", "env", "local", "vault", "infisical"] {
            assert!(
                err.contains(expected),
                "unknown-backend error should list {expected}: {err}"
            );
        }
    }
}
