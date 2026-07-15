//! In-memory TTL/FIFO cache of evaluator decisions.

use super::result::{EvalResult, EvalSource};
use crate::gating::Reversibility;
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const DEFAULT_CACHE_CAPACITY: usize = 1024;
pub const DEFAULT_CACHE_TTL_SECS: u64 = 3600;

/// In-memory cache of evaluator decisions for the stateless per-command path.
///
/// Key: the exact command line that gets evaluated. The cache is owned by a
/// single Evaluator instance; the Evaluator's prompt and mode are fixed for
/// its lifetime, so the command line alone is a sufficient key. Changing
/// the prompt requires recreating the Evaluator, which gets a fresh cache.
///
/// Eviction is FIFO on insertion time - a small LRU would be nicer but the
/// cache is size-bounded and turnover is low, so the extra complexity is
/// not worth it here.
pub struct EvalCache {
    entries: HashMap<String, CacheEntry>,
    capacity: usize,
    ttl: Duration,
}

struct CacheEntry {
    result: CachedResult,
    inserted_at: Instant,
}

#[derive(Clone)]
pub(super) enum CachedResult {
    Allow {
        reason: String,
        risk: Option<i32>,
        reversibility: Option<Reversibility>,
    },
    Deny {
        reason: String,
        risk: Option<i32>,
    },
}

impl CachedResult {
    pub(super) fn into_eval(self) -> EvalResult {
        match self {
            CachedResult::Allow {
                reason,
                risk,
                reversibility,
            } => EvalResult::Allow {
                reason,
                source: EvalSource::Cache,
                risk,
                reversibility,
            },
            CachedResult::Deny { reason, risk } => EvalResult::Deny {
                reason,
                source: EvalSource::Cache,
                risk,
            },
        }
    }
}

impl EvalCache {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            capacity: capacity.max(1),
            ttl,
        }
    }

    pub(super) fn get(&self, key: &str) -> Option<EvalResult> {
        let entry = self.entries.get(key)?;
        if entry.inserted_at.elapsed() >= self.ttl {
            return None;
        }
        Some(entry.result.clone().into_eval())
    }

    pub(super) fn insert(&mut self, key: String, result: CachedResult) {
        if !self.entries.contains_key(&key) && self.entries.len() >= self.capacity {
            let oldest_key = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.inserted_at)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest_key {
                self.entries.remove(&k);
            }
        }
        self.entries.insert(
            key,
            CacheEntry {
                result,
                inserted_at: Instant::now(),
            },
        );
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{CachedResult, EvalCache};
    use crate::evaluate::EvalResult;
    use std::time::Duration;

    #[test]
    fn cache_hit_returns_cached_allow() {
        let mut cache = EvalCache::new(4, Duration::from_secs(60));
        cache.insert(
            "ls -la".to_string(),
            CachedResult::Allow {
                reason: "inspection".to_string(),
                risk: Some(1),
                reversibility: None,
            },
        );
        match cache.get("ls -la") {
            Some(EvalResult::Allow { reason, .. }) => assert_eq!(reason, "inspection"),
            other => panic!("expected cached Allow, got {:?}", other),
        }
    }

    #[test]
    fn cache_miss_returns_none() {
        let cache = EvalCache::new(4, Duration::from_secs(60));
        assert!(cache.get("ls -la").is_none());
    }

    #[test]
    fn cache_ttl_expires_entry() {
        let mut cache = EvalCache::new(4, Duration::from_millis(10));
        cache.insert(
            "ls".to_string(),
            CachedResult::Allow {
                reason: "ok".to_string(),
                risk: Some(1),
                reversibility: None,
            },
        );
        std::thread::sleep(Duration::from_millis(20));
        assert!(cache.get("ls").is_none(), "entry should have expired");
    }

    #[test]
    fn cache_evicts_oldest_when_full() {
        let mut cache = EvalCache::new(2, Duration::from_secs(60));
        cache.insert(
            "a".into(),
            CachedResult::Allow {
                reason: "a".into(),
                risk: Some(1),
                reversibility: None,
            },
        );
        std::thread::sleep(Duration::from_millis(2));
        cache.insert(
            "b".into(),
            CachedResult::Allow {
                reason: "b".into(),
                risk: Some(1),
                reversibility: None,
            },
        );
        std::thread::sleep(Duration::from_millis(2));
        cache.insert(
            "c".into(),
            CachedResult::Allow {
                reason: "c".into(),
                risk: Some(1),
                reversibility: None,
            },
        );

        assert!(cache.get("a").is_none(), "oldest should have been evicted");
        assert!(cache.get("b").is_some());
        assert!(cache.get("c").is_some());
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn cache_caches_both_allow_and_deny() {
        let mut cache = EvalCache::new(4, Duration::from_secs(60));
        cache.insert(
            "ok".into(),
            CachedResult::Allow {
                reason: "ok".into(),
                risk: Some(1),
                reversibility: None,
            },
        );
        cache.insert(
            "bad".into(),
            CachedResult::Deny {
                reason: "bad".into(),
                risk: Some(9),
            },
        );
        assert!(matches!(cache.get("ok"), Some(EvalResult::Allow { .. })));
        assert!(matches!(cache.get("bad"), Some(EvalResult::Deny { .. })));
    }
}
