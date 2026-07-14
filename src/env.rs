//! Canonical environment-variable resolution and small process-level
//! helpers for guard.
//!
//! Configuration variables use the `GUARD_` prefix.

/// Resolve a guard configuration variable by its suffix (the part after the
/// `GUARD_` prefix). Returns `None` if `GUARD_<SUFFIX>` is not set.
pub fn guard_env(suffix: &str) -> Option<String> {
    std::env::var(format!("GUARD_{}", suffix)).ok()
}

/// Current wall-clock time as whole seconds since the Unix epoch. A clock
/// set before the epoch reads as 0 rather than failing.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
