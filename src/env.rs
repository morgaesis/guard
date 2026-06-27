//! Canonical environment-variable resolution for guard.
//!
//! Configuration variables use the `GUARD_` prefix.

/// Resolve a guard configuration variable by its suffix (the part after the
/// `GUARD_` prefix). Returns `None` if `GUARD_<SUFFIX>` is not set.
pub fn guard_env(suffix: &str) -> Option<String> {
    std::env::var(format!("GUARD_{}", suffix)).ok()
}
