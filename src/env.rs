//! Canonical environment-variable resolution for guard.
//!
//! Configuration variables use the `GUARD_` prefix. The tool was formerly
//! named `ssh-guard` and shipped a `SSH_GUARD_` prefix; that legacy prefix is
//! still honored as a fallback so existing deployments keep working. New
//! configuration should use `GUARD_`.

/// Resolve a guard configuration variable by its suffix (the part after the
/// prefix). Tries `GUARD_<SUFFIX>` first, then the legacy `SSH_GUARD_<SUFFIX>`.
/// Returns `None` if neither is set.
pub fn guard_env(suffix: &str) -> Option<String> {
    std::env::var(format!("GUARD_{}", suffix))
        .ok()
        .or_else(|| std::env::var(format!("SSH_GUARD_{}", suffix)).ok())
}
