//! Default endpoint constants shared by the client and server CLI paths.
//!
//! Every default for "where does guard listen / where do clients connect"
//! lives here so the two sides cannot drift apart.

#[cfg(unix)]
use std::path::PathBuf;

/// Default loopback TCP port, used on platforms without a Unix-socket
/// default (the Windows no-flag transport) when no socket or explicit
/// port is configured.
#[cfg(not(unix))]
pub(crate) const DEFAULT_TCP_PORT: u16 = 8123;

/// Well-known system socket path, matching the systemd RuntimeDirectory
/// layout in deployment/systemd/. Used as the default client endpoint
/// when it exists.
#[cfg(unix)]
pub(crate) const SYSTEM_SOCKET: &str = "/run/guard/guard.sock";

/// The home-directory socket a no-flag `guard server start` binds
/// (~/.guard/guard.sock). `None` when the home directory cannot be
/// resolved.
#[cfg(unix)]
pub(crate) fn home_socket() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".guard").join("guard.sock"))
}
