//! Guard server mode - accepts command execution requests and runs them with privileged access.
//!
//! The server listens on a UNIX socket or TCP port and accepts requests from clients (agents).
//! Each request is evaluated against the policy engine before execution.
//!
//! Security model:
//! - UNIX socket: peer UID-based authorization
//! - TCP socket: auth token required
//! - Socket dir: 0755 when managed by socket_group
//! - Socket: 0666 so local clients can connect before UID validation

use crate::evaluate::Evaluator;
use crate::injection::is_valid_env_name;
use crate::redact::{
    redact_exact_secrets, redact_output_text, redact_output_with_state, RedactionState,
};
use crate::secrets::{SecretManager, LEGACY_UID_SENTINEL};
use crate::session::{
    HistoricalGrant, SessionDecision, SessionDecisionSource, SessionExecStatus, SessionGrant,
    SessionGrantSummary, SessionInteraction, SessionRegistry, SessionReport,
};
use crate::session_store::SessionStore;

// Re-export so main.rs can pattern-match on history status without a
// direct dependency on the `session` module path.
pub use crate::session::HistoricalStatus;
use crate::tool_config::ToolRegistry;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
#[cfg(unix)]
use std::ffi::CString;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
#[cfg(windows)]
use tokio::net::windows::named_pipe::NamedPipeServer;
use tokio::process::Command;
use tokio::sync::{mpsc, RwLock};
#[cfg(unix)]
use uzers::os::unix::UserExt;

const DEFAULT_SOCKET_PATH: &str = "/var/run/guard/guard.sock";
const DEFAULT_TCP_PORT: u16 = 8123;
const MAX_GUARD_DEPTH: u32 = 5;
const MAX_REQUEST_BYTES: usize = 1_048_576; // 1MB
const MAX_OUTPUT_BYTES: usize = 10_485_760; // 10MB

/// Identifies the caller for per-user secret injection.
#[derive(Debug, Clone)]
pub enum CallerIdentity {
    Unix { uid: u32 },
    /// Local caller over a Windows named pipe, identified by the kernel-verified
    /// SID of the connecting process (the Windows analog of a peer UID).
    #[cfg(windows)]
    Windows { sid: String },
    Tcp { token: String },
    Unknown,
}

impl CallerIdentity {
    /// Returns the key used to look up per-user config in tools.yaml.
    pub fn user_key(&self) -> Option<String> {
        match self {
            Self::Unix { uid } => Some(uid.to_string()),
            #[cfg(windows)]
            Self::Windows { sid } => Some(sid.clone()),
            Self::Tcp { token } => Some(token.clone()),
            Self::Unknown => None,
        }
    }
}

impl std::fmt::Display for CallerIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unix { uid } => write!(f, "uid={}", uid),
            #[cfg(windows)]
            Self::Windows { sid } => write!(f, "sid={}", sid),
            Self::Tcp { token } => {
                let redacted = if token.len() > 8 {
                    format!("{}...{}", &token[..4], &token[token.len() - 4..])
                } else {
                    "***".to_string()
                };
                write!(f, "token={}", redacted)
            }
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteRequest {
    pub binary: String,
    pub args: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    /// Per-run plain environment variables requested by the client.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub env: HashMap<String, String>,
    /// Per-run secret mappings requested by the client: env var -> secret key.
    /// Secret values are resolved by the daemon immediately before execution.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub secrets: HashMap<String, String>,
    #[serde(default)]
    pub stream: bool,
    /// Session grant token. When present and matched server-side, session
    /// allow/deny patterns short-circuit the decision before the evaluator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
#[allow(clippy::enum_variant_names)]
pub enum AdminRequest {
    SessionGrant {
        token: String,
        #[serde(default)]
        allow: Vec<String>,
        #[serde(default)]
        deny: Vec<String>,
        #[serde(default)]
        ttl_secs: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prompt_append: Option<String>,
    },
    SessionRevoke {
        token: String,
    },
    SessionList {
        /// Include past (revoked/expired) grants alongside the active set.
        #[serde(default)]
        include_history: bool,
        /// When set, only history entries that ended at-or-after this
        /// unix-seconds value are returned. None = no time filter.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        since_unix: Option<u64>,
    },
    SessionShow {
        token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<usize>,
    },
    SecretSet {
        key: String,
        value: String,
    },
    SecretDelete {
        key: String,
    },
    SecretExists {
        key: String,
    },
    SecretList,
    SecretListDetailed,
    /// Privileged status snapshot. Caller must be the daemon UID.
    Status,
    /// No-auth liveness probe. Returns version, uptime, and a small
    /// set of non-elevating posture fields so any allowed client can
    /// confirm reachability and the evaluation context they are
    /// operating under, without revealing model identity, redaction
    /// state, session counts, or other fingerprintable internals.
    Ping,
}

impl AdminRequest {
    /// Admin RPCs that require the caller to be the daemon UID.
    /// Ping is a public liveness probe. Secret RPCs and session
    /// listing are open to any connected user; they self-scope or
    /// redact sensitive fields so a caller cannot elevate from them.
    fn requires_daemon_uid(&self) -> bool {
        !matches!(
            self,
            Self::Ping
                | Self::SessionList { .. }
                | Self::SecretSet { .. }
                | Self::SecretDelete { .. }
                | Self::SecretExists { .. }
                | Self::SecretList
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum AdminResponse {
    Ok,
    Error {
        message: String,
    },
    SecretExists {
        exists: bool,
    },
    SessionList {
        grants: Vec<SessionGrantSummary>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        history: Vec<HistoricalGrant>,
    },
    SessionShow {
        report: SessionReport,
    },
    SecretList {
        keys: Vec<String>,
    },
    SecretListDetailed {
        items: Vec<SecretDetail>,
    },
    Status {
        status: ServerStatus,
    },
    Ping {
        version: String,
        uptime_secs: u64,
        /// Evaluation mode the daemon is configured for. Knowing this
        /// helps a caller understand why borderline commands get
        /// allowed or denied; it is already inferable from probing.
        mode: String,
        /// True when the daemon evaluates but does not execute approved
        /// commands. Useful for callers to know whether their command
        /// will actually run.
        dry_run: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretDetail {
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(default)]
    pub legacy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerStatus {
    pub version: String,
    pub started_at_unix: u64,
    pub uptime_secs: u64,
    pub socket_path: Option<String>,
    pub tcp_port: Option<u16>,
    pub mode: String,
    pub llm_enabled: bool,
    pub llm_model_chain: Vec<String>,
    pub static_policy: bool,
    pub preflight: bool,
    pub redact: bool,
    pub dry_run: bool,
    pub cache_enabled: bool,
    pub cache_size: usize,
    pub session_count: usize,
    pub daemon_uid: u32,
    pub exec_identity: String,
    pub state_db_path: Option<String>,
    #[serde(default)]
    pub secret_backend: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum IncomingMessage {
    Admin { admin: AdminRequest },
    Execute(ExecuteRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteResponse {
    pub allowed: bool,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ExecuteStreamMessage {
    Stdout { data: String },
    Stderr { data: String },
    PolicyDecision { allowed: bool, reason: String },
    Keepalive,
    Result { response: ExecuteResponse },
}

#[derive(Debug, Clone, Copy)]
pub enum OutputStream {
    Stdout,
    Stderr,
}

#[derive(Clone)]
pub struct ServerConfig {
    pub socket_path: Option<PathBuf>,
    pub tcp_port: Option<u16>,
    pub evaluator: Arc<Evaluator>,
    pub secrets: Arc<SecretManager>,
    pub redact: bool,
    pub auth_token: Option<String>,
    pub socket_group: Option<String>,
    pub allowed_uids: Option<Vec<u32>>,
    pub shim_dir: Option<PathBuf>,
    pub dry_run: bool,
    pub tool_registry: Arc<RwLock<ToolRegistry>>,
    /// Known secret values for exact-match output redaction.
    pub redact_secrets: Vec<String>,
    /// When true, run deterministic pre-LLM checks (executable existence on
    /// PATH, credential-disclosure pattern deny). When false, the evaluator
    /// is the only authority on whether a command is allowed.
    pub preflight: bool,
    /// Session grant registry. Grants here extend or narrow the policy
    /// decision for a specific session token.
    pub sessions: Arc<RwLock<SessionRegistry>>,
    pub session_store: Option<SessionStore>,
    /// When true, approved Unix-socket requests execute as the connecting
    /// user instead of the daemon UID.
    pub exec_as_caller: bool,
    /// Wall-clock unix seconds when the daemon started. Surfaced via the
    /// Status admin RPC so callers can compute uptime.
    pub started_at_unix: u64,
    /// Effective UID of the daemon process. Admin RPCs require the
    /// caller to be this UID; there is no token-based elevation.
    pub daemon_uid: u32,
    pub state_db_path: Option<PathBuf>,
}

impl ServerConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        socket_path: Option<PathBuf>,
        tcp_port: Option<u16>,
        evaluator: Evaluator,
        secrets: SecretManager,
        redact: bool,
        auth_token: Option<String>,
        socket_group: Option<String>,
        allowed_uids: Option<Vec<u32>>,
        shim_dir: Option<PathBuf>,
        dry_run: bool,
        tool_registry: ToolRegistry,
        redact_secrets: Vec<String>,
        preflight: bool,
        sessions: SessionRegistry,
        session_store: Option<SessionStore>,
        exec_as_caller: bool,
        state_db_path: Option<PathBuf>,
    ) -> Self {
        Self {
            socket_path,
            tcp_port,
            evaluator: Arc::new(evaluator),
            secrets: Arc::new(secrets),
            redact,
            auth_token,
            socket_group,
            allowed_uids,
            shim_dir,
            dry_run,
            tool_registry: Arc::new(RwLock::new(tool_registry)),
            redact_secrets,
            preflight,
            session_store,
            exec_as_caller,
            daemon_uid: current_uid(),
            sessions: Arc::new(RwLock::new(sessions)),
            started_at_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            state_db_path,
        }
    }

    fn validate_uid(&self, uid: u32) -> Result<()> {
        if let Some(ref allowed) = self.allowed_uids {
            // The daemon's own UID is always permitted to connect: it
            // already controls the daemon process (signals, /proc), so
            // this is not a security boundary. Without this exemption
            // the daemon could not run admin RPCs against itself, which
            // breaks self-management.
            if !allowed.contains(&uid) && uid != self.daemon_uid {
                tracing::warn!("connection rejected: uid {} not in allowed list", uid);
                anyhow::bail!("connection not allowed for this user");
            }
        }
        Ok(())
    }

    /// Authorize an admin RPC. Admin = caller is the daemon's own UID.
    /// There is no token-based elevation.
    /// Without this rule, an exec-allowed agent process could mint
    /// sessions whose `--prompt` overrides the LLM policy from itself.
    fn validate_admin(&self, caller: &CallerIdentity) -> Result<()> {
        if let CallerIdentity::Unix { uid } = caller {
            if *uid == self.daemon_uid {
                return Ok(());
            }
        }
        anyhow::bail!("admin RPC refused: caller is not the daemon UID");
    }

    fn validate_token(&self, token: Option<&str>) -> Result<()> {
        if let Some(ref expected) = self.auth_token {
            let provided = token.unwrap_or("").as_bytes();
            let expected = expected.as_bytes();
            // Constant-time comparison to prevent timing side-channel
            let len_match = provided.len() == expected.len();
            let byte_match = provided
                .iter()
                .zip(expected.iter())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b));
            if !len_match || byte_match != 0 {
                anyhow::bail!("invalid auth token");
            }
        }
        Ok(())
    }

    /// Log the LLM policy decision. This is the primary audit event and
    /// uses the historical `[AUDIT] ALLOWED` / `[AUDIT] DENIED` prefixes
    /// so existing grep patterns (harness scripts, review agents) keep
    /// working. It reflects only the policy verdict, not whether the
    /// command subsequently managed to exec.
    fn log_audit_policy(
        &self,
        caller: &CallerIdentity,
        binary: &str,
        args: &[String],
        allowed: bool,
        reason: &str,
    ) {
        let action = if allowed { "ALLOWED" } else { "DENIED" };
        tracing::info!(
            "[AUDIT] {} caller={} cmd=\"{} {}\" reason=\"{}\"",
            action,
            caller,
            binary,
            args.join(" "),
            reason
        );
    }

    /// Log a failed exec attempt. Only emitted when the policy allowed
    /// the command but the kernel refused to run it (ENOENT, EACCES,
    /// etc.). Paired with a corresponding `[AUDIT] ALLOWED` line so
    /// downstream tooling can distinguish "policy denied" from "policy
    /// approved, exec failed".
    fn log_audit_exec_failed(
        &self,
        caller: &CallerIdentity,
        binary: &str,
        args: &[String],
        reason: &str,
    ) {
        tracing::info!(
            "[AUDIT] EXEC_FAILED caller={} cmd=\"{} {}\" reason=\"{}\"",
            caller,
            binary,
            args.join(" "),
            reason
        );
    }
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct Server {
    config: ServerConfig,
}

impl Server {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        socket_path: Option<PathBuf>,
        tcp_port: Option<u16>,
        evaluator: Evaluator,
        secrets: SecretManager,
        redact: bool,
        auth_token: Option<String>,
        socket_group: Option<String>,
        allowed_uids: Option<Vec<u32>>,
        shim_dir: Option<PathBuf>,
        dry_run: bool,
        tool_registry: ToolRegistry,
        redact_secrets: Vec<String>,
        preflight: bool,
        sessions: SessionRegistry,
        session_store: Option<SessionStore>,
        exec_as_caller: bool,
        state_db_path: Option<PathBuf>,
    ) -> Self {
        let config = ServerConfig::new(
            socket_path,
            tcp_port,
            evaluator,
            secrets,
            redact,
            auth_token,
            socket_group,
            allowed_uids,
            shim_dir,
            dry_run,
            tool_registry,
            redact_secrets,
            preflight,
            sessions,
            session_store,
            exec_as_caller,
            state_db_path,
        );
        Self { config }
    }

    pub async fn run(&self) -> Result<()> {
        tracing::info!("Server::run() called");

        let mut futures = Vec::new();

        if let Some(ref socket_path) = self.config.socket_path {
            tracing::info!("Starting local listener on {}", socket_path.display());
            let path = socket_path.clone();
            let config = self.config.clone();
            futures.push(tokio::spawn(async move {
                Self::run_local_static(&path, &config).await
            }));
        }

        if let Some(port) = self.config.tcp_port {
            tracing::info!("Starting TCP listener on port {}", port);
            let config = self.config.clone();
            futures.push(tokio::spawn(async move {
                Self::run_tcp_static(port, &config).await
            }));
        }

        if futures.is_empty() {
            anyhow::bail!("no socket path or TCP port specified");
        }

        let _ = futures::future::join_all(futures).await;

        Ok(())
    }

    /// Platform dispatch for the local listener: UNIX domain socket on Unix,
    /// named pipe on Windows.
    async fn run_local_static(socket_path: &PathBuf, config: &ServerConfig) -> Result<()> {
        #[cfg(unix)]
        {
            Self::run_unix_static(socket_path, config).await
        }
        #[cfg(windows)]
        {
            Self::run_pipe_static(socket_path, config).await
        }
    }

    #[cfg(windows)]
    async fn run_pipe_static(socket_path: &PathBuf, config: &ServerConfig) -> Result<()> {
        let pipe_name = winplat::pipe_name(socket_path);
        tracing::info!("guard server listening on named pipe {}", pipe_name);

        let mut server = winplat::create_pipe_server(&pipe_name, true)?;

        loop {
            // Wait for a client to connect to the current instance, then hand it
            // off and immediately stand up the next instance for the next client.
            server
                .connect()
                .await
                .context("named pipe connect failed")?;
            let connected = server;
            server = winplat::create_pipe_server(&pipe_name, false)?;

            let config = config.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_client_pipe(connected, &config).await {
                    tracing::error!("client handler error: {}", e);
                }
            });
        }
    }

    #[cfg(unix)]
    async fn run_unix_static(socket_path: &PathBuf, config: &ServerConfig) -> Result<()> {
        if let Some(parent) = socket_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .context("failed to create socket directory")?;
        }

        if socket_path.exists() {
            tokio::fs::remove_file(socket_path).await?;
        }

        let listener = UnixListener::bind(socket_path).context("failed to bind UNIX socket")?;
        Self::chmod_path(socket_path, 0o666).await?;

        tracing::info!("guard server listening on {}", socket_path.display());

        if let Some(ref group) = config.socket_group {
            Self::chown_to_group(socket_path, group).await?;
            if let Some(parent) = socket_path.parent() {
                Self::chmod_path(parent, 0o755).await?;
            }
        }

        loop {
            match listener.accept().await {
                Ok((stream, _peer_addr)) => {
                    let config = config.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_client_unix(stream, &config).await {
                            tracing::error!("client handler error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("accept error: {}", e);
                }
            }
        }
    }

    async fn run_tcp_static(port: u16, config: &ServerConfig) -> Result<()> {
        let addr = format!("127.0.0.1:{}", port);
        let listener = TcpListener::bind(&addr)
            .await
            .context("failed to bind TCP socket")?;

        tracing::info!("guard server listening on tcp://{}", addr);

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let config = config.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_client_tcp(stream, &config).await {
                            tracing::error!("client handler error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("accept error: {}", e);
                }
            }
        }
    }

    #[cfg(unix)]
    async fn chown_to_group(path: &PathBuf, group: &str) -> Result<()> {
        let output = Command::new("chgrp").arg(group).arg(path).output().await?;

        if !output.status.success() {
            bail!(
                "failed to change group of {} to {}: {}",
                path.display(),
                group,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }

    #[cfg(unix)]
    async fn chmod_path(path: &std::path::Path, mode: u32) -> Result<()> {
        let permissions = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(path, permissions)
            .with_context(|| format!("failed to chmod {} to {:o}", path.display(), mode))?;
        Ok(())
    }
}

/// Windows-only helpers: named-pipe name normalization and peer-SID resolution.
/// The SID is the Windows analog of a Unix peer UID — the kernel-verified
/// identity of the process on the other end of the local pipe.
#[cfg(windows)]
mod winplat {
    use anyhow::{bail, Context, Result};
    use std::os::windows::io::AsRawHandle;
    use tokio::net::windows::named_pipe::NamedPipeServer;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, RevertToSelf, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Pipes::{CreateNamedPipeW, ImpersonateNamedPipeClient};
    use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

    // Named pipe creation flags (avoid extra feature imports for the constants).
    const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
    const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
    const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
    const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x0000_0008; // byte type/readmode/wait = 0
    const PIPE_UNLIMITED_INSTANCES: u32 = 255;
    const PIPE_BUF: u32 = 65536;

    /// Create a named-pipe server instance with an explicit security descriptor
    /// so local authenticated users can connect to the gate. A pipe's security
    /// must be set at creation time (the server handle has no WRITE_DAC), so we
    /// call CreateNamedPipeW directly and wrap the handle into tokio.
    ///
    /// Connect access is NOT the trust boundary: the gate enforces policy on
    /// every request and never exposes the brokered credentials. The boundary is
    /// the daemon's account isolation. Tighten the trustee set (currently
    /// Administrators/SYSTEM/Authenticated Users) for a multi-user host.
    pub fn create_pipe_server(pipe_name: &str, first: bool) -> Result<NamedPipeServer> {
        let wide: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
        // Administrators/SYSTEM get full control; Authenticated Users get only
        // FILE_GENERIC_READ|FILE_GENERIC_WRITE (0x0012019b) so they can CONNECT
        // but NOT create rogue additional instances of the pipe
        // (FILE_CREATE_PIPE_INSTANCE is excluded). Tighten AU to a specific agent
        // SID for a multi-user host.
        let sddl: Vec<u16> = "D:(A;;GA;;;BA)(A;;GA;;;SY)(A;;0x0012019b;;;AU)\0"
            .encode_utf16()
            .collect();
        unsafe {
            let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut psd,
                std::ptr::null_mut(),
            ) == 0
            {
                bail!(
                    "ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: psd,
                bInheritHandle: 0,
            };
            let mut open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
            if first {
                open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
            }
            let handle = CreateNamedPipeW(
                wide.as_ptr(),
                open_mode,
                PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                PIPE_BUF,
                PIPE_BUF,
                0,
                &sa,
            );
            LocalFree(psd as _);
            if handle == INVALID_HANDLE_VALUE || handle.is_null() {
                bail!("CreateNamedPipeW failed: {}", std::io::Error::last_os_error());
            }
            NamedPipeServer::from_raw_handle(handle as _)
                .context("NamedPipeServer::from_raw_handle failed")
        }
    }

    /// Normalize a configured path/name into a `\\.\pipe\<name>` pipe name so the
    /// same `--socket` flag works on Windows.
    pub fn pipe_name(path: &std::path::Path) -> String {
        let s = path.to_string_lossy().to_string();
        if s.starts_with(r"\\.\pipe\") || s.starts_with(r"\\?\pipe\") {
            s
        } else {
            let base = path
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or("guard");
            format!(r"\\.\pipe\{}", base)
        }
    }

    /// Resolve the SID string of the connected pipe client by briefly
    /// impersonating it and reading the impersonation token's user.
    pub fn client_sid(server: &NamedPipeServer) -> Result<String> {
        let pipe = server.as_raw_handle() as HANDLE;
        unsafe {
            if ImpersonateNamedPipeClient(pipe) == 0 {
                bail!(
                    "ImpersonateNamedPipeClient failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            let outcome = sid_from_current_thread();
            // Always drop impersonation. A failed revert would leave this pooled
            // tokio worker thread impersonating the lower-privilege client for
            // subsequent tasks (policy eval, credential reads), so a failure here
            // is unrecoverable for the process: abort rather than risk running
            // privileged work under the client's token.
            if RevertToSelf() == 0 {
                tracing::error!(
                    "RevertToSelf failed after named-pipe impersonation ({}); aborting",
                    std::io::Error::last_os_error()
                );
                std::process::abort();
            }
            outcome
        }
    }

    unsafe fn sid_from_current_thread() -> Result<String> {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) == 0 {
            bail!("OpenThreadToken failed: {}", std::io::Error::last_os_error());
        }
        let result = sid_string_from_token(token);
        CloseHandle(token);
        result
    }

    unsafe fn sid_string_from_token(token: HANDLE) -> Result<String> {
        let mut len: u32 = 0;
        // First call sizes the buffer (it is expected to "fail" with the length).
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
        if len == 0 {
            bail!("GetTokenInformation returned a zero length");
        }
        let mut buf = vec![0u8; len as usize];
        if GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            len,
            &mut len,
        ) == 0
        {
            bail!("GetTokenInformation failed: {}", std::io::Error::last_os_error());
        }
        // buf is a Vec<u8> (alignment 1); forming a &TOKEN_USER to it would be UB
        // because TOKEN_USER's embedded PSID forces 8-byte alignment. Read the SID
        // pointer out with an unaligned read instead of taking a reference.
        let sid = core::ptr::read_unaligned(core::ptr::addr_of!(
            (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid
        ));
        let mut wide: *mut u16 = std::ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut wide) == 0 {
            bail!(
                "ConvertSidToStringSidW failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let s = widestring_to_string(wide);
        LocalFree(wide as _);
        Ok(s)
    }

    unsafe fn widestring_to_string(ptr: *const u16) -> String {
        if ptr.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
    }
}

#[cfg(unix)]
async fn handle_client_unix(stream: UnixStream, config: &ServerConfig) -> Result<()> {
    let uid = stream
        .peer_cred()
        .context("failed to read peer credentials")?
        .uid();
    tracing::info!("handle_client_unix: peer uid = {}", uid);

    if let Err(e) = config.validate_uid(uid) {
        tracing::warn!("uid {} rejected: {}", uid, e);
        return Err(e);
    }

    serve_connection(stream, CallerIdentity::Unix { uid }, config).await
}

#[cfg(windows)]
async fn handle_client_pipe(stream: NamedPipeServer, config: &ServerConfig) -> Result<()> {
    let caller = match winplat::client_sid(&stream) {
        Ok(sid) => {
            tracing::info!("named pipe client sid = {}", sid);
            CallerIdentity::Windows { sid }
        }
        Err(e) => {
            // Fail soft: the policy gate does not depend on identity, but log
            // loudly so an operator notices identity resolution is degraded.
            tracing::warn!("could not resolve pipe client SID ({}); treating as unknown", e);
            CallerIdentity::Windows {
                sid: "S-unknown".to_string(),
            }
        }
    };
    serve_connection(stream, caller, config).await
}

/// Drive the request/response protocol for one connected client, independent of
/// the underlying transport (UNIX socket or Windows named pipe).
async fn serve_connection<S>(
    stream: S,
    caller: CallerIdentity,
    config: &ServerConfig,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();

    tracing::info!("serve_connection: waiting for request...");
    while let Ok(Some(line)) = lines.next_line().await {
        if line.len() > MAX_REQUEST_BYTES {
            tracing::warn!("request too large ({} bytes), dropping", line.len());
            continue;
        }
        tracing::debug!("serve_connection: received request (raw)");
        let incoming: IncomingMessage = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = ExecuteResponse {
                    allowed: false,
                    reason: format!("invalid request: {}", e),
                    exit_code: None,
                    stdout: None,
                    stderr: None,
                };
                writer
                    .write_all(serde_json::to_string(&resp)?.as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                continue;
            }
        };

        let request = match incoming {
            IncomingMessage::Admin { admin } => {
                let resp = handle_admin_request(config, &caller, admin).await;
                writer
                    .write_all(serde_json::to_string(&resp)?.as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                continue;
            }
            IncomingMessage::Execute(req) => req,
        };

        if let Err(_e) = config.validate_token(request.auth_token.as_deref()) {
            config.log_audit_policy(
                &caller,
                &request.binary,
                &request.args,
                false,
                "invalid auth token",
            );
            let resp = ExecuteResponse {
                allowed: false,
                reason: "invalid auth token".to_string(),
                exit_code: None,
                stdout: None,
                stderr: None,
            };
            writer
                .write_all(serde_json::to_string(&resp)?.as_bytes())
                .await?;
            writer.write_all(b"\n").await?;
            continue;
        }

        let result = if request.stream {
            execute_command_streaming(request.clone(), config, &caller, &mut writer).await
        } else {
            execute_command(request.clone(), config, &caller).await
        };
        emit_exec_audit_events(config, &caller, &request.binary, &request.args, &result);

        let resp = result.into_response();
        if request.stream {
            write_stream_message(
                &mut writer,
                &ExecuteStreamMessage::Result { response: resp },
            )
            .await?;
        } else {
            writer
                .write_all(serde_json::to_string(&resp)?.as_bytes())
                .await?;
            writer.write_all(b"\n").await?;
        }
    }

    Ok(())
}

/// Emit POLICY and (optionally) EXEC_FAILED audit events for a single
/// request. Keeps both handlers aligned so the format stays consistent
/// whether the caller came in over UNIX or TCP.
fn emit_audit_events(
    config: &ServerConfig,
    caller: &CallerIdentity,
    binary: &str,
    args: &[String],
    result: &ExecuteResult,
) {
    // Always emit the policy decision — this is the event historical
    // grep patterns (`[AUDIT] ALLOWED` / `[AUDIT] DENIED`) key on.
    config.log_audit_policy(
        caller,
        binary,
        args,
        result.policy_allowed(),
        result.policy_reason(),
    );

    // If the policy allowed but exec failed, emit a second event so the
    // audit stream can distinguish "LLM denied" from "LLM approved but
    // exec failed". Ignored by legacy grep patterns.
    if let ExecOutcome::Failed { reason } = &result.exec {
        config.log_audit_exec_failed(caller, binary, args, reason);
    }
}

fn emit_exec_audit_events(
    config: &ServerConfig,
    caller: &CallerIdentity,
    binary: &str,
    args: &[String],
    result: &ExecuteResult,
) {
    if let ExecOutcome::Failed { reason } = &result.exec {
        config.log_audit_exec_failed(caller, binary, args, reason);
    }
}

/// Connect to the local guard daemon: UNIX domain socket on Unix, named pipe on
/// Windows. Returns a stream that implements `AsyncRead + AsyncWrite`.
#[cfg(unix)]
async fn connect_local(path: &std::path::Path) -> Result<UnixStream> {
    UnixStream::connect(path)
        .await
        .context("failed to connect to guard server")
}

#[cfg(windows)]
async fn connect_local(
    path: &std::path::Path,
) -> Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use tokio::net::windows::named_pipe::ClientOptions;
    let name = winplat::pipe_name(path);
    ClientOptions::new()
        .open(&name)
        .context("failed to connect to guard server")
}

async fn handle_admin_request(
    config: &ServerConfig,
    caller: &CallerIdentity,
    request: AdminRequest,
) -> AdminResponse {
    if request.requires_daemon_uid() {
        if let Err(e) = config.validate_admin(caller) {
            tracing::warn!("[AUDIT] ADMIN_REJECTED caller={} reason=\"{}\"", caller, e);
            return AdminResponse::Error {
                message: e.to_string(),
            };
        }
    }

    match request {
        AdminRequest::SessionGrant {
            token,
            allow,
            deny,
            ttl_secs,
            prompt_append,
        } => {
            if token.is_empty() {
                return AdminResponse::Error {
                    message: "session token must not be empty".to_string(),
                };
            }
            let expires_at = ttl_secs.map(|secs| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
                    + secs
            });
            let grant = SessionGrant {
                allow,
                deny,
                expires_at,
                prompt_append,
                granted_at: 0, // SessionRegistry::grant fills the current time
            };
            let (before, after) = {
                let mut reg = config.sessions.write().await;
                reg.purge_expired();
                let before = reg.clone();
                reg.grant(token.clone(), grant);
                (before, reg.clone())
            };
            if let Err(err) = persist_session_snapshot(config.session_store.clone(), after).await {
                *config.sessions.write().await = before;
                return AdminResponse::Error {
                    message: format!("failed to persist session grant: {}", err),
                };
            }
            tracing::info!(
                "[AUDIT] SESSION_GRANT caller={} token={} ttl={:?}",
                caller,
                token,
                ttl_secs
            );
            AdminResponse::Ok
        }
        AdminRequest::SessionRevoke { token } => {
            let (removed, before, after) = {
                let mut reg = config.sessions.write().await;
                let before = reg.clone();
                let removed = reg.revoke(&token);
                (removed, before, reg.clone())
            };
            if let Err(err) = persist_session_snapshot(config.session_store.clone(), after).await {
                *config.sessions.write().await = before;
                return AdminResponse::Error {
                    message: format!("failed to persist session revoke: {}", err),
                };
            }
            tracing::info!(
                "[AUDIT] SESSION_REVOKE caller={} token={} existed={}",
                caller,
                token,
                removed
            );
            AdminResponse::Ok
        }
        AdminRequest::SessionList {
            include_history,
            since_unix,
        } => {
            // Opportunistic purge so list shows fresh state and history
            // bookkeeping stays bounded.
            {
                let mut reg = config.sessions.write().await;
                reg.purge_expired();
            }
            if let Err(err) = persist_current_sessions(config).await {
                tracing::warn!("failed to persist purged session state: {}", err);
            }
            let reg = config.sessions.read().await;
            let show_prompt =
                matches!(caller, CallerIdentity::Unix { uid } if *uid == config.daemon_uid);
            let grants = reg
                .list()
                .into_iter()
                .map(|mut grant| {
                    if !show_prompt {
                        grant.token = "(hidden)".to_string();
                        grant.allow.clear();
                        grant.deny.clear();
                        if grant.prompt_append.is_some() {
                            grant.prompt_append = Some("(hidden)".to_string());
                        }
                    }
                    grant
                })
                .collect();
            let history = if include_history {
                reg.list_history(since_unix)
                    .into_iter()
                    .map(|mut grant| {
                        if !show_prompt {
                            grant.token = "(hidden)".to_string();
                            grant.allow.clear();
                            grant.deny.clear();
                            if grant.prompt_append.is_some() {
                                grant.prompt_append = Some("(hidden)".to_string());
                            }
                        }
                        grant
                    })
                    .collect()
            } else {
                Vec::new()
            };
            AdminResponse::SessionList { grants, history }
        }
        AdminRequest::SessionShow { token, limit } => {
            {
                let mut reg = config.sessions.write().await;
                reg.purge_expired();
            }
            if let Err(err) = persist_current_sessions(config).await {
                tracing::warn!("failed to persist purged session state: {}", err);
            }
            let reg = config.sessions.read().await;
            match reg.show(&token, limit.unwrap_or(20)) {
                Some(report) => AdminResponse::SessionShow { report },
                None => AdminResponse::Error {
                    message: format!("unknown session token: '{}'", token),
                },
            }
        }
        AdminRequest::SecretSet { key, value } => {
            if !is_valid_secret_key(&key) {
                return AdminResponse::Error {
                    message: format!("invalid secret key: '{}'", key),
                };
            }
            let caller_uid = match caller {
                CallerIdentity::Unix { uid } => *uid,
                _ => {
                    return AdminResponse::Error {
                        message: "secret operations require a unix socket caller".to_string(),
                    };
                }
            };
            match config.secrets.set(caller_uid, &key, &value).await {
                Ok(()) => {
                    tracing::info!(
                        "[AUDIT] SECRET_SET caller={} uid={} key={}",
                        caller,
                        caller_uid,
                        key
                    );
                    AdminResponse::Ok
                }
                Err(e) => AdminResponse::Error {
                    message: format!("failed to store secret '{}': {}", key, e),
                },
            }
        }
        AdminRequest::SecretDelete { key } => {
            if !is_valid_secret_key(&key) {
                return AdminResponse::Error {
                    message: format!("invalid secret key: '{}'", key),
                };
            }
            let caller_uid = match caller {
                CallerIdentity::Unix { uid } => *uid,
                _ => {
                    return AdminResponse::Error {
                        message: "secret operations require a unix socket caller".to_string(),
                    };
                }
            };
            match config.secrets.delete(caller_uid, &key).await {
                Ok(()) => {
                    tracing::info!(
                        "[AUDIT] SECRET_DELETE caller={} uid={} key={}",
                        caller,
                        caller_uid,
                        key
                    );
                    AdminResponse::Ok
                }
                Err(e) => AdminResponse::Error {
                    message: format!("failed to remove secret '{}': {}", key, e),
                },
            }
        }
        AdminRequest::SecretExists { key } => {
            if !is_valid_secret_key(&key) {
                return AdminResponse::Error {
                    message: format!("invalid secret key: '{}'", key),
                };
            }
            let caller_uid = match caller {
                CallerIdentity::Unix { uid } => *uid,
                _ => {
                    return AdminResponse::Error {
                        message: "secret operations require a unix socket caller".to_string(),
                    };
                }
            };
            match config.secrets.get(caller_uid, &key).await {
                Ok(value) => AdminResponse::SecretExists {
                    exists: value.is_some(),
                },
                Err(e) => AdminResponse::Error {
                    message: format!("failed to inspect secret '{}': {}", key, e),
                },
            }
        }
        AdminRequest::SecretList => {
            let caller_uid = match caller {
                CallerIdentity::Unix { uid } => *uid,
                _ => {
                    return AdminResponse::Error {
                        message: "secret operations require a unix socket caller".to_string(),
                    };
                }
            };
            if caller_uid == config.daemon_uid {
                match config.secrets.list_all().await {
                    Ok(pairs) => {
                        let mut keys: Vec<String> = pairs.into_iter().map(|(_, key)| key).collect();
                        keys.sort();
                        AdminResponse::SecretList { keys }
                    }
                    Err(e) => AdminResponse::Error {
                        message: format!("failed to list secrets: {}", e),
                    },
                }
            } else {
                match config.secrets.list(caller_uid).await {
                    Ok(keys) => AdminResponse::SecretList { keys },
                    Err(e) => AdminResponse::Error {
                        message: format!("failed to list secrets: {}", e),
                    },
                }
            }
        }
        AdminRequest::SecretListDetailed => match config.secrets.list_all().await {
            Ok(pairs) => {
                let mut items: Vec<SecretDetail> = pairs
                    .into_iter()
                    .map(|(uid, key)| SecretDetail {
                        key,
                        uid: if uid == LEGACY_UID_SENTINEL {
                            None
                        } else {
                            Some(uid)
                        },
                        legacy: uid == LEGACY_UID_SENTINEL,
                    })
                    .collect();
                items.sort_by(|a, b| {
                    a.legacy
                        .cmp(&b.legacy)
                        .then_with(|| a.uid.cmp(&b.uid))
                        .then_with(|| a.key.cmp(&b.key))
                });
                AdminResponse::SecretListDetailed { items }
            }
            Err(e) => AdminResponse::Error {
                message: format!("failed to list secrets: {}", e),
            },
        },
        AdminRequest::Ping => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let mode = config
                .evaluator
                .mode()
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| "readonly".to_string());
            AdminResponse::Ping {
                version: env!("CARGO_PKG_VERSION").to_string(),
                uptime_secs: now.saturating_sub(config.started_at_unix),
                mode,
                dry_run: config.dry_run,
            }
        }
        AdminRequest::Status => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let session_count = config.sessions.read().await.list().len();
            let cache_size = config.evaluator.cache_size().await;
            let mode = config
                .evaluator
                .mode()
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| "readonly".to_string());

            AdminResponse::Status {
                status: ServerStatus {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    started_at_unix: config.started_at_unix,
                    uptime_secs: now.saturating_sub(config.started_at_unix),
                    socket_path: config.socket_path.as_ref().map(|p| p.display().to_string()),
                    tcp_port: config.tcp_port,
                    mode,
                    llm_enabled: config.evaluator.llm_enabled(),
                    llm_model_chain: config.evaluator.llm_model_chain(),
                    static_policy: config.evaluator.has_static_policy(),
                    preflight: config.preflight,
                    redact: config.redact,
                    dry_run: config.dry_run,
                    cache_enabled: config.evaluator.cache_enabled(),
                    cache_size,
                    session_count,
                    daemon_uid: config.daemon_uid,
                    exec_identity: if config.exec_as_caller {
                        "caller".to_string()
                    } else {
                        "daemon".to_string()
                    },
                    state_db_path: config
                        .state_db_path
                        .as_ref()
                        .map(|path| path.display().to_string()),
                    secret_backend: config.secrets.backend_name().to_string(),
                },
            }
        }
    }
}

async fn handle_client_tcp(stream: tokio::net::TcpStream, config: &ServerConfig) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        if line.len() > MAX_REQUEST_BYTES {
            tracing::warn!("request too large ({} bytes), dropping", line.len());
            continue;
        }
        let incoming: IncomingMessage = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = ExecuteResponse {
                    allowed: false,
                    reason: format!("invalid request: {}", e),
                    exit_code: None,
                    stdout: None,
                    stderr: None,
                };
                writer
                    .write_all(serde_json::to_string(&resp)?.as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                continue;
            }
        };

        let request = match incoming {
            IncomingMessage::Admin { admin } => {
                // Admin over TCP can never satisfy the daemon-UID rule
                // (no peer-credentials over loopback that we can trust),
                // so only Ping is exposed here. Everything else is
                // Unix-socket-only.
                if !matches!(admin, AdminRequest::Ping) {
                    let resp = AdminResponse::Error {
                        message: "admin RPCs require a unix socket caller".to_string(),
                    };
                    writer
                        .write_all(serde_json::to_string(&resp)?.as_bytes())
                        .await?;
                    writer.write_all(b"\n").await?;
                    continue;
                }
                let caller = CallerIdentity::Tcp {
                    token: "<tcp>".to_string(),
                };
                let resp = handle_admin_request(config, &caller, admin).await;
                writer
                    .write_all(serde_json::to_string(&resp)?.as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                continue;
            }
            IncomingMessage::Execute(req) => req,
        };

        if let Err(_e) = config.validate_token(request.auth_token.as_deref()) {
            let caller = CallerIdentity::Unknown;
            config.log_audit_policy(
                &caller,
                &request.binary,
                &request.args,
                false,
                "invalid auth token",
            );
            let resp = ExecuteResponse {
                allowed: false,
                reason: "invalid auth token".to_string(),
                exit_code: None,
                stdout: None,
                stderr: None,
            };
            writer
                .write_all(serde_json::to_string(&resp)?.as_bytes())
                .await?;
            writer.write_all(b"\n").await?;
            continue;
        }

        let caller = CallerIdentity::Tcp {
            token: request
                .auth_token
                .clone()
                .unwrap_or_else(|| "<none>".to_string()),
        };
        let result = if request.stream {
            execute_command_streaming(request.clone(), config, &caller, &mut writer).await
        } else {
            execute_command(request.clone(), config, &caller).await
        };
        emit_exec_audit_events(config, &caller, &request.binary, &request.args, &result);

        let resp = result.into_response();
        if request.stream {
            write_stream_message(
                &mut writer,
                &ExecuteStreamMessage::Result { response: resp },
            )
            .await?;
        } else {
            writer
                .write_all(serde_json::to_string(&resp)?.as_bytes())
                .await?;
            writer.write_all(b"\n").await?;
        }
    }

    Ok(())
}

/// Policy-level outcome: did the LLM/static engine approve the command?
/// This is distinct from whether the command actually managed to run.
#[derive(Debug, Clone)]
enum PolicyOutcome {
    /// LLM allowed the command. `reason` is the rationale returned by the
    /// evaluator.
    Allowed { reason: String },
    /// LLM denied the command, or the evaluator itself errored. `reason`
    /// carries the message surfaced to the client and audit log.
    Denied { reason: String },
}

/// Execution-level outcome: attempted only when `PolicyOutcome::Allowed`.
#[derive(Debug, Clone)]
enum ExecOutcome {
    /// Command was never attempted (policy denied it first).
    NotAttempted,
    /// Command ran; exit_code and captured streams are present.
    Completed {
        exit_code: Option<i32>,
        stdout: Option<String>,
        stderr: Option<String>,
    },
    /// Policy approved, but spawning/running the child failed. `reason`
    /// describes the OS-level error (e.g. ENOENT on the binary).
    Failed { reason: String },
    /// Policy approved, but the server intentionally did not spawn the child.
    DryRun,
}

struct ExecuteResult {
    policy: PolicyOutcome,
    exec: ExecOutcome,
}

impl ExecuteResult {
    fn denied(reason: impl Into<String>) -> Self {
        Self {
            policy: PolicyOutcome::Denied {
                reason: reason.into(),
            },
            exec: ExecOutcome::NotAttempted,
        }
    }

    /// Convenience constructor for "policy approved and exec completed".
    fn completed(
        reason: impl Into<String>,
        exit_code: Option<i32>,
        stdout: Option<String>,
        stderr: Option<String>,
    ) -> Self {
        Self {
            policy: PolicyOutcome::Allowed {
                reason: reason.into(),
            },
            exec: ExecOutcome::Completed {
                exit_code,
                stdout,
                stderr,
            },
        }
    }

    /// Convenience constructor for "policy approved but exec failed".
    fn exec_failed(policy_reason: impl Into<String>, exec_reason: impl Into<String>) -> Self {
        Self {
            policy: PolicyOutcome::Allowed {
                reason: policy_reason.into(),
            },
            exec: ExecOutcome::Failed {
                reason: exec_reason.into(),
            },
        }
    }

    fn dry_run(reason: impl Into<String>) -> Self {
        Self {
            policy: PolicyOutcome::Allowed {
                reason: reason.into(),
            },
            exec: ExecOutcome::DryRun,
        }
    }

    /// True if the policy approved the command. Note: this does NOT mean
    /// the command actually ran — check the exec outcome for that.
    fn policy_allowed(&self) -> bool {
        matches!(self.policy, PolicyOutcome::Allowed { .. })
    }

    /// Reason for the policy decision (allow rationale or denial reason).
    fn policy_reason(&self) -> &str {
        match &self.policy {
            PolicyOutcome::Allowed { reason } | PolicyOutcome::Denied { reason } => reason,
        }
    }

    /// Build the `ExecuteResponse` wire payload. Callers that need to emit
    /// audit events first should do so before consuming the result.
    fn into_response(self) -> ExecuteResponse {
        let allowed = self.policy_allowed();
        match self.exec {
            ExecOutcome::Completed {
                exit_code,
                stdout,
                stderr,
            } => ExecuteResponse {
                allowed: true,
                reason: match self.policy {
                    PolicyOutcome::Allowed { reason } => reason,
                    PolicyOutcome::Denied { reason } => reason,
                },
                exit_code,
                stdout,
                stderr,
            },
            ExecOutcome::Failed { reason: exec_msg } => ExecuteResponse {
                // Even though the policy allowed it, the command could not
                // actually run. Surface this to the client as `allowed=false`
                // with the exec error as the reason, because from the
                // client's perspective nothing ran successfully. The audit
                // stream still records both POLICY=ALLOWED and EXEC_FAILED.
                allowed: false,
                reason: format!("execution error: {}", exec_msg),
                exit_code: None,
                stdout: None,
                stderr: None,
            },
            ExecOutcome::DryRun => ExecuteResponse {
                allowed: true,
                reason: match self.policy {
                    PolicyOutcome::Allowed { reason } => reason,
                    PolicyOutcome::Denied { reason } => reason,
                },
                exit_code: Some(0),
                stdout: Some("[DRY-RUN] policy allowed; command was not executed\n".to_string()),
                stderr: None,
            },
            ExecOutcome::NotAttempted => ExecuteResponse {
                allowed,
                reason: match self.policy {
                    PolicyOutcome::Allowed { reason } => reason,
                    PolicyOutcome::Denied { reason } => reason,
                },
                exit_code: None,
                stdout: None,
                stderr: None,
            },
        }
    }

    fn session_exec_status(&self) -> SessionExecStatus {
        match self.exec {
            ExecOutcome::Completed { .. } => SessionExecStatus::Completed,
            ExecOutcome::Failed { .. } => SessionExecStatus::Failed,
            ExecOutcome::DryRun => SessionExecStatus::DryRun,
            ExecOutcome::NotAttempted => SessionExecStatus::NotAttempted,
        }
    }
}

async fn write_stream_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &ExecuteStreamMessage,
) -> Result<()> {
    writer
        .write_all(serde_json::to_string(message)?.as_bytes())
        .await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

async fn write_policy_decision<W: AsyncWrite + Unpin>(
    stream_output: bool,
    writer: &mut W,
    allowed: bool,
    reason: &str,
) -> Result<()> {
    if stream_output {
        write_stream_message(
            writer,
            &ExecuteStreamMessage::PolicyDecision {
                allowed,
                reason: reason.to_string(),
            },
        )
        .await?;
    }
    Ok(())
}

async fn execute_command(
    request: ExecuteRequest,
    config: &ServerConfig,
    caller: &CallerIdentity,
) -> ExecuteResult {
    let mut sink = tokio::io::sink();
    execute_command_inner(request, config, caller, false, &mut sink).await
}

async fn execute_command_streaming<W: AsyncWrite + Unpin>(
    request: ExecuteRequest,
    config: &ServerConfig,
    caller: &CallerIdentity,
    writer: &mut W,
) -> ExecuteResult {
    execute_command_inner(request, config, caller, true, writer).await
}

async fn execute_command_inner<W: AsyncWrite + Unpin>(
    request: ExecuteRequest,
    config: &ServerConfig,
    caller: &CallerIdentity,
    stream_output: bool,
    stream_writer: &mut W,
) -> ExecuteResult {
    let session_token = request.session_token.clone();

    // Check recursion depth
    let depth: u32 = std::env::var("GUARD_DEPTH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if depth >= MAX_GUARD_DEPTH {
        let reason = format!("guard recursion depth exceeded (max {})", MAX_GUARD_DEPTH);
        config.log_audit_policy(caller, &request.binary, &request.args, false, &reason);
        let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
        record_live_session_interaction(
            config,
            session_token.as_deref(),
            SessionInteraction {
                at_unix: 0,
                command: request.binary.clone(),
                allowed: false,
                source: SessionDecisionSource::Validation,
                reason: reason.clone(),
                risk: None,
                exec_status: SessionExecStatus::NotAttempted,
            },
        )
        .await;
        return ExecuteResult::denied(reason);
    }

    // Validate binary name: reject paths, traversal, and shell metacharacters.
    // Windows path forms (backslash, drive-letter `:`, UNC) are rejected too so a
    // caller cannot smuggle an absolute/relative trojan path as the "binary".
    if request.binary.contains('/')
        || request.binary.contains('\\')
        || request.binary.contains(':')
        || request.binary.contains("..")
        || request.binary.contains('\0')
        || request.binary.is_empty()
    {
        let looks_like_shell_string = request.binary.contains(char::is_whitespace)
            || request.binary.contains('"')
            || request.binary.contains('\'');
        let reason = if looks_like_shell_string {
            format!(
                "invalid binary name: '{}'. guard run expects `<binary> [args...]`, not a shell string. Pass the command as separate arguments; e.g. `guard run ssh host 'remote cmd'` instead of `guard run 'ssh host \"remote cmd\"'`.",
                request.binary
            )
        } else {
            format!("invalid binary name: '{}'", request.binary)
        };
        config.log_audit_policy(caller, &request.binary, &request.args, false, &reason);
        let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
        record_live_session_interaction(
            config,
            session_token.as_deref(),
            SessionInteraction {
                at_unix: 0,
                command: request.binary.clone(),
                allowed: false,
                source: SessionDecisionSource::Validation,
                reason: reason.clone(),
                risk: None,
                exec_status: SessionExecStatus::NotAttempted,
            },
        )
        .await;
        return ExecuteResult::denied(reason);
    }

    // Reconstruct full command line early so session short-circuit and
    // evaluator share the same command text.
    let command_line = if request.args.is_empty() {
        request.binary.clone()
    } else {
        format!("{} {}", request.binary, request.args.join(" "))
    };

    if let Err(reason) = validate_request_injections(&request, config, caller, &command_line).await
    {
        config.log_audit_policy(caller, &request.binary, &request.args, false, &reason);
        let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
        record_live_session_interaction(
            config,
            session_token.as_deref(),
            SessionInteraction {
                at_unix: 0,
                command: command_line.clone(),
                allowed: false,
                source: SessionDecisionSource::Validation,
                reason: reason.clone(),
                risk: None,
                exec_status: SessionExecStatus::NotAttempted,
            },
        )
        .await;
        return ExecuteResult::denied(reason);
    }

    // Session grants short-circuit both directions: deny wins before the
    // evaluator, allow skips the evaluator entirely.
    //
    // If the caller passes a session_token that the daemon does not know
    // about (revoked, expired, or never existed), the request is rejected
    // — silently falling through to base policy would let an agent run
    // with surprise rules when its operator-issued grant is gone.
    if let Some(ref token) = request.session_token {
        let (decision, exists) = {
            let reg = config.sessions.read().await;
            let decision = reg.check(token, &request.binary, &request.args);
            (decision, reg.has(token))
        };
        if !exists {
            let reason = format!(
                "unknown session token: '{}' is revoked, expired, or never existed",
                token
            );
            config.log_audit_policy(caller, &request.binary, &request.args, false, &reason);
            let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
            return ExecuteResult::denied(reason);
        }
        if let Some((decision, reason)) = decision {
            match decision {
                SessionDecision::Deny => {
                    config.log_audit_policy(caller, &request.binary, &request.args, false, &reason);
                    let _ =
                        write_policy_decision(stream_output, stream_writer, false, &reason).await;
                    record_live_session_interaction(
                        config,
                        session_token.as_deref(),
                        SessionInteraction {
                            at_unix: 0,
                            command: command_line.clone(),
                            allowed: false,
                            source: SessionDecisionSource::SessionDeny,
                            reason: reason.clone(),
                            risk: None,
                            exec_status: SessionExecStatus::NotAttempted,
                        },
                    )
                    .await;
                    return ExecuteResult::denied(reason);
                }
                SessionDecision::Allow => {
                    config.log_audit_policy(caller, &request.binary, &request.args, true, &reason);
                    if let Err(e) =
                        write_policy_decision(stream_output, stream_writer, true, &reason).await
                    {
                        return ExecuteResult::exec_failed(
                            reason,
                            format!("client stream error: {}", e),
                        );
                    }
                    let result = exec_after_approval(
                        request,
                        config,
                        caller,
                        reason.clone(),
                        depth,
                        stream_output,
                        stream_writer,
                    )
                    .await;
                    record_live_session_interaction(
                        config,
                        session_token.as_deref(),
                        SessionInteraction {
                            at_unix: 0,
                            command: command_line.clone(),
                            allowed: true,
                            source: SessionDecisionSource::SessionAllow,
                            reason,
                            risk: None,
                            exec_status: result.session_exec_status(),
                        },
                    )
                    .await;
                    return result;
                }
            }
        }
    }

    if config.preflight && !binary_exists_on_path(&request.binary) {
        let reason = format!(
            "unknown binary: '{}' is not available on the guard server PATH",
            request.binary
        );
        config.log_audit_policy(caller, &request.binary, &request.args, false, &reason);
        let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
        record_live_session_interaction(
            config,
            session_token.as_deref(),
            SessionInteraction {
                at_unix: 0,
                command: command_line.clone(),
                allowed: false,
                source: SessionDecisionSource::Validation,
                reason: reason.clone(),
                risk: None,
                exec_status: SessionExecStatus::NotAttempted,
            },
        )
        .await;
        return ExecuteResult::denied(reason);
    }

    if config.preflight {
        if let Some(reason) = deterministic_credential_deny_reason(&request.binary, &request.args) {
            config.log_audit_policy(caller, &request.binary, &request.args, false, &reason);
            let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
            record_live_session_interaction(
                config,
                session_token.as_deref(),
                SessionInteraction {
                    at_unix: 0,
                    command: command_line.clone(),
                    allowed: false,
                    source: SessionDecisionSource::Validation,
                    reason: reason.clone(),
                    risk: None,
                    exec_status: SessionExecStatus::NotAttempted,
                },
            )
            .await;
            return ExecuteResult::denied(reason);
        }
    }

    // Pull session-scoped additive prompt, if any. The evaluator appends
    // it to the system prompt for this single call so the LLM has the
    // session context that the static glob patterns cannot express.
    let session_prompt = if let Some(ref token) = request.session_token {
        let reg = config.sessions.read().await;
        reg.prompt_append_for(token)
    } else {
        None
    };

    let eval_result = config
        .evaluator
        .evaluate_with_context(&command_line, session_prompt.as_deref())
        .await;

    match eval_result {
        crate::evaluate::EvalResult::Deny {
            reason,
            source,
            risk,
        } => {
            config.log_audit_policy(caller, &request.binary, &request.args, false, &reason);
            let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
            record_live_session_interaction(
                config,
                session_token.as_deref(),
                SessionInteraction {
                    at_unix: 0,
                    command: command_line.clone(),
                    allowed: false,
                    source: session_source_from_eval(source),
                    reason: reason.clone(),
                    risk,
                    exec_status: SessionExecStatus::NotAttempted,
                },
            )
            .await;
            ExecuteResult::denied(reason)
        }
        crate::evaluate::EvalResult::Error(e) => {
            tracing::error!("evaluation error: {}", e);
            let reason = format!("evaluation error: {}", e);
            config.log_audit_policy(caller, &request.binary, &request.args, false, &reason);
            let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
            record_live_session_interaction(
                config,
                session_token.as_deref(),
                SessionInteraction {
                    at_unix: 0,
                    command: command_line.clone(),
                    allowed: false,
                    source: SessionDecisionSource::EvaluatorError,
                    reason: reason.clone(),
                    risk: None,
                    exec_status: SessionExecStatus::NotAttempted,
                },
            )
            .await;
            ExecuteResult::denied(reason)
        }
        crate::evaluate::EvalResult::Allow {
            reason,
            source,
            risk,
        } => {
            tracing::debug!("command allowed: {}", reason);
            config.log_audit_policy(caller, &request.binary, &request.args, true, &reason);
            if let Err(e) = write_policy_decision(stream_output, stream_writer, true, &reason).await
            {
                return ExecuteResult::exec_failed(reason, format!("client stream error: {}", e));
            }
            let result = exec_after_approval(
                request,
                config,
                caller,
                reason.clone(),
                depth,
                stream_output,
                stream_writer,
            )
            .await;
            record_live_session_interaction(
                config,
                session_token.as_deref(),
                SessionInteraction {
                    at_unix: 0,
                    command: command_line,
                    allowed: true,
                    source: session_source_from_eval(source),
                    reason,
                    risk,
                    exec_status: result.session_exec_status(),
                },
            )
            .await;
            result
        }
    }
}

fn session_source_from_eval(source: crate::evaluate::EvalSource) -> SessionDecisionSource {
    match source {
        crate::evaluate::EvalSource::Llm => SessionDecisionSource::Llm,
        crate::evaluate::EvalSource::StaticPolicy => SessionDecisionSource::StaticPolicy,
    }
}

async fn persist_session_snapshot(
    session_store: Option<SessionStore>,
    snapshot: SessionRegistry,
) -> Result<()> {
    if let Some(store) = session_store {
        store.persist_registry(&snapshot).await?;
    }
    Ok(())
}

async fn persist_current_sessions(config: &ServerConfig) -> Result<()> {
    let snapshot = { config.sessions.read().await.clone() };
    persist_session_snapshot(config.session_store.clone(), snapshot).await
}

async fn record_live_session_interaction(
    config: &ServerConfig,
    token: Option<&str>,
    interaction: SessionInteraction,
) {
    let Some(token) = token else {
        return;
    };
    let snapshot = {
        let mut reg = config.sessions.write().await;
        if reg.has(token) {
            reg.record_interaction(token, interaction);
            Some(reg.clone())
        } else {
            None
        }
    };
    if let Some(snapshot) = snapshot {
        if let Err(err) = persist_session_snapshot(config.session_store.clone(), snapshot).await {
            tracing::warn!("failed to persist session interaction: {}", err);
        }
    }
}

#[derive(Debug, Clone)]
struct ExecCallerContext {
    uid: u32,
    gid: u32,
    username: String,
    home_dir: PathBuf,
}

#[cfg(unix)]
fn resolve_exec_caller_context(uid: u32) -> Result<ExecCallerContext> {
    let user = uzers::get_user_by_uid(uid)
        .ok_or_else(|| anyhow::anyhow!("caller uid {} does not exist in passwd", uid))?;
    let username = user
        .name()
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("caller uid {} has a non-utf8 username", uid))?
        .to_string();
    Ok(ExecCallerContext {
        uid,
        gid: user.primary_group_id(),
        username,
        home_dir: user.home_dir().to_path_buf(),
    })
}

/// On Windows there is no setuid-equivalent here; the daemon executes approved
/// commands as its own service identity. `--exec-as-caller` is therefore
/// rejected at startup, so this should only ever be reached with it disabled.
#[cfg(windows)]
fn apply_exec_identity(
    _cmd: &mut Command,
    config: &ServerConfig,
    _caller: &CallerIdentity,
) -> Result<Option<ExecCallerContext>> {
    if config.exec_as_caller {
        bail!("--exec-as-caller is not supported on Windows");
    }
    Ok(None)
}

#[cfg(unix)]
fn apply_exec_identity(
    cmd: &mut Command,
    config: &ServerConfig,
    caller: &CallerIdentity,
) -> Result<Option<ExecCallerContext>> {
    if !config.exec_as_caller {
        return Ok(None);
    }

    let caller_uid = match caller {
        CallerIdentity::Unix { uid } => *uid,
        _ => bail!("exec-as-caller requires a unix socket caller"),
    };
    let context = resolve_exec_caller_context(caller_uid)?;
    let username = CString::new(context.username.clone())
        .context("caller username contains an interior NUL byte")?;
    let gid = context.gid;

    cmd.gid(gid);
    cmd.uid(context.uid);
    unsafe {
        cmd.pre_exec(move || {
            if libc::initgroups(username.as_ptr(), gid as _) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    Ok(Some(context))
}

/// Execute a command the policy layer has already approved.
///
/// Entered from either the LLM evaluator path or a session-grant allow
/// match. Failures returned from here are exec-level, not policy-level,
/// so the audit stream can tell "policy said no" apart from "policy
/// said yes but the kernel refused".
async fn exec_after_approval<W: AsyncWrite + Unpin>(
    request: ExecuteRequest,
    config: &ServerConfig,
    caller: &CallerIdentity,
    allow_reason: String,
    depth: u32,
    stream_output: bool,
    stream_writer: &mut W,
) -> ExecuteResult {
    if config.dry_run {
        tracing::info!(
            "Dry-run: not executing {} {:?} ({})",
            request.binary,
            request.args,
            caller
        );
        return ExecuteResult::dry_run(allow_reason);
    }

    let user_key = caller.user_key();
    let tool_env_uid = match caller {
        CallerIdentity::Unix { uid } => Some(*uid),
        _ => None,
    };
    let tool_env = {
        let mut reg = config.tool_registry.write().await;
        let _ = reg.reload_if_stale();
        reg.resolve_env(
            &request.binary,
            &config.secrets,
            tool_env_uid,
            user_key.as_deref(),
        )
        .await
    };
    let tool_env = match tool_env {
        Ok(env) => env,
        Err(e) => {
            return ExecuteResult::exec_failed(allow_reason, format!("tool config error: {}", e));
        }
    };
    let mut tool_env = tool_env;

    for key in request.env.keys().chain(request.secrets.keys()) {
        if !is_valid_env_name(key) {
            return ExecuteResult::exec_failed(
                allow_reason,
                format!("invalid injected environment variable name: '{}'", key),
            );
        }
    }

    // Per-run --env injection, like --secret, is only honored for callers with a
    // trusted local UID namespace. A non-Unix (Windows named-pipe) caller cannot
    // set child environment variables, so it cannot redirect a tool's config or
    // endpoint lookup (e.g. cmk's %HOME%/%USERPROFILE%) via --env.
    if !request.env.is_empty() && !matches!(caller, CallerIdentity::Unix { .. }) {
        return ExecuteResult::exec_failed(
            allow_reason,
            "per-run --env injection requires a caller with a trusted local UID namespace"
                .to_string(),
        );
    }
    for (key, value) in &request.env {
        tool_env.insert(key.clone(), value.clone());
    }

    // Per-run --secret injection is only available to callers with a trusted
    // local UID namespace (Unix peer credentials). It is required only when the
    // request actually asks for secrets; a request with none proceeds on any
    // transport (e.g. a Windows named-pipe caller).
    if !request.secrets.is_empty() {
        let caller_uid = match caller {
            CallerIdentity::Unix { uid } => *uid,
            _ => {
                return ExecuteResult::exec_failed(
                    allow_reason,
                    "secret injection requires a caller with a trusted local UID namespace (unix peer credentials)".to_string(),
                );
            }
        };
        for (env_var, secret_key) in &request.secrets {
            let value = match config.secrets.get(caller_uid, secret_key).await {
                Ok(Some(value)) => value,
                Ok(None) => {
                    return ExecuteResult::exec_failed(
                        allow_reason,
                        format!(
                            "secret not found: '{}' (required by --secret {})",
                            secret_key, env_var
                        ),
                    );
                }
                Err(e) => {
                    return ExecuteResult::exec_failed(
                        allow_reason,
                        format!("failed to read secret '{}': {}", secret_key, e),
                    );
                }
            };
            tool_env.insert(env_var.clone(), value);
        }
    }

    tracing::info!(
        "Executing: {} {:?} ({})",
        request.binary,
        request.args,
        caller
    );

    let mut cmd = Command::new(&request.binary);
    cmd.args(&request.args);
    cmd.stdin(Stdio::null());

    // SECURITY: Clear ALL inherited env vars. The child process gets only what we
    // explicitly allow. This prevents leaking the guard's own secrets (API keys,
    // auth tokens) via env, printenv, /proc/self/environ, or $VAR expansion.
    cmd.env_clear();

    #[cfg(unix)]
    let allow_vars: &[&str] = &[
        "PATH",
        "HOME",
        "USER",
        "LANG",
        "LANGUAGE",
        "LC_ALL",
        "LC_CTYPE",
        "TERM",
        "TZ",
        "SHELL",
        "LOGNAME",
        "XDG_RUNTIME_DIR",
        "SSH_AUTH_SOCK",
    ];
    // On Windows there is no HOME/USER convention; tools resolve the profile via
    // USERPROFILE / HOMEDRIVE+HOMEPATH, so those must pass through for the child
    // (e.g. cmk reads %USERPROFILE%\.cmk\config).
    #[cfg(windows)]
    let allow_vars: &[&str] = &[
        "PATH",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "HOME",
        "APPDATA",
        "LOCALAPPDATA",
        "TEMP",
        "TMP",
        "SystemRoot",
        "SystemDrive",
        "ComSpec",
        "PATHEXT",
        "windir",
        "USERNAME",
        "USERDOMAIN",
        "NUMBER_OF_PROCESSORS",
        "PROCESSOR_ARCHITECTURE",
    ];
    for var in allow_vars {
        if let Ok(val) = std::env::var(var) {
            cmd.env(var, val);
        }
    }

    let exec_caller = match apply_exec_identity(&mut cmd, config, caller) {
        Ok(context) => context,
        Err(e) => {
            return ExecuteResult::exec_failed(allow_reason, format!("exec identity error: {}", e));
        }
    };

    for (key, value) in &tool_env {
        cmd.env(key, value);
    }

    if let Some(context) = &exec_caller {
        cmd.env("HOME", &context.home_dir);
        cmd.env("USER", &context.username);
        cmd.env("LOGNAME", &context.username);
        cmd.env_remove("SSH_AUTH_SOCK");
        cmd.env_remove("XDG_RUNTIME_DIR");
        let runtime_dir = PathBuf::from(format!("/run/user/{}", context.uid));
        if runtime_dir.exists() {
            cmd.env("XDG_RUNTIME_DIR", runtime_dir);
        }
    }

    cmd.env("GUARD_DEPTH", (depth + 1).to_string());

    // Nested-eval shims are a Unix construct; on Windows, prepending a shim dir
    // only widens CreateProcess's bare-name search path with no benefit, so it is
    // skipped there.
    #[cfg(unix)]
    if let Some(ref shim_dir) = config.shim_dir {
        let base_path = std::env::var("PATH").unwrap_or_default();
        cmd.env("PATH", format!("{}:{}", shim_dir.display(), base_path));
    }

    // On Windows, pin the child working directory to a fixed system directory so
    // the inherited (daemon) CWD is not part of CreateProcess's bare-name search
    // order, removing a path by which a planted executable could shadow the
    // intended binary.
    #[cfg(windows)]
    if let Some(sysroot) = std::env::var_os("SystemRoot") {
        cmd.current_dir(sysroot);
    }

    if stream_output {
        return execute_spawn_streaming(
            cmd,
            &request.binary,
            allow_reason,
            config,
            &tool_env,
            stream_writer,
        )
        .await;
    }

    let output = match cmd.output().await {
        Ok(o) => o,
        Err(e) => {
            return ExecuteResult::exec_failed(
                allow_reason,
                format!("failed to execute '{}': {}", request.binary, e),
            );
        }
    };

    let stdout = if output.stdout.is_empty() {
        None
    } else {
        let raw = &output.stdout[..output.stdout.len().min(MAX_OUTPUT_BYTES)];
        let s = String::from_utf8_lossy(raw).to_string();
        Some(redact_command_text(config, &tool_env, s))
    };

    let stderr = if output.stderr.is_empty() {
        None
    } else {
        let raw = &output.stderr[..output.stderr.len().min(MAX_OUTPUT_BYTES)];
        let s = String::from_utf8_lossy(raw).to_string();
        Some(redact_command_text(config, &tool_env, s))
    };

    ExecuteResult::completed(allow_reason, output.status.code(), stdout, stderr)
}

/// Read the daemon's effective UID without pulling in libc as a direct
/// dep. /proc/self/status is the kernel-blessed source on Linux. Falls
/// back to 0 only if procfs is missing — in that case admin only works
/// when the daemon happens to be uid 0, which is the conservative default.
#[cfg(unix)]
fn current_uid() -> u32 {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            if let Some(uid_str) = rest.split_whitespace().next() {
                if let Ok(uid) = uid_str.parse::<u32>() {
                    return uid;
                }
            }
        }
    }
    0
}

/// Windows has no numeric daemon UID; admin authorization there is keyed on the
/// caller SID, not this value, so a stable sentinel is sufficient.
#[cfg(windows)]
fn current_uid() -> u32 {
    0
}

fn binary_exists_on_path(binary: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };

    std::env::split_paths(&path).any(|dir| {
        let candidate = dir.join(binary);
        #[cfg(unix)]
        {
            match std::fs::metadata(&candidate) {
                Ok(metadata) => metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
                Err(_) => false,
            }
        }
        #[cfg(windows)]
        {
            windows_executable_exists(&candidate)
        }
    })
}

/// Windows executability is by extension, not a mode bit: accept the candidate
/// as-is or with any PATHEXT extension appended (so a bare `cmk` matches
/// `cmk.exe`).
#[cfg(windows)]
fn windows_executable_exists(candidate: &std::path::Path) -> bool {
    if std::fs::metadata(candidate)
        .map(|m| m.is_file())
        .unwrap_or(false)
    {
        return true;
    }
    let exts = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
    let file = match candidate.file_name().and_then(|f| f.to_str()) {
        Some(f) => f,
        None => return false,
    };
    for ext in exts.split(';') {
        let ext = ext.trim();
        if ext.is_empty() {
            continue;
        }
        let with_ext = candidate.with_file_name(format!("{}{}", file, ext));
        if std::fs::metadata(&with_ext)
            .map(|m| m.is_file())
            .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

fn deterministic_credential_deny_reason(binary: &str, args: &[String]) -> Option<String> {
    let command = if args.is_empty() {
        binary.to_string()
    } else {
        format!("{} {}", binary, args.join(" "))
    };
    let lower = command.to_ascii_lowercase();
    let tokens = command_tokens(&lower);

    if lower.contains("/proc/") && lower.contains("/environ") {
        return Some(
            "credential preflight denied: /proc/*/environ can expose process secrets".to_string(),
        );
    }

    if tokens.iter().any(|token| token == "ps") && tokens.iter().any(|token| token == "eww") {
        return Some(
            "credential preflight denied: ps eww can expose process environments".to_string(),
        );
    }

    if tokens
        .iter()
        .any(|token| token == "env" || token == "printenv")
    {
        return Some(
            "credential preflight denied: environment dumps can expose credentials".to_string(),
        );
    }

    if lower.contains("/etc/default/guard")
        || lower.contains("/var/lib/guard/.ssh/")
        || lower.contains("/var/lib/guard/.kube/config")
        || lower.contains("/.ssh/id_")
        || lower.contains("~/.ssh/id_")
        || lower.contains("/.kube/config")
        || lower.contains("~/.kube/config")
        || lower.contains("/.aws/credentials")
        || lower.contains("~/.aws/credentials")
        || lower.contains("/.env")
        || tokens.iter().any(|token| token == ".env")
    {
        return Some(
            "credential preflight denied: command references credential material".to_string(),
        );
    }

    if has_token(&tokens, "kubectl")
        && has_token(&tokens, "config")
        && has_token(&tokens, "view")
        && has_token(&tokens, "--raw")
    {
        return Some("credential preflight denied: kubectl config view --raw can expose kubeconfig credentials".to_string());
    }

    if has_token(&tokens, "kubectl")
        && (has_token(&tokens, "secret")
            || has_token(&tokens, "secrets")
            || lower.contains("/secrets/")
            || lower.contains("/secrets?"))
    {
        return Some(
            "credential preflight denied: kubectl secret access can expose cluster credentials"
                .to_string(),
        );
    }

    if has_token(&tokens, "kubectl") && has_token(&tokens, "create") && has_token(&tokens, "token")
    {
        return Some(
            "credential preflight denied: kubectl create token emits credential material"
                .to_string(),
        );
    }

    None
}

fn has_token(tokens: &[String], needle: &str) -> bool {
    tokens.iter().any(|token| token == needle)
}

fn command_tokens(command: &str) -> Vec<String> {
    command
        .split(|c: char| {
            !(c.is_ascii_alphanumeric()
                || matches!(c, '-' | '_' | '.' | '/' | '~' | '*' | '?' | ':'))
        })
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

fn is_valid_secret_key(value: &str) -> bool {
    if value.is_empty()
        || value.contains('\0')
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains("//")
    {
        return false;
    }

    value.split('/').all(|part| {
        !part.is_empty()
            && part != "."
            && part != ".."
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    })
}

fn invalid_shell_secret_reference(
    command_line: &str,
    env_var: &str,
    secret_key: &str,
) -> Option<String> {
    if is_valid_env_name(secret_key) {
        return None;
    }

    let bare_ref = format!("${secret_key}");
    let braced_ref = format!("${{{secret_key}}}");
    if command_line.contains(&bare_ref) || command_line.contains(&braced_ref) {
        return Some(format!(
            "invalid secret environment reference '{}': secret '{}' is injected as ${}. Use `--secret {}={}` to choose a different env var.",
            bare_ref, secret_key, env_var, env_var, secret_key
        ));
    }

    None
}

async fn validate_request_injections(
    request: &ExecuteRequest,
    config: &ServerConfig,
    caller: &CallerIdentity,
    command_line: &str,
) -> std::result::Result<(), String> {
    for key in request.env.keys().chain(request.secrets.keys()) {
        if !is_valid_env_name(key) {
            return Err(format!(
                "invalid injected environment variable name: '{}'",
                key
            ));
        }
    }

    for env_var in request.secrets.keys() {
        if request.env.contains_key(env_var) {
            return Err(format!(
                "conflicting injection for '{}': choose either --env or --secret, not both",
                env_var
            ));
        }
    }

    let caller_uid = match caller {
        CallerIdentity::Unix { uid } => *uid,
        _ => {
            if !request.secrets.is_empty() {
                return Err("secret injection requires a caller with a trusted local UID namespace (unix peer credentials)".to_string());
            }
            return Ok(());
        }
    };

    for (env_var, secret_key) in &request.secrets {
        if !is_valid_secret_key(secret_key) {
            return Err(format!("invalid secret key: '{}'", secret_key));
        }
        if let Some(reason) = invalid_shell_secret_reference(command_line, env_var, secret_key) {
            return Err(reason);
        }
        match config.secrets.get(caller_uid, secret_key).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err(format!(
                    "secret not found: '{}' (required by --secret {})",
                    secret_key, env_var
                ));
            }
            Err(e) => {
                return Err(format!("failed to read secret '{}': {}", secret_key, e));
            }
        }
    }

    Ok(())
}

#[derive(Debug)]
struct StreamChunk {
    stream: OutputStream,
    data: String,
}

async fn execute_spawn_streaming<W: AsyncWrite + Unpin>(
    mut cmd: Command,
    binary: &str,
    allow_reason: String,
    config: &ServerConfig,
    tool_env: &HashMap<String, String>,
    writer: &mut W,
) -> ExecuteResult {
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            return ExecuteResult::exec_failed(
                allow_reason,
                format!("failed to execute '{}': {}", binary, e),
            );
        }
    };

    let (tx, mut rx) = mpsc::channel::<StreamChunk>(32);
    let mut stream_tasks = Vec::new();

    if let Some(stdout) = child.stdout.take() {
        let tx = tx.clone();
        stream_tasks.push(tokio::spawn(async move {
            forward_stream_lines(stdout, OutputStream::Stdout, tx).await;
        }));
    }

    if let Some(stderr) = child.stderr.take() {
        let tx = tx.clone();
        stream_tasks.push(tokio::spawn(async move {
            forward_stream_lines(stderr, OutputStream::Stderr, tx).await;
        }));
    }

    drop(tx);

    let mut stdout_redaction = RedactionState::default();
    let mut stderr_redaction = RedactionState::default();
    let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        tokio::select! {
            maybe_chunk = rx.recv() => {
                match maybe_chunk {
                    Some(chunk) => {
                    let redaction_state = match chunk.stream {
                        OutputStream::Stdout => &mut stdout_redaction,
                        OutputStream::Stderr => &mut stderr_redaction,
                    };
                    let data = redact_command_text_with_state(config, tool_env, chunk.data, redaction_state);
                    let message = match chunk.stream {
                        OutputStream::Stdout => ExecuteStreamMessage::Stdout { data },
                        OutputStream::Stderr => ExecuteStreamMessage::Stderr { data },
                    };

                    if let Err(e) = write_stream_message(writer, &message).await {
                        let _ = child.kill().await;
                        return ExecuteResult::exec_failed(allow_reason, format!("client stream error: {}", e));
                    }
                    }
                    None => break,
                }
            }
            _ = keepalive.tick() => {
                if let Err(e) = write_stream_message(writer, &ExecuteStreamMessage::Keepalive).await {
                    let _ = child.kill().await;
                    return ExecuteResult::exec_failed(allow_reason, format!("client stream error: {}", e));
                }
            }
        }
    }

    for task in stream_tasks {
        let _ = task.await;
    }

    let status = match child.wait().await {
        Ok(status) => status,
        Err(e) => {
            return ExecuteResult::exec_failed(
                allow_reason,
                format!("failed to wait for '{}': {}", binary, e),
            );
        }
    };

    ExecuteResult::completed(allow_reason, status.code(), None, None)
}

async fn forward_stream_lines<R>(reader: R, stream: OutputStream, tx: mpsc::Sender<StreamChunk>)
where
    R: AsyncRead + Unpin,
{
    let mut reader = BufReader::new(reader);

    loop {
        let mut data = String::new();
        match reader.read_line(&mut data).await {
            Ok(0) => break,
            Ok(_) => {
                if tx.send(StreamChunk { stream, data }).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                let _ = tx
                    .send(StreamChunk {
                        stream: OutputStream::Stderr,
                        data: format!("guard stream read error: {}\n", e),
                    })
                    .await;
                break;
            }
        }
    }
}

fn redact_command_text(
    config: &ServerConfig,
    tool_env: &HashMap<String, String>,
    text: String,
) -> String {
    redact_command_text_inner(config, tool_env, text, None)
}

fn redact_command_text_with_state(
    config: &ServerConfig,
    tool_env: &HashMap<String, String>,
    text: String,
    state: &mut RedactionState,
) -> String {
    redact_command_text_inner(config, tool_env, text, Some(state))
}

fn redact_command_text_inner(
    config: &ServerConfig,
    tool_env: &HashMap<String, String>,
    text: String,
    state: Option<&mut RedactionState>,
) -> String {
    if !config.redact {
        return text;
    }

    let secret_refs: Vec<&str> = config
        .redact_secrets
        .iter()
        .map(|s| s.as_str())
        .chain(tool_env.values().map(|s| s.as_str()))
        .collect();

    // First: exact-match redaction catches bare secret values in output.
    let text = redact_exact_secrets(&text, &secret_refs);
    // Then: regex and context-based redaction catches KEY=value, YAML env
    // pairs, PEM blocks, etc.
    if let Some(state) = state {
        let had_trailing_newline = text.ends_with('\n');
        let mut redacted = text
            .lines()
            .map(|line| redact_output_with_state(line, state))
            .collect::<Vec<_>>()
            .join("\n");
        if had_trailing_newline {
            redacted.push('\n');
        }
        redacted
    } else {
        redact_output_text(&text)
    }
}

pub struct Client {
    socket_path: Option<PathBuf>,
    tcp_port: Option<u16>,
    auth_token: Option<String>,
    session_token: Option<String>,
}

impl Client {
    pub fn new(socket_path: Option<PathBuf>, tcp_port: Option<u16>) -> Self {
        Self {
            socket_path,
            tcp_port,
            auth_token: None,
            session_token: None,
        }
    }

    pub fn with_auth(mut self, token: String) -> Self {
        self.auth_token = Some(token);
        self
    }

    pub fn with_session(mut self, session_token: String) -> Self {
        self.session_token = Some(session_token);
        self
    }

    pub async fn send_admin(&self, request: AdminRequest) -> Result<AdminResponse> {
        let request_name = match &request {
            AdminRequest::SessionGrant { .. } => "session_grant",
            AdminRequest::SessionRevoke { .. } => "session_revoke",
            AdminRequest::SessionList { .. } => "session_list",
            AdminRequest::SessionShow { .. } => "session_show",
            AdminRequest::SecretSet { .. } => "secret_set",
            AdminRequest::SecretDelete { .. } => "secret_delete",
            AdminRequest::SecretExists { .. } => "secret_exists",
            AdminRequest::SecretList => "secret_list",
            AdminRequest::SecretListDetailed => "secret_list_detailed",
            AdminRequest::Status => "status",
            AdminRequest::Ping => "ping",
        };
        let envelope = IncomingMessage::Admin { admin: request };
        let line = serde_json::to_string(&envelope)?;

        if let Some(ref socket_path) = self.socket_path {
            let stream = connect_local(socket_path).await?;
            let (reader, writer) = tokio::io::split(stream);
            let mut writer = tokio::io::BufWriter::new(writer);
            writer.write_all(line.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;

            let mut lines = BufReader::new(reader).lines();
            let response_line = lines
                .next_line()
                .await?
                .ok_or_else(|| anyhow::anyhow!("server closed connection without response"))?;
            let resp = parse_admin_response_line(&response_line, request_name)?;
            Ok(resp)
        } else if let Some(port) = self.tcp_port {
            let addr = format!("127.0.0.1:{}", port);
            let stream = tokio::net::TcpStream::connect(&addr)
                .await
                .context("failed to connect to guard server")?;
            let (reader, writer) = stream.into_split();
            let mut writer = tokio::io::BufWriter::new(writer);
            writer.write_all(line.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;

            let mut lines = BufReader::new(reader).lines();
            let response_line = lines
                .next_line()
                .await?
                .ok_or_else(|| anyhow::anyhow!("server closed connection without response"))?;
            let resp = parse_admin_response_line(&response_line, request_name)?;
            Ok(resp)
        } else {
            anyhow::bail!("no socket path or TCP port configured");
        }
    }

    pub fn endpoint_for_log(&self) -> String {
        if let Some(ref socket_path) = self.socket_path {
            format!("unix:{}", socket_path.display())
        } else if let Some(port) = self.tcp_port {
            format!("tcp:127.0.0.1:{}", port)
        } else {
            "unconfigured".to_string()
        }
    }

    pub async fn execute(&self, binary: &str, args: &[String]) -> Result<ExecuteResponse> {
        self.execute_with_injections(binary, args, HashMap::new(), HashMap::new())
            .await
    }

    pub async fn execute_with_injections(
        &self,
        binary: &str,
        args: &[String],
        env: HashMap<String, String>,
        secrets: HashMap<String, String>,
    ) -> Result<ExecuteResponse> {
        let request = self.build_execute_request(binary, args, env, secrets, false);

        tracing::debug!(
            binary = %binary,
            arg_count = args.len(),
            endpoint = %self.endpoint_for_log(),
            "client dispatching execute request"
        );

        if let Some(ref socket_path) = self.socket_path {
            self.send_unix(socket_path, &request).await
        } else if let Some(port) = self.tcp_port {
            self.send_tcp(port, &request).await
        } else {
            anyhow::bail!("no socket path or TCP port configured");
        }
    }

    pub async fn execute_streaming<F>(
        &self,
        binary: &str,
        args: &[String],
        mut on_output: F,
    ) -> Result<ExecuteResponse>
    where
        F: FnMut(OutputStream, &str),
    {
        self.execute_streaming_with_injections(
            binary,
            args,
            HashMap::new(),
            HashMap::new(),
            on_output,
        )
        .await
    }

    pub async fn execute_streaming_with_injections<F>(
        &self,
        binary: &str,
        args: &[String],
        env: HashMap<String, String>,
        secrets: HashMap<String, String>,
        mut on_output: F,
    ) -> Result<ExecuteResponse>
    where
        F: FnMut(OutputStream, &str),
    {
        let request = self.build_execute_request(binary, args, env, secrets, true);

        tracing::debug!(
            binary = %binary,
            arg_count = args.len(),
            endpoint = %self.endpoint_for_log(),
            "client dispatching streaming execute request"
        );

        if let Some(ref socket_path) = self.socket_path {
            self.send_unix_streaming(socket_path, &request, &mut on_output)
                .await
        } else if let Some(port) = self.tcp_port {
            self.send_tcp_streaming(port, &request, &mut on_output)
                .await
        } else {
            anyhow::bail!("no socket path or TCP port configured");
        }
    }

    fn build_execute_request(
        &self,
        binary: &str,
        args: &[String],
        env: HashMap<String, String>,
        secrets: HashMap<String, String>,
        stream: bool,
    ) -> ExecuteRequest {
        ExecuteRequest {
            binary: binary.to_string(),
            args: args.to_vec(),
            auth_token: self.auth_token.clone(),
            env,
            secrets,
            stream,
            session_token: self.session_token.clone(),
        }
    }

    async fn send_unix(
        &self,
        socket_path: &PathBuf,
        request: &ExecuteRequest,
    ) -> Result<ExecuteResponse> {
        tracing::debug!(
            socket = %socket_path.display(),
            "connecting to guard server"
        );
        let stream = connect_local(socket_path).await?;
        tracing::debug!(
            socket = %socket_path.display(),
            "connected to guard server"
        );

        let (reader, writer) = tokio::io::split(stream);

        let mut writer = tokio::io::BufWriter::new(writer);
        tracing::debug!(
            binary = %request.binary,
            arg_count = request.args.len(),
            "sending execute request"
        );
        writer
            .write_all(serde_json::to_string(request)?.as_bytes())
            .await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        tracing::debug!("execute request sent; waiting for server response");

        let mut reader = BufReader::new(reader).lines();
        let Some(line) = reader.next_line().await? else {
            bail!("server closed connection without response");
        };

        let response: ExecuteResponse =
            serde_json::from_str(&line).context("invalid server response")?;
        tracing::debug!(
            allowed = response.allowed,
            exit_code = ?response.exit_code,
            has_stdout = response.stdout.is_some(),
            has_stderr = response.stderr.is_some(),
            "received execute response"
        );

        Ok(response)
    }

    async fn send_unix_streaming<F>(
        &self,
        socket_path: &PathBuf,
        request: &ExecuteRequest,
        on_output: &mut F,
    ) -> Result<ExecuteResponse>
    where
        F: FnMut(OutputStream, &str),
    {
        tracing::debug!(
            socket = %socket_path.display(),
            "connecting to guard server"
        );
        let stream = connect_local(socket_path).await?;
        tracing::debug!(
            socket = %socket_path.display(),
            "connected to guard server"
        );

        let (reader, writer) = tokio::io::split(stream);
        let mut writer = tokio::io::BufWriter::new(writer);
        tracing::debug!(
            binary = %request.binary,
            arg_count = request.args.len(),
            "sending streaming execute request"
        );
        writer
            .write_all(serde_json::to_string(request)?.as_bytes())
            .await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        tracing::debug!("streaming execute request sent; waiting for server response");

        let mut reader = BufReader::new(reader).lines();
        read_streaming_response(&mut reader, on_output).await
    }

    async fn send_tcp(&self, port: u16, request: &ExecuteRequest) -> Result<ExecuteResponse> {
        let addr = format!("127.0.0.1:{}", port);
        tracing::debug!(addr = %addr, "connecting to guard server");
        let stream = tokio::net::TcpStream::connect(&addr)
            .await
            .context("failed to connect to guard server")?;
        tracing::debug!(addr = %addr, "connected to guard server");

        let (reader, writer) = stream.into_split();

        let mut writer = tokio::io::BufWriter::new(writer);
        tracing::debug!(
            binary = %request.binary,
            arg_count = request.args.len(),
            "sending execute request"
        );
        writer
            .write_all(serde_json::to_string(request)?.as_bytes())
            .await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        tracing::debug!("execute request sent; waiting for server response");

        let mut reader = BufReader::new(reader).lines();
        let Some(line) = reader.next_line().await? else {
            bail!("server closed connection without response");
        };

        let response: ExecuteResponse =
            serde_json::from_str(&line).context("invalid server response")?;
        tracing::debug!(
            allowed = response.allowed,
            exit_code = ?response.exit_code,
            has_stdout = response.stdout.is_some(),
            has_stderr = response.stderr.is_some(),
            "received execute response"
        );

        Ok(response)
    }

    async fn send_tcp_streaming<F>(
        &self,
        port: u16,
        request: &ExecuteRequest,
        on_output: &mut F,
    ) -> Result<ExecuteResponse>
    where
        F: FnMut(OutputStream, &str),
    {
        let addr = format!("127.0.0.1:{}", port);
        tracing::debug!(addr = %addr, "connecting to guard server");
        let stream = tokio::net::TcpStream::connect(&addr)
            .await
            .context("failed to connect to guard server")?;
        tracing::debug!(addr = %addr, "connected to guard server");

        let (reader, writer) = stream.into_split();
        let mut writer = tokio::io::BufWriter::new(writer);
        tracing::debug!(
            binary = %request.binary,
            arg_count = request.args.len(),
            "sending streaming execute request"
        );
        writer
            .write_all(serde_json::to_string(request)?.as_bytes())
            .await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        tracing::debug!("streaming execute request sent; waiting for server response");

        let mut reader = BufReader::new(reader).lines();
        read_streaming_response(&mut reader, on_output).await
    }
}

fn parse_admin_response_line(response_line: &str, request_name: &str) -> Result<AdminResponse> {
    match serde_json::from_str::<AdminResponse>(response_line) {
        Ok(resp) => Ok(resp),
        Err(admin_err) => {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(response_line) {
                if let Some(result_name) = value.get("result").and_then(|v| v.as_str()) {
                    return Ok(AdminResponse::Error {
                        message: format!(
                            "guard daemon returned malformed admin response for '{}': result '{}' did not match the current schema ({admin_err}). Restart the daemon onto the current binary.",
                            request_name, result_name
                        ),
                    });
                }
            }
            if let Ok(exec_resp) = serde_json::from_str::<ExecuteResponse>(response_line) {
                let message = if exec_resp.reason.contains("invalid request")
                    && exec_resp.reason.contains("IncomingMessage")
                {
                    format!(
                        "guard daemon rejected admin RPC '{}'. The running daemon likely predates this client or needs restart onto the current binary.",
                        request_name
                    )
                } else {
                    exec_resp.reason
                };
                return Ok(AdminResponse::Error { message });
            }
            Err(admin_err).context("invalid admin server response")
        }
    }
}

async fn read_streaming_response<R, F>(
    reader: &mut tokio::io::Lines<BufReader<R>>,
    on_output: &mut F,
) -> Result<ExecuteResponse>
where
    R: AsyncRead + Unpin,
    F: FnMut(OutputStream, &str),
{
    let mut stdout = String::new();
    let mut stderr = String::new();

    while let Some(line) = reader.next_line().await? {
        match serde_json::from_str::<ExecuteStreamMessage>(&line) {
            Ok(ExecuteStreamMessage::Stdout { data }) => {
                on_output(OutputStream::Stdout, &data);
                stdout.push_str(&data);
            }
            Ok(ExecuteStreamMessage::Stderr { data }) => {
                on_output(OutputStream::Stderr, &data);
                stderr.push_str(&data);
            }
            Ok(ExecuteStreamMessage::PolicyDecision { allowed, reason }) => {
                if allowed {
                    tracing::info!(reason = %reason, "POLICY_ALLOWED");
                } else {
                    tracing::trace!(reason = %reason, "POLICY_DENIED");
                }
            }
            Ok(ExecuteStreamMessage::Keepalive) => {}
            Ok(ExecuteStreamMessage::Result { mut response }) => {
                if response.stdout.is_none() && !stdout.is_empty() {
                    response.stdout = Some(stdout);
                }
                if response.stderr.is_none() && !stderr.is_empty() {
                    response.stderr = Some(stderr);
                }
                tracing::debug!(
                    allowed = response.allowed,
                    exit_code = ?response.exit_code,
                    has_stdout = response.stdout.is_some(),
                    has_stderr = response.stderr.is_some(),
                    "received streaming execute response"
                );
                return Ok(response);
            }
            Err(_) => {
                let response: ExecuteResponse =
                    serde_json::from_str(&line).context("invalid server response")?;
                tracing::debug!(
                    allowed = response.allowed,
                    exit_code = ?response.exit_code,
                    has_stdout = response.stdout.is_some(),
                    has_stderr = response.stderr.is_some(),
                    "received non-streaming execute response"
                );
                return Ok(response);
            }
        }
    }

    bail!("server closed connection without response")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluate::{EvalConfig, Evaluator};
    use crate::secrets::{EnvBackend, SecretManager};
    use crate::tool_config::ToolRegistry;
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use tracing::subscriber::with_default;
    use tracing_subscriber::fmt::MakeWriter;

    // ---- ExecuteResult result-shape tests -----------------------------------

    #[test]
    fn execute_result_denied_has_denied_policy_and_not_attempted_exec() {
        let r = ExecuteResult::denied("nope");
        assert!(!r.policy_allowed());
        assert_eq!(r.policy_reason(), "nope");
        assert!(matches!(r.exec, ExecOutcome::NotAttempted));
    }

    #[test]
    fn execute_result_exec_failed_has_allowed_policy_and_failed_exec() {
        let r = ExecuteResult::exec_failed("looks fine", "no such file or directory");
        assert!(
            r.policy_allowed(),
            "exec_failed must still flag policy=allowed"
        );
        assert_eq!(r.policy_reason(), "looks fine");
        match &r.exec {
            ExecOutcome::Failed { reason } => {
                assert!(reason.contains("no such file"));
            }
            other => panic!("expected Failed, got {:?}", other),
        }
    }

    #[test]
    fn execute_result_completed_has_allowed_policy_and_completed_exec() {
        let r = ExecuteResult::completed(
            "static allow",
            Some(0),
            Some("out".into()),
            Some("err".into()),
        );
        assert!(r.policy_allowed());
        assert_eq!(r.policy_reason(), "static allow");
        match &r.exec {
            ExecOutcome::Completed {
                exit_code,
                stdout,
                stderr,
            } => {
                assert_eq!(*exit_code, Some(0));
                assert_eq!(stdout.as_deref(), Some("out"));
                assert_eq!(stderr.as_deref(), Some("err"));
            }
            other => panic!("expected Completed, got {:?}", other),
        }
    }

    #[test]
    fn binary_exists_on_path_rejects_natural_language_token() {
        assert!(!binary_exists_on_path(
            "Give-this-should-not-exist-as-a-real-command"
        ));
    }

    #[test]
    fn credential_preflight_denies_kubectl_raw_config_through_shell() {
        let args = vec![
            "-c".to_string(),
            "kubectl config view --raw >/dev/null && echo ok".to_string(),
        ];
        let reason = deterministic_credential_deny_reason("sh", &args)
            .expect("kubectl raw config should be denied");
        assert!(reason.contains("kubeconfig"));
    }

    #[test]
    fn credential_preflight_denies_private_key_path() {
        let args = vec![
            "-c".to_string(),
            "cat /var/lib/guard/.ssh/guard-admin >/dev/null".to_string(),
        ];
        let reason = deterministic_credential_deny_reason("sh", &args)
            .expect("guard private key path should be denied");
        assert!(reason.contains("credential material"));
    }

    #[test]
    fn credential_preflight_allows_basic_kubectl_inspection() {
        let args = vec!["get".to_string(), "namespaces".to_string()];
        assert!(deterministic_credential_deny_reason("kubectl", &args).is_none());
    }

    #[test]
    fn parse_admin_response_line_accepts_admin_response() {
        let line = r#"{"result":"error","message":"admin denied"}"#;
        match parse_admin_response_line(line, "secret_set").unwrap() {
            AdminResponse::Error { message } => assert_eq!(message, "admin denied"),
            other => panic!("expected admin error, got {:?}", other),
        }
    }

    #[test]
    fn parse_admin_response_line_maps_execute_invalid_request_to_actionable_error() {
        let line = r#"{"allowed":false,"reason":"invalid request: data did not match any variant of untagged enum IncomingMessage"}"#;
        match parse_admin_response_line(line, "secret_set").unwrap() {
            AdminResponse::Error { message } => {
                assert!(message.contains("secret_set"));
                assert!(message.contains("needs restart"));
            }
            other => panic!("expected admin error, got {:?}", other),
        }
    }

    #[test]
    fn parse_admin_response_line_surfaces_malformed_admin_payloads_as_restart_errors() {
        let line = r#"{"result":"secret_list","items":[{"key":"alpha"}]}"#;
        match parse_admin_response_line(line, "secret_list").unwrap() {
            AdminResponse::Error { message } => {
                assert!(message.contains("secret_list"));
                assert!(message.contains("malformed admin response"));
                assert!(message.contains("Restart the daemon"));
            }
            other => panic!("expected admin error, got {:?}", other),
        }
    }

    #[test]
    fn secret_key_validation_allows_namespaced_keys() {
        assert!(is_valid_secret_key("opnsense-apikey-secret"));
        assert!(is_valid_secret_key("atlas/opnsense-apikey"));
        assert!(!is_valid_secret_key("../opnsense"));
        assert!(!is_valid_secret_key("atlas/../opnsense"));
        assert!(!is_valid_secret_key("bad key"));
        assert!(!is_valid_secret_key("/absolute"));
    }

    #[test]
    fn invalid_shell_secret_reference_points_to_injected_env() {
        let reason = invalid_shell_secret_reference(
            "echo '$opnsense-apikey-secret'",
            "OPNSENSE_APIKEY_SECRET",
            "opnsense-apikey-secret",
        )
        .expect("dashed shell-style reference should be rejected");
        assert!(reason.contains("$OPNSENSE_APIKEY_SECRET"));
    }

    #[tokio::test]
    async fn env_and_secret_injections_cannot_target_same_env_var() {
        let (cfg, _) = make_test_config();
        let request = ExecuteRequest {
            binary: "echo".to_string(),
            args: vec!["ok".to_string()],
            auth_token: None,
            env: HashMap::from([("API_TOKEN".to_string(), "plain".to_string())]),
            secrets: HashMap::from([("API_TOKEN".to_string(), "api/token".to_string())]),
            stream: false,
            session_token: None,
        };

        let err = validate_request_injections(
            &request,
            &cfg,
            &CallerIdentity::Unix { uid: 1000 },
            "echo ok",
        )
        .await
        .unwrap_err();

        assert!(err.contains("conflicting injection for 'API_TOKEN'"));
    }

    #[tokio::test]
    async fn missing_requested_secret_denies_before_policy_evaluation() {
        let (cfg, _) = make_test_config();
        let request = ExecuteRequest {
            binary: "echo".to_string(),
            args: vec!["$NONEXISTING_SEC".to_string()],
            auth_token: None,
            env: HashMap::new(),
            secrets: HashMap::from([(
                "NONEXISTING_SEC".to_string(),
                "nonexisting_sec".to_string(),
            )]),
            stream: false,
            session_token: None,
        };

        let result = execute_command(request, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;
        assert!(!result.policy_allowed());
        assert!(result.policy_reason().contains("secret not found"));
    }

    #[tokio::test]
    async fn invalid_secret_shell_reference_denies_before_policy_evaluation() {
        let (cfg, _) = make_test_config();
        cfg.secrets
            .set(1000, "opnsense-apikey-secret", "dummy_api_key_12345")
            .await
            .unwrap();
        let request = ExecuteRequest {
            binary: "echo".to_string(),
            args: vec!["$opnsense-apikey-secret".to_string()],
            auth_token: None,
            env: HashMap::new(),
            secrets: HashMap::from([(
                "OPNSENSE_APIKEY_SECRET".to_string(),
                "opnsense-apikey-secret".to_string(),
            )]),
            stream: false,
            session_token: None,
        };

        let result = execute_command(request, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;
        assert!(!result.policy_allowed());
        assert!(result
            .policy_reason()
            .contains("invalid secret environment reference"));
    }

    #[test]
    fn into_response_for_denied_sets_allowed_false() {
        let resp = ExecuteResult::denied("blocked").into_response();
        assert!(!resp.allowed);
        assert_eq!(resp.reason, "blocked");
        assert!(resp.exit_code.is_none());
    }

    #[test]
    fn into_response_for_exec_failed_sets_allowed_false_with_exec_error() {
        let resp = ExecuteResult::exec_failed("llm ok", "ENOENT").into_response();
        // Client-facing: the command did not run, so allowed=false is correct.
        // The audit log records POLICY=ALLOWED + EXEC_FAILED separately.
        assert!(!resp.allowed);
        assert!(resp.reason.contains("execution error"));
        assert!(resp.reason.contains("ENOENT"));
    }

    #[test]
    fn into_response_for_dry_run_sets_allowed_true_without_child_output() {
        let resp = ExecuteResult::dry_run("llm ok").into_response();
        assert!(resp.allowed);
        assert_eq!(resp.reason, "llm ok");
        assert_eq!(resp.exit_code, Some(0));
        assert_eq!(
            resp.stdout.as_deref(),
            Some("[DRY-RUN] policy allowed; command was not executed\n")
        );
        assert!(resp.stderr.is_none());
    }

    #[test]
    fn into_response_for_completed_carries_exit_and_streams() {
        let resp = ExecuteResult::completed("ok", Some(7), Some("hi".into()), None).into_response();
        assert!(resp.allowed);
        assert_eq!(resp.exit_code, Some(7));
        assert_eq!(resp.stdout.as_deref(), Some("hi"));
    }

    // ---- Audit emission end-to-end tests ------------------------------------

    /// Shared-buffer writer for the tracing fmt subscriber. Lets us capture
    /// emitted log lines and assert on their contents.
    #[derive(Clone)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for SharedBuf {
        type Writer = SharedBuf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn make_test_config() -> (ServerConfig, SharedBuf) {
        // LLM disabled, no static policy → policy_allowed() never hits
        // this path; we manufacture results directly for audit tests.
        let eval_config = EvalConfig::default().llm_enabled(false);
        let evaluator = Evaluator::new(eval_config).expect("build evaluator");
        let secrets = SecretManager::with_backend(EnvBackend::default());
        let cfg = ServerConfig::new(
            None,
            None,
            evaluator,
            secrets,
            false,
            None,
            None,
            None,
            None,
            false,
            ToolRegistry::empty(),
            Vec::new(),
            false,
            SessionRegistry::new(),
            None,
            false,
            None,
        );
        let buf = SharedBuf(Arc::new(Mutex::new(Vec::new())));
        (cfg, buf)
    }

    fn capture<F: FnOnce()>(buf: &SharedBuf, f: F) -> String {
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_max_level(tracing::Level::INFO)
            .with_target(false)
            .with_ansi(false)
            .without_time()
            .finish();
        with_default(subscriber, f);
        let bytes = buf.0.lock().unwrap().clone();
        String::from_utf8_lossy(&bytes).to_string()
    }

    /// Policy denial: only the POLICY event fires, never EXEC_FAILED.
    /// Legacy grep patterns `[AUDIT] DENIED` still match.
    #[test]
    fn audit_policy_denied_emits_only_policy_event() {
        let (cfg, buf) = make_test_config();
        let caller = CallerIdentity::Unix { uid: 1000 };
        let result = ExecuteResult::denied("matched deny pattern: rm -rf /");

        let output = capture(&buf, || {
            emit_audit_events(&cfg, &caller, "rm", &["-rf".into(), "/".into()], &result);
        });

        assert!(
            output.contains("[AUDIT] DENIED"),
            "expected DENIED policy line, got: {output}"
        );
        assert!(
            !output.contains("EXEC_FAILED"),
            "policy denial must not produce EXEC_FAILED: {output}"
        );
    }

    /// Policy allows + exec fails: BOTH events fire. Legacy grep for
    /// `[AUDIT] ALLOWED` still matches, and tooling that wants exec-failure
    /// visibility can filter on EXEC_FAILED.
    #[test]
    fn audit_allowed_then_exec_failed_emits_both_events() {
        let (cfg, buf) = make_test_config();
        let caller = CallerIdentity::Unix { uid: 1000 };
        let result = ExecuteResult::exec_failed(
            "LLM approved: benign lookup",
            "failed to execute 'nonexistent-binary-xyz': No such file or directory",
        );

        let output = capture(&buf, || {
            emit_audit_events(&cfg, &caller, "nonexistent-binary-xyz", &[], &result);
        });

        assert!(
            output.contains("[AUDIT] ALLOWED"),
            "expected ALLOWED policy line (backward-compat format), got: {output}"
        );
        assert!(
            output.contains("[AUDIT] EXEC_FAILED"),
            "expected EXEC_FAILED line, got: {output}"
        );
        assert!(
            output.contains("nonexistent-binary-xyz"),
            "audit line should carry the binary name: {output}"
        );
        assert!(
            output.contains("No such file"),
            "EXEC_FAILED line should carry the exec error reason: {output}"
        );
    }

    /// Policy allows + exec succeeds: only the POLICY event fires.
    #[test]
    fn audit_allowed_and_completed_emits_only_policy_event() {
        let (cfg, buf) = make_test_config();
        let caller = CallerIdentity::Unix { uid: 42 };
        let result = ExecuteResult::completed("static allow", Some(0), None, None);

        let output = capture(&buf, || {
            emit_audit_events(&cfg, &caller, "echo", &["hi".into()], &result);
        });

        assert!(output.contains("[AUDIT] ALLOWED"));
        assert!(!output.contains("EXEC_FAILED"));
    }

    /// Regression: each user has an independent namespace. Two users
    /// can store the same key name without collision; neither can see
    /// the other's keys through the user-scoped list, but the daemon
    /// UID sees both via the admin list_all path.
    #[tokio::test]
    async fn secret_list_is_per_user_namespaced() {
        let (mut cfg, _) = make_test_config();
        cfg.daemon_uid = 777;

        // Unique key so parallel tests sharing the EnvBackend don't
        // collide.
        let key = format!("NAMESPACED_{}", std::process::id());

        let user_a = CallerIdentity::Unix { uid: 20_000 };
        let user_b = CallerIdentity::Unix { uid: 20_001 };
        let daemon = CallerIdentity::Unix { uid: 777 };

        // Both users store the SAME key name with different values.
        let set_a = handle_admin_request(
            &cfg,
            &user_a,
            AdminRequest::SecretSet {
                key: key.clone(),
                value: "alice".into(),
            },
        )
        .await;
        assert!(matches!(set_a, AdminResponse::Ok));

        let set_b = handle_admin_request(
            &cfg,
            &user_b,
            AdminRequest::SecretSet {
                key: key.clone(),
                value: "bob".into(),
            },
        )
        .await;
        assert!(matches!(set_b, AdminResponse::Ok));

        // Each user sees only their own namespace.
        let list_a = handle_admin_request(&cfg, &user_a, AdminRequest::SecretList).await;
        match list_a {
            AdminResponse::SecretList { keys } => {
                let ours: Vec<_> = keys.iter().filter(|k| *k == &key).collect();
                assert_eq!(ours.len(), 1);
            }
            other => panic!("unexpected {:?}", other),
        }

        // Daemon aggregate view includes both entries, annotated with uid.
        let list_daemon = handle_admin_request(&cfg, &daemon, AdminRequest::SecretList).await;
        match list_daemon {
            AdminResponse::SecretList { keys } => {
                let ours: Vec<_> = keys.iter().filter(|k| *k == &key).collect();
                assert_eq!(ours.len(), 2, "daemon sees both namespaced copies");
            }
            other => panic!("unexpected {:?}", other),
        }

        // user B's delete touches only their own namespace.
        let del_b = handle_admin_request(
            &cfg,
            &user_b,
            AdminRequest::SecretDelete { key: key.clone() },
        )
        .await;
        assert!(matches!(del_b, AdminResponse::Ok));

        // A's secret still there, value "alice" intact.
        assert_eq!(
            cfg.secrets.get(20_000, &key).await.unwrap().as_deref(),
            Some("alice")
        );
        // B's is gone.
        assert_eq!(cfg.secrets.get(20_001, &key).await.unwrap(), None);

        // Cleanup.
        let _ = handle_admin_request(
            &cfg,
            &user_a,
            AdminRequest::SecretDelete { key: key.clone() },
        )
        .await;
    }

    /// Regression: exec-time secret injection reads from the caller's
    /// namespace. Another user cannot `--secret X` their way to our X.
    #[tokio::test]
    async fn exec_secret_injection_is_isolated_per_uid() {
        let (mut cfg, _) = make_test_config();
        cfg.daemon_uid = 777;
        let key = format!("EXEC_ISO_{}", std::process::id());

        // user_a stores THE secret.
        cfg.secrets.set(30_000, &key, "alice-value").await.unwrap();

        // user_b asks to inject $key into their exec call.
        let mut secrets_map = HashMap::new();
        secrets_map.insert("INJECTED".to_string(), key.clone());
        let req = ExecuteRequest {
            binary: "echo".to_string(),
            args: vec!["hi".to_string()],
            auth_token: None,
            env: HashMap::new(),
            secrets: secrets_map,
            stream: false,
            session_token: None,
        };

        let result = execute_command(req, &cfg, &CallerIdentity::Unix { uid: 30_001 }).await;
        // user_b has no such key in their namespace -> secret not found.
        assert!(!result.policy_allowed());
        assert!(
            result.policy_reason().contains("secret not found"),
            "reason: {}",
            result.policy_reason()
        );

        // Cleanup.
        let _ = cfg.secrets.delete(30_000, &key).await;
    }

    #[tokio::test]
    async fn session_list_is_user_visible_but_prompt_is_hidden() {
        let (mut cfg, _) = make_test_config();
        cfg.daemon_uid = 777;

        let daemon = CallerIdentity::Unix { uid: 777 };
        let user = CallerIdentity::Unix { uid: 20_002 };
        let token = format!("session-{}", std::process::id());

        let grant = handle_admin_request(
            &cfg,
            &daemon,
            AdminRequest::SessionGrant {
                token: token.clone(),
                allow: vec!["mkdir /tmp/work/*".into()],
                deny: Vec::new(),
                ttl_secs: None,
                prompt_append: Some("operator-only prompt".into()),
            },
        )
        .await;
        assert!(matches!(grant, AdminResponse::Ok));

        let listed = handle_admin_request(
            &cfg,
            &user,
            AdminRequest::SessionList {
                include_history: false,
                since_unix: None,
            },
        )
        .await;
        match listed {
            AdminResponse::SessionList { grants, .. } => {
                let grant = grants.iter().find(|grant| grant.token == token).is_none();
                assert!(grant, "non-daemon callers must not receive bearer tokens");
                let hidden = grants
                    .iter()
                    .find(|grant| grant.token == "(hidden)")
                    .expect("redacted session grant visible to user");
                assert!(hidden.allow.is_empty());
                assert!(hidden.deny.is_empty());
                assert_eq!(hidden.prompt_append.as_deref(), Some("(hidden)"));
            }
            other => panic!("unexpected {:?}", other),
        }
    }

    #[tokio::test]
    async fn session_show_reports_recent_stats() {
        let (mut cfg, _) = make_test_config();
        cfg.daemon_uid = 777;

        let daemon = CallerIdentity::Unix { uid: 777 };
        let token = format!("session-show-{}", std::process::id());

        let grant = handle_admin_request(
            &cfg,
            &daemon,
            AdminRequest::SessionGrant {
                token: token.clone(),
                allow: vec!["echo*".into()],
                deny: vec!["rm*".into()],
                ttl_secs: None,
                prompt_append: Some("operator context".into()),
            },
        )
        .await;
        assert!(matches!(grant, AdminResponse::Ok));

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);

        {
            let mut reg = cfg.sessions.write().await;
            reg.record_interaction(
                &token,
                SessionInteraction {
                    at_unix: now.saturating_sub(1),
                    command: "echo hi".into(),
                    allowed: true,
                    source: SessionDecisionSource::Llm,
                    reason: "safe".into(),
                    risk: Some(1),
                    exec_status: SessionExecStatus::Completed,
                },
            );
            reg.record_interaction(
                &token,
                SessionInteraction {
                    at_unix: now,
                    command: "rm -rf /tmp/x".into(),
                    allowed: false,
                    source: SessionDecisionSource::SessionDeny,
                    reason: "session deny pattern: rm*".into(),
                    risk: None,
                    exec_status: SessionExecStatus::NotAttempted,
                },
            );
        }

        let show = handle_admin_request(
            &cfg,
            &daemon,
            AdminRequest::SessionShow {
                token: token.clone(),
                limit: Some(1),
            },
        )
        .await;
        match show {
            AdminResponse::SessionShow { report } => {
                assert_eq!(report.stats.total, 2);
                assert_eq!(report.stats.allowed, 1);
                assert_eq!(report.stats.denied, 1);
                assert_eq!(report.stats.risk_histogram[1], 1);
                assert_eq!(report.recent.len(), 1);
                assert_eq!(report.recent[0].command, "rm -rf /tmp/x");
                assert_eq!(
                    report.active.and_then(|grant| grant.prompt_append),
                    Some("operator context".into())
                );
            }
            other => panic!("unexpected {:?}", other),
        }
    }
}
