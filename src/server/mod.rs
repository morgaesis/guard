//! Guard server mode - accepts command execution requests and runs them with privileged access.
//!
//! The server listens on a UNIX socket or TCP port and accepts requests from clients (agents).
//! Each request is evaluated against the policy engine before execution.
//!
//! Security model:
//! - UNIX socket: peer UID-based authorization
//! - TCP socket: auth token required
//! - Socket dir: 0755 when managed by socket_group
//! - Socket: 0600 by default, or 0660 after a successful socket-group change

use crate::grant_profile::{GrantRequest, SavedGrantCatalog};
use crate::injection::is_valid_env_name;
use crate::secrets::SecretManager;
use crate::session::{SessionBehaviorLimits, SessionRegistry};
use crate::session_store::SessionStore;
use guard::evaluate::Evaluator;
use guard::gating::approval::ApprovalRegistry;
use guard::gating::provisional::ProvisionalRegistry;
use guard::gating::read_grant::GrantReadRegistry;
use guard::gating::ssh_readonly::{
    command_tokens, is_fixed_readonly_diagnostic, ssh_options_all_readonly_safe,
};
use guard::gating::verb::VerbCatalog;
use guard::gating::GateMode;
use guard::policy::PolicyMode;
use guard::principal::PrincipalKey;

// Re-export so main.rs can pattern-match on history status without a
// direct dependency on the `session` module path.
pub use crate::session::HistoricalStatus;
use crate::tool_config::ToolRegistry;
use anyhow::Result;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

const MAX_GUARD_DEPTH: u32 = 5;
const MAX_REQUEST_BYTES: usize = 1_048_576; // 1MB
const MAX_OUTPUT_BYTES: usize = 10_485_760; // 10MB
const SESSION_AUTO_AMEND_MAX_ALLOW_RISK: i32 = 2;
const SESSION_AUTO_AMEND_MIN_DENY_RISK: i32 = 5;
const SESSION_EXACT_RULE_MAX_ARGS: usize = 128;
const SESSION_EXACT_RULE_MAX_ARG_LEN: usize = 1024;

// --- Consequence-gating tuning (operator-overridable where noted) ---
/// How often the sweeper checks for due auto-reverts and expired holds.
const SWEEPER_TICK_SECS: u64 = 1;
/// Bound session-history pruning and storage compaction even when no command
/// writes occur.
const SESSION_MAINTENANCE_INTERVAL_SECS: u64 = 5 * 60;
/// Delay after daemon start before the sweeper begins. Startup recovery (which
/// moves past-deadline provisionals to needs_operator_decision) runs
/// synchronously *before* the sweeper is spawned, so this grace is belt-and-
/// suspenders against any clock settle and guarantees no revert fires at boot.
const SWEEPER_GRACE_SECS: u64 = 30;
/// Default auto-revert window for a containment envelope when `--confirm-within`
/// is omitted.
const DEFAULT_CONFIRM_WITHIN_SECS: u64 = 300;
/// Upper bound on the auto-revert window. The window is set by the (untrusted)
/// caller, so it is capped: any unconfirmed contained change auto-reverts within
/// this horizon no matter what the caller requests.
const MAX_CONFIRM_WITHIN_SECS: u64 = 24 * 60 * 60;
/// Wall-clock timeout for a sweeper/operator-driven revert. A hung revert must
/// not wedge the sweeper (which also drives fail-closed hold expiry).
const REVERT_EXEC_TIMEOUT_SECS: u64 = 120;
/// Default time a held command waits for operator approval before failing closed
/// (denied-expired). Mirrors the decision-cache TTL default.
pub(crate) const APPROVAL_TTL_SECS: u64 = 3600;
/// Per-caller cap on outstanding holds + provisionals (local-DoS guard).
const MAX_PENDING_PER_CALLER: usize = 32;
/// Global cap on outstanding holds + provisionals.
const MAX_PENDING_GLOBAL: usize = 256;
/// How long decided/terminal gating rows are retained before pruning.
const GATING_RETENTION_SECS: u64 = 24 * 60 * 60;

mod admin;
mod api_judge;
mod execute;
mod gate_runtime;
mod grants;
mod runtime;
mod secure_fs;
#[cfg(test)]
mod tests;
mod transport;
mod wire;

// The named public surface of the server module: the daemon entrypoint
// (`Server`, `resolve_daemon_principal`) and the wire types shared with the
// CLI, the MCP server, and `daemon_client`. Everything else stays internal.
pub(crate) use api_judge::{ApiJudgeSpend, ApiJudgeSpendConfig, DaemonApiJudge};
pub(crate) use runtime::CommandAdmissionConfig;
#[cfg(windows)]
pub(crate) use transport::winplat;
pub use transport::Server;
pub use wire::{
    AdminRequest, AdminResponse, ApprovalSummary, CommandSpec, ExecuteRequest, ExecuteResponse,
    GateStatus, OutputStream, RevertSpec, SshHostKeyMode, VerbInvocation, VerbMatchInfo,
    VerbSummary,
};
pub(crate) use wire::{ExecuteStreamMessage, IncomingMessage};

use execute::{audit_command_line, audit_session_fingerprint};
use guard::redact::audit_escape;
use wire::CallerIdentity;

/// Constant-time byte comparison for bearer credentials (auth tokens, admin
/// tokens, MCP bearers). Backed by `subtle` so the comparison does not leak a
/// prefix match through timing; a length mismatch returns false (lengths are
/// not secret).
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

#[derive(Clone)]
struct ServerConfig {
    pub socket_path: Option<PathBuf>,
    pub tcp_port: Option<u16>,
    pub evaluator: Arc<Evaluator>,
    pub secrets: Arc<SecretManager>,
    pub redact: bool,
    pub auth_token: Option<String>,
    pub admin_token: Option<String>,
    /// Unix-socket transport option; carried but never read on Windows.
    #[cfg_attr(windows, allow(dead_code))]
    pub socket_group: Option<String>,
    /// Unix-socket peer-UID allowlist; carried but never read on Windows.
    #[cfg_attr(windows, allow(dead_code))]
    pub allowed_uids: Option<Vec<u32>>,
    pub shim_dir: Option<PathBuf>,
    pub dry_run: bool,
    /// Internal non-executing admission preview. It shares evaluator cache
    /// reads/writes but suppresses every other learned or durable side effect.
    pub admission_preview: bool,
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
    /// Shared task-ownership guard. Cloned server configurations can start
    /// session maintenance at most once for this daemon instance.
    pub session_maintenance_started: Arc<AtomicBool>,
    /// When true, approved Unix-socket requests execute as the connecting
    /// user instead of the daemon UID.
    pub exec_as_caller: bool,
    /// Wall-clock unix seconds when the daemon started. Surfaced via the
    /// Status admin RPC so callers can compute uptime.
    pub started_at_unix: u64,
    /// Effective UID of the daemon process. Admin RPCs require the
    /// caller to be this UID; there is no token-based elevation.
    pub daemon_uid: u32,
    /// The daemon's own cross-platform principal: its uid on Unix, its process
    /// SID on Windows. Operator/admin RPCs require the caller's principal to
    /// equal this - the single "is the operator" source of truth on both
    /// platforms.
    pub daemon_principal: PrincipalKey,
    pub state_db_path: Option<PathBuf>,
    /// Consequence-gating mode. `Off` preserves legacy behavior; `Consequence`
    /// routes LLM-approved commands by reversibility.
    pub gate: GateMode,
    /// Containment-envelope state (recoverable provisionals).
    pub provisional: Arc<RwLock<ProvisionalRegistry>>,
    /// Operator-approval state (held irreversible commands).
    pub approvals: Arc<RwLock<ApprovalRegistry>>,
    /// Held-command lifetime. `u64::MAX` represents an unbounded operator hold.
    pub approval_ttl_secs: u64,
    /// Operator-authored verb catalog (the typed, least-expressive interface).
    pub verbs: Arc<RwLock<VerbCatalog>>,
    /// Reusable grants and their generated typed verbs.
    pub saved_grants: Arc<RwLock<SavedGrantCatalog>>,
    /// Durable requests to amend a live or saved grant.
    pub grant_requests: Arc<RwLock<std::collections::BTreeMap<String, GrantRequest>>>,
    /// Serializes terminal transitions so memory and durable state observe one
    /// winner for approve, deny, and withdraw races.
    pub grant_request_transition_gate: Arc<Mutex<()>>,
    /// Daemon-lifetime authentication key for stateless regeneration
    /// proposals. Cloned configurations share the same key so internal preview
    /// configurations can verify proposals without exposing authority.
    pub regeneration_proposal_key: Arc<[u8; 32]>,
    /// Optional server-wide binary allow-list. `None` (the default) imposes no
    /// restriction. When `Some`, only binaries permitted by [`binary_allowed`]
    /// may execute, on every route (raw run, verb, and gated approval), as a
    /// hard floor independent of the LLM decision. Set by the daemon entrypoint
    /// from `--allow-bin` / `GUARD_ALLOW_BIN`.
    pub allowed_binaries: Option<Vec<String>>,
    /// Extra environment variable names the daemon forwards from its own
    /// environment to executed children, in addition to the built-in
    /// platform allowlist. Operator-declared via `--child-env` /
    /// `GUARD_CHILD_ENV`, this is how brokered credentials reach a tool
    /// generically without per-tool code - e.g. `KUBECONFIG` so brokered
    /// kubectl/helm read a config the agent cannot see.
    pub extra_child_env: Vec<String>,
    /// Optional API proxies hosted alongside the gate socket. When set,
    /// the daemon terminates brokered clients' TLS, gates each API operation
    /// against the operator policy, and re-originates to the upstream with the
    /// credentials only the daemon holds.
    pub protocol_registry:
        Arc<RwLock<std::collections::HashMap<String, Arc<guard::proxy::ApiProxy>>>>,
    /// Evaluator-generated API verb coverage shared by all API judges and the
    /// operator inspection RPCs.
    pub api_coverage: Option<Arc<RwLock<guard::gating::api_promotion::ApiPromotionStore>>>,
    /// Active filesystem read grants (Unix-only). Time-boxed POSIX ACL read
    /// grants issued by the automatic retry path; the sweeper revokes them at
    /// expiry and startup reconciliation revokes any that expired while the
    /// daemon was down.
    pub read_grants: Arc<RwLock<GrantReadRegistry>>,
    /// Daemon-only root for child-lifetime secret files.
    pub secret_file_root: Option<PathBuf>,
    /// Optional fire-and-forget operator event hook.
    pub notify_hook: Option<runtime::NotifyHook>,
    /// Every brokered child stays owned by the daemon until it exits or uses a
    /// documented detach boundary.
    pub process_tracker: runtime::ProcessTracker,
    /// Optional session-scoped circuit breakers derived from persisted
    /// interactions. Every threshold is disabled by default.
    pub behavior_limits: SessionBehaviorLimits,
    /// Shared command-handler and evaluator admission control.
    pub command_admission: runtime::CommandAdmission,
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
        admin_token: Option<String>,
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
        use rand::Rng;
        let mut regeneration_proposal_key = [0u8; 32];
        rand::rng().fill_bytes(&mut regeneration_proposal_key);
        Self {
            socket_path,
            tcp_port,
            evaluator: Arc::new(evaluator),
            secrets: Arc::new(secrets),
            redact,
            auth_token,
            admin_token,
            socket_group,
            allowed_uids,
            shim_dir,
            dry_run,
            admission_preview: false,
            tool_registry: Arc::new(RwLock::new(tool_registry)),
            redact_secrets,
            preflight,
            session_store,
            session_maintenance_started: Arc::new(AtomicBool::new(false)),
            exec_as_caller,
            daemon_uid: current_uid(),
            daemon_principal: resolve_daemon_principal(),
            sessions: Arc::new(RwLock::new(sessions)),
            started_at_unix: guard::env::now_unix(),
            state_db_path,
            // Gating defaults to off; the daemon entrypoint enables it and
            // populates the registries from persisted state before serving.
            gate: GateMode::Off,
            provisional: Arc::new(RwLock::new(ProvisionalRegistry::new())),
            approvals: Arc::new(RwLock::new(ApprovalRegistry::new())),
            approval_ttl_secs: APPROVAL_TTL_SECS,
            verbs: Arc::new(RwLock::new(VerbCatalog::empty())),
            saved_grants: Arc::new(RwLock::new(SavedGrantCatalog::empty())),
            grant_requests: Arc::new(RwLock::new(std::collections::BTreeMap::new())),
            grant_request_transition_gate: Arc::new(Mutex::new(())),
            regeneration_proposal_key: Arc::new(regeneration_proposal_key),
            // No binary restriction by default; the entrypoint sets this from
            // --allow-bin / GUARD_ALLOW_BIN, like the gate fields above.
            allowed_binaries: None,
            // No extra child-env passthrough by default; the entrypoint sets
            // this from --child-env / GUARD_CHILD_ENV.
            extra_child_env: Vec::new(),
            protocol_registry: Arc::new(RwLock::new(std::collections::HashMap::new())),
            api_coverage: None,
            read_grants: Arc::new(RwLock::new(GrantReadRegistry::new())),
            secret_file_root: None,
            notify_hook: None,
            process_tracker: runtime::ProcessTracker::default(),
            behavior_limits: SessionBehaviorLimits::default(),
            command_admission: runtime::CommandAdmission::new(
                runtime::CommandAdmissionConfig::default(),
            ),
        }
    }

    pub(super) fn emit_event(&self, event: runtime::NotifyEvent) {
        if let Some(hook) = &self.notify_hook {
            hook.emit(event);
        }
    }

    #[cfg(unix)]
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
        // The operator is whoever runs as the daemon's own principal: its uid on
        // Unix, its SID on Windows. One comparison, both platforms. A Unix
        // caller's principal is the uid string, equal to daemon_principal
        // exactly when uid == daemon_uid, so Unix behavior is unchanged.
        if matches!(caller.principal(), Some(ref p) if self.daemon_principal.eq_ci(p)) {
            return Ok(());
        }
        if matches!(caller, CallerIdentity::TcpAdmin { .. }) {
            return Ok(());
        }
        anyhow::bail!("admin RPC refused: caller is not the daemon principal");
    }

    fn validate_token(&self, token: Option<&str>) -> Result<()> {
        if let Some(ref expected) = self.auth_token {
            if !constant_time_eq(token.unwrap_or("").as_bytes(), expected.as_bytes()) {
                anyhow::bail!("invalid auth token");
            }
        }
        Ok(())
    }

    fn validate_admin_token(&self, token: Option<&str>) -> Result<()> {
        let Some(ref expected) = self.admin_token else {
            anyhow::bail!("admin token is not configured");
        };
        if !constant_time_eq(token.unwrap_or("").as_bytes(), expected.as_bytes()) {
            anyhow::bail!("invalid admin token");
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
        session_token: Option<&str>,
        binary: &str,
        args: &[String],
        allowed: bool,
        reason: &str,
    ) {
        let action = if allowed { "ALLOWED" } else { "DENIED" };
        tracing::info!(target: "guard::audit",
            "[AUDIT] {} caller={} session_fingerprint={} cmd=\"{}\" reason=\"{}\"",
            action,
            caller,
            audit_session_fingerprint(session_token),
            audit_command_line(binary, args),
            audit_escape(reason)
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
        session_token: Option<&str>,
        binary: &str,
        args: &[String],
        reason: &str,
    ) {
        tracing::info!(target: "guard::audit",
            "[AUDIT] EXEC_FAILED caller={} session_fingerprint={} cmd=\"{}\" reason=\"{}\"",
            caller,
            audit_session_fingerprint(session_token),
            audit_command_line(binary, args),
            audit_escape(reason)
        );
    }
}

/// The daemon's own principal: its uid on Unix, its process SID on Windows.
/// On Windows, if the SID cannot be resolved (effectively impossible - a
/// process always has a token), fall back to a sentinel that no caller can ever
/// match, so operator authorization fails closed (commands stay held) rather
/// than open.
pub fn resolve_daemon_principal() -> PrincipalKey {
    #[cfg(unix)]
    {
        PrincipalKey::from_uid(current_uid())
    }
    #[cfg(windows)]
    {
        match unsafe { winplat::process_user_sid() } {
            Ok(sid) => PrincipalKey::from_sid(sid),
            Err(e) => {
                tracing::error!(
                    "daemon SID resolution failed ({e}); operator approval disabled (fail-closed)"
                );
                PrincipalKey::from_raw("\u{0}daemon-sid-unresolved\u{0}")
            }
        }
    }
}

/// Read the daemon's effective UID on Unix. Windows has no Unix UID; TCP
/// callers are represented separately and cannot satisfy daemon-UID admin
/// checks.
#[cfg(unix)]
fn current_uid() -> u32 {
    unsafe { libc::geteuid() as u32 }
}

#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
}

#[cfg(unix)]
fn child_env_allowlist() -> &'static [&'static str] {
    &[
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
    ]
}

// On Windows there is no HOME/USER convention; tools resolve the profile via
// USERPROFILE / HOMEDRIVE+HOMEPATH, so those must pass through for the child
// (e.g. cmk reads %USERPROFILE%\.cmk\config).
#[cfg(windows)]
fn child_env_allowlist() -> &'static [&'static str] {
    &[
        "PATH",
        "SystemRoot",
        "SystemDrive",
        "ComSpec",
        "PATHEXT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "HOME",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "WINDIR",
        "USERNAME",
        "USERDOMAIN",
    ]
}

#[cfg(not(any(unix, windows)))]
fn child_env_allowlist() -> &'static [&'static str] {
    &["PATH"]
}

// Shim-dir PATH prepending is a Unix construct (see the exec path in execute.rs).
#[cfg(unix)]
fn path_with_shim_dir(shim_dir: &std::path::Path) -> Option<std::ffi::OsString> {
    let mut paths = Vec::new();
    paths.push(shim_dir.to_path_buf());
    if let Some(base_path) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&base_path));
    }
    std::env::join_paths(paths).ok()
}

fn binary_exists_on_path(binary: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };

    std::env::split_paths(&path).any(|dir| {
        binary_path_candidates(&dir, binary)
            .into_iter()
            .any(|candidate| is_executable_path(&candidate))
    })
}

fn is_executable_path(path: &std::path::Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    #[cfg(unix)]
    {
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        metadata.is_file()
    }
}

fn binary_path_candidates(dir: &std::path::Path, binary: &str) -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        let binary_path = std::path::Path::new(binary);
        let mut candidates = vec![dir.join(binary_path)];
        if binary_path.extension().is_none() {
            let pathext =
                std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
            for ext in pathext.split(';').filter(|ext| !ext.is_empty()) {
                let ext = if ext.starts_with('.') {
                    ext.to_string()
                } else {
                    format!(".{ext}")
                };
                candidates.push(dir.join(format!("{binary}{ext}")));
            }
        }
        candidates
    }
    #[cfg(not(windows))]
    {
        vec![dir.join(binary)]
    }
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

/// Environment variable names that let a caller turn a benign child command
/// into arbitrary code execution: dynamic-linker preload/audit hooks, per-
/// language startup-file/option hooks, and git's command/config
/// overrides. Blocked from `--env`/`--secret` injection regardless of the
/// target binary - a value under any of these names is code, not data, and
/// the child would run it before its own logic. Compared case-insensitively;
/// the `_KEY_`/`_VALUE_` git-config families and `LD_AUDIT*` are prefix
/// matches because they are numbered/suffixed.
fn dangerous_env_name(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "BASH_ENV"
            | "ENV"
            | "LD_PRELOAD"
            | "LD_LIBRARY_PATH"
            | "DYLD_INSERT_LIBRARIES"
            | "DYLD_LIBRARY_PATH"
            | "PYTHONPATH"
            | "PYTHONHOME"
            | "PYTHONSTARTUP"
            | "RUBYOPT"
            | "NODE_OPTIONS"
            | "PERL5OPT"
            | "PERL5LIB"
            | "GIT_CONFIG"
            | "GIT_CONFIG_GLOBAL"
            | "GIT_CONFIG_SYSTEM"
            | "GIT_SSH"
            | "GIT_SSH_COMMAND"
            | "SSH_AUTH_SOCK"
            | "SSH_ASKPASS"
    ) || upper.starts_with("LD_AUDIT")
        || upper.starts_with("GIT_CONFIG_KEY_")
        || upper.starts_with("GIT_CONFIG_VALUE_")
}

/// Deterministic pre-LLM ALLOW for a small, fixed set of trivially safe
/// read-only commands: local identity/status (`id`, `whoami`, `hostname`,
/// `uptime`) and, over `ssh`, a fixed read-only diagnostic as the remote
/// command. Returns the allow reason, or `None` to fall through to the LLM.
///
/// This is a latency/cost optimization only. It is deliberately narrow:
/// paranoid mode disables it; any shell metacharacter, injected env/secret
/// (checked by the caller), or risky SSH transport option
/// (`-L`/`-D`/`-J`/`-W`/`ProxyCommand`/`LocalCommand`/forwarding) forfeits
/// the fast path back to the model. Like a trusted verb, it is a
/// deterministic allow and intentionally precedes the evaluator.
fn deterministic_safe_allow_reason(
    config: &ServerConfig,
    binary: &str,
    args: &[String],
) -> Option<String> {
    if matches!(config.evaluator.mode(), Some(PolicyMode::Paranoid)) {
        return None;
    }

    if binary == "ssh" {
        let destination = crate::ssh::extract_destination(args)?;
        let remote_command = crate::ssh::extract_command(args);
        if remote_command.trim().is_empty() || !ssh_options_all_readonly_safe(args) {
            return None;
        }
        if is_fixed_readonly_diagnostic(&remote_command) {
            return Some(format!(
                "deterministic safe allow: fixed read-only remote command on {}",
                destination
            ));
        }
        return None;
    }

    if matches!(binary, "id" | "whoami" | "hostname" | "uptime") {
        return Some("deterministic safe allow: fixed local identity/status command".to_string());
    }

    None
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
    for key in request
        .env
        .keys()
        .chain(request.secrets.keys())
        .chain(request.secret_files.keys())
    {
        if !is_valid_env_name(key) {
            return Err(format!(
                "invalid injected environment variable name: '{}'",
                key
            ));
        }
        if dangerous_env_name(key) {
            return Err(format!(
                "dangerous injected environment variable name: '{}'",
                key
            ));
        }
    }

    let mut names = std::collections::HashSet::new();
    for env_var in request
        .env
        .keys()
        .chain(request.secrets.keys())
        .chain(request.secret_files.keys())
    {
        if !names.insert(env_var) {
            return Err(format!(
                "conflicting injection for '{}': choose one of --env, --secret, or --secret-file",
                env_var
            ));
        }
    }

    if config.exec_as_caller && !request.secret_files.is_empty() {
        return Err(
            "--secret-file is unavailable when the daemon uses --exec-as-caller because the caller identity must not receive access to daemon-owned secret files"
                .to_string(),
        );
    }

    let principal = match caller.principal() {
        Some(principal) if caller.is_local_peer() => principal,
        _ => {
            if !request.secrets.is_empty() || !request.secret_files.is_empty() {
                return Err(
                    "secret and secret-file injection require an authenticated local caller"
                        .to_string(),
                );
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
        match config.secrets.get(&principal, secret_key).await {
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

    for (env_var, secret_key) in &request.secret_files {
        if !is_valid_secret_key(secret_key) {
            return Err(format!("invalid secret key: '{}'", secret_key));
        }
        match config.secrets.get(&principal, secret_key).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err(format!(
                    "secret not found: '{}' (required by --secret-file {})",
                    secret_key, env_var
                ));
            }
            Err(e) => return Err(format!("failed to read secret '{}': {}", secret_key, e)),
        }
    }

    Ok(())
}
