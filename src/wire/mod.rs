//! Untrusted wire-protocol request types shared by the daemon binary and the
//! fuzz targets. These are the exact serde shapes any socket client can send;
//! they live in the library crate so the parsing surface can be fuzzed. The
//! daemon (`src/server/wire.rs`) re-exports them, so binary-side code keeps
//! its existing paths.

pub mod mcp;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// How ssh should treat the remote host key for a guarded ssh command.
/// Default (`OnlyExisting`) preserves ssh's own strict behavior: the daemon
/// injects nothing, so a first-contact host still fails closed. The relaxed
/// modes are opt-in and only ever apply when `binary == "ssh"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SshHostKeyMode {
    /// Only connect to hosts already in known_hosts (no injection).
    OnlyExisting,
    /// Trust-on-first-use: accept and record an unknown host key, but still
    /// refuse if a known key changed (`StrictHostKeyChecking=accept-new`).
    AcceptNew,
    /// Accept any host key without recording it (`StrictHostKeyChecking=no`,
    /// `UserKnownHostsFile=/dev/null`). This gives up host authentication and
    /// is intentionally excluded from the deterministic fast path.
    AcceptAll,
}

impl SshHostKeyMode {
    /// The ssh `-o` options this mode injects ahead of the caller's args.
    /// `OnlyExisting` injects nothing so the default is a no-op.
    fn ssh_options(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::OnlyExisting => &[],
            Self::AcceptNew => &[
                ("StrictHostKeyChecking", "accept-new"),
                ("UpdateHostKeys", "yes"),
            ],
            Self::AcceptAll => &[
                ("StrictHostKeyChecking", "no"),
                ("UserKnownHostsFile", "/dev/null"),
            ],
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
    /// Per-run secret-file mappings: child env var -> daemon secret key. The
    /// daemon materializes each value into a private child-lifetime file and
    /// injects only its path.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub secret_files: HashMap<String, String>,
    #[serde(default)]
    pub stream: bool,
    /// Session grant token. When present and matched server-side, session
    /// allow/deny patterns short-circuit the decision before the evaluator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
    /// Structured rollback command for a recoverable (containment) action. Used
    /// only when consequence gating routes this command to a containment
    /// envelope. Evaluated at arm time; never run as a shell string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revert: Option<RevertSpec>,
    /// Auto-revert window in seconds for the containment envelope. Defaults to
    /// `DEFAULT_CONFIRM_WITHIN_SECS` when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm_within_secs: Option<u64>,
    /// Force the command onto the operator-approval (hold) path regardless of
    /// the evaluator's reversibility class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_approval: Option<bool>,
    /// When set, a held command blocks up to this many seconds for an operator
    /// decision and returns the real result inline instead of a bare hold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_approval_secs: Option<u64>,
    /// Invoke an operator-defined verb instead of a raw binary. When present,
    /// the daemon renders the verb's typed template into binary+args and uses
    /// the verb's declared consequence class for gating.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verb: Option<VerbInvocation>,
    /// Skip the auto-learned deny-shape fast path (`gating::deny_shape`) and
    /// force a fresh LLM call for this one request. Never skips an
    /// operator-authored `PolicyEngine` deny rule -- those stay absolute.
    /// Safe for any caller: its only effect is "ask the LLM again."
    #[serde(default)]
    pub reevaluate: bool,
    /// SSH host-key behavior for first-contact workflows. Only applied when
    /// `binary == "ssh"`; the default (`None`/`OnlyExisting`) preserves ssh's
    /// existing strict host-key checking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_hostkey: Option<SshHostKeyMode>,
    /// Caller working directory, captured by the authenticated client and
    /// canonicalized by the daemon before evaluation or execution. This is
    /// structured protocol metadata, never accepted through caller environment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<PathBuf>,
}

impl ExecuteRequest {
    /// Prepend the ssh `-o` options implied by the requested host-key mode so
    /// the policy decision, the evaluator, the audit log, and the spawned
    /// process all see the identical command. A no-op for non-ssh binaries and
    /// for `OnlyExisting`/absent modes, which keep ssh's strict default.
    pub fn apply_ssh_hostkey_options(&mut self) {
        if self.binary != "ssh" {
            return;
        }
        let options = match self.ssh_hostkey {
            Some(mode) => mode.ssh_options(),
            None => return,
        };
        if options.is_empty() {
            return;
        }
        let mut injected = Vec::with_capacity(self.args.len() + options.len() * 2);
        for (key, value) in options {
            injected.push("-o".to_string());
            injected.push(format!("{key}={value}"));
        }
        injected.append(&mut self.args);
        self.args = injected;
    }
}

/// A structured rollback command (no shell). Each arg is a single argv element.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevertSpec {
    pub binary: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// Independent verification command run at the containment deadline. Exit
    /// zero keeps the forward change; every other outcome runs the rollback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm_check: Option<CommandSpec>,
    /// Operator description of the authority and transport the daemon needs to
    /// execute the check and rollback. The evaluator treats this as data, not
    /// instructions, and holds when the forward command can plausibly sever it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_path: Option<String>,
}

impl RevertSpec {
    pub fn new(binary: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            binary: binary.into(),
            args,
            confirm_check: None,
            control_path: None,
        }
    }
}

/// A structured command used inside an already-evaluated containment envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandSpec {
    pub binary: String,
    #[serde(default)]
    pub args: Vec<String>,
}

/// A request to run a catalog verb by name with validated parameters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerbInvocation {
    pub name: String,
    #[serde(default)]
    pub params: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchCommand {
    pub binary: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub env: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub secrets: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub secret_files: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<PathBuf>,
}

/// Validate a requested binary name: reject paths, traversal, and shell
/// metacharacters. Windows path forms (backslash, drive-letter `:`, UNC) are
/// rejected too so a caller cannot pass an absolute/relative path disguised as
/// the "binary". Returns the denial reason surfaced to the client.
pub fn validate_binary_name(binary: &str) -> Result<(), String> {
    if binary.contains('/')
        || binary.contains('\\')
        || binary.contains(':')
        || binary.contains("..")
        || binary.contains('\0')
        || binary.is_empty()
    {
        let looks_like_shell_string =
            binary.contains(char::is_whitespace) || binary.contains('"') || binary.contains('\'');
        let reason = if looks_like_shell_string {
            format!(
                "invalid binary name: '{}'. guard run expects `<binary> [args...]`, not a shell string. Pass the command as separate arguments; e.g. `guard run ssh host 'remote cmd'` instead of `guard run 'ssh host \"remote cmd\"'`.",
                binary
            )
        } else {
            format!("invalid binary name: '{}'", binary)
        };
        return Err(reason);
    }
    Ok(())
}

/// Validate requested argv values. NUL can never be a legitimate argv byte
/// (execve delimits arguments with NUL), so reject it at the boundary. Other
/// control characters stay accepted: multi-line arguments (commit messages via
/// -m, heredoc-style payloads) are legitimate, and the audit renderer escapes
/// them. Returns the denial reason surfaced to the client.
pub fn validate_args(args: &[String]) -> Result<(), String> {
    if let Some(position) = args.iter().position(|arg| arg.contains('\0')) {
        return Err(format!(
            "invalid argument at index {}: contains NUL byte",
            position
        ));
    }
    Ok(())
}
