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
use crate::grant_profile::ProfileCatalog;
use crate::grant_rules::{compile_session_grant_rules, CompiledGrantRules};
use crate::injection::is_valid_env_name;
use crate::redact::{
    redact_exact_secrets, redact_output, redact_output_text, redact_output_with_state,
    RedactionState,
};
use crate::secrets::{legacy_sentinel, SecretManager};
use crate::session::{
    HistoricalGrant, SessionAmendment, SessionDecision, SessionDecisionSource, SessionExecStatus,
    SessionGrant, SessionGrantSummary, SessionInteraction, SessionRegistry, SessionReport,
};
use crate::session_store::SessionStore;
use crate::shim::ShimGenerator;
use guard::gating::approval::{Approval, ApprovalRegistry, ApprovalSnapshot, ApprovalStatus};
use guard::gating::provisional::{Provisional, ProvisionalRegistry, ProvisionalStatus};
use guard::gating::read_grant::{
    ancestor_dirs_within, clamp_ttl, credential_path_deny_reason, AclEntry, GrantReadRegistry,
    ReadGrant, ReadGrantStatus,
};
use guard::gating::verb::VerbCatalog;
use guard::gating::{decide_gate, Coverage, GateMode, GateOutcome, Reversibility};
use guard::policy::PolicyMode;
use guard::principal::{scope_eq, PrincipalKey};

// Re-export so main.rs can pattern-match on history status without a
// direct dependency on the `session` module path.
pub use crate::session::HistoricalStatus;
use crate::tool_config::ToolRegistry;
use anyhow::{bail, Context, Result};
use guard::learned_rules::{AutoShimMode, LearningOutcome};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
#[cfg(unix)]
use std::ffi::CString;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
#[cfg(windows)]
use tokio::net::windows::named_pipe::NamedPipeServer;
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::process::Command;
use tokio::sync::{mpsc, RwLock};
#[cfg(unix)]
use uzers::os::unix::UserExt;

const DEFAULT_SOCKET_PATH: &str = "/var/run/guard/guard.sock";
const DEFAULT_TCP_PORT: u16 = 8123;
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
const APPROVAL_TTL_SECS: u64 = 3600;
/// Per-caller cap on outstanding holds + provisionals (local-DoS guard).
const MAX_PENDING_PER_CALLER: usize = 32;
/// Global cap on outstanding holds + provisionals.
const MAX_PENDING_GLOBAL: usize = 256;
/// How long decided/terminal gating rows are retained before pruning.
const GATING_RETENTION_SECS: u64 = 24 * 60 * 60;

/// Identifies the caller for per-user secret injection.
#[derive(Debug, Clone)]
pub enum CallerIdentity {
    Unix {
        uid: u32,
    },
    /// Local caller over a Windows named pipe, identified by the kernel-verified
    /// SID of the connecting process (the Windows analog of a peer UID).
    #[cfg(windows)]
    Windows {
        sid: String,
    },
    Tcp {
        token: String,
    },
    TcpAdmin {
        token: String,
    },
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
            Self::TcpAdmin { token } => Some(token.clone()),
            Self::Unknown => None,
        }
    }

    /// The caller's cross-platform principal key, or `None` for an
    /// unauthenticated caller. This is the single identity used for every
    /// gating authorization and ownership decision, giving a Windows SID caller
    /// full parity with a Unix uid caller.
    pub fn principal(&self) -> Option<PrincipalKey> {
        self.user_key().map(PrincipalKey::from_raw)
    }

    /// True only for a kernel-verified LOCAL peer — a Unix-socket uid or a
    /// Windows named-pipe SID. A bearer-token TCP caller (`Tcp`/`TcpAdmin`) and
    /// `Unknown` are NOT local peers, even though a TCP caller carries a token
    /// as its principal. Credential and environment injection are gated on this
    /// so a remote token-holder can never control a child's runtime environment.
    pub fn is_local_peer(&self) -> bool {
        match self {
            Self::Unix { .. } => true,
            #[cfg(windows)]
            Self::Windows { .. } => true,
            _ => false,
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
                write!(f, "token={}", audit_token(token))
            }
            Self::TcpAdmin { token } => {
                write!(f, "admin_token={}", audit_token(token))
            }
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

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
}

impl ExecuteRequest {
    /// Prepend the ssh `-o` options implied by the requested host-key mode so
    /// the policy decision, the evaluator, the audit log, and the spawned
    /// process all see the identical command. A no-op for non-ssh binaries and
    /// for `OnlyExisting`/absent modes, which keep ssh's strict default.
    fn apply_ssh_hostkey_options(&mut self) {
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
}

/// A request to run a catalog verb by name with validated parameters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerbInvocation {
    pub name: String,
    #[serde(default)]
    pub params: std::collections::BTreeMap<String, String>,
}

/// A filesystem read-grant request. Routed through the same policy pipeline as a
/// brokered command (static credential deny-list, then session allow/deny globs,
/// then the LLM evaluator), never through an admin/operator side channel, so a
/// session-token holder can request one without per-grant operator involvement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum GrantRequest {
    /// Grant guard's brokering identity a time-boxed read grant on `path`.
    Read {
        path: String,
        ttl_secs: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_token: Option<String>,
        #[serde(default)]
        reevaluate: bool,
    },
    /// Revoke an active read grant on `path` early (de-escalation; not gated).
    Revoke {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_token: Option<String>,
    },
}

impl GrantRequest {
    fn path(&self) -> &str {
        match self {
            Self::Read { path, .. } | Self::Revoke { path, .. } => path,
        }
    }

    fn session_token(&self) -> Option<&str> {
        match self {
            Self::Read { session_token, .. } | Self::Revoke { session_token, .. } => {
                session_token.as_deref()
            }
        }
    }
}

/// Resolved verb context threaded into gate routing.
#[derive(Debug, Clone)]
struct VerbContext {
    name: String,
    class: Reversibility,
    trusted: bool,
    params: std::collections::BTreeMap<String, String>,
    catalog_version: u64,
}

/// Whether a verb's `trusted` flag still applies, given its own
/// `auto_promoted`/`promotion_stamp` and the daemon's current stamp. A
/// hand-authored verb (`auto_promoted == false`) has no expiry: an operator
/// reviewed it, so it stays trusted until the operator changes it. An
/// auto-promoted verb (`gating::allow_promotion`) is trusted only as long as
/// the daemon's current model + prompt stamp matches the one that justified
/// promoting it -- a model or prompt change silently downgrades it back to
/// an untrusted, LLM-evaluated shape rather than continuing to trust a
/// judgment made under a since-changed evaluator. The single source of truth
/// for this check: used for the explicit-invocation and reverse-match verb
/// paths in `execute_command_inner` (via `verb_trust_is_current`) and for
/// what `guard verb list` reports (via `verb_effective_trust`), so the two
/// can never disagree about whether a given verb is still trusted.
fn trust_is_current(
    trusted: bool,
    auto_promoted: bool,
    promotion_stamp: Option<&str>,
    current_stamp: &str,
) -> bool {
    trusted && (!auto_promoted || promotion_stamp == Some(current_stamp))
}

fn verb_trust_is_current(r: &guard::gating::verb::RenderedVerb, current_stamp: &str) -> bool {
    trust_is_current(
        r.trusted,
        r.auto_promoted,
        r.promotion_stamp.as_deref(),
        current_stamp,
    )
}

/// Same check for a raw catalog `Verb` (not yet rendered against params),
/// used by `guard verb list` so a stale auto-promoted verb is reported as
/// untrusted rather than misleading an operator into thinking it is still
/// fast-pathing when the daemon has actually stopped honoring it.
fn verb_effective_trust(verb: &guard::gating::verb::Verb, current_stamp: &str) -> bool {
    trust_is_current(
        verb.trusted,
        verb.auto_promoted,
        verb.promotion_stamp.as_deref(),
        current_stamp,
    )
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prose: Option<String>,
        /// Name of an operator-defined profile to seed this grant from. Unknown
        /// names are rejected; a known profile's ttl/allow/deny/prompt are merged
        /// in before the grant is installed on the normal path.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        profile: Option<String>,
        #[serde(default)]
        static_only: bool,
        #[serde(default)]
        auto_amend: bool,
    },
    SessionAppeal {
        token: String,
        binary: String,
        #[serde(default)]
        args: Vec<String>,
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
        /// Optional session token already held by the caller. Non-admin local
        /// callers can see rule bodies and prompt text for this token, while
        /// raw token values remain redacted in list output.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        visible_token: Option<String>,
    },
    SessionShow {
        token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<usize>,
        /// The caller's own authenticated session token (from `$GUARD_SESSION`).
        /// A non-admin caller may inspect a grant only when this equals `token`
        /// -- i.e. the caller is asking about the very token it holds. Absent
        /// for the daemon-principal case, which is authorized regardless.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        caller_token: Option<String>,
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
    // --- Consequence gating ---
    /// Operator confirms a provisional (keep the change, cancel auto-revert).
    Confirm {
        handle: String,
    },
    /// Operator reverts a provisional now (manual rollback).
    Revert {
        handle: String,
    },
    /// List provisional (containment) executions. Daemon UID sees all; other
    /// callers see only their own.
    Provisionals,
    /// Operator approves a held command (executes it from its bound snapshot).
    Approve {
        handle: String,
    },
    /// Operator denies a held command.
    Deny {
        handle: String,
    },
    /// List held/decided approvals. Daemon UID sees all; others see their own.
    ApprovalList,
    /// Fetch one approval's status and result (for the agent to poll its own
    /// held command). Scoped by handle ownership.
    ApprovalShow {
        handle: String,
    },
    /// Append a note to a held command's discussion thread. Allowed for the
    /// operator (any hold) or the hold's original requester (its own hold).
    ApprovalNote {
        handle: String,
        text: String,
    },
    /// List the operator-defined verb catalog (the agent's menu).
    VerbList,
    /// Synthesize a typed verb from operator prose via the LLM and (unless
    /// `preview`) append it to the catalog with the prose + evidence recorded.
    /// Operator-only (mutates the catalog).
    VerbCreate {
        prose: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        binary_hint: Option<String>,
        #[serde(default)]
        preview: bool,
    },
}

impl AdminRequest {
    /// Admin RPCs that require the caller to be the daemon UID.
    /// Ping is a public liveness probe. Secret RPCs and session
    /// listing are open to any connected user; they self-scope or
    /// redact sensitive fields so a caller cannot elevate from them.
    fn requires_daemon_uid(&self) -> bool {
        // Gate-control writes (confirm/revert/approve/deny) are daemon-UID-only:
        // a corrupted agent must never be able to confirm or approve its own
        // action. Reads (provisionals/approval list/show) self-scope inside the
        // handler by the caller's uid or by unguessable handle ownership, so they
        // do not require the daemon UID.
        !matches!(
            self,
            Self::Ping
                | Self::SessionList { .. }
                | Self::SessionShow { .. }
                | Self::SecretSet { .. }
                | Self::SecretDelete { .. }
                | Self::SecretExists { .. }
                | Self::SecretList
                | Self::Provisionals
                | Self::ApprovalList
                | Self::ApprovalShow { .. }
                // ApprovalNote does its own operator-or-owner authorization in
                // the handler, so it is not gated to the daemon UID here.
                | Self::ApprovalNote { .. }
                | Self::VerbList
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
    SessionAppeal {
        allowed: bool,
        amended: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pattern: Option<String>,
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        risk: Option<i32>,
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
    // --- Consequence gating ---
    /// A gate action ran (confirm/revert/approve/deny). Carries a human message
    /// and, for approve/revert, the resulting exit/output.
    GateAction {
        message: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stdout: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stderr: Option<String>,
    },
    Provisionals {
        items: Vec<ProvisionalSummary>,
    },
    Approvals {
        items: Vec<ApprovalSummary>,
    },
    ApprovalShow {
        item: ApprovalSummary,
    },
    Verbs {
        items: Vec<VerbSummary>,
    },
    VerbCreated {
        verb: guard::gating::verb::Verb,
        /// True when the verb was written to the catalog; false for a preview.
        persisted: bool,
    },
}

/// Agent-facing view of a catalog verb (its menu entry).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerbSummary {
    pub name: String,
    pub description: String,
    pub binary: String,
    pub consequence: String,
    /// Whether this verb currently skips the LLM. For an auto-promoted verb
    /// this already reflects the staleness check (`verb_effective_trust`):
    /// `false` here means the daemon has stopped honoring the promotion
    /// (e.g. after a model/prompt change), even if the catalog's underlying
    /// `trusted` field still says `true`.
    pub trusted: bool,
    pub has_revert: bool,
    /// Parameter name -> validation pattern.
    pub params: std::collections::BTreeMap<String, String>,
    /// True for a verb `gating::allow_promotion` appended automatically from
    /// repeated approvals, rather than authored or reviewed by an operator.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub auto_promoted: bool,
    /// Rationale recorded when the verb was created or promoted (operator
    /// prose evidence for `guard verb create`, or the derived/model evidence
    /// for an auto-promotion).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

/// Operator-facing view of a provisional execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionalSummary {
    pub handle: String,
    pub status: String,
    pub command: String,
    pub revert_command: String,
    pub reason: String,
    pub created_unix: u64,
    pub deadline_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revert_exit: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revert_detail: Option<String>,
}

/// Operator-facing view of a held/decided approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalSummary {
    pub handle: String,
    pub status: String,
    pub command: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reversibility: Option<String>,
    pub fingerprint: String,
    pub created_unix: u64,
    pub deadline_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_reason: Option<String>,
    /// Approval discussion thread (operator <-> requester).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<guard::gating::approval::ApprovalNote>,
}

impl ProvisionalSummary {
    fn from_row(p: &Provisional) -> Self {
        let command = if p.args.is_empty() {
            p.binary.clone()
        } else {
            format!("{} {}", p.binary, p.args.join(" "))
        };
        Self {
            handle: p.handle.clone(),
            status: p.status.as_str().to_string(),
            command,
            revert_command: p.revert_command_line(),
            reason: p.reason.clone(),
            created_unix: p.created_unix,
            deadline_unix: p.deadline_unix,
            principal: p.principal.as_ref().map(|p| p.as_str().to_string()),
            revert_exit: p.revert_exit,
            revert_detail: p.revert_detail.clone(),
        }
    }
}

impl ApprovalSummary {
    fn from_row(a: &Approval) -> Self {
        Self {
            handle: a.handle.clone(),
            status: a.status.as_str().to_string(),
            command: a.snapshot.command_line(),
            reason: a.reason.clone(),
            risk: a.risk,
            reversibility: a.reversibility.map(|r| r.as_str().to_string()),
            fingerprint: a.snapshot.fingerprint(),
            created_unix: a.created_unix,
            deadline_unix: a.deadline_unix(),
            principal: a
                .snapshot
                .principal
                .as_ref()
                .map(|p| p.as_str().to_string()),
            exit_code: a.result_exit,
            stdout: a.result_stdout.clone(),
            stderr: a.result_stderr.clone(),
            decided_reason: a.decided_reason.clone(),
            notes: a.notes.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretDetail {
    pub key: String,
    /// Owning uid for a Unix uid principal; `None` for a SID or legacy entry.
    /// Display-only; retained for back-compat with older clients.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// Owning principal string (uid or SID); `None` for a legacy flat entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
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
    #[serde(default)]
    pub learning_enabled: bool,
    #[serde(default)]
    pub learned_rule_count: usize,
    /// Whether auto-learned deny-shape detection is active (see
    /// `gating::deny_shape`; on by default, `--no-learn-deny` to disable).
    #[serde(default)]
    pub deny_learning_enabled: bool,
    /// Number of auto-learned deny shapes currently active as a pre-LLM fast
    /// path.
    #[serde(default)]
    pub deny_shape_count: usize,
    /// Whether auto-verb-promotion is active (see `gating::allow_promotion`;
    /// on by default, `--no-learn-allow` to disable).
    #[serde(default)]
    pub allow_promotion_enabled: bool,
    /// Number of observation buckets auto-verb-promotion is currently
    /// tracking (not the number of verbs promoted -- see `guard verb list`
    /// for those).
    #[serde(default)]
    pub allow_promotion_observation_count: usize,
    pub session_count: usize,
    pub daemon_uid: u32,
    pub exec_identity: String,
    pub state_db_path: Option<String>,
    #[serde(default)]
    pub secret_backend: String,
    /// Consequence-gating mode (`off` / `consequence`).
    #[serde(default)]
    pub gate: String,
    /// Outstanding provisional (containment) executions.
    #[serde(default)]
    pub pending_provisionals: usize,
    /// Outstanding held approvals.
    #[serde(default)]
    pub pending_approvals: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum IncomingMessage {
    Admin {
        admin: AdminRequest,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        admin_token: Option<String>,
    },
    Grant {
        grant: GrantRequest,
    },
    Execute(Box<ExecuteRequest>),
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
    /// Consequence-gate outcome. Absent on a legacy (gating-off) response, which
    /// old clients parse as a normal allow/deny. `Held`/`Provisional` mean the
    /// command was approved but routed to the operator gate / containment
    /// envelope, not denied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<GateStatus>,
    /// Handle for a held or provisional command, used by `guard approve` /
    /// `guard confirm` / `guard approvals show`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    /// Honest statement of what the gate checked and did not check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage: Option<Coverage>,
}

/// Wire-level consequence-gate outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStatus {
    /// Executed immediately (reversible, or gating off).
    Executed,
    /// Executed inside a containment envelope; auto-reverts unless confirmed.
    Provisional,
    /// Approved but held for operator approval; not executed.
    Held,
    /// A revert ran (response from `guard revert`/auto-revert reporting).
    Reverted,
    /// Policy evaluated, not executed (dry-run).
    DryRun,
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
    pub admin_token: Option<String>,
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
    /// The daemon's own cross-platform principal: its uid on Unix, its process
    /// SID on Windows. Operator/admin RPCs require the caller's principal to
    /// equal this — the single "is the operator" source of truth on both
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
    /// Operator-authored verb catalog (the typed, least-expressive interface).
    pub verbs: Arc<RwLock<VerbCatalog>>,
    /// Operator-authored session-grant profiles: named {ttl, allow, deny,
    /// prompt_append} bundles that `guard session new --profile <name>` mints a
    /// grant from. Loaded at startup from `--profiles` / `GUARD_PROFILES`; empty
    /// by default. A profile is only a pre-authored convenience: the grant it
    /// mints takes the identical install/validation path as a hand-authored one,
    /// so it is no new trust boundary.
    pub profiles: ProfileCatalog,
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
    /// generically without per-tool code — e.g. `KUBECONFIG` so brokered
    /// kubectl/helm read a config the agent cannot see.
    pub extra_child_env: Vec<String>,
    /// Optional Kubernetes API proxy hosted alongside the gate socket. When set,
    /// the daemon terminates brokered clients' TLS, gates each API operation
    /// against the operator policy, and re-originates to the real apiserver with
    /// the credentials only the daemon holds. Set by the entrypoint from
    /// `--kube-proxy`; `None` means no proxy listener.
    pub kube_proxy: Option<Arc<guard::proxy::KubeProxy>>,
    /// Active filesystem read grants (Unix-only). Time-boxed POSIX ACL read
    /// grants issued via `guard grant-read`; the sweeper auto-revokes them at
    /// expiry and startup reconciliation revokes any that expired while the
    /// daemon was down.
    pub read_grants: Arc<RwLock<GrantReadRegistry>>,
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
            tool_registry: Arc::new(RwLock::new(tool_registry)),
            redact_secrets,
            preflight,
            session_store,
            exec_as_caller,
            daemon_uid: current_uid(),
            daemon_principal: resolve_daemon_principal(),
            sessions: Arc::new(RwLock::new(sessions)),
            started_at_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            state_db_path,
            // Gating defaults to off; the daemon entrypoint enables it and
            // populates the registries from persisted state before serving.
            gate: GateMode::Off,
            provisional: Arc::new(RwLock::new(ProvisionalRegistry::new())),
            approvals: Arc::new(RwLock::new(ApprovalRegistry::new())),
            verbs: Arc::new(RwLock::new(VerbCatalog::empty())),
            // No profiles by default; the entrypoint sets this from --profiles.
            profiles: ProfileCatalog::empty(),
            // No binary restriction by default; the entrypoint sets this from
            // --allow-bin / GUARD_ALLOW_BIN, like the gate fields above.
            allowed_binaries: None,
            // No extra child-env passthrough by default; the entrypoint sets
            // this from --child-env / GUARD_CHILD_ENV.
            extra_child_env: Vec::new(),
            // No API proxy by default; the entrypoint sets this from --kube-proxy.
            kube_proxy: None,
            read_grants: Arc::new(RwLock::new(GrantReadRegistry::new())),
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

    fn validate_admin_token(&self, token: Option<&str>) -> Result<()> {
        let Some(ref expected) = self.admin_token else {
            anyhow::bail!("admin token is not configured");
        };
        let provided = token.unwrap_or("").as_bytes();
        let expected = expected.as_bytes();
        let len_match = provided.len() == expected.len();
        let byte_match = provided
            .iter()
            .zip(expected.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        if !len_match || byte_match != 0 {
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
        binary: &str,
        args: &[String],
        allowed: bool,
        reason: &str,
    ) {
        let action = if allowed { "ALLOWED" } else { "DENIED" };
        tracing::info!(
            "[AUDIT] {} caller={} cmd=\"{}\" reason=\"{}\"",
            action,
            caller,
            audit_command_line(binary, args),
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
            "[AUDIT] EXEC_FAILED caller={} cmd=\"{}\" reason=\"{}\"",
            caller,
            audit_command_line(binary, args),
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
        let config = ServerConfig::new(
            socket_path,
            tcp_port,
            evaluator,
            secrets,
            redact,
            auth_token,
            admin_token,
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

    /// Enable consequence gating. Must be called before `run`.
    pub fn set_gate(&mut self, gate: GateMode) {
        self.config.gate = gate;
    }

    /// Install the operator-defined verb catalog. Must be called before `run`.
    pub fn set_verbs(&mut self, catalog: VerbCatalog) {
        self.config.verbs = Arc::new(RwLock::new(catalog));
    }

    /// Install the operator-defined session-grant profiles. Must be called
    /// before `run`.
    pub fn set_profiles(&mut self, catalog: ProfileCatalog) {
        self.config.profiles = catalog;
    }

    /// Restrict which binaries may execute. `None` imposes no restriction (the
    /// default); an empty list denies everything. Must be called before `run`.
    pub fn set_allowed_binaries(&mut self, allowed: Option<Vec<String>>) {
        self.config.allowed_binaries = allowed;
    }

    /// Set the operator-declared extra child-env passthrough list (see
    /// [`ServerConfig::extra_child_env`]). Must be called before `run`.
    pub fn set_extra_child_env(&mut self, vars: Vec<String>) {
        self.config.extra_child_env = vars;
    }

    /// Attach a Kubernetes API proxy to run alongside the gate socket. Must be
    /// called before `run`.
    pub fn set_kube_proxy(&mut self, proxy: Arc<guard::proxy::KubeProxy>) {
        self.config.kube_proxy = Some(proxy);
    }

    /// Load persisted provisional/approval state and apply startup recovery:
    /// no revert ever runs unattended at boot. Past-deadline or interrupted
    /// provisionals become `needs_operator_decision`; interrupted approvals
    /// become `exec_failed`. Both are surfaced via a high-severity audit line.
    async fn startup_gating(&self) {
        let Some(store) = &self.config.session_store else {
            tracing::info!(
                "Consequence gating enabled (no state-db: provisional/approval state is process-local and not recovered across restart)"
            );
            return;
        };

        match store.load_provisionals().await {
            Ok(rows) => {
                let (reg, moved) = ProvisionalRegistry::from_rows(rows);
                if !moved.is_empty() {
                    tracing::warn!(
                        "[AUDIT] STARTUP_RECOVERY provisionals_needing_decision={} handles={:?} (no revert runs unattended at boot)",
                        moved.len(),
                        moved
                    );
                    for h in &moved {
                        if let Some(p) = reg.get(h) {
                            if let Err(e) = store.save_provisional(p.clone()).await {
                                tracing::warn!(
                                    "failed to persist recovered provisional {}: {}",
                                    h,
                                    e
                                );
                            }
                        }
                    }
                }
                *self.config.provisional.write().await = reg;
            }
            Err(e) => tracing::error!("failed to load provisional state: {}", e),
        }

        match store.load_approvals().await {
            Ok(rows) => {
                let now = now_unix();
                let (mut reg, recovered) = ApprovalRegistry::from_rows(rows, now);
                if !recovered.is_empty() {
                    tracing::warn!(
                        "[AUDIT] STARTUP_RECOVERY approvals_exec_failed={} handles={:?} (exec interrupted by restart)",
                        recovered.len(),
                        recovered
                    );
                    for h in &recovered {
                        if let Some(a) = reg.get(h) {
                            if let Err(e) = store.save_approval(a.clone()).await {
                                tracing::warn!("failed to persist recovered approval {}: {}", h, e);
                            }
                        }
                    }
                }
                // A kube-proxy hold cannot survive a restart: the parked HTTP
                // request died with the old process, so a still-pending row
                // would offer the operator an approval that releases nothing.
                let orphaned: Vec<String> = reg
                    .list()
                    .into_iter()
                    .filter(|a| {
                        a.status == ApprovalStatus::Pending
                            && a.snapshot.binary == KUBE_PROXY_SENTINEL_BINARY
                    })
                    .map(|a| a.handle)
                    .collect();
                for h in &orphaned {
                    reg.set_exec_failed(
                        h,
                        now,
                        "daemon restarted; the held API request is gone".to_string(),
                    );
                    if let Some(a) = reg.get(h) {
                        if let Err(e) = store.save_approval(a.clone()).await {
                            tracing::warn!("failed to persist retired proxy hold {}: {}", h, e);
                        }
                    }
                }
                if !orphaned.is_empty() {
                    tracing::warn!(
                        "[AUDIT] STARTUP_RECOVERY kube_proxy_holds_retired={} handles={:?}",
                        orphaned.len(),
                        orphaned
                    );
                }
                *self.config.approvals.write().await = reg;
            }
            Err(e) => tracing::error!("failed to load approval state: {}", e),
        }
    }

    /// Load persisted read grants at startup. Any grant already past its TTL is
    /// revoked immediately (a read grant only removes access, so this is always
    /// safe to do unattended, unlike a provisional revert); a grant still within
    /// its TTL is re-armed by loading it Active so the sweeper fires at its
    /// deadline.
    #[cfg(unix)]
    async fn startup_read_grants(&self) {
        let Some(store) = &self.config.session_store else {
            return;
        };
        let rows = match store.load_read_grants().await {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!("failed to load read-grant state: {}", e);
                return;
            }
        };
        let reg = GrantReadRegistry::from_rows(rows);
        let now = now_unix();
        let mut surviving = GrantReadRegistry::new();
        for grant in reg.list() {
            if grant.status == ReadGrantStatus::Active && now >= grant.expires_unix {
                match revoke_read_grant_acls(&grant).await {
                    Ok(()) => {
                        tracing::warn!(
                            "[AUDIT] READ_GRANT_REVOKED handle={} path=\"{}\" source=startup-expired",
                            grant.handle,
                            grant.target_path
                        );
                        delete_read_grant_row(&self.config, &grant.target_path).await;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "[AUDIT] READ_GRANT_REVOKE_FAILED handle={} path=\"{}\" source=startup-expired detail=\"{}\"",
                            grant.handle,
                            grant.target_path,
                            e
                        );
                        surviving.insert(grant);
                    }
                }
            } else {
                surviving.insert(grant);
            }
        }
        *self.config.read_grants.write().await = surviving;
    }

    pub async fn run(&self) -> Result<()> {
        tracing::info!("Server::run() called");

        // Consequence gating: load persisted state (with boot-safe recovery).
        if self.config.gate.is_on() {
            tracing::info!("Consequence gating: {}", self.config.gate);
            self.startup_gating().await;
        }
        // Reconcile persisted read grants (revoke expired, re-arm live).
        #[cfg(unix)]
        self.startup_read_grants().await;

        // The single sweeper drives both consequence-gate reverts (gate-on only)
        // and read-grant expiries (Unix, gate-independent), so it runs whenever
        // either is live. Without this a read grant could outlive its TTL simply
        // because the daemon runs without consequence gating.
        if self.config.gate.is_on() || cfg!(unix) {
            let config = self.config.clone();
            tokio::spawn(async move { gating_sweeper(config).await });
        }

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

        if let Some(ref proxy) = self.config.kube_proxy {
            // The auto-revert envelope needs the consequence sweeper, which only
            // runs under `--gate consequence`. Without it the proxy still gates
            // (allow/deny/hold/redact) but forwards recoverable writes unwrapped.
            if self.config.gate.is_on() {
                let snapshot_dir = self
                    .config
                    .state_db_path
                    .as_ref()
                    .and_then(|p| p.parent())
                    .map(|d| d.join("kube-proxy-reverts"))
                    .unwrap_or_else(|| std::env::temp_dir().join("guard-kube-proxy-reverts"));
                if let Err(e) = std::fs::create_dir_all(&snapshot_dir) {
                    tracing::warn!(
                        "could not create kube-proxy revert dir {}: {}",
                        snapshot_dir.display(),
                        e
                    );
                }
                proxy.attach_gate(Arc::new(DaemonGateSink {
                    config: self.config.clone(),
                    kubeconfig: proxy.real_kubeconfig().to_path_buf(),
                    snapshot_dir,
                    window_secs: DEFAULT_CONFIRM_WITHIN_SECS,
                }));
            } else {
                tracing::info!(
                    "kube-proxy: --gate consequence not set; recoverable writes forwarded without auto-revert and policy 'hold' rules deny fail-closed (no approval queue)"
                );
            }
            tracing::info!("Starting kube-proxy listener on {}", proxy.listen());
            let proxy = proxy.clone();
            futures.push(tokio::spawn(async move { proxy.serve().await }));
        }

        if futures.is_empty() {
            anyhow::bail!("no socket path or TCP port specified");
        }

        // A listener loop only returns on a fatal error (e.g. it could not bind);
        // surface it as an error return rather than exiting silently. This makes
        // the process exit non-zero, so the Windows service reports a failure and
        // the SCM restart action engages instead of the daemon sitting STOPPED
        // after a bind failure while having briefly reported RUNNING.
        let mut listener_error: Option<anyhow::Error> = None;
        for result in futures::future::join_all(futures).await {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::error!("listener exited with error: {:#}", e);
                    listener_error.get_or_insert(e);
                }
                Err(e) => {
                    tracing::error!("listener task panicked: {}", e);
                    listener_error
                        .get_or_insert_with(|| anyhow::anyhow!("listener task panicked: {}", e));
                }
            }
        }

        match listener_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Platform dispatch for the local listener: UNIX domain socket on Unix,
    /// named pipe on Windows.
    async fn run_local_static(socket_path: &Path, config: &ServerConfig) -> Result<()> {
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
    async fn run_pipe_static(socket_path: &Path, config: &ServerConfig) -> Result<()> {
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
    async fn run_unix_static(socket_path: &Path, config: &ServerConfig) -> Result<()> {
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
    async fn chown_to_group(path: &Path, group: &str) -> Result<()> {
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
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
    };

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
        // The daemon's own account gets full control so it can create the
        // additional pipe instances each accepted client needs
        // (FILE_CREATE_PIPE_INSTANCE). A non-elevated daemon runs as a plain
        // Authenticated User, so without this it can create the first instance
        // but is denied the second (the AU ACE below excludes create-instance).
        // Administrators/SYSTEM also get full control. Authenticated Users get
        // only FILE_GENERIC_READ|FILE_GENERIC_WRITE (0x0012019b) so they can
        // CONNECT but NOT stand up rogue instances. Tighten AU to a specific
        // agent SID for a multi-user host.
        let owner_sid =
            unsafe { process_user_sid() }.context("resolve daemon SID for pipe DACL")?;
        let sddl: Vec<u16> =
            format!("D:(A;;GA;;;{owner_sid})(A;;GA;;;BA)(A;;GA;;;SY)(A;;0x0012019b;;;AU)\0")
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
                bail!(
                    "CreateNamedPipeW failed: {}",
                    std::io::Error::last_os_error()
                );
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
            let base = path.file_name().and_then(|f| f.to_str()).unwrap_or("guard");
            format!(r"\\.\pipe\{}", base)
        }
    }

    /// SID string of the daemon's own process token. Used to grant the daemon
    /// full control of the pipe DACL so it can create additional instances.
    pub(super) unsafe fn process_user_sid() -> Result<String> {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            bail!(
                "OpenProcessToken failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let result = sid_string_from_token(token);
        CloseHandle(token);
        result
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
            bail!(
                "OpenThreadToken failed: {}",
                std::io::Error::last_os_error()
            );
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
            bail!(
                "GetTokenInformation failed: {}",
                std::io::Error::last_os_error()
            );
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
            // Fail closed: a local pipe peer whose SID we cannot resolve is not
            // trustworthy for per-identity state (secret namespaces, pending-op
            // caps). Drop the connection rather than admit a shared synthetic
            // identity that multiple degraded callers would collapse onto.
            tracing::warn!(
                "could not resolve pipe client SID ({}); rejecting connection",
                e
            );
            return Err(e);
        }
    };
    serve_connection(stream, caller, config).await
}

/// Drive the request/response protocol for one connected client, independent of
/// the underlying transport (UNIX socket or Windows named pipe).
async fn serve_connection<S>(stream: S, caller: CallerIdentity, config: &ServerConfig) -> Result<()>
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
                    status: None,
                    handle: None,
                    coverage: None,
                };
                writer
                    .write_all(serde_json::to_string(&resp)?.as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                continue;
            }
        };

        let request = match incoming {
            IncomingMessage::Admin { admin, .. } => {
                let resp = handle_admin_request(config, &caller, admin).await;
                writer
                    .write_all(serde_json::to_string(&resp)?.as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                continue;
            }
            IncomingMessage::Grant { grant } => {
                let result = handle_grant_request(config, &caller, grant).await;
                let resp = result.into_response();
                writer
                    .write_all(serde_json::to_string(&resp)?.as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                continue;
            }
            IncomingMessage::Execute(req) => *req,
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
                status: None,
                handle: None,
                coverage: None,
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
    if let ExecOutcome::Failed { reason, .. } = &result.exec {
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
    if let ExecOutcome::Failed { reason, .. } = &result.exec {
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

fn merge_unique(target: &mut Vec<String>, additions: Vec<String>) {
    for value in additions {
        if !target.iter().any(|existing| existing == &value) {
            target.push(value);
        }
    }
}

fn combine_session_prompt(
    prompt_append: Option<String>,
    prose: Option<&str>,
    _compiled: &CompiledGrantRules,
) -> Option<String> {
    let mut sections = Vec::new();
    let prompt_append = prompt_append
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if let Some(prose) = prose.map(str::trim).filter(|value| !value.is_empty()) {
        sections.push(format!("Session grant prose:\n{prose}"));
    }
    if sections.is_empty() {
        return prompt_append;
    }
    if let Some(prompt) = prompt_append {
        sections.push(format!("Additional session context:\n{prompt}"));
    }
    Some(sections.join("\n\n"))
}

fn caller_is_session_admin(config: &ServerConfig, caller: &CallerIdentity) -> bool {
    matches!(caller.principal(), Some(ref p) if config.daemon_principal.eq_ci(p))
        || matches!(caller, CallerIdentity::TcpAdmin { .. })
}

fn caller_can_view_session(
    config: &ServerConfig,
    caller: &CallerIdentity,
    token: &str,
    visible_token: Option<&str>,
) -> bool {
    caller_is_session_admin(config, caller) || visible_token == Some(token)
}

fn redact_session_summary_for_list(grant: &mut SessionGrantSummary, admin: bool, can_view: bool) {
    if !admin {
        grant.token = if can_view {
            "(current)".to_string()
        } else {
            "(hidden)".to_string()
        };
    }
    if !can_view {
        grant.allow.clear();
        grant.deny.clear();
        grant.allow_exact.clear();
        grant.deny_exact.clear();
        grant.generated_notes.clear();
        if grant.prompt_append.is_some() {
            grant.prompt_append = Some("(hidden)".to_string());
        }
    }
}

fn redact_historical_grant_for_list(grant: &mut HistoricalGrant, admin: bool, can_view: bool) {
    if !admin {
        grant.token = if can_view {
            "(current)".to_string()
        } else {
            "(hidden)".to_string()
        };
    }
    if !can_view {
        grant.allow.clear();
        grant.deny.clear();
        grant.allow_exact.clear();
        grant.deny_exact.clear();
        grant.generated_notes.clear();
        if grant.prompt_append.is_some() {
            grant.prompt_append = Some("(hidden)".to_string());
        }
    }
}

/// Mask the raw bearer token in a session report shown to its own holder. The
/// grant contents (rules, prompt, stats) are intentionally left intact for
/// self-diagnosis; only the token string is hidden so it is not echoed back.
fn mask_session_report_token(report: &mut SessionReport) {
    if let Some(active) = &mut report.active {
        active.token = "(current)".to_string();
    }
    for grant in &mut report.history {
        grant.token = "(current)".to_string();
    }
}

async fn handle_session_appeal(
    config: &ServerConfig,
    caller: &CallerIdentity,
    token: String,
    binary: String,
    args: Vec<String>,
) -> AdminResponse {
    if token.is_empty() {
        return AdminResponse::Error {
            message: "session token must not be empty".to_string(),
        };
    }
    let command_line = command_line(&binary, &args);
    if let Err(reason) = validate_session_exact_rule_candidate(&binary, &args) {
        return AdminResponse::SessionAppeal {
            allowed: false,
            amended: false,
            pattern: None,
            reason,
            risk: None,
        };
    }

    let (exists, decision, session_prompt) = {
        let reg = config.sessions.read().await;
        (
            reg.has(&token),
            reg.check(&token, &binary, &args),
            reg.prompt_append_for(&token),
        )
    };
    if !exists {
        return AdminResponse::Error {
            message: format!(
                "unknown session token: '{}' is revoked, expired, or never existed",
                token
            ),
        };
    }
    if let Some((decision, reason)) = decision {
        return match decision {
            SessionDecision::Allow => AdminResponse::SessionAppeal {
                allowed: true,
                amended: false,
                pattern: Some(command_line),
                reason: format!("already allowed by session rule: {reason}"),
                risk: None,
            },
            SessionDecision::Deny => AdminResponse::SessionAppeal {
                allowed: false,
                amended: false,
                pattern: Some(command_line),
                reason: format!("already denied by session rule: {reason}"),
                risk: None,
            },
        };
    }

    // An appeal is itself a request for a fresh look: it always bypasses the
    // auto-learned deny-shape fast path (never the operator PolicyEngine
    // deny rules, which `evaluate_with_reevaluate` never skips either way).
    let eval_result = config
        .evaluator
        .evaluate_with_reevaluate(&command_line, session_prompt.as_deref(), true)
        .await;

    match eval_result {
        crate::evaluate::EvalResult::Allow {
            reason,
            source,
            risk,
            reversibility: _,
        } => {
            if !matches!(source, crate::evaluate::EvalSource::Llm) {
                return AdminResponse::SessionAppeal {
                    allowed: false,
                    amended: false,
                    pattern: Some(command_line),
                    reason: format!(
                        "appeal not amended: evaluator source was {source:?}, not fresh LLM"
                    ),
                    risk,
                };
            }
            if let Err(skip) = allow_session_auto_amend_candidate(&binary, &args, risk) {
                record_live_session_interaction(
                    config,
                    Some(&token),
                    SessionInteraction {
                        at_unix: 0,
                        command: command_line.clone(),
                        allowed: false,
                        source: SessionDecisionSource::Llm,
                        reason: format!(
                            "appeal denied for static amendment: {skip}; LLM reason: {reason}"
                        ),
                        risk,
                        exec_status: SessionExecStatus::NotAttempted,
                    },
                )
                .await;
                return AdminResponse::SessionAppeal {
                    allowed: false,
                    amended: false,
                    pattern: Some(command_line),
                    reason: format!(
                        "appeal denied for static amendment: {skip}; LLM reason: {reason}"
                    ),
                    risk,
                };
            }

            let amended = match amend_session_exact_rule(
                config,
                &token,
                SessionAmendment::Allow,
                binary.clone(),
                args.clone(),
            )
            .await
            {
                Ok(amended) => amended,
                Err(err) => {
                    return AdminResponse::Error {
                        message: format!("failed to persist appeal allow amendment: {err}"),
                    };
                }
            };
            let final_reason = if amended {
                format!("appeal approved; amended exact session allow. LLM reason: {reason}")
            } else {
                format!(
                    "appeal approved; exact session allow already existed. LLM reason: {reason}"
                )
            };
            record_live_session_interaction(
                config,
                Some(&token),
                SessionInteraction {
                    at_unix: 0,
                    command: command_line.clone(),
                    allowed: true,
                    source: SessionDecisionSource::Llm,
                    reason: final_reason.clone(),
                    risk,
                    exec_status: SessionExecStatus::NotAttempted,
                },
            )
            .await;
            tracing::info!(
                "[AUDIT] SESSION_APPEAL caller={} token={} allowed=true amended={} cmd={}",
                caller,
                audit_token(&token),
                amended,
                redact_output(&command_line)
            );
            AdminResponse::SessionAppeal {
                allowed: true,
                amended,
                pattern: Some(command_line),
                reason: final_reason,
                risk,
            }
        }
        crate::evaluate::EvalResult::Deny {
            reason,
            source,
            risk,
        } => {
            let mut amended = false;
            if matches!(source, crate::evaluate::EvalSource::Llm)
                && deny_session_auto_amend_candidate(&binary, &args, risk).is_ok()
            {
                match amend_session_exact_rule(
                    config,
                    &token,
                    SessionAmendment::Deny,
                    binary.clone(),
                    args.clone(),
                )
                .await
                {
                    Ok(value) => amended = value,
                    Err(err) => {
                        return AdminResponse::Error {
                            message: format!("failed to persist appeal deny amendment: {err}"),
                        };
                    }
                }
            }
            let final_reason = if amended {
                format!("appeal denied; amended exact session deny. LLM reason: {reason}")
            } else {
                format!("appeal denied. LLM reason: {reason}")
            };
            record_live_session_interaction(
                config,
                Some(&token),
                SessionInteraction {
                    at_unix: 0,
                    command: command_line.clone(),
                    allowed: false,
                    source: session_source_from_eval(source),
                    reason: final_reason.clone(),
                    risk,
                    exec_status: SessionExecStatus::NotAttempted,
                },
            )
            .await;
            tracing::info!(
                "[AUDIT] SESSION_APPEAL caller={} token={} allowed=false amended={} cmd={}",
                caller,
                audit_token(&token),
                amended,
                redact_output(&command_line)
            );
            AdminResponse::SessionAppeal {
                allowed: false,
                amended,
                pattern: Some(command_line),
                reason: final_reason,
                risk,
            }
        }
        crate::evaluate::EvalResult::Error(err) => AdminResponse::SessionAppeal {
            allowed: false,
            amended: false,
            pattern: Some(command_line),
            reason: format!("appeal evaluation error: {err}"),
            risk: None,
        },
    }
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
            mut allow,
            mut deny,
            mut ttl_secs,
            prompt_append,
            prose,
            profile,
            static_only,
            auto_amend,
        } => {
            if token.is_empty() {
                return AdminResponse::Error {
                    message: "session token must not be empty".to_string(),
                };
            }
            // Expand a named operator profile into this grant before the usual
            // prose compilation. An unknown name fails loudly rather than
            // minting an empty (unrestricted) grant. The profile only seeds the
            // same fields an operator would type; the grant is installed on the
            // identical path below, so it is no separate trust boundary.
            let mut profile_prompt: Option<String> = None;
            if let Some(name) = profile.as_deref() {
                match config.profiles.get(name) {
                    Some(p) => {
                        merge_unique(&mut allow, p.allow.clone());
                        merge_unique(&mut deny, p.deny.clone());
                        ttl_secs = ttl_secs.or(p.ttl_secs);
                        profile_prompt = p.prompt_append.clone();
                    }
                    None => {
                        return AdminResponse::Error {
                            message: format!("unknown session profile: '{}'", name),
                        };
                    }
                }
            }
            let compiled = prose
                .as_deref()
                .map(compile_session_grant_rules)
                .unwrap_or_default();
            merge_unique(&mut allow, compiled.allow.clone());
            merge_unique(&mut deny, compiled.deny.clone());
            // Fold the profile's evaluator context in with any request/prose prompt.
            let base_prompt = match (prompt_append, profile_prompt) {
                (Some(request), Some(profile)) => Some(format!("{request}\n\n{profile}")),
                (some, None) | (None, some) => some,
            };
            let prompt_append = combine_session_prompt(base_prompt, prose.as_deref(), &compiled);
            let auto_amend = auto_amend && !static_only;
            let expires_at = ttl_secs.map(|secs| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
                    + secs
            });
            let mut generated_notes = compiled.notes.clone();
            if let Some(name) = profile.as_deref() {
                generated_notes.push(format!("session minted from profile '{name}'"));
            }
            let grant = SessionGrant {
                allow,
                deny,
                allow_exact: Vec::new(),
                deny_exact: Vec::new(),
                expires_at,
                prompt_append,
                generated_notes,
                static_only,
                auto_amend,
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
                "[AUDIT] SESSION_GRANT caller={} token={} profile={:?} ttl={:?} static_only={} auto_amend={} generated_allow={} generated_deny={}",
                caller,
                audit_token(&token),
                profile,
                ttl_secs,
                static_only,
                auto_amend,
                compiled.allow.len(),
                compiled.deny.len()
            );
            AdminResponse::Ok
        }
        AdminRequest::SessionAppeal {
            token,
            binary,
            args,
        } => handle_session_appeal(config, caller, token, binary, args).await,
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
                audit_token(&token),
                removed
            );
            AdminResponse::Ok
        }
        AdminRequest::SessionList {
            include_history,
            since_unix,
            visible_token,
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
            let is_admin = caller_is_session_admin(config, caller);
            let visible_token = visible_token.as_deref();
            let grants = reg
                .list()
                .into_iter()
                .map(|mut grant| {
                    let can_view =
                        caller_can_view_session(config, caller, &grant.token, visible_token);
                    redact_session_summary_for_list(&mut grant, is_admin, can_view);
                    grant
                })
                .collect();
            let history = if include_history {
                reg.list_history(since_unix)
                    .into_iter()
                    .map(|mut grant| {
                        let can_view =
                            caller_can_view_session(config, caller, &grant.token, visible_token);
                        redact_historical_grant_for_list(&mut grant, is_admin, can_view);
                        grant
                    })
                    .collect()
            } else {
                Vec::new()
            };
            AdminResponse::SessionList { grants, history }
        }
        AdminRequest::SessionShow {
            token,
            limit,
            caller_token,
        } => {
            {
                let mut reg = config.sessions.write().await;
                reg.purge_expired();
            }
            if let Err(err) = persist_current_sessions(config).await {
                tracing::warn!("failed to persist purged session state: {}", err);
            }
            let is_admin = caller_is_session_admin(config, caller);
            // A non-admin caller may inspect only the grant on its own token: the
            // token it presents as its identity ($GUARD_SESSION) must equal the
            // token it is asking about. That token is the same bearer credential
            // used for session auth, so equality is proof the caller holds it.
            // Merely naming another session's token is not enough -- that path
            // returns a denial, never the grant's contents.
            let is_self = !token.is_empty() && caller_token.as_deref() == Some(token.as_str());
            if !is_admin && !is_self {
                tracing::warn!(
                    "[AUDIT] SESSION_SHOW_REJECTED caller={} reason=\"not the token holder\"",
                    caller
                );
                return AdminResponse::Error {
                    message: "not authorized: a session token may only inspect its own grant"
                        .to_string(),
                };
            }
            let reg = config.sessions.read().await;
            match reg.show(&token, limit.unwrap_or(20)) {
                Some(mut report) => {
                    // A self-inspecting holder sees the full grant (rules, prompt,
                    // expiry) but never has its own raw bearer token echoed back.
                    if !is_admin {
                        mask_session_report_token(&mut report);
                    }
                    AdminResponse::SessionShow { report }
                }
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
            let principal = match caller.principal() {
                Some(principal) if caller.is_local_peer() => principal,
                _ => {
                    return AdminResponse::Error {
                        message: "secret ops require an authenticated local caller".to_string(),
                    };
                }
            };
            match config.secrets.set(&principal, &key, &value).await {
                Ok(()) => {
                    tracing::info!(
                        "[AUDIT] SECRET_SET caller={} principal={} key={}",
                        caller,
                        principal,
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
            let principal = match caller.principal() {
                Some(principal) if caller.is_local_peer() => principal,
                _ => {
                    return AdminResponse::Error {
                        message: "secret ops require an authenticated local caller".to_string(),
                    };
                }
            };
            match config.secrets.delete(&principal, &key).await {
                Ok(()) => {
                    tracing::info!(
                        "[AUDIT] SECRET_DELETE caller={} principal={} key={}",
                        caller,
                        principal,
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
            let principal = match caller.principal() {
                Some(principal) if caller.is_local_peer() => principal,
                _ => {
                    return AdminResponse::Error {
                        message: "secret ops require an authenticated local caller".to_string(),
                    };
                }
            };
            match config.secrets.get(&principal, &key).await {
                Ok(value) => AdminResponse::SecretExists {
                    exists: value.is_some(),
                },
                Err(e) => AdminResponse::Error {
                    message: format!("failed to inspect secret '{}': {}", key, e),
                },
            }
        }
        AdminRequest::SecretList => {
            let principal = match caller.principal() {
                Some(principal) if caller.is_local_peer() => principal,
                _ => {
                    return AdminResponse::Error {
                        message: "secret ops require an authenticated local caller".to_string(),
                    };
                }
            };
            if config.daemon_principal.eq_ci(&principal) {
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
                match config.secrets.list(&principal).await {
                    Ok(keys) => AdminResponse::SecretList { keys },
                    Err(e) => AdminResponse::Error {
                        message: format!("failed to list secrets: {}", e),
                    },
                }
            }
        }
        AdminRequest::SecretListDetailed => match config.secrets.list_all().await {
            Ok(pairs) => {
                let legacy = legacy_sentinel();
                let mut items: Vec<SecretDetail> = pairs
                    .into_iter()
                    .map(|(principal, key)| {
                        let is_legacy = principal.eq_ci(&legacy);
                        SecretDetail {
                            key,
                            // The display uid field is populated only for a pure
                            // uid principal; SID and legacy entries carry no uid.
                            uid: if is_legacy {
                                None
                            } else {
                                principal.as_str().parse::<u32>().ok()
                            },
                            principal: if is_legacy {
                                None
                            } else {
                                Some(principal.into_string())
                            },
                            legacy: is_legacy,
                        }
                    })
                    .collect();
                items.sort_by(|a, b| {
                    a.legacy
                        .cmp(&b.legacy)
                        .then_with(|| a.principal.cmp(&b.principal))
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
            let learned_rule_count = config.evaluator.learned_rule_count().await;
            let deny_shape_count = config.evaluator.deny_shape_count().await;
            let allow_promotion_observation_count =
                config.evaluator.allow_promotion_observation_count().await;
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
                    learning_enabled: config.evaluator.learning_enabled(),
                    learned_rule_count,
                    deny_learning_enabled: config.evaluator.deny_learning_enabled(),
                    deny_shape_count,
                    allow_promotion_enabled: config.evaluator.allow_promotion_enabled(),
                    allow_promotion_observation_count,
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
                    gate: config.gate.as_str().to_string(),
                    pending_provisionals: config.provisional.read().await.outstanding(),
                    pending_approvals: config.approvals.read().await.outstanding(),
                },
            }
        }
        AdminRequest::Confirm { handle } => handle_confirm(config, caller, &handle).await,
        AdminRequest::Revert { handle } => handle_manual_revert(config, caller, &handle).await,
        AdminRequest::Approve { handle } => handle_approve(config, caller, &handle).await,
        AdminRequest::Deny { handle } => handle_deny(config, caller, &handle).await,
        AdminRequest::Provisionals => {
            let (is_daemon, caller_key) = caller_scope(config, caller);
            let items = config
                .provisional
                .read()
                .await
                .list()
                .iter()
                .filter(|p| is_daemon || scope_eq(&p.principal, &caller_key))
                .map(ProvisionalSummary::from_row)
                .collect();
            AdminResponse::Provisionals { items }
        }
        AdminRequest::ApprovalList => {
            let (is_daemon, caller_key) = caller_scope(config, caller);
            let items = config
                .approvals
                .read()
                .await
                .list()
                .iter()
                .filter(|a| is_daemon || scope_eq(&a.snapshot.principal, &caller_key))
                .map(ApprovalSummary::from_row)
                .collect();
            AdminResponse::Approvals { items }
        }
        AdminRequest::ApprovalShow { handle } => {
            let (is_daemon, caller_key) = caller_scope(config, caller);
            let found = config.approvals.read().await.get(&handle).cloned();
            match found {
                // Handle is an unguessable bearer secret; the owner (or daemon)
                // may read its status and result. Others get NotFound, not a
                // leak of existence.
                Some(a) if is_daemon || scope_eq(&a.snapshot.principal, &caller_key) => {
                    AdminResponse::ApprovalShow {
                        item: ApprovalSummary::from_row(&a),
                    }
                }
                _ => AdminResponse::Error {
                    message: format!("no approval with handle '{}'", handle),
                },
            }
        }
        AdminRequest::ApprovalNote { handle, text } => {
            handle_approval_note(config, caller, &handle, &text).await
        }
        AdminRequest::VerbList => {
            let items = {
                let mut cat = config.verbs.write().await;
                if let Err(e) = cat.reload_if_stale() {
                    tracing::warn!("verb catalog reload failed: {}", e);
                }
                let current_stamp = config.evaluator.verb_promotion_stamp();
                cat.list()
                    .iter()
                    .map(|v| VerbSummary {
                        name: v.name.clone(),
                        description: v.description.clone(),
                        binary: v.binary.clone(),
                        consequence: v.consequence.as_str().to_string(),
                        trusted: verb_effective_trust(v, current_stamp),
                        has_revert: v.revert.is_some(),
                        params: v
                            .params
                            .iter()
                            .map(|(k, spec)| (k.clone(), spec.pattern.clone()))
                            .collect(),
                        auto_promoted: v.auto_promoted,
                        evidence: v.evidence.clone(),
                    })
                    .collect()
            };
            AdminResponse::Verbs { items }
        }
        AdminRequest::VerbCreate {
            prose,
            binary_hint,
            preview,
        } => {
            let prose_norm = normalize_ws(&prose);
            if prose_norm.is_empty() {
                return AdminResponse::Error {
                    message: "verb create requires non-empty --prompt prose".to_string(),
                };
            }
            let mut verb = match config
                .evaluator
                .synthesize_verb(&prose, binary_hint.as_deref())
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    return AdminResponse::Error {
                        message: format!("verb synthesis failed: {e}"),
                    }
                }
            };
            // Record provenance verbatim (tidied to one line); the model's
            // evidence is metadata only and never affects rendering.
            verb.source_prose = Some(prose_norm);
            if let Some(ev) = verb.evidence.take() {
                verb.evidence = Some(normalize_ws(&ev));
            }
            // The model chose this shape, so do not trust its safety-critical
            // fields: a synthesized verb is never `trusted` (the LLM still
            // evaluates the rendered command at run time), and the shape must
            // pass the synthesis safety gate (no shell/interpreter binary, no
            // over-broad parameter pattern, kebab-case name).
            verb.trusted = false;
            if let Err(e) = guard::gating::verb::validate_synthesized_safety(&verb) {
                return AdminResponse::Error {
                    message: format!("synthesized verb rejected by the safety gate: {e}"),
                };
            }
            let mut cat = config.verbs.write().await;
            let result = if preview {
                cat.validate_candidate(&verb)
            } else {
                cat.append_verb(&verb)
            };
            match result {
                Ok(()) => {
                    if !preview {
                        tracing::info!(
                            "[AUDIT] VERB_CREATED name={} consequence={} trusted={}",
                            verb.name,
                            verb.consequence.as_str(),
                            verb.trusted
                        );
                    }
                    AdminResponse::VerbCreated {
                        verb,
                        persisted: !preview,
                    }
                }
                Err(e) => AdminResponse::Error {
                    message: format!("synthesized verb rejected by validation: {e}"),
                },
            }
        }
    }
}

/// Collapse runs of whitespace (incl. newlines) to single spaces, so prose and
/// evidence persist as a tidy single line in the YAML catalog.
fn normalize_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Returns `(is_daemon, caller_principal)` for read-scoping. A caller is the
/// daemon (operator) when its principal equals the daemon's; row visibility is
/// then either daemon-wide or scoped to the caller's own principal via
/// `scope_eq` (so two unauthenticated `None` callers never share rows).
fn caller_scope(config: &ServerConfig, caller: &CallerIdentity) -> (bool, Option<PrincipalKey>) {
    let p = caller.principal();
    (
        matches!(p, Some(ref k) if config.daemon_principal.eq_ci(k)),
        p,
    )
}

async fn handle_confirm(
    config: &ServerConfig,
    caller: &CallerIdentity,
    handle: &str,
) -> AdminResponse {
    let updated = {
        let mut reg = config.provisional.write().await;
        reg.confirm(handle)
    };
    match updated {
        Ok(p) => {
            persist_provisional(config, &p).await;
            forget_proxy_provenance(config, handle);
            tracing::info!("[AUDIT] CONFIRM handle={} caller={}", handle, caller);
            AdminResponse::GateAction {
                message: format!("provisional {} confirmed; change kept", handle),
                exit_code: None,
                stdout: None,
                stderr: None,
            }
        }
        Err(e) => AdminResponse::Error {
            message: e.to_string(),
        },
    }
}

async fn handle_manual_revert(
    config: &ServerConfig,
    caller: &CallerIdentity,
    handle: &str,
) -> AdminResponse {
    let claimed = {
        let mut reg = config.provisional.write().await;
        reg.begin_revert(handle)
    };
    let p = match claimed {
        Ok(p) => p,
        Err(e) => {
            return AdminResponse::Error {
                message: e.to_string(),
            }
        }
    };
    persist_provisional(config, &p).await;
    let outcome = finish_revert(config, &p, caller, "manual").await;
    AdminResponse::GateAction {
        message: outcome.0,
        exit_code: outcome.1,
        stdout: None,
        stderr: None,
    }
}

/// Run a claimed (`Reverting`) provisional's revert and record the outcome.
/// Returns `(message, exit_code)`.
async fn finish_revert(
    config: &ServerConfig,
    p: &Provisional,
    caller: &CallerIdentity,
    kind: &str,
) -> (String, Option<i32>) {
    // Bound the revert so a hung rollback cannot pin the sweeper (which also
    // drives fail-closed hold expiry). A timeout is recorded as RevertFailed.
    let (status_ok, exit, detail) = match tokio::time::timeout(
        std::time::Duration::from_secs(REVERT_EXEC_TIMEOUT_SECS),
        run_provisional_revert(config, p),
    )
    .await
    {
        Ok(result) => match &result.exec {
            ExecOutcome::Completed { exit_code, .. } => {
                let ok = exit_code.unwrap_or(-1) == 0;
                (ok, *exit_code, None)
            }
            ExecOutcome::Failed { reason, .. } => (false, None, Some(reason.clone())),
            _ => (false, None, Some("unexpected revert outcome".to_string())),
        },
        Err(_) => (
            false,
            None,
            Some(format!(
                "revert timed out after {}s",
                REVERT_EXEC_TIMEOUT_SECS
            )),
        ),
    };
    let updated = {
        let mut reg = config.provisional.write().await;
        if status_ok {
            reg.set_reverted(&p.handle, exit);
        } else {
            reg.set_revert_failed(
                &p.handle,
                exit,
                detail
                    .clone()
                    .unwrap_or_else(|| format!("revert exited with code {:?}", exit)),
            );
        }
        reg.get(&p.handle).cloned()
    };
    if let Some(u) = &updated {
        persist_provisional(config, u).await;
    }
    // The create-revert is terminal (whether it succeeded or failed); drop any
    // kube-proxy provenance tied to it so it cannot outlive its window.
    forget_proxy_provenance(config, &p.handle);
    if status_ok {
        tracing::info!(
            "[AUDIT] REVERT handle={} caller={} kind={} exit={:?}",
            p.handle,
            caller,
            kind,
            exit
        );
        (
            format!("provisional {} reverted (exit {:?})", p.handle, exit),
            exit,
        )
    } else {
        tracing::error!(
            "[AUDIT] REVERT_FAILED handle={} caller={} kind={} exit={:?} detail={:?}",
            p.handle,
            caller,
            kind,
            exit,
            detail
        );
        (
            format!(
                "REVERT FAILED for provisional {} (exit {:?}); the change may still be in place: {}",
                p.handle,
                exit,
                detail.unwrap_or_default()
            ),
            exit,
        )
    }
}

async fn handle_approve(
    config: &ServerConfig,
    caller: &CallerIdentity,
    handle: &str,
) -> AdminResponse {
    let snapshot = {
        let mut reg = config.approvals.write().await;
        reg.begin_approve(handle)
    };
    let snapshot = match snapshot {
        Ok(s) => s,
        Err(e) => {
            return AdminResponse::Error {
                message: e.to_string(),
            }
        }
    };
    // A kube-proxy hold carries no executable snapshot: approving it releases
    // the API request parked in the proxy (the proxy waiter forwards it), it
    // never spawns a process. A caller cannot steer a real command into this
    // branch by naming the sentinel binary, because the row must also be owned
    // by the daemon principal, which peer credentials assign only to the
    // daemon's own gate sink.
    if snapshot.binary == KUBE_PROXY_SENTINEL_BINARY
        && matches!(&snapshot.principal, Some(p) if config.daemon_principal.eq_ci(p))
    {
        let now = now_unix();
        {
            let mut reg = config.approvals.write().await;
            reg.set_result(handle, now, None, None, None);
        }
        if let Some(a) = config.approvals.read().await.get(handle).cloned() {
            persist_approval(config, &a).await;
        }
        tracing::info!(
            "[AUDIT] APPROVED handle={} caller={} (kube-proxy request released)",
            handle,
            caller
        );
        return AdminResponse::GateAction {
            message: format!("approved held API request {handle}; the proxy is forwarding it"),
            exit_code: None,
            stdout: None,
            stderr: None,
        };
    }
    // Gate-on-prediction: if this hold came from a verb and the catalog changed
    // since it was held, the approved artifact may no longer mean what the
    // operator reviewed. Void the approval rather than execute a stale rendering.
    if let Some(vname) = &snapshot.verb_name {
        let current = config.verbs.read().await.version();
        if snapshot.catalog_version != Some(current) {
            let now = now_unix();
            let detail = format!(
                "verb catalog changed since '{}' was held; approval voided (re-issue the command)",
                vname
            );
            {
                let mut reg = config.approvals.write().await;
                reg.set_exec_failed(handle, now, detail.clone());
            }
            if let Some(a) = config.approvals.read().await.get(handle).cloned() {
                persist_approval(config, &a).await;
            }
            tracing::warn!(
                "[AUDIT] APPROVE_VOIDED handle={} caller={} {}",
                handle,
                caller,
                detail
            );
            return AdminResponse::Error { message: detail };
        }
    }
    // Persist the Approving transition before exec so an interrupted exec is
    // recoverable (startup recovery routes Approving -> ExecFailed).
    if let Some(a) = config.approvals.read().await.get(handle).cloned() {
        persist_approval(config, &a).await;
    }
    let reason = format!("operator-approved held command {}", handle);
    let result = execute_snapshot(config, &snapshot, &reason).await;
    let now = now_unix();
    let (message, exit, stdout, stderr) = match result.exec {
        ExecOutcome::Completed {
            exit_code,
            stdout,
            stderr,
        } => {
            {
                let mut reg = config.approvals.write().await;
                reg.set_result(handle, now, exit_code, stdout.clone(), stderr.clone());
            }
            tracing::info!(
                "[AUDIT] APPROVED handle={} caller={} exit={:?}",
                handle,
                caller,
                exit_code
            );
            (
                format!("approved and executed {} (exit {:?})", handle, exit_code),
                exit_code,
                stdout,
                stderr,
            )
        }
        ExecOutcome::Failed { reason: detail, .. } => {
            {
                let mut reg = config.approvals.write().await;
                reg.set_exec_failed(handle, now, detail.clone());
            }
            tracing::error!(
                "[AUDIT] APPROVE_EXEC_FAILED handle={} caller={} detail={}",
                handle,
                caller,
                detail
            );
            (
                format!("approved {} but execution failed: {}", handle, detail),
                None,
                None,
                None,
            )
        }
        _ => (
            format!("approved {} (unexpected outcome)", handle),
            None,
            None,
            None,
        ),
    };
    if let Some(a) = config.approvals.read().await.get(handle).cloned() {
        persist_approval(config, &a).await;
    }
    AdminResponse::GateAction {
        message,
        exit_code: exit,
        stdout,
        stderr,
    }
}

/// Append a note to a held command's discussion thread, turning the gate into a
/// short operator<->requester conversation before a decision. The operator may
/// note any hold; the hold's original requester (a local peer whose principal
/// matches the snapshot) may note its own; nobody else. Returns the updated hold
/// view (including the thread) so the caller can render it.
async fn handle_approval_note(
    config: &ServerConfig,
    caller: &CallerIdentity,
    handle: &str,
    text: &str,
) -> AdminResponse {
    let text = text.trim();
    if text.is_empty() {
        return AdminResponse::Error {
            message: "note text must not be empty".to_string(),
        };
    }
    let (is_operator, caller_key) = caller_scope(config, caller);
    let author = {
        let reg = config.approvals.read().await;
        match reg.get(handle) {
            Some(_) if is_operator => "operator",
            Some(a) if caller.is_local_peer() && scope_eq(&a.snapshot.principal, &caller_key) => {
                "requester"
            }
            // Unknown handle, or a caller who is neither operator nor owner:
            // return NotFound, never leaking the hold's existence.
            _ => {
                return AdminResponse::Error {
                    message: format!("no approval with handle '{}'", handle),
                };
            }
        }
    };
    let now = now_unix();
    let result = {
        let mut reg = config.approvals.write().await;
        reg.add_note(handle, author, text, now)
    };
    match result {
        Ok(()) => {
            let updated = config.approvals.read().await.get(handle).cloned();
            match updated {
                Some(a) => {
                    persist_approval(config, &a).await;
                    tracing::info!(
                        "[AUDIT] APPROVAL_NOTE handle={} author={} caller={}",
                        handle,
                        author,
                        caller
                    );
                    AdminResponse::ApprovalShow {
                        item: ApprovalSummary::from_row(&a),
                    }
                }
                None => AdminResponse::Error {
                    message: format!("no approval with handle '{}'", handle),
                },
            }
        }
        Err(e) => AdminResponse::Error {
            message: e.to_string(),
        },
    }
}

async fn handle_deny(
    config: &ServerConfig,
    caller: &CallerIdentity,
    handle: &str,
) -> AdminResponse {
    let now = now_unix();
    let result = {
        let mut reg = config.approvals.write().await;
        reg.deny(handle, now, "operator denied".to_string())
    };
    match result {
        Ok(()) => {
            if let Some(a) = config.approvals.read().await.get(handle).cloned() {
                persist_approval(config, &a).await;
            }
            tracing::info!("[AUDIT] DENIED_HOLD handle={} caller={}", handle, caller);
            AdminResponse::GateAction {
                message: format!("held command {} denied", handle),
                exit_code: None,
                stdout: None,
                stderr: None,
            }
        }
        Err(e) => AdminResponse::Error {
            message: e.to_string(),
        },
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
                    status: None,
                    handle: None,
                    coverage: None,
                };
                writer
                    .write_all(serde_json::to_string(&resp)?.as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                continue;
            }
        };

        let request = match incoming {
            IncomingMessage::Admin { admin, admin_token } => {
                let caller = if matches!(admin, AdminRequest::Ping) {
                    CallerIdentity::Tcp {
                        token: "<tcp>".to_string(),
                    }
                } else if let Err(e) = config.validate_admin_token(admin_token.as_deref()) {
                    let resp = AdminResponse::Error {
                        message: format!("admin RPC refused: {}", e),
                    };
                    writer
                        .write_all(serde_json::to_string(&resp)?.as_bytes())
                        .await?;
                    writer.write_all(b"\n").await?;
                    continue;
                } else {
                    CallerIdentity::TcpAdmin {
                        token: admin_token.unwrap_or_else(|| "<missing>".to_string()),
                    }
                };
                let resp = handle_admin_request(config, &caller, admin).await;
                writer
                    .write_all(serde_json::to_string(&resp)?.as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                continue;
            }
            IncomingMessage::Grant { grant } => {
                // Read grants apply a POSIX ACL for a kernel-verified local uid;
                // a bearer-token TCP caller carries no such identity, so it can
                // never be the grant principal. Refuse rather than guess.
                let reason = format!(
                    "read grants require a local Unix socket caller: '{}' cannot be requested over TCP",
                    grant.path()
                );
                let resp = ExecuteResponse {
                    allowed: false,
                    reason,
                    exit_code: None,
                    stdout: None,
                    stderr: None,
                    status: None,
                    handle: None,
                    coverage: None,
                };
                writer
                    .write_all(serde_json::to_string(&resp)?.as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                continue;
            }
            IncomingMessage::Execute(req) => *req,
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
                status: None,
                handle: None,
                coverage: None,
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
    /// Policy approved, but the child failed. `started` distinguishes a
    /// spawn/setup failure where the child never ran (e.g. ENOENT on the binary)
    /// from a failure after it was launched (e.g. the client stream dropped
    /// mid-run). A contained forward command that fails with `started: true` may
    /// already have applied its mutation, so the containment envelope keeps the
    /// auto-revert armed rather than dropping it.
    Failed { reason: String, started: bool },
    /// Policy approved, but the server intentionally did not spawn the child.
    /// Carries gate coverage when the dry-run was routed by the consequence gate.
    DryRun { coverage: Option<Coverage> },
    /// Approved and routed to the operator gate; not executed. Awaits approval.
    Held { handle: String, coverage: Coverage },
    /// Approved and executed inside a containment envelope; auto-revert armed.
    Provisional {
        handle: String,
        coverage: Coverage,
        exit_code: Option<i32>,
        stdout: Option<String>,
        stderr: Option<String>,
    },
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

    /// Convenience constructor for "policy approved but the child never ran"
    /// (a spawn/setup failure such as ENOENT on the binary).
    fn exec_failed(policy_reason: impl Into<String>, exec_reason: impl Into<String>) -> Self {
        Self {
            policy: PolicyOutcome::Allowed {
                reason: policy_reason.into(),
            },
            exec: ExecOutcome::Failed {
                reason: exec_reason.into(),
                started: false,
            },
        }
    }

    /// Constructor for "policy approved, the child WAS launched, then execution
    /// failed" (e.g. the client stream dropped mid-run). The child may have had
    /// observable effects, which the containment envelope must account for.
    fn exec_failed_after_start(
        policy_reason: impl Into<String>,
        exec_reason: impl Into<String>,
    ) -> Self {
        Self {
            policy: PolicyOutcome::Allowed {
                reason: policy_reason.into(),
            },
            exec: ExecOutcome::Failed {
                reason: exec_reason.into(),
                started: true,
            },
        }
    }

    fn dry_run(reason: impl Into<String>) -> Self {
        Self {
            policy: PolicyOutcome::Allowed {
                reason: reason.into(),
            },
            exec: ExecOutcome::DryRun { coverage: None },
        }
    }

    /// A consequence-gated dry-run: reports the gate decision and its coverage
    /// (what would be checked and what would not) without executing.
    fn dry_run_gated(reason: impl Into<String>, coverage: Coverage) -> Self {
        Self {
            policy: PolicyOutcome::Allowed {
                reason: reason.into(),
            },
            exec: ExecOutcome::DryRun {
                coverage: Some(coverage),
            },
        }
    }

    /// Approved but held for operator approval (irreversible / uncertain /
    /// high-risk). Not executed.
    fn held(reason: impl Into<String>, handle: String, coverage: Coverage) -> Self {
        Self {
            policy: PolicyOutcome::Allowed {
                reason: reason.into(),
            },
            exec: ExecOutcome::Held { handle, coverage },
        }
    }

    /// Approved and executed inside a containment envelope.
    fn provisional(
        reason: impl Into<String>,
        handle: String,
        coverage: Coverage,
        exit_code: Option<i32>,
        stdout: Option<String>,
        stderr: Option<String>,
    ) -> Self {
        Self {
            policy: PolicyOutcome::Allowed {
                reason: reason.into(),
            },
            exec: ExecOutcome::Provisional {
                handle,
                coverage,
                exit_code,
                stdout,
                stderr,
            },
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
        let policy_reason = match self.policy {
            PolicyOutcome::Allowed { reason } | PolicyOutcome::Denied { reason } => reason,
        };
        match self.exec {
            // Legacy arms keep status/handle/coverage = None so a gating-off
            // response is byte-identical to today's wire format.
            ExecOutcome::Completed {
                exit_code,
                stdout,
                stderr,
            } => ExecuteResponse {
                allowed: true,
                reason: policy_reason,
                exit_code,
                stdout,
                stderr,
                status: None,
                handle: None,
                coverage: None,
            },
            ExecOutcome::Failed {
                reason: exec_msg, ..
            } => ExecuteResponse {
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
                status: None,
                handle: None,
                coverage: None,
            },
            ExecOutcome::DryRun { coverage } => ExecuteResponse {
                allowed: true,
                reason: policy_reason,
                exit_code: Some(0),
                stdout: Some("[DRY-RUN] policy allowed; command was not executed\n".to_string()),
                stderr: None,
                // A gated dry-run carries its coverage and a DryRun status; a
                // plain dry-run stays byte-identical to the pre-gating wire.
                status: coverage.as_ref().map(|_| GateStatus::DryRun),
                handle: None,
                coverage,
            },
            ExecOutcome::NotAttempted => ExecuteResponse {
                allowed,
                reason: policy_reason,
                exit_code: None,
                stdout: None,
                stderr: None,
                status: None,
                handle: None,
                coverage: None,
            },
            ExecOutcome::Held { handle, coverage } => ExecuteResponse {
                // Approved but held: allowed=true (not a denial), no exit code.
                allowed: true,
                reason: policy_reason,
                exit_code: None,
                stdout: None,
                stderr: None,
                status: Some(GateStatus::Held),
                handle: Some(handle),
                coverage: Some(coverage),
            },
            ExecOutcome::Provisional {
                handle,
                coverage,
                exit_code,
                stdout,
                stderr,
            } => ExecuteResponse {
                allowed: true,
                reason: policy_reason,
                exit_code,
                stdout,
                stderr,
                status: Some(GateStatus::Provisional),
                handle: Some(handle),
                coverage: Some(coverage),
            },
        }
    }

    fn session_exec_status(&self) -> SessionExecStatus {
        match self.exec {
            ExecOutcome::Completed { .. } => SessionExecStatus::Completed,
            ExecOutcome::Failed { .. } => SessionExecStatus::Failed,
            ExecOutcome::DryRun { .. } => SessionExecStatus::DryRun,
            ExecOutcome::NotAttempted => SessionExecStatus::NotAttempted,
            ExecOutcome::Held { .. } => SessionExecStatus::Held,
            ExecOutcome::Provisional { .. } => SessionExecStatus::Provisional,
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
    mut request: ExecuteRequest,
    config: &ServerConfig,
    caller: &CallerIdentity,
    stream_output: bool,
    stream_writer: &mut W,
) -> ExecuteResult {
    let session_token = request.session_token.clone();

    // Resolve a verb invocation into a concrete command BEFORE any validation or
    // evaluation. The rendered binary/args then pass through the same checks as a
    // raw command; the verb's declared consequence class and rollback drive the
    // gate. Verbs are operator-authored, so the catalog is hot-reloaded by mtime.
    let mut verb_ctx: Option<VerbContext> = None;
    if let Some(invocation) = request.verb.clone() {
        if !config.gate.is_on() {
            let reason =
                "verbs require consequence gating (start the daemon with --gate consequence)"
                    .to_string();
            let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
            return ExecuteResult::denied(reason);
        }
        let rendered = {
            let mut cat = config.verbs.write().await;
            if let Err(e) = cat.reload_if_stale() {
                tracing::warn!("verb catalog reload failed, using previous: {}", e);
            }
            cat.render(&invocation.name, &invocation.params)
                .map(|r| (r, cat.version()))
        };
        match rendered {
            Ok((r, version)) => {
                let trusted = verb_trust_is_current(&r, config.evaluator.verb_promotion_stamp());
                request.binary = r.binary;
                request.args = r.args;
                request.revert = r.revert.map(|(binary, args)| RevertSpec { binary, args });
                verb_ctx = Some(VerbContext {
                    name: r.name,
                    class: r.consequence,
                    trusted,
                    params: r.params,
                    catalog_version: version,
                });
            }
            Err(e) => {
                let reason = format!("verb error: {}", e);
                config.log_audit_policy(caller, &invocation.name, &[], false, &reason);
                let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
                return ExecuteResult::denied(reason);
            }
        }
    } else if config.gate.is_on() {
        // No explicit `--verb` invocation, but a raw command may still match
        // a catalog verb's template (hand-authored or auto-promoted -- see
        // `gating::allow_promotion`). Reverse-matching lets a caller that
        // invokes a tool directly (`kubectl get pods -n foo`) pick up the
        // matching verb's declared consequence class and trust the same way
        // an explicit invocation would; the catalog is the transparent,
        // operator-inspectable/editable record either way. Gated on
        // `config.gate.is_on()` for the same reason the explicit path is:
        // without consequence gating there is no routing for a verb's class
        // to drive, so this stays a no-op and raw commands behave exactly as
        // before.
        let matched = {
            let mut cat = config.verbs.write().await;
            if let Err(e) = cat.reload_if_stale() {
                tracing::warn!("verb catalog reload failed, using previous: {}", e);
            }
            cat.match_command(&request.binary, &request.args)
                .map(|r| (r, cat.version()))
        };
        if let Some((r, version)) = matched {
            let trusted = verb_trust_is_current(&r, config.evaluator.verb_promotion_stamp());
            request.revert = r.revert.map(|(binary, args)| RevertSpec { binary, args });
            verb_ctx = Some(VerbContext {
                name: r.name,
                class: r.consequence,
                trusted,
                params: r.params,
                catalog_version: version,
            });
        }
    }

    // Fold the requested ssh host-key mode into the command now that the verb
    // (if any) has been rendered. From here on, request.args carries any
    // injected `-o` options, so the policy decision, the evaluator, the audit
    // record, and the spawned process all act on the same command.
    request.apply_ssh_hostkey_options();

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
    // caller cannot pass an absolute/relative path disguised as the "binary".
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
    let command_line = command_line(&request.binary, &request.args);

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
        let (decision, exists, static_only) = {
            let reg = config.sessions.read().await;
            let decision = reg.check(token, &request.binary, &request.args);
            (decision, reg.has(token), reg.static_only_for(token))
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
        if static_only {
            let reason = "session static-only: no matching session allow rule".to_string();
            config.log_audit_policy(caller, &request.binary, &request.args, false, &reason);
            let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
            record_live_session_interaction(
                config,
                session_token.as_deref(),
                SessionInteraction {
                    at_unix: 0,
                    command: command_line.clone(),
                    allowed: false,
                    source: SessionDecisionSource::SessionStaticOnly,
                    reason: reason.clone(),
                    risk: None,
                    exec_status: SessionExecStatus::NotAttempted,
                },
            )
            .await;
            return ExecuteResult::denied(reason);
        }
    }

    // Server-wide binary allow-list: a hard floor enforced before evaluation on
    // every execution route, so a disallowed binary never reaches the LLM or an
    // operator hold. Independent of --preflight.
    if !binary_allowed(&config.allowed_binaries, &request.binary) {
        let reason = format!(
            "binary '{}' is not in the server allow-list",
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

    // Deterministic pre-LLM fast allow for a fixed set of trivially safe
    // read-only commands. Like a trusted verb, it is a deterministic allow
    // that precedes the evaluator; it never applies when the caller injected
    // env/secrets (which could change the command's meaning) and is disabled
    // in paranoid mode. `accept-all` host-key mode is excluded explicitly:
    // its injected `StrictHostKeyChecking=no` already fails the ssh option
    // allow-list, but keeping the guard here documents that giving up host
    // authentication never rides the fast path even if the diagnostic is fixed.
    if request.env.is_empty()
        && request.secrets.is_empty()
        && !matches!(request.ssh_hostkey, Some(SshHostKeyMode::AcceptAll))
    {
        if let Some(reason) =
            deterministic_safe_allow_reason(config, &request.binary, &request.args)
        {
            config.log_audit_policy(caller, &request.binary, &request.args, true, &reason);
            if let Err(e) = write_policy_decision(stream_output, stream_writer, true, &reason).await
            {
                return ExecuteResult::exec_failed_after_start(
                    reason,
                    format!("client stream error: {}", e),
                );
            }
            let inputs = GateInputs {
                reason: reason.clone(),
                risk: Some(0),
                reversibility: None,
                revert_preauthorized: false,
                verb: None,
                bypass: true,
            };
            let result = route_gated_allow(
                request,
                config,
                caller,
                inputs,
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
                    source: SessionDecisionSource::StaticPolicy,
                    reason,
                    risk: Some(0),
                    exec_status: result.session_exec_status(),
                },
            )
            .await;
            return result;
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

    // Trusted verb: an operator-reviewed shape skips the LLM evaluator (a
    // deterministic allow path, like a static-policy allow). The verb's declared
    // reversibility class drives the gate and its revert is pre-authorized.
    if let Some(vc) = verb_ctx.clone() {
        if vc.trusted {
            let reason = format!("trusted verb '{}'", vc.name);
            config.log_audit_policy(caller, &request.binary, &request.args, true, &reason);
            if let Err(e) = write_policy_decision(stream_output, stream_writer, true, &reason).await
            {
                return ExecuteResult::exec_failed_after_start(
                    reason,
                    format!("client stream error: {}", e),
                );
            }
            let inputs = GateInputs {
                reason: reason.clone(),
                risk: Some(0),
                reversibility: Some(vc.class),
                revert_preauthorized: true,
                verb: Some(vc),
                bypass: false,
            };
            let result = route_gated_allow(
                request,
                config,
                caller,
                inputs,
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
                    source: SessionDecisionSource::StaticPolicy,
                    reason,
                    risk: Some(0),
                    exec_status: result.session_exec_status(),
                },
            )
            .await;
            return result;
        }
    }

    let eval_result = config
        .evaluator
        .evaluate_with_reevaluate(&command_line, session_prompt.as_deref(), request.reevaluate)
        .await;

    match eval_result {
        crate::evaluate::EvalResult::Deny {
            reason,
            source,
            risk,
        } => {
            let mut reason = reason;
            if matches!(source, crate::evaluate::EvalSource::Llm) {
                if let Some(notice) = maybe_auto_amend_session_after_llm(
                    config,
                    session_token.as_deref(),
                    SessionAmendment::Deny,
                    &request.binary,
                    &request.args,
                    risk,
                )
                .await
                {
                    reason = format!("{reason} {notice}");
                }
                maybe_promote_deny_shape(
                    config,
                    &request.binary,
                    &request.args,
                    &command_line,
                    &reason,
                )
                .await;
            }
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
            reversibility,
        } => {
            let mut reason = reason;
            if matches!(source, crate::evaluate::EvalSource::Llm)
                && session_prompt
                    .as_deref()
                    .map(|prompt| prompt.trim().is_empty())
                    .unwrap_or(true)
                && session_token.is_none()
            {
                match config
                    .evaluator
                    .record_learned_approval(
                        &request.binary,
                        &request.args,
                        &command_line,
                        risk,
                        &reason,
                    )
                    .await
                {
                    Ok(Some(outcome)) => {
                        if let Some(notice) = learning_notice(config, &outcome).await {
                            reason = format!("{reason} {notice}");
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        tracing::warn!("failed to record learned rule candidate: {}", err);
                    }
                }
                maybe_promote_allow_verb(
                    config,
                    &request.binary,
                    &request.args,
                    &command_line,
                    risk,
                    reversibility,
                    &reason,
                )
                .await;
            }
            if matches!(source, crate::evaluate::EvalSource::Llm) {
                if let Some(notice) = maybe_auto_amend_session_after_llm(
                    config,
                    session_token.as_deref(),
                    SessionAmendment::Allow,
                    &request.binary,
                    &request.args,
                    risk,
                )
                .await
                {
                    reason = format!("{reason} {notice}");
                }
            }
            tracing::debug!("command allowed: {}", reason);
            config.log_audit_policy(caller, &request.binary, &request.args, true, &reason);
            if let Err(e) = write_policy_decision(stream_output, stream_writer, true, &reason).await
            {
                return ExecuteResult::exec_failed_after_start(
                    reason,
                    format!("client stream error: {}", e),
                );
            }
            // Consequence gate: when enabled, route this LLM-approved command by
            // reversibility (execute / contain / hold). When off, this is a
            // straight exec, byte-identical to before. Operator-authored allows
            // (session-allow above, static-policy) deliberately bypass the gate.
            // A verb's declared class overrides the model's, and a verb's revert
            // is pre-authorized (operator-reviewed); a free-form --revert is not.
            let effective_class = verb_ctx.as_ref().map(|v| v.class).or(reversibility);
            // A static-policy allow (operator-authored, deterministic) bypasses
            // the gate. A verb invocation never bypasses — its declared class
            // routes it. The LLM path is gated.
            let bypass =
                matches!(source, crate::evaluate::EvalSource::StaticPolicy) && verb_ctx.is_none();
            let inputs = GateInputs {
                reason: reason.clone(),
                risk,
                reversibility: effective_class,
                revert_preauthorized: verb_ctx.is_some(),
                verb: verb_ctx.clone(),
                bypass,
            };
            let result = route_gated_allow(
                request,
                config,
                caller,
                inputs,
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
        crate::evaluate::EvalSource::Cache => SessionDecisionSource::Cache,
        crate::evaluate::EvalSource::StaticPolicy => SessionDecisionSource::StaticPolicy,
        crate::evaluate::EvalSource::LearnedDeny => SessionDecisionSource::LearnedDeny,
    }
}

fn command_line(binary: &str, args: &[String]) -> String {
    if args.is_empty() {
        binary.to_string()
    } else {
        format!("{} {}", binary, args.join(" "))
    }
}

/// Render a command line for an audit log entry with secret-shaped values
/// masked. Argv routinely carries inline credentials (`--password=...`,
/// `Authorization: Bearer <token>`, connection URLs); the audit trail needs
/// the command shape, not the values, and the daemon log must not become a
/// secret store.
fn audit_command_line(binary: &str, args: &[String]) -> String {
    redact_output(&command_line(binary, args))
}

/// Truncate a token for an audit log entry. Tokens are bearer capabilities;
/// the log needs enough of one to correlate events against
/// `guard session list`, not the full value. Char-based slicing: the value is
/// caller-supplied, so byte indexing could split a UTF-8 sequence and panic.
fn audit_token(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    if chars.len() > 8 {
        let head: String = chars[..4].iter().collect();
        let tail: String = chars[chars.len() - 4..].iter().collect();
        format!("{head}...{tail}")
    } else {
        "***".to_string()
    }
}

fn validate_session_exact_rule_candidate(
    binary: &str,
    args: &[String],
) -> std::result::Result<(), String> {
    if binary.is_empty()
        || binary.contains('\0')
        || binary.contains(char::is_whitespace)
        || binary.contains('"')
        || binary.contains('\'')
    {
        return Err("appeal command has an invalid binary name".to_string());
    }
    if args.len() > SESSION_EXACT_RULE_MAX_ARGS {
        return Err(format!(
            "appeal command has too many arguments for a durable exact rule (max {})",
            SESSION_EXACT_RULE_MAX_ARGS
        ));
    }
    for arg in args {
        if arg.len() > SESSION_EXACT_RULE_MAX_ARG_LEN {
            return Err(format!(
                "appeal argument is too long for a durable exact rule (max {} bytes)",
                SESSION_EXACT_RULE_MAX_ARG_LEN
            ));
        }
        if arg.contains('\0') || arg.contains('\n') || arg.contains('\r') {
            return Err("appeal command contains control characters".to_string());
        }
    }
    Ok(())
}

fn allow_session_auto_amend_candidate(
    binary: &str,
    args: &[String],
    risk: Option<i32>,
) -> std::result::Result<(), String> {
    validate_session_exact_rule_candidate(binary, args)?;
    let risk = risk.unwrap_or(5);
    if risk > SESSION_AUTO_AMEND_MAX_ALLOW_RISK {
        return Err(format!(
            "risk {risk} exceeds auto-amend allow threshold {}",
            SESSION_AUTO_AMEND_MAX_ALLOW_RISK
        ));
    }
    if let Some(reason) = deterministic_credential_deny_reason(binary, args) {
        return Err(reason);
    }
    let command = command_line(binary, args);
    if crate::grant_rules::looks_dangerous_static_command(&command) {
        return Err("command contains shell control or sensitive material".to_string());
    }
    Ok(())
}

fn deny_session_auto_amend_candidate(
    binary: &str,
    args: &[String],
    risk: Option<i32>,
) -> std::result::Result<(), String> {
    validate_session_exact_rule_candidate(binary, args)?;
    let risk = risk.unwrap_or(5);
    if risk < SESSION_AUTO_AMEND_MIN_DENY_RISK {
        return Err(format!(
            "risk {risk} is below auto-amend deny threshold {}",
            SESSION_AUTO_AMEND_MIN_DENY_RISK
        ));
    }
    if deterministic_credential_deny_reason(binary, args).is_some() {
        return Err("command may contain or expose credential material".to_string());
    }
    Ok(())
}

async fn amend_session_exact_rule(
    config: &ServerConfig,
    token: &str,
    decision: SessionAmendment,
    binary: String,
    args: Vec<String>,
) -> Result<bool> {
    let (amended, before, after) = {
        let mut reg = config.sessions.write().await;
        let before = reg.clone();
        let amended = reg
            .amend_exact(token, decision, binary, args)
            .ok_or_else(|| anyhow::anyhow!("session token is revoked, expired, or unknown"))?;
        (amended, before, reg.clone())
    };
    if let Err(err) = persist_session_snapshot(config.session_store.clone(), after).await {
        *config.sessions.write().await = before;
        return Err(err);
    }
    Ok(amended)
}

async fn maybe_auto_amend_session_after_llm(
    config: &ServerConfig,
    token: Option<&str>,
    decision: SessionAmendment,
    binary: &str,
    args: &[String],
    risk: Option<i32>,
) -> Option<String> {
    let token = token?;
    let enabled = {
        let reg = config.sessions.read().await;
        reg.auto_amend_for(token)
    };
    if !enabled {
        return None;
    }

    let candidate = match decision {
        SessionAmendment::Allow => allow_session_auto_amend_candidate(binary, args, risk),
        SessionAmendment::Deny => deny_session_auto_amend_candidate(binary, args, risk),
    };
    if let Err(reason) = candidate {
        return Some(format!("Session auto-amend skipped: {reason}."));
    }

    match amend_session_exact_rule(config, token, decision, binary.to_string(), args.to_vec()).await
    {
        Ok(true) => {
            let rule = command_line(binary, args);
            match decision {
                SessionAmendment::Allow => {
                    Some(format!("Session auto-amended exact allow `{rule}`."))
                }
                SessionAmendment::Deny => {
                    Some(format!("Session auto-amended exact deny `{rule}`."))
                }
            }
        }
        Ok(false) => None,
        Err(err) => Some(format!("Session auto-amend failed: {err}.")),
    }
}

/// Record one fresh LLM denial against the auto-learned deny-shape store
/// (`gating::deny_shape`). This is the only orchestration step for deny-shape
/// auto-learning: no operator action is needed because the store can only
/// ever hold shapes the LLM already denied. `record_learned_denial` is a fast
/// local bookkeeping write, awaited inline; if the bucket just crossed its
/// synthesis threshold, the actual promotion (a real LLM round trip) is
/// spawned as a detached background task so it never adds latency to this
/// (already-decided) denied request's response. Failures are logged, not
/// surfaced to the caller.
async fn maybe_promote_deny_shape(
    config: &ServerConfig,
    binary: &str,
    args: &[String],
    command_line: &str,
    reason: &str,
) {
    let outcome = match config
        .evaluator
        .record_learned_denial(binary, args, command_line, reason)
        .await
    {
        Ok(Some(outcome)) => outcome,
        Ok(None) => return,
        Err(err) => {
            tracing::warn!("failed to record deny-shape observation: {}", err);
            return;
        }
    };
    if !outcome.ready_to_synthesize {
        return;
    }
    let evaluator = config.evaluator.clone();
    tokio::spawn(async move {
        match evaluator.try_promote_deny_shape(&outcome).await {
            Ok(true) => {
                tracing::info!(
                    "[AUDIT] DENY_SHAPE_LEARNED service={} binary={} denials={}",
                    outcome.service,
                    outcome.binary,
                    outcome.denials
                );
            }
            Ok(false) => {
                tracing::debug!(
                    "deny-shape synthesis for {} declined or not confident yet",
                    outcome.binary
                );
            }
            Err(err) => {
                tracing::warn!("deny-shape promotion failed: {}", err);
            }
        }
    });
}

/// Record one fresh LLM approval against the auto-verb-promotion observation
/// store (`gating::allow_promotion`), and, once a bucket is ready, spawn a
/// detached background task that confirms and appends a trusted verb to the
/// catalog. Mirrors `maybe_promote_deny_shape`'s split between a fast inline
/// bookkeeping write and a backgrounded LLM round trip, with one difference:
/// on success this also appends to `config.verbs`, since a promoted verb (an
/// allow) has to land somewhere the daemon actually consults, unlike a deny
/// shape, which lives entirely inside the evaluator. There is deliberately no
/// operator notification anywhere in this path -- see the `gating::allow_promotion`
/// module docs for why an allow-side auto-promotion is designed to need none:
/// the promoted-or-not state is fully recoverable from `guard verb list` at
/// any time, so there is nothing time-sensitive for a human to be paged about.
#[allow(clippy::too_many_arguments)]
async fn maybe_promote_allow_verb(
    config: &ServerConfig,
    binary: &str,
    args: &[String],
    command_line: &str,
    risk: Option<i32>,
    reversibility: Option<Reversibility>,
    reason: &str,
) {
    let outcome = match config
        .evaluator
        .record_learned_approval_for_promotion(
            binary,
            args,
            command_line,
            risk,
            reversibility,
            reason,
        )
        .await
    {
        Ok(Some(outcome)) => outcome,
        Ok(None) => return,
        Err(err) => {
            tracing::warn!("failed to record allow-promotion observation: {}", err);
            return;
        }
    };
    if !outcome.ready_to_synthesize {
        return;
    }
    let evaluator = config.evaluator.clone();
    let verbs = config.verbs.clone();
    tokio::spawn(async move {
        // `Ok(None)` here means "not confident yet" or a transient LLM
        // failure -- both should keep retrying as more evidence accumulates,
        // so the bucket is left as-is. Both `Ok(Some(verb))` (whether the
        // subsequent `append_verb` succeeds or fails) and `Err` are
        // definitive verdicts for this evidence and mark the bucket resolved
        // so it never retries the same doomed-to-repeat outcome (an
        // unbounded silent retry loop, e.g. on a deterministic catalog name
        // collision, or an unbounded stream of near-duplicate verbs from a
        // long-lived shape that keeps re-promoting under a fresh model-chosen
        // name every `min_approvals` multiple).
        let verb = match evaluator.try_confirm_verb_promotion(&outcome).await {
            Ok(Some(verb)) => verb,
            Ok(None) => {
                tracing::debug!(
                    "verb promotion for {} {} declined or not confident yet",
                    outcome.binary,
                    outcome.subcommand
                );
                return;
            }
            Err(err) => {
                tracing::warn!("verb-promotion confirmation failed: {}", err);
                if let Err(mark_err) = evaluator.mark_allow_promotion_resolved(&outcome).await {
                    tracing::warn!(
                        "failed to mark allow-promotion bucket resolved: {}",
                        mark_err
                    );
                }
                return;
            }
        };
        let mut cat = verbs.write().await;
        match cat.append_verb(&verb) {
            Ok(()) => {
                tracing::info!(
                    "[AUDIT] VERB_AUTO_PROMOTED name={} binary={} consequence={} approvals={}",
                    verb.name,
                    verb.binary,
                    verb.consequence.as_str(),
                    outcome.approvals
                );
            }
            Err(err) => {
                tracing::warn!(
                    "failed to append auto-promoted verb '{}' to the catalog: {}",
                    verb.name,
                    err
                );
            }
        }
        drop(cat);
        if let Err(err) = evaluator.mark_allow_promotion_resolved(&outcome).await {
            tracing::warn!("failed to mark allow-promotion bucket resolved: {}", err);
        }
    });
}

async fn learning_notice(config: &ServerConfig, outcome: &LearningOutcome) -> Option<String> {
    let mut notice = if outcome.is_candidate {
        format!(
            "Learned-rule candidate `{}` for `{}` reached {} approvals. This does NOT skip the \
             LLM by itself; an operator can promote it with: guard verb create --prompt \
             \"allow exactly: {}\" --binary {}.",
            outcome.pattern, outcome.service, outcome.approvals, outcome.pattern, outcome.service
        )
    } else if let Some(reason) = &outcome.skipped_reason {
        format!("Learned-rule skip: {reason}.")
    } else {
        format!(
            "Learned-rule candidate `{}` for `{}` ({}/{} approvals).",
            outcome.pattern, outcome.service, outcome.approvals, outcome.required_approvals
        )
    };

    let Some(shim) = &outcome.shim else {
        return Some(notice);
    };
    let mode = config
        .evaluator
        .learned_auto_shim_mode()
        .await
        .unwrap_or(AutoShimMode::Off);

    match mode {
        AutoShimMode::Off => {}
        AutoShimMode::Suggest => {
            notice.push_str(&format!(
                " Shim hint: `{}` wraps `{}`.",
                shim.name,
                shim.render_command()
            ));
        }
        AutoShimMode::Create if outcome.is_candidate => {
            let Some(ref shim_dir) = config.shim_dir else {
                notice.push_str(&format!(
                    " Shim `{}` could be created after configuring a shim directory.",
                    shim.name
                ));
                return Some(notice);
            };
            match std::env::current_exe()
                .map_err(anyhow::Error::from)
                .and_then(|guard_bin| {
                    ShimGenerator::new(guard_bin, shim_dir.clone()).generate_alias(
                        &shim.name,
                        &shim.target_binary,
                        &shim.target_args,
                    )
                }) {
                Ok(path) => {
                    notice.push_str(&format!(
                        " Created shim `{}` at {}.",
                        shim.name,
                        path.display()
                    ));
                }
                Err(err) => {
                    tracing::warn!("failed to create learned shim {}: {}", shim.name, err);
                    notice.push_str(&format!(
                        " Shim hint: `{}` wraps `{}`.",
                        shim.name,
                        shim.render_command()
                    ));
                }
            }
        }
        AutoShimMode::Create => {
            notice.push_str(&format!(
                " Shim `{}` will be created once this candidate reaches {} approvals.",
                shim.name, outcome.required_approvals
            ));
        }
    }

    Some(notice)
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
    #[cfg(unix)]
    uid: u32,
    #[cfg(unix)]
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

#[cfg(not(unix))]
fn apply_exec_identity(
    _cmd: &mut Command,
    config: &ServerConfig,
    _caller: &CallerIdentity,
) -> Result<Option<ExecCallerContext>> {
    if config.exec_as_caller {
        bail!("--exec-as-caller is not supported on this platform");
    }
    Ok(None)
}

/// Strip inherited capabilities from a brokered child before `execve`.
///
/// Under the packaged unit the daemon holds `CAP_FOWNER` and
/// `CAP_DAC_READ_SEARCH` in its ambient set so its own `grant-read` `setfacl`/
/// `getfacl` calls can manipulate ACLs on files it does not own. Ambient
/// capabilities are, by design, preserved across `execve()` for a non-privileged
/// process, so without this every caller-requested command (a plain
/// `cat /etc/shadow`, an `ansible-playbook` reading arbitrary files) would
/// inherit those capabilities and bypass file DAC entirely -- `CAP_DAC_READ_SEARCH`
/// bypasses file read permission checks and `CAP_FOWNER` bypasses the file-owner
/// checks `chmod`/`setfacl` enforce -- defeating the scoped, policy-gated read
/// grants. This clears the ambient set (so nothing survives `execve`) and zeroes
/// the inheritable set (so a target binary carrying its own file-inheritable caps
/// cannot pick anything up via the `P(inh) & F(inh)` intersection).
///
/// Applies only inside the forked child via `pre_exec`; the long-lived daemon
/// keeps its capabilities for its own direct `setfacl`/`getfacl` `Command`s,
/// which are separate and never pass through here. Clearing capabilities needs
/// no privilege (only raising them does), so it is safe under both the default
/// service-identity model and `--exec-as-caller`.
///
/// The capget/capset structs and version magic are declared here because the
/// `libc` crate does not expose `capget`/`capset` or the `cap_user_*` types; the
/// calls go through `libc::syscall` with the stable `SYS_capget`/`SYS_capset`
/// numbers.
#[cfg(all(unix, target_os = "linux"))]
#[repr(C)]
struct CapUserHeader {
    version: u32,
    pid: libc::c_int,
}

#[cfg(all(unix, target_os = "linux"))]
#[repr(C)]
#[derive(Clone, Copy)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// `_LINUX_CAPABILITY_VERSION_3` from `<linux/capability.h>` (64-bit caps).
#[cfg(all(unix, target_os = "linux"))]
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[cfg(unix)]
fn drop_brokered_child_capabilities(cmd: &mut Command) {
    // SAFETY: the closure runs in the forked child after `fork()` and before
    // `execve`. It calls only async-signal-safe raw syscalls (prctl/capget/
    // capset) and performs no allocation.
    unsafe {
        cmd.pre_exec(|| {
            #[cfg(target_os = "linux")]
            {
                // 1. Clear the ambient set: these are the capabilities that would
                //    otherwise be preserved across `execve` for a non-privileged
                //    process.
                if libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                ) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                // 2. Zero the inheritable set. Reading the current sets first and
                //    only clearing `inheritable` leaves `permitted`/`effective`
                //    untouched (they collapse to the ambient set at `execve`
                //    anyway for a non-privileged target). Dropping bits is always
                //    permitted; only raising them requires CAP_SETPCAP.
                let mut header = CapUserHeader {
                    version: LINUX_CAPABILITY_VERSION_3,
                    pid: 0,
                };
                let mut data = [CapUserData {
                    effective: 0,
                    permitted: 0,
                    inheritable: 0,
                }; 2];
                if libc::syscall(
                    libc::SYS_capget,
                    &mut header as *mut CapUserHeader,
                    data.as_mut_ptr(),
                ) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                data[0].inheritable = 0;
                data[1].inheritable = 0;
                if libc::syscall(
                    libc::SYS_capset,
                    &header as *const CapUserHeader,
                    data.as_ptr(),
                ) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
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
        // Under gating, even the execute-now (reversible) path reports honest
        // coverage; off-gate keeps the legacy byte-identical dry-run.
        return if config.gate.is_on() {
            ExecuteResult::dry_run_gated(allow_reason, Coverage::dry_run())
        } else {
            ExecuteResult::dry_run(allow_reason)
        };
    }

    let user_key = caller.user_key();
    let caller_principal = caller.principal();
    let tool_env = {
        let mut reg = config.tool_registry.write().await;
        let _ = reg.reload_if_stale();
        reg.resolve_env(
            &request.binary,
            &config.secrets,
            caller_principal.as_ref(),
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

    // Per-run --env injection is honored for any authenticated local caller
    // (a Unix uid OR a Windows SID), but never for an unauthenticated/TCP
    // caller, which has no trusted local identity. The daemon sets the child
    // environment at spawn; the agent is a different process and cannot read
    // the child's environment, so this does not leak across callers.
    if !request.env.is_empty() && !caller.is_local_peer() {
        return ExecuteResult::exec_failed(
            allow_reason,
            "per-run --env injection requires an authenticated local caller".to_string(),
        );
    }
    for (key, value) in &request.env {
        tool_env.insert(key.clone(), value.clone());
    }

    // Per-run --secret injection is honored for any authenticated local caller
    // (Unix uid OR Windows SID); secrets are resolved from that caller's own
    // namespace via its principal. Required only when the request asks for
    // secrets; a request with none proceeds on any transport. An
    // unauthenticated/TCP caller has no principal and is refused.
    if !request.secrets.is_empty() {
        let principal = match caller.principal() {
            Some(principal) if caller.is_local_peer() => principal,
            _ => {
                return ExecuteResult::exec_failed(
                    allow_reason,
                    "secret injection requires an authenticated local caller".to_string(),
                );
            }
        };
        for (env_var, secret_key) in &request.secrets {
            let value = match config.secrets.get(&principal, secret_key).await {
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

    for var in child_env_allowlist() {
        if let Ok(val) = std::env::var(var) {
            cmd.env(var, val);
        }
    }

    // Operator-declared passthroughs (GUARD_CHILD_ENV): forward these daemon
    // env vars to the child so brokered credentials reach a tool generically.
    // The value comes from the DAEMON's environment (not the caller), so an
    // agent cannot introduce one here; e.g. KUBECONFIG points kubectl at a config
    // only the daemon can read.
    for var in &config.extra_child_env {
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

    // Drop the daemon's grant-read capabilities (CAP_FOWNER / CAP_DAC_READ_SEARCH)
    // from the brokered child so they never survive execve into a caller-requested
    // command. Applies to both the default and --exec-as-caller models.
    #[cfg(unix)]
    drop_brokered_child_capabilities(&mut cmd);

    for (key, value) in &tool_env {
        cmd.env(key, value);
    }

    if let Some(context) = &exec_caller {
        cmd.env("HOME", &context.home_dir);
        cmd.env("USER", &context.username);
        cmd.env("LOGNAME", &context.username);
        cmd.env_remove("SSH_AUTH_SOCK");
        cmd.env_remove("XDG_RUNTIME_DIR");
        #[cfg(unix)]
        {
            let runtime_dir = PathBuf::from(format!("/run/user/{}", context.uid));
            if runtime_dir.exists() {
                cmd.env("XDG_RUNTIME_DIR", runtime_dir);
            }
        }
    }

    cmd.env("GUARD_DEPTH", (depth + 1).to_string());

    // Nested-eval shims are a Unix construct; on Windows, prepending a shim dir
    // only widens CreateProcess's bare-name search path with no benefit, so it is
    // skipped there.
    #[cfg(unix)]
    if let Some(ref shim_dir) = config.shim_dir {
        if let Some(path) = path_with_shim_dir(shim_dir) {
            cmd.env("PATH", path);
        }
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

// ===========================================================================
// Consequence gating: routing of LLM-approved commands by reversibility.
// ===========================================================================

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Mint an unguessable handle for a provisional/approval, using the same
/// entropy source as session tokens (128 bits hex).
fn new_handle() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Rebuild a caller identity from a stored row owner so deferred execution
/// (sweeper revert, operator approve) runs under the original caller's identity
/// rather than silently as the daemon. On Unix a principal whose key parses as a
/// decimal uid reconstructs `Unix { uid }` (round-tripping the legacy uid
/// identity exactly); on Windows the key is the caller's SID, so it reconstructs
/// `Windows { sid }`. A `None` owner (or an unparseable Unix key) means the
/// daemon executes as its own identity (non-exec-as-caller deployments).
fn reconstruct_caller(
    principal: Option<PrincipalKey>,
    fallback: &CallerIdentity,
) -> CallerIdentity {
    match principal {
        Some(key) => {
            #[cfg(windows)]
            {
                CallerIdentity::Windows {
                    sid: key.into_string(),
                }
            }
            #[cfg(not(windows))]
            {
                match key.as_str().parse::<u32>() {
                    Ok(uid) => CallerIdentity::Unix { uid },
                    Err(_) => fallback.clone(),
                }
            }
        }
        None => fallback.clone(),
    }
}

/// Reject a binary name that is a path, traversal, or contains shell-metachar
/// noise — the same invariants `execute_command_inner` enforces for the primary
/// binary, applied to a revert command before it is armed.
/// Normalize a binary reference to the match key used by the allow-list: its
/// file name with any directory stripped, a trailing `.exe`/`.EXE` removed, and
/// lowercased. Lowercasing keeps the operator's list case-insensitive (Windows
/// paths are case-insensitive; tool names are conventionally lowercase).
fn binary_match_key(binary: &str) -> String {
    let name = std::path::Path::new(binary)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(binary);
    let name = name
        .strip_suffix(".exe")
        .or_else(|| name.strip_suffix(".EXE"))
        .unwrap_or(name);
    name.to_ascii_lowercase()
}

/// Whether `binary` is permitted by the optional allow-list. `None` means no
/// restriction. A bare command name (no path separator) matches an allow-list
/// entry by match key — the common case, where the daemon's trusted PATH
/// resolves the name. A path-qualified binary bypasses PATH resolution, so it is
/// permitted ONLY by an exact allow-list entry; this stops a payload placed at
/// an arbitrary path and named after an allowed tool (e.g. `/tmp/x/kubectl`)
/// from slipping through basename matching.
fn binary_allowed(allowed: &Option<Vec<String>>, binary: &str) -> bool {
    let Some(list) = allowed else {
        return true;
    };
    if binary.contains('/') || binary.contains('\\') {
        return list.iter().any(|entry| entry == binary);
    }
    let key = binary_match_key(binary);
    list.iter().any(|entry| {
        !entry.contains('/') && !entry.contains('\\') && binary_match_key(entry) == key
    })
}

fn invalid_binary_reason(binary: &str) -> Option<String> {
    if binary.contains('/')
        || binary.contains('\\')
        || binary.contains(':')
        || binary.contains("..")
        || binary.contains('\0')
        || binary.is_empty()
        || binary.contains(char::is_whitespace)
    {
        Some(format!("invalid revert binary name: '{}'", binary))
    } else {
        None
    }
}

/// True when a new hold/provisional would exceed the per-caller or global cap.
/// Counts outstanding rows across both registries (a local-DoS guard).
async fn gate_capacity_reason(
    config: &ServerConfig,
    caller_principal: Option<&PrincipalKey>,
) -> Option<String> {
    let (prov_global, prov_caller) = {
        let reg = config.provisional.read().await;
        (reg.outstanding(), reg.outstanding_for(caller_principal))
    };
    let (appr_global, appr_caller) = {
        let reg = config.approvals.read().await;
        (reg.outstanding(), reg.outstanding_for(caller_principal))
    };
    let global = prov_global + appr_global;
    let per_caller = prov_caller + appr_caller;
    if per_caller >= MAX_PENDING_PER_CALLER {
        return Some(format!(
            "too many outstanding gated actions for this caller ({}); confirm, approve, or let some expire first",
            per_caller
        ));
    }
    if global >= MAX_PENDING_GLOBAL {
        return Some(format!(
            "too many outstanding gated actions on this daemon ({}); the operator must clear the queue",
            global
        ));
    }
    None
}

async fn persist_provisional(config: &ServerConfig, p: &Provisional) {
    if let Some(store) = &config.session_store {
        if let Err(e) = store.save_provisional(p.clone()).await {
            tracing::warn!("failed to persist provisional {}: {}", p.handle, e);
        }
    }
}

/// Drop any kube-proxy delete-provenance tied to a now-resolved auto-revert
/// handle. A proxy-armed create records provenance so a later contained delete
/// of that object cancels the moot create-revert; once the revert itself
/// resolves (operator confirm, or auto/manual revert), that provenance must not
/// outlive its window, or a delete of a same-named resource an operator later
/// recreates outside guard would still match the stale entry and bypass policy.
/// A no-op when the proxy is not enabled or the handle was not a proxy create.
fn forget_proxy_provenance(config: &ServerConfig, handle: &str) {
    if let Some(proxy) = &config.kube_proxy {
        proxy.forget_created_by_handle(handle);
    }
}

/// Sentinel binary naming a kube-proxy-originated row in the provisional and
/// approval registries. Such a row is never executed: approving one releases
/// the API request parked in the proxy instead of spawning a process.
const KUBE_PROXY_SENTINEL_BINARY: &str = "(kube-proxy)";

/// Retires a kube-proxy hold whose parked request vanished (the brokered
/// client disconnected while waiting), so the queue never offers the operator
/// an approval that releases nothing. Disarmed on a normal decision.
struct ProxyHoldOrphanGuard {
    config: ServerConfig,
    handle: String,
    armed: bool,
}

impl Drop for ProxyHoldOrphanGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let config = self.config.clone();
        let handle = self.handle.clone();
        tokio::spawn(async move {
            let now = now_unix();
            {
                let mut reg = config.approvals.write().await;
                match reg.get(&handle).map(|a| a.status) {
                    Some(s) if s.is_pending() => {}
                    _ => return,
                }
                reg.set_exec_failed(
                    &handle,
                    now,
                    "requester disconnected before a decision; the held API request is gone"
                        .to_string(),
                );
            }
            if let Some(a) = config.approvals.read().await.get(&handle).cloned() {
                persist_approval(&config, &a).await;
            }
            tracing::info!(
                "[AUDIT] HOLD_ORPHANED handle={} (kube-proxy client disconnected)",
                handle
            );
        });
    }
}

/// Bridges the kube-proxy's synthesized reverts into the daemon's consequence
/// machinery. Holds a clone of the server config (which shares the provisional
/// registry and state store), the operator kubeconfig for the `kubectl` revert,
/// and a directory for snapshot files. The proxy acts as the daemon principal,
/// so the operator manages proxy-armed provisionals with the same
/// `guard confirm` / `guard provisionals` / `guard revert` commands.
struct DaemonGateSink {
    config: ServerConfig,
    kubeconfig: PathBuf,
    snapshot_dir: PathBuf,
    window_secs: u64,
}

#[async_trait::async_trait]
impl guard::proxy::GateSink for DaemonGateSink {
    async fn arm_revert(&self, mutation: guard::proxy::ApiMutation) -> Option<String> {
        let principal = Some(self.config.daemon_principal.clone());
        if let Some(reason) = gate_capacity_reason(&self.config, principal.as_ref()).await {
            tracing::warn!("kube-proxy auto-revert not armed: {}", reason);
            return None;
        }
        let handle = new_handle();
        let now = now_unix();
        let kubeconfig = self.kubeconfig.display().to_string();
        let (revert_binary, revert_args) = match mutation.revert {
            guard::proxy::ApiRevert::Restore { object_json } => {
                let file = self.snapshot_dir.join(format!("revert-{handle}.json"));
                if let Err(e) = tokio::fs::write(&file, &object_json).await {
                    tracing::error!(
                        "kube-proxy: failed to write revert snapshot {}: {}",
                        file.display(),
                        e
                    );
                    return None;
                }
                (
                    "kubectl".to_string(),
                    vec![
                        "--kubeconfig".to_string(),
                        kubeconfig,
                        "replace".to_string(),
                        "-f".to_string(),
                        file.display().to_string(),
                    ],
                )
            }
            guard::proxy::ApiRevert::DeleteCreated {
                group,
                resource,
                name,
                namespace,
            } => {
                let target = if group.is_empty() {
                    resource
                } else {
                    format!("{resource}.{group}")
                };
                let mut args = vec![
                    "--kubeconfig".to_string(),
                    kubeconfig,
                    "delete".to_string(),
                    target,
                    name,
                ];
                if let Some(ns) = namespace {
                    args.push("-n".to_string());
                    args.push(ns);
                }
                ("kubectl".to_string(), args)
            }
        };
        let provisional = Provisional {
            handle: handle.clone(),
            principal,
            binary: KUBE_PROXY_SENTINEL_BINARY.to_string(),
            args: vec![mutation.label.clone()],
            revert_binary,
            revert_args,
            reason: mutation.label,
            created_unix: now,
            deadline_unix: now.saturating_add(self.window_secs),
            forward_done: true,
            status: ProvisionalStatus::Armed,
            revert_exit: None,
            revert_detail: None,
        };
        persist_provisional(&self.config, &provisional).await;
        self.config.provisional.write().await.insert(provisional);
        Some(handle)
    }

    async fn hold_request(&self, label: &str, reason: &str) -> guard::proxy::HoldDecision {
        use guard::proxy::HoldDecision;
        let principal = Some(self.config.daemon_principal.clone());
        if let Some(why) = gate_capacity_reason(&self.config, principal.as_ref()).await {
            return HoldDecision::Denied { reason: why };
        }
        let handle = new_handle();
        let now = now_unix();
        // The snapshot is descriptive, not executable: the sentinel binary plus
        // the operation label. Approval releases the parked request; nothing is
        // ever spawned from this row (see the sentinel branch in
        // `handle_approve`).
        let snapshot = ApprovalSnapshot {
            binary: KUBE_PROXY_SENTINEL_BINARY.to_string(),
            args: vec![label.to_string()],
            env: std::collections::BTreeMap::new(),
            secret_keys: std::collections::BTreeMap::new(),
            verb_name: None,
            verb_params: std::collections::BTreeMap::new(),
            catalog_version: None,
            principal,
            secret_binding: None,
        };
        let approval = Approval {
            handle: handle.clone(),
            snapshot,
            reason: reason.to_string(),
            risk: None,
            reversibility: None,
            created_unix: now,
            ttl_secs: APPROVAL_TTL_SECS,
            status: ApprovalStatus::Pending,
            decided_unix: None,
            decided_reason: None,
            result_exit: None,
            result_stdout: None,
            result_stderr: None,
            notes: Vec::new(),
        };
        let notify = self
            .config
            .approvals
            .write()
            .await
            .enqueue(approval.clone());
        persist_approval(&self.config, &approval).await;
        tracing::info!(
            "[AUDIT] HELD handle={} caller=(kube-proxy) api=\"{}\" ttl={}s",
            handle,
            label,
            APPROVAL_TTL_SECS
        );
        // If the brokered client disconnects while parked, this future is
        // dropped mid-await; the guard then retires the orphaned hold.
        let mut orphan_guard = ProxyHoldOrphanGuard {
            config: self.config.clone(),
            handle: handle.clone(),
            armed: true,
        };
        // The sweeper expires the row at its TTL and wakes this waiter; the
        // slack past the TTL is a backstop against a missed wakeup, not a
        // second policy timer.
        let deadline = tokio::time::Instant::now()
            + std::time::Duration::from_secs(APPROVAL_TTL_SECS.saturating_add(60));
        loop {
            match self.config.approvals.read().await.get(&handle).cloned() {
                Some(a) if a.status == ApprovalStatus::Approved => {
                    orphan_guard.armed = false;
                    return HoldDecision::Approved { handle };
                }
                Some(a) if a.status.is_decided() => {
                    orphan_guard.armed = false;
                    return HoldDecision::Denied {
                        reason: a
                            .decided_reason
                            .unwrap_or_else(|| a.status.as_str().to_string()),
                    };
                }
                Some(_) => {}
                None => {
                    orphan_guard.armed = false;
                    return HoldDecision::Denied {
                        reason: "held request disappeared from the queue".to_string(),
                    };
                }
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                // Past TTL plus slack: the sweeper's expiry (or an operator
                // decision) is authoritative, but nothing woke us. Leave the
                // row to the sweeper and fail closed.
                orphan_guard.armed = false;
                return HoldDecision::Denied {
                    reason: "expired without operator approval".to_string(),
                };
            }
            let _ = tokio::time::timeout(
                remaining.min(std::time::Duration::from_secs(5)),
                notify.notified(),
            )
            .await;
        }
    }

    async fn resolve(&self, handle: &str) {
        // The created object is already gone by the workload's own action, so the
        // pending create-revert (a `kubectl delete`) is moot. Confirm it to cancel
        // the timer; the sweeper then never tries to delete an absent object. A
        // handle that is already terminal is a no-op.
        let updated = {
            let mut reg = self.config.provisional.write().await;
            reg.confirm(handle)
        };
        match updated {
            Ok(p) => {
                persist_provisional(&self.config, &p).await;
                tracing::info!(
                    "kube-proxy: resolved auto-revert {} (created object deleted by workload)",
                    handle
                );
            }
            Err(e) => tracing::debug!("kube-proxy: resolve {} was a no-op: {}", handle, e),
        }
    }
}

async fn delete_provisional_row(config: &ServerConfig, handle: &str) {
    if let Some(store) = &config.session_store {
        if let Err(e) = store.delete_provisional(handle.to_string()).await {
            tracing::warn!("failed to delete provisional {}: {}", handle, e);
        }
    }
}

async fn persist_approval(config: &ServerConfig, a: &Approval) {
    if let Some(store) = &config.session_store {
        if let Err(e) = store.save_approval(a.clone()).await {
            tracing::warn!("failed to persist approval {}: {}", a.handle, e);
        }
    }
}

/// Outcome of assessing a free-form `--revert` before arming a containment
/// envelope.
enum RevertAssessment {
    /// The rollback is policy-compliant and a sensible inverse of the forward
    /// command; it is safe to arm the auto-revert envelope.
    Sensible,
    /// The rollback could not be affirmed (structurally invalid, denied by
    /// policy, judged off-target, or unevaluable). The forward command is held
    /// for operator review instead of being armed with an unverified rollback.
    NeedsReview(String),
}

/// Assess a free-form `--revert` at arm time. The evaluator judges the rollback
/// both for policy compliance and for whether it is a sensible inverse of the
/// forward command (supplied as context), since the daemon may run it unattended.
/// Only an explicit APPROVE arms the envelope; any other verdict escalates to
/// operator review (a human decides) rather than silently denying or arming an
/// unverified rollback. An operator-authored verb revert is the slow clock and is
/// not routed here.
async fn assess_revert(
    config: &ServerConfig,
    forward: &ExecuteRequest,
    revert: &RevertSpec,
) -> RevertAssessment {
    if let Some(reason) = invalid_binary_reason(&revert.binary) {
        return RevertAssessment::NeedsReview(reason);
    }
    let forward_line = if forward.args.is_empty() {
        forward.binary.clone()
    } else {
        format!("{} {}", forward.binary, forward.args.join(" "))
    };
    let revert_line = if revert.args.is_empty() {
        revert.binary.clone()
    } else {
        format!("{} {}", revert.binary, revert.args.join(" "))
    };
    let context = format!(
        "ROLLBACK ASSESSMENT. A recoverable command was approved to run inside an \
         auto-revert containment envelope. If the operator does not confirm in time, \
         the daemon runs the rollback unattended.\n\
         Forward command: {forward_line}\n\
         Proposed rollback: {revert_line}\n\
         APPROVE only if the rollback is safe under policy AND is a sensible inverse \
         that undoes the forward command without additional damage, broader scope, or \
         unrelated side effects. DENY if it is off-target, destructive, overly broad, \
         or unrelated to the forward command."
    );
    match config
        .evaluator
        .evaluate_with_context(&revert_line, Some(&context))
        .await
    {
        crate::evaluate::EvalResult::Allow { .. } => RevertAssessment::Sensible,
        crate::evaluate::EvalResult::Deny { reason, .. } => {
            RevertAssessment::NeedsReview(format!("rollback not affirmed by policy: {reason}"))
        }
        crate::evaluate::EvalResult::Error(e) => {
            RevertAssessment::NeedsReview(format!("rollback could not be evaluated: {e}"))
        }
    }
}

/// Bundled inputs for consequence-gate routing.
struct GateInputs {
    reason: String,
    risk: Option<i32>,
    reversibility: Option<Reversibility>,
    /// True when the revert is operator-authored (a verb's `revert`), so it is
    /// not re-evaluated at arm time. A free-form `--revert` is always evaluated.
    revert_preauthorized: bool,
    /// Verb context when this command came from the catalog (pins the approval
    /// snapshot to the verb name + params + catalog version).
    verb: Option<VerbContext>,
    /// When true the command bypasses the gate and executes immediately. Set for
    /// operator-authored deterministic allows (static policy), already vetted and
    /// carrying no reversibility class.
    bypass: bool,
}

/// Route an approved command through the consequence gate.
async fn route_gated_allow<W: AsyncWrite + Unpin>(
    request: ExecuteRequest,
    config: &ServerConfig,
    caller: &CallerIdentity,
    inputs: GateInputs,
    depth: u32,
    stream_output: bool,
    stream_writer: &mut W,
) -> ExecuteResult {
    // Gating off, or an operator-authored static-policy allow: execute directly.
    if !config.gate.is_on() || inputs.bypass {
        return exec_after_approval(
            request,
            config,
            caller,
            inputs.reason,
            depth,
            stream_output,
            stream_writer,
        )
        .await;
    }

    // The row owner is the caller's cross-platform principal (uid string on
    // Unix, SID on Windows). A non-Unix caller is no longer dropped to None.
    let caller_principal = caller.principal();
    let force_hold = request.require_approval.unwrap_or(false);
    let revert_available = request.revert.is_some();
    let outcome = decide_gate(
        inputs.reversibility,
        inputs.risk,
        revert_available,
        force_hold,
    );

    match outcome {
        GateOutcome::ExecuteNow => {
            exec_after_approval(
                request,
                config,
                caller,
                inputs.reason,
                depth,
                stream_output,
                stream_writer,
            )
            .await
        }
        GateOutcome::Contain => {
            // The rollback is itself a consequential action the daemon may run
            // unattended. An operator-authored verb revert is pre-authorized (the
            // slow clock). A free-form `--revert` is assessed for policy and for
            // being a sensible inverse of the forward command; if it cannot be
            // affirmed, the command is held for operator review rather than denied
            // or armed with an unverified rollback.
            if !inputs.revert_preauthorized {
                if let Some(revert) = request.revert.clone() {
                    if let RevertAssessment::NeedsReview(why) =
                        assess_revert(config, &request, &revert).await
                    {
                        let hold_reason = format!(
                            "{} [held for operator review: auto-revert not validated: {}]",
                            inputs.reason, why
                        );
                        return hold_for_approval(
                            request,
                            config,
                            caller,
                            caller_principal,
                            hold_reason,
                            inputs.risk,
                            inputs.reversibility,
                            inputs.verb,
                            stream_output,
                            stream_writer,
                        )
                        .await;
                    }
                }
            }
            arm_containment(
                request,
                config,
                caller,
                caller_principal,
                inputs.reason,
                depth,
                stream_output,
                stream_writer,
            )
            .await
        }
        GateOutcome::Hold => {
            hold_for_approval(
                request,
                config,
                caller,
                caller_principal,
                inputs.reason,
                inputs.risk,
                inputs.reversibility,
                inputs.verb,
                stream_output,
                stream_writer,
            )
            .await
        }
    }
}

/// Arm a containment envelope: persist the provisional, run the forward command,
/// then mark it armed with an auto-revert deadline.
#[allow(clippy::too_many_arguments)]
async fn arm_containment<W: AsyncWrite + Unpin>(
    request: ExecuteRequest,
    config: &ServerConfig,
    caller: &CallerIdentity,
    caller_principal: Option<PrincipalKey>,
    reason: String,
    depth: u32,
    stream_output: bool,
    stream_writer: &mut W,
) -> ExecuteResult {
    // decide_gate only returns Contain when a revert is present.
    let revert = match request.revert.clone() {
        Some(r) => r,
        None => return ExecuteResult::held(reason, new_handle(), Coverage::hold()),
    };

    if config.dry_run {
        return ExecuteResult::dry_run_gated(
            format!(
                "{} [GATE] would execute inside a containment envelope (auto-revert: {} {})",
                reason,
                revert.binary,
                revert.args.join(" ")
            ),
            Coverage::contain(),
        );
    }

    // The rollback was assessed by the gate router before this point (free-form
    // reverts are policy- and sensibility-checked; a verb revert is the
    // operator-authored slow clock), so the envelope is armed here directly.
    if let Some(why) = gate_capacity_reason(config, caller_principal.as_ref()).await {
        return ExecuteResult::denied(why);
    }

    let handle = new_handle();
    let now = now_unix();
    // The window is caller-supplied, so cap it: a contained change always
    // auto-reverts within MAX_CONFIRM_WITHIN_SECS even if the caller asks for
    // longer. The caller can still shorten it.
    let window = request
        .confirm_within_secs
        .unwrap_or(DEFAULT_CONFIRM_WITHIN_SECS)
        .clamp(1, MAX_CONFIRM_WITHIN_SECS);
    let provisional = Provisional {
        handle: handle.clone(),
        principal: caller_principal,
        binary: request.binary.clone(),
        args: request.args.clone(),
        revert_binary: revert.binary.clone(),
        revert_args: revert.args.clone(),
        reason: reason.clone(),
        created_unix: now,
        deadline_unix: now.saturating_add(window),
        forward_done: false,
        status: ProvisionalStatus::Armed,
        revert_exit: None,
        revert_detail: None,
    };

    // Commit BEFORE exec so a crash between exec and arm still leaves a
    // recoverable revert (startup recovery routes it to needs_operator_decision).
    persist_provisional(config, &provisional).await;
    config.provisional.write().await.insert(provisional.clone());

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

    match result.exec {
        ExecOutcome::Completed {
            exit_code,
            stdout,
            stderr,
        } => {
            let updated = {
                let mut reg = config.provisional.write().await;
                reg.mark_forward_done(&handle, exit_code);
                reg.get(&handle).cloned()
            };
            if let Some(u) = updated {
                persist_provisional(config, &u).await;
            }
            tracing::info!(
                "[AUDIT] PROVISIONAL handle={} caller={} deadline={} window={}s revert=\"{}\"",
                handle,
                caller,
                now.saturating_add(window),
                window,
                audit_command_line(&revert.binary, &revert.args)
            );
            ExecuteResult::provisional(
                reason,
                handle,
                Coverage::contain(),
                exit_code,
                stdout,
                stderr,
            )
        }
        // The child was launched and then failed (e.g. the client stream dropped
        // mid-run). It may already have applied its mutation, so keep the
        // provisional armed: the auto-revert timer fires at the deadline and
        // rolls the unconfirmed change back rather than leaking it. Mark the
        // forward done so the deadline is honored, and surface the failure.
        ExecOutcome::Failed { started: true, .. } => {
            let updated = {
                let mut reg = config.provisional.write().await;
                reg.mark_forward_done(&handle, None);
                reg.get(&handle).cloned()
            };
            if let Some(u) = updated {
                persist_provisional(config, &u).await;
            }
            tracing::warn!(
                "[AUDIT] PROVISIONAL_INTERRUPTED handle={} caller={} deadline={} (forward launched then failed; auto-revert armed)",
                handle,
                caller,
                now.saturating_add(window)
            );
            result
        }
        _ => {
            // The child never ran (spawn/setup failure) — nothing to revert.
            // Drop the provisional and return the failure as-is.
            config.provisional.write().await.remove(&handle);
            delete_provisional_row(config, &handle).await;
            result
        }
    }
}

/// Hold an irreversible/uncertain/high-risk command for operator approval.
#[allow(clippy::too_many_arguments)]
async fn hold_for_approval<W: AsyncWrite + Unpin>(
    request: ExecuteRequest,
    config: &ServerConfig,
    caller: &CallerIdentity,
    caller_principal: Option<PrincipalKey>,
    reason: String,
    risk: Option<i32>,
    reversibility: Option<Reversibility>,
    verb: Option<VerbContext>,
    stream_output: bool,
    stream_writer: &mut W,
) -> ExecuteResult {
    if config.dry_run {
        return ExecuteResult::dry_run_gated(
            format!(
                "{} [GATE] would be held for operator approval (irreversible/uncertain)",
                reason
            ),
            Coverage::hold(),
        );
    }
    if let Some(why) = gate_capacity_reason(config, caller_principal.as_ref()).await {
        return ExecuteResult::denied(why);
    }

    let handle = new_handle();
    let now = now_unix();

    // Secret-value binding: hash each referenced secret value NOW so a
    // same-principal caller cannot swap its mapped values between this hold and
    // the operator's approval. The binding is MANDATORY when there are secrets
    // and a principal: every referenced secret is bound, a resolved one by its
    // salted hash and an unresolved one by a sentinel. Binding the unresolved
    // case closes the gap where a caller makes a secret unresolvable at hold
    // (so it would otherwise be unbound) and then creates it with a chosen value
    // before approval. Verification at approve time fails closed on any change.
    let secret_binding = match caller_principal.clone() {
        Some(principal) if !request.secrets.is_empty() => {
            let salt = hex_encode(&rand::random::<u128>().to_le_bytes());
            let mut hashes = std::collections::BTreeMap::new();
            for (env_var, secret_name) in &request.secrets {
                let entry = match config.secrets.get(&principal, secret_name).await {
                    Ok(Some(value)) => hash_secret_value(&salt, &value),
                    _ => SECRET_BINDING_UNRESOLVED.to_string(),
                };
                hashes.insert(env_var.clone(), entry);
            }
            Some(guard::gating::approval::SecretBinding { salt, hashes })
        }
        _ => None,
    };

    let snapshot = ApprovalSnapshot {
        binary: request.binary.clone(),
        args: request.args.clone(),
        env: request
            .env
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        secret_keys: request
            .secrets
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        verb_name: verb.as_ref().map(|v| v.name.clone()),
        verb_params: verb.as_ref().map(|v| v.params.clone()).unwrap_or_default(),
        catalog_version: verb.as_ref().map(|v| v.catalog_version),
        principal: caller_principal,
        secret_binding,
    };
    let approval = Approval {
        handle: handle.clone(),
        snapshot,
        reason: reason.clone(),
        risk,
        reversibility,
        created_unix: now,
        ttl_secs: APPROVAL_TTL_SECS,
        status: ApprovalStatus::Pending,
        decided_unix: None,
        decided_reason: None,
        result_exit: None,
        result_stdout: None,
        result_stderr: None,
        notes: Vec::new(),
    };

    let notify = config.approvals.write().await.enqueue(approval.clone());
    persist_approval(config, &approval).await;
    tracing::info!(
        "[AUDIT] HELD handle={} caller={} risk={:?} class={:?} cmd=\"{}\" ttl={}s",
        handle,
        caller,
        risk,
        reversibility.map(|r| r.as_str()),
        audit_command_line(&request.binary, &request.args),
        APPROVAL_TTL_SECS
    );

    match request.wait_approval_secs {
        Some(wait) => {
            wait_for_decision(config, &handle, notify, wait, stream_output, stream_writer).await
        }
        None => ExecuteResult::held(reason, handle, Coverage::hold()),
    }
}

/// Block (up to `wait_secs`) for an operator decision on a held command,
/// emitting keepalives on the streaming path so the connection stays open, then
/// return the real outcome. On timeout the command stays held.
async fn wait_for_decision<W: AsyncWrite + Unpin>(
    config: &ServerConfig,
    handle: &str,
    notify: std::sync::Arc<tokio::sync::Notify>,
    wait_secs: u64,
    stream_output: bool,
    stream_writer: &mut W,
) -> ExecuteResult {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(wait_secs);
    let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        // Check current status first so a decision that landed before we parked
        // is not missed.
        if let Some(a) = config.approvals.read().await.get(handle).cloned() {
            if a.status.is_decided() {
                return approval_to_result(&a);
            }
        } else {
            return ExecuteResult::denied("held command disappeared from the queue");
        }

        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            // Still pending at timeout: stays held.
            return ExecuteResult::held(
                "still awaiting operator approval".to_string(),
                handle.to_string(),
                Coverage::hold(),
            );
        }

        tokio::select! {
            _ = notify.notified() => { /* re-check status at loop top */ }
            _ = tokio::time::sleep(remaining) => { /* timeout: re-check, then held */ }
            _ = keepalive.tick(), if stream_output => {
                let _ = write_stream_message(stream_writer, &ExecuteStreamMessage::Keepalive).await;
            }
        }
    }
}

/// Build the client-facing result from a decided approval record.
fn approval_to_result(a: &Approval) -> ExecuteResult {
    match a.status {
        ApprovalStatus::Approved => ExecuteResult::completed(
            a.reason.clone(),
            a.result_exit,
            a.result_stdout.clone(),
            a.result_stderr.clone(),
        ),
        ApprovalStatus::Denied => ExecuteResult::denied(
            a.decided_reason
                .clone()
                .unwrap_or_else(|| "operator denied this command".to_string()),
        ),
        ApprovalStatus::Expired => {
            ExecuteResult::denied("expired without operator approval (fail-closed)")
        }
        ApprovalStatus::ExecFailed => ExecuteResult::exec_failed(
            a.reason.clone(),
            a.decided_reason
                .clone()
                .unwrap_or_else(|| "approved command failed to execute".to_string()),
        ),
        ApprovalStatus::Pending | ApprovalStatus::Approving => {
            ExecuteResult::held(a.reason.clone(), a.handle.clone(), Coverage::hold())
        }
    }
}

/// Sentinel stored in a [`SecretBinding`] for a secret that did not resolve at
/// hold time. It is not a 64-char SHA-256 hex digest, so it can never collide
/// with a real value hash. A binding entry equal to this means "the secret was
/// absent when the operator reviewed the hold"; if it resolves at approve time,
/// verification fails closed.
const SECRET_BINDING_UNRESOLVED: &str = "<unresolved-at-hold>";

/// Lowercase hex-encode bytes without pulling in a hex crate.
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Salted SHA-256 of a secret value, hex-encoded. The salt and a 0x00 domain
/// separator ensure the stored digest is not a plain hash of the value, so a
/// persisted binding does not expose a brute-forceable fingerprint of the
/// secret. Used only to detect a value change between hold and approval.
fn hash_secret_value(salt_hex: &str, value: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(salt_hex.as_bytes());
    hasher.update([0u8]);
    hasher.update(value.as_bytes());
    hex_encode(&hasher.finalize())
}

/// Execute an approved snapshot verbatim under the original caller's identity,
/// with no client stream. Used by `guard approve`.
async fn execute_snapshot(
    config: &ServerConfig,
    snapshot: &ApprovalSnapshot,
    reason: &str,
) -> ExecuteResult {
    // Verify the secret-value binding captured at hold time. A same-principal
    // caller must not have swapped its mapped secret values since the operator
    // reviewed the hold. Fail closed (exec_failed, command not started) on any
    // mismatch, missing binding entry, or re-resolution failure.
    if let Some(binding) = &snapshot.secret_binding {
        let Some(principal) = snapshot.principal.clone() else {
            return ExecuteResult::exec_failed(
                reason.to_string(),
                "approval rejected: a secret-value binding is present but the caller principal is unknown".to_string(),
            );
        };
        for (env_var, secret_name) in &snapshot.secret_keys {
            // Every secret was bound at hold; a missing entry means the request
            // was altered between hold and approval. Fail closed.
            let Some(expected) = binding.hashes.get(env_var) else {
                return ExecuteResult::exec_failed(
                    reason.to_string(),
                    format!(
                        "approval rejected: secret '{}' was not bound at hold",
                        secret_name
                    ),
                );
            };
            let resolved = match config.secrets.get(&principal, secret_name).await {
                Ok(v) => v,
                Err(e) => {
                    return ExecuteResult::exec_failed(
                        reason.to_string(),
                        format!(
                            "approval rejected: failed to re-resolve bound secret '{}': {}",
                            secret_name, e
                        ),
                    );
                }
            };
            let consistent = match (expected.as_str(), resolved) {
                // Unresolved at hold and still unresolved: consistent (the exec
                // path surfaces the missing secret on its own).
                (SECRET_BINDING_UNRESOLVED, None) => true,
                // Unresolved at hold but now resolves: a value swap between
                // hold and approval. Reject.
                (SECRET_BINDING_UNRESOLVED, Some(_)) => false,
                // Bound to a value: it must still resolve to the same value.
                (hash, Some(v)) => hash_secret_value(&binding.salt, &v) == hash,
                // Was bound to a value, now gone. Reject.
                (_, None) => false,
            };
            if !consistent {
                return ExecuteResult::exec_failed(
                    reason.to_string(),
                    "approval rejected: a mapped secret value changed since the command was held"
                        .to_string(),
                );
            }
        }
    }

    let caller = reconstruct_caller(snapshot.principal.clone(), &CallerIdentity::Unknown);
    let request = ExecuteRequest {
        binary: snapshot.binary.clone(),
        args: snapshot.args.clone(),
        auth_token: None,
        env: snapshot
            .env
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        secrets: snapshot
            .secret_keys
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        stream: false,
        session_token: None,
        revert: None,
        confirm_within_secs: None,
        reevaluate: false,
        ssh_hostkey: None,
        require_approval: None,
        wait_approval_secs: None,
        verb: None,
    };
    let mut sink = tokio::io::sink();
    exec_after_approval(
        request,
        config,
        &caller,
        reason.to_string(),
        0,
        false,
        &mut sink,
    )
    .await
}

/// The single background task that drives time-based gate transitions: fires due
/// auto-reverts (after a startup grace so it can never race startup recovery) and
/// expires unattended holds (fail-closed). Runs only when gating is enabled.
async fn gating_sweeper(config: ServerConfig) {
    // Startup recovery has already run synchronously; this grace is belt-and-
    // suspenders so no revert can fire in the first window after boot. The
    // default is operator-overridable (and test harnesses shorten it) but is
    // floored so it can never race startup recovery.
    let grace = std::env::var("GUARD_SWEEPER_GRACE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(|v| v.max(1))
        .unwrap_or(SWEEPER_GRACE_SECS);
    tokio::time::sleep(std::time::Duration::from_secs(grace)).await;
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(SWEEPER_TICK_SECS));
    loop {
        tick.tick().await;
        let now = now_unix();

        // Expire unattended holds FIRST (fail-closed deny on a timer). Doing this
        // before the reverts guarantees the fail-closed promise is met every tick
        // even if a revert is slow.
        let expired = { config.approvals.write().await.expire_due(now) };
        for h in &expired {
            let row = config.approvals.read().await.get(h).cloned();
            if let Some(a) = row {
                persist_approval(&config, &a).await;
                tracing::warn!("[AUDIT] APPROVAL_EXPIRED handle={} (fail-closed deny)", h);
            }
        }

        // Due auto-reverts. take_due transitions each to Reverting; persist that
        // before running so a crash mid-revert recovers to needs_operator_decision.
        // Each revert is bounded by a wall-clock timeout (a timeout is recorded as
        // RevertFailed and stays queryable), and reverts are dispatched as
        // independent tasks so a burst of slow rollbacks cannot serialize and push
        // out the next tick's fail-closed expiry sweep.
        let due = { config.provisional.write().await.take_due(now) };
        for p in due {
            persist_provisional(&config, &p).await;
            let cfg = config.clone();
            tokio::spawn(async move {
                let _ = finish_revert(&cfg, &p, &CallerIdentity::Unknown, "auto").await;
            });
        }

        // Due read-grant expiries. Revoking a read grant only removes access, so
        // unlike a provisional revert it is always safe to run unattended; there
        // is no needs-operator-decision path. Persist the Reverting transition
        // before running so a crash mid-revocation recovers to Active and retries.
        let due_grants = { config.read_grants.write().await.take_due(now) };
        for g in due_grants {
            persist_read_grant(&config, &g).await;
            let cfg = config.clone();
            tokio::spawn(async move {
                finish_read_grant_revert(&cfg, &g, "expiry").await;
            });
        }

        // Bound the tables: drop terminal rows past the retention window.
        let pruned_p = {
            config
                .provisional
                .write()
                .await
                .prune_terminal(now, GATING_RETENTION_SECS)
        };
        for h in pruned_p {
            delete_provisional_row(&config, &h).await;
        }
        let pruned_a = {
            config
                .approvals
                .write()
                .await
                .prune_decided(now, GATING_RETENTION_SECS)
        };
        for h in pruned_a {
            if let Some(store) = &config.session_store {
                if let Err(e) = store.delete_approval(h.clone()).await {
                    tracing::warn!("failed to delete pruned approval {}: {}", h, e);
                }
            }
        }
        let pruned_g = {
            config
                .read_grants
                .write()
                .await
                .prune_terminal(now, GATING_RETENTION_SECS)
        };
        for path in pruned_g {
            delete_read_grant_row(&config, &path).await;
        }
    }
}

/// Run the revert for a provisional under the original caller's identity, with no
/// client stream. Used by the sweeper and `guard revert`.
async fn run_provisional_revert(config: &ServerConfig, p: &Provisional) -> ExecuteResult {
    let caller = reconstruct_caller(p.principal.clone(), &CallerIdentity::Unknown);
    let request = ExecuteRequest {
        binary: p.revert_binary.clone(),
        args: p.revert_args.clone(),
        auth_token: None,
        env: HashMap::new(),
        secrets: HashMap::new(),
        stream: false,
        session_token: None,
        revert: None,
        confirm_within_secs: None,
        reevaluate: false,
        ssh_hostkey: None,
        require_approval: None,
        wait_approval_secs: None,
        verb: None,
    };
    let mut sink = tokio::io::sink();
    exec_after_approval(
        request,
        config,
        &caller,
        format!("auto-revert of provisional {}", p.handle),
        0,
        false,
        &mut sink,
    )
    .await
}

/// Label used for the binary field of a read-grant request's audit records, so
/// `[AUDIT] ALLOWED`/`DENIED` grep patterns and session allow/deny globs treat a
/// grant request the same shape as `grant-read <path> --ttl <ttl>`.
const GRANT_READ_LABEL: &str = "grant-read";

fn grant_read_audit_args(path: &str, ttl: u64) -> Vec<String> {
    vec![path.to_string(), "--ttl".to_string(), ttl.to_string()]
}

/// Handle a filesystem read-grant request. Platform-gated to Unix (POSIX ACLs);
/// on any other platform it fails clearly and immediately, mirroring the
/// `--exec-as-caller` platform gate.
async fn handle_grant_request(
    config: &ServerConfig,
    caller: &CallerIdentity,
    grant: GrantRequest,
) -> ExecuteResult {
    #[cfg(not(unix))]
    {
        let reason = format!(
            "read grants are not supported on this platform (POSIX ACLs are Unix-only): '{}'",
            grant.path()
        );
        config.log_audit_policy(
            caller,
            GRANT_READ_LABEL,
            &[grant.path().to_string()],
            false,
            &reason,
        );
        ExecuteResult::denied(reason)
    }
    #[cfg(unix)]
    {
        match grant {
            GrantRequest::Read {
                path,
                ttl_secs,
                session_token,
                reevaluate,
            } => handle_grant_read(config, caller, path, ttl_secs, session_token, reevaluate).await,
            GrantRequest::Revoke {
                path,
                session_token,
            } => handle_grant_revoke(config, caller, path, session_token).await,
        }
    }
}

/// Issue a scoped, time-boxed POSIX ACL read grant, routed through the same
/// policy pipeline as any brokered command: a hard credential deny-list first
/// (before the evaluator ever sees it), then session allow/deny globs, then the
/// LLM evaluator. On allow, the ACL entries are applied and an expiry is armed.
#[cfg(unix)]
async fn handle_grant_read(
    config: &ServerConfig,
    caller: &CallerIdentity,
    path: String,
    ttl_secs: u64,
    session_token: Option<String>,
    reevaluate: bool,
) -> ExecuteResult {
    let ttl = clamp_ttl(ttl_secs);

    // A read grant applies an ACL for a kernel-verified local uid; only a local
    // Unix peer carries one.
    let caller_uid = match caller {
        CallerIdentity::Unix { uid } => *uid,
        _ => {
            let reason = "read grants require a local Unix socket caller".to_string();
            config.log_audit_policy(
                caller,
                GRANT_READ_LABEL,
                &grant_read_audit_args(&path, ttl),
                false,
                &reason,
            );
            return ExecuteResult::denied(reason);
        }
    };

    // Canonicalize first: resolve symlinks and `..` so the deny-list and the
    // home-boundary check reason about the real target, not a path that only
    // textually sits under a home directory.
    let canonical = match std::fs::canonicalize(&path) {
        Ok(p) => p,
        Err(e) => {
            let reason = format!("read-grant denied: cannot resolve '{path}': {e}");
            config.log_audit_policy(
                caller,
                GRANT_READ_LABEL,
                &grant_read_audit_args(&path, ttl),
                false,
                &reason,
            );
            return ExecuteResult::denied(reason);
        }
    };
    let canonical_str = canonical.display().to_string();
    let audit_args = grant_read_audit_args(&canonical_str, ttl);

    // 1. Hard static credential deny-list, BEFORE the evaluator.
    if let Some(reason) = credential_path_deny_reason(&canonical_str) {
        config.log_audit_policy(caller, GRANT_READ_LABEL, &audit_args, false, &reason);
        return ExecuteResult::denied(reason);
    }

    // 2. Session allow/deny globs short-circuit, exactly as for a command: a
    // deny wins before the evaluator; an allow skips it.
    let mut allow_reason: Option<String> = None;
    if let Some(ref token) = session_token {
        let (decision, exists, static_only) = {
            let reg = config.sessions.read().await;
            (
                reg.check(token, GRANT_READ_LABEL, &audit_args),
                reg.has(token),
                reg.static_only_for(token),
            )
        };
        if !exists {
            let reason =
                format!("unknown session token: '{token}' is revoked, expired, or never existed");
            config.log_audit_policy(caller, GRANT_READ_LABEL, &audit_args, false, &reason);
            return ExecuteResult::denied(reason);
        }
        match decision {
            Some((SessionDecision::Deny, reason)) => {
                config.log_audit_policy(caller, GRANT_READ_LABEL, &audit_args, false, &reason);
                return ExecuteResult::denied(reason);
            }
            Some((SessionDecision::Allow, reason)) => allow_reason = Some(reason),
            None if static_only => {
                let reason = "session static-only: no matching session allow rule".to_string();
                config.log_audit_policy(caller, GRANT_READ_LABEL, &audit_args, false, &reason);
                return ExecuteResult::denied(reason);
            }
            None => {}
        }
    }

    // 3. LLM evaluator, when no session allow already settled it. Same
    // `evaluate_with_reevaluate` call the command pipeline uses; the request is
    // phrased naturally and given assessment context so the model has real
    // signal about what reading this path means.
    if allow_reason.is_none() {
        let session_prompt = match session_token.as_deref() {
            Some(token) => config.sessions.read().await.prompt_append_for(token),
            None => None,
        };
        let command_line = format!(
            "grant guard's brokering service account scoped read access to the file {canonical_str} for {ttl} seconds"
        );
        let context = format!(
            "READ-GRANT ASSESSMENT. A brokered caller is asking guard to add a scoped, \
             time-boxed POSIX ACL read grant for its own low-privilege service account on \
             the single file below, so a brokered ansible/helm command can read an operator \
             config/vars/values file. The grant auto-revokes after the TTL; it is not a \
             command execution and touches no other path.\n\
             Target file: {canonical_str}\n\
             TTL: {ttl} seconds\n\
             APPROVE if this is an ordinary configuration/vars/values file the operator would \
             let a brokered tool read. DENY if the path looks like it exposes credentials, \
             private keys, tokens, or other secrets."
        );
        let prompt_append = match session_prompt {
            Some(sp) if !sp.trim().is_empty() => format!("{context}\n\n{sp}"),
            _ => context,
        };
        match config
            .evaluator
            .evaluate_with_reevaluate(&command_line, Some(&prompt_append), reevaluate)
            .await
        {
            crate::evaluate::EvalResult::Allow { reason, .. } => allow_reason = Some(reason),
            crate::evaluate::EvalResult::Deny { reason, .. } => {
                config.log_audit_policy(caller, GRANT_READ_LABEL, &audit_args, false, &reason);
                return ExecuteResult::denied(reason);
            }
            crate::evaluate::EvalResult::Error(e) => {
                let reason = format!("evaluation error: {e}");
                config.log_audit_policy(caller, GRANT_READ_LABEL, &audit_args, false, &reason);
                return ExecuteResult::denied(reason);
            }
        }
    }
    let reason = allow_reason.unwrap_or_default();

    if config.dry_run {
        config.log_audit_policy(caller, GRANT_READ_LABEL, &audit_args, true, &reason);
        return ExecuteResult::completed(
            reason,
            Some(0),
            Some(format!(
                "[DRY-RUN] would grant read on {canonical_str} for {ttl}s\n"
            )),
            None,
        );
    }

    // 4. Determine the grantee: guard's own service account by default, or the
    // caller's uid under --exec-as-caller (where brokered children run as the
    // caller, not the daemon).
    let grantee_uid = if config.exec_as_caller {
        caller_uid
    } else {
        config.daemon_uid
    };
    let grantee_gid = match resolve_exec_caller_context(grantee_uid) {
        Ok(ctx) => ctx.gid,
        Err(e) => {
            let reason = format!("grantee uid {grantee_uid} could not be resolved: {e}");
            config.log_audit_policy(caller, GRANT_READ_LABEL, &audit_args, true, &reason);
            return ExecuteResult::exec_failed(reason.clone(), reason);
        }
    };

    // The traverse boundary is the home directory of the file's owner: walk no
    // higher than it so a grant can never add traverse ACLs into shared system
    // paths above a home. Fail closed if the target is not under it.
    let home_boundary = match owner_home_boundary(&canonical) {
        Ok(home) => home,
        Err(e) => {
            let reason = format!("read-grant denied: {e}");
            config.log_audit_policy(caller, GRANT_READ_LABEL, &audit_args, false, &reason);
            return ExecuteResult::denied(reason);
        }
    };

    // Plan the entries, commit the grant row, THEN apply the ACLs, so a crash
    // mid-apply leaves a recoverable row the reconciler can revoke rather than a
    // permanently-open grant with no record.
    let entries = match plan_read_grant(&canonical, grantee_uid, grantee_gid, &home_boundary).await
    {
        Ok(entries) => entries,
        Err(e) => {
            let reason = format!("read-grant denied: {e}");
            config.log_audit_policy(caller, GRANT_READ_LABEL, &audit_args, false, &reason);
            return ExecuteResult::denied(reason);
        }
    };

    let now = now_unix();
    let grant = ReadGrant {
        handle: new_handle(),
        principal: caller.principal(),
        granting_session: session_token.clone(),
        target_path: canonical_str.clone(),
        grantee_uid,
        entries: entries.clone(),
        reason: reason.clone(),
        created_unix: now,
        expires_unix: now.saturating_add(ttl),
        status: ReadGrantStatus::Active,
        revert_detail: None,
    };
    persist_read_grant(config, &grant).await;

    if let Err(e) = apply_read_grant_entries(grantee_uid, &entries).await {
        // Nothing survived the in-apply rollback, so drop the committed row too.
        delete_read_grant_row(config, &grant.target_path).await;
        let exec_reason = format!("failed to apply read grant: {e}");
        config.log_audit_policy(caller, GRANT_READ_LABEL, &audit_args, true, &reason);
        config.log_audit_exec_failed(caller, GRANT_READ_LABEL, &audit_args, &exec_reason);
        return ExecuteResult::exec_failed(reason, exec_reason);
    }

    let traverse_count = grant.entries.len().saturating_sub(1);
    config.read_grants.write().await.insert(grant.clone());

    config.log_audit_policy(caller, GRANT_READ_LABEL, &audit_args, true, &reason);
    tracing::info!(
        "[AUDIT] READ_GRANT_ISSUED caller={} handle={} path=\"{}\" grantee_uid={} ttl={} traverse_grants={} session={}",
        caller,
        grant.handle,
        grant.target_path,
        grantee_uid,
        ttl,
        traverse_count,
        session_token.as_deref().unwrap_or("-"),
    );

    let stdout = format!(
        "granted read on {} to uid {} for {}s (handle {}); {} ancestor traverse grant(s); auto-revokes at unix {}\n",
        grant.target_path,
        grantee_uid,
        ttl,
        grant.handle,
        traverse_count,
        grant.expires_unix,
    );
    ExecuteResult::completed(reason, Some(0), Some(stdout), None)
}

/// Early revoke of an active read grant. Revocation only removes access, so it
/// is a de-escalation and is not routed through the evaluator; it is still
/// audited.
#[cfg(unix)]
async fn handle_grant_revoke(
    config: &ServerConfig,
    caller: &CallerIdentity,
    path: String,
    // Revocation is deliberately NOT scoped to the requesting caller's own
    // grants: any allowed local caller may revoke any read grant by path. This
    // is intentional, not an oversight (hence the unused `_session_token`).
    // Revoking is always safe and monotonic -- it only removes access an
    // evaluator/operator previously approved and never grants anything -- so
    // there is no benefit to restricting who may run it, and an operator or a
    // sibling worker must be able to tear down a grant unattended. See the
    // ReadGrantStatus lifecycle note in `guard::gating::read_grant`.
    _session_token: Option<String>,
) -> ExecuteResult {
    // Match on the canonical path when it still resolves, else fall back to the
    // literal path so a grant whose target was since deleted can still be
    // revoked by the name it was granted under.
    let key = std::fs::canonicalize(&path)
        .map(|p| p.display().to_string())
        .unwrap_or(path);
    let audit_args = vec![key.clone()];

    let claimed = config.read_grants.write().await.begin_revert(&key);
    let Some(grant) = claimed else {
        let reason = format!("no active read grant for '{key}'");
        config.log_audit_policy(caller, GRANT_READ_LABEL, &audit_args, false, &reason);
        return ExecuteResult::denied(reason);
    };
    persist_read_grant(config, &grant).await;
    finish_read_grant_revert(config, &grant, "manual").await;

    let reason = format!("revoked read grant on {key}");
    config.log_audit_policy(caller, GRANT_READ_LABEL, &audit_args, true, &reason);
    let stdout = format!("{reason}\n");
    ExecuteResult::completed(reason, Some(0), Some(stdout), None)
}

/// The home directory of the file at `target`'s owner, used as the ceiling for
/// ancestor traverse grants. Canonicalized so a symlinked home compares equal.
#[cfg(unix)]
fn owner_home_boundary(target: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(target).with_context(|| format!("stat {}", target.display()))?;
    let owner_uid = meta.uid();
    let ctx = resolve_exec_caller_context(owner_uid)
        .with_context(|| format!("resolve owner uid {owner_uid}"))?;
    let home = std::fs::canonicalize(&ctx.home_dir).unwrap_or(ctx.home_dir);
    if !target.starts_with(&home) || target == home.as_path() {
        bail!(
            "target {} is not under the owning home directory {}",
            target.display(),
            home.display()
        );
    }
    Ok(home)
}

/// Compute the ACL entries a read grant needs WITHOUT applying them: a `--x`
/// traverse grant on each ancestor directory the grantee cannot already cross,
/// then the `r` read grant on the leaf. Separated from application so the grant
/// row can be committed to the state store before any ACL is touched (mirroring
/// the provisional "commit before the forward command runs" pattern), so a crash
/// mid-apply always leaves a recoverable row rather than a leaked grant.
#[cfg(unix)]
async fn plan_read_grant(
    target: &Path,
    grantee_uid: u32,
    grantee_gid: u32,
    home_boundary: &Path,
) -> Result<Vec<AclEntry>> {
    let ancestors = ancestor_dirs_within(target, home_boundary).ok_or_else(|| {
        anyhow::anyhow!(
            "target {} is not under the owning home directory {}",
            target.display(),
            home_boundary.display()
        )
    })?;
    // A regular file open requires `--x` (traverse) on every ancestor directory,
    // so plan it only where the grantee cannot already cross, from the leaf's
    // parent up to the home boundary.
    let mut entries = Vec::new();
    for dir in &ancestors {
        let meta = std::fs::metadata(dir).with_context(|| format!("stat {}", dir.display()))?;
        if dir_allows_traverse(&meta, dir, grantee_uid, grantee_gid).await {
            continue;
        }
        entries.push(AclEntry {
            path: dir.display().to_string(),
            perms: "x".to_string(),
        });
    }
    entries.push(AclEntry {
        path: target.display().to_string(),
        perms: "r".to_string(),
    });
    Ok(entries)
}

/// Apply a planned set of ACL entries. Rolls back everything it applied on a
/// partial failure so a failed grant never leaves stray ACL entries behind.
#[cfg(unix)]
async fn apply_read_grant_entries(grantee_uid: u32, entries: &[AclEntry]) -> Result<()> {
    let mut applied: Vec<&AclEntry> = Vec::new();
    for entry in entries {
        let spec = format!("u:{grantee_uid}:{}", entry.perms);
        if let Err(e) = setfacl_modify(&spec, Path::new(&entry.path)).await {
            for done in &applied {
                let _ = setfacl_remove(grantee_uid, Path::new(&done.path)).await;
            }
            return Err(e).with_context(|| format!("grant {} on {}", entry.perms, entry.path));
        }
        applied.push(entry);
    }
    Ok(())
}

/// Test/convenience wrapper: plan then apply, returning the applied entries.
#[cfg(unix)]
async fn apply_read_grant(
    target: &Path,
    grantee_uid: u32,
    grantee_gid: u32,
    home_boundary: &Path,
) -> Result<Vec<AclEntry>> {
    let entries = plan_read_grant(target, grantee_uid, grantee_gid, home_boundary).await?;
    apply_read_grant_entries(grantee_uid, &entries).await?;
    Ok(entries)
}

/// Whether `uid` (primary group `gid`) can already traverse `dir` without a new
/// ACL entry: via the base `other`/owner/group execute bits, or an existing
/// `user:<uid>:` ACL entry that grants execute. Conservative toward adding: an
/// undetected named-group ACL grant only causes a redundant `--x` entry that is
/// removed on revoke, never a stripped pre-existing permission.
#[cfg(unix)]
async fn dir_allows_traverse(meta: &std::fs::Metadata, dir: &Path, uid: u32, gid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    let mode = meta.mode();
    if mode & 0o001 != 0 {
        return true;
    }
    if meta.uid() == uid && mode & 0o100 != 0 {
        return true;
    }
    if meta.gid() == gid && mode & 0o010 != 0 {
        return true;
    }
    getfacl_user_has_traverse(dir, uid).await
}

/// Parse `getfacl -n` for a `user:<uid>:` entry whose permission triad grants
/// execute. Numeric output (`-n`) avoids name resolution; the owner entry
/// (`user::`) is skipped because the base owner bits are checked separately.
#[cfg(unix)]
async fn getfacl_user_has_traverse(dir: &Path, uid: u32) -> bool {
    let output = Command::new("getfacl")
        .arg("-n")
        .arg("--absolute-names")
        .arg("--")
        .arg(dir)
        .output()
        .await;
    let Ok(output) = output else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let want = uid.to_string();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(3, ':');
        let (Some(kind), Some(qualifier), Some(perms)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if kind == "user" && qualifier == want {
            // perms triad is r,w,x; execute is the third position.
            if perms.as_bytes().get(2) == Some(&b'x') {
                return true;
            }
        }
    }
    false
}

#[cfg(unix)]
async fn setfacl_modify(spec: &str, path: &Path) -> Result<()> {
    let output = Command::new("setfacl")
        .arg("-m")
        .arg(spec)
        .arg("--")
        .arg(path)
        .output()
        .await
        .context("spawn setfacl")?;
    if !output.status.success() {
        bail!(
            "setfacl -m {} {}: {}",
            spec,
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(unix)]
async fn setfacl_remove(uid: u32, path: &Path) -> Result<()> {
    // A deleted target has no ACL left to remove; treat that as done.
    if !path.exists() {
        return Ok(());
    }
    let output = Command::new("setfacl")
        .arg("-x")
        .arg(format!("u:{uid}"))
        .arg("--")
        .arg(path)
        .output()
        .await
        .context("spawn setfacl")?;
    if !output.status.success() {
        bail!(
            "setfacl -x u:{} {}: {}",
            uid,
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Remove exactly the ACL entries a grant recorded, in reverse order (leaf
/// first, then ancestors) so a directory's traverse grant outlives the leaf read
/// grant during teardown. A per-path failure is collected rather than aborting,
/// so one stuck path does not strand the rest.
#[cfg(unix)]
async fn revoke_read_grant_acls(grant: &ReadGrant) -> Result<()> {
    let mut errors = Vec::new();
    for entry in grant.entries.iter().rev() {
        if let Err(e) = setfacl_remove(grant.grantee_uid, Path::new(&entry.path)).await {
            errors.push(format!("{}: {}", entry.path, e));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        bail!("{}", errors.join("; "))
    }
}

/// Run a read grant's revocation and record the outcome. On non-Unix this is a
/// no-op (read grants can only be created on Unix).
async fn finish_read_grant_revert(config: &ServerConfig, grant: &ReadGrant, source: &str) {
    #[cfg(unix)]
    {
        match revoke_read_grant_acls(grant).await {
            Ok(()) => {
                config
                    .read_grants
                    .write()
                    .await
                    .set_revoked(&grant.target_path);
                if let Some(updated) = config.read_grants.read().await.get(&grant.target_path) {
                    persist_read_grant(config, updated).await;
                }
                tracing::info!(
                    "[AUDIT] READ_GRANT_REVOKED handle={} path=\"{}\" source={}",
                    grant.handle,
                    grant.target_path,
                    source
                );
            }
            Err(e) => {
                config
                    .read_grants
                    .write()
                    .await
                    .set_revert_failed(&grant.target_path, e.to_string());
                if let Some(updated) = config.read_grants.read().await.get(&grant.target_path) {
                    persist_read_grant(config, updated).await;
                }
                tracing::warn!(
                    "[AUDIT] READ_GRANT_REVOKE_FAILED handle={} path=\"{}\" source={} detail=\"{}\"",
                    grant.handle,
                    grant.target_path,
                    source,
                    e
                );
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (config, grant, source);
    }
}

async fn persist_read_grant(config: &ServerConfig, g: &ReadGrant) {
    if let Some(store) = &config.session_store {
        if let Err(e) = store.save_read_grant(g.clone()).await {
            tracing::warn!("failed to persist read grant {}: {}", g.target_path, e);
        }
    }
}

async fn delete_read_grant_row(config: &ServerConfig, target_path: &str) {
    if let Some(store) = &config.session_store {
        if let Err(e) = store.delete_read_grant(target_path.to_string()).await {
            tracing::warn!("failed to delete read grant {}: {}", target_path, e);
        }
    }
}

/// The daemon's own principal: its uid on Unix, its process SID on Windows.
/// On Windows, if the SID cannot be resolved (effectively impossible — a
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
        "SSH_AUTH_SOCK",
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
/// target binary — a value under any of these names is code, not data, and
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

/// Allow-list (deny-by-default) check on the ssh options in an invocation.
/// Returns true only when every option is on a small set known to be safe for
/// a read-only diagnostic: no command execution, no agent / X11 / port /
/// socket forwarding, no proxy or jump host, no tunnel, no external config or
/// identity/library file, and no control socket. Any unrecognized option
/// forfeits the fast path to the evaluator.
///
/// The scan covers the whole "option zone", not just the options before the
/// destination. ssh honors options that appear *between* the destination and
/// the remote command (e.g. `ssh host -o ProxyCommand=... id`), so scanning
/// stops only at the command itself — the second positional (non-option)
/// token. Everything from there on is the remote command's own arguments,
/// which ssh does not re-parse as options. (Verified against ssh's own
/// `-G` dry run: an `-o` before the command token is applied; one after it is
/// not.)
///
/// This is intentionally stricter than enumerating dangerous options: an
/// option we have not vetted (including future ssh additions, `-F` external
/// configs, `-I` PKCS#11 modules, `-E`/`-i`/`-S` file paths, and `-o`
/// directives outside the vetted keyword set) never takes the fast path.
/// Combined short flags such as `-Cq` are treated as unrecognized rather than
/// decomposed, again forfeiting to the evaluator.
fn ssh_options_all_readonly_safe(args: &[String]) -> bool {
    // 0 = before the destination, 1 = between destination and remote command.
    let mut positionals_seen = 0;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();

        // A non-option token is either the destination (first) or the start
        // of the remote command (second). Once the command starts, the rest
        // are command arguments that ssh does not treat as options.
        if !arg.starts_with('-') {
            positionals_seen += 1;
            if positionals_seen >= 2 {
                return true;
            }
            i += 1;
            continue;
        }
        // A bare "-" is not a valid ssh option; be conservative.
        if arg == "-" {
            return false;
        }

        // `-o directive` (separate value): only a vetted keyword is allowed.
        if arg == "-o" {
            match args.get(i + 1) {
                Some(value) if ssh_o_directive_readonly_safe(value) => {
                    i += 2;
                    continue;
                }
                _ => return false,
            }
        }
        // `-oDirective` (concatenated value).
        if let Some(value) = arg.strip_prefix("-o") {
            if ssh_o_directive_readonly_safe(value) {
                i += 1;
                continue;
            }
            return false;
        }

        // `-p port` / `-l login`: the value is an inert port or username.
        // Consume the value token so it is not mistaken for a positional.
        if arg == "-p" || arg == "-l" {
            if args.get(i + 1).is_none() {
                return false;
            }
            i += 2;
            continue;
        }
        // `-p2222` / `-lroot` (concatenated value).
        if arg.starts_with("-p") || arg.starts_with("-l") {
            i += 1;
            continue;
        }

        // Bare boolean flags known safe for a read-only diagnostic.
        if is_safe_ssh_flag(arg) {
            i += 1;
            continue;
        }

        // Anything else (forwarding, proxy, jump, tunnel, external config or
        // key/library file, control socket, X11, unknown option) forfeits.
        return false;
    }
    true
}

/// Boolean ssh flags that cannot turn a read-only diagnostic into code
/// execution, forwarding, or file indirection: address-family selection,
/// compression, quiet/verbose logging, no-tty, and the *restrictive* toggles
/// that disable agent / X11 / GSSAPI forwarding.
fn is_safe_ssh_flag(arg: &str) -> bool {
    if matches!(arg, "-4" | "-6" | "-C" | "-q" | "-T" | "-a" | "-x" | "-k") {
        return true;
    }
    // Verbosity: `-v`, `-vv`, `-vvv`, ...
    arg.len() >= 2 && arg[1..].bytes().all(|b| b == b'v')
}

/// True only for an `-o keyword[=value]` directive whose keyword is on a small
/// vetted set (batch/non-interactive behavior, connection timeouts, keepalive,
/// and host-key handling). Everything else — ProxyCommand, ProxyJump,
/// LocalCommand, RemoteCommand, *Forward, Tunnel, Include, IdentityFile,
/// ControlPath, and any unknown keyword — is rejected. A value containing a
/// newline is rejected outright so a second directive cannot be introduced on
/// a later line past the first-keyword check.
fn ssh_o_directive_readonly_safe(value: &str) -> bool {
    if value.contains('\n') || value.contains('\r') {
        return false;
    }
    let lower = value.trim_start().to_ascii_lowercase();
    let mut parts = lower
        .split(|ch: char| ch == '=' || ch.is_whitespace())
        .filter(|part| !part.is_empty());
    let key = parts.next().unwrap_or("");
    let directive_value = parts.next().unwrap_or("");
    match key {
        "batchmode"
        | "connecttimeout"
        | "connectionattempts"
        | "serveraliveinterval"
        | "serveralivecountmax"
        | "updatehostkeys"
        | "checkhostip" => true,
        // Host-key checking is permitted only in its security-preserving
        // forms. Disabling it (`no`/`off`) or deferring to an interactive
        // prompt (`ask`) would let an interposed relay alter the
        // diagnostic's output, so those forfeit to the evaluator rather than
        // taking the deterministic fast path. An empty value falls back to
        // ssh's strict default, which is safe.
        "stricthostkeychecking" => matches!(directive_value, "yes" | "accept-new" | ""),
        _ => false,
    }
}

/// True only for an exact, whole read-only diagnostic command (no shell
/// control, no arguments beyond a fixed safe flag). Anything else returns
/// false and falls back to the model.
fn is_fixed_readonly_diagnostic(command: &str) -> bool {
    if contains_shell_control(command) {
        return false;
    }
    let lower = command.trim().to_ascii_lowercase();
    let tokens = command_tokens(&lower);
    if tokens.is_empty() {
        return false;
    }

    matches!(
        tokens.as_slice(),
        [cmd] if matches!(cmd.as_str(), "id" | "whoami" | "hostname" | "uptime")
    ) || matches!(
        tokens.as_slice(),
        [cmd, flag] if cmd == "uname" && matches!(flag.as_str(), "-a" | "-r" | "-sr")
    ) || matches!(
        tokens.as_slice(),
        [cmd, flag] if cmd == "df" && matches!(flag.as_str(), "-h" | "-hi")
    )
}

fn contains_shell_control(command: &str) -> bool {
    command.contains(';')
        || command.contains("&&")
        || command.contains("||")
        || command.contains('|')
        || command.contains('>')
        || command.contains('<')
        || command.contains('`')
        || command.contains("$(")
        || command.contains('\n')
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
        if dangerous_env_name(key) {
            return Err(format!(
                "dangerous injected environment variable name: '{}'",
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

    let principal = match caller.principal() {
        Some(principal) if caller.is_local_peer() => principal,
        _ => {
            if !request.secrets.is_empty() {
                return Err("secret injection requires an authenticated local caller".to_string());
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
                        return ExecuteResult::exec_failed_after_start(
                            allow_reason,
                            format!("client stream error: {}", e),
                        );
                    }
                    }
                    None => break,
                }
            }
            _ = keepalive.tick() => {
                if let Err(e) = write_stream_message(writer, &ExecuteStreamMessage::Keepalive).await {
                    let _ = child.kill().await;
                    return ExecuteResult::exec_failed_after_start(
                        allow_reason,
                        format!("client stream error: {}", e),
                    );
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
    admin_token: Option<String>,
    session_token: Option<String>,
    /// Consequence-gating options carried onto each `guard run` request.
    revert: Option<RevertSpec>,
    confirm_within_secs: Option<u64>,
    require_approval: bool,
    wait_approval_secs: Option<u64>,
    verb: Option<VerbInvocation>,
    reevaluate: bool,
    ssh_hostkey: Option<SshHostKeyMode>,
}

impl Client {
    pub fn new(socket_path: Option<PathBuf>, tcp_port: Option<u16>) -> Self {
        Self {
            socket_path,
            tcp_port,
            auth_token: None,
            admin_token: None,
            session_token: None,
            revert: None,
            confirm_within_secs: None,
            require_approval: false,
            wait_approval_secs: None,
            verb: None,
            reevaluate: false,
            ssh_hostkey: None,
        }
    }

    /// Invoke a catalog verb instead of a raw binary.
    pub fn with_verb(mut self, verb: VerbInvocation) -> Self {
        self.verb = Some(verb);
        self
    }

    /// Skip the auto-learned deny-shape fast path for this client's requests
    /// and force a fresh LLM call. Never skips an operator-authored
    /// `PolicyEngine` deny rule.
    pub fn with_reevaluate(mut self, reevaluate: bool) -> Self {
        self.reevaluate = reevaluate;
        self
    }

    /// Set the ssh host-key mode carried onto each `guard run` request. Only
    /// affects ssh commands; the daemon injects the corresponding `-o` options
    /// server-side before evaluation and execution.
    pub fn with_hostkey(mut self, mode: SshHostKeyMode) -> Self {
        self.ssh_hostkey = Some(mode);
        self
    }

    pub fn with_auth(mut self, token: String) -> Self {
        self.auth_token = Some(token);
        self
    }

    pub fn with_admin_token(mut self, token: String) -> Self {
        self.admin_token = Some(token);
        self
    }

    pub fn with_session(mut self, session_token: String) -> Self {
        self.session_token = Some(session_token);
        self
    }

    /// Attach consequence-gating options for `guard run` (rollback command,
    /// auto-revert window, force-approval, and a blocking wait-for-approval).
    pub fn with_gating(
        mut self,
        revert: Option<RevertSpec>,
        confirm_within_secs: Option<u64>,
        require_approval: bool,
        wait_approval_secs: Option<u64>,
    ) -> Self {
        self.revert = revert;
        self.confirm_within_secs = confirm_within_secs;
        self.require_approval = require_approval;
        self.wait_approval_secs = wait_approval_secs;
        self
    }

    pub async fn send_admin(&self, request: AdminRequest) -> Result<AdminResponse> {
        let request_name = match &request {
            AdminRequest::SessionGrant { .. } => "session_grant",
            AdminRequest::SessionAppeal { .. } => "session_appeal",
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
            AdminRequest::Confirm { .. } => "confirm",
            AdminRequest::Revert { .. } => "revert",
            AdminRequest::Provisionals => "provisionals",
            AdminRequest::Approve { .. } => "approve",
            AdminRequest::Deny { .. } => "deny",
            AdminRequest::ApprovalList => "approval_list",
            AdminRequest::ApprovalShow { .. } => "approval_show",
            AdminRequest::ApprovalNote { .. } => "approval_note",
            AdminRequest::VerbList => "verb_list",
            AdminRequest::VerbCreate { .. } => "verb_create",
        };
        let envelope = IncomingMessage::Admin {
            admin: request,
            admin_token: self.admin_token.clone(),
        };
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
            self.send_local(socket_path, &request).await
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
            self.send_local_streaming(socket_path, &request, &mut on_output)
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
            revert: self.revert.clone(),
            confirm_within_secs: self.confirm_within_secs,
            require_approval: if self.require_approval {
                Some(true)
            } else {
                None
            },
            wait_approval_secs: self.wait_approval_secs,
            verb: self.verb.clone(),
            reevaluate: self.reevaluate,
            ssh_hostkey: self.ssh_hostkey,
        }
    }

    /// Send a filesystem read-grant request (grant or revoke) and return the
    /// server's `ExecuteResponse`. Routed as its own `IncomingMessage::Grant`
    /// envelope, but evaluated server-side through the same policy pipeline as a
    /// command; the daemon requires a local Unix socket peer.
    pub async fn grant(&self, grant: GrantRequest) -> Result<ExecuteResponse> {
        let envelope = IncomingMessage::Grant { grant };
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
            serde_json::from_str(&response_line).context("invalid server response")
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
            serde_json::from_str(&response_line).context("invalid server response")
        } else {
            anyhow::bail!("no socket path or TCP port configured");
        }
    }

    async fn send_local(
        &self,
        socket_path: &Path,
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

    async fn send_local_streaming<F>(
        &self,
        socket_path: &Path,
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

    // ---- Audit-line redaction helpers ---------------------------------------

    /// Argv rendered into audit lines must have inline credentials masked:
    /// the log records the command shape, never the secret values.
    #[test]
    fn audit_command_line_masks_inline_credentials() {
        let line = audit_command_line(
            "mysql",
            &[
                "-u".to_string(),
                "root".to_string(),
                "--password=hunter2sekrit".to_string(),
            ],
        );
        assert!(!line.contains("hunter2sekrit"), "got: {line}");
        assert!(line.contains("mysql"), "command shape survives: {line}");

        let line = audit_command_line(
            "curl",
            &[
                "-H".to_string(),
                "Authorization: Bearer sk-live-abcdef1234567890".to_string(),
                "https://api.example.com".to_string(),
            ],
        );
        assert!(!line.contains("sk-live-abcdef1234567890"), "got: {line}");
        assert!(line.contains("curl"), "got: {line}");
    }

    /// Tokens in audit lines are truncated head/tail; short and multi-byte
    /// values must not panic or leak.
    #[test]
    fn audit_token_truncates_and_is_char_safe() {
        assert_eq!(audit_token("abcdefghij"), "abcd...ghij");
        assert_eq!(audit_token("short"), "***");
        // Multi-byte chars: byte slicing would panic here.
        let t = audit_token("éééééééééé");
        assert!(t.starts_with("éééé"), "got: {t}");
        assert!(!t.contains("éééééééééé"), "full value never appears: {t}");
    }

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
            ExecOutcome::Failed { reason, .. } => {
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

    #[cfg(windows)]
    #[test]
    fn binary_path_candidates_include_windows_pathext() {
        let candidates = binary_path_candidates(std::path::Path::new("C:\\Tools"), "ssh");
        assert!(candidates.iter().any(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.eq_ignore_ascii_case("ssh.exe"))
                .unwrap_or(false)
        }));
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
    fn binary_allowlist_none_allows_everything() {
        assert!(binary_allowed(&None, "kubectl"));
        assert!(binary_allowed(&None, "/tmp/whatever"));
    }

    #[test]
    fn binary_allowlist_matches_bare_name_case_insensitively() {
        let allow = Some(vec!["kubectl".to_string(), "git".to_string()]);
        assert!(binary_allowed(&allow, "kubectl"));
        assert!(binary_allowed(&allow, "KUBECTL"));
        assert!(binary_allowed(&allow, "kubectl.exe"));
        assert!(binary_allowed(&allow, "git"));
        assert!(!binary_allowed(&allow, "helm"));
    }

    #[test]
    fn binary_allowlist_rejects_path_qualified_spoof() {
        // A payload placed at an arbitrary path and named after an allowed tool
        // must NOT pass via basename matching; only an exact path entry allows
        // a path-qualified binary.
        let allow = Some(vec!["kubectl".to_string()]);
        assert!(!binary_allowed(&allow, "/tmp/evil/kubectl"));
        assert!(!binary_allowed(&allow, "./kubectl"));
        assert!(!binary_allowed(&allow, r"C:\tmp\kubectl.exe"));

        let allow_path = Some(vec!["/usr/bin/kubectl".to_string()]);
        assert!(binary_allowed(&allow_path, "/usr/bin/kubectl"));
        assert!(!binary_allowed(&allow_path, "kubectl"));
        assert!(!binary_allowed(&allow_path, "/tmp/kubectl"));
    }

    #[test]
    fn binary_allowlist_empty_denies_everything() {
        let allow = Some(vec![]);
        assert!(!binary_allowed(&allow, "kubectl"));
        assert!(!binary_allowed(&allow, "/usr/bin/anything"));
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
            revert: None,
            confirm_within_secs: None,
            reevaluate: false,
            ssh_hostkey: None,
            require_approval: None,
            wait_approval_secs: None,
            verb: None,
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

    #[test]
    fn is_local_peer_excludes_tcp_and_unknown() {
        assert!(CallerIdentity::Unix { uid: 0 }.is_local_peer());
        assert!(!CallerIdentity::Tcp { token: "t".into() }.is_local_peer());
        assert!(!CallerIdentity::TcpAdmin { token: "t".into() }.is_local_peer());
        assert!(!CallerIdentity::Unknown.is_local_peer());
        #[cfg(windows)]
        assert!(CallerIdentity::Windows {
            sid: "S-1-5-18".into()
        }
        .is_local_peer());
    }

    #[test]
    fn exec_failed_constructors_set_started_flag() {
        // Spawn/setup failure: the child never ran -> the containment envelope
        // drops the provisional (nothing to revert).
        let pre = ExecuteResult::exec_failed("allowed", "ENOENT");
        assert!(matches!(
            pre.exec,
            ExecOutcome::Failed { started: false, .. }
        ));
        // Failure after the child was launched (e.g. client stream dropped):
        // the mutation may have applied -> keep the auto-revert armed.
        let post = ExecuteResult::exec_failed_after_start("allowed", "client stream error");
        assert!(matches!(
            post.exec,
            ExecOutcome::Failed { started: true, .. }
        ));
    }

    #[cfg(windows)]
    #[test]
    fn reconstruct_caller_round_trips_windows_sid() {
        let sid = "S-1-5-21-1-2-3-1001";
        let rebuilt =
            reconstruct_caller(Some(PrincipalKey::from_sid(sid)), &CallerIdentity::Unknown);
        assert!(matches!(rebuilt, CallerIdentity::Windows { sid: s } if s == sid));
    }

    #[cfg(windows)]
    #[test]
    fn pipe_name_normalizes_bare_name() {
        assert_eq!(
            winplat::pipe_name(std::path::Path::new("guard")),
            r"\\.\pipe\guard"
        );
    }

    #[tokio::test]
    async fn injection_refuses_non_local_tcp_caller() {
        let (cfg, _) = make_test_config();
        let request = ExecuteRequest {
            binary: "echo".to_string(),
            args: vec!["ok".to_string()],
            auth_token: None,
            env: HashMap::new(),
            secrets: HashMap::from([("API_TOKEN".to_string(), "api/token".to_string())]),
            stream: false,
            session_token: None,
            revert: None,
            confirm_within_secs: None,
            reevaluate: false,
            ssh_hostkey: None,
            require_approval: None,
            wait_approval_secs: None,
            verb: None,
        };
        // A bearer-token TCP caller carries a token principal but is NOT a
        // kernel-verified local peer; secret/env injection must be refused so a
        // remote token-holder cannot control the child's environment.
        for caller in [
            CallerIdentity::Tcp {
                token: "exec-token".into(),
            },
            CallerIdentity::TcpAdmin {
                token: "admin-token".into(),
            },
            CallerIdentity::Unknown,
        ] {
            let err = validate_request_injections(&request, &cfg, &caller, "echo ok")
                .await
                .unwrap_err();
            assert!(
                err.contains("authenticated local caller"),
                "caller {caller:?} must be refused injection, got: {err}"
            );
        }
        // A local Unix caller passes the transport check (it fails later only if
        // the secret is absent, never with the local-caller refusal).
        if let Err(e) = validate_request_injections(
            &request,
            &cfg,
            &CallerIdentity::Unix { uid: 1000 },
            "echo ok",
        )
        .await
        {
            assert!(
                !e.contains("authenticated local caller"),
                "local caller wrongly refused: {e}"
            );
        }
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
            revert: None,
            confirm_within_secs: None,
            reevaluate: false,
            ssh_hostkey: None,
            require_approval: None,
            wait_approval_secs: None,
            verb: None,
        };

        let result = execute_command(request, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;
        assert!(!result.policy_allowed());
        assert!(result.policy_reason().contains("secret not found"));
    }

    #[tokio::test]
    async fn invalid_secret_shell_reference_denies_before_policy_evaluation() {
        let (cfg, _) = make_test_config();
        cfg.secrets
            .set(
                &PrincipalKey::from_uid(1000),
                "opnsense-apikey-secret",
                "dummy_api_key_12345",
            )
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
            revert: None,
            confirm_within_secs: None,
            reevaluate: false,
            ssh_hostkey: None,
            require_approval: None,
            wait_approval_secs: None,
            verb: None,
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
            None,
            false,
            ToolRegistry::isolated_for_tests(),
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

    fn paranoid_test_config() -> ServerConfig {
        let eval_config = EvalConfig::default()
            .llm_enabled(false)
            .mode(PolicyMode::Paranoid);
        let evaluator = Evaluator::new(eval_config).expect("build evaluator");
        let secrets = SecretManager::with_backend(EnvBackend::default());
        ServerConfig::new(
            None,
            None,
            evaluator,
            secrets,
            false,
            None,
            None,
            None,
            None,
            None,
            false,
            ToolRegistry::isolated_for_tests(),
            Vec::new(),
            false,
            SessionRegistry::new(),
            None,
            false,
            None,
        )
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn dangerous_env_name_blocks_code_injection_vectors() {
        for name in [
            "LD_PRELOAD",
            "ld_preload",
            "BASH_ENV",
            "GIT_SSH_COMMAND",
            "PYTHONPATH",
            "NODE_OPTIONS",
            "LD_AUDIT",
            "LD_AUDIT_2",
            "GIT_CONFIG_KEY_0",
            "GIT_CONFIG_VALUE_0",
            "DYLD_INSERT_LIBRARIES",
        ] {
            assert!(dangerous_env_name(name), "{name} must be blocked");
        }
        for name in ["PATH", "HOME", "AWS_PROFILE", "MY_TOKEN", "GIT_AUTHOR_NAME"] {
            assert!(!dangerous_env_name(name), "{name} must be allowed");
        }
    }

    #[test]
    fn safe_allow_accepts_fixed_local_identity() {
        let (cfg, _buf) = make_test_config();
        assert!(deterministic_safe_allow_reason(&cfg, "id", &[]).is_some());
        assert!(deterministic_safe_allow_reason(&cfg, "whoami", &[]).is_some());
        assert!(deterministic_safe_allow_reason(&cfg, "hostname", &[]).is_some());
        assert!(deterministic_safe_allow_reason(&cfg, "uptime", &[]).is_some());
        // A non-fixed local command falls through to the LLM.
        assert!(deterministic_safe_allow_reason(&cfg, "cat", &args(&["/etc/passwd"])).is_none());
    }

    #[test]
    fn safe_allow_disabled_in_paranoid_mode() {
        let cfg = paranoid_test_config();
        assert!(deterministic_safe_allow_reason(&cfg, "id", &[]).is_none());
    }

    #[test]
    fn safe_allow_accepts_fixed_ssh_diagnostic() {
        let (cfg, _buf) = make_test_config();
        let reason = deterministic_safe_allow_reason(&cfg, "ssh", &args(&["host01", "id"]));
        assert!(reason.is_some(), "fixed ssh diagnostic should be allowed");
    }

    fn ssh_request(mode: Option<SshHostKeyMode>, argv: &[&str]) -> ExecuteRequest {
        ExecuteRequest {
            binary: "ssh".to_string(),
            args: args(argv),
            auth_token: None,
            env: HashMap::new(),
            secrets: HashMap::new(),
            stream: false,
            session_token: None,
            revert: None,
            confirm_within_secs: None,
            require_approval: None,
            wait_approval_secs: None,
            verb: None,
            reevaluate: false,
            ssh_hostkey: mode,
        }
    }

    #[test]
    fn apply_ssh_hostkey_injects_options_by_mode() {
        // OnlyExisting / absent: no change, ssh keeps its strict default.
        for mode in [None, Some(SshHostKeyMode::OnlyExisting)] {
            let mut req = ssh_request(mode, &["host01", "id"]);
            req.apply_ssh_hostkey_options();
            assert_eq!(req.args, args(&["host01", "id"]), "mode {mode:?}");
        }

        // AcceptNew prepends accept-new + UpdateHostKeys ahead of the host.
        let mut req = ssh_request(Some(SshHostKeyMode::AcceptNew), &["host01", "id"]);
        req.apply_ssh_hostkey_options();
        assert_eq!(
            req.args,
            args(&[
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-o",
                "UpdateHostKeys=yes",
                "host01",
                "id",
            ])
        );

        // AcceptAll gives up host verification.
        let mut req = ssh_request(Some(SshHostKeyMode::AcceptAll), &["host01", "id"]);
        req.apply_ssh_hostkey_options();
        assert_eq!(
            req.args,
            args(&[
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "host01",
                "id",
            ])
        );
    }

    #[test]
    fn apply_ssh_hostkey_is_noop_for_non_ssh() {
        let mut req = ssh_request(Some(SshHostKeyMode::AcceptAll), &["get", "pods"]);
        req.binary = "kubectl".to_string();
        req.apply_ssh_hostkey_options();
        assert_eq!(req.args, args(&["get", "pods"]));
    }

    #[test]
    fn accept_new_hostkey_keeps_fixed_diagnostic_on_fast_path() {
        // The options accept-new injects are allow-listed, so a fixed
        // diagnostic still qualifies for the deterministic fast path.
        let (cfg, _buf) = make_test_config();
        let mut req = ssh_request(Some(SshHostKeyMode::AcceptNew), &["host01", "id"]);
        req.apply_ssh_hostkey_options();
        assert!(deterministic_safe_allow_reason(&cfg, "ssh", &req.args).is_some());
    }

    #[test]
    fn accept_all_hostkey_forfeits_fast_path() {
        // accept-all injects StrictHostKeyChecking=no, which the option
        // allow-list rejects, so even a fixed diagnostic forfeits to the
        // evaluator rather than auto-allowing over an unauthenticated channel.
        let (cfg, _buf) = make_test_config();
        let mut req = ssh_request(Some(SshHostKeyMode::AcceptAll), &["host01", "id"]);
        req.apply_ssh_hostkey_options();
        assert!(deterministic_safe_allow_reason(&cfg, "ssh", &req.args).is_none());
    }

    #[test]
    fn safe_allow_rejects_ssh_arbitrary_remote_command() {
        let (cfg, _buf) = make_test_config();
        assert!(
            deterministic_safe_allow_reason(&cfg, "ssh", &args(&["host01", "rm", "-rf", "/"]))
                .is_none()
        );
    }

    #[test]
    fn safe_allow_rejects_ssh_chained_remote_command() {
        let (cfg, _buf) = make_test_config();
        assert!(
            deterministic_safe_allow_reason(&cfg, "ssh", &args(&["host01", "id; rm -rf /"]))
                .is_none()
        );
    }

    #[test]
    fn ssh_options_allow_list_permits_only_vetted_options() {
        // Options a read-only diagnostic may legitimately carry, in both the
        // separate-value and concatenated forms.
        for ok in [
            &["host01", "id"][..],
            &["-4", "host01", "id"][..],
            &["-6", "-C", "-q", "host01", "id"][..],
            &["-v", "host01", "id"][..],
            &["-vvv", "host01", "id"][..],
            &["-T", "-a", "-x", "-k", "host01", "id"][..],
            &["-p", "2222", "host01", "id"][..],
            &["-p2222", "host01", "id"][..],
            &["-l", "root", "host01", "id"][..],
            &["-lroot", "host01", "id"][..],
            &["-o", "ConnectTimeout=5", "host01", "id"][..],
            &["-o", "BatchMode=yes", "host01", "id"][..],
            &["-oConnectTimeout=5", "host01", "id"][..],
            // Host-key handling injected by the --hostkey mode must not
            // knock the diagnostic off the fast path.
            &[
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-o",
                "UpdateHostKeys=yes",
                "host01",
                "id",
            ][..],
        ] {
            assert!(
                ssh_options_all_readonly_safe(&args(ok)),
                "options should be allow-listed: {ok:?}"
            );
        }

        // Every unvetted option forfeits the fast path. This covers the
        // classes an allow-list must reject: forwarding, proxy/jump, tunnel,
        // external config (-F) and PKCS#11 module (-I), identity/log/socket
        // files, and any -o directive outside the vetted keyword set.
        for bad in [
            &["-A", "host01", "id"][..],
            &["-X", "host01", "id"][..],
            &["-Y", "host01", "id"][..],
            &["-L", "8080:localhost:80", "host01", "id"][..],
            &["-R", "9000:localhost:22", "host01", "id"][..],
            &["-D", "1080", "host01", "id"][..],
            &["-W", "host:22", "host01", "id"][..],
            &["-J", "jump", "host01", "id"][..],
            &["-F", "/tmp/evil_ssh_config", "host01", "id"][..],
            &["-I", "/tmp/pkcs11.so", "host01", "id"][..],
            &["-E", "/tmp/log", "host01", "id"][..],
            &["-i", "/tmp/key", "host01", "id"][..],
            &["-S", "/tmp/ctl.sock", "host01", "id"][..],
            &["-o", "ProxyCommand=nc x 22", "host01", "id"][..],
            &["-oProxyJump=jump", "host01", "id"][..],
            &["-o", "LocalCommand=touch /tmp/x", "host01", "id"][..],
            &["-o", "RemoteCommand=cat /etc/shadow", "host01", "id"][..],
            &["-o", "PermitLocalCommand=yes", "host01", "id"][..],
            &["-o", "Include=/tmp/evil", "host01", "id"][..],
            // Combined short flags are not decomposed; forfeit conservatively.
            &["-Cq", "host01", "id"][..],
            // A value option with no following value is malformed; forfeit.
            &["-p"][..],
            &["host01", "-l"][..],
        ] {
            assert!(
                !ssh_options_all_readonly_safe(&args(bad)),
                "option should forfeit the fast path: {bad:?}"
            );
        }
    }

    #[test]
    fn ssh_options_reject_dangerous_option_between_host_and_command() {
        // ssh honors options placed between the destination and the remote
        // command (confirmed against `ssh -G`), so the allow-list must scan
        // past the destination up to the command token. A proxy/forward/jump
        // in that position must forfeit the fast path.
        for bad in [
            &["host01", "-o", "ProxyCommand=nc x 22", "id"][..],
            &["host01", "-L", "8080:localhost:80", "id"][..],
            &["host01", "-J", "jump", "id"][..],
            &["host01", "-oProxyJump=jump", "id"][..],
            &["host01", "-F", "/tmp/evil_ssh_config", "id"][..],
        ] {
            assert!(
                !ssh_options_all_readonly_safe(&args(bad)),
                "option between host and command must forfeit: {bad:?}"
            );
        }
        // An option that appears *after* the command token is a command
        // argument, not an ssh option, and ssh does not re-parse it; it does
        // not affect the fast-path decision for the (fixed) command itself.
        assert!(ssh_options_all_readonly_safe(&args(&[
            "host01",
            "id",
            "-o",
            "ProxyCommand=nc x 22"
        ])));
    }

    #[test]
    fn ssh_o_directive_rejects_newline_smuggled_second_directive() {
        // A single -o value carrying a second directive on a later line must
        // be rejected outright rather than inspected only up to its first
        // keyword.
        assert!(!ssh_o_directive_readonly_safe(
            "ConnectTimeout=5\nProxyCommand=nc attacker 22"
        ));
        assert!(!ssh_o_directive_readonly_safe(
            "BatchMode=yes\rLocalCommand=touch /tmp/x"
        ));
        assert!(!ssh_options_all_readonly_safe(&args(&[
            "-o",
            "ConnectTimeout=5\nProxyCommand=nc x 22",
            "host01",
            "id"
        ])));
        // The same keyword without a newline stays on the fast path.
        assert!(ssh_o_directive_readonly_safe("ConnectTimeout=5"));
    }

    #[test]
    fn ssh_o_stricthostkeychecking_permits_only_secure_values() {
        // Security-preserving values keep the fast path (accept-new is what
        // the --hostkey mode injects).
        assert!(ssh_o_directive_readonly_safe("StrictHostKeyChecking=yes"));
        assert!(ssh_o_directive_readonly_safe(
            "StrictHostKeyChecking=accept-new"
        ));
        // Disabling or deferring host-key verification forfeits to the
        // evaluator rather than auto-allowing over an unauthenticated channel.
        for weak in [
            "StrictHostKeyChecking=no",
            "StrictHostKeyChecking=off",
            "StrictHostKeyChecking=ask",
            "stricthostkeychecking no",
        ] {
            assert!(
                !ssh_o_directive_readonly_safe(weak),
                "{weak} should forfeit the fast path"
            );
        }
        // And the whole invocation forfeits when the caller disables it.
        let (cfg, _buf) = make_test_config();
        assert!(deterministic_safe_allow_reason(
            &cfg,
            "ssh",
            &args(&["-o", "StrictHostKeyChecking=no", "host01", "id"])
        )
        .is_none());
    }

    #[test]
    fn safe_allow_rejects_ssh_forwarding_and_proxy() {
        let (cfg, _buf) = make_test_config();
        for reject in [
            &["-L", "8080:localhost:80", "host01", "id"][..],
            &["-A", "host01", "id"][..],
            &["-o", "ProxyCommand=nc x 22", "host01", "id"][..],
            &["-oProxyJump=jump", "host01", "id"][..],
            &["-F", "/tmp/evil_ssh_config", "host01", "id"][..],
        ] {
            assert!(
                deterministic_safe_allow_reason(&cfg, "ssh", &args(reject)).is_none(),
                "ssh with {reject:?} must not take the fast path"
            );
        }
        // A benign, vetted option still allows the fixed diagnostic.
        assert!(deterministic_safe_allow_reason(
            &cfg,
            "ssh",
            &args(&["-o", "ConnectTimeout=5", "host01", "id"])
        )
        .is_some());
    }

    #[test]
    fn is_fixed_readonly_diagnostic_is_narrow() {
        assert!(is_fixed_readonly_diagnostic("id"));
        assert!(is_fixed_readonly_diagnostic("uname -a"));
        assert!(is_fixed_readonly_diagnostic("df -h"));
        assert!(!is_fixed_readonly_diagnostic("id && rm -rf /"));
        assert!(!is_fixed_readonly_diagnostic("cat /etc/shadow"));
        assert!(!is_fixed_readonly_diagnostic("uname -a; whoami"));
        assert!(!is_fixed_readonly_diagnostic(""));
    }

    /// Trusted-verb + consequence-gate interaction: `trusted` only skips the
    /// LLM evaluator (`bypass: false` in the `GateInputs` built for it,
    /// see `execute_command_inner`); it must NOT also skip consequence
    /// routing. An irreversible trusted verb must still be held for operator
    /// approval, never executed immediately, even though it never went
    /// through the LLM.
    #[tokio::test]
    async fn trusted_verb_irreversible_still_holds_for_approval() {
        let (mut cfg, _buf) = make_test_config();
        cfg.gate = GateMode::Consequence;
        let catalog = VerbCatalog::from_yaml(
            "verbs:\n  - name: danger-op\n    binary: true\n    consequence: irreversible\n    trusted: true\n",
        )
        .unwrap();
        cfg.verbs = Arc::new(RwLock::new(catalog));

        let request = ExecuteRequest {
            binary: String::new(),
            args: Vec::new(),
            auth_token: None,
            env: HashMap::new(),
            secrets: HashMap::new(),
            stream: false,
            session_token: None,
            revert: None,
            confirm_within_secs: None,
            reevaluate: false,
            ssh_hostkey: None,
            require_approval: None,
            wait_approval_secs: None,
            verb: Some(VerbInvocation {
                name: "danger-op".to_string(),
                params: std::collections::BTreeMap::new(),
            }),
        };

        let result = execute_command(request, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;
        let response = result.into_response();
        assert!(response.allowed, "a held command is still policy-allowed");
        assert_eq!(
            response.status,
            Some(GateStatus::Held),
            "a trusted verb declared irreversible must be held, not executed, despite skipping \
             the LLM: got {:?}",
            response.status
        );
        assert!(
            response.exit_code.is_none(),
            "a held command must not have run"
        );
    }

    /// The other half of the same interaction: a trusted verb declared
    /// reversible with a low (verb-forced) risk of 0 clears the gate at
    /// execute-now, exactly like an LLM-approved reversible command would.
    #[tokio::test]
    async fn trusted_verb_reversible_executes_now() {
        let (mut cfg, _buf) = make_test_config();
        cfg.gate = GateMode::Consequence;
        let catalog = VerbCatalog::from_yaml(
            "verbs:\n  - name: safe-op\n    binary: true\n    consequence: reversible\n    trusted: true\n",
        )
        .unwrap();
        cfg.verbs = Arc::new(RwLock::new(catalog));

        let request = ExecuteRequest {
            binary: String::new(),
            args: Vec::new(),
            auth_token: None,
            env: HashMap::new(),
            secrets: HashMap::new(),
            stream: false,
            session_token: None,
            revert: None,
            confirm_within_secs: None,
            reevaluate: false,
            ssh_hostkey: None,
            require_approval: None,
            wait_approval_secs: None,
            verb: Some(VerbInvocation {
                name: "safe-op".to_string(),
                params: std::collections::BTreeMap::new(),
            }),
        };

        let result = execute_command(request, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;
        let response = result.into_response();
        assert!(response.allowed);
        assert!(
            response.status.is_none() || response.status == Some(GateStatus::Executed),
            "a trusted reversible verb should execute immediately, got {:?}",
            response.status
        );
        assert_eq!(
            response.exit_code,
            Some(0),
            "the verb should have actually run"
        );
    }

    /// A raw command (no explicit `--verb` invocation) that happens to match
    /// a catalog verb's template picks up the verb's declared class and trust
    /// the same way an explicit invocation would (`VerbCatalog::match_command`),
    /// as long as the verb's trust is current (see the next test for the
    /// stale case). This is what makes a catalog useful for gating a tool a
    /// caller invokes normally, rather than only via `--verb name`.
    #[tokio::test]
    async fn raw_command_reverse_matches_trusted_verb_and_executes_now() {
        let (mut cfg, _buf) = make_test_config();
        cfg.gate = GateMode::Consequence;
        let catalog = VerbCatalog::from_yaml(
            "verbs:\n  - name: safe-op\n    binary: true\n    consequence: reversible\n    trusted: true\n",
        )
        .unwrap();
        cfg.verbs = Arc::new(RwLock::new(catalog));

        let request = ExecuteRequest {
            binary: "true".to_string(),
            args: Vec::new(),
            auth_token: None,
            env: HashMap::new(),
            secrets: HashMap::new(),
            stream: false,
            session_token: None,
            revert: None,
            confirm_within_secs: None,
            reevaluate: false,
            ssh_hostkey: None,
            require_approval: None,
            wait_approval_secs: None,
            verb: None,
        };

        let result = execute_command(request, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;
        let response = result.into_response();
        assert!(
            response.allowed,
            "a raw command matching a trusted verb's template should be allowed"
        );
        assert_eq!(
            response.exit_code,
            Some(0),
            "should have executed immediately via the reverse-matched trusted verb"
        );
    }

    /// An auto-promoted verb (`gating::allow_promotion`) is trusted only as
    /// long as its `promotion_stamp` matches the daemon's current model +
    /// prompt stamp. A stale stamp must downgrade `trusted` to false rather
    /// than continuing to trust a judgment made under a since-changed
    /// evaluator -- with the LLM disabled and no static policy in this test
    /// config, that downgrade is observable as a default-deny instead of an
    /// immediate execution.
    #[tokio::test]
    async fn stale_auto_promoted_verb_is_not_trusted() {
        let (mut cfg, _buf) = make_test_config();
        cfg.gate = GateMode::Consequence;
        let catalog = VerbCatalog::from_yaml(
            "verbs:\n  - name: auto-op\n    binary: true\n    consequence: reversible\n    \
             trusted: true\n    auto_promoted: true\n    promotion_stamp: definitely-stale\n",
        )
        .unwrap();
        cfg.verbs = Arc::new(RwLock::new(catalog));
        assert_ne!(
            cfg.evaluator.verb_promotion_stamp(),
            "definitely-stale",
            "the fixture stamp must not accidentally collide with a real stamp"
        );

        let request = ExecuteRequest {
            binary: "true".to_string(),
            args: Vec::new(),
            auth_token: None,
            env: HashMap::new(),
            secrets: HashMap::new(),
            stream: false,
            session_token: None,
            revert: None,
            confirm_within_secs: None,
            reevaluate: false,
            ssh_hostkey: None,
            require_approval: None,
            wait_approval_secs: None,
            verb: None,
        };

        let result = execute_command(request, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;
        let response = result.into_response();
        assert!(
            !response.allowed,
            "a stale auto-promoted verb must not skip the LLM (denied here since the test \
             evaluator has the LLM disabled and no static policy): got {:?}",
            response
        );
    }

    /// `guard verb list` must not misrepresent a stale auto-promoted verb as
    /// still trusted: its reported `trusted` field has to reflect the same
    /// staleness check `execute_command_inner` applies, not the catalog's raw
    /// `Verb.trusted` flag, or an operator reading the list would believe a
    /// promotion is still fast-pathing when the daemon has actually stopped
    /// honoring it. A current (non-stale, or non-auto-promoted) verb must
    /// still report trusted, and `auto_promoted`/`evidence` must come through.
    #[tokio::test]
    async fn verb_list_reports_staleness_corrected_trust_and_provenance() {
        let (mut cfg, _buf) = make_test_config();
        let current_stamp = cfg.evaluator.verb_promotion_stamp().to_string();
        let catalog = VerbCatalog::from_yaml(&format!(
            "verbs:\n\
             - name: fresh-auto\n  binary: true\n  consequence: reversible\n  trusted: true\n  \
             auto_promoted: true\n  promotion_stamp: {current_stamp}\n  evidence: fresh\n\
             - name: stale-auto\n  binary: true\n  consequence: reversible\n  trusted: true\n  \
             auto_promoted: true\n  promotion_stamp: definitely-stale\n  evidence: stale\n\
             - name: hand-authored\n  binary: true\n  consequence: reversible\n  trusted: true\n"
        ))
        .unwrap();
        cfg.verbs = Arc::new(RwLock::new(catalog));

        let response = handle_admin_request(
            &cfg,
            &CallerIdentity::Unix { uid: 1000 },
            AdminRequest::VerbList,
        )
        .await;
        let AdminResponse::Verbs { items } = response else {
            panic!("expected Verbs response, got {response:?}");
        };
        let by_name = |name: &str| items.iter().find(|v| v.name == name).unwrap();

        let fresh = by_name("fresh-auto");
        assert!(fresh.trusted, "a current auto-promoted verb stays trusted");
        assert!(fresh.auto_promoted);
        assert_eq!(fresh.evidence.as_deref(), Some("fresh"));

        let stale = by_name("stale-auto");
        assert!(
            !stale.trusted,
            "a stale auto-promoted verb must be reported as untrusted, not just downgraded \
             silently at execution time"
        );
        assert!(stale.auto_promoted);

        let hand = by_name("hand-authored");
        assert!(hand.trusted, "a hand-authored verb has no staleness expiry");
        assert!(!hand.auto_promoted);
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
        cfg.daemon_principal = PrincipalKey::from_uid(777);

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
            cfg.secrets
                .get(&PrincipalKey::from_uid(20_000), &key)
                .await
                .unwrap()
                .as_deref(),
            Some("alice")
        );
        // B's is gone.
        assert_eq!(
            cfg.secrets
                .get(&PrincipalKey::from_uid(20_001), &key)
                .await
                .unwrap(),
            None
        );

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
        cfg.secrets
            .set(&PrincipalKey::from_uid(30_000), &key, "alice-value")
            .await
            .unwrap();

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
            revert: None,
            confirm_within_secs: None,
            reevaluate: false,
            ssh_hostkey: None,
            require_approval: None,
            wait_approval_secs: None,
            verb: None,
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
        let _ = cfg
            .secrets
            .delete(&PrincipalKey::from_uid(30_000), &key)
            .await;
    }

    #[tokio::test]
    async fn extra_child_env_forwards_named_var_to_child() {
        let (mut cfg, _) = make_test_config();
        // The daemon forwards GUARD_CHILD_TEST_PT to children only because it is
        // listed in extra_child_env; the value comes from the daemon's own env.
        std::env::set_var("GUARD_CHILD_TEST_PT", "brokered-value-xyz");
        cfg.extra_child_env = vec!["GUARD_CHILD_TEST_PT".to_string()];

        #[cfg(unix)]
        let (bin, args) = (
            "sh".to_string(),
            vec![
                "-c".to_string(),
                "printf %s \"$GUARD_CHILD_TEST_PT\"".to_string(),
            ],
        );
        #[cfg(windows)]
        let (bin, args) = (
            "cmd".to_string(),
            vec!["/c".to_string(), "echo %GUARD_CHILD_TEST_PT%".to_string()],
        );

        let token = format!("child-env-{}", std::process::id());
        {
            let mut sessions = cfg.sessions.write().await;
            sessions.grant(
                token.clone(),
                SessionGrant {
                    allow: vec!["*".into()],
                    deny: Vec::new(),
                    allow_exact: Vec::new(),
                    deny_exact: Vec::new(),
                    expires_at: None,
                    prompt_append: None,
                    generated_notes: Vec::new(),
                    static_only: true,
                    auto_amend: false,
                    granted_at: 0,
                },
            );
        }
        let req = ExecuteRequest {
            binary: bin,
            args,
            auth_token: None,
            env: HashMap::new(),
            secrets: HashMap::new(),
            stream: false,
            session_token: Some(token),
            revert: None,
            confirm_within_secs: None,
            reevaluate: false,
            ssh_hostkey: None,
            require_approval: None,
            wait_approval_secs: None,
            verb: None,
        };
        let result = execute_command(req, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;
        match &result.exec {
            ExecOutcome::Completed { stdout, .. } => assert!(
                stdout
                    .as_deref()
                    .unwrap_or_default()
                    .contains("brokered-value-xyz"),
                "child did not receive the forwarded var; stdout={:?}",
                stdout
            ),
            other => panic!("expected Completed, got {:?}", other),
        }
        std::env::remove_var("GUARD_CHILD_TEST_PT");
    }

    #[tokio::test]
    async fn static_only_session_miss_denies_before_evaluator() {
        let (cfg, _) = make_test_config();
        let token = format!("static-only-{}", std::process::id());
        {
            let mut sessions = cfg.sessions.write().await;
            sessions.grant(
                token.clone(),
                SessionGrant {
                    allow: vec!["kubectl -n grafana get pods*".into()],
                    deny: Vec::new(),
                    allow_exact: Vec::new(),
                    deny_exact: Vec::new(),
                    expires_at: None,
                    prompt_append: None,
                    generated_notes: Vec::new(),
                    static_only: true,
                    auto_amend: false,
                    granted_at: 0,
                },
            );
        }

        let req = ExecuteRequest {
            binary: "kubectl".to_string(),
            args: vec!["get".into(), "pods".into(), "-n".into(), "default".into()],
            auth_token: None,
            env: HashMap::new(),
            secrets: HashMap::new(),
            stream: false,
            session_token: Some(token),
            revert: None,
            confirm_within_secs: None,
            reevaluate: false,
            ssh_hostkey: None,
            require_approval: None,
            wait_approval_secs: None,
            verb: None,
        };

        let result = execute_command(req, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;
        assert!(!result.policy_allowed());
        assert!(result.policy_reason().contains("static-only"));
    }

    #[test]
    fn session_auto_amend_allow_candidates_are_low_risk_and_simple() {
        assert!(allow_session_auto_amend_candidate("echo", &["ok".into()], Some(2)).is_ok());
        assert!(allow_session_auto_amend_candidate("echo", &["ok".into()], Some(3)).is_err());
        assert!(allow_session_auto_amend_candidate(
            "sh",
            &["-c".into(), "id; whoami".into()],
            Some(1)
        )
        .is_err());
        assert!(
            allow_session_auto_amend_candidate("cat", &["/etc/shadow".into()], Some(1)).is_err()
        );
    }

    #[test]
    fn session_auto_amend_deny_candidates_are_high_risk_exact_rules() {
        assert!(deny_session_auto_amend_candidate(
            "kubectl",
            &["delete".into(), "pod/x".into()],
            Some(5)
        )
        .is_ok());
        assert!(deny_session_auto_amend_candidate(
            "kubectl",
            &["delete".into(), "pod/x".into()],
            Some(4)
        )
        .is_err());
        assert!(
            deny_session_auto_amend_candidate("kubectl", &["delete\npod/x".into()], Some(9))
                .is_err()
        );
    }

    #[test]
    fn session_source_reports_cache_separately_from_static_policy() {
        assert_eq!(
            session_source_from_eval(crate::evaluate::EvalSource::Cache),
            SessionDecisionSource::Cache
        );
        assert_eq!(
            session_source_from_eval(crate::evaluate::EvalSource::StaticPolicy),
            SessionDecisionSource::StaticPolicy
        );
    }

    #[test]
    fn tcp_admin_token_validation_is_separate_from_exec_token() {
        let (mut cfg, _) = make_test_config();
        cfg.auth_token = Some("exec-token".into());
        cfg.admin_token = Some("admin-token".into());

        assert!(cfg.validate_token(Some("exec-token")).is_ok());
        assert!(cfg.validate_admin_token(Some("admin-token")).is_ok());
        assert!(cfg.validate_admin_token(Some("exec-token")).is_err());
        assert!(cfg
            .validate_admin(&CallerIdentity::TcpAdmin {
                token: "admin-token".into(),
            })
            .is_ok());
        assert!(cfg
            .validate_admin(&CallerIdentity::Tcp {
                token: "exec-token".into(),
            })
            .is_err());
    }

    #[tokio::test]
    async fn session_list_is_user_visible_but_prompt_is_hidden() {
        let (mut cfg, _) = make_test_config();
        cfg.daemon_uid = 777;
        cfg.daemon_principal = PrincipalKey::from_uid(777);

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
                prose: None,
                profile: None,
                static_only: false,
                auto_amend: false,
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
                visible_token: None,
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
                assert!(hidden.allow_exact.is_empty());
                assert!(hidden.deny_exact.is_empty());
                assert_eq!(hidden.prompt_append.as_deref(), Some("(hidden)"));
                assert!(hidden.generated_notes.is_empty());
            }
            other => panic!("unexpected {:?}", other),
        }
    }

    #[tokio::test]
    async fn session_list_shows_current_session_details_without_raw_token_for_user() {
        let (mut cfg, _) = make_test_config();
        cfg.daemon_uid = 777;
        cfg.daemon_principal = PrincipalKey::from_uid(777);

        let daemon = CallerIdentity::Unix { uid: 777 };
        let user = CallerIdentity::Unix { uid: 20_002 };
        let token = format!("session-visible-{}", std::process::id());

        let grant = handle_admin_request(
            &cfg,
            &daemon,
            AdminRequest::SessionGrant {
                token: token.clone(),
                allow: vec!["mkdir /tmp/work/*".into()],
                deny: Vec::new(),
                ttl_secs: None,
                prompt_append: Some("operator prompt".into()),
                prose: Some("kubernetes access for namespace nextcloud".into()),
                profile: None,
                static_only: false,
                auto_amend: false,
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
                visible_token: Some(token.clone()),
            },
        )
        .await;
        match listed {
            AdminResponse::SessionList { grants, .. } => {
                let visible = grants
                    .iter()
                    .find(|grant| grant.token == "(current)")
                    .expect("current session grant visible to token holder");
                assert!(
                    !visible.allow.is_empty(),
                    "current token holder should see grant rules"
                );
                assert_eq!(
                    visible.prompt_append.as_deref(),
                    Some("Session grant prose:\nkubernetes access for namespace nextcloud\n\nAdditional session context:\noperator prompt")
                );
                assert!(!visible.generated_notes.is_empty());
                assert!(
                    grants.iter().all(|grant| grant.token != token),
                    "non-admin list output must not echo raw bearer tokens"
                );
            }
            other => panic!("unexpected {:?}", other),
        }
    }

    #[tokio::test]
    async fn session_show_reports_recent_stats() {
        let (mut cfg, _) = make_test_config();
        cfg.daemon_uid = 777;
        cfg.daemon_principal = PrincipalKey::from_uid(777);

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
                prose: None,
                profile: None,
                static_only: false,
                auto_amend: false,
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
                caller_token: None,
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

    #[tokio::test]
    async fn session_show_self_token_sees_full_grant() {
        let (mut cfg, _) = make_test_config();
        cfg.daemon_uid = 777;
        cfg.daemon_principal = PrincipalKey::from_uid(777);

        let daemon = CallerIdentity::Unix { uid: 777 };
        let user = CallerIdentity::Unix { uid: 20_003 };
        let token = format!("session-self-{}", std::process::id());

        let grant = handle_admin_request(
            &cfg,
            &daemon,
            AdminRequest::SessionGrant {
                token: token.clone(),
                allow: vec!["kubectl get pods*".into()],
                deny: vec!["rm*".into()],
                ttl_secs: Some(3600),
                prompt_append: Some("cert rotation context".into()),
                prose: None,
                profile: None,
                static_only: false,
                auto_amend: false,
            },
        )
        .await;
        assert!(matches!(grant, AdminResponse::Ok));

        // The holder presents its own token as both identity and target.
        let show = handle_admin_request(
            &cfg,
            &user,
            AdminRequest::SessionShow {
                token: token.clone(),
                limit: Some(20),
                caller_token: Some(token.clone()),
            },
        )
        .await;
        match show {
            AdminResponse::SessionShow { report } => {
                let active = report.active.expect("holder sees its own active grant");
                assert_eq!(active.allow, vec!["kubectl get pods*".to_string()]);
                assert_eq!(active.deny, vec!["rm*".to_string()]);
                assert_eq!(
                    active.prompt_append.as_deref(),
                    Some("cert rotation context")
                );
                assert!(active.expires_at.is_some(), "remaining time is visible");
                assert_eq!(
                    active.token, "(current)",
                    "self view must not echo the raw bearer token"
                );
            }
            other => panic!("unexpected {:?}", other),
        }
    }

    #[tokio::test]
    async fn session_show_other_token_denied_for_non_admin() {
        let (mut cfg, _) = make_test_config();
        cfg.daemon_uid = 777;
        cfg.daemon_principal = PrincipalKey::from_uid(777);

        let daemon = CallerIdentity::Unix { uid: 777 };
        let attacker = CallerIdentity::Unix { uid: 20_004 };
        let token_a = format!("session-a-{}", std::process::id());
        let token_b = format!("session-b-{}", std::process::id());

        for token in [&token_a, &token_b] {
            let grant = handle_admin_request(
                &cfg,
                &daemon,
                AdminRequest::SessionGrant {
                    token: token.clone(),
                    allow: vec!["echo*".into()],
                    deny: Vec::new(),
                    ttl_secs: None,
                    prompt_append: Some("secret operator context".into()),
                    prose: None,
                    profile: None,
                    static_only: false,
                    auto_amend: false,
                },
            )
            .await;
            assert!(matches!(grant, AdminResponse::Ok));
        }

        // Holder of A tries to inspect B's grant by naming B as the target.
        let show = handle_admin_request(
            &cfg,
            &attacker,
            AdminRequest::SessionShow {
                token: token_b.clone(),
                limit: Some(20),
                caller_token: Some(token_a.clone()),
            },
        )
        .await;
        match show {
            AdminResponse::Error { message } => {
                assert!(
                    message.contains("only inspect its own grant"),
                    "expected a clear authorization denial, got: {message}"
                );
                assert!(
                    !message.contains("secret operator context"),
                    "denial must not leak the other grant's contents"
                );
            }
            other => panic!("expected denial, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn session_new_from_profile_mints_expected_grant() {
        let (mut cfg, _) = make_test_config();
        cfg.daemon_uid = 777;
        cfg.daemon_principal = PrincipalKey::from_uid(777);
        cfg.profiles = ProfileCatalog::from_yaml(
            "profiles:\n  - name: cert-manager-rotation\n    ttl_secs: 1800\n    allow:\n      - \"kubectl get certificate*\"\n    deny:\n      - \"kubectl delete namespace*\"\n    prompt_append: \"rotating cert-manager certificates\"\n",
        )
        .expect("valid profile catalog");

        let daemon = CallerIdentity::Unix { uid: 777 };
        let token = format!("session-profile-{}", std::process::id());

        // Profile-only: no explicit allow/deny/ttl/prompt on the request.
        let resp = handle_admin_request(
            &cfg,
            &daemon,
            AdminRequest::SessionGrant {
                token: token.clone(),
                allow: Vec::new(),
                deny: Vec::new(),
                ttl_secs: None,
                prompt_append: None,
                prose: None,
                profile: Some("cert-manager-rotation".into()),
                static_only: false,
                auto_amend: false,
            },
        )
        .await;
        assert!(matches!(resp, AdminResponse::Ok));

        let reg = cfg.sessions.read().await;
        let summary = reg
            .list()
            .into_iter()
            .find(|g| g.token == token)
            .expect("profile grant installed");
        assert_eq!(summary.allow, vec!["kubectl get certificate*".to_string()]);
        assert_eq!(summary.deny, vec!["kubectl delete namespace*".to_string()]);
        assert!(summary.expires_at.is_some(), "profile ttl applied");
        assert_eq!(
            summary.prompt_append.as_deref(),
            Some("rotating cert-manager certificates")
        );
        assert!(
            summary
                .generated_notes
                .iter()
                .any(|note| note.contains("cert-manager-rotation")),
            "grant records which profile minted it"
        );
    }

    #[tokio::test]
    async fn session_new_unknown_profile_fails_clearly() {
        let (mut cfg, _) = make_test_config();
        cfg.daemon_uid = 777;
        cfg.daemon_principal = PrincipalKey::from_uid(777);
        // The profile catalog is left empty.

        let daemon = CallerIdentity::Unix { uid: 777 };
        let token = format!("session-badprofile-{}", std::process::id());
        let resp = handle_admin_request(
            &cfg,
            &daemon,
            AdminRequest::SessionGrant {
                token: token.clone(),
                allow: Vec::new(),
                deny: Vec::new(),
                ttl_secs: None,
                prompt_append: None,
                prose: None,
                profile: Some("does-not-exist".into()),
                static_only: false,
                auto_amend: false,
            },
        )
        .await;
        match resp {
            AdminResponse::Error { message } => {
                assert!(
                    message.contains("unknown session profile")
                        && message.contains("does-not-exist"),
                    "expected a clear unknown-profile error, got: {message}"
                );
            }
            other => panic!("expected error, got {:?}", other),
        }
        // A failed lookup must not install an (empty, unrestricted) grant.
        let reg = cfg.sessions.read().await;
        assert!(
            reg.list().into_iter().all(|g| g.token != token),
            "no grant should be installed for an unknown profile"
        );
    }

    #[tokio::test]
    async fn profile_grant_still_deny_short_circuits_and_falls_through() {
        let (mut cfg, _) = make_test_config();
        cfg.daemon_uid = 777;
        cfg.daemon_principal = PrincipalKey::from_uid(777);
        cfg.profiles = ProfileCatalog::from_yaml(
            "profiles:\n  - name: scoped\n    allow:\n      - \"kubectl get*\"\n    deny:\n      - \"kubectl delete*\"\n",
        )
        .expect("valid profile catalog");

        let daemon = CallerIdentity::Unix { uid: 777 };
        let token = format!("session-profcheck-{}", std::process::id());
        let resp = handle_admin_request(
            &cfg,
            &daemon,
            AdminRequest::SessionGrant {
                token: token.clone(),
                allow: Vec::new(),
                deny: Vec::new(),
                ttl_secs: None,
                prompt_append: None,
                prose: None,
                profile: Some("scoped".into()),
                static_only: false,
                auto_amend: false,
            },
        )
        .await;
        assert!(matches!(resp, AdminResponse::Ok));

        let reg = cfg.sessions.read().await;
        // A profile-derived grant behaves exactly like any other grant: its deny
        // glob short-circuits to Deny...
        assert!(matches!(
            reg.check(&token, "kubectl", &["delete".into(), "pod".into()]),
            Some((SessionDecision::Deny, _))
        ));
        // ...its allow glob short-circuits to Allow...
        assert!(matches!(
            reg.check(&token, "kubectl", &["get".into(), "pods".into()]),
            Some((SessionDecision::Allow, _))
        ));
        // ...and a command matching neither falls through to normal evaluation.
        assert!(
            reg.check(&token, "helm", &["list".into()]).is_none(),
            "an unmatched command must fall through to the evaluator"
        );
    }

    // ---- Consequence-gating orchestration tests -----------------------------
    //
    // These drive the daemon orchestration in this file (arm_containment,
    // hold_for_approval, handle_admin_request -> confirm/approve/deny/revert,
    // and the sweeper's expire/auto-revert steps) directly in-process, so the
    // invariants the Docker CTF (ctf/gating) checks end-to-end are also caught
    // by `cargo test`. Tests that must spawn a real forward/revert child use
    // POSIX `echo`/`true`/`false` and are `#[cfg(unix)]`; the authoritative
    // cross-platform run is the Linux container. The pure registry/handler
    // invariants (operator gating, TTL expiry, catalog voiding) run everywhere.

    // The gating types (Approval, ApprovalSnapshot, ApprovalStatus, Provisional,
    // ProvisionalStatus, Coverage, GateMode, Reversibility) and AsyncWrite are
    // already in scope via `use super::*;`.
    use std::collections::BTreeMap;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// Build a containment-gating config: gate on, a distinct operator
    /// principal, and the caller uid as the row owner. Returns
    /// `(config, operator_caller, agent_caller)`.
    fn gating_config(
        operator_uid: u32,
        agent_uid: u32,
    ) -> (ServerConfig, CallerIdentity, CallerIdentity) {
        let (mut cfg, _) = make_test_config();
        cfg.gate = GateMode::Consequence;
        cfg.daemon_uid = operator_uid;
        cfg.daemon_principal = PrincipalKey::from_uid(operator_uid);
        let operator = CallerIdentity::Unix { uid: operator_uid };
        let agent = CallerIdentity::Unix { uid: agent_uid };
        (cfg, operator, agent)
    }

    /// A request with a structured revert, used to drive `arm_containment`.
    fn contain_request(binary: &str, args: &[&str], revert: RevertSpec) -> ExecuteRequest {
        ExecuteRequest {
            binary: binary.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            auth_token: None,
            env: HashMap::new(),
            secrets: HashMap::new(),
            stream: false,
            session_token: None,
            revert: Some(revert),
            confirm_within_secs: None,
            reevaluate: false,
            ssh_hostkey: None,
            require_approval: None,
            wait_approval_secs: None,
            verb: None,
        }
    }

    /// A `tokio::io::AsyncWrite` whose writes succeed `ok_writes` times and then
    /// fail with `BrokenPipe`. With `ok_writes == 0` it fails on the very first
    /// write, simulating a client stream that drops the instant the daemon
    /// begins forwarding the child's output. The forward child still spawns and
    /// runs (so the mutation may have applied); only streaming its output fails.
    struct FlakyWriter {
        remaining_ok: usize,
    }

    impl FlakyWriter {
        fn failing_after(ok_writes: usize) -> Self {
            Self {
                remaining_ok: ok_writes,
            }
        }
    }

    impl AsyncWrite for FlakyWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.remaining_ok == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "client stream dropped",
                )));
            }
            self.remaining_ok -= 1;
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// CONTAINMENT-LEAK (regression for the just-landed disconnect fix): a
    /// contained forward command that LAUNCHES and then fails because the client
    /// stream drops mid-run must STAY ARMED — the provisional stays in the
    /// registry with `forward_done` set so the auto-revert can still fire. A
    /// leak here would let an unconfirmed mutation persist past its deadline.
    #[cfg(unix)]
    #[tokio::test]
    async fn containment_stays_armed_when_client_stream_drops_after_launch() {
        let (cfg, _operator, agent) = gating_config(7001, 1000);
        let agent_principal = agent.principal();

        // Forward `echo` produces a line, so the daemon attempts to stream it;
        // our writer fails on that first write -> exec_failed_after_start.
        let request = contain_request(
            "echo",
            &["contained-change"],
            RevertSpec {
                binary: "true".to_string(),
                args: Vec::new(),
            },
        );
        let mut writer = FlakyWriter::failing_after(0);

        let result = arm_containment(
            request,
            &cfg,
            &agent,
            agent_principal,
            "recoverable change".to_string(),
            0,
            true, // stream_output: exercise the streaming failure path
            &mut writer,
        )
        .await;

        // The forward child launched then failed: started=true.
        match &result.exec {
            ExecOutcome::Failed { started, .. } => {
                assert!(*started, "client stream drop must report started=true");
            }
            other => panic!("expected Failed{{started:true}}, got {:?}", other),
        }

        // Invariant: the provisional is STILL ARMED with forward_done set, so the
        // sweeper's take_due can fire the auto-revert. It must NOT have been
        // dropped (that would leak the unconfirmed mutation).
        let reg = cfg.provisional.read().await;
        let rows = reg.list();
        assert_eq!(rows.len(), 1, "the armed provisional must be retained");
        let p = &rows[0];
        assert_eq!(p.status, ProvisionalStatus::Armed);
        assert!(
            p.forward_done,
            "forward_done must be set so the deadline is honored"
        );
        assert_eq!(reg.outstanding(), 1, "the armed row still occupies a slot");
    }

    /// Counterpart to the leak test: a contained forward command that FAILS TO
    /// SPAWN (nonexistent binary, started=false) has no observable effect, so
    /// the provisional is DROPPED — there is nothing to revert.
    #[cfg(unix)]
    #[tokio::test]
    async fn containment_dropped_when_forward_fails_to_spawn() {
        let (cfg, _operator, agent) = gating_config(7002, 1000);
        let agent_principal = agent.principal();

        let request = contain_request(
            "guard-nonexistent-binary-xyz",
            &[],
            RevertSpec {
                binary: "true".to_string(),
                args: Vec::new(),
            },
        );
        let mut sink = tokio::io::sink();

        let result = arm_containment(
            request,
            &cfg,
            &agent,
            agent_principal,
            "recoverable change".to_string(),
            0,
            false,
            &mut sink,
        )
        .await;

        match &result.exec {
            ExecOutcome::Failed { started, .. } => {
                assert!(!*started, "spawn failure must report started=false");
            }
            other => panic!("expected Failed{{started:false}}, got {:?}", other),
        }

        // The provisional was dropped: nothing ran, so nothing to revert.
        let reg = cfg.provisional.read().await;
        assert!(
            reg.list().is_empty(),
            "a never-launched forward must drop its provisional"
        );
    }

    /// contain -> operator confirm keeps the change (no revert fires), and
    /// confirm is daemon-principal-only: a non-operator caller is refused before
    /// the registry is touched.
    #[cfg(unix)]
    #[tokio::test]
    async fn contain_then_operator_confirm_keeps_change_nonoperator_refused() {
        let (cfg, operator, agent) = gating_config(7003, 1000);
        let agent_principal = agent.principal();

        let request = contain_request(
            "true",
            &[],
            RevertSpec {
                binary: "true".to_string(),
                args: Vec::new(),
            },
        );
        let mut sink = tokio::io::sink();
        let result = arm_containment(
            request,
            &cfg,
            &agent,
            agent_principal,
            "recoverable change".to_string(),
            0,
            false,
            &mut sink,
        )
        .await;
        let handle = match &result.exec {
            ExecOutcome::Provisional { handle, .. } => handle.clone(),
            other => panic!("expected Provisional, got {:?}", other),
        };

        // A non-operator (uid != daemon_principal) cannot confirm: validate_admin
        // refuses before handle_confirm runs, so the row is untouched.
        let refused = handle_admin_request(
            &cfg,
            &agent,
            AdminRequest::Confirm {
                handle: handle.clone(),
            },
        )
        .await;
        match refused {
            AdminResponse::Error { message } => {
                assert!(
                    message.contains("not the daemon principal"),
                    "got: {message}"
                );
            }
            other => panic!("non-operator confirm must be refused, got {:?}", other),
        }
        assert_eq!(
            cfg.provisional.read().await.get(&handle).unwrap().status,
            ProvisionalStatus::Armed,
            "a refused confirm must not change state"
        );

        // The operator confirms: the change is kept and the auto-revert is
        // cancelled.
        let ok = handle_admin_request(
            &cfg,
            &operator,
            AdminRequest::Confirm {
                handle: handle.clone(),
            },
        )
        .await;
        assert!(matches!(ok, AdminResponse::GateAction { .. }));
        assert_eq!(
            cfg.provisional.read().await.get(&handle).unwrap().status,
            ProvisionalStatus::Confirmed
        );

        // A confirmed provisional is never due, even far past any deadline: the
        // sweeper's take_due step yields nothing to revert.
        let due = cfg
            .provisional
            .write()
            .await
            .take_due(now_unix() + 10_000_000);
        assert!(due.is_empty(), "a confirmed change must never auto-revert");
    }

    /// contain -> deadline passes -> the sweeper's auto-revert path fires and
    /// rolls the change back. Drives the sweeper's `take_due` + `finish_revert`
    /// steps directly (the live `gating_sweeper` is an infinite loop with a
    /// startup grace, so its time-driven body is exercised piecewise here).
    #[cfg(unix)]
    #[tokio::test]
    async fn contain_then_deadline_triggers_sweeper_autorevert() {
        let (cfg, _operator, agent) = gating_config(7004, 1000);
        let agent_principal = agent.principal();

        // A 1s window: the smallest the clamp allows.
        let mut request = contain_request(
            "true",
            &[],
            RevertSpec {
                binary: "true".to_string(),
                args: Vec::new(),
            },
        );
        request.confirm_within_secs = Some(1);
        let mut sink = tokio::io::sink();
        let result = arm_containment(
            request,
            &cfg,
            &agent,
            agent_principal,
            "recoverable change".to_string(),
            0,
            false,
            &mut sink,
        )
        .await;
        let handle = match &result.exec {
            ExecOutcome::Provisional { handle, .. } => handle.clone(),
            other => panic!("expected Provisional, got {:?}", other),
        };

        // Sweeper step: claim every armed-and-due provisional (simulate the
        // deadline by passing a `now` well past it), then run each revert.
        let due = cfg
            .provisional
            .write()
            .await
            .take_due(now_unix() + 10_000_000);
        assert_eq!(
            due.len(),
            1,
            "the armed provisional is due past its deadline"
        );
        for p in &due {
            finish_revert(&cfg, p, &CallerIdentity::Unknown, "auto").await;
        }

        // The `true` revert exits 0 -> Reverted.
        assert_eq!(
            cfg.provisional.read().await.get(&handle).unwrap().status,
            ProvisionalStatus::Reverted,
            "auto-revert must roll the unconfirmed change back"
        );
    }

    /// A recoverable command whose free-form `--revert` cannot be affirmed is
    /// HELD for operator review, not armed with an unverified rollback and not
    /// silently denied. Here the rollback binary is structurally invalid, so
    /// `assess_revert` returns `NeedsReview` before any evaluator call, keeping
    /// the test deterministic and cross-platform (the hold path spawns no child).
    #[tokio::test]
    async fn recoverable_with_unaffirmable_revert_is_held_for_review() {
        let (cfg, _operator, agent) = gating_config(7011, 1000);

        let request = contain_request(
            "systemctl",
            &["restart", "app"],
            RevertSpec {
                binary: "../evil".to_string(), // `..` rejected by invalid_binary_reason
                args: Vec::new(),
            },
        );
        let inputs = GateInputs {
            reason: "recoverable restart".to_string(),
            risk: Some(2),
            reversibility: Some(Reversibility::Recoverable),
            revert_preauthorized: false,
            verb: None,
            bypass: false,
        };
        let mut sink = tokio::io::sink();
        let result = route_gated_allow(request, &cfg, &agent, inputs, 0, false, &mut sink).await;

        let handle = match &result.exec {
            ExecOutcome::Held { handle, .. } => handle.clone(),
            other => panic!("expected Held, got {:?}", other),
        };
        assert!(
            result.policy_reason().contains("held for operator review"),
            "reason should explain the escalation: {}",
            result.policy_reason()
        );
        assert_eq!(
            cfg.provisional.read().await.outstanding(),
            0,
            "an unaffirmable rollback must never arm a containment envelope"
        );
        assert_eq!(
            cfg.approvals.read().await.get(&handle).unwrap().status,
            ApprovalStatus::Pending,
            "the forward command must be queued for an operator decision"
        );
    }

    /// hold -> operator approve executes from the bound snapshot; a non-operator
    /// caller cannot approve (validate_admin refuses before any state change).
    #[cfg(unix)]
    #[tokio::test]
    async fn hold_then_operator_approve_executes_snapshot_nonoperator_refused() {
        let (cfg, operator, agent) = gating_config(7005, 1000);
        let agent_principal = agent.principal();

        // Hold a command. `true` is the bound binary; approval must run exactly
        // this snapshot.
        let request = ExecuteRequest {
            binary: "true".to_string(),
            args: Vec::new(),
            auth_token: None,
            env: HashMap::new(),
            secrets: HashMap::new(),
            stream: false,
            session_token: None,
            revert: None,
            confirm_within_secs: None,
            reevaluate: false,
            ssh_hostkey: None,
            require_approval: None,
            wait_approval_secs: None,
            verb: None,
        };
        let mut sink = tokio::io::sink();
        let held = hold_for_approval(
            request,
            &cfg,
            &agent,
            agent_principal,
            "needs sign-off".to_string(),
            Some(9),
            Some(Reversibility::Irreversible),
            None,
            false,
            &mut sink,
        )
        .await;
        let handle = match &held.exec {
            ExecOutcome::Held { handle, .. } => handle.clone(),
            other => panic!("expected Held, got {:?}", other),
        };

        // Non-operator approve is refused; the hold stays pending.
        let refused = handle_admin_request(
            &cfg,
            &agent,
            AdminRequest::Approve {
                handle: handle.clone(),
            },
        )
        .await;
        match refused {
            AdminResponse::Error { message } => {
                assert!(
                    message.contains("not the daemon principal"),
                    "got: {message}"
                );
            }
            other => panic!("non-operator approve must be refused, got {:?}", other),
        }
        assert_eq!(
            cfg.approvals.read().await.get(&handle).unwrap().status,
            ApprovalStatus::Pending,
            "a refused approve must not change state"
        );

        // Operator approves: the snapshot executes (`true` -> exit 0) and the row
        // becomes Approved.
        let ok = handle_admin_request(
            &cfg,
            &operator,
            AdminRequest::Approve {
                handle: handle.clone(),
            },
        )
        .await;
        match ok {
            AdminResponse::GateAction { exit_code, .. } => {
                assert_eq!(exit_code, Some(0), "approved `true` exits 0");
            }
            other => panic!("operator approve should execute, got {:?}", other),
        }
        assert_eq!(
            cfg.approvals.read().await.get(&handle).unwrap().status,
            ApprovalStatus::Approved
        );
    }

    /// Wait (bounded) for a pending approval row to appear and return its handle.
    async fn wait_for_pending_hold(cfg: &ServerConfig) -> String {
        for _ in 0..100 {
            let pending: Vec<String> = cfg
                .approvals
                .read()
                .await
                .list()
                .into_iter()
                .filter(|a| a.status == ApprovalStatus::Pending)
                .map(|a| a.handle)
                .collect();
            if let Some(h) = pending.into_iter().next() {
                return h;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("no pending hold appeared");
    }

    /// A kube-proxy `hold` parks the request in the approval queue: an operator
    /// approve releases the waiter without spawning any process, an operator
    /// deny fails it closed, and a waiter that vanishes undecided (client
    /// disconnect) retires its row so the queue never offers a dead approval.
    #[cfg(unix)]
    #[tokio::test]
    async fn kube_proxy_hold_routes_through_approval_queue() {
        let (cfg, operator, _agent) = gating_config(7013, 1000);
        let sink = Arc::new(DaemonGateSink {
            config: cfg.clone(),
            kubeconfig: PathBuf::from("unused-in-test"),
            snapshot_dir: std::env::temp_dir(),
            window_secs: 60,
        });

        // Approve: the waiter returns Approved with the queue handle; the row is
        // Approved and carries no exec result (nothing ran).
        let s = sink.clone();
        let waiter = tokio::spawn(async move {
            guard::proxy::GateSink::hold_request(&*s, "delete namespaces/prod", "namespace delete")
                .await
        });
        let handle = wait_for_pending_hold(&cfg).await;
        let resp = handle_admin_request(
            &cfg,
            &operator,
            AdminRequest::Approve {
                handle: handle.clone(),
            },
        )
        .await;
        match resp {
            AdminResponse::GateAction {
                message, exit_code, ..
            } => {
                assert!(message.contains("forwarding"), "got: {message}");
                assert_eq!(exit_code, None, "a released API hold executes nothing");
            }
            other => panic!("operator approve should release the hold, got {:?}", other),
        }
        match waiter.await.unwrap() {
            guard::proxy::HoldDecision::Approved { handle: h } => assert_eq!(h, handle),
            other => panic!("expected Approved, got {:?}", other),
        }
        assert_eq!(
            cfg.approvals.read().await.get(&handle).unwrap().status,
            ApprovalStatus::Approved
        );

        // Deny: the waiter fails closed with the operator's reason.
        let s = sink.clone();
        let waiter = tokio::spawn(async move {
            guard::proxy::GateSink::hold_request(&*s, "delete namespaces/prod", "namespace delete")
                .await
        });
        let handle = wait_for_pending_hold(&cfg).await;
        let resp = handle_admin_request(
            &cfg,
            &operator,
            AdminRequest::Deny {
                handle: handle.clone(),
            },
        )
        .await;
        assert!(
            !matches!(resp, AdminResponse::Error { .. }),
            "operator deny should succeed: {:?}",
            resp
        );
        match waiter.await.unwrap() {
            guard::proxy::HoldDecision::Denied { .. } => {}
            other => panic!("expected Denied, got {:?}", other),
        }
        assert_eq!(
            cfg.approvals.read().await.get(&handle).unwrap().status,
            ApprovalStatus::Denied
        );

        // Disconnect: dropping the waiter mid-hold retires the pending row.
        let s = sink.clone();
        let waiter = tokio::spawn(async move {
            guard::proxy::GateSink::hold_request(&*s, "delete namespaces/prod", "namespace delete")
                .await
        });
        let handle = wait_for_pending_hold(&cfg).await;
        waiter.abort();
        let mut retired = false;
        for _ in 0..100 {
            if cfg.approvals.read().await.get(&handle).unwrap().status == ApprovalStatus::ExecFailed
            {
                retired = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            retired,
            "an abandoned hold must be retired, not left pending"
        );
    }

    /// hold -> TTL expiry -> the sweeper denies (fail-closed); the command never
    /// executes. Cross-platform: no child is spawned on this path.
    #[tokio::test]
    async fn hold_then_ttl_expiry_denies_fail_closed() {
        let (cfg, _operator, agent) = gating_config(7006, 1000);
        let agent_principal = agent.principal();

        let request = ExecuteRequest {
            binary: "rm".to_string(),
            args: vec!["-rf".to_string(), "/data".to_string()],
            auth_token: None,
            env: HashMap::new(),
            secrets: HashMap::new(),
            stream: false,
            session_token: None,
            revert: None,
            confirm_within_secs: None,
            reevaluate: false,
            ssh_hostkey: None,
            require_approval: None,
            wait_approval_secs: None,
            verb: None,
        };
        let mut sink = tokio::io::sink();
        let held = hold_for_approval(
            request,
            &cfg,
            &agent,
            agent_principal,
            "destructive".to_string(),
            Some(10),
            Some(Reversibility::Irreversible),
            None,
            false,
            &mut sink,
        )
        .await;
        let handle = match &held.exec {
            ExecOutcome::Held { handle, .. } => handle.clone(),
            other => panic!("expected Held, got {:?}", other),
        };

        // Sweeper step: expire every pending hold past its TTL. Pass a `now` far
        // beyond the TTL so the deadline has certainly passed.
        let expired = cfg
            .approvals
            .write()
            .await
            .expire_due(now_unix() + APPROVAL_TTL_SECS + 10_000);
        assert_eq!(expired, vec![handle.clone()]);

        let row = cfg.approvals.read().await.get(&handle).cloned().unwrap();
        assert_eq!(
            row.status,
            ApprovalStatus::Expired,
            "an unattended hold must fail closed (deny), not execute"
        );
        // The client-facing result is a denial, never an execution.
        let result = approval_to_result(&row);
        assert!(!result.policy_allowed());
        assert!(result.policy_reason().contains("expired"));
        assert!(matches!(result.exec, ExecOutcome::NotAttempted));
    }

    #[test]
    fn hash_secret_value_is_salted_and_value_sensitive() {
        let a = hash_secret_value("salt1", "v1");
        // Deterministic for the same (salt, value).
        assert_eq!(a, hash_secret_value("salt1", "v1"));
        // Sensitive to the value.
        assert_ne!(a, hash_secret_value("salt1", "v2"));
        // Sensitive to the salt (so a persisted digest is not a plain value hash).
        assert_ne!(a, hash_secret_value("salt2", "v1"));
        // 32-byte SHA-256 -> 64 hex chars.
        assert_eq!(a.len(), 64);
    }

    /// A held command captures a salted hash of its mapped secret VALUES. If the
    /// same-principal caller swaps a value between hold and approval, approval
    /// fails closed before the command runs.
    #[tokio::test]
    async fn approve_rejected_when_bound_secret_value_changed() {
        let (cfg, _operator, agent) = gating_config(7201, 4201);
        let agent_principal = agent.principal();
        let p = agent_principal.clone().expect("agent principal");
        cfg.secrets.set(&p, "BIND_TEST_KEY", "v1").await.unwrap();

        let mut secrets = HashMap::new();
        secrets.insert("INJECTED".to_string(), "BIND_TEST_KEY".to_string());
        let request = ExecuteRequest {
            binary: "true".to_string(),
            args: Vec::new(),
            auth_token: None,
            env: HashMap::new(),
            secrets,
            stream: false,
            session_token: None,
            revert: None,
            confirm_within_secs: None,
            reevaluate: false,
            ssh_hostkey: None,
            require_approval: None,
            wait_approval_secs: None,
            verb: None,
        };
        let mut sink = tokio::io::sink();
        let held = hold_for_approval(
            request,
            &cfg,
            &agent,
            agent_principal.clone(),
            "needs review".to_string(),
            Some(8),
            Some(Reversibility::Irreversible),
            None,
            false,
            &mut sink,
        )
        .await;
        let handle = match &held.exec {
            ExecOutcome::Held { handle, .. } => handle.clone(),
            other => panic!("expected Held, got {:?}", other),
        };

        let snapshot = cfg
            .approvals
            .read()
            .await
            .get(&handle)
            .cloned()
            .unwrap()
            .snapshot;
        assert!(
            snapshot.secret_binding.is_some(),
            "a secret-value binding must be captured at hold time"
        );

        // The same principal swaps the value the operator was reviewing.
        cfg.secrets
            .set(&p, "BIND_TEST_KEY", "v2-tampered")
            .await
            .unwrap();

        let result = execute_snapshot(&cfg, &snapshot, "operator approved").await;
        match &result.exec {
            ExecOutcome::Failed { reason, started } => {
                assert!(!started, "the command must not have started");
                assert!(
                    reason.contains("changed since the command was held"),
                    "got: {}",
                    reason
                );
            }
            other => panic!("expected a fail-closed rejection, got {:?}", other),
        }

        let _ = cfg.secrets.delete(&p, "BIND_TEST_KEY").await;
    }

    /// When the bound value is unchanged, the binding check passes (it does not
    /// reject), so the approved command proceeds to execution.
    #[tokio::test]
    async fn approve_passes_binding_when_secret_value_unchanged() {
        let (cfg, _operator, agent) = gating_config(7202, 4202);
        let agent_principal = agent.principal();
        let p = agent_principal.clone().expect("agent principal");
        cfg.secrets.set(&p, "BIND_OK_KEY", "stable").await.unwrap();

        let mut secrets = HashMap::new();
        secrets.insert("INJECTED".to_string(), "BIND_OK_KEY".to_string());
        let request = ExecuteRequest {
            binary: "true".to_string(),
            args: Vec::new(),
            auth_token: None,
            env: HashMap::new(),
            secrets,
            stream: false,
            session_token: None,
            revert: None,
            confirm_within_secs: None,
            reevaluate: false,
            ssh_hostkey: None,
            require_approval: None,
            wait_approval_secs: None,
            verb: None,
        };
        let mut sink = tokio::io::sink();
        let held = hold_for_approval(
            request,
            &cfg,
            &agent,
            agent_principal.clone(),
            "needs review".to_string(),
            Some(8),
            Some(Reversibility::Irreversible),
            None,
            false,
            &mut sink,
        )
        .await;
        let handle = match &held.exec {
            ExecOutcome::Held { handle, .. } => handle.clone(),
            other => panic!("expected Held, got {:?}", other),
        };
        let snapshot = cfg
            .approvals
            .read()
            .await
            .get(&handle)
            .cloned()
            .unwrap()
            .snapshot;

        // Value unchanged -> the binding check must NOT reject. The subsequent
        // exec of `true` succeeds on Unix; on Windows there is no `true` binary,
        // so it may fail to spawn — either way it is not the binding rejection,
        // which is what this test asserts.
        let result = execute_snapshot(&cfg, &snapshot, "operator approved").await;
        if let ExecOutcome::Failed { reason, .. } = &result.exec {
            assert!(
                !reason.contains("changed since the command was held"),
                "binding check must not reject an unchanged value; got: {}",
                reason
            );
        }

        let _ = cfg.secrets.delete(&p, "BIND_OK_KEY").await;
    }

    /// The binding is mandatory: a secret that is UNRESOLVED at hold is bound by
    /// a sentinel, so a same-principal caller cannot disable verification by
    /// making a secret absent at hold and then creating it with a chosen value
    /// before approval. Approval fails closed when the absent secret appears.
    #[tokio::test]
    async fn approve_rejected_when_unresolved_secret_appears_after_hold() {
        let (cfg, _operator, agent) = gating_config(7203, 4203);
        let agent_principal = agent.principal();
        let p = agent_principal.clone().expect("agent principal");
        // The secret does NOT exist at hold time.
        let _ = cfg.secrets.delete(&p, "BIND_LATE_KEY").await;

        let mut secrets = HashMap::new();
        secrets.insert("INJECTED".to_string(), "BIND_LATE_KEY".to_string());
        let request = ExecuteRequest {
            binary: "true".to_string(),
            args: Vec::new(),
            auth_token: None,
            env: HashMap::new(),
            secrets,
            stream: false,
            session_token: None,
            revert: None,
            confirm_within_secs: None,
            reevaluate: false,
            ssh_hostkey: None,
            require_approval: None,
            wait_approval_secs: None,
            verb: None,
        };
        let mut sink = tokio::io::sink();
        let held = hold_for_approval(
            request,
            &cfg,
            &agent,
            agent_principal.clone(),
            "needs review".to_string(),
            Some(8),
            Some(Reversibility::Irreversible),
            None,
            false,
            &mut sink,
        )
        .await;
        let handle = match &held.exec {
            ExecOutcome::Held { handle, .. } => handle.clone(),
            other => panic!("expected Held, got {:?}", other),
        };
        let snapshot = cfg
            .approvals
            .read()
            .await
            .get(&handle)
            .cloned()
            .unwrap()
            .snapshot;
        // A binding is captured even though the secret was unresolved at hold.
        assert!(
            snapshot.secret_binding.is_some(),
            "the binding must be mandatory, capturing a sentinel for the absent secret"
        );

        // The caller now creates the previously-absent secret with a chosen value.
        cfg.secrets
            .set(&p, "BIND_LATE_KEY", "sneaked-in")
            .await
            .unwrap();

        let result = execute_snapshot(&cfg, &snapshot, "operator approved").await;
        match &result.exec {
            ExecOutcome::Failed { reason, started } => {
                assert!(!started, "the command must not have started");
                assert!(
                    reason.contains("changed since the command was held"),
                    "got: {}",
                    reason
                );
            }
            other => panic!("expected a fail-closed rejection, got {:?}", other),
        }

        let _ = cfg.secrets.delete(&p, "BIND_LATE_KEY").await;
    }

    /// The approval discussion thread accepts notes from the operator and from
    /// the hold's original requester, refuses everyone else, and freezes once
    /// the hold is decided.
    #[tokio::test]
    async fn approval_note_operator_and_owner_post_others_refused() {
        let (cfg, operator, agent) = gating_config(7301, 4301);
        let agent_principal = agent.principal();
        let request = ExecuteRequest {
            binary: "true".to_string(),
            args: Vec::new(),
            auth_token: None,
            env: HashMap::new(),
            secrets: HashMap::new(),
            stream: false,
            session_token: None,
            revert: None,
            confirm_within_secs: None,
            reevaluate: false,
            ssh_hostkey: None,
            require_approval: None,
            wait_approval_secs: None,
            verb: None,
        };
        let mut sink = tokio::io::sink();
        let held = hold_for_approval(
            request,
            &cfg,
            &agent,
            agent_principal.clone(),
            "review".to_string(),
            Some(8),
            Some(Reversibility::Irreversible),
            None,
            false,
            &mut sink,
        )
        .await;
        let handle = match &held.exec {
            ExecOutcome::Held { handle, .. } => handle.clone(),
            other => panic!("expected Held, got {:?}", other),
        };

        // The requester (hold owner) can post.
        let r = handle_approval_note(&cfg, &agent, &handle, "why is this needed?").await;
        assert!(
            matches!(r, AdminResponse::ApprovalShow { .. }),
            "owner should post: {:?}",
            r
        );

        // The operator can post; the thread now has both turns, labeled.
        let r = handle_approval_note(&cfg, &operator, &handle, "ok, approving").await;
        match r {
            AdminResponse::ApprovalShow { item } => {
                assert_eq!(item.notes.len(), 2);
                assert_eq!(item.notes[0].author, "requester");
                assert_eq!(item.notes[1].author, "operator");
            }
            other => panic!("operator should post: {:?}", other),
        }

        // A different non-operator principal is refused (NotFound, no leak).
        let stranger = CallerIdentity::Unix { uid: 9999 };
        assert!(
            matches!(
                handle_approval_note(&cfg, &stranger, &handle, "let me in").await,
                AdminResponse::Error { .. }
            ),
            "a stranger must be refused"
        );

        // Empty text is rejected.
        assert!(matches!(
            handle_approval_note(&cfg, &operator, &handle, "   ").await,
            AdminResponse::Error { .. }
        ));

        // Once decided, the thread is frozen.
        cfg.approvals
            .write()
            .await
            .deny(&handle, now_unix(), "denied".to_string())
            .unwrap();
        assert!(
            matches!(
                handle_approval_note(&cfg, &operator, &handle, "too late").await,
                AdminResponse::Error { .. }
            ),
            "a decided hold's thread must be frozen"
        );
    }

    /// approve after the verb catalog version changed is voided: the approved
    /// artifact may no longer mean what the operator reviewed, so the daemon
    /// fails it closed rather than executing a stale rendering. Cross-platform:
    /// the void check returns before any child is spawned.
    #[tokio::test]
    async fn approve_voided_when_verb_catalog_version_changed() {
        let (cfg, operator, agent) = gating_config(7007, 1000);

        // Enqueue a hold that originated from a verb, stamped with a catalog
        // version that differs from the live (empty) catalog's version. Use a
        // binary that would clearly execute if the void check were skipped, so a
        // false pass is detectable.
        let handle = new_handle();
        let snapshot = ApprovalSnapshot {
            binary: "true".to_string(),
            args: Vec::new(),
            env: BTreeMap::new(),
            secret_keys: BTreeMap::new(),
            verb_name: Some("restart-service".to_string()),
            verb_params: BTreeMap::new(),
            // Live catalog (VerbCatalog::empty()) has version 0; a stale stamp.
            catalog_version: Some(424_242),
            principal: agent.principal(),
            secret_binding: None,
        };
        let approval = Approval {
            handle: handle.clone(),
            snapshot,
            reason: "verb hold".to_string(),
            risk: Some(8),
            reversibility: Some(Reversibility::Irreversible),
            created_unix: now_unix(),
            ttl_secs: APPROVAL_TTL_SECS,
            status: ApprovalStatus::Pending,
            decided_unix: None,
            decided_reason: None,
            result_exit: None,
            result_stdout: None,
            result_stderr: None,
            notes: Vec::new(),
        };
        assert_ne!(
            approval.snapshot.catalog_version,
            Some(cfg.verbs.read().await.version()),
            "test precondition: the stamped version must differ from live"
        );
        cfg.approvals.write().await.enqueue(approval);

        let voided = handle_admin_request(
            &cfg,
            &operator,
            AdminRequest::Approve {
                handle: handle.clone(),
            },
        )
        .await;
        match voided {
            AdminResponse::Error { message } => {
                assert!(
                    message.contains("catalog changed") && message.contains("voided"),
                    "got: {message}"
                );
            }
            other => panic!("a stale-catalog approve must be voided, got {:?}", other),
        }

        // The hold is terminal (ExecFailed), not Approved: nothing executed.
        assert_eq!(
            cfg.approvals.read().await.get(&handle).unwrap().status,
            ApprovalStatus::ExecFailed
        );
    }

    /// Sanity: `Coverage::contain` is what a provisional carries, so the
    /// client-facing result of a contained action advertises the residual risk
    /// the operator owns (the gate did not verify the rollback inverts the
    /// change). Guards against silently dropping coverage from the result.
    #[test]
    fn provisional_result_carries_contain_coverage() {
        let r = ExecuteResult::provisional(
            "recoverable".to_string(),
            "handle123".to_string(),
            Coverage::contain(),
            Some(0),
            None,
            None,
        );
        match &r.exec {
            ExecOutcome::Provisional {
                coverage, handle, ..
            } => {
                assert_eq!(handle, "handle123");
                assert!(coverage.not_checked.iter().any(|s| s.contains("invert")));
            }
            other => panic!("expected Provisional, got {:?}", other),
        }
    }

    // ---- Filesystem read-grant tests ----------------------------------------

    #[test]
    fn grant_envelope_routes_to_its_own_variant() {
        let grant_json = serde_json::to_string(&IncomingMessage::Grant {
            grant: GrantRequest::Read {
                path: "/home/op/values.yaml".to_string(),
                ttl_secs: 300,
                session_token: None,
                reevaluate: false,
            },
        })
        .unwrap();
        let parsed: IncomingMessage = serde_json::from_str(&grant_json).unwrap();
        assert!(matches!(parsed, IncomingMessage::Grant { .. }));

        // A bare execute request still routes to Execute, not Grant, under the
        // untagged enum.
        let exec: IncomingMessage = serde_json::from_str(r#"{"binary":"ls","args":[]}"#).unwrap();
        assert!(matches!(exec, IncomingMessage::Execute(_)));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn grant_read_is_denied_on_non_unix_platform() {
        let (cfg, _buf) = make_test_config();
        let caller = CallerIdentity::Unix { uid: 1000 };
        let result = handle_grant_request(
            &cfg,
            &caller,
            GrantRequest::Read {
                path: "/home/op/values.yaml".to_string(),
                ttl_secs: 300,
                session_token: None,
                reevaluate: false,
            },
        )
        .await;
        assert!(!result.policy_allowed());
        assert!(
            result
                .policy_reason()
                .contains("not supported on this platform"),
            "got: {}",
            result.policy_reason()
        );
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    fn acl_tools_available() -> bool {
        let ok = |bin: &str| {
            std::process::Command::new(bin)
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        };
        ok("setfacl") && ok("getfacl")
    }

    #[cfg(unix)]
    async fn getfacl_raw(path: &Path) -> String {
        let out = Command::new("getfacl")
            .arg("-n")
            .arg("--absolute-names")
            .arg("--")
            .arg(path)
            .output()
            .await
            .unwrap();
        String::from_utf8_lossy(&out.stdout).to_string()
    }

    /// Whether a named `user:<uid>:` ACL entry exists on `path` (any perms).
    #[cfg(unix)]
    async fn getfacl_has_user(path: &Path, uid: u32) -> bool {
        let want = format!("user:{uid}:");
        getfacl_raw(path)
            .await
            .lines()
            .any(|l| l.trim().starts_with(&want))
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn grant_read_deny_list_short_circuits_before_evaluator() {
        // The evaluator here is LLM-disabled with no policy, so a request that
        // reached it would be denied with "default-deny". A .vault_pass path is
        // instead denied with the deny-list reason, proving the static check
        // ran before any evaluator involvement.
        let (cfg, _buf) = make_test_config();
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join(".vault_pass");
        std::fs::write(&vault, "secret").unwrap();
        let caller = CallerIdentity::Unix {
            uid: unsafe { libc::geteuid() },
        };
        let result = handle_grant_request(
            &cfg,
            &caller,
            GrantRequest::Read {
                path: vault.display().to_string(),
                ttl_secs: 300,
                session_token: None,
                reevaluate: false,
            },
        )
        .await;
        assert!(!result.policy_allowed());
        assert!(
            result.policy_reason().contains("credential material"),
            "expected deny-list reason, got: {}",
            result.policy_reason()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn grant_read_denies_kubeconfig() {
        let (cfg, _buf) = make_test_config();
        let dir = tempfile::tempdir().unwrap();
        let kube = dir.path().join(".kube");
        std::fs::create_dir_all(&kube).unwrap();
        let config_file = kube.join("config");
        std::fs::write(&config_file, "apiVersion: v1").unwrap();
        let caller = CallerIdentity::Unix {
            uid: unsafe { libc::geteuid() },
        };
        let result = handle_grant_request(
            &cfg,
            &caller,
            GrantRequest::Read {
                path: config_file.display().to_string(),
                ttl_secs: 300,
                session_token: None,
                reevaluate: false,
            },
        )
        .await;
        assert!(!result.policy_allowed());
        assert!(
            result.policy_reason().contains("kube-proxy"),
            "got: {}",
            result.policy_reason()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn grant_revoke_is_not_scoped_to_the_requesting_caller() {
        // Revocation is intentionally an any-caller operation: a grant created
        // under session A can be revoked by a caller presenting session B's token
        // (or none at all), because revoking only ever removes access. This
        // proves that documented design (see the comment at handle_grant_revoke),
        // not an oversight in the unused `_session_token` parameter.
        let (cfg, _buf) = make_test_config();
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("values.yaml");
        std::fs::write(&target, "k: v").unwrap();
        let key = std::fs::canonicalize(&target)
            .unwrap()
            .display()
            .to_string();

        // Session A seeds an active grant. Empty ACL entries keep revocation free
        // of any real setfacl call (nothing to remove), so the test does not
        // depend on ACL tooling being installed.
        let now = now_unix();
        cfg.read_grants.write().await.insert(ReadGrant {
            handle: "hA".to_string(),
            principal: Some(PrincipalKey::from_uid(4242)),
            granting_session: Some("session-A".to_string()),
            target_path: key.clone(),
            grantee_uid: 4242,
            entries: Vec::new(),
            reason: "seeded by session A".to_string(),
            created_unix: now,
            expires_unix: now + 300,
            status: ReadGrantStatus::Active,
            revert_detail: None,
        });

        // Session B (a different token) revokes by path alone.
        let caller_b = CallerIdentity::Unix {
            uid: unsafe { libc::geteuid() },
        };
        let result = handle_grant_revoke(
            &cfg,
            &caller_b,
            target.display().to_string(),
            Some("session-B".to_string()),
        )
        .await;

        assert!(
            result.policy_allowed(),
            "any caller may revoke; got: {}",
            result.policy_reason()
        );
        assert_eq!(
            cfg.read_grants.read().await.get(&key).unwrap().status,
            ReadGrantStatus::Revoked,
            "the grant session A created must be revoked by session B"
        );
    }

    /// Build a home/pub_dir(0755)/priv_dir(0700)/values.yaml tree and return the
    /// paths, so ACL tests can exercise "add traverse only where missing".
    #[cfg(unix)]
    fn build_grant_tree(home: &Path) -> (PathBuf, PathBuf, PathBuf) {
        let pub_dir = home.join("pub_dir");
        std::fs::create_dir(&pub_dir).unwrap();
        set_mode(&pub_dir, 0o755);
        let priv_dir = pub_dir.join("priv_dir");
        std::fs::create_dir(&priv_dir).unwrap();
        set_mode(&priv_dir, 0o700);
        let target = priv_dir.join("values.yaml");
        std::fs::write(&target, "k: v").unwrap();
        set_mode(&target, 0o600);
        (pub_dir, priv_dir, target)
    }

    // A uid distinct from the test runner's own, so owner permission bits never
    // grant it traverse and the "where missing" logic must add an entry.
    #[cfg(unix)]
    const TEST_GRANTEE_UID: u32 = 987654;
    #[cfg(unix)]
    const TEST_GRANTEE_GID: u32 = 987654;

    #[cfg(unix)]
    #[tokio::test]
    async fn apply_read_grant_adds_traverse_only_where_missing_and_only_x() {
        if !acl_tools_available() {
            eprintln!("skipping: setfacl/getfacl not available");
            return;
        }
        let home = tempfile::tempdir().unwrap();
        set_mode(home.path(), 0o755); // world-traversable home: no traverse grant needed here
        let (pub_dir, priv_dir, target) = build_grant_tree(home.path());
        let pub_before = getfacl_raw(&pub_dir).await;

        let entries = apply_read_grant(&target, TEST_GRANTEE_UID, TEST_GRANTEE_GID, home.path())
            .await
            .expect("apply grant");

        // The private dir was 0700, so a traverse grant was added; the
        // world-traversable pub dir and home were skipped. The leaf got read.
        let priv_str = priv_dir.display().to_string();
        let target_str = target.display().to_string();
        let pub_str = pub_dir.display().to_string();
        let home_str = home.path().display().to_string();
        assert!(
            entries.iter().any(|e| e.path == priv_str && e.perms == "x"),
            "priv dir should get an x-only traverse grant: {entries:?}"
        );
        assert!(
            entries
                .iter()
                .any(|e| e.path == target_str && e.perms == "r"),
            "leaf should get an r grant: {entries:?}"
        );
        assert!(
            !entries.iter().any(|e| e.path == pub_str),
            "world-traversable pub dir must NOT get a grant: {entries:?}"
        );
        assert!(
            !entries.iter().any(|e| e.path == home_str),
            "world-traversable home must NOT get a grant: {entries:?}"
        );
        // Every ancestor grant is x-only (never r or w).
        for e in &entries {
            if e.path != target_str {
                assert_eq!(e.perms, "x", "ancestor grant must be x-only: {e:?}");
            }
        }
        // The untouched pub dir's ACL is byte-identical to before.
        assert_eq!(pub_before, getfacl_raw(&pub_dir).await);
        assert!(getfacl_user_has_traverse(&priv_dir, TEST_GRANTEE_UID).await);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn revoke_removes_exactly_added_entries_and_nothing_else() {
        if !acl_tools_available() {
            eprintln!("skipping: setfacl/getfacl not available");
            return;
        }
        let home = tempfile::tempdir().unwrap();
        set_mode(home.path(), 0o755);
        let (pub_dir, priv_dir, target) = build_grant_tree(home.path());

        // Seed an unrelated pre-existing ACL entry on the private dir; revocation
        // must leave it untouched (proving "removes exactly the added entries and
        // nothing else", which a blanket ACL wipe would violate).
        const OTHER_UID: u32 = 111222;
        let seed = Command::new("setfacl")
            .arg("-m")
            .arg(format!("u:{OTHER_UID}:rx"))
            .arg("--")
            .arg(&priv_dir)
            .output()
            .await
            .unwrap();
        assert!(seed.status.success());
        assert!(getfacl_has_user(&priv_dir, OTHER_UID).await);
        let pub_before = getfacl_raw(&pub_dir).await;

        let entries = apply_read_grant(&target, TEST_GRANTEE_UID, TEST_GRANTEE_GID, home.path())
            .await
            .expect("apply grant");
        assert!(getfacl_has_user(&priv_dir, TEST_GRANTEE_UID).await);

        let grant = ReadGrant {
            handle: "h".to_string(),
            principal: None,
            granting_session: None,
            target_path: target.display().to_string(),
            grantee_uid: TEST_GRANTEE_UID,
            entries,
            reason: "test".to_string(),
            created_unix: 0,
            expires_unix: 0,
            status: ReadGrantStatus::Reverting,
            revert_detail: None,
        };
        revoke_read_grant_acls(&grant).await.expect("revoke");

        // Exactly the granted entry is gone; the pre-existing unrelated entry
        // survives, and the never-touched pub dir is byte-identical.
        assert!(
            !getfacl_has_user(&priv_dir, TEST_GRANTEE_UID).await,
            "granted entry must be removed"
        );
        assert!(
            getfacl_has_user(&priv_dir, OTHER_UID).await,
            "pre-existing unrelated ACL entry must survive revocation"
        );
        assert!(!getfacl_has_user(&target, TEST_GRANTEE_UID).await);
        assert_eq!(pub_before, getfacl_raw(&pub_dir).await);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn expired_read_grant_is_auto_revoked() {
        if !acl_tools_available() {
            eprintln!("skipping: setfacl/getfacl not available");
            return;
        }
        let (cfg, _buf) = make_test_config();
        let home = tempfile::tempdir().unwrap();
        set_mode(home.path(), 0o755);
        let (_pub_dir, priv_dir, target) = build_grant_tree(home.path());

        let entries = apply_read_grant(&target, TEST_GRANTEE_UID, TEST_GRANTEE_GID, home.path())
            .await
            .expect("apply grant");
        assert!(getfacl_user_has_traverse(&priv_dir, TEST_GRANTEE_UID).await);

        let now = now_unix();
        let grant = ReadGrant {
            handle: "h".to_string(),
            principal: None,
            granting_session: None,
            target_path: target.display().to_string(),
            grantee_uid: TEST_GRANTEE_UID,
            entries,
            reason: "test".to_string(),
            created_unix: now,
            expires_unix: now.saturating_sub(1), // already past its TTL
            status: ReadGrantStatus::Active,
            revert_detail: None,
        };
        cfg.read_grants.write().await.insert(grant.clone());

        // The sweeper's due-claim drives the timer: an expired Active grant is
        // taken and then reverted.
        let due = cfg.read_grants.write().await.take_due(now_unix());
        assert_eq!(due.len(), 1);
        finish_read_grant_revert(&cfg, &due[0], "expiry").await;

        assert!(!getfacl_user_has_traverse(&priv_dir, TEST_GRANTEE_UID).await);
        assert_eq!(
            cfg.read_grants
                .read()
                .await
                .get(&grant.target_path)
                .unwrap()
                .status,
            ReadGrantStatus::Revoked
        );
    }
}
