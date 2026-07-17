use crate::grant_profile::{EvaluationMode, GrantRequest, GrantRequestDelta, SavedGrant};
use crate::session::{
    HistoricalGrant, SessionDecisionSource, SessionExecStatus, SessionGrantSummary, SessionOwner,
    SessionReport,
};
use guard::gating::approval::Approval;
use guard::gating::provisional::Provisional;
use guard::gating::{Coverage, DecisionTrace, DecisionVerbMatch};
use guard::principal::PrincipalKey;
use guard::redact::redact_output_text;
use serde::{Deserialize, Serialize};

use super::execute::audit_session_fingerprint;

// The untrusted request types any socket client can send live in the library
// crate (`guard::wire`) so their parsing surface can be fuzzed; re-export them
// here so daemon-side code keeps its existing `server::wire::*` paths.
pub use guard::wire::{
    BatchCommand, CommandSpec, ExecuteRequest, RevertSpec, SshHostKeyMode, VerbInvocation,
};

/// Identifies the caller for per-user secret injection.
#[derive(Debug, Clone)]
pub(super) enum CallerIdentity {
    /// Local caller over a Unix domain socket, identified by peer UID.
    /// Constructed only by the Unix transport; on Windows it exists for the
    /// shared match arms (and tests) but is never built.
    #[cfg_attr(windows, allow(dead_code))]
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

    /// True only for a kernel-verified LOCAL peer - a Unix-socket uid or a
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
                write!(
                    f,
                    "token_fingerprint={}",
                    audit_session_fingerprint(Some(token))
                )
            }
            Self::TcpAdmin { token } => {
                write!(
                    f,
                    "admin_token_fingerprint={}",
                    audit_session_fingerprint(Some(token))
                )
            }
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Distinct, greppable substring shared by every session principal-mismatch
/// denial across the execute, appeal, kubeconfig, batch, and self-inspection
/// paths, so an operator can grep the audit stream for one phrase.
pub(super) const SESSION_PRINCIPAL_MISMATCH: &str = "session principal mismatch";

/// Distinct, greppable substring for the fail-closed refusal of a session that
/// predates principal binding (state schema < 7). The operator must reissue the
/// session (or revoke it) before its authority can be used again.
pub(super) const SESSION_UNOWNED_REFUSED: &str =
    "session predates principal binding; reissue or revoke it";

/// Result of checking whether a caller may exercise a session's authority.
pub(super) enum SessionAuthz {
    /// The caller is the owning principal, or the daemon/operator principal.
    Allowed,
    /// The caller's authenticated principal is not the session owner.
    Mismatch,
    /// The session is `Unowned` (legacy) and the caller is not the operator.
    Unowned,
}

/// Server-side session-ownership decision. Uses only the principal the daemon
/// reads itself (`caller.principal()`), never a client-supplied value. The
/// daemon/operator principal keeps cross-session authority; any other caller
/// must be the exact owning principal on a kernel-authenticated local peer.
///
/// `Unowned` legacy sessions resolve to `Allowed` for the operator (so it can
/// inspect and revoke them) and `Unowned` for everyone else. Execution paths
/// additionally refuse `Unowned` for the operator too, fail-closed, at their
/// own call site.
pub(super) fn authorize_session_use(
    owner: &SessionOwner,
    caller: &CallerIdentity,
    daemon_principal: &PrincipalKey,
) -> SessionAuthz {
    let caller_principal = caller.principal();
    let is_operator = matches!(&caller_principal, Some(p) if daemon_principal.eq_ci(p))
        || matches!(caller, CallerIdentity::TcpAdmin { .. });
    match owner {
        SessionOwner::Unowned => {
            if is_operator {
                SessionAuthz::Allowed
            } else {
                SessionAuthz::Unowned
            }
        }
        SessionOwner::Principal(owner_key) => {
            if is_operator {
                return SessionAuthz::Allowed;
            }
            match &caller_principal {
                Some(p) if caller.is_local_peer() && owner_key.eq_ci(p) => SessionAuthz::Allowed,
                _ => SessionAuthz::Mismatch,
            }
        }
    }
}

// Coverage-composition results (`gating::coverage`) surface directly in the
// daemon's wire responses; re-export them so daemon-side code keeps its
// existing `server::wire::*` paths.
pub(super) use guard::gating::coverage::VerbContext;
pub use guard::gating::coverage::{VerbMatchInfo, VerbMatchScope};

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

pub(super) fn verb_trust_is_current(
    r: &guard::gating::verb::RenderedVerb,
    current_stamp: &str,
) -> bool {
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
pub(super) fn verb_effective_trust(verb: &guard::gating::verb::Verb, current_stamp: &str) -> bool {
    trust_is_current(
        verb.trusted,
        verb.auto_promoted,
        verb.promotion_stamp.as_deref(),
        current_stamp,
    )
}

fn default_api_endpoint() -> String {
    "default".to_string()
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
        activated_verbs: Vec<String>,
        #[serde(default)]
        override_markers: Vec<String>,
        #[serde(default)]
        ttl_secs: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prompt_append: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prose: Option<String>,
        /// Reusable grant to issue. `profile` remains a wire alias for older clients.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        saved_grant: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        profile: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        evaluation_mode: Option<EvaluationMode>,
        #[serde(default)]
        static_only: bool,
        #[serde(default)]
        auto_amend: bool,
        /// The principal (Unix uid or Windows SID string) the issued session is
        /// bound to. The operator sets this when minting a session for an agent
        /// that runs under a different local identity; when omitted the session
        /// is owned by the authenticated caller that issues it (the daemon
        /// principal for an operator-issued grant). Only the owning principal, or
        /// the daemon/operator principal, may later exercise the session's
        /// authority.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        owner: Option<String>,
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
    SessionExtend {
        token: String,
        ttl_secs: u64,
    },
    SessionLabel {
        token: String,
        label: String,
    },
    SessionRevokeFiltered {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        saved_grant: Option<String>,
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
    SessionStatus {
        token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        caller_token: Option<String>,
    },
    /// Issue an agent kubeconfig for one live, expiring Guard session. The
    /// upstream credential remains daemon-only.
    KubeconfigIssue {
        #[serde(default = "default_api_endpoint")]
        endpoint: String,
        session_token: String,
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
    VerbShow {
        name: String,
    },
    VerbDelete {
        name: String,
    },
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
    /// List evaluator-generated API verb coverage. Operator-only because
    /// coverage reveals policy topology and evaluator regime identifiers.
    VerbCoverageList,
    /// Clear evaluator-generated API verb coverage and evidence.
    VerbCoverageClear,
    SavedGrantList,
    SavedGrantShow {
        name: String,
    },
    SavedGrantSave {
        grant: SavedGrant,
    },
    SavedGrantEdit {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        activated_verbs: Vec<String>,
        #[serde(default)]
        clear_verbs: bool,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        override_markers: Vec<String>,
        #[serde(default)]
        clear_override_markers: bool,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        secret_names: Vec<String>,
        #[serde(default)]
        clear_secrets: bool,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        ceiling_verbs: Vec<String>,
        #[serde(default)]
        clear_ceiling_verbs: bool,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        ceiling_secrets: Vec<String>,
        #[serde(default)]
        clear_ceiling_secrets: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ceiling_ttl_secs: Option<u64>,
        #[serde(default)]
        clear_ceiling_ttl: bool,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        ceiling_modes: Vec<EvaluationMode>,
        #[serde(default)]
        clear_ceiling_modes: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allow_prompt_append: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ttl_secs: Option<u64>,
        #[serde(default)]
        clear_ttl: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prompt_append: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        evaluation_mode: Option<EvaluationMode>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auto_approve_requests: Option<bool>,
    },
    SavedGrantDelete {
        name: String,
    },
    SavedGrantRegenerate {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prompt: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        proposal_id: Option<String>,
    },
    GrantRequestSubmit {
        session_token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        caller_token: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        saved_grant: Option<String>,
        /// Human rationale for the requested change. Kept as `prompt` on the
        /// wire for backward compatibility; requested evaluator prose lives in
        /// `delta.prompt_append`.
        prompt: String,
        delta: GrantRequestDelta,
    },
    GrantRequestList {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_token: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        caller_token: Option<String>,
    },
    GrantRequestShow {
        handle: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_token: Option<String>,
    },
    GrantRequestApprove {
        handle: String,
    },
    GrantRequestDeny {
        handle: String,
        reason: String,
    },
    GrantRequestWithdraw {
        handle: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_token: Option<String>,
    },
    EvaluateBatch {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_token: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        caller_token: Option<String>,
        commands: Vec<BatchCommand>,
    },
    /// Walk the hash-chained audit log and report whether it is intact.
    /// Daemon-principal only: the audit file is daemon-owned state.
    AuditVerify,
    /// Read the last `limit` records of the audit log. Daemon-principal only.
    AuditTail {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<usize>,
    },
}

impl AdminRequest {
    /// Admin RPCs that require the caller to be the daemon UID.
    /// Ping is a public liveness probe. Secret RPCs and session
    /// listing are open to any connected user; they self-scope or
    /// redact sensitive fields so a caller cannot elevate from them.
    pub(super) fn requires_daemon_uid(&self) -> bool {
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
                | Self::SessionStatus { .. }
                | Self::KubeconfigIssue { .. }
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
                | Self::VerbShow { .. }
                | Self::GrantRequestList { .. }
                | Self::GrantRequestShow { .. }
                | Self::GrantRequestSubmit { .. }
                | Self::GrantRequestWithdraw { .. }
                | Self::EvaluateBatch { .. }
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
    SessionStatus {
        report: SessionReport,
        approvals: Vec<ApprovalSummary>,
        provisionals: Vec<ProvisionalSummary>,
        requests: Vec<GrantRequest>,
    },
    KubeconfigIssued {
        yaml: String,
        expires_at: u64,
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
    VerbCoverage {
        items: Vec<guard::gating::api_promotion::ApiCoverageEntry>,
    },
    VerbCoverageCleared {
        removed: usize,
    },
    SavedGrants {
        items: Vec<SavedGrant>,
    },
    SavedGrant {
        grant: SavedGrant,
    },
    SavedGrantRegenerated {
        grant: SavedGrant,
        added: Vec<String>,
        removed: Vec<String>,
        changed: Vec<String>,
    },
    SavedGrantRegenerationProposal {
        name: String,
        source_revision: u64,
        regime: String,
        proposal_id: String,
        candidate: guard::gating::verb::Verb,
        added: Vec<String>,
        removed: Vec<String>,
        changed: Vec<String>,
    },
    GrantRequests {
        items: Vec<GrantRequest>,
    },
    GrantRequest {
        request: GrantRequest,
    },
    SessionBulkRevoked {
        count: usize,
    },
    EvaluationBatch {
        items: Vec<BatchEvaluation>,
    },
    AuditVerification {
        path: String,
        verification: guard::audit::ChainVerification,
    },
    AuditRecords {
        path: String,
        items: Vec<serde_json::Value>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchEvaluation {
    pub command: String,
    pub allowed: bool,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<i32>,
    pub decision_source: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verb_matches: Vec<VerbMatchInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guidance: Option<String>,
}

/// Agent-facing view of a catalog verb (its menu entry).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerbSummary {
    pub name: String,
    pub description: String,
    pub binary: String,
    #[serde(default = "verb_summary_default_baseline")]
    pub baseline: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coverage: Vec<guard::gating::verb::VerbCoverageCell>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_plan: Option<String>,
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

fn verb_summary_default_baseline() -> bool {
    true
}

/// Operator-facing view of a provisional execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionalSummary {
    pub handle: String,
    pub status: String,
    pub command: String,
    pub revert_command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm_check: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_fingerprint: Option<String>,
    pub reason: String,
    pub created_unix: u64,
    pub deadline_unix: u64,
    pub forward_done: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revert_exit: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revert_detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_trace: Option<DecisionTrace>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_trace: Option<DecisionTrace>,
}

impl ProvisionalSummary {
    pub(super) fn from_row(p: &Provisional) -> Self {
        // Summaries are operator-facing display records (session status,
        // provisional listings), never the executed command, so credential
        // material embedded in argv is redacted at this boundary.
        let command = if p.args.is_empty() {
            p.binary.clone()
        } else {
            format!("{} {}", p.binary, p.args.join(" "))
        };
        Self {
            handle: p.handle.clone(),
            status: p.status.as_str().to_string(),
            command: redact_output_text(&command),
            revert_command: redact_output_text(&p.revert_command_line()),
            confirm_check: p.confirm_check_binary.as_ref().map(|binary| {
                redact_output_text(&if p.confirm_check_args.is_empty() {
                    binary.clone()
                } else {
                    format!("{} {}", binary, p.confirm_check_args.join(" "))
                })
            }),
            control_path: p.control_path.clone(),
            session_fingerprint: p.session_fingerprint.clone(),
            reason: redact_output_text(&p.reason),
            created_unix: p.created_unix,
            deadline_unix: p.deadline_unix,
            forward_done: p.forward_done,
            cwd: p.cwd.as_ref().map(|path| path.display().to_string()),
            secret_names: p
                .secret_keys
                .values()
                .chain(p.secret_file_keys.values())
                .cloned()
                .collect(),
            principal: p.principal.as_ref().map(|p| p.as_str().to_string()),
            revert_exit: p.revert_exit,
            revert_detail: p.revert_detail.as_deref().map(redact_output_text),
            decision_trace: p.decision_trace.clone(),
        }
    }
}

impl ApprovalSummary {
    pub(super) fn from_row(a: &Approval) -> Self {
        // See `ProvisionalSummary::from_row`: display boundary, argv may
        // carry inline credentials.
        Self {
            handle: a.handle.clone(),
            status: a.status.as_str().to_string(),
            command: redact_output_text(&a.snapshot.command_line()),
            reason: redact_output_text(&a.reason),
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
            stdout: a.result_stdout.as_deref().map(redact_output_text),
            stderr: a.result_stderr.as_deref().map(redact_output_text),
            decided_reason: a.decided_reason.as_deref().map(redact_output_text),
            notes: a
                .notes
                .iter()
                .map(|note| guard::gating::approval::ApprovalNote {
                    at_unix: note.at_unix,
                    author: note.author.clone(),
                    text: redact_output_text(&note.text),
                })
                .collect(),
            decision_trace: a.decision_trace.clone(),
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
    /// Short content hash of the active verb catalog.
    #[serde(default)]
    pub verb_catalog_hash: String,
    /// Filesystem change time for a file-backed verb catalog.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verb_catalog_changed_unix: Option<u64>,
    /// Bounded command-handler and evaluator admission counters.
    #[serde(default)]
    pub command_admission: CommandAdmissionStatus,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CommandAdmissionStatus {
    pub handler_attempted: u64,
    pub handler_admitted: u64,
    pub handler_rejected: u64,
    pub evaluator_attempted: u64,
    pub evaluator_admitted: u64,
    pub evaluator_rate_limited: u64,
    pub evaluator_concurrency_limited: u64,
    pub evaluator_errors: u64,
    pub evaluator_circuit_rejections: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum IncomingMessage {
    Admin {
        admin: Box<AdminRequest>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        admin_token: Option<String>,
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
    /// Every applicable typed verb cell in canonical order. Present in
    /// structured output even when success stays quiet on stderr.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verb_matches: Vec<VerbMatchInfo>,
    /// Actionable guidance for denied or held coverage decisions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verb_guidance: Option<String>,
    /// Stable source label for the admission decision.
    #[serde(default = "default_decision_source")]
    pub decision_source: String,
    /// Complete versioned explanation of the admission decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_trace: Option<DecisionTrace>,
}

fn default_decision_source() -> String {
    "validation".to_string()
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
#[allow(clippy::large_enum_variant)]
pub(crate) enum ExecuteStreamMessage {
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
pub(super) enum ExecOutcome {
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

pub(super) struct ExecuteResult {
    policy: PolicyOutcome,
    pub(super) exec: ExecOutcome,
    /// Secret-store key names whose values entered the environment of a
    /// successfully spawned child. This does not prove the child consumed them.
    exposed_secret_refs: Vec<String>,
    verb_matches: Vec<VerbMatchInfo>,
    verb_guidance: Option<String>,
    decision_source: SessionDecisionSource,
}

impl ExecuteResult {
    pub(super) fn denied(reason: impl Into<String>) -> Self {
        Self {
            policy: PolicyOutcome::Denied {
                reason: reason.into(),
            },
            exec: ExecOutcome::NotAttempted,
            exposed_secret_refs: Vec::new(),
            verb_matches: Vec::new(),
            verb_guidance: None,
            decision_source: SessionDecisionSource::Validation,
        }
    }

    /// Convenience constructor for "policy approved and exec completed".
    pub(super) fn completed(
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
            exposed_secret_refs: Vec::new(),
            verb_matches: Vec::new(),
            verb_guidance: None,
            decision_source: SessionDecisionSource::Validation,
        }
    }

    /// Convenience constructor for "policy approved but the child never ran"
    /// (a spawn/setup failure such as ENOENT on the binary).
    pub(super) fn exec_failed(
        policy_reason: impl Into<String>,
        exec_reason: impl Into<String>,
    ) -> Self {
        Self {
            policy: PolicyOutcome::Allowed {
                reason: policy_reason.into(),
            },
            exec: ExecOutcome::Failed {
                reason: exec_reason.into(),
                started: false,
            },
            exposed_secret_refs: Vec::new(),
            verb_matches: Vec::new(),
            verb_guidance: None,
            decision_source: SessionDecisionSource::Validation,
        }
    }

    /// Constructor for "policy approved, the child WAS launched, then execution
    /// failed" (e.g. the client stream dropped mid-run). The child may have had
    /// observable effects, which the containment envelope must account for.
    pub(super) fn exec_failed_after_start(
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
            exposed_secret_refs: Vec::new(),
            verb_matches: Vec::new(),
            verb_guidance: None,
            decision_source: SessionDecisionSource::Validation,
        }
    }

    pub(super) fn dry_run(reason: impl Into<String>) -> Self {
        Self {
            policy: PolicyOutcome::Allowed {
                reason: reason.into(),
            },
            exposed_secret_refs: Vec::new(),
            exec: ExecOutcome::DryRun { coverage: None },
            verb_matches: Vec::new(),
            verb_guidance: None,
            decision_source: SessionDecisionSource::Validation,
        }
    }

    /// A consequence-gated dry-run: reports the gate decision and its coverage
    /// (what would be checked and what would not) without executing.
    pub(super) fn dry_run_gated(reason: impl Into<String>, coverage: Coverage) -> Self {
        Self {
            policy: PolicyOutcome::Allowed {
                reason: reason.into(),
            },
            exec: ExecOutcome::DryRun {
                coverage: Some(coverage),
            },
            exposed_secret_refs: Vec::new(),
            verb_matches: Vec::new(),
            verb_guidance: None,
            decision_source: SessionDecisionSource::Validation,
        }
    }

    /// Approved but held for operator approval (irreversible / uncertain /
    /// high-risk). Not executed.
    pub(super) fn held(reason: impl Into<String>, handle: String, coverage: Coverage) -> Self {
        Self {
            policy: PolicyOutcome::Allowed {
                reason: reason.into(),
            },
            exec: ExecOutcome::Held { handle, coverage },
            exposed_secret_refs: Vec::new(),
            verb_matches: Vec::new(),
            verb_guidance: None,
            decision_source: SessionDecisionSource::Validation,
        }
    }

    /// Approved and executed inside a containment envelope.
    pub(super) fn provisional(
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
            exposed_secret_refs: Vec::new(),
            verb_matches: Vec::new(),
            verb_guidance: None,
            decision_source: SessionDecisionSource::Validation,
        }
    }

    pub(super) fn with_exposed_secret_refs(mut self, mut exposed_secret_refs: Vec<String>) -> Self {
        exposed_secret_refs.sort();
        exposed_secret_refs.dedup();
        self.exposed_secret_refs = exposed_secret_refs;
        self
    }

    pub(super) fn exposed_secret_refs(&self) -> &[String] {
        &self.exposed_secret_refs
    }

    pub(super) fn exit_code(&self) -> Option<i32> {
        match &self.exec {
            ExecOutcome::Completed { exit_code, .. }
            | ExecOutcome::Provisional { exit_code, .. } => *exit_code,
            _ => None,
        }
    }

    pub(super) fn with_verb_resolution(
        mut self,
        matches: Vec<VerbMatchInfo>,
        guidance: Option<String>,
    ) -> Self {
        self.verb_matches = matches;
        self.verb_guidance = guidance;
        self
    }

    pub(super) fn with_decision_source(mut self, source: SessionDecisionSource) -> Self {
        self.decision_source = source;
        self
    }

    /// True if the policy approved the command. Note: this does NOT mean
    /// the command actually ran - check the exec outcome for that.
    pub(super) fn policy_allowed(&self) -> bool {
        matches!(self.policy, PolicyOutcome::Allowed { .. })
    }

    /// Reason for the policy decision (allow rationale or denial reason).
    /// Production paths consume the reason via `into_response`; tests assert
    /// on it directly.
    #[cfg(test)]
    pub(super) fn policy_reason(&self) -> &str {
        match &self.policy {
            PolicyOutcome::Allowed { reason } | PolicyOutcome::Denied { reason } => reason,
        }
    }

    /// Build the `ExecuteResponse` wire payload. Callers that need to emit
    /// audit events first should do so before consuming the result.
    pub(super) fn into_response(self) -> ExecuteResponse {
        let allowed = self.policy_allowed();
        let verb_matches = self.verb_matches;
        let verb_guidance = self.verb_guidance;
        let decision_source = self.decision_source.as_str().to_string();
        let decision_trace = Some(DecisionTrace {
            version: DecisionTrace::VERSION,
            decision_source: decision_source.clone(),
            verb_matches: verb_matches
                .iter()
                .map(|matched| DecisionVerbMatch {
                    verb: matched.verb.clone(),
                    cell: matched.cell.clone(),
                    scope: format!("{:?}", matched.scope).to_ascii_lowercase(),
                    action: format!("{:?}", matched.action).to_ascii_lowercase(),
                    features: matched.features.clone(),
                    selected: matched.selected,
                    overridden: matched.overridden,
                })
                .collect(),
            failed_dimensions: if allowed {
                Vec::new()
            } else {
                vec![decision_source.clone()]
            },
            conflict: verb_guidance
                .as_ref()
                .filter(|guidance| guidance.to_ascii_lowercase().contains("conflict"))
                .cloned(),
            guidance: verb_guidance.clone(),
            suggested_grant_delta: verb_guidance
                .as_ref()
                .filter(|guidance| guidance.contains("grant"))
                .cloned(),
        });
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
                verb_matches,
                verb_guidance,
                decision_source,
                decision_trace,
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
                verb_matches,
                verb_guidance,
                decision_source,
                decision_trace,
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
                verb_matches,
                verb_guidance,
                decision_source,
                decision_trace,
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
                verb_matches,
                verb_guidance,
                decision_source,
                decision_trace,
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
                verb_matches,
                verb_guidance,
                decision_source,
                decision_trace,
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
                verb_matches,
                verb_guidance,
                decision_source,
                decision_trace,
            },
        }
    }

    pub(super) fn session_exec_status(&self) -> SessionExecStatus {
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
