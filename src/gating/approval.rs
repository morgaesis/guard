//! Operator-approval state: irreversible (or uncertain / high-risk) commands
//! held at a point of no return until a human approves the exact artifact.
//!
//! A held command does not execute. It is enqueued with an immutable execution
//! snapshot, and only an authenticated operator can approve it. Approval executes
//! strictly from the stored snapshot - no fields are accepted at approve time -
//! so the approval is bound to exactly what was reviewed (gate on prediction).
//! An unattended queue fails closed: holds past their TTL transition to
//! `Expired` (a denial), they never stall forever.
//!
//! This module is pure state plus a per-handle `Notify` so a blocking
//! `--wait-approval` client can be woken the instant a decision lands. Process
//! exec and persistence live in the daemon.

use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use tokio::sync::Notify;

use super::{sanitize_gate_text, DecisionTrace, GateError, Reversibility};
use crate::principal::{scope_eq, PrincipalKey};

/// Optional binding of held secret VALUES to the artifact the operator reviewed.
/// Captured at hold time, keyed by the injected env-var name: every referenced
/// secret is bound - a resolved one by an installation-keyed HMAC of its value
/// (never the value itself), an unresolved one by a sentinel. Verified at
/// approve time: if a mapped value changed, a bound-resolved secret vanished, or a
/// bound-unresolved secret now resolves, approval fails closed. This closes the
/// window where a same-principal caller alters (or creates) its own mapped
/// secret values between hold and approval. `None` means no binding was captured
/// (an older row, or a hold with no referenced secrets) and verification is
/// accepted only when no secret authority exists. The HMAC key lives outside
/// SQLite, so a copied state database does not expose an offline secret-guessing oracle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash, Default)]
pub struct SecretBinding {
    /// Per-hold random salt (hex).
    pub salt: String,
    /// env-var -> hex HMAC-SHA-256(domain, salt, value).
    pub hashes: BTreeMap<String, String>,
    /// Secret-store names injected by the tool configuration. `None` marks a
    /// legacy hold that did not capture tool-level secret provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_hashes: Option<BTreeMap<String, ToolSecretBinding>>,
}

/// Secret reference and value digest bound to one tool-configured environment
/// variable at hold time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct ToolSecretBinding {
    pub secret_name: String,
    pub hash: String,
}

/// Provenance of command authority that may survive an approval or restart
/// boundary. Typed sources are required for tools whose behavior depends on
/// operator-bound configuration and artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DelayedAuthoritySource {
    RawApproval,
    TypedVerb,
    RawControl,
    TypedControl,
}

/// Closed command grammar used to reconstruct delayed process authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DelayedAuthorityProfile {
    PrimaryOnly,
    FixtureApi,
    SystemdControl,
    TypedAnsible,
    TypedKubectl,
    TypedHelm,
}

impl DelayedAuthorityProfile {
    /// Whether the tool can discover executable, configuration, credential,
    /// or filesystem authority through its user profile and environment.
    /// Keeping this property on the closed profile enum makes every new
    /// process-authority profile classify its environment behavior.
    pub const fn discovers_profile_authority(self) -> bool {
        match self {
            Self::TypedAnsible | Self::TypedKubectl | Self::TypedHelm => true,
            Self::PrimaryOnly | Self::FixtureApi | Self::SystemdControl => false,
        }
    }
}

/// Versioned proof that a delayed command remains inside a known process and
/// secondary-authority grammar. Replay regenerates the plan under current code
/// and requires exact equality before process start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct DelayedAuthorityPlan {
    pub version: u8,
    pub source: DelayedAuthoritySource,
    pub profile: DelayedAuthorityProfile,
    pub normalized_command_digest: String,
    pub secondary_path_search: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ProcessExecutionIdentityMode {
    FixedUser,
    Caller,
}

/// Complete Unix process identity selected for an approved child. Group
/// membership is executable and filesystem authority, so replay must bind it
/// with the command rather than resolve it after approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct ProcessExecutionIdentity {
    pub mode: ProcessExecutionIdentityMode,
    pub user_id: u32,
    pub primary_group_id: u32,
    pub supplementary_group_ids: Vec<u32>,
}

/// Immutable process-start authority captured when a command enters the hold
/// queue. Replay recomputes this binding before approval can spawn a child, so
/// executable resolution, tool mappings, profiles, and secondary executable
/// search paths cannot change underneath an operator decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct ProcessAuthorityBinding {
    /// Closed delayed-execution grammar and its authority provenance. `None`
    /// marks a legacy row that cannot be replayed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delayed_authority: Option<DelayedAuthorityPlan>,
    /// Exact execution mode and OS identity selected when authority was
    /// captured. `None` marks a legacy row that must be re-armed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_identity: Option<ProcessExecutionIdentity>,
    /// Canonical primary executable selected by the daemon.
    pub executable: PathBuf,
    /// Daemon executable-search input retained only for profiles that permit
    /// secondary process discovery.
    pub daemon_path: Option<String>,
    /// Non-secret digest of the complete tool environment registry.
    pub tool_registry_fingerprint: String,
    /// Installation-keyed HMAC of the complete effective child environment. Secret
    /// values and daemon-created secret-file paths are represented by their
    /// stable secret references before hashing, so this binds environment
    /// authority without persisting credentials or ephemeral paths.
    #[serde(default)]
    pub effective_environment_fingerprint: String,
    /// Canonical operator artifacts and their content-bound SHA-256 digests.
    pub artifacts: BTreeMap<PathBuf, String>,
    /// Ordered executable-search directories and their entry fingerprints.
    pub executable_search_directories: Vec<(PathBuf, String)>,
}

/// The immutable execution inputs an approval is bound to. Stored at enqueue and
/// replayed verbatim at approve time. Secret *values* are never stored - only the
/// env-var -> secret-key mappings for environment and file injection, resolved
/// at exec under the original caller's namespace, plus an optional keyed-HMAC
/// [`SecretBinding`] used to detect a value swap between hold and approval.
/// `BTreeMap` gives a stable order for a stable fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct ApprovalSnapshot {
    pub binary: String,
    pub args: Vec<String>,
    /// Canonical working directory for execution. Absent on rows written before
    /// cwd propagation existed, which replays under the daemon's default cwd.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<PathBuf>,
    /// Non-sensitive plain per-run environment values authorized by the bound
    /// operator-authored typed verb. Credential-shaped bindings use
    /// `secret_keys` or `secret_file_keys` instead.
    pub env: BTreeMap<String, String>,
    /// env-var -> secret-key mapping (keys only; values resolved at exec).
    pub secret_keys: BTreeMap<String, String>,
    /// Non-secret fingerprint of the originating Guard session. Approval
    /// audit events use this to correlate the held command without persisting
    /// the bearer token itself.
    #[serde(
        default,
        alias = "session_ref",
        skip_serializing_if = "Option::is_none"
    )]
    pub session_fingerprint: Option<String>,
    /// Revision of the issued session at hold time. A changed or revoked live
    /// session voids approval of the forward command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_revision: Option<String>,
    /// Saved-grant secret selectors captured at hold time. `None` means the
    /// session was unrestricted; `Some([])` means no secret is entitled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_entitlements: Option<Vec<String>>,
    /// env-var -> secret-key mapping materialized as child-lifetime files.
    #[serde(default)]
    pub secret_file_keys: BTreeMap<String, String>,
    /// If this hold originated from a verb, the verb name and catalog version.
    /// `verb_params` remains for schema compatibility and is always empty;
    /// replay uses the rendered immutable argv above. The version is the
    /// staleness fallback for rows without a `verb_digest`, where any catalog
    /// change voids the approval.
    pub verb_name: Option<String>,
    pub verb_params: BTreeMap<String, String>,
    pub catalog_version: Option<u64>,
    /// Definition digest of the matched verb at hold time. The hold is bound
    /// to the matched verb's definition, so it survives unrelated catalog
    /// changes; only removing or changing that verb voids the approval.
    /// Absent on rows written before the digest existed.
    #[serde(default)]
    pub verb_digest: Option<String>,
    /// Canonical digest of the complete composed matcher selection. Rows
    /// without this field use the conservative single-verb compatibility
    /// check at replay.
    #[serde(default)]
    pub verb_composition_digest: Option<String>,
    /// Whether the held typed matcher explicitly authorized every
    /// caller-controlled environment binding. Older rows fail closed.
    #[serde(default)]
    pub verb_environment_authority: bool,
    /// Whether the held typed matcher authorized local file authority through
    /// an exact argv template. Older rows fail closed.
    #[serde(default)]
    pub verb_local_file_authority: bool,
    /// Effective execution timeout captured with the immutable approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec_timeout_secs: Option<u64>,
    /// Session-scoped access verbs selected when this immutable hold was
    /// created. Approval consumes their original bounded authority.
    #[serde(default)]
    pub access_verbs: Vec<String>,
    /// Exact access-request IDs selected without consumption when the hold was
    /// created. Replay may consume only this bound set.
    #[serde(default)]
    pub access_requests: Vec<String>,
    /// Principal of the original caller, to reconstruct exec identity.
    /// Deserializes from the legacy numeric `caller_uid` form so rows written by
    /// an older daemon survive an upgrade.
    #[serde(
        default,
        alias = "caller_uid",
        deserialize_with = "crate::principal::principal_from_legacy"
    )]
    pub principal: Option<PrincipalKey>,
    /// Optional secret-value binding captured at hold time (see
    /// [`SecretBinding`]). Absent on rows written before value binding existed.
    #[serde(default)]
    pub secret_binding: Option<SecretBinding>,
    /// Exact non-secret process authority captured at hold time. Legacy
    /// executable rows without this field fail closed; descriptive API holds
    /// never spawn and do not require it.
    #[serde(default)]
    pub process_authority: Option<ProcessAuthorityBinding>,
}

impl ApprovalSnapshot {
    pub fn has_typed_environment_authority(&self) -> bool {
        self.verb_environment_authority
            && self.verb_name.is_some()
            && self.catalog_version.is_some()
    }

    pub fn command_line(&self) -> String {
        crate::redact::redact_command_line(&self.binary, &self.args)
    }

    pub fn contains_sensitive_literals(&self) -> bool {
        crate::redact::command_contains_sensitive_literals(&self.binary, &self.args)
    }

    /// Remove literal-sensitive argv after the row has become non-replayable.
    pub fn scrub_sensitive_literals(&mut self) -> bool {
        if !self.contains_sensitive_literals() {
            return false;
        }
        self.binary = "<unavailable>".to_string();
        self.args.clear();
        true
    }

    /// Short, stable fingerprint shown to the operator so two visually-similar
    /// holds are distinguishable. Not a security boundary - the binding is the
    /// stored snapshot itself, executed verbatim - just an operator aid.
    pub fn fingerprint(&self) -> String {
        let mut h = DefaultHasher::new();
        self.hash(&mut h);
        format!("{:016x}", h.finish())
    }
}

/// Lifecycle of a held command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    /// Waiting for an operator decision.
    Pending,
    /// Operator approved; exec is in flight. In-memory transient; if seen on
    /// startup the exec was interrupted, so recovery routes it to `ExecFailed`.
    Approving,
    /// Approved and executed; the result fields carry the outcome.
    Approved,
    /// Operator denied it.
    Denied,
    /// TTL elapsed with no decision - a fail-closed denial.
    Expired,
    /// Approved but the command could not run (spawn error, or interrupted).
    ExecFailed,
}

impl ApprovalStatus {
    pub fn is_pending(self) -> bool {
        matches!(self, Self::Pending | Self::Approving)
    }

    /// Whether a waiter or poller should stop waiting (a decision has landed).
    pub fn is_decided(self) -> bool {
        matches!(
            self,
            Self::Approved | Self::Denied | Self::Expired | Self::ExecFailed
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approving => "approving",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::ExecFailed => "exec_failed",
        }
    }
}

/// One turn in a held command's approval discussion. Either side of the gate
/// (the operator, or the hold's original requester) can post context before the
/// operator decides, turning the accept/deny gate into a short conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalNote {
    pub at_unix: u64,
    /// Which side posted: `operator` or `requester`.
    pub author: String,
    pub text: String,
}

/// One held command awaiting operator approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub handle: String,
    pub snapshot: ApprovalSnapshot,
    /// Caller-facing rationale for the hold (the evaluator's allow reason).
    pub reason: String,
    pub risk: Option<i32>,
    pub reversibility: Option<Reversibility>,
    /// Admission explanation captured with the immutable held artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_trace: Option<DecisionTrace>,
    pub created_unix: u64,
    pub ttl_secs: u64,
    pub status: ApprovalStatus,
    /// Decision/outcome fields, populated once decided.
    pub decided_unix: Option<u64>,
    pub decided_reason: Option<String>,
    pub result_exit: Option<i32>,
    pub result_stdout: Option<String>,
    pub result_stderr: Option<String>,
    /// Discussion thread on this hold (operator <-> requester) before a
    /// decision. Defaults empty for rows written before notes existed.
    #[serde(default)]
    pub notes: Vec<ApprovalNote>,
}

impl Approval {
    pub fn deadline_unix(&self) -> u64 {
        self.created_unix.saturating_add(self.ttl_secs)
    }

    /// Canonicalize all non-authoritative text before it reaches a registry,
    /// durable store, audit projection, or wire response.
    pub fn sanitize_explanatory_text(&mut self) -> bool {
        fn sanitize(value: &mut String) -> bool {
            let sanitized = sanitize_gate_text(value);
            if sanitized == *value {
                return false;
            }
            *value = sanitized;
            true
        }

        let mut changed = sanitize(&mut self.reason);
        if let Some(trace) = self.decision_trace.as_mut() {
            changed |= trace.sanitize_explanatory_text();
        }
        if let Some(reason) = self.decided_reason.as_mut() {
            changed |= sanitize(reason);
        }
        for note in &mut self.notes {
            changed |= sanitize(&mut note.author);
            changed |= sanitize(&mut note.text);
        }
        let original_stdout = self.result_stdout.take();
        let original_stderr = self.result_stderr.take();
        let stdout = bound_approval_transcript(original_stdout.clone()).0;
        let stderr = bound_approval_transcript(original_stderr.clone()).0;
        let stdout_changed = stdout != original_stdout;
        let stderr_changed = stderr != original_stderr;
        self.result_stdout = stdout;
        self.result_stderr = stderr;
        changed | stdout_changed | stderr_changed
    }
}

/// In-memory registry of held commands plus per-handle notifiers for blocking
/// waiters. Notifiers are not persisted (they are process-local wakeups).
#[derive(Default)]
pub struct ApprovalRegistry {
    items: HashMap<String, Approval>,
    notifiers: HashMap<String, Arc<Notify>>,
    leases: Arc<WaiterLeaseState>,
}

pub const APPROVAL_TRANSCRIPT_SERIALIZED_BYTES: usize = 262_144;
pub const APPROVAL_TRANSCRIPT_TRUNCATED_SUFFIX: &str = "\n[guard persisted transcript truncated]\n";

fn json_payload_bytes(character: char) -> usize {
    match character {
        '"' | '\\' | '\u{0008}' | '\u{0009}' | '\u{000a}' | '\u{000c}' | '\u{000d}' => 2,
        '\u{0000}'..='\u{001f}' => 6,
        _ => character.len_utf8(),
    }
}

/// Redact and bound one transcript using the bytes occupied by its serialized
/// JSON string field, including quotes and escapes. The same projection is
/// used for persistence, restart loading, and wire responses.
pub fn bound_approval_transcript(value: Option<String>) -> (Option<String>, bool) {
    let Some(value) = value else {
        return (None, false);
    };
    let exposed = crate::redact::redact_output_text(&value);
    let already_truncated = exposed.ends_with(APPROVAL_TRANSCRIPT_TRUNCATED_SUFFIX);
    if serde_json::to_vec(&exposed)
        .expect("serializing a string cannot fail")
        .len()
        <= APPROVAL_TRANSCRIPT_SERIALIZED_BYTES
    {
        return (Some(exposed), already_truncated);
    }

    let source = exposed
        .strip_suffix(APPROVAL_TRANSCRIPT_TRUNCATED_SUFFIX)
        .unwrap_or(&exposed);
    let suffix_payload = APPROVAL_TRANSCRIPT_TRUNCATED_SUFFIX
        .chars()
        .map(json_payload_bytes)
        .sum::<usize>();
    let mut available = APPROVAL_TRANSCRIPT_SERIALIZED_BYTES
        .saturating_sub(2)
        .saturating_sub(suffix_payload);
    let mut boundary = 0;
    for (offset, character) in source.char_indices() {
        let bytes = json_payload_bytes(character);
        if bytes > available {
            break;
        }
        available -= bytes;
        boundary = offset + character.len_utf8();
    }
    let mut bounded = source[..boundary].to_string();
    bounded.push_str(APPROVAL_TRANSCRIPT_TRUNCATED_SUFFIX);
    debug_assert!(
        serde_json::to_vec(&bounded)
            .expect("serializing a string cannot fail")
            .len()
            <= APPROVAL_TRANSCRIPT_SERIALIZED_BYTES
    );
    (Some(bounded), true)
}

#[derive(Default)]
struct WaiterLeaseState {
    next_id: AtomicU64,
    active: Mutex<HashMap<String, HashMap<u64, ()>>>,
}

/// A transport-owned hold observation lease. Dropping it is idempotent and
/// only releases the exact token that created it.
pub struct WaiterLease {
    handle: String,
    lease_id: u64,
    state: Weak<WaiterLeaseState>,
}

impl WaiterLease {
    pub fn release_once(&mut self) {
        let Some(state) = self.state.upgrade() else {
            return;
        };
        let Ok(mut active) = state.active.lock() else {
            return;
        };
        if let Some(tokens) = active.get_mut(&self.handle) {
            tokens.remove(&self.lease_id);
            if tokens.is_empty() {
                active.remove(&self.handle);
            }
        }
        self.state = Weak::new();
    }
}

impl Drop for WaiterLease {
    fn drop(&mut self) {
        self.release_once();
    }
}

impl ApprovalRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuild from persisted rows, applying recovery: an `Approving` row means
    /// an exec was interrupted by a restart, so it becomes `ExecFailed` (an
    /// irreversible action may have partially run; surface it, never silently
    /// re-run). Returns handles recovered to `ExecFailed`.
    pub fn from_rows(rows: Vec<Approval>, now: u64) -> (Self, Vec<String>) {
        let mut items = HashMap::new();
        let mut recovered = Vec::new();
        for mut row in rows {
            row.sanitize_explanatory_text();
            if row.status == ApprovalStatus::Approving {
                row.status = ApprovalStatus::ExecFailed;
                row.decided_unix = Some(now);
                row.decided_reason =
                    Some("daemon restarted while executing; outcome unknown".to_string());
                recovered.push(row.handle.clone());
            }
            items.insert(row.handle.clone(), row);
        }
        recovered.sort();
        (
            Self {
                items,
                notifiers: HashMap::new(),
                leases: Arc::new(WaiterLeaseState::default()),
            },
            recovered,
        )
    }

    /// Enqueue a hold and return its notifier so a blocking waiter can await it.
    pub fn enqueue(&mut self, mut approval: Approval) -> Arc<Notify> {
        approval.sanitize_explanatory_text();
        let notify = Arc::new(Notify::new());
        self.notifiers
            .insert(approval.handle.clone(), notify.clone());
        self.items.insert(approval.handle.clone(), approval);
        notify
    }

    /// Register a waiter before an approval mutation. The notifier and lease
    /// are created under the same registry lock, so retention cannot remove a
    /// row between authorization and observation.
    pub fn register_waiter(&mut self, handle: &str) -> Option<(Arc<Notify>, WaiterLease)> {
        if !self.items.contains_key(handle) {
            return None;
        }
        let notify = self
            .notifiers
            .entry(handle.to_string())
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone();
        let lease_id = self.leases.next_id.fetch_add(1, Ordering::Relaxed);
        let mut active = self.leases.active.lock().ok()?;
        active
            .entry(handle.to_string())
            .or_default()
            .insert(lease_id, ());
        Some((
            notify,
            WaiterLease {
                handle: handle.to_string(),
                lease_id,
                state: Arc::downgrade(&self.leases),
            },
        ))
    }

    pub fn active_waiters(&self, handle: &str) -> usize {
        self.leases
            .active
            .lock()
            .ok()
            .and_then(|active| active.get(handle).map(HashMap::len))
            .unwrap_or(0)
    }

    pub fn get(&self, handle: &str) -> Option<&Approval> {
        self.items.get(handle)
    }

    pub fn set_decision_trace(&mut self, handle: &str, trace: DecisionTrace) -> Option<Approval> {
        let approval = self.items.get_mut(handle)?;
        approval.decision_trace = Some(trace);
        approval.sanitize_explanatory_text();
        Some(approval.clone())
    }

    pub fn notifier(&self, handle: &str) -> Option<Arc<Notify>> {
        self.notifiers.get(handle).cloned()
    }

    /// Obtain the notifier for an existing hold, creating it when the row has
    /// none. `from_rows` rebuilds the registry without notifiers, so every hold
    /// recovered across a restart needs one minted on first wait; without this
    /// a waiter parks on a notifier nobody wakes. Returns `None` for an unknown
    /// handle so a caller cannot mint state for a row that does not exist.
    pub fn notifier_or_create(&mut self, handle: &str) -> Option<Arc<Notify>> {
        if !self.items.contains_key(handle) {
            return None;
        }
        Some(
            self.notifiers
                .entry(handle.to_string())
                .or_insert_with(|| Arc::new(Notify::new()))
                .clone(),
        )
    }

    /// All holds, newest first.
    pub fn list(&self) -> Vec<Approval> {
        let mut v: Vec<_> = self.items.values().cloned().collect();
        v.sort_by(|a, b| {
            b.created_unix
                .cmp(&a.created_unix)
                .then(a.handle.cmp(&b.handle))
        });
        v
    }

    pub fn outstanding(&self) -> usize {
        self.items
            .values()
            .filter(|a| a.status.is_pending())
            .count()
    }

    /// Count of outstanding holds created by a principal, for the per-caller
    /// cap. Absence never matches absence (`scope_eq` semantics), so
    /// unauthenticated callers do not share a quota bucket.
    pub fn outstanding_for(&self, principal: Option<&PrincipalKey>) -> usize {
        let owner = principal.cloned();
        self.items
            .values()
            .filter(|a| a.status.is_pending() && scope_eq(&a.snapshot.principal, &owner))
            .count()
    }

    /// Operator approves: `Pending` -> `Approving`. Returns the immutable
    /// snapshot for the daemon to execute. No fields are accepted from the
    /// approver; exec replays the snapshot verbatim.
    pub fn begin_approve(&mut self, handle: &str, now: u64) -> Result<ApprovalSnapshot, GateError> {
        let a = self
            .items
            .get_mut(handle)
            .ok_or_else(|| GateError::NotFound(handle.to_string()))?;
        if a.status != ApprovalStatus::Pending {
            return Err(GateError::WrongState {
                handle: handle.to_string(),
                detail: format!("already {}", a.status.as_str()),
            });
        }
        if now >= a.deadline_unix() {
            a.status = ApprovalStatus::Expired;
            a.decided_unix = Some(now);
            a.decided_reason = Some("expired without operator approval".to_string());
            self.wake(handle);
            return Err(GateError::WrongState {
                handle: handle.to_string(),
                detail: "expired without operator approval".to_string(),
            });
        }
        a.status = ApprovalStatus::Approving;
        Ok(a.snapshot.clone())
    }

    /// Record a completed approved exec and wake any waiter.
    pub fn set_result(
        &mut self,
        handle: &str,
        now: u64,
        exit: Option<i32>,
        stdout: Option<String>,
        stderr: Option<String>,
    ) {
        if let Some(a) = self.items.get_mut(handle) {
            a.status = ApprovalStatus::Approved;
            a.decided_unix = Some(now);
            a.result_exit = exit;
            a.result_stdout = stdout;
            a.result_stderr = stderr;
            a.sanitize_explanatory_text();
        }
        self.wake(handle);
    }

    /// Record an approved-but-failed-to-run exec and wake any waiter.
    pub fn set_exec_failed(&mut self, handle: &str, now: u64, detail: String) {
        if let Some(a) = self.items.get_mut(handle) {
            a.status = ApprovalStatus::ExecFailed;
            a.decided_unix = Some(now);
            a.decided_reason = Some(detail);
            a.sanitize_explanatory_text();
        }
        self.wake(handle);
    }

    /// Build a note transition without changing registry state or waking a
    /// waiter. The server persists the returned row with an exact CAS, then
    /// installs it through [`Self::install_persisted`].
    pub fn prepare_note(
        &self,
        handle: &str,
        author: &str,
        text: &str,
        now: u64,
    ) -> Result<Approval, GateError> {
        let mut approval = self
            .items
            .get(handle)
            .cloned()
            .ok_or_else(|| GateError::NotFound(handle.to_string()))?;
        if approval.status != ApprovalStatus::Pending {
            return Err(GateError::WrongState {
                handle: handle.to_string(),
                detail: format!("already {}; its thread is closed", approval.status.as_str()),
            });
        }
        approval.notes.push(ApprovalNote {
            at_unix: now,
            author: author.to_string(),
            text: text.to_string(),
        });
        approval.sanitize_explanatory_text();
        Ok(approval)
    }

    /// Build a denial without changing registry state or waking its waiter.
    pub fn prepare_denial(
        &self,
        handle: &str,
        now: u64,
        reason: String,
    ) -> Result<Approval, GateError> {
        let mut approval = self
            .items
            .get(handle)
            .cloned()
            .ok_or_else(|| GateError::NotFound(handle.to_string()))?;
        if approval.status != ApprovalStatus::Pending {
            return Err(GateError::WrongState {
                handle: handle.to_string(),
                detail: format!("already {}", approval.status.as_str()),
            });
        }
        approval.status = ApprovalStatus::Denied;
        approval.decided_unix = Some(now);
        approval.decided_reason = Some(reason);
        approval.sanitize_explanatory_text();
        Ok(approval)
    }

    /// Install a row after its durable transition commits. Existing notifier
    /// identity is preserved; terminal transitions wake the waiter only after
    /// SQLite is authoritative.
    pub fn install_persisted(&mut self, mut approval: Approval, wake: bool) {
        approval.sanitize_explanatory_text();
        let handle = approval.handle.clone();
        self.items.insert(handle.clone(), approval);
        if wake {
            self.wake(&handle);
        }
    }

    /// Append a note to a pending hold's discussion thread. Allowed only while
    /// the hold is undecided; a decided hold's thread is frozen. The caller
    /// (server) authorizes who may post (operator or the hold's requester).
    pub fn add_note(
        &mut self,
        handle: &str,
        author: &str,
        text: &str,
        now: u64,
    ) -> Result<(), GateError> {
        let approval = self.prepare_note(handle, author, text, now)?;
        self.install_persisted(approval, false);
        Ok(())
    }

    /// Operator denies a pending hold and wakes any waiter.
    pub fn deny(&mut self, handle: &str, now: u64, reason: String) -> Result<(), GateError> {
        let approval = self.prepare_denial(handle, now, reason)?;
        self.install_persisted(approval, true);
        Ok(())
    }

    /// Fail-closed expiry: every `Pending` hold past its TTL becomes `Expired`
    /// and its waiter is woken. Returns the expired handles for audit. Driven by
    /// the daemon's sweeper each tick, so an unattended queue denies on a timer.
    pub fn expire_due(&mut self, now: u64) -> Vec<String> {
        let expired: Vec<String> = self
            .items
            .values()
            .filter(|a| a.status == ApprovalStatus::Pending && now >= a.deadline_unix())
            .map(|a| a.handle.clone())
            .collect();
        for h in &expired {
            if let Some(a) = self.items.get_mut(h) {
                a.status = ApprovalStatus::Expired;
                a.decided_unix = Some(now);
                a.decided_reason = Some("expired without operator approval".to_string());
            }
            self.wake(h);
        }
        let mut sorted = expired;
        sorted.sort();
        sorted
    }

    /// Drop decided rows older than `retention_secs` so the table stays bounded.
    pub fn prune_decided(&mut self, now: u64, retention_secs: u64) -> Vec<String> {
        let drop: Vec<String> = self
            .items
            .values()
            .filter(|a| {
                a.status.is_decided()
                    && now.saturating_sub(a.decided_unix.unwrap_or(a.created_unix)) > retention_secs
                    && self.active_waiters(&a.handle) == 0
            })
            .map(|a| a.handle.clone())
            .collect();
        for h in &drop {
            self.items.remove(h);
            self.notifiers.remove(h);
        }
        drop
    }

    fn wake(&self, handle: &str) {
        if let Some(n) = self.notifiers.get(handle) {
            n.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(binary: &str) -> ApprovalSnapshot {
        ApprovalSnapshot {
            binary: binary.to_string(),
            args: vec!["-rf".into(), "/data".into()],
            cwd: None,
            env: BTreeMap::new(),
            secret_keys: BTreeMap::new(),
            session_fingerprint: None,
            session_revision: None,
            secret_entitlements: None,
            secret_file_keys: BTreeMap::new(),
            verb_name: None,
            verb_params: BTreeMap::new(),
            catalog_version: None,
            verb_digest: None,
            verb_composition_digest: None,
            verb_environment_authority: false,
            verb_local_file_authority: false,
            exec_timeout_secs: None,
            access_verbs: Vec::new(),
            access_requests: Vec::new(),
            principal: Some(PrincipalKey::from_uid(1001)),
            secret_binding: None,
            process_authority: None,
        }
    }

    fn held(handle: &str, created: u64, ttl: u64) -> Approval {
        Approval {
            handle: handle.to_string(),
            snapshot: snap("rm"),
            reason: "destructive".into(),
            risk: Some(9),
            reversibility: Some(Reversibility::Irreversible),
            decision_trace: None,
            created_unix: created,
            ttl_secs: ttl,
            status: ApprovalStatus::Pending,
            decided_unix: None,
            decided_reason: None,
            result_exit: None,
            result_stdout: None,
            result_stderr: None,
            notes: Vec::new(),
        }
    }

    #[test]
    fn approve_executes_from_snapshot_only() {
        let mut r = ApprovalRegistry::new();
        r.enqueue(held("h1", 100, 3600));
        let snap = r.begin_approve("h1", 1).unwrap();
        assert_eq!(snap.binary, "rm");
        assert_eq!(r.get("h1").unwrap().status, ApprovalStatus::Approving);
        r.set_result("h1", 200, Some(0), Some("done".into()), None);
        let a = r.get("h1").unwrap();
        assert_eq!(a.status, ApprovalStatus::Approved);
        assert_eq!(a.result_exit, Some(0));
    }

    #[test]
    fn cannot_approve_twice() {
        let mut r = ApprovalRegistry::new();
        r.enqueue(held("h1", 100, 3600));
        r.begin_approve("h1", 1).unwrap();
        assert!(matches!(
            r.begin_approve("h1", 1),
            Err(GateError::WrongState { .. })
        ));
    }

    #[test]
    fn deny_is_terminal() {
        let mut r = ApprovalRegistry::new();
        r.enqueue(held("h1", 100, 3600));
        r.deny("h1", 150, "operator rejected".into()).unwrap();
        assert_eq!(r.get("h1").unwrap().status, ApprovalStatus::Denied);
        assert!(r.begin_approve("h1", 1).is_err());
    }

    #[test]
    fn notes_and_denial_accept_exactly_pending() {
        let mut registry = ApprovalRegistry::new();
        registry.enqueue(held("claimed", 100, 3600));
        registry.begin_approve("claimed", 150).unwrap();

        assert!(matches!(
            registry.add_note("claimed", "operator", "late note", 151),
            Err(GateError::WrongState { .. })
        ));
        assert!(matches!(
            registry.deny("claimed", 151, "late denial".to_string()),
            Err(GateError::WrongState { .. })
        ));
        assert_eq!(
            registry.get("claimed").unwrap().status,
            ApprovalStatus::Approving
        );
    }

    #[test]
    fn expiry_is_fail_closed_on_timer() {
        let mut r = ApprovalRegistry::new();
        r.enqueue(held("h1", 100, 50)); // deadline 150
        r.enqueue(held("h2", 100, 5000)); // not due
        let expired = r.expire_due(200);
        assert_eq!(expired, vec!["h1".to_string()]);
        assert_eq!(r.get("h1").unwrap().status, ApprovalStatus::Expired);
        assert_eq!(r.get("h2").unwrap().status, ApprovalStatus::Pending);
    }

    #[test]
    fn approval_checks_deadline_even_before_the_sweeper_runs() {
        let mut registry = ApprovalRegistry::new();
        registry.enqueue(held("expired", 100, 50));
        assert!(matches!(
            registry.begin_approve("expired", 150),
            Err(GateError::WrongState { .. })
        ));
        let expired = registry.get("expired").unwrap();
        assert_eq!(expired.status, ApprovalStatus::Expired);
        assert_eq!(expired.decided_unix, Some(150));
    }

    #[test]
    fn startup_recovery_marks_interrupted_exec_failed() {
        let mut a = held("h1", 100, 3600);
        a.status = ApprovalStatus::Approving;
        let (reg, recovered) = ApprovalRegistry::from_rows(vec![a], 500);
        assert_eq!(recovered, vec!["h1".to_string()]);
        assert_eq!(reg.get("h1").unwrap().status, ApprovalStatus::ExecFailed);
    }

    #[test]
    fn restarted_hold_registers_and_releases_a_new_waiter() {
        let (mut registry, recovered) =
            ApprovalRegistry::from_rows(vec![held("h1", 100, 3600)], 500);
        assert!(recovered.is_empty());
        assert!(registry.notifier("h1").is_none());

        let (notifier, lease) = registry.register_waiter("h1").expect("known hold");
        assert!(Arc::ptr_eq(
            &notifier,
            &registry.notifier("h1").expect("notifier re-registered")
        ));
        assert_eq!(registry.active_waiters("h1"), 1);
        drop(lease);
        assert_eq!(registry.active_waiters("h1"), 0);
    }

    #[test]
    fn transcript_bound_counts_json_escapes_and_utf8_after_redaction() {
        let pattern = "\"\\\n\u{0001}é界";
        let input = pattern.repeat(APPROVAL_TRANSCRIPT_SERIALIZED_BYTES / pattern.len() + 1);
        let (bounded, truncated) = bound_approval_transcript(Some(input));
        let bounded = bounded.expect("transcript remains present");

        assert!(truncated);
        assert_eq!(
            bounded
                .matches(APPROVAL_TRANSCRIPT_TRUNCATED_SUFFIX)
                .count(),
            1
        );
        assert!(bounded.ends_with(APPROVAL_TRANSCRIPT_TRUNCATED_SUFFIX));
        assert!(
            serde_json::to_vec(&bounded).unwrap().len() <= APPROVAL_TRANSCRIPT_SERIALIZED_BYTES
        );
        assert!(std::str::from_utf8(bounded.as_bytes()).is_ok());
    }

    #[test]
    fn transcript_bound_is_stable_when_loaded_again() {
        let input = "\\\"\n".repeat(APPROVAL_TRANSCRIPT_SERIALIZED_BYTES);
        let (first, first_truncated) = bound_approval_transcript(Some(input));
        let (second, second_truncated) = bound_approval_transcript(first.clone());

        assert!(first_truncated);
        assert!(second_truncated);
        assert_eq!(second, first);
    }

    #[test]
    fn caps_count_pending_and_approving() {
        let mut r = ApprovalRegistry::new();
        r.enqueue(held("a", 100, 3600));
        r.enqueue(held("b", 100, 3600));
        assert_eq!(r.outstanding(), 2);
        assert_eq!(r.outstanding_for(Some(&PrincipalKey::from_uid(1001))), 2);
        r.deny("a", 150, "no".into()).unwrap();
        assert_eq!(r.outstanding(), 1);
    }

    #[test]
    fn none_owner_never_shares_quota_with_none_caller() {
        // A hold owned by an unauthenticated caller (`None`) must not count
        // toward another `None`-scope caller's per-caller cap.
        let mut r = ApprovalRegistry::new();
        let mut anon = held("anon", 100, 3600);
        anon.snapshot.principal = None;
        r.enqueue(anon);
        assert_eq!(r.outstanding(), 1);
        assert_eq!(r.outstanding_for(None), 0);
    }

    #[test]
    fn fingerprint_changes_when_inputs_change() {
        let mut s1 = snap("rm");
        let s2 = snap("rm");
        assert_eq!(s1.fingerprint(), s2.fingerprint());
        s1.env.insert("DANGER".into(), "1".into());
        assert_ne!(s1.fingerprint(), s2.fingerprint());
    }

    #[tokio::test]
    async fn waiter_is_woken_on_decision() {
        let mut r = ApprovalRegistry::new();
        let notify = r.enqueue(held("h1", 100, 3600));
        let (registered_tx, registered_rx) = tokio::sync::oneshot::channel();
        let waiter = tokio::spawn(async move {
            let mut notified = Box::pin(notify.notified());
            notified.as_mut().enable();
            let _ = registered_tx.send(());
            notified.await;
        });
        registered_rx.await.unwrap();
        r.deny("h1", 150, "no".into()).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), waiter)
            .await
            .expect("waiter should have been woken");
    }
}
