// Re-exported so sibling server modules keep a single import path for the
// gating clock.
pub(super) use guard::env::now_unix;

use guard::gating::approval::{Approval, ApprovalSnapshot, ApprovalStatus};
use guard::gating::provisional::{ApiRevertPlan, Provisional, ProvisionalStatus};
use guard::gating::{decide_gate, Coverage, GateOutcome, Reversibility};
use guard::principal::PrincipalKey;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::io::AsyncWrite;

use super::execute::{
    audit_command_line, audit_session_ref, exec_after_approval, exec_with_read_grant_retry,
};
use super::grants::{delete_read_grant_row, finish_read_grant_revert, persist_read_grant};
use super::transport::write_stream_message;
use super::wire::{
    CallerIdentity, ExecOutcome, ExecuteRequest, ExecuteResult, ExecuteStreamMessage, RevertSpec,
    VerbContext,
};
use super::{
    ServerConfig, APPROVAL_TTL_SECS, DEFAULT_CONFIRM_WITHIN_SECS, GATING_RETENTION_SECS,
    MAX_CONFIRM_WITHIN_SECS, MAX_PENDING_GLOBAL, MAX_PENDING_PER_CALLER, REVERT_EXEC_TIMEOUT_SECS,
    SWEEPER_GRACE_SECS, SWEEPER_TICK_SECS,
};

// ===========================================================================
// Consequence gating: routing of LLM-approved commands by reversibility.
// ===========================================================================

/// Mint an unguessable handle for a provisional/approval, using the same
/// entropy source as session tokens (128 bits hex).
pub(super) fn new_handle() -> String {
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
pub(super) fn reconstruct_caller(
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
pub(super) fn binary_allowed(allowed: &Option<Vec<String>>, binary: &str) -> bool {
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

pub(super) async fn persist_provisional(config: &ServerConfig, p: &Provisional) {
    if let Some(store) = &config.session_store {
        if let Err(e) = store.save_provisional(p.clone()).await {
            tracing::warn!("failed to persist provisional {}: {}", p.handle, e);
        }
    }
}

/// Drop any API-proxy delete-provenance tied to a now-resolved auto-revert
/// handle. A proxy-armed create records provenance so a later contained delete
/// of that object cancels the moot create-revert; once the revert itself
/// resolves (operator confirm, or auto/manual revert), that provenance must not
/// outlive its window, or a delete of a same-named resource an operator later
/// recreates outside guard would still match the stale entry and bypass policy.
/// A no-op when the proxy is not enabled or the handle was not a proxy create.
pub(super) async fn forget_proxy_provenance(config: &ServerConfig, handle: &str) {
    let proxies: Vec<_> = config
        .protocol_registry
        .read()
        .await
        .values()
        .cloned()
        .collect();
    for proxy in proxies {
        proxy.forget_created_by_handle(handle);
    }
}

/// Sentinel binary naming an API-proxy-originated row in the provisional and
/// approval registries. Such a row is never executed: approving one releases
/// the API request parked in the proxy instead of spawning a process.
pub(super) const API_PROXY_SENTINEL_BINARY: &str = "(api-proxy)";

/// The sentinel this proxy used before it was generalized past Kubernetes.
/// Recognized on read so rows persisted by an older binary are still identified
/// as proxy-originated across an upgrade.
pub(super) const LEGACY_KUBE_PROXY_SENTINEL_BINARY: &str = "(kube-proxy)";

/// Whether a persisted row's binary marks it as API-proxy-originated, matching
/// both the current and the pre-generalization sentinel.
pub(super) fn is_api_proxy_sentinel(binary: &str) -> bool {
    binary == API_PROXY_SENTINEL_BINARY || binary == LEGACY_KUBE_PROXY_SENTINEL_BINARY
}

/// Write a file readable and writable only by the daemon account. On Unix the
/// mode is set atomically at create so the secret-bearing body is never briefly
/// world-readable, and `O_NOFOLLOW` refuses to follow a symlink planted at the
/// target path; other platforms fall back to a plain write.
async fn write_owner_only(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::io::AsyncWriteExt;
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .await?;
        file.write_all(bytes).await?;
        file.flush().await
    }
    #[cfg(not(unix))]
    {
        tokio::fs::write(path, bytes).await
    }
}

/// Remove a revert's persisted body file once its provisional reaches a terminal
/// state, so secret-bearing snapshots do not accumulate on disk.
pub(super) fn remove_revert_body(p: &Provisional) {
    if let Some(api) = &p.api_revert {
        if let Some(body_file) = &api.body_file {
            let _ = std::fs::remove_file(body_file);
        }
    }
}

/// Retires an API-proxy hold whose parked request vanished (the brokered
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
            tracing::info!(target: "guard::audit",
                "[AUDIT] HOLD_ORPHANED handle={} (api-proxy client disconnected)",
                handle
            );
        });
    }
}

/// Bridges the API proxy's synthesized reverts into the daemon's consequence
/// machinery. Holds a clone of the server config (which shares the provisional
/// registry and state store), and a directory for stored HTTP revert bodies.
/// The proxy acts as the daemon principal, so the operator manages
/// proxy-armed provisionals with the same
/// `guard confirm` / `guard provisionals` / `guard revert` commands.
pub(super) struct DaemonGateSink {
    pub(super) config: ServerConfig,
    pub(super) protocol: String,
    pub(super) snapshot_dir: PathBuf,
    /// Whether `snapshot_dir` is exclusively the daemon's. When false, a
    /// body-bearing revert is not armed rather than risk writing a
    /// secret-bearing snapshot into a directory another local user controls.
    pub(super) snapshot_dir_safe: bool,
    pub(super) window_secs: u64,
}

/// Whether a revert directory is a real directory owned by the current process
/// with no group/other access, so a secret-bearing body written into it cannot
/// be read or substituted by another local user.
#[cfg(unix)]
pub(super) fn revert_dir_is_owner_only(dir: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    match std::fs::symlink_metadata(dir) {
        Ok(meta) => {
            meta.is_dir()
                && meta.uid() == unsafe { libc::geteuid() }
                && meta.permissions().mode() & 0o077 == 0
        }
        Err(_) => false,
    }
}

#[async_trait::async_trait]
impl guard::proxy::GateSink for DaemonGateSink {
    async fn can_arm_revert(&self) -> bool {
        // A body-bearing revert cannot be persisted into a directory that is not
        // exclusively the daemon's, and no revert can be armed when the
        // provisional queue is full. The evaluate path consults this before
        // forwarding a write it would only forward because a revert was
        // promised, so it holds rather than forward an uncontainable write.
        let principal = Some(self.config.daemon_principal.clone());
        self.snapshot_dir_safe
            && gate_capacity_reason(&self.config, principal.as_ref())
                .await
                .is_none()
    }

    async fn arm_revert(&self, mutation: guard::proxy::ApiMutation) -> Option<String> {
        let principal = Some(self.config.daemon_principal.clone());
        if let Some(reason) = gate_capacity_reason(&self.config, principal.as_ref()).await {
            tracing::warn!("api-proxy auto-revert not armed: {}", reason);
            return None;
        }
        let handle = new_handle();
        let now = now_unix();
        let body_file = if let Some(body) = &mutation.revert.body {
            if !self.snapshot_dir_safe {
                tracing::error!(
                    "api-proxy: refusing to arm a body-bearing revert because the revert directory is not owner-only; the change is live but will not auto-revert"
                );
                return None;
            }
            let file = self.snapshot_dir.join(format!("api-revert-{handle}.body"));
            // The snapshot can carry secret material (e.g. a Secret captured
            // before a delete-restore), so the file is owner-only.
            if let Err(e) = write_owner_only(&file, body).await {
                tracing::error!(
                    "api-proxy: failed to write revert body {}: {}",
                    file.display(),
                    e
                );
                return None;
            }
            Some(file)
        } else {
            None
        };
        let api_revert = ApiRevertPlan {
            protocol: self.protocol.clone(),
            method: mutation.revert.method,
            path: mutation.revert.path,
            body_file,
        };

        let provisional = Provisional {
            handle: handle.clone(),
            principal,
            binary: API_PROXY_SENTINEL_BINARY.to_string(),
            args: vec![mutation.label.clone()],
            cwd: None,
            // An API revert is executed from `api_revert`, not the command-shaped
            // revert_binary/revert_args of a shell provisional.
            revert_binary: String::new(),
            revert_args: Vec::new(),
            reason: mutation.label,
            created_unix: now,
            deadline_unix: now.saturating_add(self.window_secs),
            forward_done: true,
            status: ProvisionalStatus::Armed,
            revert_exit: None,
            revert_detail: None,
            api_revert: Some(api_revert),
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
            binary: API_PROXY_SENTINEL_BINARY.to_string(),
            args: vec![label.to_string()],
            cwd: None,
            env: std::collections::BTreeMap::new(),
            secret_keys: std::collections::BTreeMap::new(),
            session_ref: None,
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
        tracing::info!(target: "guard::audit",
            "[AUDIT] HELD handle={} caller=(api-proxy) session=none api=\"{}\" ttl={}s",
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
            // Register with the notifier before checking status (see
            // `wait_for_decision`): a decision landing between the check and
            // the park must complete the park immediately, not wait out the
            // poll interval.
            let notified = notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

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
                &mut notified,
            )
            .await;
        }
    }

    async fn resolve(&self, handle: &str) {
        // The created object is already gone by the workload's own action, so the
        // pending create-revert is moot. Confirm it to cancel
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
                    "api-proxy: resolved auto-revert {} (created object deleted by workload)",
                    handle
                );
            }
            Err(e) => tracing::debug!("api-proxy: resolve {} was a no-op: {}", handle, e),
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

pub(super) async fn persist_approval(config: &ServerConfig, a: &Approval) {
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
pub(super) struct GateInputs {
    pub(super) reason: String,
    pub(super) risk: Option<i32>,
    pub(super) reversibility: Option<Reversibility>,
    /// True when the revert is operator-authored (a verb's `revert`), so it is
    /// not re-evaluated at arm time. A free-form `--revert` is always evaluated.
    pub(super) revert_preauthorized: bool,
    /// Verb context when this command came from the catalog (pins the approval
    /// snapshot to the verb name + params + catalog version).
    pub(super) verb: Option<VerbContext>,
    /// When true the command bypasses the gate and executes immediately. Set for
    /// operator-authored deterministic allows (static policy), already vetted and
    /// carrying no reversibility class.
    pub(super) bypass: bool,
}

/// Route an approved command through the consequence gate.
pub(super) async fn route_gated_allow<W: AsyncWrite + Unpin>(
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
        return exec_with_read_grant_retry(
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
            exec_with_read_grant_retry(
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
pub(super) async fn arm_containment<W: AsyncWrite + Unpin>(
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
        cwd: request.cwd.clone(),
        revert_binary: revert.binary.clone(),
        revert_args: revert.args.clone(),
        api_revert: None,
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

    let session_ref = audit_session_ref(request.session_token.as_deref());
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
    let secret_refs = result.secret_refs().to_vec();

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
            tracing::info!(target: "guard::audit",
                "[AUDIT] PROVISIONAL handle={} caller={} session={} deadline={} window={}s revert=\"{}\"",
                handle,
                caller,
                session_ref,
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
            .with_secret_refs(secret_refs)
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
            tracing::warn!(target: "guard::audit",
                "[AUDIT] PROVISIONAL_INTERRUPTED handle={} caller={} session={} deadline={} (forward launched then failed; auto-revert armed)",
                handle,
                caller,
                session_ref,
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
pub(super) async fn hold_for_approval<W: AsyncWrite + Unpin>(
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
        cwd: request.cwd.clone(),
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
        session_ref: request
            .session_token
            .as_deref()
            .map(|token| audit_session_ref(Some(token))),
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
    tracing::info!(target: "guard::audit",
        "[AUDIT] HELD handle={} caller={} session={} risk={:?} class={:?} cmd=\"{}\" ttl={}s",
        handle,
        caller,
        audit_session_ref(request.session_token.as_deref()),
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
        // Register with the notifier BEFORE checking status: notify_waiters()
        // wakes only already-registered waiters, so a decision landing between
        // the check and the park would otherwise be missed. The streaming path
        // masks that with its 1s keepalive re-check, but a non-streaming
        // waiter would stay parked for the full timeout.
        let notified = notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

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
            _ = &mut notified => { /* re-check status at loop top */ }
            _ = tokio::time::sleep(remaining) => { /* timeout: re-check, then held */ }
            _ = keepalive.tick(), if stream_output => {
                let _ = write_stream_message(stream_writer, &ExecuteStreamMessage::Keepalive).await;
            }
        }
    }
}

/// Build the client-facing result from a decided approval record.
pub(super) fn approval_to_result(a: &Approval) -> ExecuteResult {
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
pub(super) fn hash_secret_value(salt_hex: &str, value: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(salt_hex.as_bytes());
    hasher.update([0u8]);
    hasher.update(value.as_bytes());
    hex_encode(&hasher.finalize())
}

/// Execute an approved snapshot verbatim under the original caller's identity,
/// with no client stream. Used by `guard approve`.
pub(super) async fn execute_snapshot(
    config: &ServerConfig,
    snapshot: &ApprovalSnapshot,
    reason: &str,
) -> ExecuteResult {
    if !binary_allowed(&config.allowed_binaries, &snapshot.binary) {
        return ExecuteResult::exec_failed(
            reason.to_string(),
            format!(
                "approval rejected: binary '{}' is not in the server allow-list",
                snapshot.binary
            ),
        );
    }

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
        cwd: snapshot.cwd.clone(),
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
pub(super) async fn gating_sweeper(config: ServerConfig) {
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
                tracing::warn!(target: "guard::audit",
                    "[AUDIT] APPROVAL_EXPIRED handle={} session={} (fail-closed deny)",
                    h,
                    a.snapshot.session_ref.as_deref().unwrap_or("none")
                );
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
        cwd: p.cwd.clone(),
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

async fn run_api_revert(
    config: &ServerConfig,
    p: &Provisional,
    api: &ApiRevertPlan,
) -> Result<(), RevertError> {
    let Some(proxy) = config
        .protocol_registry
        .read()
        .await
        .get(&api.protocol)
        .cloned()
    else {
        // The mutation is still live; the proxy that would carry the revert is
        // just not running now (a restart without the flag, a protocol change).
        // Surface it for an operator decision rather than burning the revert.
        return Err(RevertError::Retryable(format!(
            "no running api-proxy for protocol '{}'; the change is still live and needs an operator decision",
            api.protocol
        )));
    };
    let body = if let Some(path) = &api.body_file {
        Some(tokio::fs::read(path).await.map_err(|e| {
            RevertError::Failed(format!("read api revert body {}: {e}", path.display()))
        })?)
    } else {
        None
    };
    let method: reqwest::Method = api.method.parse().map_err(|e| {
        RevertError::Failed(format!("invalid api revert method '{}': {e}", api.method))
    })?;
    let upstream = proxy.upstream();
    let url = format!("{}{}", upstream.base(), api.path);
    let mut rb = upstream
        .client()
        .request(method, &url)
        .header(reqwest::header::ACCEPT, "application/json");
    if let Some(token) = upstream.bearer() {
        rb = rb.bearer_auth(token);
    } else if let Some((user, pass)) = upstream.basic_auth() {
        rb = rb.basic_auth(user, Some(pass));
    }
    if let Some(body) = body {
        rb = rb
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body);
    }
    let resp = rb.send().await.map_err(|e| {
        RevertError::Failed(format!("send api revert for provisional {}: {e}", p.handle))
    })?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(RevertError::Failed(format!(
            "api revert returned HTTP {status}: {text}"
        )));
    }
    Ok(())
}

/// Why an API revert did not complete. A retryable failure leaves the live
/// mutation for an operator decision; a hard failure is terminal.
enum RevertError {
    Retryable(String),
    Failed(String),
}

/// Run a claimed (`Reverting`) provisional's revert and record the outcome.
/// Returns `(message, exit_code)`.
pub(super) async fn finish_revert(
    config: &ServerConfig,
    p: &Provisional,
    caller: &CallerIdentity,
    kind: &str,
) -> (String, Option<i32>) {
    // Bound the revert so a hung rollback cannot pin the sweeper (which also
    // drives fail-closed hold expiry). A timeout is recorded as RevertFailed.
    let (status_ok, exit, detail) = if let Some(api) = &p.api_revert {
        match tokio::time::timeout(
            std::time::Duration::from_secs(REVERT_EXEC_TIMEOUT_SECS),
            run_api_revert(config, p, api),
        )
        .await
        {
            Ok(Ok(())) => (true, Some(0), None),
            // Recoverable (no proxy for the protocol right now): route to the
            // operator instead of terminal-failing, so a restart or flag change
            // does not silently strand a live mutation.
            Ok(Err(RevertError::Retryable(detail))) => {
                let updated = {
                    let mut reg = config.provisional.write().await;
                    reg.set_needs_operator_decision(&p.handle, detail.clone());
                    reg.get(&p.handle).cloned()
                };
                if let Some(u) = &updated {
                    persist_provisional(config, u).await;
                }
                tracing::error!(target: "guard::audit",
                    "[AUDIT] REVERT_DEFERRED handle={} caller={} kind={} reason={}",
                    p.handle,
                    caller,
                    kind,
                    detail
                );
                return (
                    format!("provisional {} revert deferred: {}", p.handle, detail),
                    None,
                );
            }
            Ok(Err(RevertError::Failed(reason))) => (false, None, Some(reason)),
            Err(_) => (
                false,
                None,
                Some(format!(
                    "api revert timed out after {}s",
                    REVERT_EXEC_TIMEOUT_SECS
                )),
            ),
        }
    } else {
        match tokio::time::timeout(
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
        }
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
    // The revert is terminal (whether it succeeded or failed); drop any
    // api-proxy provenance tied to it so it cannot outlive its window, and
    // remove the persisted revert body so secret-bearing snapshots do not
    // accumulate on disk.
    forget_proxy_provenance(config, &p.handle).await;
    remove_revert_body(p);
    if status_ok {
        tracing::info!(target: "guard::audit",
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
        tracing::error!(target: "guard::audit",
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
