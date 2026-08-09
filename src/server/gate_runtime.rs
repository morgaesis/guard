// Re-exported so sibling server modules keep a single import path for the
// gating clock.
pub(super) use guard::env::now_unix;

use guard::audit::{AuditEvent, AuditKind};

use guard::gating::approval::{
    bound_approval_transcript, Approval, ApprovalSnapshot, ApprovalStatus,
};
use guard::gating::provisional::{ApiRevertPlan, Provisional, ProvisionalStatus};
use guard::gating::{decide_gate, Coverage, GateOutcome, Reversibility};
use guard::principal::{scope_eq, PrincipalKey};
use guard::redact::{
    command_contains_sensitive_literals, redact_command_line, SENSITIVE_ARGV_REPLAY_GUIDANCE,
};
use std::path::PathBuf;
use tokio::io::AsyncWrite;

use super::execute::{
    admit_access_use, audit_command_line, audit_session_fingerprint,
    exec_after_approval_with_command_authority, exec_after_approval_with_secret_authority,
    exec_with_read_grant_retry_with_command_authority, CommandAuthorization,
    VerbAuthorityExpectation,
};
use super::grants::{delete_read_grant_row, finish_read_grant_revert, persist_read_grant};
use super::runtime::NotifyEvent;
use super::transport::write_stream_message;
use super::wire::{
    approval_is_armed, CallerIdentity, ContainmentOutcome, ExecOutcome, ExecuteRequest,
    ExecuteResult, ExecuteStreamMessage, RevertSpec, VerbContext,
};
use super::{
    RequestContext, ServerContext, DEFAULT_CONFIRM_WITHIN_SECS, GATING_RETENTION_SECS,
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
/// noise - the same invariants `execute_command_inner` enforces for the primary
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
/// entry by match key - the common case, where the daemon's trusted PATH
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
    server: &ServerContext,
    caller_principal: Option<&PrincipalKey>,
) -> Option<String> {
    let (prov_global, prov_caller) = {
        let reg = server.state.provisional.read().await;
        (reg.outstanding(), reg.outstanding_for(caller_principal))
    };
    let (appr_global, appr_caller) = {
        let reg = server.state.approvals.read().await;
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

async fn try_persist_provisional(server: &ServerContext, p: &Provisional) -> Result<(), String> {
    let Some(store) = &server.state.session_store else {
        return Err("durable provisional state is unavailable".to_string());
    };
    store
        .save_provisional(p.clone())
        .await
        .map_err(|error| format!("failed to persist provisional {}: {error}", p.handle))
}

/// Complete the safe transition from the live post-forward persistence-loss
/// row to durable state before an operator decision is applied. The detailed
/// store error is kept in local diagnostics only.
pub(super) async fn converge_forward_persistence_failure(
    server: &ServerContext,
    provisional: &Provisional,
) -> bool {
    if !provisional.forward_persistence_failed {
        return true;
    }
    let Some(store) = &server.state.session_store else {
        tracing::error!(
            "cannot converge provisional {}: durable state store is unavailable",
            provisional.handle
        );
        return false;
    };
    match store.save_provisional(provisional.clone()).await {
        Ok(()) => true,
        Err(error) => {
            tracing::error!(
                "cannot converge provisional {} after forward persistence failure: {}",
                provisional.handle,
                error
            );
            false
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
pub(super) async fn forget_proxy_provenance(server: &ServerContext, handle: &str) {
    let proxies: Vec<_> = server
        .state
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
/// target path. Windows creates the empty file inside a daemon-only directory,
/// applies and verifies a protected daemon-SID-only DACL, then writes the body.
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
    #[cfg(windows)]
    {
        super::secure_fs::write_new_private(path, bytes).map_err(std::io::Error::other)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, bytes);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "owner-only files are unsupported on this platform",
        ))
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
    server: ServerContext,
    handle: String,
    armed: bool,
}

impl Drop for ProxyHoldOrphanGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let server = self.server.clone();
        let handle = self.handle.clone();
        tokio::spawn(async move {
            let now = now_unix();
            {
                let mut reg = server.state.approvals.write().await;
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
            let session_fingerprint =
                if let Some(a) = server.state.approvals.read().await.get(&handle).cloned() {
                    let session_fingerprint = a.snapshot.session_fingerprint.clone();
                    let _ = persist_approval(&server, &a).await;
                    session_fingerprint
                } else {
                    None
                };
            let requester_principal =
                server
                    .state
                    .approvals
                    .read()
                    .await
                    .get(&handle)
                    .and_then(|approval| {
                        approval
                            .snapshot
                            .principal
                            .as_ref()
                            .map(ToString::to_string)
                    });
            server.emit_audit_ungated(
                AuditEvent::new(AuditKind::HoldOrphaned)
                    .handle(&handle)
                    .reason("api-proxy client disconnected"),
            );
            server.emit_event(NotifyEvent {
                event: "decision_made",
                at_unix: now,
                handle: Some(handle),
                session_fingerprint,
                requester_principal,
                reason: Some("requester disconnected before a held API decision".to_string()),
                status: Some("orphaned".to_string()),
                behavior: None,
            });
        });
    }
}

/// Bridges the API proxy's synthesized reverts into the daemon's consequence
/// machinery. Holds a clone of the server server (which shares the provisional
/// registry and state store), and a directory for stored HTTP revert bodies.
/// The proxy acts as the daemon principal, so the operator manages
/// proxy-armed provisionals with the same
/// `guard confirm` / `guard provisionals` / `guard revert` commands.
pub(super) struct DaemonGateSink {
    pub(super) server: ServerContext,
    pub(super) endpoint: String,
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
        let principal = Some(self.server.config.daemon_principal.clone());
        self.snapshot_dir_safe
            && self.server.state.session_store.is_some()
            && gate_capacity_reason(&self.server, principal.as_ref())
                .await
                .is_none()
    }

    async fn arm_revert(&self, mutation: guard::proxy::ApiMutation) -> Option<String> {
        let principal = Some(self.server.config.daemon_principal.clone());
        if let Some(reason) = gate_capacity_reason(&self.server, principal.as_ref()).await {
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
            endpoint: self.endpoint.clone(),
            protocol: self.protocol.clone(),
            upstream_target: mutation.upstream_target,
            upstream_identity: mutation.upstream_identity,
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
            secret_keys: std::collections::BTreeMap::new(),
            secret_file_keys: std::collections::BTreeMap::new(),
            // An API revert is executed from `api_revert`, not the command-shaped
            // revert_binary/revert_args of a shell provisional.
            revert_binary: String::new(),
            revert_args: Vec::new(),
            confirm_check_binary: None,
            confirm_check_args: Vec::new(),
            control_path: Some(format!("daemon API proxy for protocol {}", self.protocol)),
            session_fingerprint: mutation.session_fingerprint.clone(),
            session_revision: mutation.session_revision,
            secret_entitlements: mutation.secret_entitlements,
            reason: mutation.label,
            decision_trace: Some(guard::gating::DecisionTrace::source("api_proxy")),
            created_unix: now,
            deadline_unix: now.saturating_add(self.window_secs),
            window_secs: self.window_secs,
            auto_reverted_unix: None,
            forward_done: true,
            forward_exit: Some(0),
            forward_persistence_failed: false,
            status: ProvisionalStatus::Armed,
            revert_exit: None,
            revert_detail: None,
            api_revert: Some(api_revert),
        };
        if let Err(error) = try_persist_provisional(&self.server, &provisional).await {
            tracing::error!("api-proxy auto-revert was not armed: {error}");
            remove_revert_body(&provisional);
            return None;
        }
        self.server
            .state
            .provisional
            .write()
            .await
            .insert(provisional.clone());
        self.server.emit_event(NotifyEvent {
            event: "provisional_armed",
            at_unix: now,
            handle: Some(handle.clone()),
            session_fingerprint: mutation.session_fingerprint,
            requester_principal: None,
            reason: Some(provisional.reason.clone()),
            status: Some("armed".to_string()),
            behavior: None,
        });
        Some(handle)
    }

    async fn hold_request(
        &self,
        api_snapshot: &guard::proxy::ApiHoldSnapshot,
        reason: &str,
        session_context: Option<&guard::proxy::ApiSessionContext>,
    ) -> guard::proxy::HoldDecision {
        use guard::proxy::HoldDecision;
        let principal = Some(self.server.config.daemon_principal.clone());
        if let Some(why) = gate_capacity_reason(&self.server, principal.as_ref()).await {
            return HoldDecision::Denied { reason: why };
        }
        let handle = new_handle();
        let now = now_unix();
        // The snapshot is descriptive, not executable: the sentinel binary plus
        // the operation label. Approval releases the parked request; nothing is
        // ever spawned from this row (see the sentinel branch in
        // `handle_approve`).
        let selector_facts = api_snapshot
            .authority_selectors
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(",");
        let snapshot = ApprovalSnapshot {
            binary: API_PROXY_SENTINEL_BINARY.to_string(),
            args: vec![
                api_snapshot.label.clone(),
                format!("body_sha256={}", api_snapshot.body_sha256),
                format!("body_shape={}", api_snapshot.redacted_body_shape),
                format!(
                    "query={}",
                    if api_snapshot.redacted_query.is_empty() {
                        "(none)"
                    } else {
                        &api_snapshot.redacted_query
                    }
                ),
                format!(
                    "authority_selectors={}",
                    if selector_facts.is_empty() {
                        "(none)"
                    } else {
                        &selector_facts
                    }
                ),
            ],
            cwd: None,
            env: std::collections::BTreeMap::new(),
            secret_keys: std::collections::BTreeMap::new(),
            session_fingerprint: session_context.map(|context| context.fingerprint.clone()),
            session_revision: session_context.map(|context| context.revision.clone()),
            secret_entitlements: session_context
                .and_then(|context| context.secret_entitlements.clone()),
            secret_file_keys: std::collections::BTreeMap::new(),
            verb_name: None,
            verb_params: std::collections::BTreeMap::new(),
            catalog_version: None,
            verb_digest: None,
            verb_composition_digest: None,
            access_verbs: Vec::new(),
            access_requests: Vec::new(),
            principal,
            secret_binding: None,
        };
        let approval = Approval {
            handle: handle.clone(),
            snapshot,
            reason: reason.to_string(),
            risk: None,
            reversibility: None,
            decision_trace: Some(guard::gating::DecisionTrace::source("api_proxy")),
            created_unix: now,
            ttl_secs: self.server.config.approval_ttl_secs,
            status: ApprovalStatus::Pending,
            decided_unix: None,
            decided_reason: None,
            result_exit: None,
            result_stdout: None,
            result_stderr: None,
            notes: Vec::new(),
        };
        if let Err(reason) = persist_approval(&self.server, &approval).await {
            return HoldDecision::Denied { reason };
        }
        let notify = self
            .server
            .state
            .approvals
            .write()
            .await
            .enqueue(approval.clone());
        self.server.emit_audit_ungated(
            AuditEvent::new(AuditKind::Held)
                .handle(&handle)
                .caller("(api-proxy)")
                .session_fingerprint(
                    session_context
                        .map(|context| context.fingerprint.as_str())
                        .unwrap_or("none"),
                )
                .field("api", &api_snapshot.label)
                .field("body_sha256", &api_snapshot.body_sha256)
                .field("ttl", format!("{}s", self.server.config.approval_ttl_secs)),
        );
        self.server.emit_event(NotifyEvent {
            event: "hold_created",
            at_unix: now,
            handle: Some(handle.clone()),
            session_fingerprint: session_context.map(|context| context.fingerprint.clone()),
            requester_principal: approval
                .snapshot
                .principal
                .as_ref()
                .map(ToString::to_string),
            reason: Some(reason.to_string()),
            status: Some("pending".to_string()),
            behavior: None,
        });
        // If the brokered client disconnects while parked, this future is
        // dropped mid-await; the guard then retires the orphaned hold.
        let mut orphan_guard = ProxyHoldOrphanGuard {
            server: self.server.clone(),
            handle: handle.clone(),
            armed: true,
        };
        // The sweeper expires the row at its TTL and wakes this waiter; the
        // slack past the TTL is a backstop against a missed wakeup, not a
        // second policy timer.
        let deadline = (self.server.config.approval_ttl_secs != u64::MAX).then(|| {
            tokio::time::Instant::now()
                .checked_add(std::time::Duration::from_secs(
                    self.server.config.approval_ttl_secs.saturating_add(60),
                ))
                .unwrap_or_else(tokio::time::Instant::now)
        });
        loop {
            // Register with the notifier before checking status (see
            // `wait_for_decision`): a decision landing between the check and
            // the park must complete the park immediately, not wait out the
            // poll interval.
            let notified = notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            match self
                .server
                .state
                .approvals
                .read()
                .await
                .get(&handle)
                .cloned()
            {
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
            let remaining = deadline
                .map(|deadline| deadline.saturating_duration_since(tokio::time::Instant::now()));
            if remaining.is_some_and(|remaining| remaining.is_zero()) {
                // Past TTL plus slack: the sweeper's expiry (or an operator
                // decision) is authoritative, but nothing woke us. Leave the
                // row to the sweeper and fail closed.
                orphan_guard.armed = false;
                return HoldDecision::Denied {
                    reason: "expired without operator approval".to_string(),
                };
            }
            let poll = remaining
                .unwrap_or(std::time::Duration::from_secs(5))
                .min(std::time::Duration::from_secs(5));
            let _ = tokio::time::timeout(poll, &mut notified).await;
        }
    }

    async fn resolve(&self, handle: &str) {
        // The created object is already gone by the workload's own action, so the
        // pending create-revert is moot. Confirm it to cancel
        // the timer; the sweeper then never tries to delete an absent object. A
        // handle that is already terminal is a no-op.
        let mut registry = self.server.state.provisional.write().await;
        let Some(expected) = registry.get(handle).cloned() else {
            return;
        };
        let mut staged = guard::gating::provisional::ProvisionalRegistry::new();
        staged.insert(expected.clone());
        match staged.confirm(handle) {
            Ok(p) => {
                if let Some(store) = &self.server.state.session_store {
                    if let Err(error) = store
                        .compare_and_swap_provisional(expected, p.clone())
                        .await
                    {
                        tracing::warn!(
                            "api-proxy: could not durably resolve auto-revert {}: {}",
                            handle,
                            error
                        );
                        return;
                    }
                }
                registry.insert(p.clone());
                drop(registry);
                tracing::info!(
                    "api-proxy: resolved auto-revert {} (created object deleted by workload)",
                    handle
                );
                self.server.emit_event(NotifyEvent {
                    event: "decision_made",
                    at_unix: now_unix(),
                    handle: Some(handle.to_string()),
                    session_fingerprint: p.session_fingerprint.clone(),
                    requester_principal: None,
                    reason: Some("workload removed its contained created object".to_string()),
                    status: Some("confirmed".to_string()),
                    behavior: None,
                });
            }
            Err(e) => {
                drop(registry);
                tracing::debug!("api-proxy: resolve {} was a no-op: {}", handle, e);
            }
        }
    }
}

async fn try_delete_provisional_row(server: &ServerContext, handle: &str) -> Result<(), String> {
    if let Some(store) = &server.state.session_store {
        store
            .delete_provisional(handle.to_string())
            .await
            .map_err(|error| format!("failed to delete provisional {handle}: {error}"))?;
    }
    Ok(())
}

async fn delete_provisional_row(server: &ServerContext, handle: &str) {
    if let Err(error) = try_delete_provisional_row(server, handle).await {
        tracing::warn!("{error}");
    }
}

/// Retire a staging row for a forward command that never ran. The terminal
/// row is installed in memory first and persisted before deletion, so a failed
/// delete cannot leave an actionable `Armed` record or consume capacity.
async fn retire_non_executed_provisional(
    server: &ServerContext,
    provisional: &Provisional,
    detail: String,
) -> Result<(), String> {
    let mut terminal = provisional.clone();
    terminal.status = ProvisionalStatus::Reverted;
    terminal.revert_detail = Some(detail);
    server
        .state
        .provisional
        .write()
        .await
        .insert(terminal.clone());

    match try_persist_provisional(server, &terminal).await {
        Ok(()) => match try_delete_provisional_row(server, &terminal.handle).await {
            Ok(()) => {
                server
                    .state
                    .provisional
                    .write()
                    .await
                    .remove(&terminal.handle);
                Ok(())
            }
            Err(delete_error) => {
                tracing::warn!(
                    "{delete_error}; retained terminal non-executed provisional {}",
                    terminal.handle
                );
                Ok(())
            }
        },
        Err(save_error) => match try_delete_provisional_row(server, &terminal.handle).await {
            Ok(()) => {
                server
                    .state
                    .provisional
                    .write()
                    .await
                    .remove(&terminal.handle);
                Ok(())
            }
            Err(delete_error) => Err(format!(
                "failed to retire non-executed provisional {}: {save_error}; {delete_error}",
                terminal.handle
            )),
        },
    }
}

pub(super) async fn persist_approval(server: &ServerContext, a: &Approval) -> Result<(), String> {
    if let Some(store) = &server.state.session_store {
        if let Err(error) = store.save_approval(a.clone()).await {
            let message = format!("failed to persist approval {}: {error}", a.handle);
            tracing::warn!("{message}");
            return Err(message);
        }
    }
    Ok(())
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
    server: &ServerContext,
    forward: &ExecuteRequest,
    revert: &RevertSpec,
) -> RevertAssessment {
    let sensitive_check = revert
        .confirm_check
        .as_ref()
        .is_some_and(|check| command_contains_sensitive_literals(&check.binary, &check.args));
    if command_contains_sensitive_literals(&forward.binary, &forward.args)
        || command_contains_sensitive_literals(&revert.binary, &revert.args)
        || sensitive_check
    {
        return RevertAssessment::NeedsReview(SENSITIVE_ARGV_REPLAY_GUIDANCE.to_string());
    }
    if let Some(reason) = invalid_binary_reason(&revert.binary) {
        return RevertAssessment::NeedsReview(reason);
    }
    if !binary_allowed(&server.config.allowed_binaries, &revert.binary) {
        return RevertAssessment::NeedsReview(format!(
            "rollback binary '{}' is outside the server allow-list",
            revert.binary
        ));
    }
    if let Some(check) = &revert.confirm_check {
        if let Some(reason) = invalid_binary_reason(&check.binary) {
            return RevertAssessment::NeedsReview(format!(
                "invalid confirmation-check command: {reason}"
            ));
        }
        if !binary_allowed(&server.config.allowed_binaries, &check.binary) {
            return RevertAssessment::NeedsReview(format!(
                "confirmation-check binary '{}' is outside the server allow-list",
                check.binary
            ));
        }
    }
    let forward_line = redact_command_line(&forward.binary, &forward.args);
    let revert_line = redact_command_line(&revert.binary, &revert.args);
    let check_line = revert
        .confirm_check
        .as_ref()
        .map(|check| redact_command_line(&check.binary, &check.args));
    let window = forward
        .confirm_within_secs
        .unwrap_or(DEFAULT_CONFIRM_WITHIN_SECS)
        .clamp(1, MAX_CONFIRM_WITHIN_SECS);
    let control_path = revert
        .control_path
        .clone()
        .unwrap_or_else(|| infer_control_path(forward, revert));
    let context = format!(
        "CONTAINMENT ENVELOPE ASSESSMENT. A recoverable command may run unattended. \
         At the deadline the daemon runs the independent confirmation check when one \
         is present; exit zero confirms and every other outcome runs the rollback.\n\
         Forward command: {forward_line}\n\
         Proposed rollback: {revert_line}\n\
         Confirmation check: {}\n\
         Confirmation deadline: {window} seconds\n\
         Required control path: {control_path}\n\
         APPROVE only if the rollback is policy-compliant and a sensible inverse, the \
         check independently verifies the intended result, and the forward command \
         cannot plausibly sever the SSH, API, socket, credential, daemon, or local \
         authority needed to run the check and rollback. DENY when any part is \
         off-target, destructive, overly broad, circular, or connectivity-dependent \
         in a way the forward action may break.",
        check_line
            .as_deref()
            .unwrap_or("none; deadline always rolls back")
    );
    let session_prompt = match forward.session_token.as_deref() {
        Some(token) => server.state.sessions.read().await.prompt_append_for(token),
        None => None,
    };
    let evaluation_context = merge_revert_assessment_prompt(session_prompt.as_deref(), &context);
    match server
        .state
        .evaluator
        .evaluate_with_context(&revert_line, Some(&evaluation_context))
        .await
    {
        guard::evaluate::EvalResult::Allow { .. } => RevertAssessment::Sensible,
        guard::evaluate::EvalResult::Deny { reason, .. } => {
            RevertAssessment::NeedsReview(format!("rollback not affirmed by policy: {reason}"))
        }
        guard::evaluate::EvalResult::Error(e) => {
            RevertAssessment::NeedsReview(format!("rollback could not be evaluated: {e}"))
        }
    }
}

pub(super) fn merge_revert_assessment_prompt(
    session_prompt: Option<&str>,
    context: &str,
) -> String {
    match session_prompt
        .map(str::trim)
        .filter(|prompt| !prompt.is_empty())
    {
        Some(prompt) => format!(
            "SESSION AUTHORITY CONTEXT. The rollback must remain within this scoped intent:\n\
             {prompt}\n\n{context}"
        ),
        None => context.to_string(),
    }
}

fn infer_control_path(forward: &ExecuteRequest, revert: &RevertSpec) -> String {
    let mut transports = Vec::new();
    for binary in [
        forward.binary.as_str(),
        revert.binary.as_str(),
        revert
            .confirm_check
            .as_ref()
            .map(|check| check.binary.as_str())
            .unwrap_or(""),
    ] {
        let transport = match binary {
            "ssh" | "scp" | "sftp" | "rsync" => "brokered SSH transport",
            "kubectl" | "helm" => "daemon-held Kubernetes API credentials and connectivity",
            "curl" | "wget" => "daemon network and API credential path",
            _ => "local daemon process execution",
        };
        if !transports.contains(&transport) {
            transports.push(transport);
        }
    }
    if !forward.secrets.is_empty() || !forward.secret_files.is_empty() {
        transports.push("original caller secret namespace");
    }
    transports.join("; ")
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
    /// Session authority captured before evaluation or deterministic routing.
    /// Its revision is rechecked before routing and its immutable entitlements
    /// govern the forward command, confirmation check, and rollback.
    pub(super) authority: Option<SessionAuthoritySnapshot>,
    /// Selected requester-session verbs supplying this execution's authority.
    /// Baseline or unrelated work leaves this empty.
    pub(super) consume_access_verbs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SessionAuthoritySnapshot {
    pub(super) revision: String,
    pub(super) secret_entitlements: Option<Vec<String>>,
}

impl From<(String, Option<Vec<String>>)> for SessionAuthoritySnapshot {
    fn from((revision, secret_entitlements): (String, Option<Vec<String>>)) -> Self {
        Self {
            revision,
            secret_entitlements,
        }
    }
}

async fn session_authority_is_current(
    server: &ServerContext,
    request: &ExecuteRequest,
    expected: Option<&SessionAuthoritySnapshot>,
) -> bool {
    let Some(token) = request.session_token.as_deref() else {
        return expected.is_none();
    };
    let current = server
        .state
        .sessions
        .read()
        .await
        .authority_snapshot(token)
        .map(SessionAuthoritySnapshot::from);
    current.as_ref() == expected
}

async fn access_admission_denial(
    server: &ServerContext,
    caller: &CallerIdentity,
    selected_verbs: &[String],
    reason: String,
) -> ExecuteResult {
    let mut intents = selected_verbs.to_vec();
    intents.sort();
    intents.dedup();
    if intents.is_empty() {
        return ExecuteResult::denied(reason);
    }
    let required = intents.len();
    let mut handles = Vec::new();
    for intent in intents {
        if let Ok(item) =
            super::admin::submit_access_request(server, caller, None, &intent, None, None).await
        {
            if item.kind == "request" {
                handles.push(item.reference);
            }
        }
    }
    handles.sort();
    handles.dedup();
    if handles.len() != required {
        ExecuteResult::denied(reason)
    } else {
        ExecuteResult::denied(reason).with_access_requests(handles)
    }
}

/// Route an approved command through the consequence gate.
pub(super) async fn route_gated_allow<W: AsyncWrite + Unpin>(
    context: &mut RequestContext<'_, W>,
    request: ExecuteRequest,
    mut inputs: GateInputs,
    decision_trace: Option<guard::gating::DecisionTrace>,
) -> ExecuteResult {
    let server = context.server;
    if request.session_token.is_some() {
        let Some(expected) = inputs.authority.as_ref() else {
            return ExecuteResult::denied(
                "session authority was not captured before execution routing",
            );
        };
        if !session_authority_is_current(server, &request, Some(expected)).await {
            return ExecuteResult::denied(
                "session expired, was revoked, or changed while the command was being evaluated",
            );
        }
    }
    let command_authority = Some(CommandAuthorization::routed(inputs.verb.as_ref()));
    let secret_authority = inputs
        .authority
        .as_ref()
        .map(|snapshot| snapshot.secret_entitlements.clone());

    // Gating off, or an operator-authored static-policy allow: execute directly.
    if !server.config.gate.is_on() || inputs.bypass {
        if let Err(reason) =
            admit_access_use(server, &request, &inputs.consume_access_verbs, None).await
        {
            return access_admission_denial(
                server,
                context.caller,
                &inputs.consume_access_verbs,
                reason,
            )
            .await;
        }
        return exec_with_read_grant_retry_with_command_authority(
            context,
            request,
            inputs.reason,
            secret_authority,
            command_authority,
        )
        .await;
    }

    // The row owner is the caller's cross-platform principal (uid string on
    // Unix, SID on Windows). A non-Unix caller is no longer dropped to None.
    let caller_principal = context.caller.principal();
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
            if let Err(reason) =
                admit_access_use(server, &request, &inputs.consume_access_verbs, None).await
            {
                return access_admission_denial(
                    server,
                    context.caller,
                    &inputs.consume_access_verbs,
                    reason,
                )
                .await;
            }
            exec_with_read_grant_retry_with_command_authority(
                context,
                request,
                inputs.reason,
                secret_authority,
                command_authority,
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
            if let Some(revert) = request.revert.clone() {
                let requires_live_assessment = !inputs.revert_preauthorized
                    || revert.confirm_check.is_some()
                    || revert.control_path.is_some();
                if requires_live_assessment {
                    if let RevertAssessment::NeedsReview(why) =
                        assess_revert(server, &request, &revert).await
                    {
                        inputs.reason = format!(
                            "{} [held for operator review: containment envelope not validated: {}]",
                            inputs.reason, why
                        );
                        return hold_for_approval_with_trace(
                            context,
                            request,
                            caller_principal,
                            inputs,
                            decision_trace,
                        )
                        .await;
                    }
                }
            }
            arm_containment_with_access_use(
                context,
                request,
                caller_principal,
                ContainmentInputs {
                    reason: inputs.reason,
                    authority: inputs.authority,
                    consume_access_verbs: inputs.consume_access_verbs,
                    decision_trace,
                    command_authority,
                },
            )
            .await
        }
        GateOutcome::Hold => {
            hold_for_approval_with_trace(context, request, caller_principal, inputs, decision_trace)
                .await
        }
    }
}

/// Arm a containment envelope: persist the provisional, run the forward command,
/// then mark it armed with an auto-revert deadline.
#[cfg(all(test, unix))]
pub(super) async fn arm_containment_with_authority<W: AsyncWrite + Unpin>(
    context: &mut RequestContext<'_, W>,
    request: ExecuteRequest,
    caller_principal: Option<PrincipalKey>,
    reason: String,
    authority: Option<SessionAuthoritySnapshot>,
) -> ExecuteResult {
    arm_containment_with_access_use(
        context,
        request,
        caller_principal,
        ContainmentInputs {
            reason,
            authority,
            consume_access_verbs: Vec::new(),
            decision_trace: None,
            command_authority: None,
        },
    )
    .await
}

#[cfg(all(test, unix))]
pub(super) async fn arm_containment_with_access_use_for_test<W: AsyncWrite + Unpin>(
    context: &mut RequestContext<'_, W>,
    request: ExecuteRequest,
    caller_principal: Option<PrincipalKey>,
    reason: String,
    authority: Option<SessionAuthoritySnapshot>,
    consume_access_verbs: Vec<String>,
) -> ExecuteResult {
    arm_containment_with_access_use(
        context,
        request,
        caller_principal,
        ContainmentInputs {
            reason,
            authority,
            consume_access_verbs,
            decision_trace: None,
            command_authority: None,
        },
    )
    .await
}

struct ContainmentInputs {
    reason: String,
    authority: Option<SessionAuthoritySnapshot>,
    consume_access_verbs: Vec<String>,
    decision_trace: Option<guard::gating::DecisionTrace>,
    command_authority: Option<CommandAuthorization>,
}

async fn arm_containment_with_access_use<W: AsyncWrite + Unpin>(
    context: &mut RequestContext<'_, W>,
    request: ExecuteRequest,
    caller_principal: Option<PrincipalKey>,
    inputs: ContainmentInputs,
) -> ExecuteResult {
    let ContainmentInputs {
        reason,
        authority,
        consume_access_verbs,
        decision_trace,
        command_authority,
    } = inputs;
    let server = context.server;
    let caller = context.caller;
    // decide_gate only returns Contain when a revert is present.
    let revert = match request.revert.clone() {
        Some(r) => r,
        None => return ExecuteResult::held(reason, new_handle(), Coverage::hold()),
    };

    let sensitive_check = revert
        .confirm_check
        .as_ref()
        .is_some_and(|check| command_contains_sensitive_literals(&check.binary, &check.args));
    if command_contains_sensitive_literals(&request.binary, &request.args)
        || command_contains_sensitive_literals(&revert.binary, &revert.args)
        || sensitive_check
    {
        return ExecuteResult::denied(SENSITIVE_ARGV_REPLAY_GUIDANCE);
    }

    if let Some(why) = invalid_binary_reason(&revert.binary) {
        return ExecuteResult::exec_failed(reason, why);
    }
    if !binary_allowed(&server.config.allowed_binaries, &revert.binary) {
        return ExecuteResult::exec_failed(
            reason,
            format!(
                "rollback binary '{}' is outside the server allow-list",
                revert.binary
            ),
        );
    }
    if let Some(check) = &revert.confirm_check {
        if let Some(why) = invalid_binary_reason(&check.binary) {
            return ExecuteResult::exec_failed(
                reason,
                format!("invalid confirmation-check command: {why}"),
            );
        }
        if !binary_allowed(&server.config.allowed_binaries, &check.binary) {
            return ExecuteResult::exec_failed(
                reason,
                format!(
                    "confirmation-check binary '{}' is outside the server allow-list",
                    check.binary
                ),
            );
        }
    }

    if server.config.dry_run {
        return ExecuteResult::dry_run_gated(
            format!(
                "{} [GATE] would execute inside a containment envelope (auto-revert: {})",
                reason,
                redact_command_line(&revert.binary, &revert.args)
            ),
            Coverage::contain(),
        );
    }
    // A provisional persists across restarts, but plain `--env` values have no
    // stable store reference to re-resolve. Any such value could be a secret
    // regardless of its name or shape, so fail closed before persistence or
    // forward execution and require the reference-based `--secret` path.
    if !request.env.is_empty() {
        return ExecuteResult::exec_failed(
            reason,
            "command was not run: containment cannot persist plain --env values; store them in the daemon secret backend and pass them with --secret"
                .to_string(),
        );
    }

    // The rollback was assessed by the gate router before this point (free-form
    // reverts are policy- and sensibility-checked; a verb revert is the
    // operator-authored slow clock), so the envelope is armed here directly.
    if let Some(why) = gate_capacity_reason(server, caller_principal.as_ref()).await {
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
    if !session_authority_is_current(server, &request, authority.as_ref()).await {
        return ExecuteResult::denied(
            "session expired, was revoked, or changed before containment could be armed",
        );
    }
    let (session_revision, secret_entitlements) = match request.session_token.as_deref() {
        Some(_) => match authority {
            Some(snapshot) => (snapshot.revision, snapshot.secret_entitlements),
            None => {
                return ExecuteResult::denied(
                    "session expired or was revoked before containment could be armed",
                )
            }
        },
        None => (String::new(), None),
    };
    let provisional = Provisional {
        handle: handle.clone(),
        principal: caller_principal,
        binary: request.binary.clone(),
        args: request.args.clone(),
        cwd: request.cwd.clone(),
        secret_keys: request
            .secrets
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        secret_file_keys: request
            .secret_files
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        revert_binary: revert.binary.clone(),
        revert_args: revert.args.clone(),
        confirm_check_binary: revert
            .confirm_check
            .as_ref()
            .map(|check| check.binary.clone()),
        confirm_check_args: revert
            .confirm_check
            .as_ref()
            .map(|check| check.args.clone())
            .unwrap_or_default(),
        control_path: Some(
            revert
                .control_path
                .clone()
                .unwrap_or_else(|| infer_control_path(&request, &revert)),
        ),
        session_fingerprint: request
            .session_token
            .as_deref()
            .map(|token| audit_session_fingerprint(Some(token))),
        session_revision: (!session_revision.is_empty()).then_some(session_revision),
        secret_entitlements,
        api_revert: None,
        reason: reason.clone(),
        decision_trace,
        created_unix: now,
        // No confirmation deadline exists until the forward command exits
        // successfully. Zero is a persisted sentinel for "not started".
        deadline_unix: 0,
        window_secs: 0,
        auto_reverted_unix: None,
        forward_done: false,
        forward_exit: None,
        forward_persistence_failed: false,
        status: ProvisionalStatus::Armed,
        revert_exit: None,
        revert_detail: None,
    };

    // Commit BEFORE exec so a crash between exec and arm still leaves a
    // recoverable revert (startup recovery routes it to needs_operator_decision).
    if let Err(detail) = try_persist_provisional(server, &provisional).await {
        tracing::error!(
            "containment provisional {} was not durable before forward execution: {}",
            handle,
            detail
        );
        return ExecuteResult::exec_failed(
            reason.clone(),
            "command was not run because durable rollback state is unavailable".to_string(),
        )
        .containment_failed(
            "command was not run because durable rollback state is unavailable",
            None,
            Coverage::contain(),
            ContainmentOutcome::PersistenceFailure {
                command_started: false,
                forward_exit_code: None,
            },
            None,
            None,
            None,
        );
    }
    server
        .state
        .provisional
        .write()
        .await
        .insert(provisional.clone());

    // The containment row is durable before bounded access is consumed. If
    // admission rejects the request, remove the unused row and leave the
    // authority budget untouched.
    if let Err(admission_reason) =
        admit_access_use(server, &request, &consume_access_verbs, None).await
    {
        if let Err(cleanup_error) = retire_non_executed_provisional(
            server,
            &provisional,
            "forward command was not admitted; no rollback is required".to_string(),
        )
        .await
        {
            tracing::error!(
                "failed to retire unstarted provisional {handle} after access admission denial: {cleanup_error}"
            );
        }
        return access_admission_denial(server, caller, &consume_access_verbs, admission_reason)
            .await;
    }

    let session_fingerprint = audit_session_fingerprint(request.session_token.as_deref());
    let result = exec_after_approval_with_command_authority(
        context,
        request,
        reason.clone(),
        Some(provisional.secret_entitlements.clone()),
        command_authority,
    )
    .await;
    let exposed_secret_refs = result.exposed_secret_refs().to_vec();

    match result.exec {
        ExecOutcome::Completed {
            exit_code,
            ref stdout,
            ref stderr,
        } => {
            let stdout = stdout.clone();
            let stderr = stderr.clone();
            let finished_unix = now_unix();
            let updated = {
                let mut reg = server.state.provisional.write().await;
                reg.mark_forward_done(&handle, exit_code, finished_unix, window)
            };
            // Zero on a forward command that did not exit cleanly: no timer was
            // armed, so the response must not advertise a deadline.
            let Some(updated) = updated else {
                let response_reason =
                    "command executed, but its durable containment row was lost; operator decision required";
                return result
                    .containment_failed(
                        response_reason,
                        None,
                        Coverage::contain(),
                        ContainmentOutcome::PersistenceFailure {
                            command_started: true,
                            forward_exit_code: exit_code,
                        },
                        exit_code,
                        stdout,
                        stderr,
                    )
                    .with_exposed_secret_refs(exposed_secret_refs);
            };
            if let Err(detail) = try_persist_provisional(server, &updated).await {
                tracing::error!("post-forward provisional persistence failed: {detail}");
                let _ = server
                    .state
                    .provisional
                    .write()
                    .await
                    .mark_forward_persistence_failed(&handle, exit_code);
                let response_reason = match exit_code {
                    Some(0) => "command executed, but its durable auto-revert state could not be recorded; operator decision required".to_string(),
                    Some(exit_code) => format!(
                        "forward command exited with code {exit_code}, but its durable outcome could not be recorded; operator decision required"
                    ),
                    None => "forward command ended without an exit code, but its durable outcome could not be recorded; operator decision required".to_string(),
                };
                server.emit_audit_ungated(
                    AuditEvent::new(AuditKind::ProvisionalInterrupted)
                        .handle(&handle)
                        .caller(caller)
                        .session_fingerprint(&session_fingerprint)
                        .reason(&response_reason)
                        .field("exit", format!("{exit_code:?}")),
                );
                return result
                    .containment_failed(
                        response_reason,
                        Some(handle),
                        Coverage::contain(),
                        ContainmentOutcome::PersistenceFailure {
                            command_started: true,
                            forward_exit_code: exit_code,
                        },
                        exit_code,
                        stdout,
                        stderr,
                    )
                    .with_exposed_secret_refs(exposed_secret_refs);
            }
            if exit_code.is_none() {
                let response_reason = format!(
                    "{reason}; forward command ended without an exit code; auto-revert was not armed; operator decision required"
                );
                server.emit_audit_ungated(
                    AuditEvent::new(AuditKind::ProvisionalInterrupted)
                        .handle(&handle)
                        .caller(caller)
                        .session_fingerprint(&session_fingerprint)
                        .reason(&response_reason),
                );
                return result
                    .containment_failed(
                        response_reason,
                        Some(handle),
                        Coverage::contain(),
                        ContainmentOutcome::ForwardNoExitCode,
                        None,
                        stdout,
                        stderr,
                    )
                    .with_exposed_secret_refs(exposed_secret_refs);
            }
            if exit_code != Some(0) {
                let exit_code = exit_code.expect("nonzero containment exit has a code");
                let response_reason = format!(
                    "{reason}; forward command exited with code {exit_code}; auto-revert was not armed; operator decision required"
                );
                server.emit_audit_ungated(
                    AuditEvent::new(AuditKind::ProvisionalInterrupted)
                        .handle(&handle)
                        .caller(caller)
                        .session_fingerprint(&session_fingerprint)
                        .reason(&response_reason)
                        .field("exit", exit_code),
                );
                return result
                    .containment_failed(
                        response_reason,
                        Some(handle),
                        Coverage::contain(),
                        ContainmentOutcome::ForwardNonzeroExit { exit_code },
                        Some(exit_code),
                        stdout,
                        stderr,
                    )
                    .with_exposed_secret_refs(exposed_secret_refs);
            }
            let armed_deadline = updated.deadline_unix;
            let armed_window = updated.window_secs;
            {
                server.emit_audit_ungated(
                    AuditEvent::new(AuditKind::Provisional)
                        .handle(&handle)
                        .caller(caller)
                        .session_fingerprint(&session_fingerprint)
                        .field("deadline", finished_unix.saturating_add(window))
                        .field("window", format!("{window}s"))
                        .field("revert", audit_command_line(&revert.binary, &revert.args)),
                );
                server.emit_event(NotifyEvent {
                    event: "provisional_armed",
                    at_unix: finished_unix,
                    handle: Some(handle.clone()),
                    session_fingerprint: Some(session_fingerprint),
                    requester_principal: None,
                    reason: Some(reason.clone()),
                    status: Some("armed".to_string()),
                    behavior: None,
                });
            }
            ExecuteResult::provisional(
                reason,
                handle,
                Coverage::contain(),
                exit_code,
                stdout,
                stderr,
                armed_deadline,
                armed_window,
            )
            .with_exposed_secret_refs(exposed_secret_refs)
        }
        // The child was launched and then failed (for example, the client
        // stream dropped). Its partial effects are unknown. Persist that
        // interruption explicitly and require an operator to confirm or revert;
        // a confirmation timer cannot start from an unobserved completion.
        ExecOutcome::Failed {
            started: true,
            reason: ref failure_detail,
        } => {
            let detail = format!(
                "forward command was interrupted after launch: {failure_detail}; operator confirmation or rollback is required"
            );
            let updated = {
                let mut reg = server.state.provisional.write().await;
                reg.mark_forward_interrupted(&handle, detail.clone())
            };
            let (response_reason, recovery_handle, outcome) = match updated {
                Some(updated) => match try_persist_provisional(server, &updated).await {
                    Ok(()) => (
                        "forward command ended without an exit code; auto-revert was not armed; operator decision required",
                        Some(handle.clone()),
                        ContainmentOutcome::ForwardNoExitCode,
                    ),
                    Err(error) => {
                        tracing::warn!("{error}");
                        let actionable = server
                            .state
                            .provisional
                            .write()
                            .await
                            .mark_forward_interrupted_persistence_failed(&handle)
                            .is_some();
                        (
                            "forward command ended without an exit code, and its interrupted state was not recorded durably; operator decision required",
                            actionable.then(|| handle.clone()),
                            ContainmentOutcome::PersistenceFailure {
                                command_started: true,
                                forward_exit_code: None,
                            },
                        )
                    }
                },
                None => (
                    "forward command ended without an exit code, but its containment row is unavailable; operator decision required",
                    None,
                    ContainmentOutcome::PersistenceFailure {
                        command_started: true,
                        forward_exit_code: None,
                    },
                ),
            };
            server.emit_audit_ungated(
                AuditEvent::new(AuditKind::ProvisionalInterrupted)
                    .handle(&handle)
                    .caller(caller)
                    .session_fingerprint(&session_fingerprint)
                    .reason(&detail),
            );
            result
                .containment_failed(
                    response_reason,
                    recovery_handle,
                    Coverage::contain(),
                    outcome,
                    None,
                    None,
                    None,
                )
                .with_exposed_secret_refs(exposed_secret_refs)
        }
        ExecOutcome::Failed {
            started: false,
            reason: ref spawn_detail,
        } => {
            // The child never ran, so persist a terminal tombstone before
            // deleting the staging row. If deletion fails, restart recovery
            // sees a non-rollbackable terminal record rather than interpreting
            // an armed, unstarted row as an ambiguous mutation.
            if let Err(retire_error) = retire_non_executed_provisional(
                server,
                &provisional,
                format!("forward command did not start; no rollback is required: {spawn_detail}"),
            )
            .await
            {
                tracing::error!("{retire_error}");
                return ExecuteResult::exec_failed(
                    reason,
                    format!("{spawn_detail}; rollback state could not be retired safely"),
                );
            }
            result
        }
        _ => result,
    }
}

/// Hold an irreversible/uncertain/high-risk command for operator approval.
/// Consumes the routed [`GateInputs`]; `revert_preauthorized` and `bypass`
/// have already been acted on by the router and are ignored here.
#[cfg(test)]
pub(super) async fn hold_for_approval_with_authority<W: AsyncWrite + Unpin>(
    context: &mut RequestContext<'_, W>,
    request: ExecuteRequest,
    caller_principal: Option<PrincipalKey>,
    inputs: GateInputs,
) -> ExecuteResult {
    hold_for_approval_with_trace(context, request, caller_principal, inputs, None).await
}

pub(super) async fn hold_for_approval_with_trace<W: AsyncWrite + Unpin>(
    context: &mut RequestContext<'_, W>,
    request: ExecuteRequest,
    caller_principal: Option<PrincipalKey>,
    inputs: GateInputs,
    decision_trace: Option<guard::gating::DecisionTrace>,
) -> ExecuteResult {
    let server = context.server;
    let caller = context.caller;
    let GateInputs {
        reason,
        risk,
        reversibility,
        verb,
        authority,
        consume_access_verbs,
        ..
    } = inputs;
    if command_contains_sensitive_literals(&request.binary, &request.args) {
        return ExecuteResult::denied(SENSITIVE_ARGV_REPLAY_GUIDANCE);
    }
    if server.config.dry_run {
        return ExecuteResult::dry_run_gated(
            format!(
                "{} [GATE] would be held for operator approval (irreversible/uncertain)",
                reason
            ),
            Coverage::hold(),
        );
    }
    if !request.env.is_empty() {
        return ExecuteResult::denied(
            "approval holds reject plain environment values; use named secret references",
        );
    }
    if let Some(why) = gate_capacity_reason(server, caller_principal.as_ref()).await {
        return ExecuteResult::denied(why);
    }

    let handle = new_handle();
    let now = now_unix();

    let tool_secret_sources = {
        let mut registry = server.state.tool_registry.write().await;
        let _ = registry.reload_if_stale();
        match registry
            .resolve_env(
                &request.binary,
                &server.state.secrets,
                caller_principal.as_ref(),
                caller.user_key().as_deref(),
            )
            .await
        {
            Ok(resolved) => resolved.secret_sources,
            Err(error) => {
                return ExecuteResult::exec_failed(
                    reason,
                    format!("approval hold rejected: tool secret resolution failed: {error}"),
                )
            }
        }
    };

    // Secret-value binding: hash each referenced secret value NOW so a
    // same-principal caller cannot swap its mapped values between this hold and
    // the operator's approval. The binding is MANDATORY when there are secrets
    // and a principal: every referenced secret is bound, a resolved one by its
    // salted hash and an unresolved one by a sentinel. Binding the unresolved
    // case closes the gap where a caller makes a secret unresolvable at hold
    // (so it would otherwise be unbound) and then creates it with a chosen value
    // before approval. Verification at approve time fails closed on any change.
    let secret_binding = match caller_principal.clone() {
        Some(principal) => {
            let salt = hex_encode(&rand::random::<u128>().to_le_bytes());
            let mut hashes = std::collections::BTreeMap::new();
            for (env_var, secret_name) in request.secrets.iter().chain(&request.secret_files) {
                let entry = match server.state.secrets.get(&principal, secret_name).await {
                    Ok(Some(value)) => hash_secret_value(&salt, &value),
                    _ => SECRET_BINDING_UNRESOLVED.to_string(),
                };
                hashes.insert(env_var.clone(), entry);
            }
            let mut tool_hashes = std::collections::BTreeMap::new();
            for (env_var, secret_name) in tool_secret_sources {
                let entry = match server.state.secrets.get(&principal, &secret_name).await {
                    Ok(Some(value)) => hash_secret_value(&salt, &value),
                    _ => SECRET_BINDING_UNRESOLVED.to_string(),
                };
                tool_hashes.insert(
                    env_var,
                    guard::gating::approval::ToolSecretBinding {
                        secret_name,
                        hash: entry,
                    },
                );
            }
            Some(guard::gating::approval::SecretBinding {
                salt,
                hashes,
                tool_hashes: Some(tool_hashes),
            })
        }
        _ => None,
    };

    if !session_authority_is_current(server, &request, authority.as_ref()).await {
        return ExecuteResult::denied(
            "session expired, was revoked, or changed before approval hold creation",
        );
    }

    let (session_revision, secret_entitlements) = match request.session_token.as_deref() {
        Some(_) => match authority {
            Some(snapshot) => (snapshot.revision, snapshot.secret_entitlements),
            None => {
                return ExecuteResult::denied(
                    "session expired or was revoked before approval hold creation",
                )
            }
        },
        None => (String::new(), None),
    };
    let access_requests = match request.session_token.as_deref() {
        Some(token) if !consume_access_verbs.is_empty() => {
            match server
                .state
                .sessions
                .read()
                .await
                .select_access_requests(token, &consume_access_verbs)
            {
                Ok(requests) => requests,
                Err(reason) => {
                    return access_admission_denial(server, caller, &consume_access_verbs, reason)
                        .await
                }
            }
        }
        _ => Vec::new(),
    };
    let snapshot = ApprovalSnapshot {
        binary: request.binary.clone(),
        args: request.args.clone(),
        cwd: request.cwd.clone(),
        env: std::collections::BTreeMap::new(),
        secret_keys: request
            .secrets
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        session_fingerprint: request
            .session_token
            .as_deref()
            .map(|token| audit_session_fingerprint(Some(token))),
        session_revision: (!session_revision.is_empty()).then_some(session_revision),
        secret_entitlements,
        secret_file_keys: request
            .secret_files
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        verb_name: verb.as_ref().map(|v| v.name.clone()),
        verb_params: std::collections::BTreeMap::new(),
        catalog_version: verb.as_ref().map(|v| v.catalog_version),
        verb_digest: verb.as_ref().and_then(|v| v.verb_digest.clone()),
        verb_composition_digest: verb.as_ref().and_then(|v| v.composition_digest.clone()),
        access_verbs: consume_access_verbs,
        access_requests,
        principal: caller_principal,
        secret_binding,
    };
    let approval = Approval {
        handle: handle.clone(),
        snapshot,
        reason: reason.clone(),
        risk,
        reversibility,
        decision_trace,
        created_unix: now,
        ttl_secs: server.config.approval_ttl_secs,
        status: ApprovalStatus::Pending,
        decided_unix: None,
        decided_reason: None,
        result_exit: None,
        result_stdout: None,
        result_stderr: None,
        notes: Vec::new(),
    };

    if let Err(message) = persist_approval(server, &approval).await {
        return ExecuteResult::exec_failed(reason, message);
    }
    let notify = server
        .state
        .approvals
        .write()
        .await
        .enqueue(approval.clone());
    server.emit_audit_ungated(
        AuditEvent::new(AuditKind::Held)
            .handle(&handle)
            .caller(caller)
            .session_fingerprint(audit_session_fingerprint(request.session_token.as_deref()))
            .cmd(audit_command_line(&request.binary, &request.args))
            .field("risk", format!("{risk:?}"))
            .field("class", format!("{:?}", reversibility.map(|r| r.as_str())))
            .field("ttl", format!("{}s", server.config.approval_ttl_secs)),
    );
    server.emit_event(NotifyEvent {
        event: "hold_created",
        at_unix: now_unix(),
        handle: Some(handle.clone()),
        session_fingerprint: request
            .session_token
            .as_deref()
            .map(|token| audit_session_fingerprint(Some(token))),
        requester_principal: approval
            .snapshot
            .principal
            .as_ref()
            .map(ToString::to_string),
        reason: Some(reason.clone()),
        status: Some("pending".to_string()),
        behavior: None,
    });

    match request.wait_approval_secs {
        Some(wait) => {
            wait_for_decision(
                server,
                caller,
                &handle,
                notify,
                wait,
                context.stream_output,
                context.stream_writer,
            )
            .await
        }
        None => ExecuteResult::held(reason, handle.clone(), Coverage::hold()).with_verb_resolution(
            Vec::new(),
            Some(format!("approve: guard access approve {handle} --once")),
        ),
    }
}

/// Block (up to `wait_secs`) for an operator decision on a held command,
/// emitting keepalives on the streaming path so the connection stays open, then
/// return the real outcome. On timeout the command stays held.
async fn wait_for_decision<W: AsyncWrite + Unpin>(
    server: &ServerContext,
    caller: &CallerIdentity,
    handle: &str,
    notify: std::sync::Arc<tokio::sync::Notify>,
    wait_secs: u64,
    stream_output: bool,
    stream_writer: &mut W,
) -> ExecuteResult {
    let deadline = (wait_secs != u64::MAX).then(|| {
        tokio::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(wait_secs))
            .unwrap_or_else(tokio::time::Instant::now)
    });
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

        // Drop the registry read guard before attempting requester resume.
        // Holding it across `resume_approval()` deadlocks when the resume path
        // installs its `Pending -> Approving` transition under the write lock.
        let approval = {
            let approvals = server.state.approvals.read().await;
            approvals.get(handle).cloned()
        };
        if let Some(a) = approval {
            if approval_is_armed(&a) {
                return resume_approval(server, caller, handle).await;
            }
            if a.status.is_decided() {
                return approval_to_result(&a);
            }
        } else {
            return ExecuteResult::denied("held command disappeared from the queue");
        }

        let remaining = deadline
            .map(|deadline| deadline.saturating_duration_since(tokio::time::Instant::now()));
        if remaining.is_some_and(|remaining| remaining.is_zero()) {
            // Still pending at timeout: stays held.
            return ExecuteResult::held(
                "still awaiting operator approval".to_string(),
                handle.to_string(),
                Coverage::hold(),
            )
            .with_verb_resolution(
                Vec::new(),
                Some(format!("approve: guard access approve {handle} --once")),
            );
        }

        tokio::select! {
            _ = &mut notified => { /* re-check status at loop top */ }
            _ = async {
                match remaining {
                    Some(remaining) => tokio::time::sleep(remaining).await,
                    None => std::future::pending::<()>().await,
                }
            } => { /* timeout: re-check, then held */ }
            _ = keepalive.tick(), if stream_output => {
                let _ = write_stream_message(stream_writer, &ExecuteStreamMessage::Keepalive).await;
            }
        }
    }
}

pub(super) fn bound_persisted_transcript(value: Option<String>) -> Option<String> {
    bound_approval_transcript(value).0
}

async fn reconcile_resumed_approval(server: &ServerContext, handle: &str) {
    let Some(store) = &server.state.session_store else {
        return;
    };
    match store.load_approvals().await {
        Ok(rows) => {
            if let Some(row) = rows.into_iter().find(|row| row.handle == handle) {
                let wake = row.status.is_decided();
                server
                    .state
                    .approvals
                    .write()
                    .await
                    .install_persisted(row, wake);
            }
        }
        Err(error) => tracing::warn!("failed to reconcile resumed approval {handle}: {error}"),
    }
}

async fn commit_resumed_approval(
    server: &ServerContext,
    expected: Approval,
    next: Approval,
    wake: bool,
) -> Result<(), String> {
    let handle = expected.handle.clone();
    if let Some(store) = &server.state.session_store {
        if let Err(error) = store
            .compare_and_swap_approval(expected, next.clone())
            .await
        {
            reconcile_resumed_approval(server, &handle).await;
            return Err(format!(
                "approval transition conflict for {handle}: {error}"
            ));
        }
    }
    server
        .state
        .approvals
        .write()
        .await
        .install_persisted(next, wake);
    Ok(())
}

/// Claim and execute one operator-armed hold as its original requester. The
/// durable `Pending -> Approving` compare-and-set is the one-shot boundary.
/// A daemon restart while the child runs recovers `Approving` to `ExecFailed`,
/// so an ambiguous execution is never replayed.
pub(super) async fn resume_approval(
    server: &ServerContext,
    caller: &CallerIdentity,
    handle: &str,
) -> ExecuteResult {
    let transition = server.state.grant_request_transition_gate.lock().await;
    let Some(expected) = server.state.approvals.read().await.get(handle).cloned() else {
        return ExecuteResult::denied("no armed held command for this requester");
    };
    let caller_principal = caller.principal();
    if !caller.is_local_peer()
        || !scope_eq(&expected.snapshot.principal, &caller_principal)
        || !approval_is_armed(&expected)
    {
        return ExecuteResult::denied("no armed held command for this requester");
    }

    let now = now_unix();
    if now >= expected.deadline_unix() {
        let mut expired = expected.clone();
        expired.status = ApprovalStatus::Expired;
        expired.decided_unix = Some(now);
        expired.decided_reason = Some("expired before requester resume".to_string());
        if let Err(error) = commit_resumed_approval(server, expected, expired, true).await {
            return ExecuteResult::exec_failed("held command expired", error);
        }
        return ExecuteResult::denied("held command expired before requester resume");
    }

    let mut claimed = expected.clone();
    claimed.status = ApprovalStatus::Approving;
    claimed.decided_reason = Some("requester claimed armed hold for execution".to_string());
    if let Err(error) = commit_resumed_approval(server, expected, claimed.clone(), false).await {
        return ExecuteResult::denied(error);
    }
    drop(transition);

    if !server.emit_audit(
        AuditEvent::new(AuditKind::ApprovedExecuted)
            .handle(handle)
            .caller(caller)
            .session_fingerprint(
                claimed
                    .snapshot
                    .session_fingerprint
                    .as_deref()
                    .unwrap_or("none"),
            )
            .cmd(claimed.snapshot.command_line())
            .field("phase", "requester_claimed"),
    ) {
        let mut failed = claimed.clone();
        failed.status = ApprovalStatus::ExecFailed;
        failed.decided_unix = Some(now_unix());
        failed.decided_reason = Some(super::AUDIT_UNAVAILABLE_REASON.to_string());
        let _ = commit_resumed_approval(server, claimed, failed, true).await;
        return ExecuteResult::exec_failed(
            "requester resume refused",
            super::AUDIT_UNAVAILABLE_REASON.to_string(),
        );
    }

    let reason = format!("requester resumed operator-approved hold {handle}");
    let result = execute_snapshot(server, &claimed.snapshot, &reason).await;
    let completed_unix = now_unix();
    let mut terminal = claimed.clone();
    match &result.exec {
        ExecOutcome::Completed {
            exit_code,
            stdout,
            stderr,
        } => {
            terminal.status = ApprovalStatus::Approved;
            terminal.decided_unix = Some(completed_unix);
            terminal.decided_reason = Some("requester resumed operator-approved hold".to_string());
            terminal.result_exit = *exit_code;
            terminal.result_stdout = bound_persisted_transcript(stdout.clone());
            terminal.result_stderr = bound_persisted_transcript(stderr.clone());
        }
        ExecOutcome::Failed { reason, .. } => {
            terminal.status = ApprovalStatus::ExecFailed;
            terminal.decided_unix = Some(completed_unix);
            terminal.decided_reason = Some(reason.clone());
            terminal.result_exit = None;
            terminal.result_stdout = None;
            terminal.result_stderr = None;
        }
        _ => {
            terminal.status = ApprovalStatus::ExecFailed;
            terminal.decided_unix = Some(completed_unix);
            terminal.decided_reason =
                Some("resumed execution returned a non-terminal outcome".to_string());
            terminal.result_exit = None;
            terminal.result_stdout = None;
            terminal.result_stderr = None;
        }
    }
    if let Err(error) =
        commit_resumed_approval(server, claimed.clone(), terminal.clone(), true).await
    {
        return ExecuteResult::exec_failed(
            reason,
            format!("held command ran but its result was not durable: {error}"),
        );
    }
    server.emit_audit_ungated(
        AuditEvent::new(AuditKind::ApprovedExecuted)
            .handle(handle)
            .caller(caller)
            .session_fingerprint(
                claimed
                    .snapshot
                    .session_fingerprint
                    .as_deref()
                    .unwrap_or("none"),
            )
            .field("phase", "completed")
            .field("status", terminal.status.as_str())
            .field("exit", format!("{:?}", terminal.result_exit)),
    );
    server.emit_event(NotifyEvent {
        event: "decision_made",
        at_unix: completed_unix,
        handle: Some(handle.to_string()),
        session_fingerprint: claimed.snapshot.session_fingerprint.clone(),
        requester_principal: claimed.snapshot.principal.as_ref().map(ToString::to_string),
        reason: terminal.decided_reason.clone(),
        status: Some(terminal.status.as_str().to_string()),
        behavior: None,
    });
    result
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
/// separator ensure the stored digest is not a reusable plain hash of the
/// value. The persisted salt does not make a weak secret resistant to offline
/// guessing, so approval state remains daemon-private. Used only to detect a
/// value change between hold and approval.
pub(super) fn hash_secret_value(salt_hex: &str, value: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(salt_hex.as_bytes());
    hasher.update([0u8]);
    hasher.update(value.as_bytes());
    hex_encode(&hasher.finalize())
}

/// Execute an approved snapshot verbatim under the original caller's identity,
/// with no client stream. Used by `guard access approve`.
pub(super) async fn execute_snapshot(
    server: &ServerContext,
    snapshot: &ApprovalSnapshot,
    reason: &str,
) -> ExecuteResult {
    let access_requests =
        (!snapshot.access_requests.is_empty()).then_some(snapshot.access_requests.as_slice());
    execute_snapshot_with_access_request_inner(server, snapshot, reason, access_requests).await
}

#[cfg(all(test, unix))]
pub(super) async fn execute_snapshot_with_access_request(
    server: &ServerContext,
    snapshot: &ApprovalSnapshot,
    reason: &str,
    preferred_access_requests: Option<&[String]>,
) -> ExecuteResult {
    execute_snapshot_with_access_request_inner(server, snapshot, reason, preferred_access_requests)
        .await
}

async fn execute_snapshot_with_access_request_inner(
    server: &ServerContext,
    snapshot: &ApprovalSnapshot,
    reason: &str,
    preferred_access_requests: Option<&[String]>,
) -> ExecuteResult {
    if snapshot.contains_sensitive_literals() {
        return ExecuteResult::exec_failed(
            reason.to_string(),
            SENSITIVE_ARGV_REPLAY_GUIDANCE.to_string(),
        );
    }
    if !binary_allowed(&server.config.allowed_binaries, &snapshot.binary) {
        return ExecuteResult::exec_failed(
            reason.to_string(),
            format!(
                "approval rejected: binary '{}' is not in the server allow-list",
                snapshot.binary
            ),
        );
    }
    if snapshot.session_fingerprint.is_some() != snapshot.session_revision.is_some() {
        return ExecuteResult::exec_failed(
            reason.to_string(),
            "approval rejected: originating session identity is incomplete".to_string(),
        );
    }
    let preferred_access_requests =
        preferred_access_requests.filter(|requests| !requests.is_empty());
    if let Some(preferred) = preferred_access_requests {
        let mut expected = snapshot.access_requests.clone();
        expected.sort();
        expected.dedup();
        let mut supplied = preferred.to_vec();
        supplied.sort();
        supplied.dedup();
        if snapshot.session_fingerprint.is_none()
            || snapshot.access_verbs.is_empty()
            || expected.is_empty()
            || expected != supplied
        {
            return ExecuteResult::exec_failed(
                reason.to_string(),
                "approval rejected: originating access session expired or was revoked, or the held access binding is incomplete"
                    .to_string(),
            );
        }
    }
    if let (Some(fingerprint), Some(expected_revision)) = (
        snapshot.session_fingerprint.as_deref(),
        snapshot.session_revision.as_deref(),
    ) {
        let current = server
            .state
            .sessions
            .read()
            .await
            .effective_revision_for_fingerprint(fingerprint);
        if current.as_deref() != Some(expected_revision) {
            return ExecuteResult::exec_failed(
                reason.to_string(),
                "approval rejected: the issued session changed or was revoked after hold"
                    .to_string(),
            );
        }
    }

    let caller = reconstruct_caller(snapshot.principal.clone(), &CallerIdentity::Unknown);

    let current_tool_sources = {
        let mut registry = server.state.tool_registry.write().await;
        let _ = registry.reload_if_stale();
        match registry
            .resolve_env(
                &snapshot.binary,
                &server.state.secrets,
                snapshot.principal.as_ref(),
                caller.user_key().as_deref(),
            )
            .await
        {
            Ok(resolved) => resolved.secret_sources,
            Err(error) => {
                return ExecuteResult::exec_failed(
                    reason.to_string(),
                    format!("approval rejected: failed to re-resolve tool secrets: {error}"),
                )
            }
        }
    };

    // Legacy holds cannot safely use live secret mappings because no value or
    // tool-environment binding exists for the operator-reviewed snapshot.
    if snapshot.secret_binding.is_none()
        && (!snapshot.secret_keys.is_empty()
            || !snapshot.secret_file_keys.is_empty()
            || !current_tool_sources.is_empty())
    {
        return ExecuteResult::exec_failed(
            reason.to_string(),
            "approval rejected: secrets were not bound by the held snapshot".to_string(),
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
        for (env_var, secret_name) in snapshot
            .secret_keys
            .iter()
            .chain(&snapshot.secret_file_keys)
        {
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
            let resolved = match server.state.secrets.get(&principal, secret_name).await {
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
        let Some(tool_hashes) = binding.tool_hashes.as_ref() else {
            if !current_tool_sources.is_empty() {
                return ExecuteResult::exec_failed(
                    reason.to_string(),
                    "approval rejected: tool secrets were not bound by the held snapshot"
                        .to_string(),
                );
            }
            return execute_snapshot_request(
                server,
                snapshot,
                reason,
                &caller,
                preferred_access_requests,
            )
            .await;
        };
        if current_tool_sources.len() != tool_hashes.len()
            || current_tool_sources.iter().any(|(env_var, secret_name)| {
                tool_hashes
                    .get(env_var)
                    .is_none_or(|bound| bound.secret_name != *secret_name)
            })
        {
            return ExecuteResult::exec_failed(
                reason.to_string(),
                "approval rejected: tool secret mappings changed since the command was held"
                    .to_string(),
            );
        }
        for bound in tool_hashes.values() {
            let resolved = match server
                .state
                .secrets
                .get(&principal, &bound.secret_name)
                .await
            {
                Ok(value) => value,
                Err(error) => {
                    return ExecuteResult::exec_failed(
                        reason.to_string(),
                        format!(
                            "approval rejected: failed to re-resolve tool secret '{}': {error}",
                            bound.secret_name
                        ),
                    )
                }
            };
            let consistent = match (bound.hash.as_str(), resolved) {
                (SECRET_BINDING_UNRESOLVED, None) => true,
                (SECRET_BINDING_UNRESOLVED, Some(_)) => false,
                (hash, Some(value)) => hash_secret_value(&binding.salt, &value) == hash,
                (_, None) => false,
            };
            if !consistent {
                return ExecuteResult::exec_failed(
                    reason.to_string(),
                    "approval rejected: a tool-configured secret value changed since the command was held"
                        .to_string(),
                );
            }
        }
    }
    execute_snapshot_request(server, snapshot, reason, &caller, preferred_access_requests).await
}

async fn execute_snapshot_request(
    server: &ServerContext,
    snapshot: &ApprovalSnapshot,
    reason: &str,
    caller: &CallerIdentity,
    preferred_access_requests: Option<&[String]>,
) -> ExecuteResult {
    let mut request = ExecuteRequest {
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
        secret_files: snapshot
            .secret_file_keys
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
    request.session_token = if snapshot.session_fingerprint.is_none() {
        None
    } else {
        let sessions = server.state.sessions.read().await;
        super::admin::session_token_for_approval_snapshot(&sessions, snapshot)
    };
    if snapshot.session_fingerprint.is_some() && request.session_token.is_none() {
        return ExecuteResult::denied(
            "originating session expired, changed, or was revoked before held-command admission",
        );
    }
    let mut selected_verbs = snapshot.access_verbs.clone();
    selected_verbs.sort();
    selected_verbs.dedup();
    match admit_access_use(server, &request, &selected_verbs, preferred_access_requests).await {
        Ok(Some(_)) => {}
        Ok(None) if preferred_access_requests.is_some() => {
            return ExecuteResult::exec_failed(
                reason.to_string(),
                "approval rejected: originating access session expired or was revoked before held-command admission"
                    .to_string(),
            )
        }
        Ok(None) => {}
        Err(admission_reason) => {
            return ExecuteResult::exec_failed(reason.to_string(), admission_reason)
        }
    }
    let mut sink = tokio::io::sink();
    let mut context = RequestContext {
        server,
        caller,
        depth: 0,
        stream_output: false,
        stream_writer: &mut sink,
    };
    let verb_authority = snapshot
        .verb_name
        .as_ref()
        .map(|name| VerbAuthorityExpectation {
            name: name.clone(),
            catalog_version: snapshot.catalog_version,
            definition_digest: snapshot.verb_digest.clone(),
            composition_digest: snapshot.verb_composition_digest.clone(),
        });
    exec_after_approval_with_command_authority(
        &mut context,
        request,
        reason.to_string(),
        Some(snapshot.secret_entitlements.clone()),
        Some(CommandAuthorization::replay(verb_authority)),
    )
    .await
}

/// The single background task that drives time-based gate transitions: fires due
/// auto-reverts (after a startup grace so it can never race startup recovery) and
/// expires unattended holds (fail-closed). Runs only when gating is enabled.
pub(super) async fn gating_sweeper(server: ServerContext) {
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
        let expired = { server.state.approvals.write().await.expire_due(now) };
        for h in &expired {
            let row = server.state.approvals.read().await.get(h).cloned();
            if let Some(a) = row {
                let _ = persist_approval(&server, &a).await;
                server.emit_audit_ungated(
                    AuditEvent::new(AuditKind::ApprovalExpired)
                        .handle(h)
                        .session_fingerprint(
                            a.snapshot.session_fingerprint.as_deref().unwrap_or("none"),
                        )
                        .reason("fail-closed deny"),
                );
                server.emit_event(NotifyEvent {
                    event: "decision_made",
                    at_unix: now,
                    handle: Some(h.clone()),
                    session_fingerprint: a.snapshot.session_fingerprint.clone(),
                    requester_principal: a.snapshot.principal.as_ref().map(ToString::to_string),
                    reason: Some("held action expired without approval".to_string()),
                    status: Some("expired".to_string()),
                    behavior: None,
                });
            }
        }

        // Due auto-reverts. Each exact Armed -> Reverting transition becomes
        // durable before the rollback task starts, so a write failure leaves
        // the timer armed and retryable.
        // Each revert is bounded by a wall-clock timeout (a timeout is recorded as
        // RevertFailed and stays queryable), and reverts are dispatched as
        // independent tasks so a burst of slow rollbacks cannot serialize and push
        // out the next tick's fail-closed expiry sweep.
        let due = { server.state.provisional.read().await.due_handles(now) };
        for handle in due {
            let claimed = {
                let mut registry = server.state.provisional.write().await;
                let Some(expected) = registry.get(&handle).cloned() else {
                    continue;
                };
                let mut staged = guard::gating::provisional::ProvisionalRegistry::new();
                staged.insert(expected.clone());
                let Ok(next) = staged.begin_revert(&handle) else {
                    continue;
                };
                if let Some(store) = &server.state.session_store {
                    if let Err(error) = store
                        .compare_and_swap_provisional(expected, next.clone())
                        .await
                    {
                        tracing::warn!(
                            "failed to persist due rollback claim {}: {}",
                            handle,
                            error
                        );
                        continue;
                    }
                }
                registry.insert(next.clone());
                next
            };
            server.emit_event(NotifyEvent {
                event: "provisional_due",
                at_unix: now,
                handle: Some(claimed.handle.clone()),
                session_fingerprint: claimed.session_fingerprint.clone(),
                requester_principal: None,
                reason: Some(claimed.reason.clone()),
                status: Some("reverting".to_string()),
                behavior: None,
            });
            let cfg = server.clone();
            tokio::spawn(async move {
                let _ = finish_due_provisional(&cfg, &claimed).await;
            });
        }

        // Due read-grant expiries. Revoking a read grant only removes access, so
        // unlike a provisional revert it is always safe to run unattended; there
        // is no needs-operator-decision path. Persist the Reverting transition
        // before running so a crash mid-revocation recovers to Active and retries.
        let due_grants = { server.state.read_grants.write().await.take_due(now) };
        for g in due_grants {
            persist_read_grant(&server, &g).await;
            let cfg = server.clone();
            tokio::spawn(async move {
                finish_read_grant_revert(&cfg, &g, "expiry").await;
            });
        }

        // Bound the tables: drop terminal rows past the retention window.
        let pruned_p = {
            server
                .state
                .provisional
                .write()
                .await
                .prune_terminal(now, GATING_RETENTION_SECS)
        };
        for h in pruned_p {
            delete_provisional_row(&server, &h).await;
        }
        let pruned_a = {
            server
                .state
                .approvals
                .write()
                .await
                .prune_decided(now, GATING_RETENTION_SECS)
        };
        for h in pruned_a {
            if let Some(store) = &server.state.session_store {
                if let Err(e) = store.delete_approval(h.clone()).await {
                    tracing::warn!("failed to delete pruned approval {}: {}", h, e);
                }
            }
        }
        let pruned_g = {
            server
                .state
                .read_grants
                .write()
                .await
                .prune_terminal(now, GATING_RETENTION_SECS)
        };
        for path in pruned_g {
            delete_read_grant_row(&server, &path).await;
        }
    }
}

/// Run the revert for a provisional under the original caller's identity, with no
/// client stream. Used by the sweeper and `guard revert`.
async fn run_provisional_revert(server: &ServerContext, p: &Provisional) -> ExecuteResult {
    if p.api_revert.is_none()
        && command_contains_sensitive_literals(&p.revert_binary, &p.revert_args)
    {
        return ExecuteResult::exec_failed(
            format!("auto-revert of provisional {}", p.handle),
            SENSITIVE_ARGV_REPLAY_GUIDANCE.to_string(),
        );
    }
    if let Some(reason) = invalid_binary_reason(&p.revert_binary) {
        return ExecuteResult::exec_failed(
            format!("auto-revert of provisional {}", p.handle),
            reason,
        );
    }
    if !binary_allowed(&server.config.allowed_binaries, &p.revert_binary) {
        return ExecuteResult::exec_failed(
            format!("auto-revert of provisional {}", p.handle),
            format!(
                "rollback binary '{}' is outside the server allow-list",
                p.revert_binary
            ),
        );
    }
    let caller = reconstruct_caller(p.principal.clone(), &CallerIdentity::Unknown);
    let request = ExecuteRequest {
        binary: p.revert_binary.clone(),
        args: p.revert_args.clone(),
        cwd: p.cwd.clone(),
        auth_token: None,
        env: std::collections::HashMap::new(),
        secrets: p
            .secret_keys
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        secret_files: p
            .secret_file_keys
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
    let mut context = RequestContext {
        server,
        caller: &caller,
        depth: 0,
        stream_output: false,
        stream_writer: &mut sink,
    };
    exec_after_approval_with_secret_authority(
        &mut context,
        request,
        format!("auto-revert of provisional {}", p.handle),
        Some(p.secret_entitlements.clone()),
    )
    .await
}

pub(super) async fn run_provisional_check(
    server: &ServerContext,
    p: &Provisional,
) -> ExecuteResult {
    let binary = p.confirm_check_binary.as_deref().unwrap_or_default();
    if command_contains_sensitive_literals(binary, &p.confirm_check_args) {
        return ExecuteResult::exec_failed(
            format!("confirmation check for provisional {}", p.handle),
            SENSITIVE_ARGV_REPLAY_GUIDANCE.to_string(),
        );
    }
    if let Some(reason) = invalid_binary_reason(binary) {
        return ExecuteResult::exec_failed(
            format!("confirmation check for provisional {}", p.handle),
            format!("invalid confirmation-check command: {reason}"),
        );
    }
    if !binary_allowed(&server.config.allowed_binaries, binary) {
        return ExecuteResult::exec_failed(
            format!("confirmation check for provisional {}", p.handle),
            format!(
                "confirmation-check binary '{}' is outside the server allow-list",
                binary
            ),
        );
    }
    let caller = reconstruct_caller(p.principal.clone(), &CallerIdentity::Unknown);
    let request = ExecuteRequest {
        binary: p.confirm_check_binary.clone().unwrap_or_default(),
        args: p.confirm_check_args.clone(),
        cwd: p.cwd.clone(),
        auth_token: None,
        env: std::collections::HashMap::new(),
        secrets: p
            .secret_keys
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        secret_files: p
            .secret_file_keys
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        stream: false,
        session_token: None,
        revert: None,
        confirm_within_secs: None,
        require_approval: None,
        wait_approval_secs: None,
        verb: None,
        reevaluate: false,
        ssh_hostkey: None,
    };
    let mut sink = tokio::io::sink();
    let mut context = RequestContext {
        server,
        caller: &caller,
        depth: 0,
        stream_output: false,
        stream_writer: &mut sink,
    };
    exec_after_approval_with_secret_authority(
        &mut context,
        request,
        format!("confirmation check for provisional {}", p.handle),
        Some(p.secret_entitlements.clone()),
    )
    .await
}

pub(super) async fn finish_due_provisional(
    server: &ServerContext,
    p: &Provisional,
) -> (String, Option<i32>) {
    if p.confirm_check_binary.is_none() {
        return finish_revert(server, p, &CallerIdentity::Unknown, "auto").await;
    }
    let checked = tokio::time::timeout(
        std::time::Duration::from_secs(REVERT_EXEC_TIMEOUT_SECS),
        run_provisional_check(server, p),
    )
    .await;
    let check_exit = checked.ok().and_then(|result| match result.exec {
        ExecOutcome::Completed { exit_code, .. } => exit_code,
        _ => None,
    });
    if check_exit == Some(0) {
        let mut registry = server.state.provisional.write().await;
        let expected = registry.get(&p.handle).cloned();
        let confirmed = expected.as_ref().and_then(|expected| {
            let mut staged = guard::gating::provisional::ProvisionalRegistry::new();
            staged.insert(expected.clone());
            staged.confirm_after_check(&p.handle).ok()
        });
        match (expected, confirmed) {
            (Some(expected), Some(row)) => {
                if let Some(store) = &server.state.session_store {
                    if let Err(error) = store
                        .compare_and_swap_provisional(expected, row.clone())
                        .await
                    {
                        drop(registry);
                        tracing::warn!(
                            "confirmation check succeeded but provisional {} could not become durable: {}",
                            p.handle,
                            error
                        );
                    } else {
                        registry.insert(row.clone());
                        drop(registry);
                        forget_proxy_provenance(server, &p.handle).await;
                        remove_revert_body(p);
                        server.emit_audit_ungated(
                            AuditEvent::new(AuditKind::ProvisionalAutoConfirmed)
                                .handle(&p.handle)
                                .field(
                                    "check",
                                    audit_command_line(
                                        p.confirm_check_binary.as_deref().unwrap_or_default(),
                                        &p.confirm_check_args,
                                    ),
                                )
                                .field("control_path", format!("{:?}", p.control_path)),
                        );
                        server.emit_event(NotifyEvent {
                            event: "decision_made",
                            at_unix: now_unix(),
                            handle: Some(p.handle.clone()),
                            session_fingerprint: p.session_fingerprint.clone(),
                            requester_principal: None,
                            reason: Some("independent confirmation check succeeded".to_string()),
                            status: Some("confirmed".to_string()),
                            behavior: None,
                        });
                        return (
                            format!("provisional {} confirmed by independent check", p.handle),
                            Some(0),
                        );
                    }
                } else {
                    registry.insert(row.clone());
                    drop(registry);
                    forget_proxy_provenance(server, &p.handle).await;
                    remove_revert_body(p);
                    server.emit_audit_ungated(
                        AuditEvent::new(AuditKind::ProvisionalAutoConfirmed)
                            .handle(&p.handle)
                            .field(
                                "check",
                                audit_command_line(
                                    p.confirm_check_binary.as_deref().unwrap_or_default(),
                                    &p.confirm_check_args,
                                ),
                            )
                            .field("control_path", format!("{:?}", p.control_path)),
                    );
                    return (
                        format!("provisional {} confirmed by independent check", p.handle),
                        Some(0),
                    );
                }
            }
            _ => {
                drop(registry);
                tracing::warn!(
                    "confirmation check succeeded but provisional {} was no longer reverting",
                    p.handle
                );
            }
        }
    }
    server.emit_audit_ungated(
        AuditEvent::new(AuditKind::ProvisionalCheckFailed)
            .handle(&p.handle)
            .reason("running rollback")
            .field("exit", format!("{check_exit:?}")),
    );
    finish_revert(server, p, &CallerIdentity::Unknown, "auto-check-failed").await
}

async fn run_api_revert(
    server: &ServerContext,
    p: &Provisional,
    api: &ApiRevertPlan,
) -> Result<(), RevertError> {
    let registry = server.state.protocol_registry.read().await;
    let proxy = if api.endpoint.is_empty() {
        let mut matches = registry
            .values()
            .filter(|proxy| proxy.protocol_name() == api.protocol);
        let first = matches.next().cloned();
        if first.is_some() && matches.next().is_some() {
            return Err(RevertError::Retryable(format!(
                "persisted API revert for protocol '{}' predates endpoint binding and matches multiple running endpoints; the change is still live and needs an operator decision",
                api.protocol
            )));
        }
        first
    } else {
        registry.get(&api.endpoint).cloned()
    };
    let Some(proxy) = proxy else {
        // The mutation is still live; the proxy that would carry the revert is
        // just not running now (a restart without the flag, a protocol change).
        // Surface it for an operator decision rather than burning the revert.
        let target = if api.endpoint.is_empty() {
            format!("no running api-proxy for protocol '{}'", api.protocol)
        } else {
            format!(
                "no running API endpoint '{}' for protocol '{}'",
                api.endpoint, api.protocol
            )
        };
        return Err(RevertError::Retryable(format!(
            "{target}; the change is still live and needs an operator decision"
        )));
    };
    if api.upstream_target.is_empty() || api.upstream_identity.is_empty() {
        return Err(RevertError::Retryable(
            "persisted API revert predates upstream identity binding; the change is still live and needs an operator decision"
                .to_string(),
        ));
    }
    if !proxy.matches_upstream_identity(&api.protocol, &api.upstream_target, &api.upstream_identity)
    {
        return Err(RevertError::Retryable(format!(
            "API endpoint '{}' no longer matches the protocol, target, and credential identity that armed this revert; the change is still live and needs an operator decision",
            api.endpoint
        )));
    }
    drop(registry);
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
    let mut resp = rb.send().await.map_err(|error| {
        let detail = upstream.redact_error_excerpt(error.to_string().as_bytes(), 512);
        RevertError::Failed(format!(
            "send api revert for provisional {}: {detail}",
            p.handle
        ))
    })?;
    if !resp.status().is_success() {
        let status = resp.status();
        const MAX_REVERT_ERROR_BYTES: usize = 4096;
        const MAX_REVERT_ERROR_CHARS: usize = 512;
        let mut bytes = Vec::new();
        while bytes.len() < MAX_REVERT_ERROR_BYTES {
            let chunk = match resp.chunk().await {
                Ok(Some(chunk)) => chunk,
                Ok(None) | Err(_) => break,
            };
            let remaining = MAX_REVERT_ERROR_BYTES - bytes.len();
            bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        }
        let text = upstream.redact_error_excerpt(&bytes, MAX_REVERT_ERROR_CHARS);
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

async fn defer_revert(
    server: &ServerContext,
    p: &Provisional,
    caller: &CallerIdentity,
    kind: &str,
    detail: String,
) -> (String, Option<i32>) {
    let updated = {
        let mut reg = server.state.provisional.write().await;
        reg.set_needs_operator_decision(&p.handle, detail.clone());
        reg.get(&p.handle).cloned()
    };
    if let Some(u) = &updated {
        if let Err(error) = try_persist_provisional(server, u).await {
            tracing::error!(
                "deferred rollback state for provisional {} was not durable: {}",
                p.handle,
                error
            );
            return (
                format!(
                    "provisional {} revert was deferred but its durable state could not be recorded; retry the operator action",
                    p.handle
                ),
                None,
            );
        }
    }
    server.emit_audit_ungated(
        AuditEvent::new(AuditKind::RevertDeferred)
            .handle(&p.handle)
            .caller(caller)
            .reason(&detail)
            .field("kind", kind),
    );
    server.emit_event(NotifyEvent {
        event: "decision_made",
        at_unix: now_unix(),
        handle: Some(p.handle.clone()),
        session_fingerprint: p.session_fingerprint.clone(),
        requester_principal: None,
        reason: Some(detail.clone()),
        status: Some("needs_operator_decision".to_string()),
        behavior: None,
    });
    (
        format!("provisional {} revert deferred: {}", p.handle, detail),
        None,
    )
}

/// Run a claimed (`Reverting`) provisional's revert and record the outcome.
/// Returns `(message, exit_code)`.
pub(super) async fn finish_revert(
    server: &ServerContext,
    p: &Provisional,
    caller: &CallerIdentity,
    kind: &str,
) -> (String, Option<i32>) {
    // Bound the revert so a hung rollback cannot pin the sweeper (which also
    // drives fail-closed hold expiry). A timeout is recorded as RevertFailed.
    let (status_ok, exit, detail) = if let Some(api) = &p.api_revert {
        match tokio::time::timeout(
            std::time::Duration::from_secs(REVERT_EXEC_TIMEOUT_SECS),
            run_api_revert(server, p, api),
        )
        .await
        {
            Ok(Ok(())) => (true, Some(0), None),
            // Recoverable (no proxy for the protocol right now): route to the
            // operator instead of terminal-failing, so a restart or flag change
            // does not silently strand a live mutation.
            Ok(Err(RevertError::Retryable(detail))) => {
                return defer_revert(server, p, caller, kind, detail).await;
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
            run_provisional_revert(server, p),
        )
        .await
        {
            Ok(result) => match &result.exec {
                ExecOutcome::Completed { exit_code, .. } => {
                    let ok = exit_code.unwrap_or(-1) == 0;
                    (ok, *exit_code, None)
                }
                ExecOutcome::Failed {
                    started: false,
                    reason,
                    ..
                } if !p.secret_keys.is_empty() || !p.secret_file_keys.is_empty() => {
                    return defer_revert(
                        server,
                        p,
                        caller,
                        kind,
                        format!("revert secret resolution or pre-spawn setup failed: {reason}"),
                    )
                    .await;
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
    // `kind` names who drove this rollback ("auto"/"auto-check-failed" for the
    // deadline sweeper, "manual" for `guard revert`). Only the sweeper's own
    // rollback stamps the row, so a later `guard confirm` can say the timer
    // fired rather than only that the handle is spent.
    let auto_reverted_unix = kind.starts_with("auto").then(now_unix);
    let updated = {
        let mut reg = server.state.provisional.write().await;
        if status_ok {
            reg.set_reverted(&p.handle, exit, auto_reverted_unix);
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
        if let Err(error) = try_persist_provisional(server, u).await {
            tracing::error!(
                "rollback for provisional {} completed but its terminal state was not durable: {}",
                p.handle,
                error
            );
            return (
                format!(
                    "provisional {} rollback completed but its terminal state could not be recorded",
                    p.handle
                ),
                exit,
            );
        }
    }
    // The revert is terminal (whether it succeeded or failed); drop any
    // api-proxy provenance tied to it so it cannot outlive its window, and
    // remove the persisted revert body so secret-bearing snapshots do not
    // accumulate on disk.
    forget_proxy_provenance(server, &p.handle).await;
    remove_revert_body(p);
    if status_ok {
        server.emit_audit_ungated(
            AuditEvent::new(AuditKind::Revert)
                .handle(&p.handle)
                .caller(caller)
                .field("kind", kind)
                .field("exit", format!("{exit:?}")),
        );
        server.emit_event(NotifyEvent {
            event: "decision_made",
            at_unix: now_unix(),
            handle: Some(p.handle.clone()),
            session_fingerprint: p.session_fingerprint.clone(),
            requester_principal: None,
            reason: Some(format!("rollback completed ({kind})")),
            status: Some("reverted".to_string()),
            behavior: None,
        });
        (
            format!("provisional {} reverted (exit {:?})", p.handle, exit),
            exit,
        )
    } else {
        server.emit_audit_ungated(
            AuditEvent::new(AuditKind::RevertFailed)
                .handle(&p.handle)
                .caller(caller)
                .field("kind", kind)
                .field("exit", format!("{exit:?}"))
                .field("detail", format!("{detail:?}")),
        );
        server.emit_event(NotifyEvent {
            event: "decision_made",
            at_unix: now_unix(),
            handle: Some(p.handle.clone()),
            session_fingerprint: p.session_fingerprint.clone(),
            requester_principal: None,
            reason: detail.clone(),
            status: Some("revert_failed".to_string()),
            behavior: None,
        });
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

#[cfg(test)]
mod transactional_tests {
    use super::*;

    #[tokio::test]
    async fn api_revert_creation_failure_does_not_arm_memory_only_authority() {
        let mut server = crate::server::tests::config_for_proposal_test();
        let state = tempfile::tempdir().unwrap();
        let store = crate::session_store::SessionStore::open(state.path().join("state.db"), 3600)
            .await
            .unwrap();
        store.fail_next_write_for_test();
        server.state.session_store = Some(store.clone());
        let sink = DaemonGateSink {
            server: server.clone(),
            endpoint: "fixture-endpoint".to_string(),
            protocol: "fixture-protocol".to_string(),
            snapshot_dir: state.path().to_path_buf(),
            snapshot_dir_safe: true,
            window_secs: 60,
        };

        let handle = guard::proxy::GateSink::arm_revert(
            &sink,
            guard::proxy::ApiMutation {
                label: "fixture mutation".to_string(),
                revert: guard::proxy::HttpRevert {
                    method: "DELETE".to_string(),
                    path: "/fixture".to_string(),
                    body: None,
                },
                session_fingerprint: None,
                session_revision: None,
                secret_entitlements: None,
                upstream_target: "https://fixture.invalid".to_string(),
                upstream_identity: "fixture-identity".to_string(),
            },
        )
        .await;

        assert!(handle.is_none());
        assert!(server.state.provisional.read().await.list().is_empty());
        assert!(store.load_provisionals().await.unwrap().is_empty());
    }
}
