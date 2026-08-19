// Re-exported so sibling server modules keep a single import path for the
// gating clock.
pub(super) use guard::env::now_unix;

use guard::audit::{AuditEvent, AuditKind};

use guard::gating::approval::{
    bound_approval_transcript, Approval, ApprovalSnapshot, ApprovalStatus,
};
use guard::gating::provisional::{
    ApiRevertPlan, Provisional, ProvisionalRegistry, ProvisionalStatus, REVERT_BODY_CLEANUP_PREFIX,
};
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
    exec_with_read_grant_retry_with_command_authority, resolve_current_tool_env,
    CommandAuthorization, VerbAuthorityExpectation,
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

async fn api_session_requester_principal(
    server: &ServerContext,
    fingerprint: Option<&str>,
    revision: Option<&str>,
) -> Option<PrincipalKey> {
    let (Some(fingerprint), Some(revision)) = (fingerprint, revision) else {
        return None;
    };
    let sessions = server.state.sessions.read().await;
    sessions.list().into_iter().find_map(|summary| {
        let matches_authority = sessions
            .api_authority_for(&summary.token)
            .is_some_and(|(candidate, _)| candidate == fingerprint)
            && sessions
                .authority_snapshot(&summary.token)
                .is_some_and(|(candidate, _)| candidate == revision);
        if !matches_authority {
            return None;
        }
        match summary.owner {
            crate::session::SessionOwner::Principal(principal) => Some(principal),
            crate::session::SessionOwner::Unowned => None,
        }
    })
}

const STAGED_CLEANUP_RETRY_SECS: u64 = 30;
const DISPATCH_CLASSIFICATION_RETRY_SECS: u64 = 90;

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
    let mut durable = provisional.clone();
    durable.forward_persistence_failed = false;
    let transition_gate = server.provisional_transition_gate(&provisional.handle);
    let _transition = transition_gate.lock().await;
    if server
        .state
        .provisional
        .read()
        .await
        .get(&provisional.handle)
        != Some(provisional)
    {
        return false;
    }
    match store.save_provisional(durable.clone()).await {
        Ok(()) => {
            let mut registry = server.state.provisional.write().await;
            if registry.get(&provisional.handle) != Some(provisional) {
                return false;
            }
            registry.insert(durable);
            true
        }
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

/// Commit one exact provisional transition before conditionally publishing it
/// to the live registry. The independently owned task retains coordination
/// through durable completion even if its caller is cancelled.
pub(super) async fn persist_provisional_transition(
    server: &ServerContext,
    expected: Provisional,
    next: Provisional,
) -> Result<bool, String> {
    let server = server.clone();
    tokio::spawn(async move {
        let transition_gate = server.provisional_transition_gate(&expected.handle);
        let _transition = transition_gate.lock().await;
        if server.state.provisional.read().await.get(&expected.handle) != Some(&expected) {
            return Ok(false);
        }
        let Some(store) = &server.state.session_store else {
            return Err("durable provisional state is unavailable".to_string());
        };
        if expected.forward_persistence_failed {
            store
                .save_provisional(expected.clone())
                .await
                .map_err(|error| format!("failed to converge provisional state: {error}"))?;
        }
        #[cfg(test)]
        if let Some(api) = expected.api_revert.as_ref() {
            pause_api_containment(&api.endpoint, "provisional_transition_before_persist").await;
        }
        store
            .compare_and_swap_provisional(expected.clone(), next.clone())
            .await
            .map_err(|error| format!("failed to persist provisional transition: {error}"))?;
        #[cfg(test)]
        if let Some(api) = expected.api_revert.as_ref() {
            pause_api_containment(&api.endpoint, "provisional_transition_committed").await;
        }
        let mut registry = server.state.provisional.write().await;
        if registry.get(&expected.handle) == Some(&expected) {
            registry.insert(next);
            Ok(true)
        } else {
            // A live mutation that did not participate in this coordinator is
            // never overwritten by a stale post-I/O result.
            Ok(false)
        }
    })
    .await
    .map_err(|error| format!("provisional transition task failed: {error}"))?
}

/// Cancel one exact inert API row under the same coordinator used by dispatch
/// publication. Once a dispatch transition commits, this operation cannot
/// match either durable or live state.
async fn cancel_exact_staged_provisional(server: &ServerContext, handle: &str) -> bool {
    let server = server.clone();
    let handle = handle.to_string();
    tokio::spawn(async move {
        let transition_gate = server.provisional_transition_gate(&handle);
        let _transition = transition_gate.lock().await;
        let Some(expected) = server.state.provisional.read().await.get(&handle).cloned() else {
            return true;
        };
        if expected.status != ProvisionalStatus::Staged || expected.forward_done {
            return false;
        }
        let Some(store) = &server.state.session_store else {
            return false;
        };
        if let Err(error) = remove_revert_body(&expected) {
            tracing::warn!("api-proxy staged revert body cleanup failed: {error}");
            let mut cleanup_pending = expected.clone();
            cleanup_pending.revert_detail = Some(
                "pre-dispatch containment cleanup is pending a bounded durable retry".to_string(),
            );
            if store
                .compare_and_swap_provisional(expected.clone(), cleanup_pending.clone())
                .await
                .is_ok()
            {
                let mut registry = server.state.provisional.write().await;
                if registry.get(&handle) == Some(&expected) {
                    registry.insert(cleanup_pending);
                }
            }
            return false;
        }
        if let Err(error) = store.compare_and_delete_provisional(expected.clone()).await {
            tracing::warn!("api-proxy staged revert cleanup failed: {error}");
            let mut cleanup_pending = expected.clone();
            cleanup_pending.revert_detail = Some(
                "pre-dispatch containment cleanup is pending a bounded durable retry".to_string(),
            );
            if store
                .compare_and_swap_provisional(expected.clone(), cleanup_pending.clone())
                .await
                .is_ok()
            {
                let mut registry = server.state.provisional.write().await;
                if registry.get(&handle) == Some(&expected) {
                    registry.insert(cleanup_pending);
                }
            }
            return false;
        }
        let mut registry = server.state.provisional.write().await;
        if registry.get(&handle) != Some(&expected) {
            return false;
        }
        registry.remove(&handle);
        drop(registry);
        #[cfg(test)]
        if let Some(api) = expected.api_revert.as_ref() {
            pause_api_containment(&api.endpoint, "staging_cleanup_completed").await;
        }
        true
    })
    .await
    .unwrap_or(false)
}

/// Remove a failed pre-dispatch body staging transaction while its per-handle
/// coordinator is held. Failure leaves the exact durable owner row intact so
/// startup and the bounded cleanup path retain both quota and file ownership.
async fn retire_failed_body_staging_locked(server: &ServerContext, expected: &Provisional) -> bool {
    if remove_revert_body(expected).is_err() {
        return false;
    }
    let Some(store) = &server.state.session_store else {
        return false;
    };
    if store
        .compare_and_delete_provisional(expected.clone())
        .await
        .is_err()
    {
        return false;
    }
    let mut registry = server.state.provisional.write().await;
    if registry.get(&expected.handle) != Some(expected) {
        return false;
    }
    registry.remove(&expected.handle);
    true
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
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .await?;
        file.write_all(bytes).await?;
        file.sync_all().await?;
        let parent = path.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "revert body has no parent",
            )
        })?;
        tokio::fs::File::open(parent).await?.sync_all().await
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

#[cfg(test)]
type ApiContainmentHook = (
    std::sync::Arc<tokio::sync::Semaphore>,
    std::sync::Arc<tokio::sync::Semaphore>,
);

#[cfg(test)]
fn api_containment_hooks(
) -> &'static std::sync::Mutex<std::collections::BTreeMap<(String, &'static str), ApiContainmentHook>>
{
    static HOOKS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::BTreeMap<(String, &'static str), ApiContainmentHook>>,
    > = std::sync::OnceLock::new();
    HOOKS.get_or_init(|| std::sync::Mutex::new(std::collections::BTreeMap::new()))
}

#[cfg(test)]
pub(super) struct ApprovalLifecycleTestHook {
    pub(super) enqueued: std::sync::Arc<tokio::sync::Semaphore>,
    pub(super) retired: std::sync::Arc<tokio::sync::Semaphore>,
}

#[cfg(test)]
fn approval_lifecycle_hooks(
) -> &'static std::sync::Mutex<std::collections::BTreeMap<usize, ApprovalLifecycleTestHook>> {
    static HOOKS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::BTreeMap<usize, ApprovalLifecycleTestHook>>,
    > = std::sync::OnceLock::new();
    HOOKS.get_or_init(|| std::sync::Mutex::new(std::collections::BTreeMap::new()))
}

#[cfg(test)]
pub(super) fn observe_approval_lifecycle_for_test(
    server: &ServerContext,
) -> ApprovalLifecycleTestHook {
    let hook = ApprovalLifecycleTestHook {
        enqueued: std::sync::Arc::new(tokio::sync::Semaphore::new(0)),
        retired: std::sync::Arc::new(tokio::sync::Semaphore::new(0)),
    };
    approval_lifecycle_hooks().lock().unwrap().insert(
        std::sync::Arc::as_ptr(&server.state.approvals) as usize,
        ApprovalLifecycleTestHook {
            enqueued: hook.enqueued.clone(),
            retired: hook.retired.clone(),
        },
    );
    hook
}

#[cfg(test)]
fn signal_approval_lifecycle(server: &ServerContext, retired: bool) {
    let hooks = approval_lifecycle_hooks().lock().unwrap();
    let Some(hook) = hooks.get(&(std::sync::Arc::as_ptr(&server.state.approvals) as usize)) else {
        return;
    };
    if retired {
        hook.retired.add_permits(1);
    } else {
        hook.enqueued.add_permits(1);
    }
}

#[cfg(test)]
fn install_api_containment_hook(endpoint: &str, phase: &'static str) -> ApiContainmentHook {
    let reached = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    let release = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    api_containment_hooks().lock().unwrap().insert(
        (endpoint.to_string(), phase),
        (reached.clone(), release.clone()),
    );
    (reached, release)
}

#[cfg(test)]
async fn pause_api_containment(endpoint: &str, phase: &'static str) {
    let hook = api_containment_hooks()
        .lock()
        .unwrap()
        .remove(&(endpoint.to_string(), phase));
    if let Some((reached, release)) = hook {
        reached.add_permits(1);
        release.acquire().await.unwrap().forget();
    }
}

/// Remove a revert's persisted body file once its provisional reaches a terminal
/// state, so secret-bearing snapshots do not accumulate on disk.
pub(super) fn remove_revert_body(p: &Provisional) -> std::io::Result<()> {
    if let Some(api) = &p.api_revert {
        if let Some(body_file) = &api.body_file {
            match std::fs::remove_file(body_file) {
                Ok(()) => {
                    #[cfg(unix)]
                    {
                        let parent = body_file.parent().ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "revert body has no parent",
                            )
                        })?;
                        std::fs::File::open(parent)?.sync_all()?;
                    }
                    return Ok(());
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    #[cfg(unix)]
                    {
                        let parent = body_file.parent().ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "revert body has no parent",
                            )
                        })?;
                        std::fs::File::open(parent)?.sync_all()?;
                    }
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

fn mark_revert_body_cleanup_pending(row: &mut Provisional) {
    if row
        .api_revert
        .as_ref()
        .and_then(|revert| revert.body_file.as_ref())
        .is_none()
    {
        return;
    }
    let detail = row
        .revert_detail
        .take()
        .unwrap_or_else(|| "rollback completed".to_string());
    row.revert_detail = Some(format!("{REVERT_BODY_CLEANUP_PREFIX}{detail}"));
}

async fn converge_terminal_revert_body_cleanup(
    server: &ServerContext,
    expected: &Provisional,
) -> bool {
    let Some(current) = server
        .state
        .provisional
        .read()
        .await
        .get(&expected.handle)
        .cloned()
    else {
        return false;
    };
    if !current.status.is_lifecycle_final()
        || current.status != expected.status
        || current
            .api_revert
            .as_ref()
            .and_then(|revert| revert.body_file.as_ref())
            != expected
                .api_revert
                .as_ref()
                .and_then(|revert| revert.body_file.as_ref())
    {
        return false;
    }
    let Some(detail) = current
        .revert_detail
        .as_deref()
        .and_then(|detail| detail.strip_prefix(REVERT_BODY_CLEANUP_PREFIX))
    else {
        return true;
    };
    if let Err(error) = remove_revert_body(&current) {
        tracing::warn!(
            "rollback body cleanup for provisional {} remains pending: {}",
            current.handle,
            error
        );
        return false;
    }
    let mut next = current.clone();
    if let Some(revert) = next.api_revert.as_mut() {
        revert.body_file = None;
    }
    next.revert_detail = (detail != "rollback completed").then(|| detail.to_string());
    persist_provisional_transition(server, current, next)
        .await
        .unwrap_or(false)
}

pub(super) async fn persist_terminal_provisional_with_body_cleanup(
    server: &ServerContext,
    expected: Provisional,
    mut next: Provisional,
) -> Result<bool, String> {
    if !next.status.is_lifecycle_final() {
        return Err("rollback-body cleanup requires a terminal provisional".to_string());
    }
    mark_revert_body_cleanup_pending(&mut next);
    if !persist_provisional_transition(server, expected, next.clone()).await? {
        return Ok(false);
    }
    let _ = converge_terminal_revert_body_cleanup(server, &next).await;
    Ok(true)
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
                    #[cfg(test)]
                    signal_approval_lifecycle(&server, true);
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
/// machinery. Holds a clone of the server context (which shares the provisional
/// registry and state store), and a directory for stored HTTP revert bodies.
/// The proxy acts as the daemon principal, so the operator manages
/// proxy-armed provisionals with the same
/// `guard confirm` / `guard provisionals` / `guard revert` commands.
#[derive(Clone)]
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
        let requester_principal = api_session_requester_principal(
            &self.server,
            mutation.session_fingerprint.as_deref(),
            mutation.session_revision.as_deref(),
        )
        .await;

        let revert_body = mutation.revert.body.clone();
        let body_file = if revert_body.is_some() {
            if !self.snapshot_dir_safe {
                tracing::error!(
                    "api-proxy: refusing to stage a body-bearing revert because the revert directory is not owner-only; the mutation will not be forwarded without containment"
                );
                return None;
            }
            Some(self.snapshot_dir.join(format!("api-revert-{handle}.body")))
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
            requires_uid_precondition: mutation.revert_requires_uid_precondition,
            resource_uid: None,
            create_provenance: mutation.create_provenance,
            body_file,
        };

        let provisional = Provisional {
            handle: handle.clone(),
            principal,
            requester_principal,
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
            deadline_unix: 0,
            window_secs: 0,
            auto_reverted_unix: None,
            forward_done: false,
            forward_exit: None,
            forward_persistence_failed: false,
            status: ProvisionalStatus::Staged,
            revert_exit: None,
            revert_detail: None,
            api_revert: Some(api_revert),
        };
        let server = self.server.clone();
        #[cfg(test)]
        let endpoint = self.endpoint.clone();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let transition_gate = server.provisional_transition_gate(&provisional.handle);
            let transition = transition_gate.lock().await;
            let body_path = provisional
                .api_revert
                .as_ref()
                .and_then(|api| api.body_file.as_ref());
            let mut durable_owner = provisional.clone();
            if body_path.is_some() {
                durable_owner.revert_detail = Some(
                    "pre-dispatch revert body preparation is pending durable cleanup".to_string(),
                );
            }
            if let Err(error) = try_persist_provisional(&server, &durable_owner).await {
                tracing::error!("api-proxy auto-revert was not staged: {error}");
                let _ = ready_tx.send(None);
                return;
            }
            server
                .state
                .provisional
                .write()
                .await
                .insert(durable_owner.clone());
            if let (Some(path), Some(body)) = (body_path, revert_body.as_deref()) {
                // The snapshot can carry secret material, so creation and all
                // later publication remain owned by this detached operation.
                if let Err(error) = write_owner_only(path, body).await {
                    tracing::error!(
                        "api-proxy: failed to write revert body {}: {}",
                        path.display(),
                        error
                    );
                    let _ = retire_failed_body_staging_locked(&server, &durable_owner).await;
                    let _ = ready_tx.send(None);
                    return;
                }
                #[cfg(test)]
                pause_api_containment(&endpoint, "body_written").await;
                let Some(store) = &server.state.session_store else {
                    let _ = retire_failed_body_staging_locked(&server, &durable_owner).await;
                    let _ = ready_tx.send(None);
                    return;
                };
                if let Err(error) = store
                    .compare_and_swap_provisional(durable_owner.clone(), provisional.clone())
                    .await
                {
                    tracing::error!("api-proxy revert body ownership was not finalized: {error}");
                    let _ = retire_failed_body_staging_locked(&server, &durable_owner).await;
                    let _ = ready_tx.send(None);
                    return;
                }
                let mut registry = server.state.provisional.write().await;
                if registry.get(&provisional.handle) != Some(&durable_owner) {
                    drop(registry);
                    let _ = retire_failed_body_staging_locked(&server, &provisional).await;
                    let _ = ready_tx.send(None);
                    return;
                }
                registry.insert(provisional.clone());
            }
            #[cfg(test)]
            pause_api_containment(&endpoint, "published").await;
            let delivered = ready_tx.send(Some(handle.clone())).is_ok();
            drop(transition);
            if !delivered || accepted_rx.await.is_err() {
                let _ = cancel_exact_staged_provisional(&server, &handle).await;
            }
        });
        let handle = ready_rx.await.ok().flatten()?;
        let _ = accepted_tx.send(());
        Some(handle)
    }

    async fn mark_revert_dispatching(&self, handle: &str) -> bool {
        let server = self.server.clone();
        let handle = handle.to_string();
        tokio::spawn(async move {
            let expected = {
                let registry = server.state.provisional.read().await;
                let Some(expected) = registry.get(&handle).cloned() else {
                    return false;
                };
                if expected.status == ProvisionalStatus::Dispatching && !expected.forward_done {
                    return true;
                }
                if expected.status != ProvisionalStatus::Staged || expected.forward_done {
                    return false;
                }
                expected
            };
            let mut next = expected.clone();
            next.status = ProvisionalStatus::Dispatching;
            match persist_provisional_transition(&server, expected, next).await {
                Ok(published) => published,
                Err(error) => {
                    tracing::error!("api-proxy dispatch marker was not persisted: {error}");
                    false
                }
            }
        })
        .await
        .unwrap_or(false)
    }

    async fn mark_revert_forwarded(&self, handle: &str, resource_uid: Option<&str>) -> bool {
        let server = self.server.clone();
        #[cfg(test)]
        let endpoint = self.endpoint.clone();
        let handle = handle.to_string();
        let resource_uid = resource_uid.map(str::to_string);
        let window_secs = self.window_secs;
        let task = tokio::spawn(async move {
            let transition_gate = server.provisional_transition_gate(&handle);
            let _transition = transition_gate.lock().await;
            let Some(expected) = server.state.provisional.read().await.get(&handle).cloned() else {
                return false;
            };
            if expected.forward_done && expected.forward_exit == Some(0) {
                return expected.status == ProvisionalStatus::Armed
                    && resource_uid.as_deref()
                        == expected
                            .api_revert
                            .as_ref()
                            .and_then(|api| api.resource_uid.as_deref());
            }
            if expected.forward_done
                || expected.forward_exit.is_some()
                || expected.status != ProvisionalStatus::Dispatching
            {
                return false;
            }
            if let Some(api) = expected.api_revert.as_ref() {
                if api.requires_uid_precondition && resource_uid.is_none() {
                    return false;
                }
            }
            let now = now_unix();
            let mut next = expected.clone();
            next.status = ProvisionalStatus::Armed;
            next.forward_done = true;
            next.forward_exit = Some(0);
            next.forward_persistence_failed = false;
            next.deadline_unix = now.saturating_add(window_secs);
            next.window_secs = window_secs;
            next.revert_detail = None;
            if let Some(api) = next.api_revert.as_mut() {
                api.resource_uid = resource_uid;
            }
            let Some(store) = &server.state.session_store else {
                return false;
            };
            if let Err(error) = store
                .compare_and_swap_provisional(expected.clone(), next.clone())
                .await
            {
                tracing::error!("api-proxy auto-revert activation failed: {error}");
                return false;
            }
            #[cfg(test)]
            pause_api_containment(&endpoint, "activation_committed").await;
            server.state.provisional.write().await.insert(next.clone());
            server.emit_event(NotifyEvent {
                event: "provisional_armed",
                at_unix: now,
                handle: Some(handle),
                session_fingerprint: next.session_fingerprint,
                requester_principal: None,
                reason: Some(next.reason),
                status: Some("armed".to_string()),
                behavior: None,
            });
            #[cfg(test)]
            pause_api_containment(&endpoint, "activation_published").await;
            true
        });
        task.await.unwrap_or(false)
    }

    async fn provisional_deadline(&self, handle: &str) -> Option<u64> {
        let provisional = self
            .server
            .state
            .provisional
            .read()
            .await
            .get(handle)
            .cloned()?;
        (provisional.status == ProvisionalStatus::Armed
            && provisional.forward_done
            && provisional.deadline_unix > 0)
            .then_some(provisional.deadline_unix)
    }

    async fn mark_revert_indeterminate(
        &self,
        handle: &str,
        reason: &str,
        resource_uid: Option<&str>,
    ) -> bool {
        let server = self.server.clone();
        let handle = handle.to_string();
        let reason = guard::redact::redact_output_text(reason);
        let resource_uid = resource_uid.map(str::to_string);
        let task = tokio::spawn(async move {
            let transition_gate = server.provisional_transition_gate(&handle);
            let _transition = transition_gate.lock().await;
            let Some(expected) = server.state.provisional.read().await.get(&handle).cloned() else {
                return false;
            };
            if expected.status == ProvisionalStatus::Armed
                && expected.forward_done
                && expected.forward_exit == Some(0)
            {
                return true;
            }
            if !matches!(
                expected.status,
                ProvisionalStatus::Dispatching | ProvisionalStatus::NeedsOperatorDecision
            ) || (expected.forward_done
                && expected.status != ProvisionalStatus::NeedsOperatorDecision)
                || expected.forward_exit.is_some()
            {
                return false;
            }
            let mut next = expected.clone();
            next.status = ProvisionalStatus::NeedsOperatorDecision;
            next.forward_done = true;
            next.forward_exit = None;
            next.forward_persistence_failed = false;
            next.deadline_unix = 0;
            next.window_secs = 0;
            next.revert_detail = Some(reason);
            if let Some(api) = next.api_revert.as_mut() {
                if resource_uid.is_some() {
                    api.resource_uid = resource_uid;
                }
            }
            let Some(store) = &server.state.session_store else {
                return false;
            };
            let persisted = if expected.forward_persistence_failed {
                store.save_provisional(next.clone()).await
            } else {
                store
                    .compare_and_swap_provisional(expected.clone(), next.clone())
                    .await
            };
            if let Err(error) = persisted {
                tracing::error!("api-proxy uncertain mutation state was not updated: {error}");
                return false;
            }
            server.state.provisional.write().await.insert(next.clone());
            server.emit_event(NotifyEvent {
                event: "provisional_needs_operator_decision",
                at_unix: now_unix(),
                handle: Some(handle),
                session_fingerprint: next.session_fingerprint,
                requester_principal: None,
                reason: next.revert_detail,
                status: Some("needs_operator_decision".to_string()),
                behavior: None,
            });
            true
        });
        task.await.unwrap_or(false)
    }

    async fn mark_revert_rejected(&self, handle: &str, reason: &str) -> bool {
        let Some(expected) = self
            .server
            .state
            .provisional
            .read()
            .await
            .get(handle)
            .cloned()
        else {
            return false;
        };
        if expected.status != ProvisionalStatus::Dispatching || expected.forward_done {
            return false;
        }
        let mut next = expected.clone();
        next.status = ProvisionalStatus::Reverted;
        next.revert_detail = Some(guard::redact::redact_output_text(reason));
        match persist_terminal_provisional_with_body_cleanup(&self.server, expected, next).await {
            Ok(true) => true,
            Ok(false) => false,
            Err(error) => {
                tracing::warn!("api-proxy rejected mutation retirement failed: {error}");
                false
            }
        }
    }

    async fn cancel_staged_revert(&self, handle: &str) -> bool {
        cancel_exact_staged_provisional(&self.server, handle).await
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
        #[cfg(test)]
        signal_approval_lifecycle(&self.server, false);
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

    async fn resolve(&self, handle: &str) -> bool {
        // The created object is already gone by the workload's own action, so the
        // pending create-revert is moot. Confirm it to cancel
        // the timer; the sweeper then never tries to delete an absent object. A
        // missing row is already resolved, while an incompatible live state
        // fails closed.
        let server = self.server.clone();
        #[cfg(test)]
        let endpoint = self.endpoint.clone();
        let handle = handle.to_string();
        tokio::spawn(async move {
            let Some(expected) = server.state.provisional.read().await.get(&handle).cloned() else {
                return true;
            };
            let mut staged = guard::gating::provisional::ProvisionalRegistry::new();
            staged.insert(expected.clone());
            match staged.confirm(&handle) {
                Ok(p) => {
                    #[cfg(test)]
                    pause_api_containment(&endpoint, "resolve_before_persist").await;
                    let Some(store) = &server.state.session_store else {
                        return false;
                    };
                    if let Err(error) = store
                        .compare_and_swap_provisional(expected, p.clone())
                        .await
                    {
                        tracing::warn!(
                            "api-proxy: could not durably resolve auto-revert {}: {}",
                            handle,
                            error
                        );
                        return false;
                    }
                    server.state.provisional.write().await.insert(p.clone());
                    tracing::info!(
                        "api-proxy: resolved auto-revert {} (created object deleted by workload)",
                        handle
                    );
                    server.emit_event(NotifyEvent {
                        event: "decision_made",
                        at_unix: now_unix(),
                        handle: Some(handle),
                        session_fingerprint: p.session_fingerprint.clone(),
                        requester_principal: None,
                        reason: Some("workload removed its contained created object".to_string()),
                        status: Some("confirmed".to_string()),
                        behavior: None,
                    });
                    true
                }
                Err(e) => {
                    tracing::debug!("api-proxy: resolve {} was a no-op: {}", handle, e);
                    false
                }
            }
        })
        .await
        .unwrap_or(false)
    }

    async fn authorize_cleanup(
        &self,
        handle: &str,
        resource_uid: &str,
        create_provenance: &str,
        handoff: &mut dyn guard::proxy::ApiForwardHandoff,
    ) -> Result<(), String> {
        let transition_gate = self.server.provisional_transition_gate(handle);
        let _transition =
            tokio::time::timeout(std::time::Duration::from_secs(5), transition_gate.lock())
                .await
                .map_err(|_| "provisional cleanup authority lock timed out".to_string())?;
        let api = {
            let registry = self.server.state.provisional.read().await;
            let row = registry
                .get(handle)
                .filter(|row| {
                    row.status == ProvisionalStatus::Armed
                        && row.forward_done
                        && row.forward_exit == Some(0)
                })
                .ok_or_else(|| "provisional cleanup authority was revoked".to_string())?;
            row.api_revert
                .clone()
                .filter(|api| {
                    api.resource_uid.as_deref() == Some(resource_uid)
                        && api.create_provenance.as_deref() == Some(create_provenance)
                })
                .ok_or_else(|| "provisional cleanup identity changed".to_string())?
        };
        if !api.requires_uid_precondition {
            return Err("provisional cleanup lacks an exact UID precondition".to_string());
        }
        // This exact row/UID/provenance comparison is the cleanup admission
        // point. Keep the per-handle coordinator through the finite upstream
        // handoff so confirm, revert, and resolution cannot retire this exact
        // cleanup authority before the request is initiated. The lock is
        // handle-scoped and is never held while streaming the response body.
        handoff.forward().await
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

fn held_containment_guidance(
    reversibility: Option<Reversibility>,
    risk: Option<i32>,
    revert_preauthorized: bool,
    has_revert: bool,
    confirm_within_secs: Option<u64>,
) -> Option<String> {
    if decide_gate(reversibility, risk, true, false) != GateOutcome::Contain {
        return None;
    }
    let window = confirm_within_secs.unwrap_or(DEFAULT_CONFIRM_WITHIN_SECS);
    if revert_preauthorized && has_revert {
        Some(format!(
            "contain: re-run with --confirm-within {window} to execute under auto-revert"
        ))
    } else {
        Some(format!(
            "contain: re-run with --revert '<cmd>' --confirm-within {window} to execute under auto-revert"
        ))
    }
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
    let command_authority = Some(CommandAuthorization::routed(
        inputs.verb.as_ref(),
        inputs.authority.as_ref(),
    ));
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
            let containment_guidance = held_containment_guidance(
                inputs.reversibility,
                inputs.risk,
                inputs.revert_preauthorized,
                request.revert.is_some(),
                request.confirm_within_secs,
            );
            hold_for_approval_with_trace(context, request, caller_principal, inputs, decision_trace)
                .await
                .with_verb_resolution(Vec::new(), containment_guidance)
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
        requester_principal: None,
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
                let mut staged = ProvisionalRegistry::new();
                staged.insert(provisional.clone());
                staged.mark_forward_done(&handle, exit_code, finished_unix, window)
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
            if !persist_provisional_transition(server, provisional.clone(), updated.clone())
                .await
                .unwrap_or(false)
            {
                let mut recovery = provisional.clone();
                recovery.status = ProvisionalStatus::NeedsOperatorDecision;
                recovery.forward_done = true;
                recovery.forward_exit = exit_code;
                recovery.deadline_unix = 0;
                recovery.window_secs = 0;
                recovery.revert_detail = Some(
                    "forward command completed but its final containment outcome requires durable recovery"
                        .to_string(),
                );
                let recovery_committed =
                    persist_provisional_transition(server, provisional.clone(), recovery)
                        .await
                        .unwrap_or(false);
                tracing::error!(
                    "post-forward provisional outcome did not reach its primary durable transition"
                );
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
                        recovery_committed.then_some(handle),
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
                let mut staged = ProvisionalRegistry::new();
                staged.insert(provisional.clone());
                staged.mark_forward_interrupted(&handle, detail.clone())
            };
            let (response_reason, recovery_handle, outcome) = match updated {
                Some(updated) => match persist_provisional_transition(
                    server,
                    provisional.clone(),
                    updated,
                )
                .await
                {
                    Ok(true) => (
                        "forward command ended without an exit code; auto-revert was not armed; operator decision required",
                        Some(handle.clone()),
                        ContainmentOutcome::ForwardNoExitCode,
                    ),
                    Ok(false) | Err(_) => {
                        let mut recovery = provisional.clone();
                        recovery.status = ProvisionalStatus::NeedsOperatorDecision;
                        recovery.forward_done = true;
                        recovery.forward_exit = None;
                        recovery.deadline_unix = 0;
                        recovery.window_secs = 0;
                        recovery.revert_detail = Some(detail.clone());
                        let durable_recovery = persist_provisional_transition(
                            server,
                            provisional.clone(),
                            recovery,
                        )
                        .await
                        .unwrap_or(false);
                        tracing::warn!(
                            "interrupted forward outcome did not reach its primary durable transition"
                        );
                        (
                            "forward command ended without an exit code, and its interrupted state was not recorded durably; operator decision required",
                            durable_recovery.then(|| handle.clone()),
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

    let tool_secret_sources = match resolve_current_tool_env(
        server,
        &request.binary,
        caller_principal.as_ref(),
        caller.user_key().as_deref(),
    )
    .await
    {
        Ok(resolved) => resolved.into_resolved().secret_sources,
        Err(error) => {
            return ExecuteResult::exec_failed(
                reason,
                format!("approval hold rejected: tool secret resolution failed: {error}"),
            )
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
    #[cfg(test)]
    signal_approval_lifecycle(server, false);
    server.emit_audit_ungated(
        AuditEvent::new(AuditKind::Held)
            .handle(&handle)
            .caller(caller)
            .session_fingerprint(audit_session_fingerprint(request.session_token.as_deref()))
            .cmd(server.redact_command_line(&request.binary, &request.args))
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
            Some(super::admin::approval_guidance(
                server, caller, &handle, true,
            )),
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
                Some(super::admin::approval_guidance(
                    server, caller, handle, true,
                )),
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

    let current_tool_sources = match resolve_current_tool_env(
        server,
        &snapshot.binary,
        snapshot.principal.as_ref(),
        caller.user_key().as_deref(),
    )
    .await
    {
        Ok(resolved) => resolved.into_resolved().secret_sources,
        Err(error) => {
            return ExecuteResult::exec_failed(
                reason.to_string(),
                format!("approval rejected: failed to re-resolve tool secrets: {error}"),
            )
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
    let session_authority =
        snapshot
            .session_revision
            .as_ref()
            .map(|revision| SessionAuthoritySnapshot {
                revision: revision.clone(),
                secret_entitlements: snapshot.secret_entitlements.clone(),
            });
    exec_after_approval_with_command_authority(
        &mut context,
        request,
        reason.to_string(),
        Some(snapshot.secret_entitlements.clone()),
        Some(CommandAuthorization::replay(
            verb_authority,
            session_authority,
        )),
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

        // Staging is inert and hidden, but a failed request-side cleanup must
        // not occupy admission capacity forever. Retry only exact Staged rows;
        // a concurrent dispatch CAS makes cancellation fail closed.
        let stale_staged = server
            .state
            .provisional
            .read()
            .await
            .staged_cleanup_due_handles(now, STAGED_CLEANUP_RETRY_SECS);
        for handle in stale_staged {
            if !cancel_exact_staged_provisional(&server, &handle).await {
                tracing::warn!("staged API containment cleanup remains pending");
            }
        }

        let terminal_body_cleanup = server
            .state
            .provisional
            .read()
            .await
            .list()
            .into_iter()
            .filter(|row| {
                row.status.is_lifecycle_final()
                    && row
                        .revert_detail
                        .as_deref()
                        .is_some_and(|detail| detail.starts_with(REVERT_BODY_CLEANUP_PREFIX))
            })
            .collect::<Vec<_>>();
        for row in terminal_body_cleanup {
            if !converge_terminal_revert_body_cleanup(&server, &row).await {
                tracing::warn!("terminal rollback-body cleanup remains pending");
            }
        }

        let stale_dispatches = server
            .state
            .provisional
            .read()
            .await
            .dispatch_classification_due_handles(now, DISPATCH_CLASSIFICATION_RETRY_SECS);
        for handle in stale_dispatches {
            let Some(expected) = server.state.provisional.read().await.get(&handle).cloned() else {
                continue;
            };
            if expected.status != ProvisionalStatus::Dispatching || expected.forward_done {
                continue;
            }
            let mut next = expected.clone();
            next.status = ProvisionalStatus::NeedsOperatorDecision;
            next.forward_done = true;
            next.forward_exit = None;
            next.deadline_unix = 0;
            next.window_secs = 0;
            next.revert_detail = Some(
                "upstream mutation dispatch completed without a durable outcome classification"
                    .to_string(),
            );
            if let Err(error) = persist_provisional_transition(&server, expected, next).await {
                tracing::warn!("mutation containment classification retry failed: {error}");
            }
        }

        let failed_classifications = server
            .state
            .provisional
            .read()
            .await
            .list()
            .into_iter()
            .filter(|row| row.forward_persistence_failed)
            .collect::<Vec<_>>();
        for row in failed_classifications {
            if !converge_forward_persistence_failure(&server, &row).await {
                tracing::warn!("mutation containment classification remains pending");
            }
        }

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
            let Some(expected) = server.state.provisional.read().await.get(&handle).cloned() else {
                continue;
            };
            let mut staged = guard::gating::provisional::ProvisionalRegistry::new();
            staged.insert(expected.clone());
            let Ok(claimed) = staged.begin_revert(&handle) else {
                continue;
            };
            match persist_provisional_transition(&server, expected, claimed.clone()).await {
                Ok(true) => {}
                Ok(false) => continue,
                Err(error) => {
                    tracing::warn!("failed to persist due rollback claim {}: {}", handle, error);
                    continue;
                }
            }
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
        let expected = server
            .state
            .provisional
            .read()
            .await
            .get(&p.handle)
            .cloned();
        let confirmed = expected.as_ref().and_then(|expected| {
            let mut staged = guard::gating::provisional::ProvisionalRegistry::new();
            staged.insert(expected.clone());
            staged.confirm_after_check(&p.handle).ok()
        });
        match (expected, confirmed) {
            (Some(expected), Some(row)) => {
                match persist_terminal_provisional_with_body_cleanup(server, expected, row.clone())
                    .await
                {
                    Ok(true) => {
                        forget_proxy_provenance(server, &p.handle).await;
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
                    Ok(false) => tracing::warn!(
                        "confirmation check succeeded but provisional {} changed before publication",
                        p.handle
                    ),
                    Err(error) => tracing::warn!(
                        "confirmation check succeeded but provisional {} could not become durable: {}",
                        p.handle,
                        error
                    ),
                }
            }
            _ => {
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
    let mut body = if let Some(path) = &api.body_file {
        Some(tokio::fs::read(path).await.map_err(|e| {
            RevertError::Failed(format!("read api revert body {}: {e}", path.display()))
        })?)
    } else {
        None
    };
    if api.requires_uid_precondition {
        let uid = api.resource_uid.as_deref().ok_or_else(|| {
            RevertError::Retryable(
                "created resource identity is not verified; rollback remains disabled".to_string(),
            )
        })?;
        if uid.is_empty() || uid.len() > 256 || uid.chars().any(char::is_control) {
            return Err(RevertError::Retryable(
                "created resource identity is invalid; rollback remains disabled".to_string(),
            ));
        }
        body = Some(
            bind_created_resource_precondition(body.take(), uid).map_err(RevertError::Failed)?,
        );
    }
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

fn bind_created_resource_precondition(body: Option<Vec<u8>>, uid: &str) -> Result<Vec<u8>, String> {
    let mut options = match body {
        Some(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes)
            .map_err(|_| "created-resource rollback options are not valid JSON".to_string())?,
        None => serde_json::json!({
            "kind": "DeleteOptions",
            "apiVersion": "v1",
        }),
    };
    let Some(object) = options.as_object_mut() else {
        return Err("created-resource rollback options are not a JSON object".to_string());
    };
    object.insert(
        "preconditions".to_string(),
        serde_json::json!({ "uid": uid }),
    );
    serde_json::to_vec(&options)
        .map_err(|_| "serialize created-resource rollback options".to_string())
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
        let mut reg = ProvisionalRegistry::new();
        reg.insert(p.clone());
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
        let persistence =
            persist_terminal_provisional_with_body_cleanup(server, p.clone(), u.clone()).await;
        let persistence_failure = match persistence {
            Ok(true) => None,
            Ok(false) => Some(
                "live provisional state changed before the terminal transition committed"
                    .to_string(),
            ),
            Err(error) => Some(bounded_persistence_diagnostic(&error)),
        };
        if let Some(diagnostic) = persistence_failure {
            tracing::error!(
                "rollback for provisional {} completed but its terminal state was not durable: {}",
                p.handle,
                diagnostic
            );
            return (
                format!(
                    "provisional {} rollback completed but its terminal state could not be recorded: {}",
                    p.handle, diagnostic
                ),
                exit,
            );
        }
    }
    // The revert is terminal (whether it succeeded or failed); drop any
    // api-proxy provenance tied to it so it cannot outlive its window.
    forget_proxy_provenance(server, &p.handle).await;
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

const MAX_PERSISTENCE_DIAGNOSTIC_CHARS: usize = 512;

fn bounded_persistence_diagnostic(error: &str) -> String {
    let redacted = guard::redact::redact_output_text(error);
    let mut diagnostic = redacted
        .chars()
        .take(MAX_PERSISTENCE_DIAGNOSTIC_CHARS)
        .collect::<String>();
    if redacted.chars().count() > MAX_PERSISTENCE_DIAGNOSTIC_CHARS {
        diagnostic.push('…');
    }
    diagnostic
}

#[cfg(test)]
mod transactional_tests {
    use super::*;
    use guard::gating::provisional::ProvisionalRegistry;

    fn fixture_api_mutation(with_body: bool) -> guard::proxy::ApiMutation {
        guard::proxy::ApiMutation {
            label: "fixture mutation".to_string(),
            revert: guard::proxy::HttpRevert {
                method: "DELETE".to_string(),
                path: "/fixture".to_string(),
                body: with_body.then(|| b"{}".to_vec()),
            },
            revert_requires_uid_precondition: false,
            create_provenance: None,
            session_fingerprint: None,
            session_revision: None,
            secret_entitlements: None,
            upstream_target: "https://fixture.invalid".to_string(),
            upstream_identity: "fixture-identity".to_string(),
        }
    }

    #[test]
    fn held_recoverable_commands_name_the_available_containment_route() {
        assert_eq!(
            held_containment_guidance(
                Some(Reversibility::Recoverable),
                Some(4),
                false,
                false,
                Some(120),
            ),
            Some(
                "contain: re-run with --revert '<cmd>' --confirm-within 120 to execute under auto-revert"
                    .to_string()
            )
        );
        assert_eq!(
            held_containment_guidance(Some(Reversibility::Recoverable), Some(4), true, true, None,),
            Some(
                "contain: re-run with --confirm-within 300 to execute under auto-revert"
                    .to_string()
            )
        );
    }

    #[test]
    fn held_irreversible_or_high_risk_commands_do_not_promise_containment() {
        assert_eq!(
            held_containment_guidance(
                Some(Reversibility::Irreversible),
                Some(4),
                false,
                false,
                None,
            ),
            None
        );
        assert_eq!(
            held_containment_guidance(Some(Reversibility::Recoverable), Some(9), true, true, None,),
            None
        );
    }

    fn api_session(owner: PrincipalKey) -> crate::session::SessionGrant {
        crate::session::SessionGrant {
            allow: Vec::new(),
            deny: Vec::new(),
            allow_exact: Vec::new(),
            deny_exact: Vec::new(),
            activated_verbs: Vec::new(),
            override_markers: Vec::new(),
            scope: Default::default(),
            expires_at: None,
            prompt_append: None,
            generated_notes: Vec::new(),
            static_only: false,
            auto_amend: false,
            granted_at: 0,
            owner: crate::session::SessionOwner::Principal(owner),
        }
    }

    #[tokio::test]
    async fn api_revert_persists_session_owner_without_changing_daemon_identity() {
        let mut server = crate::server::tests::config_for_proposal_test();
        let state = tempfile::tempdir().unwrap();
        let store = crate::session_store::SessionStore::open(state.path().join("state.db"), 3600)
            .await
            .unwrap();
        server.state.session_store = Some(store.clone());
        let owner = PrincipalKey::from_uid(4242);
        let token = "session-attribution";
        assert!(server
            .state
            .sessions
            .write()
            .await
            .grant(token.to_string(), api_session(owner.clone())));
        let (session_fingerprint, session_revision) = {
            let sessions = server.state.sessions.read().await;
            let (fingerprint, _) = sessions.api_authority_for(token).unwrap();
            let (revision, _) = sessions.authority_snapshot(token).unwrap();
            (fingerprint, revision)
        };
        let sink = DaemonGateSink {
            server: server.clone(),
            endpoint: "fixture-endpoint".to_string(),
            protocol: "fixture-protocol".to_string(),
            snapshot_dir: state.path().to_path_buf(),
            snapshot_dir_safe: true,
            window_secs: 60,
        };
        let mut mutation = fixture_api_mutation(false);
        mutation.session_fingerprint = Some(session_fingerprint.clone());
        mutation.session_revision = Some(session_revision);

        let handle = guard::proxy::GateSink::arm_revert(&sink, mutation)
            .await
            .unwrap();
        let staged = server
            .state
            .provisional
            .read()
            .await
            .get(&handle)
            .cloned()
            .unwrap();
        assert_eq!(
            staged.principal,
            Some(server.config.daemon_principal.clone())
        );
        assert_eq!(staged.requester_principal, Some(owner.clone()));
        assert_eq!(staged.session_fingerprint, Some(session_fingerprint));

        assert!(guard::proxy::GateSink::mark_revert_dispatching(&sink, &handle).await);
        assert!(guard::proxy::GateSink::mark_revert_forwarded(&sink, &handle, None).await);
        let armed = server
            .state
            .provisional
            .read()
            .await
            .get(&handle)
            .cloned()
            .unwrap();
        assert_eq!(
            guard::proxy::GateSink::provisional_deadline(&sink, &handle).await,
            Some(armed.deadline_unix)
        );

        let persisted = store
            .load_provisionals()
            .await
            .unwrap()
            .into_iter()
            .find(|row| row.handle == handle)
            .unwrap();
        assert_eq!(persisted.principal, Some(server.config.daemon_principal));
        assert_eq!(persisted.requester_principal, Some(owner));
        assert_eq!(persisted.session_fingerprint, armed.session_fingerprint);
    }

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
                revert_requires_uid_precondition: false,
                create_provenance: None,
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

    #[tokio::test]
    async fn api_revert_activation_failure_keeps_durable_operator_authority() {
        let mut server = crate::server::tests::config_for_proposal_test();
        let state = tempfile::tempdir().unwrap();
        let store = crate::session_store::SessionStore::open(state.path().join("state.db"), 3600)
            .await
            .unwrap();
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
                revert_requires_uid_precondition: false,
                create_provenance: None,
                session_fingerprint: None,
                session_revision: None,
                secret_entitlements: None,
                upstream_target: "https://fixture.invalid".to_string(),
                upstream_identity: "fixture-identity".to_string(),
            },
        )
        .await
        .unwrap();
        assert!(guard::proxy::GateSink::mark_revert_dispatching(&sink, &handle).await);
        store.fail_next_write_for_test();
        assert!(!guard::proxy::GateSink::mark_revert_forwarded(&sink, &handle, None).await);
        let live_after_failure = server
            .state
            .provisional
            .read()
            .await
            .get(&handle)
            .cloned()
            .unwrap();
        assert_eq!(live_after_failure.status, ProvisionalStatus::Dispatching);
        assert!(!live_after_failure.forward_persistence_failed);
        assert_eq!(
            store
                .load_provisionals()
                .await
                .unwrap()
                .into_iter()
                .find(|row| row.handle == handle)
                .unwrap()
                .status,
            ProvisionalStatus::Dispatching
        );
        store.fail_next_write_for_test();
        assert!(
            !guard::proxy::GateSink::mark_revert_indeterminate(
                &sink,
                &handle,
                "upstream handoff outcome is uncertain",
                None,
            )
            .await
        );
        let still_live = server
            .state
            .provisional
            .read()
            .await
            .get(&handle)
            .cloned()
            .unwrap();
        assert_eq!(still_live.status, ProvisionalStatus::Dispatching);
        assert!(!still_live.forward_persistence_failed);
        assert_eq!(
            store
                .load_provisionals()
                .await
                .unwrap()
                .into_iter()
                .find(|row| row.handle == handle)
                .unwrap()
                .status,
            ProvisionalStatus::Dispatching
        );
        assert!(
            guard::proxy::GateSink::mark_revert_indeterminate(
                &sink,
                &handle,
                "upstream handoff outcome is uncertain",
                None,
            )
            .await
        );

        let live = server
            .state
            .provisional
            .read()
            .await
            .get(&handle)
            .cloned()
            .unwrap();
        assert!(live.forward_done);
        assert_eq!(live.forward_exit, None);
        assert_eq!(live.status, ProvisionalStatus::NeedsOperatorDecision);
        let durable = store
            .load_provisionals()
            .await
            .unwrap()
            .into_iter()
            .find(|row| row.handle == handle)
            .unwrap();
        assert_eq!(durable.status, ProvisionalStatus::NeedsOperatorDecision);
        assert_eq!(durable.forward_exit, None);
        let mut registry = ProvisionalRegistry::new();
        registry.insert(durable);
        assert!(registry.begin_revert(&handle).is_ok());
    }

    #[tokio::test]
    async fn cleanup_resolution_persistence_does_not_hold_the_live_registry_writer() {
        let mut server = crate::server::tests::config_for_proposal_test();
        let state = tempfile::tempdir().unwrap();
        let store = crate::session_store::SessionStore::open(state.path().join("state.db"), 3600)
            .await
            .unwrap();
        server.state.session_store = Some(store);
        let endpoint = "fixture-resolve".to_string();
        let sink = DaemonGateSink {
            server: server.clone(),
            endpoint: endpoint.clone(),
            protocol: "fixture-protocol".to_string(),
            snapshot_dir: state.path().to_path_buf(),
            snapshot_dir_safe: true,
            window_secs: 60,
        };
        let handle = guard::proxy::GateSink::arm_revert(&sink, fixture_api_mutation(false))
            .await
            .unwrap();
        assert!(guard::proxy::GateSink::mark_revert_dispatching(&sink, &handle).await);
        assert!(guard::proxy::GateSink::mark_revert_forwarded(&sink, &handle, None).await);

        let (reached, release) = install_api_containment_hook(&endpoint, "resolve_before_persist");
        let resolving = tokio::spawn({
            let sink = sink.clone();
            let handle = handle.clone();
            async move { guard::proxy::GateSink::resolve(&sink, &handle).await }
        });
        reached.acquire().await.unwrap().forget();
        let unrelated_writer = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            server.state.provisional.write(),
        )
        .await
        .expect("durable cleanup resolution must not retain the live registry writer");
        drop(unrelated_writer);
        release.add_permits(1);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(2), resolving)
                .await
                .expect("cleanup resolution completes after persistence resumes")
                .unwrap()
        );
    }

    #[tokio::test]
    async fn provisional_transition_releases_live_registry_and_rejects_stale_publication() {
        let mut server = crate::server::tests::config_for_proposal_test();
        let state = tempfile::tempdir().unwrap();
        let store = crate::session_store::SessionStore::open(state.path().join("state.db"), 3600)
            .await
            .unwrap();
        server.state.session_store = Some(store);
        let endpoint = "fixture-transition";
        let sink = DaemonGateSink {
            server: server.clone(),
            endpoint: endpoint.to_string(),
            protocol: "fixture-protocol".to_string(),
            snapshot_dir: state.path().to_path_buf(),
            snapshot_dir_safe: true,
            window_secs: 60,
        };
        let handle = guard::proxy::GateSink::arm_revert(&sink, fixture_api_mutation(false))
            .await
            .unwrap();
        assert!(guard::proxy::GateSink::mark_revert_dispatching(&sink, &handle).await);
        assert!(guard::proxy::GateSink::mark_revert_forwarded(&sink, &handle, None).await);
        let expected = server
            .state
            .provisional
            .read()
            .await
            .get(&handle)
            .cloned()
            .unwrap();
        let mut staged = ProvisionalRegistry::new();
        staged.insert(expected.clone());
        let next = staged.confirm(&handle).unwrap();
        let (reached, release) =
            install_api_containment_hook(endpoint, "provisional_transition_before_persist");
        let transition = tokio::spawn({
            let server = server.clone();
            let expected = expected.clone();
            async move { persist_provisional_transition(&server, expected, next).await }
        });
        reached.acquire().await.unwrap().forget();

        let mut live = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            server.state.provisional.write(),
        )
        .await
        .expect("durable transition must not retain the live registry writer");
        let mut newer = expected.clone();
        newer.revert_detail = Some("newer live classification".to_string());
        live.insert(newer.clone());
        drop(live);

        release.add_permits(1);
        assert!(!transition.await.unwrap().unwrap());
        assert_eq!(
            server.state.provisional.read().await.get(&handle).cloned(),
            Some(newer)
        );
    }

    #[tokio::test]
    async fn staged_cancel_cannot_cross_a_committed_dispatch_transition() {
        let mut server = crate::server::tests::config_for_proposal_test();
        let state = tempfile::tempdir().unwrap();
        let store = crate::session_store::SessionStore::open(state.path().join("state.db"), 3600)
            .await
            .unwrap();
        server.state.session_store = Some(store.clone());
        let endpoint = "fixture-dispatch-cancel";
        let sink = DaemonGateSink {
            server: server.clone(),
            endpoint: endpoint.to_string(),
            protocol: "fixture-protocol".to_string(),
            snapshot_dir: state.path().to_path_buf(),
            snapshot_dir_safe: true,
            window_secs: 60,
        };
        let handle = guard::proxy::GateSink::arm_revert(&sink, fixture_api_mutation(false))
            .await
            .unwrap();
        let (committed, publish) =
            install_api_containment_hook(endpoint, "provisional_transition_committed");
        let dispatch = tokio::spawn({
            let sink = sink.clone();
            let handle = handle.clone();
            async move { guard::proxy::GateSink::mark_revert_dispatching(&sink, &handle).await }
        });
        committed.acquire().await.unwrap().forget();

        let (cancel_started, cancel_entered) = tokio::sync::oneshot::channel();
        let cancel = tokio::spawn({
            let sink = sink.clone();
            let handle = handle.clone();
            async move {
                let _ = cancel_started.send(());
                guard::proxy::GateSink::cancel_staged_revert(&sink, &handle).await
            }
        });
        cancel_entered.await.unwrap();
        assert!(server
            .provisional_transition_gate(&handle)
            .try_lock()
            .is_err());

        publish.add_permits(1);
        assert!(dispatch.await.unwrap());
        assert!(!cancel.await.unwrap());
        assert_eq!(
            server
                .state
                .provisional
                .read()
                .await
                .get(&handle)
                .unwrap()
                .status,
            ProvisionalStatus::Dispatching
        );
        assert_eq!(
            store
                .load_provisionals()
                .await
                .unwrap()
                .into_iter()
                .find(|row| row.handle == handle)
                .unwrap()
                .status,
            ProvisionalStatus::Dispatching
        );
    }

    #[tokio::test]
    async fn durable_transition_for_one_handle_does_not_serialize_an_unrelated_handle() {
        let mut server = crate::server::tests::config_for_proposal_test();
        let state = tempfile::tempdir().unwrap();
        server.state.session_store = Some(
            crate::session_store::SessionStore::open(state.path().join("state.db"), 3600)
                .await
                .unwrap(),
        );
        let endpoint = "fixture-per-handle-transition";
        let sink = DaemonGateSink {
            server: server.clone(),
            endpoint: endpoint.to_string(),
            protocol: "fixture-protocol".to_string(),
            snapshot_dir: state.path().to_path_buf(),
            snapshot_dir_safe: true,
            window_secs: 60,
        };
        let first = guard::proxy::GateSink::arm_revert(&sink, fixture_api_mutation(false))
            .await
            .unwrap();
        let second = guard::proxy::GateSink::arm_revert(&sink, fixture_api_mutation(false))
            .await
            .unwrap();
        let (committed, release) =
            install_api_containment_hook(endpoint, "provisional_transition_committed");
        let paused = tokio::spawn({
            let sink = sink.clone();
            async move { guard::proxy::GateSink::mark_revert_dispatching(&sink, &first).await }
        });
        committed.acquire().await.unwrap().forget();

        assert!(tokio::time::timeout(
            std::time::Duration::from_secs(5),
            guard::proxy::GateSink::mark_revert_dispatching(&sink, &second),
        )
        .await
        .expect("unrelated transition must not wait for the paused handle"));

        release.add_permits(1);
        assert!(paused.await.unwrap());
    }

    #[tokio::test]
    async fn failed_staged_cleanup_is_visible_and_retryable() {
        let mut server = crate::server::tests::config_for_proposal_test();
        let state = tempfile::tempdir().unwrap();
        let store = crate::session_store::SessionStore::open(state.path().join("state.db"), 3600)
            .await
            .unwrap();
        server.state.session_store = Some(store.clone());
        let sink = DaemonGateSink {
            server: server.clone(),
            endpoint: "fixture-cleanup-retry".to_string(),
            protocol: "fixture-protocol".to_string(),
            snapshot_dir: state.path().to_path_buf(),
            snapshot_dir_safe: true,
            window_secs: 60,
        };
        let handle = guard::proxy::GateSink::arm_revert(&sink, fixture_api_mutation(false))
            .await
            .unwrap();

        store.fail_next_provisional_delete_for_test();
        assert!(!guard::proxy::GateSink::cancel_staged_revert(&sink, &handle).await);
        let visible = server.state.provisional.read().await.visible_list();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].forward_outcome(), "cleanup_pending");
        assert_eq!(store.load_provisionals().await.unwrap(), visible);

        assert!(guard::proxy::GateSink::cancel_staged_revert(&sink, &handle).await);
        assert!(server.state.provisional.read().await.list().is_empty());
        assert!(store.load_provisionals().await.unwrap().is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn revert_body_deletion_failure_retains_a_visible_cleanup_owner() {
        let mut server = crate::server::tests::config_for_proposal_test();
        let state = tempfile::tempdir().unwrap();
        let store = crate::session_store::SessionStore::open(state.path().join("state.db"), 3600)
            .await
            .unwrap();
        server.state.session_store = Some(store.clone());
        let sink = DaemonGateSink {
            server: server.clone(),
            endpoint: "fixture-body-cleanup-retry".to_string(),
            protocol: "fixture-protocol".to_string(),
            snapshot_dir: state.path().to_path_buf(),
            snapshot_dir_safe: true,
            window_secs: 60,
        };
        let handle = guard::proxy::GateSink::arm_revert(&sink, fixture_api_mutation(true))
            .await
            .unwrap();
        let body = server
            .state
            .provisional
            .read()
            .await
            .get(&handle)
            .and_then(|row| row.api_revert.as_ref())
            .and_then(|revert| revert.body_file.clone())
            .unwrap();
        std::fs::remove_file(&body).unwrap();
        std::fs::create_dir(&body).unwrap();

        assert!(!guard::proxy::GateSink::cancel_staged_revert(&sink, &handle).await);
        let durable = store.load_provisionals().await.unwrap();
        assert_eq!(durable.len(), 1);
        assert_eq!(durable[0].forward_outcome(), "cleanup_pending");

        std::fs::remove_dir(&body).unwrap();
        assert!(guard::proxy::GateSink::cancel_staged_revert(&sink, &handle).await);
        assert!(store.load_provisionals().await.unwrap().is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn terminal_revert_body_cleanup_failure_is_durable_and_retryable() {
        let mut server = crate::server::tests::config_for_proposal_test();
        let state = tempfile::tempdir().unwrap();
        let store = crate::session_store::SessionStore::open(state.path().join("state.db"), 3600)
            .await
            .unwrap();
        server.state.session_store = Some(store.clone());
        let sink = DaemonGateSink {
            server: server.clone(),
            endpoint: "fixture-terminal-body-cleanup".to_string(),
            protocol: "fixture-protocol".to_string(),
            snapshot_dir: state.path().to_path_buf(),
            snapshot_dir_safe: true,
            window_secs: 60,
        };
        let handle = guard::proxy::GateSink::arm_revert(&sink, fixture_api_mutation(true))
            .await
            .unwrap();
        assert!(guard::proxy::GateSink::mark_revert_dispatching(&sink, &handle).await);
        assert!(guard::proxy::GateSink::mark_revert_forwarded(&sink, &handle, None).await);
        let expected = server
            .state
            .provisional
            .read()
            .await
            .get(&handle)
            .cloned()
            .unwrap();
        let body = expected
            .api_revert
            .as_ref()
            .and_then(|revert| revert.body_file.clone())
            .unwrap();
        std::fs::remove_file(&body).unwrap();
        std::fs::create_dir(&body).unwrap();
        let mut staged = ProvisionalRegistry::new();
        staged.insert(expected.clone());
        let confirmed = staged.confirm(&handle).unwrap();

        assert!(
            persist_terminal_provisional_with_body_cleanup(&server, expected, confirmed,)
                .await
                .unwrap()
        );
        let pending = store.load_provisionals().await.unwrap().remove(0);
        assert_eq!(pending.status, ProvisionalStatus::Confirmed);
        assert!(pending
            .revert_detail
            .as_deref()
            .is_some_and(|detail| detail.starts_with(REVERT_BODY_CLEANUP_PREFIX)));

        std::fs::remove_dir(&body).unwrap();
        assert!(converge_terminal_revert_body_cleanup(&server, &pending).await);
        let cleaned = store.load_provisionals().await.unwrap().remove(0);
        assert!(cleaned
            .api_revert
            .as_ref()
            .is_some_and(|revert| revert.body_file.is_none()));
        assert!(cleaned.revert_detail.is_none());
    }

    #[tokio::test]
    async fn cancelled_api_revert_staging_finishes_cleanup_after_body_and_publication() {
        for phase in ["body_written", "published"] {
            let mut server = crate::server::tests::config_for_proposal_test();
            let state = tempfile::tempdir().unwrap();
            let store = crate::session_store::SessionStore::open(
                state.path().join(format!("{phase}.db")),
                3600,
            )
            .await
            .unwrap();
            server.state.session_store = Some(store.clone());
            let endpoint = format!("fixture-{phase}");
            let sink = DaemonGateSink {
                server: server.clone(),
                endpoint: endpoint.clone(),
                protocol: "fixture-protocol".to_string(),
                snapshot_dir: state.path().to_path_buf(),
                snapshot_dir_safe: true,
                window_secs: 60,
            };
            let (reached, release) = install_api_containment_hook(&endpoint, phase);
            let (cleanup_completed, cleanup_release) =
                install_api_containment_hook(&endpoint, "staging_cleanup_completed");
            let task = tokio::spawn(async move {
                guard::proxy::GateSink::arm_revert(&sink, fixture_api_mutation(true)).await
            });
            reached.acquire().await.unwrap().forget();
            task.abort();
            release.add_permits(1);
            cleanup_completed.acquire().await.unwrap().forget();
            assert!(server.state.provisional.read().await.list().is_empty());
            assert!(store.load_provisionals().await.unwrap().is_empty());
            let body_count = std::fs::read_dir(state.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with("api-revert-")
                })
                .count();
            assert_eq!(body_count, 0);
            cleanup_release.add_permits(1);
        }
    }

    #[tokio::test]
    async fn cancelled_api_revert_activation_finishes_durable_live_publication() {
        let mut server = crate::server::tests::config_for_proposal_test();
        let state = tempfile::tempdir().unwrap();
        let store = crate::session_store::SessionStore::open(state.path().join("state.db"), 3600)
            .await
            .unwrap();
        server.state.session_store = Some(store.clone());
        let endpoint = "fixture-activation";
        let sink = DaemonGateSink {
            server: server.clone(),
            endpoint: endpoint.to_string(),
            protocol: "fixture-protocol".to_string(),
            snapshot_dir: state.path().to_path_buf(),
            snapshot_dir_safe: true,
            window_secs: 60,
        };
        let handle = guard::proxy::GateSink::arm_revert(&sink, fixture_api_mutation(false))
            .await
            .unwrap();
        assert!(
            guard::proxy::GateSink::mark_revert_dispatching(&sink, &handle).await,
            "staged mutation advances to the dispatch boundary"
        );
        let (reached, release) = install_api_containment_hook(endpoint, "activation_committed");
        let (published, published_release) =
            install_api_containment_hook(endpoint, "activation_published");
        let sink_task = sink.clone();
        let handle_task = handle.clone();
        let task = tokio::spawn(async move {
            guard::proxy::GateSink::mark_revert_forwarded(&sink_task, &handle_task, None).await
        });
        reached.acquire().await.unwrap().forget();
        task.abort();
        release.add_permits(1);
        published.acquire().await.unwrap().forget();
        let live = server.state.provisional.read().await.get(&handle).cloned();
        let durable = store
            .load_provisionals()
            .await
            .unwrap()
            .into_iter()
            .find(|row| row.handle == handle);
        assert!(live.is_some_and(|row| row.status == ProvisionalStatus::Armed));
        assert!(durable.is_some_and(|row| row.status == ProvisionalStatus::Armed));
        published_release.add_permits(1);
    }

    #[test]
    fn created_resource_rollback_is_bound_to_the_original_uid() {
        let original_uid = "original-resource-uid";
        let replacement_uid = "replacement-resource-uid";
        let body = bind_created_resource_precondition(
            Some(
                serde_json::to_vec(&serde_json::json!({
                    "kind": "DeleteOptions",
                    "apiVersion": "v1",
                    "propagationPolicy": "Background",
                }))
                .unwrap(),
            ),
            original_uid,
        )
        .unwrap();
        let options: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(options["preconditions"]["uid"].as_str(), Some(original_uid));
        assert_ne!(
            options["preconditions"]["uid"].as_str(),
            Some(replacement_uid)
        );
    }
}
