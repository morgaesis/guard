//! Operator-approval state: irreversible (or uncertain / high-risk) commands
//! held at a point of no return until a human approves the exact artifact.
//!
//! A held command does not execute. It is enqueued with an immutable execution
//! snapshot, and only an operator (daemon UID) can approve it. Approval executes
//! strictly from the stored snapshot — no fields are accepted at approve time —
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
use std::sync::Arc;
use tokio::sync::Notify;

use super::{GateError, Reversibility};
use crate::principal::{scope_eq, PrincipalKey};

/// Optional binding of held secret VALUES to the artifact the operator reviewed.
/// Captured at hold time as salted SHA-256 hashes of each resolved secret value
/// (never the value itself), keyed by the injected env-var name. Verified at
/// approve time: if a mapped value changed since the hold, approval fails closed.
/// This closes the window where a same-principal caller alters its own mapped
/// secret values between hold and approval. `None`/empty means no binding was
/// captured (an older row, or no secret resolved at hold time) and verification
/// is skipped for back-compat. The salt makes a stored hash not a plain value
/// hash, so the snapshot does not leak a brute-forceable digest of the secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash, Default)]
pub struct SecretBinding {
    /// Per-hold random salt (hex).
    pub salt: String,
    /// env-var -> hex SHA-256(salt-bytes, 0x00, value-bytes).
    pub hashes: BTreeMap<String, String>,
}

/// The immutable execution inputs an approval is bound to. Stored at enqueue and
/// replayed verbatim at approve time. Secret *values* are never stored — only the
/// env-var -> secret-key mapping, resolved at exec under the original caller's
/// namespace, plus an optional salted-hash [`SecretBinding`] used to detect a
/// value swap between hold and approval. `BTreeMap` gives a stable order for a
/// stable fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct ApprovalSnapshot {
    pub binary: String,
    pub args: Vec<String>,
    /// Plain per-run env injections.
    pub env: BTreeMap<String, String>,
    /// env-var -> secret-key mapping (keys only; values resolved at exec).
    pub secret_keys: BTreeMap<String, String>,
    /// If this hold originated from a verb, the verb name and the validated
    /// params, plus the catalog version it was rendered against. A catalog
    /// change voids the approval.
    pub verb_name: Option<String>,
    pub verb_params: BTreeMap<String, String>,
    pub catalog_version: Option<u64>,
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
}

impl ApprovalSnapshot {
    pub fn command_line(&self) -> String {
        if self.args.is_empty() {
            self.binary.clone()
        } else {
            format!("{} {}", self.binary, self.args.join(" "))
        }
    }

    /// Short, stable fingerprint shown to the operator so two visually-similar
    /// holds are distinguishable. Not a security boundary — the binding is the
    /// stored snapshot itself, executed verbatim — just an operator aid.
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
    /// TTL elapsed with no decision — a fail-closed denial.
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
}

/// In-memory registry of held commands plus per-handle notifiers for blocking
/// waiters. Notifiers are not persisted (they are process-local wakeups).
#[derive(Default)]
pub struct ApprovalRegistry {
    items: HashMap<String, Approval>,
    notifiers: HashMap<String, Arc<Notify>>,
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
            },
            recovered,
        )
    }

    /// Enqueue a hold and return its notifier so a blocking waiter can await it.
    pub fn enqueue(&mut self, approval: Approval) -> Arc<Notify> {
        let notify = Arc::new(Notify::new());
        self.notifiers
            .insert(approval.handle.clone(), notify.clone());
        self.items.insert(approval.handle.clone(), approval);
        notify
    }

    pub fn get(&self, handle: &str) -> Option<&Approval> {
        self.items.get(handle)
    }

    pub fn notifier(&self, handle: &str) -> Option<Arc<Notify>> {
        self.notifiers.get(handle).cloned()
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
    pub fn begin_approve(&mut self, handle: &str) -> Result<ApprovalSnapshot, GateError> {
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
        }
        self.wake(handle);
    }

    /// Record an approved-but-failed-to-run exec and wake any waiter.
    pub fn set_exec_failed(&mut self, handle: &str, now: u64, detail: String) {
        if let Some(a) = self.items.get_mut(handle) {
            a.status = ApprovalStatus::ExecFailed;
            a.decided_unix = Some(now);
            a.decided_reason = Some(detail);
        }
        self.wake(handle);
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
        let a = self
            .items
            .get_mut(handle)
            .ok_or_else(|| GateError::NotFound(handle.to_string()))?;
        if !a.status.is_pending() {
            return Err(GateError::WrongState {
                handle: handle.to_string(),
                detail: format!("already {}; its thread is closed", a.status.as_str()),
            });
        }
        a.notes.push(ApprovalNote {
            at_unix: now,
            author: author.to_string(),
            text: text.to_string(),
        });
        Ok(())
    }

    /// Operator denies a pending hold and wakes any waiter.
    pub fn deny(&mut self, handle: &str, now: u64, reason: String) -> Result<(), GateError> {
        let a = self
            .items
            .get_mut(handle)
            .ok_or_else(|| GateError::NotFound(handle.to_string()))?;
        if !a.status.is_pending() {
            return Err(GateError::WrongState {
                handle: handle.to_string(),
                detail: format!("already {}", a.status.as_str()),
            });
        }
        a.status = ApprovalStatus::Denied;
        a.decided_unix = Some(now);
        a.decided_reason = Some(reason);
        self.wake(handle);
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
            env: BTreeMap::new(),
            secret_keys: BTreeMap::new(),
            verb_name: None,
            verb_params: BTreeMap::new(),
            catalog_version: None,
            principal: Some(PrincipalKey::from_uid(1001)),
            secret_binding: None,
        }
    }

    fn held(handle: &str, created: u64, ttl: u64) -> Approval {
        Approval {
            handle: handle.to_string(),
            snapshot: snap("rm"),
            reason: "destructive".into(),
            risk: Some(9),
            reversibility: Some(Reversibility::Irreversible),
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
        let snap = r.begin_approve("h1").unwrap();
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
        r.begin_approve("h1").unwrap();
        assert!(matches!(
            r.begin_approve("h1"),
            Err(GateError::WrongState { .. })
        ));
    }

    #[test]
    fn deny_is_terminal() {
        let mut r = ApprovalRegistry::new();
        r.enqueue(held("h1", 100, 3600));
        r.deny("h1", 150, "operator rejected".into()).unwrap();
        assert_eq!(r.get("h1").unwrap().status, ApprovalStatus::Denied);
        assert!(r.begin_approve("h1").is_err());
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
    fn startup_recovery_marks_interrupted_exec_failed() {
        let mut a = held("h1", 100, 3600);
        a.status = ApprovalStatus::Approving;
        let (reg, recovered) = ApprovalRegistry::from_rows(vec![a], 500);
        assert_eq!(recovered, vec!["h1".to_string()]);
        assert_eq!(reg.get("h1").unwrap().status, ApprovalStatus::ExecFailed);
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
        // Spawn a waiter; then decide and ensure it wakes.
        let waiter = tokio::spawn(async move {
            notify.notified().await;
        });
        // Ensure the waiter has parked on notified() before we wake it;
        // notify_waiters() only wakes tasks already awaiting.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        r.deny("h1", 150, "no".into()).unwrap();
        // notify_waiters wakes those currently awaiting; the spawned task should finish.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), waiter)
            .await
            .expect("waiter should have been woken");
    }
}
