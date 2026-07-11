//! Containment-envelope state: provisional (recoverable) executions that
//! auto-revert unless an operator confirms them in time.
//!
//! A `recoverable` command that is approved and accompanied by a usable revert
//! is executed immediately, then held *provisional*: an auto-revert timer is
//! armed. If the operator confirms before the deadline, the change is kept; if
//! not, the daemon runs the revert. This mirrors `netplan try` and the
//! "defensive apply" rollback-timer pattern.
//!
//! This module is the pure state machine: it owns no clock, no process exec, and
//! no I/O. The daemon supplies `now`, runs the forward command and the revert,
//! and feeds the outcomes back. The registry only enforces legal transitions and
//! tells the daemon which provisionals are due.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use super::GateError;
use crate::principal::{scope_eq, PrincipalKey};

/// Lifecycle of a provisional execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvisionalStatus {
    /// Forward command ran; the auto-revert timer is counting down.
    Armed,
    /// The sweeper has claimed this for revert and the revert is in flight.
    /// In-memory transient; if seen on startup it means a revert was
    /// interrupted, so startup recovery routes it to `NeedsOperatorDecision`.
    Reverting,
    /// Operator confirmed; the change is kept and the timer is cancelled.
    Confirmed,
    /// The revert ran successfully; the change was rolled back.
    Reverted,
    /// The revert was attempted but failed; the mutation may still be in place.
    /// Kept queryable so an operator notices.
    RevertFailed,
    /// The daemon restarted while this was armed/reverting. To avoid running a
    /// revert unattended at boot, it waits for an explicit operator decision.
    NeedsOperatorDecision,
}

impl ProvisionalStatus {
    /// Whether this status still occupies an outstanding/“stuck” slot for cap
    /// accounting. Terminal-good (`Confirmed`, `Reverted`) do not; everything
    /// that still needs attention does.
    pub fn is_outstanding(self) -> bool {
        matches!(
            self,
            Self::Armed | Self::Reverting | Self::RevertFailed | Self::NeedsOperatorDecision
        )
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Confirmed | Self::Reverted)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::Reverting => "reverting",
            Self::Confirmed => "confirmed",
            Self::Reverted => "reverted",
            Self::RevertFailed => "revert_failed",
            Self::NeedsOperatorDecision => "needs_operator_decision",
        }
    }
}

/// One provisional execution and its revert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provisional {
    pub handle: String,
    /// Principal of the caller that created this, used to reconstruct the exec
    /// identity for the revert (so under `--exec-as-caller` the revert runs as
    /// the original caller). `None` means the daemon executes as its own
    /// identity. Deserializes from the legacy numeric `caller_uid` form so rows
    /// written by an older daemon survive an upgrade.
    #[serde(
        default,
        alias = "caller_uid",
        deserialize_with = "crate::principal::principal_from_legacy"
    )]
    pub principal: Option<PrincipalKey>,
    pub binary: String,
    pub args: Vec<String>,
    /// The structured revert command (no shell). Operator-authored (verb) or an
    /// agent-supplied `--revert` that was itself evaluated to APPROVE at arm time.
    pub revert_binary: String,
    pub revert_args: Vec<String>,
    /// Structured API revert plan for proxy-originated provisionals. Command
    /// reverts leave this unset and use `revert_binary` / `revert_args`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_revert: Option<ApiRevertPlan>,
    /// Short, caller-facing rationale for the original approval.
    pub reason: String,
    pub created_unix: u64,
    /// Auto-revert fires at or after this wall-clock unix-seconds value.
    pub deadline_unix: u64,
    /// Set once the forward command has actually run. A provisional persisted
    /// before exec with `forward_done=false` that survives a restart is
    /// indeterminate and routes to `NeedsOperatorDecision`.
    pub forward_done: bool,
    pub status: ProvisionalStatus,
    /// Exit code of the revert, once it has run.
    pub revert_exit: Option<i32>,
    /// Human-readable detail for a failed revert (stderr tail or spawn error).
    pub revert_detail: Option<String>,
}

impl Provisional {
    pub fn revert_command_line(&self) -> String {
        if let Some(api) = &self.api_revert {
            return format!("{} {} {}", api.protocol, api.method, api.path);
        }
        if self.revert_args.is_empty() {
            self.revert_binary.clone()
        } else {
            format!("{} {}", self.revert_binary, self.revert_args.join(" "))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiRevertPlan {
    pub protocol: String,
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_file: Option<PathBuf>,
}

/// In-memory registry of provisional executions. Pure: no clock, no I/O.
#[derive(Debug, Default, Clone)]
pub struct ProvisionalRegistry {
    items: HashMap<String, Provisional>,
}

impl ProvisionalRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuild from persisted rows (daemon startup), applying recovery: any row
    /// that was `Armed`/`Reverting` (or armed-but-not-forward-done) is moved to
    /// `NeedsOperatorDecision` so no revert fires unattended at boot. Returns the
    /// handles that were moved, for an operator-facing audit summary.
    pub fn from_rows(rows: Vec<Provisional>) -> (Self, Vec<String>) {
        let mut items = HashMap::new();
        let mut moved = Vec::new();
        for mut row in rows {
            let needs_recovery = matches!(
                row.status,
                ProvisionalStatus::Armed | ProvisionalStatus::Reverting
            );
            if needs_recovery {
                row.status = ProvisionalStatus::NeedsOperatorDecision;
                moved.push(row.handle.clone());
            }
            items.insert(row.handle.clone(), row);
        }
        moved.sort();
        (Self { items }, moved)
    }

    pub fn insert(&mut self, p: Provisional) {
        self.items.insert(p.handle.clone(), p);
    }

    pub fn get(&self, handle: &str) -> Option<&Provisional> {
        self.items.get(handle)
    }

    /// Drop a provisional outright (e.g. its forward command failed, so there is
    /// nothing to revert).
    pub fn remove(&mut self, handle: &str) -> Option<Provisional> {
        self.items.remove(handle)
    }

    /// All provisionals, newest first.
    pub fn list(&self) -> Vec<Provisional> {
        let mut v: Vec<_> = self.items.values().cloned().collect();
        v.sort_by(|a, b| {
            b.created_unix
                .cmp(&a.created_unix)
                .then(a.handle.cmp(&b.handle))
        });
        v
    }

    /// Count of outstanding (non-terminal) provisionals, for the global cap.
    pub fn outstanding(&self) -> usize {
        self.items
            .values()
            .filter(|p| p.status.is_outstanding())
            .count()
    }

    /// Count of outstanding provisionals created by a principal, for the
    /// per-caller cap. Absence never matches absence (`scope_eq` semantics), so
    /// unauthenticated callers do not share a quota bucket.
    pub fn outstanding_for(&self, principal: Option<&PrincipalKey>) -> usize {
        let owner = principal.cloned();
        self.items
            .values()
            .filter(|p| p.status.is_outstanding() && scope_eq(&p.principal, &owner))
            .count()
    }

    pub fn mark_forward_done(&mut self, handle: &str, exit: Option<i32>) {
        if let Some(p) = self.items.get_mut(handle) {
            p.forward_done = true;
            let _ = exit; // forward exit is recorded by the caller's response path
        }
    }

    /// Operator confirms: keep the change, cancel the timer. Allowed from
    /// `Armed` and `NeedsOperatorDecision`.
    pub fn confirm(&mut self, handle: &str) -> Result<Provisional, GateError> {
        let p = self
            .items
            .get_mut(handle)
            .ok_or_else(|| GateError::NotFound(handle.to_string()))?;
        match p.status {
            ProvisionalStatus::Armed | ProvisionalStatus::NeedsOperatorDecision => {
                p.status = ProvisionalStatus::Confirmed;
                Ok(p.clone())
            }
            other => Err(GateError::WrongState {
                handle: handle.to_string(),
                detail: format!("already {}", other.as_str()),
            }),
        }
    }

    /// Claim a handle for revert (operator-initiated `guard revert`, allowed
    /// from `Armed`/`NeedsOperatorDecision`). Transitions to `Reverting` and
    /// returns the row so the daemon can run the revert.
    pub fn begin_revert(&mut self, handle: &str) -> Result<Provisional, GateError> {
        let p = self
            .items
            .get_mut(handle)
            .ok_or_else(|| GateError::NotFound(handle.to_string()))?;
        match p.status {
            ProvisionalStatus::Armed | ProvisionalStatus::NeedsOperatorDecision => {
                p.status = ProvisionalStatus::Reverting;
                Ok(p.clone())
            }
            other => Err(GateError::WrongState {
                handle: handle.to_string(),
                detail: format!("already {}", other.as_str()),
            }),
        }
    }

    /// Sweeper tick: claim every `Armed` provisional whose forward command has
    /// run and whose deadline has passed, transitioning each to `Reverting`, and
    /// return them so the daemon can run their reverts. The startup grace is the
    /// daemon's responsibility (it delays starting the sweeper), so this only
    /// considers the live deadline.
    pub fn take_due(&mut self, now: u64) -> Vec<Provisional> {
        let due: Vec<String> = self
            .items
            .values()
            .filter(|p| {
                p.status == ProvisionalStatus::Armed && p.forward_done && now >= p.deadline_unix
            })
            .map(|p| p.handle.clone())
            .collect();
        let mut taken = Vec::new();
        for h in due {
            if let Some(p) = self.items.get_mut(&h) {
                p.status = ProvisionalStatus::Reverting;
                taken.push(p.clone());
            }
        }
        taken.sort_by(|a, b| a.handle.cmp(&b.handle));
        taken
    }

    /// Record a successful revert (`Reverting` -> `Reverted`).
    pub fn set_reverted(&mut self, handle: &str, exit: Option<i32>) {
        if let Some(p) = self.items.get_mut(handle) {
            p.status = ProvisionalStatus::Reverted;
            p.revert_exit = exit;
            p.revert_detail = None;
        }
    }

    /// Record a failed revert (`Reverting` -> `RevertFailed`); the mutation may
    /// still be in place, so this stays outstanding and queryable.
    pub fn set_revert_failed(&mut self, handle: &str, exit: Option<i32>, detail: String) {
        if let Some(p) = self.items.get_mut(handle) {
            p.status = ProvisionalStatus::RevertFailed;
            p.revert_exit = exit;
            p.revert_detail = Some(detail);
        }
    }

    /// Route a revert that could not run for a recoverable reason (for example
    /// the proxy that would execute an API revert is not currently running) to
    /// `NeedsOperatorDecision` rather than terminal `RevertFailed`, so the live
    /// mutation is surfaced to the operator instead of silently abandoned.
    pub fn set_needs_operator_decision(&mut self, handle: &str, detail: String) {
        if let Some(p) = self.items.get_mut(handle) {
            p.status = ProvisionalStatus::NeedsOperatorDecision;
            p.revert_detail = Some(detail);
        }
    }

    /// Drop terminal rows older than `retention_secs` so the table stays bounded.
    /// Outstanding rows are never pruned.
    pub fn prune_terminal(&mut self, now: u64, retention_secs: u64) -> Vec<String> {
        let drop: Vec<String> = self
            .items
            .values()
            .filter(|p| {
                p.status.is_terminal() && now.saturating_sub(p.created_unix) > retention_secs
            })
            .map(|p| p.handle.clone())
            .collect();
        for h in &drop {
            self.items.remove(h);
        }
        drop
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn armed(handle: &str, principal: Option<PrincipalKey>, deadline: u64) -> Provisional {
        Provisional {
            handle: handle.to_string(),
            principal,
            binary: "systemctl".into(),
            args: vec!["restart".into(), "app".into()],
            revert_binary: "systemctl".into(),
            revert_args: vec!["stop".into(), "app".into()],
            api_revert: None,
            reason: "restart".into(),
            created_unix: 100,
            deadline_unix: deadline,
            forward_done: true,
            status: ProvisionalStatus::Armed,
            revert_exit: None,
            revert_detail: None,
        }
    }

    #[test]
    fn confirm_cancels_timer() {
        let mut r = ProvisionalRegistry::new();
        r.insert(armed("h1", Some(PrincipalKey::from_uid(1001)), 200));
        let p = r.confirm("h1").unwrap();
        assert_eq!(p.status, ProvisionalStatus::Confirmed);
        // A confirmed provisional is never due.
        assert!(r.take_due(9999).is_empty());
    }

    #[test]
    fn take_due_only_claims_armed_past_deadline() {
        let mut r = ProvisionalRegistry::new();
        r.insert(armed("due", Some(PrincipalKey::from_uid(1001)), 150));
        r.insert(armed("future", Some(PrincipalKey::from_uid(1001)), 500));
        let mut not_done = armed("notdone", Some(PrincipalKey::from_uid(1001)), 150);
        not_done.forward_done = false;
        r.insert(not_done);

        let due = r.take_due(200);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].handle, "due");
        assert_eq!(r.get("due").unwrap().status, ProvisionalStatus::Reverting);
        // A second tick does not re-claim the now-Reverting item.
        assert!(r.take_due(200).is_empty());
    }

    #[test]
    fn revert_outcomes_recorded() {
        let mut r = ProvisionalRegistry::new();
        r.insert(armed("ok", Some(PrincipalKey::from_uid(1001)), 150));
        r.insert(armed("bad", Some(PrincipalKey::from_uid(1001)), 150));
        let _ = r.take_due(200);
        r.set_reverted("ok", Some(0));
        r.set_revert_failed("bad", Some(1), "boom".into());
        assert_eq!(r.get("ok").unwrap().status, ProvisionalStatus::Reverted);
        assert_eq!(
            r.get("bad").unwrap().status,
            ProvisionalStatus::RevertFailed
        );
        assert_eq!(r.get("bad").unwrap().revert_detail.as_deref(), Some("boom"));
        // RevertFailed stays outstanding; Reverted does not.
        assert_eq!(r.outstanding(), 1);
    }

    #[test]
    fn startup_recovery_never_auto_fires() {
        let p = armed("h1", Some(PrincipalKey::from_uid(1001)), 150); // deadline already passed at "now"
        let (mut reg, moved) = ProvisionalRegistry::from_rows(vec![p]);
        assert_eq!(moved, vec!["h1".to_string()]);
        assert_eq!(
            reg.get("h1").unwrap().status,
            ProvisionalStatus::NeedsOperatorDecision
        );
        // The sweeper must NOT pick up a needs-decision row even past deadline.
        assert!(reg.take_due(9999).is_empty());
        // It can still be confirmed or reverted by the operator.
        assert!(reg.confirm("h1").is_ok());
    }

    #[test]
    fn caps_count_outstanding_only() {
        let p1001 = PrincipalKey::from_uid(1001);
        let mut r = ProvisionalRegistry::new();
        r.insert(armed("a", Some(p1001.clone()), 200));
        r.insert(armed("b", Some(p1001.clone()), 200));
        r.insert(armed("c", Some(PrincipalKey::from_uid(1002)), 200));
        assert_eq!(r.outstanding(), 3);
        assert_eq!(r.outstanding_for(Some(&p1001)), 2);
        r.confirm("a").unwrap();
        assert_eq!(r.outstanding(), 2);
        assert_eq!(r.outstanding_for(Some(&p1001)), 1);
    }

    #[test]
    fn none_owner_never_shares_quota_with_none_caller() {
        // A row owned by an unauthenticated caller (`None`) must not count
        // toward another `None`-scope caller's per-caller cap: two missing
        // principals never match.
        let mut r = ProvisionalRegistry::new();
        r.insert(armed("anon", None, 200));
        assert_eq!(r.outstanding(), 1);
        assert_eq!(r.outstanding_for(None), 0);
    }

    #[test]
    fn confirm_unknown_handle_errs() {
        let mut r = ProvisionalRegistry::new();
        assert!(matches!(r.confirm("nope"), Err(GateError::NotFound(_))));
    }

    #[test]
    fn prune_terminal_drops_old_confirmed() {
        let mut r = ProvisionalRegistry::new();
        r.insert(armed("old", Some(PrincipalKey::from_uid(1001)), 200));
        r.confirm("old").unwrap();
        let dropped = r.prune_terminal(100 + 999_999, 1000);
        assert_eq!(dropped, vec!["old".to_string()]);
        assert!(r.get("old").is_none());
    }
}
