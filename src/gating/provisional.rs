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
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use super::{DecisionTrace, GateError};
use crate::principal::{scope_eq, PrincipalKey};

/// Lifecycle of a provisional execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvisionalStatus {
    /// The forward command is running, or it completed successfully and the
    /// auto-revert timer is counting down. `forward_done` distinguishes them.
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
    /// Recovery could not prove that the persisted rollback authority remains
    /// exact, or the daemon stopped while a rollback was in flight. It waits
    /// for an explicit operator decision.
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
    /// Canonical working directory used by the forward command and its
    /// command-shaped revert. Absent on older rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<PathBuf>,
    /// env-var -> secret-key mapping injected into the revert environment.
    /// Secret values are never persisted; the daemon resolves these references
    /// under `principal` immediately before the revert executes. Absent on older
    /// rows.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secret_keys: BTreeMap<String, String>,
    /// env-var -> secret-key mappings materialized as files for the revert.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secret_file_keys: BTreeMap<String, String>,
    /// The structured revert command (no shell). Operator-authored (verb) or an
    /// agent-supplied `--revert` that was itself evaluated to APPROVE at arm time.
    pub revert_binary: String,
    pub revert_args: Vec<String>,
    /// Independent command run at the deadline before rollback. Older rows
    /// omit it and retain the unconditional auto-revert behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm_check_binary: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub confirm_check_args: Vec<String>,
    /// Evaluator-reviewed authority and transport required by the check and
    /// rollback. Stored for audit and operator inspection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_path: Option<String>,
    /// Stable audit-safe attribution for lifecycle notifications. The bearer
    /// token itself is never persisted in the provisional row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_fingerprint: Option<String>,
    /// Immutable issued-session revision and secret selectors captured before
    /// the forward command. Rollback and confirmation checks use these even if
    /// the live bearer is later revoked, so an armed rollback remains viable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_entitlements: Option<Vec<String>>,
    /// Structured API revert plan for proxy-originated provisionals. Command
    /// reverts leave this unset and use `revert_binary` / `revert_args`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_revert: Option<ApiRevertPlan>,
    /// Short, caller-facing rationale for the original approval.
    pub reason: String,
    /// Admission explanation captured before the forward command runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_trace: Option<DecisionTrace>,
    pub created_unix: u64,
    /// Auto-revert fires at or after this wall-clock unix-seconds value.
    pub deadline_unix: u64,
    /// Confirmation window the envelope was armed with, in seconds. Retained
    /// alongside the deadline so a later message can state the window an
    /// operator actually got rather than only the instant it expired. Zero on
    /// rows written before the window was recorded.
    #[serde(default)]
    pub window_secs: u64,
    /// When the deadline sweeper's automatic rollback ran. `None` while the
    /// envelope is live and after an operator-initiated `guard revert`, so it
    /// distinguishes "the timer fired" from "somebody reverted this".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_reverted_unix: Option<u64>,
    /// Set once the forward command has actually run. A provisional persisted
    /// before exec with `forward_done=false` that survives a restart is
    /// indeterminate and routes to `NeedsOperatorDecision`.
    pub forward_done: bool,
    /// Exit status observed from the forward command. `None` means the
    /// process was interrupted before a normal exit was observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forward_exit: Option<i32>,
    /// The forward command completed, but the completed outcome could not be
    /// committed after execution. Operator action first converges this live
    /// row with the durable pre-forward row.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub forward_persistence_failed: bool,
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

    /// Why a lifecycle transition is refused from this row's current state.
    /// An automatic rollback names when it ran and the window that elapsed: a
    /// bare "already reverted" reads as a fault, when it is the envelope doing
    /// exactly what `--confirm-within` armed it to do.
    pub fn transition_block_detail(&self) -> String {
        match self.auto_reverted_unix {
            Some(at) if self.status == ProvisionalStatus::Reverted => {
                let at = crate::env::unix_seconds_to_utc(at);
                if self.window_secs > 0 {
                    format!(
                        "auto-reverted at {at} (deadline {}s elapsed)",
                        self.window_secs
                    )
                } else {
                    format!("auto-reverted at {at}")
                }
            }
            _ => format!("already {}", self.status.as_str()),
        }
    }

    /// Durable forward-side outcome derived from the lifecycle fields. This is
    /// separate from the rollback status exposed by [`ProvisionalStatus`].
    pub fn forward_outcome(&self) -> &'static str {
        if self.forward_persistence_failed {
            "persistence_failed"
        } else if !self.forward_done {
            if self.status == ProvisionalStatus::Armed {
                "running"
            } else {
                "interrupted"
            }
        } else if self.forward_exit.is_some_and(|exit| exit != 0)
            || (self.forward_exit.is_none()
                && self.status == ProvisionalStatus::NeedsOperatorDecision
                && self.deadline_unix == 0)
        {
            "failed"
        } else {
            "completed"
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiRevertPlan {
    #[serde(default)]
    pub endpoint: String,
    pub protocol: String,
    #[serde(default)]
    pub upstream_target: String,
    #[serde(default)]
    pub upstream_identity: String,
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

    /// Rebuild persisted rows at daemon startup. A completed forward command
    /// remains armed across restart, including when its deadline is already
    /// due. The daemon applies a startup grace before the sweeper can claim it.
    /// An interrupted rollback or a row persisted before the forward outcome
    /// became known is ambiguous and therefore needs an operator decision.
    pub fn from_rows(rows: Vec<Provisional>) -> (Self, Vec<String>) {
        let mut items = HashMap::new();
        let mut moved = Vec::new();
        for mut row in rows {
            let needs_recovery = row.status == ProvisionalStatus::Reverting
                || (row.status == ProvisionalStatus::Armed && !row.forward_done);
            if needs_recovery {
                row.status = ProvisionalStatus::NeedsOperatorDecision;
                if !row.forward_done {
                    row.deadline_unix = 0;
                    row.revert_detail = Some(
                        "daemon restarted while the forward command was running; outcome unknown"
                            .to_string(),
                    );
                }
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

    pub fn set_decision_trace(
        &mut self,
        handle: &str,
        trace: DecisionTrace,
    ) -> Option<Provisional> {
        let provisional = self.items.get_mut(handle)?;
        provisional.decision_trace = Some(trace);
        Some(provisional.clone())
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

    /// Record a completed forward process. A successful exit starts the
    /// confirmation window at `finished_unix`. A non-zero or signal exit has
    /// no confirmation deadline and requires an explicit operator decision.
    pub fn mark_forward_done(
        &mut self,
        handle: &str,
        exit: Option<i32>,
        finished_unix: u64,
        window_secs: u64,
    ) -> Option<Provisional> {
        let p = self.items.get_mut(handle)?;
        p.forward_done = true;
        p.forward_exit = exit;
        p.forward_persistence_failed = false;
        if exit == Some(0) {
            p.deadline_unix = finished_unix.saturating_add(window_secs);
            p.window_secs = window_secs;
            p.revert_detail = None;
        } else {
            p.deadline_unix = 0;
            p.window_secs = 0;
            p.status = ProvisionalStatus::NeedsOperatorDecision;
            p.revert_detail = Some(format!(
                "forward command exited with code {exit:?}; confirmation window was not started"
            ));
        }
        Some(p.clone())
    }

    /// Record a launched forward command whose transport or wait path failed.
    /// Its partial effects are unknown, so no timer is fabricated from the
    /// command's start time and the row remains available for operator action.
    pub fn mark_forward_interrupted(
        &mut self,
        handle: &str,
        detail: String,
    ) -> Option<Provisional> {
        let p = self.items.get_mut(handle)?;
        p.forward_done = false;
        p.forward_exit = None;
        p.forward_persistence_failed = false;
        p.deadline_unix = 0;
        p.status = ProvisionalStatus::NeedsOperatorDecision;
        p.revert_detail = Some(detail);
        Some(p.clone())
    }

    /// Record that the forward command completed but its durable outcome could
    /// not be committed. The pre-forward row remains the restart recovery
    /// authority, while the live registry must not leave a timer eligible for
    /// automatic rollback.
    pub fn mark_forward_persistence_failed(
        &mut self,
        handle: &str,
        exit: Option<i32>,
    ) -> Option<Provisional> {
        let p = self.items.get_mut(handle)?;
        p.forward_done = true;
        p.forward_exit = exit;
        p.forward_persistence_failed = true;
        p.deadline_unix = 0;
        p.window_secs = 0;
        p.status = ProvisionalStatus::NeedsOperatorDecision;
        p.revert_detail =
            Some("forward command completed but its durable outcome was not recorded".to_string());
        Some(p.clone())
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
            _ => Err(GateError::WrongState {
                handle: handle.to_string(),
                detail: p.transition_block_detail(),
            }),
        }
    }

    /// A due confirmation check succeeded after the sweeper claimed the row.
    pub fn confirm_after_check(&mut self, handle: &str) -> Result<Provisional, GateError> {
        let p = self
            .items
            .get_mut(handle)
            .ok_or_else(|| GateError::NotFound(handle.to_string()))?;
        if p.status != ProvisionalStatus::Reverting {
            return Err(GateError::WrongState {
                handle: handle.to_string(),
                detail: p.transition_block_detail(),
            });
        }
        p.status = ProvisionalStatus::Confirmed;
        p.revert_exit = None;
        p.revert_detail = Some("confirmation check exited successfully".to_string());
        Ok(p.clone())
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
            _ => Err(GateError::WrongState {
                handle: handle.to_string(),
                detail: p.transition_block_detail(),
            }),
        }
    }

    /// Handles whose completed forward action is due for rollback. This does
    /// not claim them; the daemon first persists an exact `Armed -> Reverting`
    /// CAS and only then installs the claimed row in memory.
    pub fn due_handles(&self, now: u64) -> Vec<String> {
        let mut due = self
            .items
            .values()
            .filter(|p| {
                p.status == ProvisionalStatus::Armed && p.forward_done && now >= p.deadline_unix
            })
            .map(|p| p.handle.clone())
            .collect::<Vec<_>>();
        due.sort();
        due
    }

    /// Sweeper tick: claim every `Armed` provisional whose forward command has
    /// run and whose deadline has passed, transitioning each to `Reverting`, and
    /// return them so the daemon can run their reverts. The startup grace is the
    /// daemon's responsibility (it delays starting the sweeper), so this only
    /// considers the live deadline.
    pub fn take_due(&mut self, now: u64) -> Vec<Provisional> {
        let due = self.due_handles(now);
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
    /// `auto_reverted_unix` is `Some(now)` when the deadline sweeper drove the
    /// rollback and `None` when an operator asked for it, so a later refusal
    /// can say which happened.
    pub fn set_reverted(
        &mut self,
        handle: &str,
        exit: Option<i32>,
        auto_reverted_unix: Option<u64>,
    ) {
        if let Some(p) = self.items.get_mut(handle) {
            p.status = ProvisionalStatus::Reverted;
            p.revert_exit = exit;
            p.revert_detail = None;
            p.auto_reverted_unix = auto_reverted_unix;
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
            cwd: None,
            secret_keys: BTreeMap::new(),
            secret_file_keys: BTreeMap::new(),
            revert_binary: "systemctl".into(),
            revert_args: vec!["stop".into(), "app".into()],
            confirm_check_binary: None,
            confirm_check_args: Vec::new(),
            control_path: None,
            session_fingerprint: None,
            session_revision: None,
            secret_entitlements: None,
            api_revert: None,
            reason: "restart".into(),
            decision_trace: None,
            created_unix: 100,
            deadline_unix: deadline,
            window_secs: 0,
            auto_reverted_unix: None,
            forward_done: true,
            forward_exit: Some(0),
            forward_persistence_failed: false,
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
    fn confirming_after_the_deadline_names_the_automatic_revert_and_its_window() {
        let mut r = ProvisionalRegistry::new();
        let mut p = armed("h1", Some(PrincipalKey::from_uid(1001)), 1_700_000_300);
        p.window_secs = 300;
        r.insert(p);
        r.take_due(1_700_000_301);
        r.set_reverted("h1", Some(0), Some(1_700_000_301));

        let error = r.confirm("h1").unwrap_err();
        assert_eq!(
            error.to_string(),
            "handle 'h1' cannot transition: auto-reverted at 2023-11-14T22:18:21Z \
             (deadline 300s elapsed)"
        );
        // `guard revert` on the same spent handle explains itself the same way.
        assert_eq!(r.begin_revert("h1").unwrap_err(), error);
    }

    #[test]
    fn an_operator_revert_is_not_reported_as_an_automatic_one() {
        let mut r = ProvisionalRegistry::new();
        let mut p = armed("h1", Some(PrincipalKey::from_uid(1001)), 1_700_000_300);
        p.window_secs = 300;
        r.insert(p);
        r.begin_revert("h1")
            .expect("operator revert claims the row");
        r.set_reverted("h1", Some(0), None);

        let error = r.confirm("h1").unwrap_err();
        assert_eq!(
            error.to_string(),
            "handle 'h1' cannot transition: already reverted"
        );
    }

    #[test]
    fn a_row_without_a_recorded_window_still_names_the_automatic_revert() {
        let mut r = ProvisionalRegistry::new();
        r.insert(armed(
            "h1",
            Some(PrincipalKey::from_uid(1001)),
            1_700_000_300,
        ));
        r.take_due(1_700_000_301);
        r.set_reverted("h1", Some(0), Some(1_700_000_301));

        assert_eq!(
            r.confirm("h1").unwrap_err().to_string(),
            "handle 'h1' cannot transition: auto-reverted at 2023-11-14T22:18:21Z"
        );
    }

    #[test]
    fn a_successful_forward_command_records_the_window_behind_its_deadline() {
        let mut r = ProvisionalRegistry::new();
        let mut armed_row = armed("h1", Some(PrincipalKey::from_uid(1001)), 0);
        armed_row.forward_done = false;
        r.insert(armed_row);

        let updated = r.mark_forward_done("h1", Some(0), 1_000, 300).unwrap();
        assert_eq!(updated.deadline_unix, 1_300);
        assert_eq!(updated.window_secs, 300);

        // A forward command that failed arms no timer, so it advertises none.
        let mut failed = armed("h2", Some(PrincipalKey::from_uid(1001)), 0);
        failed.forward_done = false;
        r.insert(failed);
        let updated = r.mark_forward_done("h2", Some(1), 1_000, 300).unwrap();
        assert_eq!(updated.deadline_unix, 0);
        assert_eq!(updated.window_secs, 0);
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
        r.set_reverted("ok", Some(0), Some(250));
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
    fn startup_recovery_rearms_completed_forward() {
        let p = armed("h1", Some(PrincipalKey::from_uid(1001)), 150);
        let (mut reg, moved) = ProvisionalRegistry::from_rows(vec![p]);
        assert!(moved.is_empty());
        assert_eq!(reg.get("h1").unwrap().status, ProvisionalStatus::Armed);
        assert_eq!(reg.take_due(9999)[0].handle, "h1");
    }

    #[test]
    fn startup_recovery_escalates_ambiguous_rows() {
        let mut before_forward = armed("not-forwarded", Some(PrincipalKey::from_uid(1001)), 150);
        before_forward.forward_done = false;
        let mut interrupted = armed("interrupted", Some(PrincipalKey::from_uid(1001)), 150);
        interrupted.status = ProvisionalStatus::Reverting;
        let (reg, moved) = ProvisionalRegistry::from_rows(vec![before_forward, interrupted]);
        assert_eq!(moved, vec!["interrupted", "not-forwarded"]);
        for handle in moved {
            assert_eq!(
                reg.get(&handle).unwrap().status,
                ProvisionalStatus::NeedsOperatorDecision
            );
        }
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

    #[test]
    fn pre_injection_fields_row_deserializes_with_empty_defaults() {
        let json = r#"{
            "handle":"legacy",
            "caller_uid":1001,
            "binary":"systemctl",
            "args":["restart","app"],
            "revert_binary":"systemctl",
            "revert_args":["stop","app"],
            "reason":"restart",
            "created_unix":100,
            "deadline_unix":200,
            "forward_done":true,
            "status":"armed",
            "revert_exit":null,
            "revert_detail":null
        }"#;

        let p: Provisional = serde_json::from_str(json).expect("legacy provisional row");
        assert_eq!(p.principal, Some(PrincipalKey::from_uid(1001)));
        assert!(p.secret_keys.is_empty());
    }
}
