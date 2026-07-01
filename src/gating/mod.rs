//! Consequence-gated execution: shared types and the pure routing decision.
//!
//! The evaluator keeps deciding APPROVE/DENY exactly as before. When gating is
//! enabled (`GateMode::Consequence`), it ALSO classifies the reversibility of
//! the commands it approves, and the daemon routes an approved command to one of
//! three gates by consequence:
//!
//! - `GateOutcome::ExecuteNow` — run immediately (today's behavior).
//! - `GateOutcome::Contain` — execute inside a containment envelope that
//!   auto-reverts unless an operator confirms (see [`provisional`]).
//! - `GateOutcome::Hold` — do not execute; enqueue for operator approval bound
//!   to the exact artifact (see [`approval`]).
//!
//! The routing is fail-safe: reversibility can only *raise* the gate, never
//! lower it. A missing or uncertain class routes to `Hold`. Only an explicitly
//! `Reversible`, low-risk command reaches `ExecuteNow`.
//!
//! These types live in the library crate so the evaluator can carry a
//! reversibility class. The registries that hold runtime state are in
//! [`provisional`] and [`approval`]; the operator-authored catalog is in
//! [`verb`].

pub mod approval;
pub mod deny_shape;
pub mod provisional;
pub mod verb;

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Errors from the provisional / approval state machines. Surfaced to the
/// operator or agent as a denial/error reason, so messages are caller-facing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateError {
    /// No record with that handle.
    NotFound(String),
    /// The record exists but is not in a state that permits this transition
    /// (e.g. confirming an already-reverted provisional).
    WrongState { handle: String, detail: String },
    /// A per-caller or global outstanding-hold cap was hit.
    CapExceeded(String),
}

impl fmt::Display for GateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(h) => write!(f, "no pending item with handle '{}'", h),
            Self::WrongState { handle, detail } => {
                write!(f, "handle '{}' cannot transition: {}", handle, detail)
            }
            Self::CapExceeded(detail) => write!(f, "{}", detail),
        }
    }
}

impl std::error::Error for GateError {}

/// Risk at or above this score forces an operator hold regardless of the
/// reversibility label the model emitted. A high-risk command the model
/// nonetheless tagged "reversible" is a classification we do not trust.
pub const HOLD_RISK_THRESHOLD: i32 = 7;

/// A command must score strictly below this to be eligible for execute-now.
/// Anything at or above is raised to at least a containment envelope.
pub const EXECUTE_NOW_MAX_RISK: i32 = 4;

/// How reversible the *effect* of an approved command is. Produced by the
/// evaluator when gating is enabled; never changes whether a command is
/// approved or denied, only which gate an already-approved command passes
/// through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reversibility {
    /// Read-only, idempotent, or trivially undone (ls, cat, systemctl status,
    /// git status, kubectl get).
    Reversible,
    /// A mutation with a known inverse and bounded blast radius that a rollback
    /// can restore (systemctl restart, kubectl scale, a config edit with a
    /// backup, a firewall change behind an auto-revert).
    Recoverable,
    /// Destruction or a change with no clean inverse (rm -rf, mkfs, DROP TABLE,
    /// kubectl delete pvc/namespace, key rotation, expunge).
    Irreversible,
}

impl Reversibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reversible => "reversible",
            Self::Recoverable => "recoverable",
            Self::Irreversible => "irreversible",
        }
    }

    /// Lenient parse accepting the canonical names and a few obvious synonyms a
    /// small model might emit. Unknown input yields `None`, which the routing
    /// treats as "uncertain" and fails safe to `Hold`.
    pub fn parse_lenient(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "reversible" | "read_only" | "readonly" | "read-only" | "safe" => {
                Some(Self::Reversible)
            }
            "recoverable" | "revertible" | "reversible_with_rollback" | "contained" => {
                Some(Self::Recoverable)
            }
            "irreversible" | "destructive" | "unrecoverable" | "permanent" => {
                Some(Self::Irreversible)
            }
            _ => None,
        }
    }
}

impl fmt::Display for Reversibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Reversibility {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_lenient(s).ok_or_else(|| format!("invalid reversibility: '{}'", s))
    }
}

/// Whether the consequence gate is active for a daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateMode {
    /// No routing; an approved command executes immediately (legacy behavior).
    #[default]
    Off,
    /// Route approved LLM decisions by reversibility (execute / contain / hold).
    Consequence,
}

impl GateMode {
    pub fn is_on(self) -> bool {
        matches!(self, Self::Consequence)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Consequence => "consequence",
        }
    }
}

impl fmt::Display for GateMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for GateMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" | "none" | "false" | "0" | "" => Ok(Self::Off),
            "consequence" | "on" | "true" | "1" => Ok(Self::Consequence),
            other => Err(format!("invalid gate mode: '{}'", other)),
        }
    }
}

/// Which gate an approved command was routed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateOutcome {
    /// Run immediately.
    ExecuteNow,
    /// Execute inside a containment envelope (requires a revert).
    Contain,
    /// Do not execute; hold for operator approval.
    Hold,
}

/// Pure routing decision for an LLM-approved command. This is the single source
/// of truth for the trust ladder and is unit-tested in isolation.
///
/// Inputs:
/// - `class`: the model's reversibility label, or `None` if absent/unparseable.
/// - `risk`: the model's 0-10 risk score, or `None` if absent.
/// - `revert_available`: whether a usable revert (verb-declared or an evaluated
///   `--revert`) accompanies the request.
/// - `force_hold`: the caller asked to require approval (`--require-approval`).
///
/// Guarantees:
/// - Reversibility can only *raise* the gate. Execute-now requires an explicit
///   `Reversible` class AND `risk < EXECUTE_NOW_MAX_RISK`.
/// - A missing/uncertain class, a missing risk, or `risk >= HOLD_RISK_THRESHOLD`
///   routes to `Hold`.
/// - A `Recoverable` command without a usable revert routes to `Hold`, never to
///   an unconfined execute.
pub fn decide_gate(
    class: Option<Reversibility>,
    risk: Option<i32>,
    revert_available: bool,
    force_hold: bool,
) -> GateOutcome {
    if force_hold {
        return GateOutcome::Hold;
    }
    // A missing risk is treated as maximally risky (fail safe).
    let risk = risk.unwrap_or(10);
    if risk >= HOLD_RISK_THRESHOLD {
        return GateOutcome::Hold;
    }
    match class {
        Some(Reversibility::Irreversible) => GateOutcome::Hold,
        Some(Reversibility::Recoverable) => {
            if revert_available {
                GateOutcome::Contain
            } else {
                GateOutcome::Hold
            }
        }
        Some(Reversibility::Reversible) => {
            if risk < EXECUTE_NOW_MAX_RISK {
                GateOutcome::ExecuteNow
            } else if revert_available {
                // A "reversible" command the model still scored mid-risk is a
                // contradiction; contain it if we can, else hold.
                GateOutcome::Contain
            } else {
                GateOutcome::Hold
            }
        }
        // Unknown / uncertain class: fail safe.
        None => GateOutcome::Hold,
    }
}

/// Honest statement of what a gate verified and what it deliberately did not.
/// Surfaced to the caller for held/provisional/dry-run outcomes so an approval
/// is never mistaken for a guarantee the action is correct or safe to keep.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Coverage {
    /// Checks the gate actually performed.
    pub checked: Vec<String>,
    /// Checks the gate did NOT perform (residual risk the operator owns).
    pub not_checked: Vec<String>,
}

impl Coverage {
    fn of(checked: &[&str], not_checked: &[&str]) -> Self {
        Self {
            checked: checked.iter().map(|s| s.to_string()).collect(),
            not_checked: not_checked.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Coverage for a containment envelope (recoverable + auto-revert armed).
    pub fn contain() -> Self {
        Self::of(
            &[
                "command evaluated and approved by the policy",
                "classified recoverable",
                "rollback command present and evaluated",
                "auto-revert timer armed",
            ],
            &[
                "that the rollback actually inverts this command's effect",
                "that preconditions (target exists, current state) hold",
                "post-change health of the affected service",
                "downstream consumers of the changed state",
            ],
        )
    }

    /// Coverage for an operator hold (irreversible / uncertain / high-risk).
    pub fn hold() -> Self {
        Self::of(
            &[
                "command evaluated and approved by the policy",
                "classified as needing operator sign-off before execution",
            ],
            &[
                "the command has NOT executed; nothing has changed yet",
                "the runtime effect, which is unknown until an operator approves",
                "any rollback path, since irreversible actions have none",
            ],
        )
    }

    /// Coverage for a dry-run (policy evaluated, nothing executed).
    pub fn dry_run() -> Self {
        Self::of(
            &["policy evaluated the command"],
            &[
                "the command was not executed; no runtime effects were observed",
                "consequence routing was not enforced (dry-run stops after the decision)",
            ],
        )
    }

    pub fn is_empty(&self) -> bool {
        self.checked.is_empty() && self.not_checked.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reversible_low_risk_executes_now() {
        assert_eq!(
            decide_gate(Some(Reversibility::Reversible), Some(1), false, false),
            GateOutcome::ExecuteNow
        );
        assert_eq!(
            decide_gate(Some(Reversibility::Reversible), Some(3), false, false),
            GateOutcome::ExecuteNow
        );
    }

    #[test]
    fn reversible_mid_risk_is_raised_not_executed() {
        // risk 4..6 on a "reversible" label: contain if a revert exists, else hold.
        assert_eq!(
            decide_gate(Some(Reversibility::Reversible), Some(5), true, false),
            GateOutcome::Contain
        );
        assert_eq!(
            decide_gate(Some(Reversibility::Reversible), Some(5), false, false),
            GateOutcome::Hold
        );
    }

    #[test]
    fn high_risk_always_holds_even_if_labeled_reversible() {
        assert_eq!(
            decide_gate(Some(Reversibility::Reversible), Some(8), true, false),
            GateOutcome::Hold
        );
    }

    #[test]
    fn recoverable_needs_a_revert_else_holds() {
        assert_eq!(
            decide_gate(Some(Reversibility::Recoverable), Some(2), true, false),
            GateOutcome::Contain
        );
        assert_eq!(
            decide_gate(Some(Reversibility::Recoverable), Some(2), false, false),
            GateOutcome::Hold
        );
    }

    #[test]
    fn irreversible_always_holds() {
        assert_eq!(
            decide_gate(Some(Reversibility::Irreversible), Some(1), true, false),
            GateOutcome::Hold
        );
    }

    #[test]
    fn missing_class_fails_safe_to_hold() {
        assert_eq!(
            decide_gate(None, Some(1), true, false),
            GateOutcome::Hold,
            "an unclassified command must never reach execute-now"
        );
    }

    #[test]
    fn missing_risk_fails_safe_to_hold() {
        assert_eq!(
            decide_gate(Some(Reversibility::Reversible), None, false, false),
            GateOutcome::Hold
        );
    }

    #[test]
    fn force_hold_overrides_everything() {
        assert_eq!(
            decide_gate(Some(Reversibility::Reversible), Some(0), true, true),
            GateOutcome::Hold
        );
    }

    #[test]
    fn reversibility_parse_roundtrip() {
        for r in [
            Reversibility::Reversible,
            Reversibility::Recoverable,
            Reversibility::Irreversible,
        ] {
            assert_eq!(Reversibility::parse_lenient(r.as_str()), Some(r));
        }
        assert_eq!(Reversibility::parse_lenient("nonsense"), None);
        assert_eq!(
            Reversibility::parse_lenient("DESTRUCTIVE"),
            Some(Reversibility::Irreversible)
        );
    }

    #[test]
    fn gate_mode_parse() {
        assert_eq!(
            "consequence".parse::<GateMode>().unwrap(),
            GateMode::Consequence
        );
        assert_eq!("off".parse::<GateMode>().unwrap(), GateMode::Off);
        assert!("bogus".parse::<GateMode>().is_err());
    }

    #[test]
    fn coverage_states_negatives() {
        let c = Coverage::contain();
        assert!(!c.not_checked.is_empty());
        assert!(c.not_checked.iter().any(|s| s.contains("invert")));
        let h = Coverage::hold();
        assert!(h.not_checked.iter().any(|s| s.contains("NOT executed")));
    }
}
