//! Public decision types returned by the evaluator.

use crate::gating::Reversibility;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmResponse {
    pub decision: String,
    pub reason: String,
    pub risk: i32,
    /// Reversibility class for an APPROVE decision when gating is enabled.
    /// `None` when gating is off or the model omitted/garbled the field; the
    /// routing layer treats `None` as "uncertain" and fails safe to a hold.
    #[serde(default)]
    pub reversibility: Option<Reversibility>,
}

#[derive(Debug, Clone)]
pub enum EvalResult {
    Allow {
        reason: String,
        source: EvalSource,
        risk: Option<i32>,
        /// Reversibility class from the LLM when gating is enabled. `None` for
        /// static-policy allows and when gating is off; the consequence gate
        /// treats `None` as uncertain and holds.
        reversibility: Option<Reversibility>,
    },
    Deny {
        reason: String,
        source: EvalSource,
        risk: Option<i32>,
    },
    Error(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalSource {
    StaticPolicy,
    Cache,
    Llm,
    /// A deny fast path the daemon synthesized itself from repeated LLM
    /// denials of this shape (see `gating::deny_shape`). Always a deny; this
    /// source can never appear on an `EvalResult::Allow`.
    LearnedDeny,
}

impl std::fmt::Display for EvalResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvalResult::Allow { reason, source, .. } => {
                write!(f, "Allow ({:?}): {}", source, reason)
            }
            EvalResult::Deny { reason, source, .. } => {
                write!(f, "Deny ({:?}): {}", source, reason)
            }
            EvalResult::Error(e) => {
                write!(f, "Error: {}", e)
            }
        }
    }
}

impl EvalResult {
    pub fn is_allow(&self) -> bool {
        matches!(self, EvalResult::Allow { .. })
    }

    pub fn is_deny(&self) -> bool {
        matches!(self, EvalResult::Deny { .. })
    }

    pub fn is_error(&self) -> bool {
        matches!(self, EvalResult::Error(_))
    }

    pub fn reason(&self) -> String {
        match self {
            EvalResult::Allow { reason, .. } => reason.clone(),
            EvalResult::Deny { reason, .. } => reason.clone(),
            EvalResult::Error(e) => format!("LLM unavailable: {}", e),
        }
    }

    /// Reversibility class for an allow decision, if the evaluator produced one
    /// (LLM allows under gating). `None` for denials, errors, static-policy
    /// allows, and allows made with gating off.
    pub fn reversibility(&self) -> Option<Reversibility> {
        match self {
            EvalResult::Allow { reversibility, .. } => *reversibility,
            _ => None,
        }
    }

    pub fn risk(&self) -> Option<i32> {
        match self {
            EvalResult::Allow { risk, .. } | EvalResult::Deny { risk, .. } => *risk,
            EvalResult::Error(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EvalResult, EvalSource};

    #[test]
    fn test_eval_result_display() {
        let allow = EvalResult::Allow {
            reason: "test".to_string(),
            source: EvalSource::Llm,
            risk: Some(1),
            reversibility: None,
        };
        assert!(allow.to_string().contains("Allow"));
        assert!(allow.to_string().contains("Llm"));

        let deny = EvalResult::Deny {
            reason: "test".to_string(),
            source: EvalSource::StaticPolicy,
            risk: None,
        };
        assert!(deny.to_string().contains("Deny"));
        assert!(deny.to_string().contains("StaticPolicy"));

        let err = EvalResult::Error("test error".to_string());
        assert!(err.to_string().contains("Error"));
        assert!(err.to_string().contains("test error"));
    }

    #[test]
    fn test_eval_result_helpers() {
        let allow = EvalResult::Allow {
            reason: "test".to_string(),
            source: EvalSource::Llm,
            risk: Some(1),
            reversibility: None,
        };
        assert!(allow.is_allow());
        assert!(!allow.is_deny());
        assert!(!allow.is_error());

        let deny = EvalResult::Deny {
            reason: "test".to_string(),
            source: EvalSource::StaticPolicy,
            risk: None,
        };
        assert!(!deny.is_allow());
        assert!(deny.is_deny());
        assert!(!deny.is_error());

        let err = EvalResult::Error("test".to_string());
        assert!(!err.is_allow());
        assert!(!err.is_deny());
        assert!(err.is_error());
    }
}
