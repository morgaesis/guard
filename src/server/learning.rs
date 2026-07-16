//! Learned-rule and session-amendment orchestration for fresh LLM verdicts.
//!
//! Every function here runs after the evaluator has already decided a request
//! (or while an operator amends a session) and only records evidence or
//! promotes it into durable coverage:
//!
//! - Session auto-amend turns one fresh LLM allow/deny into an exact session
//!   rule when the command shape is safe to pin (`maybe_auto_amend_session_after_llm`).
//! - Deny-shape learning feeds the auto-learned deny store
//!   (`gating::deny_shape`) and backgrounds the synthesis round trip
//!   (`maybe_promote_deny_shape`).
//! - Allow-verb promotion feeds the observation store
//!   (`gating::allow_promotion`) and backgrounds the confirmation that appends
//!   a trusted verb to the catalog (`maybe_promote_allow_verb`).
//!
//! None of this affects the current request's decision; failures are logged or
//! surfaced as advisory notices appended to the evaluator's reason.

use crate::session::SessionAmendment;
use crate::shim::ShimGenerator;
use anyhow::Result;
use guard::gating::Reversibility;
use guard::learned_rules::{AutoShimMode, LearningOutcome};
use guard::redact::{audit_escape, command_line};
use std::path::PathBuf;

use super::execute::persist_session_snapshot;
use super::{deterministic_credential_deny_reason, ServerConfig};

const SESSION_AUTO_AMEND_MAX_ALLOW_RISK: i32 = 2;
const SESSION_AUTO_AMEND_MIN_DENY_RISK: i32 = 5;
const SESSION_EXACT_RULE_MAX_ARGS: usize = 128;
const SESSION_EXACT_RULE_MAX_ARG_LEN: usize = 1024;

pub(super) fn validate_session_exact_rule_candidate(
    binary: &str,
    args: &[String],
) -> std::result::Result<(), String> {
    if binary.is_empty()
        || binary.contains('\0')
        || binary.contains(char::is_whitespace)
        || binary.contains('"')
        || binary.contains('\'')
    {
        return Err("appeal command has an invalid binary name".to_string());
    }
    if args.len() > SESSION_EXACT_RULE_MAX_ARGS {
        return Err(format!(
            "appeal command has too many arguments for durable exact coverage (max {})",
            SESSION_EXACT_RULE_MAX_ARGS
        ));
    }
    for arg in args {
        if arg.len() > SESSION_EXACT_RULE_MAX_ARG_LEN {
            return Err(format!(
                "appeal argument is too long for durable exact coverage (max {} bytes)",
                SESSION_EXACT_RULE_MAX_ARG_LEN
            ));
        }
        if arg.contains('\0') || arg.contains('\n') || arg.contains('\r') {
            return Err("appeal command contains control characters".to_string());
        }
    }
    Ok(())
}

pub(super) fn allow_session_auto_amend_candidate(
    binary: &str,
    args: &[String],
    risk: Option<i32>,
) -> std::result::Result<(), String> {
    validate_session_exact_rule_candidate(binary, args)?;
    let risk = risk.unwrap_or(5);
    if risk > SESSION_AUTO_AMEND_MAX_ALLOW_RISK {
        return Err(format!(
            "risk {risk} exceeds auto-amend allow threshold {}",
            SESSION_AUTO_AMEND_MAX_ALLOW_RISK
        ));
    }
    if let Some(reason) = deterministic_credential_deny_reason(binary, args) {
        return Err(reason);
    }
    let command = command_line(binary, args);
    if looks_dangerous_appeal_command(&command) {
        return Err("command contains shell control or sensitive material".to_string());
    }
    Ok(())
}

fn looks_dangerous_appeal_command(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    lower.contains(';')
        || lower.contains('|')
        || lower.contains("&&")
        || lower.contains("||")
        || lower.contains('>')
        || lower.contains('<')
        || lower.contains('`')
        || lower.contains("$(")
        || lower.contains(" rm -rf")
        || lower.starts_with("rm -rf")
        || lower.contains("/etc/shadow")
        || lower.contains(" secret")
        || lower.contains(" secrets")
}

pub(super) fn deny_session_auto_amend_candidate(
    binary: &str,
    args: &[String],
    risk: Option<i32>,
) -> std::result::Result<(), String> {
    validate_session_exact_rule_candidate(binary, args)?;
    let risk = risk.unwrap_or(5);
    if risk < SESSION_AUTO_AMEND_MIN_DENY_RISK {
        return Err(format!(
            "risk {risk} is below auto-amend deny threshold {}",
            SESSION_AUTO_AMEND_MIN_DENY_RISK
        ));
    }
    if deterministic_credential_deny_reason(binary, args).is_some() {
        return Err("command may contain or expose credential material".to_string());
    }
    Ok(())
}

pub(super) async fn amend_session_exact_rule(
    config: &ServerConfig,
    token: &str,
    decision: SessionAmendment,
    binary: String,
    args: Vec<String>,
    cwd: Option<PathBuf>,
) -> Result<bool> {
    let (amended, before, after) = {
        let mut reg = config.sessions.write().await;
        let before = reg.clone();
        let amended = reg
            .amend_exact(token, decision, binary, args, cwd)
            .ok_or_else(|| anyhow::anyhow!("session token is revoked, expired, or unknown"))?;
        (amended, before, reg.clone())
    };
    if let Err(err) = persist_session_snapshot(config.session_store.clone(), after).await {
        *config.sessions.write().await = before;
        return Err(err);
    }
    Ok(amended)
}

pub(super) async fn maybe_auto_amend_session_after_llm(
    config: &ServerConfig,
    token: Option<&str>,
    decision: SessionAmendment,
    binary: &str,
    args: &[String],
    cwd: Option<&PathBuf>,
    risk: Option<i32>,
) -> Option<String> {
    let token = token?;
    let enabled = {
        let reg = config.sessions.read().await;
        reg.auto_amend_for(token)
    };
    if !enabled {
        return None;
    }

    let candidate = match decision {
        SessionAmendment::Allow => allow_session_auto_amend_candidate(binary, args, risk),
        SessionAmendment::Deny => deny_session_auto_amend_candidate(binary, args, risk),
    };
    if let Err(reason) = candidate {
        return Some(format!("Session auto-amend skipped: {reason}."));
    }

    match amend_session_exact_rule(
        config,
        token,
        decision,
        binary.to_string(),
        args.to_vec(),
        cwd.cloned(),
    )
    .await
    {
        Ok(true) => {
            let rule = command_line(binary, args);
            match decision {
                SessionAmendment::Allow => {
                    Some(format!("Session recorded exact allow coverage `{rule}`."))
                }
                SessionAmendment::Deny => {
                    Some(format!("Session recorded exact deny coverage `{rule}`."))
                }
            }
        }
        Ok(false) => None,
        Err(err) => Some(format!("Session auto-amend failed: {err}.")),
    }
}

/// Record one fresh LLM denial against the auto-learned deny-shape store
/// (`gating::deny_shape`). This is the only orchestration step for deny-shape
/// auto-learning: no operator action is needed because the store can only
/// ever hold shapes the LLM already denied. `record_learned_denial` is a fast
/// local bookkeeping write, awaited inline; if the bucket just crossed its
/// synthesis threshold, the actual promotion (a real LLM round trip) is
/// spawned as a detached background task so it never adds latency to this
/// (already-decided) denied request's response. Failures are logged, not
/// surfaced to the caller.
pub(super) async fn maybe_promote_deny_shape(
    config: &ServerConfig,
    binary: &str,
    args: &[String],
    command_line: &str,
    reason: &str,
) -> Option<String> {
    let outcome = match config
        .evaluator
        .record_learned_denial(binary, args, command_line, reason)
        .await
    {
        Ok(Some(outcome)) => outcome,
        Ok(None) => return None,
        Err(err) => {
            tracing::warn!("failed to record deny-shape observation: {}", err);
            return None;
        }
    };
    let hint = (outcome.denials >= outcome.required_denials).then(|| {
        format!(
            "guard has denied {} similar {} commands; if this access is needed, use the escalation handle to request a saved-grant or verb amendment",
            outcome.denials, binary
        )
    });
    if !outcome.ready_to_synthesize {
        return hint;
    }
    let evaluator = config.evaluator.clone();
    tokio::spawn(async move {
        match evaluator.try_promote_deny_shape(&outcome).await {
            Ok(true) => {
                tracing::info!(target: "guard::audit",
                    "[AUDIT] DENY_SHAPE_LEARNED service={} binary={} denials={}",
                    audit_escape(&outcome.service),
                    audit_escape(&outcome.binary),
                    outcome.denials
                );
            }
            Ok(false) => {
                tracing::debug!(
                    "deny-shape synthesis for {} declined or not confident yet",
                    outcome.binary
                );
            }
            Err(err) => {
                tracing::warn!("deny-shape promotion failed: {}", err);
            }
        }
    });
    hint
}

/// Record one fresh LLM approval against the auto-verb-promotion observation
/// store (`gating::allow_promotion`), and, once a bucket is ready, spawn a
/// detached background task that confirms and appends a trusted verb to the
/// catalog. Mirrors `maybe_promote_deny_shape`'s split between a fast inline
/// bookkeeping write and a backgrounded LLM round trip, with one difference:
/// on success this also appends to `config.verbs`, since a promoted verb (an
/// allow) has to land somewhere the daemon actually consults, unlike a deny
/// shape, which lives entirely inside the evaluator. There is deliberately no
/// operator notification anywhere in this path -- see the `gating::allow_promotion`
/// module docs for why an allow-side auto-promotion is designed to need none:
/// the promoted-or-not state is fully recoverable from `guard verb list` at
/// any time, so there is nothing time-sensitive for a human to be paged about.
#[allow(clippy::too_many_arguments)]
pub(super) async fn maybe_promote_allow_verb(
    config: &ServerConfig,
    binary: &str,
    args: &[String],
    command_line: &str,
    risk: Option<i32>,
    reversibility: Option<Reversibility>,
    reason: &str,
) {
    let outcome = match config
        .evaluator
        .record_learned_approval_for_promotion(
            binary,
            args,
            command_line,
            risk,
            reversibility,
            reason,
        )
        .await
    {
        Ok(Some(outcome)) => outcome,
        Ok(None) => return,
        Err(err) => {
            tracing::warn!("failed to record allow-promotion observation: {}", err);
            return;
        }
    };
    if !outcome.ready_to_synthesize {
        return;
    }
    let evaluator = config.evaluator.clone();
    let verbs = config.verbs.clone();
    tokio::spawn(async move {
        // `Ok(None)` here means "not confident yet" or a transient LLM
        // failure -- both should keep retrying as more evidence accumulates,
        // so the bucket is left as-is. Both `Ok(Some(verb))` (whether the
        // subsequent `append_verb` succeeds or fails) and `Err` are
        // definitive verdicts for this evidence and mark the bucket resolved
        // so it never retries the same doomed-to-repeat outcome (an
        // unbounded silent retry loop, e.g. on a deterministic catalog name
        // collision, or an unbounded stream of near-duplicate verbs from a
        // long-lived shape that keeps re-promoting under a fresh model-chosen
        // name every `min_approvals` multiple).
        let verb = match evaluator.try_confirm_verb_promotion(&outcome).await {
            Ok(Some(verb)) => verb,
            Ok(None) => {
                tracing::debug!(
                    "verb promotion for {} {} declined or not confident yet",
                    outcome.binary,
                    outcome.subcommand
                );
                return;
            }
            Err(err) => {
                tracing::warn!("verb-promotion confirmation failed: {}", err);
                if let Err(mark_err) = evaluator.mark_allow_promotion_resolved(&outcome).await {
                    tracing::warn!(
                        "failed to mark allow-promotion bucket resolved: {}",
                        mark_err
                    );
                }
                return;
            }
        };
        let mut cat = verbs.write().await;
        match cat.append_verb(&verb) {
            Ok(()) => {
                tracing::info!(target: "guard::audit",
                    "[AUDIT] VERB_AUTO_PROMOTED name={} binary={} consequence={} approvals={}",
                    audit_escape(&verb.name),
                    audit_escape(&verb.binary),
                    verb.consequence.as_str(),
                    outcome.approvals
                );
            }
            Err(err) => {
                tracing::warn!(
                    "failed to append auto-promoted verb '{}' to the catalog: {}",
                    verb.name,
                    err
                );
            }
        }
        drop(cat);
        if let Err(err) = evaluator.mark_allow_promotion_resolved(&outcome).await {
            tracing::warn!("failed to mark allow-promotion bucket resolved: {}", err);
        }
    });
}

pub(super) async fn learning_notice(
    config: &ServerConfig,
    outcome: &LearningOutcome,
) -> Option<String> {
    let mut notice = if outcome.is_candidate {
        format!(
            "Verb evidence for `{}` on `{}` reached {} approvals; automatic typed promotion evaluates coverage evidence and boundary probes without routine operator review.",
            outcome.pattern, outcome.service, outcome.approvals
        )
    } else if let Some(reason) = &outcome.skipped_reason {
        format!("Verb evidence not promotable: {reason}.")
    } else {
        format!(
            "Verb evidence `{}` for `{}` ({}/{} approvals).",
            outcome.pattern, outcome.service, outcome.approvals, outcome.required_approvals
        )
    };

    let Some(shim) = &outcome.shim else {
        return Some(notice);
    };
    let mode = config
        .evaluator
        .learned_auto_shim_mode()
        .await
        .unwrap_or(AutoShimMode::Off);

    match mode {
        AutoShimMode::Off => {}
        AutoShimMode::Suggest => {
            notice.push_str(&format!(
                " Shim hint: `{}` wraps `{}`.",
                shim.name,
                shim.render_command()
            ));
        }
        AutoShimMode::Create if outcome.is_candidate => {
            let Some(ref shim_dir) = config.shim_dir else {
                notice.push_str(&format!(
                    " Shim `{}` could be created after configuring a shim directory.",
                    shim.name
                ));
                return Some(notice);
            };
            match std::env::current_exe()
                .map_err(anyhow::Error::from)
                .and_then(|guard_bin| {
                    ShimGenerator::new(guard_bin, shim_dir.clone()).generate_alias(
                        &shim.name,
                        &shim.target_binary,
                        &shim.target_args,
                    )
                }) {
                Ok(path) => {
                    notice.push_str(&format!(
                        " Created shim `{}` at {}.",
                        shim.name,
                        path.display()
                    ));
                }
                Err(err) => {
                    tracing::warn!("failed to create learned shim {}: {}", shim.name, err);
                    notice.push_str(&format!(
                        " Shim hint: `{}` wraps `{}`.",
                        shim.name,
                        shim.render_command()
                    ));
                }
            }
        }
        AutoShimMode::Create => {
            notice.push_str(&format!(
                " Shim `{}` will be created once this candidate reaches {} approvals.",
                shim.name, outcome.required_approvals
            ));
        }
    }

    Some(notice)
}
