use crate::injection::is_valid_env_name;
use crate::redact::{
    redact_exact_secrets, redact_output, redact_output_text, redact_output_with_state,
    RedactionState,
};
use crate::session::{
    SessionAmendment, SessionDecision, SessionDecisionSource, SessionExecStatus,
    SessionInteraction, SessionRegistry,
};
use crate::session_store::SessionStore;
use crate::shim::ShimGenerator;
#[cfg(unix)]
use anyhow::Context;
use anyhow::{bail, Result};
use guard::gating::{Coverage, Reversibility};
use guard::learned_rules::{AutoShimMode, LearningOutcome};
use std::collections::HashMap;
#[cfg(unix)]
use std::ffi::CString;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
#[cfg(unix)]
use uzers::os::unix::UserExt;

use super::gate_runtime::{binary_allowed, route_gated_allow, GateInputs};
#[cfg(unix)]
use super::grants::handle_grant_read;
#[cfg(unix)]
use super::path_with_shim_dir;
use super::transport::{write_policy_decision, write_stream_message};
#[cfg(unix)]
use super::wire::ExecOutcome;
use super::wire::{
    verb_trust_is_current, CallerIdentity, ExecuteRequest, ExecuteResult, ExecuteStreamMessage,
    OutputStream, RevertSpec, SshHostKeyMode, VerbContext,
};
use super::{
    binary_exists_on_path, child_env_allowlist, deterministic_credential_deny_reason,
    deterministic_safe_allow_reason, validate_request_injections, ServerConfig, MAX_GUARD_DEPTH,
    MAX_OUTPUT_BYTES, SESSION_AUTO_AMEND_MAX_ALLOW_RISK, SESSION_AUTO_AMEND_MIN_DENY_RISK,
    SESSION_EXACT_RULE_MAX_ARGS, SESSION_EXACT_RULE_MAX_ARG_LEN,
};

pub(super) async fn execute_command(
    request: ExecuteRequest,
    config: &ServerConfig,
    caller: &CallerIdentity,
) -> ExecuteResult {
    let mut sink = tokio::io::sink();
    execute_command_inner(request, config, caller, false, &mut sink).await
}

pub(super) async fn execute_command_streaming<W: AsyncWrite + Unpin>(
    request: ExecuteRequest,
    config: &ServerConfig,
    caller: &CallerIdentity,
    writer: &mut W,
) -> ExecuteResult {
    execute_command_inner(request, config, caller, true, writer).await
}

async fn execute_command_inner<W: AsyncWrite + Unpin>(
    mut request: ExecuteRequest,
    config: &ServerConfig,
    caller: &CallerIdentity,
    stream_output: bool,
    stream_writer: &mut W,
) -> ExecuteResult {
    let session_token = request.session_token.clone();

    // Resolve a verb invocation into a concrete command BEFORE any validation or
    // evaluation. The rendered binary/args then pass through the same checks as a
    // raw command; the verb's declared consequence class and rollback drive the
    // gate. Verbs are operator-authored, so the catalog is hot-reloaded by mtime.
    let mut verb_ctx: Option<VerbContext> = None;
    if let Some(invocation) = request.verb.clone() {
        if !config.gate.is_on() {
            let reason =
                "verbs require consequence gating (start the daemon with --gate consequence)"
                    .to_string();
            let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
            return ExecuteResult::denied(reason);
        }
        let rendered = {
            let mut cat = config.verbs.write().await;
            if let Err(e) = cat.reload_if_stale() {
                tracing::warn!("verb catalog reload failed, using previous: {}", e);
            }
            cat.render(&invocation.name, &invocation.params)
                .map(|r| (r, cat.version()))
        };
        match rendered {
            Ok((r, version)) => {
                let trusted = verb_trust_is_current(&r, config.evaluator.verb_promotion_stamp());
                request.binary = r.binary;
                request.args = r.args;
                request.revert = r.revert.map(|(binary, args)| RevertSpec { binary, args });
                verb_ctx = Some(VerbContext {
                    name: r.name,
                    class: r.consequence,
                    trusted,
                    params: r.params,
                    catalog_version: version,
                });
            }
            Err(e) => {
                let reason = format!("verb error: {}", e);
                config.log_audit_policy(caller, &invocation.name, &[], false, &reason);
                let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
                return ExecuteResult::denied(reason);
            }
        }
    } else if config.gate.is_on() {
        // No explicit `--verb` invocation, but a raw command may still match
        // a catalog verb's template (hand-authored or auto-promoted -- see
        // `gating::allow_promotion`). Reverse-matching lets a caller that
        // invokes a tool directly (`kubectl get pods -n foo`) pick up the
        // matching verb's declared consequence class and trust the same way
        // an explicit invocation would; the catalog is the transparent,
        // operator-inspectable/editable record either way. Gated on
        // `config.gate.is_on()` for the same reason the explicit path is:
        // without consequence gating there is no routing for a verb's class
        // to drive, so this stays a no-op and raw commands behave exactly as
        // before.
        let matched = {
            let mut cat = config.verbs.write().await;
            if let Err(e) = cat.reload_if_stale() {
                tracing::warn!("verb catalog reload failed, using previous: {}", e);
            }
            cat.match_command(&request.binary, &request.args)
                .map(|r| (r, cat.version()))
        };
        if let Some((r, version)) = matched {
            let trusted = verb_trust_is_current(&r, config.evaluator.verb_promotion_stamp());
            request.revert = r.revert.map(|(binary, args)| RevertSpec { binary, args });
            verb_ctx = Some(VerbContext {
                name: r.name,
                class: r.consequence,
                trusted,
                params: r.params,
                catalog_version: version,
            });
        }
    }

    // Fold the requested ssh host-key mode into the command now that the verb
    // (if any) has been rendered. From here on, request.args carries any
    // injected `-o` options, so the policy decision, the evaluator, the audit
    // record, and the spawned process all act on the same command.
    request.apply_ssh_hostkey_options();

    // Check recursion depth
    let depth: u32 = std::env::var("GUARD_DEPTH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if depth >= MAX_GUARD_DEPTH {
        let reason = format!("guard recursion depth exceeded (max {})", MAX_GUARD_DEPTH);
        config.log_audit_policy(caller, &request.binary, &request.args, false, &reason);
        let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
        record_live_session_interaction(
            config,
            session_token.as_deref(),
            SessionInteraction {
                at_unix: 0,
                command: request.binary.clone(),
                allowed: false,
                source: SessionDecisionSource::Validation,
                reason: reason.clone(),
                risk: None,
                exec_status: SessionExecStatus::NotAttempted,
            },
        )
        .await;
        return ExecuteResult::denied(reason);
    }

    // Validate binary name: reject paths, traversal, and shell metacharacters.
    // Windows path forms (backslash, drive-letter `:`, UNC) are rejected too so a
    // caller cannot pass an absolute/relative path disguised as the "binary".
    if request.binary.contains('/')
        || request.binary.contains('\\')
        || request.binary.contains(':')
        || request.binary.contains("..")
        || request.binary.contains('\0')
        || request.binary.is_empty()
    {
        let looks_like_shell_string = request.binary.contains(char::is_whitespace)
            || request.binary.contains('"')
            || request.binary.contains('\'');
        let reason = if looks_like_shell_string {
            format!(
                "invalid binary name: '{}'. guard run expects `<binary> [args...]`, not a shell string. Pass the command as separate arguments; e.g. `guard run ssh host 'remote cmd'` instead of `guard run 'ssh host \"remote cmd\"'`.",
                request.binary
            )
        } else {
            format!("invalid binary name: '{}'", request.binary)
        };
        config.log_audit_policy(caller, &request.binary, &request.args, false, &reason);
        let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
        record_live_session_interaction(
            config,
            session_token.as_deref(),
            SessionInteraction {
                at_unix: 0,
                command: request.binary.clone(),
                allowed: false,
                source: SessionDecisionSource::Validation,
                reason: reason.clone(),
                risk: None,
                exec_status: SessionExecStatus::NotAttempted,
            },
        )
        .await;
        return ExecuteResult::denied(reason);
    }

    // Reconstruct full command line early so session short-circuit and
    // evaluator share the same command text.
    let command_line = command_line(&request.binary, &request.args);

    if let Err(reason) = validate_request_injections(&request, config, caller, &command_line).await
    {
        config.log_audit_policy(caller, &request.binary, &request.args, false, &reason);
        let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
        record_live_session_interaction(
            config,
            session_token.as_deref(),
            SessionInteraction {
                at_unix: 0,
                command: command_line.clone(),
                allowed: false,
                source: SessionDecisionSource::Validation,
                reason: reason.clone(),
                risk: None,
                exec_status: SessionExecStatus::NotAttempted,
            },
        )
        .await;
        return ExecuteResult::denied(reason);
    }

    // Session grants short-circuit both directions: deny wins before the
    // evaluator, allow skips the evaluator entirely.
    //
    // If the caller passes a session_token that the daemon does not know
    // about (revoked, expired, or never existed), the request is rejected
    // — silently falling through to base policy would let an agent run
    // with surprise rules when its operator-issued grant is gone.
    if let Some(ref token) = request.session_token {
        let (decision, exists, static_only) = {
            let reg = config.sessions.read().await;
            let decision = reg.check(token, &request.binary, &request.args);
            (decision, reg.has(token), reg.static_only_for(token))
        };
        if !exists {
            let reason = format!(
                "unknown session token: '{}' is revoked, expired, or never existed",
                token
            );
            config.log_audit_policy(caller, &request.binary, &request.args, false, &reason);
            let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
            return ExecuteResult::denied(reason);
        }
        if let Some((decision, reason)) = decision {
            match decision {
                SessionDecision::Deny => {
                    config.log_audit_policy(caller, &request.binary, &request.args, false, &reason);
                    let _ =
                        write_policy_decision(stream_output, stream_writer, false, &reason).await;
                    record_live_session_interaction(
                        config,
                        session_token.as_deref(),
                        SessionInteraction {
                            at_unix: 0,
                            command: command_line.clone(),
                            allowed: false,
                            source: SessionDecisionSource::SessionDeny,
                            reason: reason.clone(),
                            risk: None,
                            exec_status: SessionExecStatus::NotAttempted,
                        },
                    )
                    .await;
                    return ExecuteResult::denied(reason);
                }
                SessionDecision::Allow => {
                    config.log_audit_policy(caller, &request.binary, &request.args, true, &reason);
                    if let Err(e) =
                        write_policy_decision(stream_output, stream_writer, true, &reason).await
                    {
                        return ExecuteResult::exec_failed(
                            reason,
                            format!("client stream error: {}", e),
                        );
                    }
                    let result = exec_with_read_grant_retry(
                        request,
                        config,
                        caller,
                        reason.clone(),
                        depth,
                        stream_output,
                        stream_writer,
                    )
                    .await;
                    record_live_session_interaction(
                        config,
                        session_token.as_deref(),
                        SessionInteraction {
                            at_unix: 0,
                            command: command_line.clone(),
                            allowed: true,
                            source: SessionDecisionSource::SessionAllow,
                            reason,
                            risk: None,
                            exec_status: result.session_exec_status(),
                        },
                    )
                    .await;
                    return result;
                }
            }
        }
        if static_only {
            let reason = "session static-only: no matching session allow rule".to_string();
            config.log_audit_policy(caller, &request.binary, &request.args, false, &reason);
            let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
            record_live_session_interaction(
                config,
                session_token.as_deref(),
                SessionInteraction {
                    at_unix: 0,
                    command: command_line.clone(),
                    allowed: false,
                    source: SessionDecisionSource::SessionStaticOnly,
                    reason: reason.clone(),
                    risk: None,
                    exec_status: SessionExecStatus::NotAttempted,
                },
            )
            .await;
            return ExecuteResult::denied(reason);
        }
    }

    // Server-wide binary allow-list: a hard floor enforced before evaluation on
    // every execution route, so a disallowed binary never reaches the LLM or an
    // operator hold. Independent of --preflight.
    if !binary_allowed(&config.allowed_binaries, &request.binary) {
        let reason = format!(
            "binary '{}' is not in the server allow-list",
            request.binary
        );
        config.log_audit_policy(caller, &request.binary, &request.args, false, &reason);
        let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
        record_live_session_interaction(
            config,
            session_token.as_deref(),
            SessionInteraction {
                at_unix: 0,
                command: command_line.clone(),
                allowed: false,
                source: SessionDecisionSource::Validation,
                reason: reason.clone(),
                risk: None,
                exec_status: SessionExecStatus::NotAttempted,
            },
        )
        .await;
        return ExecuteResult::denied(reason);
    }

    if config.preflight && !binary_exists_on_path(&request.binary) {
        let reason = format!(
            "unknown binary: '{}' is not available on the guard server PATH",
            request.binary
        );
        config.log_audit_policy(caller, &request.binary, &request.args, false, &reason);
        let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
        record_live_session_interaction(
            config,
            session_token.as_deref(),
            SessionInteraction {
                at_unix: 0,
                command: command_line.clone(),
                allowed: false,
                source: SessionDecisionSource::Validation,
                reason: reason.clone(),
                risk: None,
                exec_status: SessionExecStatus::NotAttempted,
            },
        )
        .await;
        return ExecuteResult::denied(reason);
    }

    if config.preflight {
        if let Some(reason) = deterministic_credential_deny_reason(&request.binary, &request.args) {
            config.log_audit_policy(caller, &request.binary, &request.args, false, &reason);
            let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
            record_live_session_interaction(
                config,
                session_token.as_deref(),
                SessionInteraction {
                    at_unix: 0,
                    command: command_line.clone(),
                    allowed: false,
                    source: SessionDecisionSource::Validation,
                    reason: reason.clone(),
                    risk: None,
                    exec_status: SessionExecStatus::NotAttempted,
                },
            )
            .await;
            return ExecuteResult::denied(reason);
        }
    }

    // Deterministic pre-LLM fast allow for a fixed set of trivially safe
    // read-only commands. Like a trusted verb, it is a deterministic allow
    // that precedes the evaluator; it never applies when the caller injected
    // env/secrets (which could change the command's meaning) and is disabled
    // in paranoid mode. `accept-all` host-key mode is excluded explicitly:
    // its injected `StrictHostKeyChecking=no` already fails the ssh option
    // allow-list, but keeping the guard here documents that giving up host
    // authentication never rides the fast path even if the diagnostic is fixed.
    if request.env.is_empty()
        && request.secrets.is_empty()
        && !matches!(request.ssh_hostkey, Some(SshHostKeyMode::AcceptAll))
    {
        if let Some(reason) =
            deterministic_safe_allow_reason(config, &request.binary, &request.args)
        {
            config.log_audit_policy(caller, &request.binary, &request.args, true, &reason);
            if let Err(e) = write_policy_decision(stream_output, stream_writer, true, &reason).await
            {
                return ExecuteResult::exec_failed_after_start(
                    reason,
                    format!("client stream error: {}", e),
                );
            }
            let inputs = GateInputs {
                reason: reason.clone(),
                risk: Some(0),
                reversibility: None,
                revert_preauthorized: false,
                verb: None,
                bypass: true,
            };
            let result = route_gated_allow(
                request,
                config,
                caller,
                inputs,
                depth,
                stream_output,
                stream_writer,
            )
            .await;
            record_live_session_interaction(
                config,
                session_token.as_deref(),
                SessionInteraction {
                    at_unix: 0,
                    command: command_line.clone(),
                    allowed: true,
                    source: SessionDecisionSource::StaticPolicy,
                    reason,
                    risk: Some(0),
                    exec_status: result.session_exec_status(),
                },
            )
            .await;
            return result;
        }
    }

    // Pull session-scoped additive prompt, if any. The evaluator appends
    // it to the system prompt for this single call so the LLM has the
    // session context that the static glob patterns cannot express.
    let session_prompt = if let Some(ref token) = request.session_token {
        let reg = config.sessions.read().await;
        reg.prompt_append_for(token)
    } else {
        None
    };
    // Reversibility as an evaluator input: a constructible rollback widens
    // what the evaluator may approve at the margin, while decide_gate's
    // deterministic routing stays the hard floor (the fragment says so
    // explicitly). Only meaningful under the consequence gate, where the
    // envelope actually arms. A non-empty prompt append bypasses the decision
    // cache, so a revert-aware verdict is never replayed for a revert-less
    // request.
    let session_prompt = merge_revert_context(
        session_prompt,
        config.gate.is_on() && request.revert.is_some(),
    );

    // Trusted verb: an operator-reviewed shape skips the LLM evaluator (a
    // deterministic allow path, like a static-policy allow). The verb's declared
    // reversibility class drives the gate and its revert is pre-authorized.
    if let Some(vc) = verb_ctx.clone() {
        if vc.trusted {
            let reason = format!("trusted verb '{}'", vc.name);
            config.log_audit_policy(caller, &request.binary, &request.args, true, &reason);
            if let Err(e) = write_policy_decision(stream_output, stream_writer, true, &reason).await
            {
                return ExecuteResult::exec_failed_after_start(
                    reason,
                    format!("client stream error: {}", e),
                );
            }
            let inputs = GateInputs {
                reason: reason.clone(),
                risk: Some(0),
                reversibility: Some(vc.class),
                revert_preauthorized: true,
                verb: Some(vc),
                bypass: false,
            };
            let result = route_gated_allow(
                request,
                config,
                caller,
                inputs,
                depth,
                stream_output,
                stream_writer,
            )
            .await;
            record_live_session_interaction(
                config,
                session_token.as_deref(),
                SessionInteraction {
                    at_unix: 0,
                    command: command_line.clone(),
                    allowed: true,
                    source: SessionDecisionSource::StaticPolicy,
                    reason,
                    risk: Some(0),
                    exec_status: result.session_exec_status(),
                },
            )
            .await;
            return result;
        }
    }

    let eval_result = config
        .evaluator
        .evaluate_with_reevaluate(&command_line, session_prompt.as_deref(), request.reevaluate)
        .await;

    match eval_result {
        crate::evaluate::EvalResult::Deny {
            reason,
            source,
            risk,
        } => {
            let mut reason = reason;
            if matches!(source, crate::evaluate::EvalSource::Llm) {
                if let Some(notice) = maybe_auto_amend_session_after_llm(
                    config,
                    session_token.as_deref(),
                    SessionAmendment::Deny,
                    &request.binary,
                    &request.args,
                    risk,
                )
                .await
                {
                    reason = format!("{reason} {notice}");
                }
                maybe_promote_deny_shape(
                    config,
                    &request.binary,
                    &request.args,
                    &command_line,
                    &reason,
                )
                .await;
            }
            config.log_audit_policy(caller, &request.binary, &request.args, false, &reason);
            let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
            record_live_session_interaction(
                config,
                session_token.as_deref(),
                SessionInteraction {
                    at_unix: 0,
                    command: command_line.clone(),
                    allowed: false,
                    source: session_source_from_eval(source),
                    reason: reason.clone(),
                    risk,
                    exec_status: SessionExecStatus::NotAttempted,
                },
            )
            .await;
            ExecuteResult::denied(reason)
        }
        crate::evaluate::EvalResult::Error(e) => {
            tracing::error!("evaluation error: {}", e);
            let reason = format!("evaluation error: {}", e);
            config.log_audit_policy(caller, &request.binary, &request.args, false, &reason);
            let _ = write_policy_decision(stream_output, stream_writer, false, &reason).await;
            record_live_session_interaction(
                config,
                session_token.as_deref(),
                SessionInteraction {
                    at_unix: 0,
                    command: command_line.clone(),
                    allowed: false,
                    source: SessionDecisionSource::EvaluatorError,
                    reason: reason.clone(),
                    risk: None,
                    exec_status: SessionExecStatus::NotAttempted,
                },
            )
            .await;
            ExecuteResult::denied(reason)
        }
        crate::evaluate::EvalResult::Allow {
            reason,
            source,
            risk,
            reversibility,
        } => {
            let mut reason = reason;
            if matches!(source, crate::evaluate::EvalSource::Llm)
                && session_prompt
                    .as_deref()
                    .map(|prompt| prompt.trim().is_empty())
                    .unwrap_or(true)
                && session_token.is_none()
            {
                match config
                    .evaluator
                    .record_learned_approval(
                        &request.binary,
                        &request.args,
                        &command_line,
                        risk,
                        &reason,
                    )
                    .await
                {
                    Ok(Some(outcome)) => {
                        if let Some(notice) = learning_notice(config, &outcome).await {
                            reason = format!("{reason} {notice}");
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        tracing::warn!("failed to record learned rule candidate: {}", err);
                    }
                }
                maybe_promote_allow_verb(
                    config,
                    &request.binary,
                    &request.args,
                    &command_line,
                    risk,
                    reversibility,
                    &reason,
                )
                .await;
            }
            if matches!(source, crate::evaluate::EvalSource::Llm) {
                if let Some(notice) = maybe_auto_amend_session_after_llm(
                    config,
                    session_token.as_deref(),
                    SessionAmendment::Allow,
                    &request.binary,
                    &request.args,
                    risk,
                )
                .await
                {
                    reason = format!("{reason} {notice}");
                }
            }
            tracing::debug!("command allowed: {}", reason);
            config.log_audit_policy(caller, &request.binary, &request.args, true, &reason);
            if let Err(e) = write_policy_decision(stream_output, stream_writer, true, &reason).await
            {
                return ExecuteResult::exec_failed_after_start(
                    reason,
                    format!("client stream error: {}", e),
                );
            }
            // Consequence gate: when enabled, route this LLM-approved command by
            // reversibility (execute / contain / hold). When off, this is a
            // straight exec, byte-identical to before. Operator-authored allows
            // (session-allow above, static-policy) deliberately bypass the gate.
            // A verb's declared class overrides the model's, and a verb's revert
            // is pre-authorized (operator-reviewed); a free-form --revert is not.
            let effective_class = verb_ctx.as_ref().map(|v| v.class).or(reversibility);
            // A static-policy allow (operator-authored, deterministic) bypasses
            // the gate. A verb invocation never bypasses — its declared class
            // routes it. The LLM path is gated.
            let bypass =
                matches!(source, crate::evaluate::EvalSource::StaticPolicy) && verb_ctx.is_none();
            let inputs = GateInputs {
                reason: reason.clone(),
                risk,
                reversibility: effective_class,
                revert_preauthorized: verb_ctx.is_some(),
                verb: verb_ctx.clone(),
                bypass,
            };
            let result = route_gated_allow(
                request,
                config,
                caller,
                inputs,
                depth,
                stream_output,
                stream_writer,
            )
            .await;
            record_live_session_interaction(
                config,
                session_token.as_deref(),
                SessionInteraction {
                    at_unix: 0,
                    command: command_line,
                    allowed: true,
                    source: session_source_from_eval(source),
                    reason,
                    risk,
                    exec_status: result.session_exec_status(),
                },
            )
            .await;
            result
        }
    }
}

pub(super) fn session_source_from_eval(
    source: crate::evaluate::EvalSource,
) -> SessionDecisionSource {
    match source {
        crate::evaluate::EvalSource::Llm => SessionDecisionSource::Llm,
        crate::evaluate::EvalSource::Cache => SessionDecisionSource::Cache,
        crate::evaluate::EvalSource::StaticPolicy => SessionDecisionSource::StaticPolicy,
        crate::evaluate::EvalSource::LearnedDeny => SessionDecisionSource::LearnedDeny,
    }
}

pub(super) fn command_line(binary: &str, args: &[String]) -> String {
    if args.is_empty() {
        binary.to_string()
    } else {
        format!("{} {}", binary, args.join(" "))
    }
}

/// Render a command line for an audit log entry with secret-shaped values
/// masked. Argv routinely carries inline credentials (`--password=...`,
/// `Authorization: Bearer <token>`, connection URLs); the audit trail needs
/// the command shape, not the values, and the daemon log must not become a
/// secret store.
pub(super) fn audit_command_line(binary: &str, args: &[String]) -> String {
    redact_output(&command_line(binary, args))
}

/// Truncate a token for an audit log entry. Tokens are bearer capabilities;
/// the log needs enough of one to correlate events against
/// `guard session list`, not the full value. Char-based slicing: the value is
/// caller-supplied, so byte indexing could split a UTF-8 sequence and panic.
pub(super) fn audit_token(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    if chars.len() > 8 {
        let head: String = chars[..4].iter().collect();
        let tail: String = chars[chars.len() - 4..].iter().collect();
        format!("{head}...{tail}")
    } else {
        "***".to_string()
    }
}

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
            "appeal command has too many arguments for a durable exact rule (max {})",
            SESSION_EXACT_RULE_MAX_ARGS
        ));
    }
    for arg in args {
        if arg.len() > SESSION_EXACT_RULE_MAX_ARG_LEN {
            return Err(format!(
                "appeal argument is too long for a durable exact rule (max {} bytes)",
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
    if crate::grant_rules::looks_dangerous_static_command(&command) {
        return Err("command contains shell control or sensitive material".to_string());
    }
    Ok(())
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
) -> Result<bool> {
    let (amended, before, after) = {
        let mut reg = config.sessions.write().await;
        let before = reg.clone();
        let amended = reg
            .amend_exact(token, decision, binary, args)
            .ok_or_else(|| anyhow::anyhow!("session token is revoked, expired, or unknown"))?;
        (amended, before, reg.clone())
    };
    if let Err(err) = persist_session_snapshot(config.session_store.clone(), after).await {
        *config.sessions.write().await = before;
        return Err(err);
    }
    Ok(amended)
}

async fn maybe_auto_amend_session_after_llm(
    config: &ServerConfig,
    token: Option<&str>,
    decision: SessionAmendment,
    binary: &str,
    args: &[String],
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

    match amend_session_exact_rule(config, token, decision, binary.to_string(), args.to_vec()).await
    {
        Ok(true) => {
            let rule = command_line(binary, args);
            match decision {
                SessionAmendment::Allow => {
                    Some(format!("Session auto-amended exact allow `{rule}`."))
                }
                SessionAmendment::Deny => {
                    Some(format!("Session auto-amended exact deny `{rule}`."))
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
async fn maybe_promote_deny_shape(
    config: &ServerConfig,
    binary: &str,
    args: &[String],
    command_line: &str,
    reason: &str,
) {
    let outcome = match config
        .evaluator
        .record_learned_denial(binary, args, command_line, reason)
        .await
    {
        Ok(Some(outcome)) => outcome,
        Ok(None) => return,
        Err(err) => {
            tracing::warn!("failed to record deny-shape observation: {}", err);
            return;
        }
    };
    if !outcome.ready_to_synthesize {
        return;
    }
    let evaluator = config.evaluator.clone();
    tokio::spawn(async move {
        match evaluator.try_promote_deny_shape(&outcome).await {
            Ok(true) => {
                tracing::info!(
                    "[AUDIT] DENY_SHAPE_LEARNED service={} binary={} denials={}",
                    outcome.service,
                    outcome.binary,
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
async fn maybe_promote_allow_verb(
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
                tracing::info!(
                    "[AUDIT] VERB_AUTO_PROMOTED name={} binary={} consequence={} approvals={}",
                    verb.name,
                    verb.binary,
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

async fn learning_notice(config: &ServerConfig, outcome: &LearningOutcome) -> Option<String> {
    let mut notice = if outcome.is_candidate {
        format!(
            "Learned-rule candidate `{}` for `{}` reached {} approvals. This does NOT skip the \
             LLM by itself; an operator can promote it with: guard verb create --prompt \
             \"allow exactly: {}\" --binary {}.",
            outcome.pattern, outcome.service, outcome.approvals, outcome.pattern, outcome.service
        )
    } else if let Some(reason) = &outcome.skipped_reason {
        format!("Learned-rule skip: {reason}.")
    } else {
        format!(
            "Learned-rule candidate `{}` for `{}` ({}/{} approvals).",
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

pub(super) async fn persist_session_snapshot(
    session_store: Option<SessionStore>,
    snapshot: SessionRegistry,
) -> Result<()> {
    if let Some(store) = session_store {
        store.persist_registry(&snapshot).await?;
    }
    Ok(())
}

pub(super) async fn persist_current_sessions(config: &ServerConfig) -> Result<()> {
    let snapshot = { config.sessions.read().await.clone() };
    persist_session_snapshot(config.session_store.clone(), snapshot).await
}

pub(super) async fn record_live_session_interaction(
    config: &ServerConfig,
    token: Option<&str>,
    interaction: SessionInteraction,
) {
    let Some(token) = token else {
        return;
    };
    let snapshot = {
        let mut reg = config.sessions.write().await;
        if reg.has(token) {
            reg.record_interaction(token, interaction);
            Some(reg.clone())
        } else {
            None
        }
    };
    if let Some(snapshot) = snapshot {
        if let Err(err) = persist_session_snapshot(config.session_store.clone(), snapshot).await {
            tracing::warn!("failed to persist session interaction: {}", err);
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct ExecCallerContext {
    #[cfg(unix)]
    uid: u32,
    #[cfg(unix)]
    pub(super) gid: u32,
    username: String,
    pub(super) home_dir: PathBuf,
}

#[cfg(unix)]
pub(super) fn resolve_exec_caller_context(uid: u32) -> Result<ExecCallerContext> {
    let user = uzers::get_user_by_uid(uid)
        .ok_or_else(|| anyhow::anyhow!("caller uid {} does not exist in passwd", uid))?;
    let username = user
        .name()
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("caller uid {} has a non-utf8 username", uid))?
        .to_string();
    Ok(ExecCallerContext {
        uid,
        gid: user.primary_group_id(),
        username,
        home_dir: user.home_dir().to_path_buf(),
    })
}

#[cfg(unix)]
fn apply_exec_identity(
    cmd: &mut Command,
    config: &ServerConfig,
    caller: &CallerIdentity,
) -> Result<Option<ExecCallerContext>> {
    if !config.exec_as_caller {
        return Ok(None);
    }

    let caller_uid = match caller {
        CallerIdentity::Unix { uid } => *uid,
        _ => bail!("exec-as-caller requires a unix socket caller"),
    };
    let context = resolve_exec_caller_context(caller_uid)?;
    let username = CString::new(context.username.clone())
        .context("caller username contains an interior NUL byte")?;
    let gid = context.gid;

    cmd.gid(gid);
    cmd.uid(context.uid);
    unsafe {
        cmd.pre_exec(move || {
            if libc::initgroups(username.as_ptr(), gid as _) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    Ok(Some(context))
}

#[cfg(not(unix))]
fn apply_exec_identity(
    _cmd: &mut Command,
    config: &ServerConfig,
    _caller: &CallerIdentity,
) -> Result<Option<ExecCallerContext>> {
    if config.exec_as_caller {
        bail!("--exec-as-caller is not supported on this platform");
    }
    Ok(None)
}

/// Strip inherited capabilities from a brokered child before `execve`.
///
/// Under the packaged unit the daemon holds `CAP_FOWNER` and
/// `CAP_DAC_READ_SEARCH` in its ambient set so its own `grant-read` `setfacl`/
/// `getfacl` calls can manipulate ACLs on files it does not own. Ambient
/// capabilities are, by design, preserved across `execve()` for a non-privileged
/// process, so without this every caller-requested command (a plain
/// `cat /etc/shadow`, an `ansible-playbook` reading arbitrary files) would
/// inherit those capabilities and bypass file DAC entirely -- `CAP_DAC_READ_SEARCH`
/// bypasses file read permission checks and `CAP_FOWNER` bypasses the file-owner
/// checks `chmod`/`setfacl` enforce -- defeating the scoped, policy-gated read
/// grants. This clears the ambient set (so nothing survives `execve`) and zeroes
/// the inheritable set (so a target binary carrying its own file-inheritable caps
/// cannot pick anything up via the `P(inh) & F(inh)` intersection).
///
/// Applies only inside the forked child via `pre_exec`; the long-lived daemon
/// keeps its capabilities for its own direct `setfacl`/`getfacl` `Command`s,
/// which are separate and never pass through here. Clearing capabilities needs
/// no privilege (only raising them does), so it is safe under both the default
/// service-identity model and `--exec-as-caller`.
///
/// The capget/capset structs and version magic are declared here because the
/// `libc` crate does not expose `capget`/`capset` or the `cap_user_*` types; the
/// calls go through `libc::syscall` with the stable `SYS_capget`/`SYS_capset`
/// numbers.
#[cfg(all(unix, target_os = "linux"))]
#[repr(C)]
struct CapUserHeader {
    version: u32,
    pid: libc::c_int,
}

#[cfg(all(unix, target_os = "linux"))]
#[repr(C)]
#[derive(Clone, Copy)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// `_LINUX_CAPABILITY_VERSION_3` from `<linux/capability.h>` (64-bit caps).
#[cfg(all(unix, target_os = "linux"))]
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[cfg(unix)]
fn drop_brokered_child_capabilities(cmd: &mut Command) {
    // SAFETY: the closure runs in the forked child after `fork()` and before
    // `execve`. It calls only async-signal-safe raw syscalls (prctl/capget/
    // capset) and performs no allocation.
    unsafe {
        cmd.pre_exec(|| {
            #[cfg(target_os = "linux")]
            {
                // 1. Clear the ambient set: these are the capabilities that would
                //    otherwise be preserved across `execve` for a non-privileged
                //    process.
                if libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                ) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                // 2. Zero the inheritable set. Reading the current sets first and
                //    only clearing `inheritable` leaves `permitted`/`effective`
                //    untouched (they collapse to the ambient set at `execve`
                //    anyway for a non-privileged target). Dropping bits is always
                //    permitted; only raising them requires CAP_SETPCAP.
                let mut header = CapUserHeader {
                    version: LINUX_CAPABILITY_VERSION_3,
                    pid: 0,
                };
                let mut data = [CapUserData {
                    effective: 0,
                    permitted: 0,
                    inheritable: 0,
                }; 2];
                if libc::syscall(
                    libc::SYS_capget,
                    &mut header as *mut CapUserHeader,
                    data.as_mut_ptr(),
                ) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                data[0].inheritable = 0;
                data[1].inheritable = 0;
                if libc::syscall(
                    libc::SYS_capset,
                    &header as *const CapUserHeader,
                    data.as_ptr(),
                ) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

/// Execute a command the policy layer has already approved.
///
/// Entered from either the LLM evaluator path or a session-grant allow
/// match. Failures returned from here are exec-level, not policy-level,
/// so the audit stream can tell "policy said no" apart from "policy
/// said yes but the kernel refused".
/// TTL for a read grant issued by the transparent retry path. Shorter than an
/// explicit `grant-read` default: the grant exists to unblock the one command
/// that just failed, not to stand open.
#[cfg(unix)]
const AUTO_READ_GRANT_TTL_SECS: u64 = 600;

/// Cap on grant+retry rounds for one command (a run may trip over several
/// operator files in sequence, e.g. an inventory and a vars file).
#[cfg(unix)]
const AUTO_READ_GRANT_MAX_ROUNDS: usize = 3;

/// Extract the absolute file path named by a permission-denied error line, if
/// any. Understands the common shapes: `cat: /path: Permission denied`,
/// `[Errno 13] Permission denied: '/path'`, and `open /path: permission
/// denied`.
#[cfg(unix)]
pub(super) fn permission_denied_path(output: &str) -> Option<String> {
    for line in output.lines() {
        let lower = line.to_ascii_lowercase();
        if !(lower.contains("permission denied") || lower.contains("eacces")) {
            continue;
        }
        // Quoted path first (Python/ansible: `... denied: '/path'`).
        for quote in ['\'', '"'] {
            for (i, chunk) in line.split(quote).enumerate() {
                if i % 2 == 1 && chunk.starts_with('/') {
                    return Some(chunk.to_string());
                }
            }
        }
        // Plain token (coreutils/Go: `cat: /path: Permission denied`).
        for token in line.split_whitespace() {
            let t = token.trim_matches(|c: char| {
                matches!(
                    c,
                    ',' | ':' | ';' | '(' | ')' | '[' | ']' | '<' | '>' | '\'' | '"'
                )
            });
            if t.starts_with('/') && t.len() > 1 {
                return Some(t.to_string());
            }
        }
    }
    None
}

/// Execute an approved command; when it fails naming a file it could not read,
/// transparently run the read-grant pipeline on that file (credential
/// deny-list, session rules, evaluator, pinned TTL ACL, full audit — exactly
/// as an explicit `grant-read`) and retry the command. A denied or failed
/// grant returns the original failure untouched; each round must unblock a
/// new path or the loop stops. The agent never has to know `grant-read`
/// exists, and nothing is granted that an explicit request would not get.
pub(super) async fn exec_with_read_grant_retry<W: AsyncWrite + Unpin>(
    request: ExecuteRequest,
    config: &ServerConfig,
    caller: &CallerIdentity,
    allow_reason: String,
    depth: u32,
    stream_output: bool,
    stream_writer: &mut W,
) -> ExecuteResult {
    #[cfg(not(unix))]
    {
        exec_after_approval(
            request,
            config,
            caller,
            allow_reason,
            depth,
            stream_output,
            stream_writer,
        )
        .await
    }
    #[cfg(unix)]
    {
        let mut result = exec_after_approval(
            request.clone(),
            config,
            caller,
            allow_reason.clone(),
            depth,
            stream_output,
            stream_writer,
        )
        .await;
        let mut granted: std::collections::HashSet<String> = std::collections::HashSet::new();
        loop {
            if granted.len() >= AUTO_READ_GRANT_MAX_ROUNDS {
                break;
            }
            let ExecOutcome::Completed {
                exit_code,
                stdout,
                stderr,
            } = &result.exec
            else {
                break;
            };
            if !matches!(exit_code, Some(c) if *c != 0) {
                break;
            }
            let combined = format!(
                "{}\n{}",
                stderr.as_deref().unwrap_or(""),
                stdout.as_deref().unwrap_or("")
            );
            let Some(path) = permission_denied_path(&combined) else {
                break;
            };
            if !granted.insert(path.clone()) {
                // The grant did not unblock this path; do not loop on it.
                break;
            }
            let grant = handle_grant_read(
                config,
                caller,
                path.clone(),
                AUTO_READ_GRANT_TTL_SECS,
                request.session_token.clone(),
                false,
            )
            .await;
            if !(grant.policy_allowed() && matches!(grant.exec, ExecOutcome::Completed { .. })) {
                // Denied (credential path, session deny, evaluator) or the ACL
                // failed to apply: surface the command's own failure.
                break;
            }
            tracing::info!(
                "[AUDIT] READ_GRANT_AUTO caller={} path=\"{}\" ttl={}s (retrying after permission denied)",
                caller,
                path,
                AUTO_READ_GRANT_TTL_SECS
            );
            result = exec_after_approval(
                request.clone(),
                config,
                caller,
                allow_reason.clone(),
                depth,
                stream_output,
                stream_writer,
            )
            .await;
        }
        result
    }
}

pub(super) async fn exec_after_approval<W: AsyncWrite + Unpin>(
    request: ExecuteRequest,
    config: &ServerConfig,
    caller: &CallerIdentity,
    allow_reason: String,
    depth: u32,
    stream_output: bool,
    stream_writer: &mut W,
) -> ExecuteResult {
    if config.dry_run {
        tracing::info!(
            "Dry-run: not executing {} {:?} ({})",
            request.binary,
            request.args,
            caller
        );
        // Under gating, even the execute-now (reversible) path reports honest
        // coverage; off-gate keeps the legacy byte-identical dry-run.
        return if config.gate.is_on() {
            ExecuteResult::dry_run_gated(allow_reason, Coverage::dry_run())
        } else {
            ExecuteResult::dry_run(allow_reason)
        };
    }

    let user_key = caller.user_key();
    let caller_principal = caller.principal();
    let tool_env = {
        let mut reg = config.tool_registry.write().await;
        let _ = reg.reload_if_stale();
        reg.resolve_env(
            &request.binary,
            &config.secrets,
            caller_principal.as_ref(),
            user_key.as_deref(),
        )
        .await
    };
    let tool_env = match tool_env {
        Ok(env) => env,
        Err(e) => {
            return ExecuteResult::exec_failed(allow_reason, format!("tool config error: {}", e));
        }
    };
    let mut tool_env = tool_env;

    for key in request.env.keys().chain(request.secrets.keys()) {
        if !is_valid_env_name(key) {
            return ExecuteResult::exec_failed(
                allow_reason,
                format!("invalid injected environment variable name: '{}'", key),
            );
        }
    }

    // Per-run --env injection is honored for any authenticated local caller
    // (a Unix uid OR a Windows SID), but never for an unauthenticated/TCP
    // caller, which has no trusted local identity. The daemon sets the child
    // environment at spawn; the agent is a different process and cannot read
    // the child's environment, so this does not leak across callers.
    if !request.env.is_empty() && !caller.is_local_peer() {
        return ExecuteResult::exec_failed(
            allow_reason,
            "per-run --env injection requires an authenticated local caller".to_string(),
        );
    }
    for (key, value) in &request.env {
        tool_env.insert(key.clone(), value.clone());
    }

    // Per-run --secret injection is honored for any authenticated local caller
    // (Unix uid OR Windows SID); secrets are resolved from that caller's own
    // namespace via its principal. Required only when the request asks for
    // secrets; a request with none proceeds on any transport. An
    // unauthenticated/TCP caller has no principal and is refused.
    if !request.secrets.is_empty() {
        let principal = match caller.principal() {
            Some(principal) if caller.is_local_peer() => principal,
            _ => {
                return ExecuteResult::exec_failed(
                    allow_reason,
                    "secret injection requires an authenticated local caller".to_string(),
                );
            }
        };
        for (env_var, secret_key) in &request.secrets {
            let value = match config.secrets.get(&principal, secret_key).await {
                Ok(Some(value)) => value,
                Ok(None) => {
                    return ExecuteResult::exec_failed(
                        allow_reason,
                        format!(
                            "secret not found: '{}' (required by --secret {})",
                            secret_key, env_var
                        ),
                    );
                }
                Err(e) => {
                    return ExecuteResult::exec_failed(
                        allow_reason,
                        format!("failed to read secret '{}': {}", secret_key, e),
                    );
                }
            };
            tool_env.insert(env_var.clone(), value);
        }
    }

    tracing::info!(
        "Executing: {} {:?} ({})",
        request.binary,
        request.args,
        caller
    );

    let mut cmd = Command::new(&request.binary);
    cmd.args(&request.args);
    cmd.stdin(Stdio::null());

    // SECURITY: Clear ALL inherited env vars. The child process gets only what we
    // explicitly allow. This prevents leaking the guard's own secrets (API keys,
    // auth tokens) via env, printenv, /proc/self/environ, or $VAR expansion.
    cmd.env_clear();

    for var in child_env_allowlist() {
        if let Ok(val) = std::env::var(var) {
            cmd.env(var, val);
        }
    }

    // Operator-declared passthroughs (GUARD_CHILD_ENV): forward these daemon
    // env vars to the child so brokered credentials reach a tool generically.
    // The value comes from the DAEMON's environment (not the caller), so an
    // agent cannot introduce one here; e.g. KUBECONFIG points kubectl at a config
    // only the daemon can read.
    for var in &config.extra_child_env {
        if let Ok(val) = std::env::var(var) {
            cmd.env(var, val);
        }
    }

    let exec_caller = match apply_exec_identity(&mut cmd, config, caller) {
        Ok(context) => context,
        Err(e) => {
            return ExecuteResult::exec_failed(allow_reason, format!("exec identity error: {}", e));
        }
    };

    // Drop the daemon's grant-read capabilities (CAP_FOWNER / CAP_DAC_READ_SEARCH)
    // from the brokered child so they never survive execve into a caller-requested
    // command. Applies to both the default and --exec-as-caller models.
    #[cfg(unix)]
    drop_brokered_child_capabilities(&mut cmd);

    for (key, value) in &tool_env {
        cmd.env(key, value);
    }

    if let Some(context) = &exec_caller {
        cmd.env("HOME", &context.home_dir);
        cmd.env("USER", &context.username);
        cmd.env("LOGNAME", &context.username);
        cmd.env_remove("SSH_AUTH_SOCK");
        cmd.env_remove("XDG_RUNTIME_DIR");
        #[cfg(unix)]
        {
            let runtime_dir = PathBuf::from(format!("/run/user/{}", context.uid));
            if runtime_dir.exists() {
                cmd.env("XDG_RUNTIME_DIR", runtime_dir);
            }
        }
    }

    cmd.env("GUARD_DEPTH", (depth + 1).to_string());

    // Nested-eval shims are a Unix construct; on Windows, prepending a shim dir
    // only widens CreateProcess's bare-name search path with no benefit, so it is
    // skipped there.
    #[cfg(unix)]
    if let Some(ref shim_dir) = config.shim_dir {
        if let Some(path) = path_with_shim_dir(shim_dir) {
            cmd.env("PATH", path);
        }
    }

    // On Windows, pin the child working directory to a fixed system directory so
    // the inherited (daemon) CWD is not part of CreateProcess's bare-name search
    // order, removing a path by which a planted executable could shadow the
    // intended binary.
    #[cfg(windows)]
    if let Some(sysroot) = std::env::var_os("SystemRoot") {
        cmd.current_dir(sysroot);
    }

    if stream_output {
        return execute_spawn_streaming(
            cmd,
            &request.binary,
            allow_reason,
            config,
            &tool_env,
            stream_writer,
        )
        .await;
    }

    let output = match cmd.output().await {
        Ok(o) => o,
        Err(e) => {
            return ExecuteResult::exec_failed(
                allow_reason,
                format!("failed to execute '{}': {}", request.binary, e),
            );
        }
    };

    let stdout = if output.stdout.is_empty() {
        None
    } else {
        let raw = &output.stdout[..output.stdout.len().min(MAX_OUTPUT_BYTES)];
        let s = String::from_utf8_lossy(raw).to_string();
        Some(redact_command_text(config, &tool_env, s))
    };

    let stderr = if output.stderr.is_empty() {
        None
    } else {
        let raw = &output.stderr[..output.stderr.len().min(MAX_OUTPUT_BYTES)];
        let s = String::from_utf8_lossy(raw).to_string();
        Some(redact_command_text(config, &tool_env, s))
    };

    ExecuteResult::completed(allow_reason, output.status.code(), stdout, stderr)
}

#[derive(Debug)]
struct StreamChunk {
    stream: OutputStream,
    data: String,
}

async fn execute_spawn_streaming<W: AsyncWrite + Unpin>(
    mut cmd: Command,
    binary: &str,
    allow_reason: String,
    config: &ServerConfig,
    tool_env: &HashMap<String, String>,
    writer: &mut W,
) -> ExecuteResult {
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            return ExecuteResult::exec_failed(
                allow_reason,
                format!("failed to execute '{}': {}", binary, e),
            );
        }
    };

    let (tx, mut rx) = mpsc::channel::<StreamChunk>(32);
    let mut stream_tasks = Vec::new();

    if let Some(stdout) = child.stdout.take() {
        let tx = tx.clone();
        stream_tasks.push(tokio::spawn(async move {
            forward_stream_lines(stdout, OutputStream::Stdout, tx).await;
        }));
    }

    if let Some(stderr) = child.stderr.take() {
        let tx = tx.clone();
        stream_tasks.push(tokio::spawn(async move {
            forward_stream_lines(stderr, OutputStream::Stderr, tx).await;
        }));
    }

    drop(tx);

    let mut stdout_redaction = RedactionState::default();
    let mut stderr_redaction = RedactionState::default();
    let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        tokio::select! {
            maybe_chunk = rx.recv() => {
                match maybe_chunk {
                    Some(chunk) => {
                    let redaction_state = match chunk.stream {
                        OutputStream::Stdout => &mut stdout_redaction,
                        OutputStream::Stderr => &mut stderr_redaction,
                    };
                    let data = redact_command_text_with_state(config, tool_env, chunk.data, redaction_state);
                    let message = match chunk.stream {
                        OutputStream::Stdout => ExecuteStreamMessage::Stdout { data },
                        OutputStream::Stderr => ExecuteStreamMessage::Stderr { data },
                    };

                    if let Err(e) = write_stream_message(writer, &message).await {
                        let _ = child.kill().await;
                        return ExecuteResult::exec_failed_after_start(
                            allow_reason,
                            format!("client stream error: {}", e),
                        );
                    }
                    }
                    None => break,
                }
            }
            _ = keepalive.tick() => {
                if let Err(e) = write_stream_message(writer, &ExecuteStreamMessage::Keepalive).await {
                    let _ = child.kill().await;
                    return ExecuteResult::exec_failed_after_start(
                        allow_reason,
                        format!("client stream error: {}", e),
                    );
                }
            }
        }
    }

    for task in stream_tasks {
        let _ = task.await;
    }

    let status = match child.wait().await {
        Ok(status) => status,
        Err(e) => {
            return ExecuteResult::exec_failed(
                allow_reason,
                format!("failed to wait for '{}': {}", binary, e),
            );
        }
    };

    ExecuteResult::completed(allow_reason, status.code(), None, None)
}

async fn forward_stream_lines<R>(reader: R, stream: OutputStream, tx: mpsc::Sender<StreamChunk>)
where
    R: AsyncRead + Unpin,
{
    let mut reader = BufReader::new(reader);

    loop {
        let mut data = String::new();
        match reader.read_line(&mut data).await {
            Ok(0) => break,
            Ok(_) => {
                if tx.send(StreamChunk { stream, data }).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                let _ = tx
                    .send(StreamChunk {
                        stream: OutputStream::Stderr,
                        data: format!("guard stream read error: {}\n", e),
                    })
                    .await;
                break;
            }
        }
    }
}

fn redact_command_text(
    config: &ServerConfig,
    tool_env: &HashMap<String, String>,
    text: String,
) -> String {
    redact_command_text_inner(config, tool_env, text, None)
}

fn redact_command_text_with_state(
    config: &ServerConfig,
    tool_env: &HashMap<String, String>,
    text: String,
    state: &mut RedactionState,
) -> String {
    redact_command_text_inner(config, tool_env, text, Some(state))
}

fn redact_command_text_inner(
    config: &ServerConfig,
    tool_env: &HashMap<String, String>,
    text: String,
    state: Option<&mut RedactionState>,
) -> String {
    if !config.redact {
        return text;
    }

    let secret_refs: Vec<&str> = config
        .redact_secrets
        .iter()
        .map(|s| s.as_str())
        .chain(tool_env.values().map(|s| s.as_str()))
        .collect();

    // First: exact-match redaction catches bare secret values in output.
    let text = redact_exact_secrets(&text, &secret_refs);
    // Then: regex and context-based redaction catches KEY=value, YAML env
    // pairs, PEM blocks, etc.
    if let Some(state) = state {
        let had_trailing_newline = text.ends_with('\n');
        let mut redacted = text
            .lines()
            .map(|line| redact_output_with_state(line, state))
            .collect::<Vec<_>>()
            .join("\n");
        if had_trailing_newline {
            redacted.push('\n');
        }
        redacted
    } else {
        redact_output_text(&text)
    }
}

/// The evaluator context fragment appended when the caller supplied a rollback
/// under the consequence gate. It informs the marginal approve/deny decision
/// only; the deterministic post-approval routing in `decide_gate` (and the
/// separate rollback assessment before an envelope arms) is unaffected.
const REVERT_AVAILABLE_CONTEXT: &str = "REVERSIBILITY CONTEXT. The caller supplied a rollback \
command for this action. If you approve and classify it as recoverable, the daemon validates the \
rollback separately and executes the action inside an auto-revert containment envelope that rolls \
it back unattended unless an operator confirms. A constructible rollback may justify approving a \
borderline recoverable action; it never justifies approving an irreversible or high-risk one, and \
it does not change your reversibility classification duties.";

/// Merge the session prompt with the revert-availability fragment. Returns
/// `None` only when neither applies, preserving the cache semantics: any
/// non-empty append bypasses the decision cache.
pub(super) fn merge_revert_context(
    session_prompt: Option<String>,
    revert_supplied: bool,
) -> Option<String> {
    match (session_prompt, revert_supplied) {
        (sp, false) => sp,
        (None, true) => Some(REVERT_AVAILABLE_CONTEXT.to_string()),
        (Some(sp), true) if sp.trim().is_empty() => Some(REVERT_AVAILABLE_CONTEXT.to_string()),
        (Some(sp), true) => Some(format!("{REVERT_AVAILABLE_CONTEXT}\n\n{sp}")),
    }
}
