use crate::injection::is_valid_env_name;
use crate::session::{
    session_token_fingerprint, CredentialReference, SessionAmendment, SessionDecision,
    SessionDecisionSource, SessionEvaluatorPosture, SessionExecStatus, SessionInteraction,
    SessionOwner, SessionRegistry,
};
use crate::session_store::SessionStore;
use crate::tool_config::{ResolvedToolEnv, ToolRegistry};
use anyhow::{bail, Context, Result};
use guard::gating::coverage::{
    baseline_override_applies, resolve_scoped_matches, LearnedDenyMatchPolicy, ScopedCoverageMatch,
    VerbDecision, VerbResolution,
};
use guard::gating::verb::{CoverageAction, VerbCatalog};
use guard::gating::{Coverage, DecisionTrace};
use guard::redact::{
    command_contains_exact_secrets, command_line, redact_command_line, redact_exact_secrets,
    redact_output_text, redact_output_with_state, ExactSecretStreamRedactor, RedactionState,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::process::Command;
use tokio::sync::mpsc;
#[cfg(unix)]
use uzers::os::unix::UserExt;

use super::gate_runtime::{
    binary_allowed, route_gated_allow, GateInputs, SessionAuthoritySnapshot,
};
#[cfg(unix)]
use super::grants::handle_grant_read;
use super::learning::{
    learning_notice, maybe_auto_amend_session_after_llm, maybe_promote_allow_verb,
    maybe_promote_deny_shape,
};
#[cfg(unix)]
use super::path_with_shim_dir;
use super::runtime::{NotifyEvent, ProcessGuard};
use super::transport::{write_policy_decision, write_stream_message};
#[cfg(unix)]
use super::wire::ExecOutcome;
use super::wire::{
    authorize_session_use, decision_verb_match, verb_trust_is_current, CallerIdentity,
    ExecuteRequest, ExecuteResult, ExecuteStreamMessage, OutputStream, RevertSpec, SessionAuthz,
    SshHostKeyMode, VerbContext, VerbMatchInfo, VerbMatchScope, SESSION_PRINCIPAL_MISMATCH,
    SESSION_UNOWNED_REFUSED,
};
use super::{
    binary_exists_on_path, child_env_allowlist, configured_credential_path_deny_reason,
    dangerous_env_name, deterministic_credential_deny_reason, deterministic_safe_allow_reason,
    validate_request_injections, RequestContext, ServerContext, MAX_GUARD_DEPTH, MAX_OUTPUT_BYTES,
};
#[cfg(windows)]
use super::{binary_path_candidates, is_executable_path};
use super::{DEFAULT_CONFIRM_WITHIN_SECS, MAX_CONFIRM_WITHIN_SECS};

type ExecuteError = Box<ExecuteResult>;

/// Emit the ALLOWED/DENIED policy record for one execute request. Returns
/// whether the record is durable; an allow that cannot be durably audited
/// must fail closed before anything acts on it.
#[must_use]
pub(super) fn log_audit_policy_for_request(
    server: &ServerContext,
    caller: &CallerIdentity,
    request: &ExecuteRequest,
    allowed: bool,
    reason: &str,
) -> bool {
    if let Some(cwd) = &request.cwd {
        let kind = if allowed {
            guard::audit::AuditKind::Allowed
        } else {
            guard::audit::AuditKind::Denied
        };
        server.emit_audit(
            guard::audit::AuditEvent::new(kind)
                .caller(caller)
                .session_fingerprint(audit_session_fingerprint(request.session_token.as_deref()))
                .cwd(cwd.display().to_string())
                .cmd(server.redact_command_line(&request.binary, &request.args))
                .reason(reason),
        )
    } else {
        server.log_audit_policy(
            caller,
            request.session_token.as_deref(),
            &request.binary,
            &request.args,
            allowed,
            reason,
        )
    }
}

/// Stable correlation identifier for a session without exposing any bearer
/// token bytes. This can be joined to persisted session interactions by hashing
/// the operator-held token with the same function.
pub(super) fn audit_session_fingerprint(token: Option<&str>) -> String {
    let Some(token) = token.filter(|token| !token.is_empty()) else {
        return "none".to_string();
    };
    session_token_fingerprint(token)
}

pub(super) async fn execute_command(
    request: ExecuteRequest,
    server: &ServerContext,
    caller: &CallerIdentity,
) -> ExecuteResult {
    let mut sink = tokio::io::sink();
    let result = execute_command_inner(request, server, caller, false, &mut sink).await;
    let audience = super::admin::AccessAudience::from_caller(server, caller);
    result.with_operator_guidance(audience.is_operator())
}

pub(super) async fn execute_command_streaming<W: AsyncWrite + Unpin>(
    request: ExecuteRequest,
    server: &ServerContext,
    caller: &CallerIdentity,
    writer: &mut W,
) -> ExecuteResult {
    let result = execute_command_inner(request, server, caller, true, writer).await;
    let audience = super::admin::AccessAudience::from_caller(server, caller);
    result.with_operator_guidance(audience.is_operator())
}

async fn execute_command_inner<W: AsyncWrite + Unpin>(
    mut request: ExecuteRequest,
    server: &ServerContext,
    caller: &CallerIdentity,
    stream_output: bool,
    stream_writer: &mut W,
) -> ExecuteResult {
    // Local access authority is selected by the kernel-authenticated principal.
    // Replace only an unknown or expired supplied handle; a known handle stays
    // attached so the owner check below rejects cross-principal use.
    if caller.is_local_peer() {
        if let Some(principal) = caller.principal() {
            let sessions = server.state.sessions.read().await;
            let supplied_session_is_known = request
                .session_token
                .as_deref()
                .is_some_and(|token| sessions.owner_for(token).is_some());
            if request.session_token.is_none() || !supplied_session_is_known {
                if let Some(token) =
                    super::admin::access_token_for_principal_ci(&sessions, &principal)
                {
                    request.session_token = Some(token);
                }
            }
        }
    }
    let admission_scope = caller.to_string();
    let _handler_permit = match server
        .state
        .command_admission
        .admit_handler(&admission_scope)
    {
        Ok(permit) => permit,
        Err(reason) => {
            let _ = log_audit_policy_for_request(server, caller, &request, false, reason);
            return ExecuteResult::denied(reason);
        }
    };
    let mut phase = ExecPhase {
        server,
        caller,
        stream_output,
        stream_writer,
        session_token: request.session_token.clone(),
        verb_matches: Vec::new(),
        verb_guidance: None,
    };

    // Classify the final attached token after local-principal selection, so
    // daemon-selected and client-supplied access authority share one path.
    // Session authority is owner-bound before any catalog lookup. A replayed
    // bearer therefore cannot reveal foreign session verbs, match precedence,
    // or approval guidance through the pre-validation resolution path.
    let attached_access_overlay = if let Some(token) = request.session_token.as_deref() {
        let (refusal, access_managed) = {
            let sessions = server.state.sessions.read().await;
            match sessions.owner_for(token) {
                None => (
                    Some(format!(
                        "unknown session token: '{token}' is revoked, expired, or never existed"
                    )),
                    false,
                ),
                Some(SessionOwner::Unowned) => (
                    Some(format!("session '{token}' {SESSION_UNOWNED_REFUSED}")),
                    false,
                ),
                Some(owner) => match authorize_session_use(
                    &owner,
                    caller,
                    server.config.allow_windows_system_operator,
                ) {
                    SessionAuthz::Allowed => (None, sessions.is_access_managed(token)),
                    SessionAuthz::Mismatch => (
                        Some(format!(
                            "{SESSION_PRINCIPAL_MISMATCH}: caller {caller} is not the owner of session '{token}'"
                        )),
                        false,
                    ),
                    SessionAuthz::Unowned => (
                        Some(format!("session '{token}' {SESSION_UNOWNED_REFUSED}")),
                        false,
                    ),
                },
            }
        };
        if let Some(reason) = refusal {
            server.audit_deny(caller, None, &request.binary, &request.args, &reason);
            let _ = write_policy_decision(stream_output, &mut *phase.stream_writer, false, &reason)
                .await;
            return ExecuteResult::denied(reason);
        }
        access_managed
    } else {
        false
    };

    if let Err(result) = canonicalize_request_cwd(&mut phase, &mut request).await {
        return *result;
    }
    if let Err(result) = bind_default_request_cwd(&mut phase, &mut request).await {
        return *result;
    }

    let request_before_verb_resolution = request.clone();
    let mut verb_resolution = match resolve_verb_context(&mut phase, &mut request).await {
        Ok(resolution) => resolution,
        Err(result) => return *result,
    };
    phase.verb_matches = verb_resolution.matches.clone();
    phase.verb_guidance = verb_resolution.guidance.clone();

    // Persisted access-managed authority is an additive overlay regardless of
    // whether the client supplied its token or the daemon selected it for the
    // authenticated principal. Detach an unmatched overlay before policy
    // validation so unrelated commands follow the caller's baseline policy.
    // Restoring the pre-resolution request also discards session-derived
    // rendering and revert state. Ordinary explicit sessions remain attached
    // and policy-only.
    if attached_access_overlay && selected_session_verbs(&phase).is_empty() {
        request = request_before_verb_resolution;
        request.session_token = None;
        phase.session_token = None;
        verb_resolution = match resolve_verb_context(&mut phase, &mut request).await {
            Ok(resolution) => resolution,
            Err(result) => return *result,
        };
        phase.verb_matches = verb_resolution.matches.clone();
        phase.verb_guidance = verb_resolution.guidance.clone();
    }

    let (depth, command_line) = match validate_exec_request(&mut phase, &request).await {
        Ok(validated) => validated,
        Err(result) => {
            return (*result).with_verb_resolution(
                verb_resolution.matches.clone(),
                verb_resolution.guidance.clone(),
            )
        }
    };

    let result = execute_after_verb_resolution(
        &mut phase,
        request,
        verb_resolution.clone(),
        command_line,
        depth,
    )
    .await;
    result.with_verb_resolution(phase.verb_matches.clone(), phase.verb_guidance.clone())
}

async fn execute_after_verb_resolution<W: AsyncWrite + Unpin>(
    phase: &mut ExecPhase<'_, W>,
    mut request: ExecuteRequest,
    verb_resolution: VerbResolution,
    command_line: String,
    depth: u32,
) -> ExecuteResult {
    if let Err(result) = enforce_binary_policy(phase, &request).await {
        return *result;
    }

    if matches!(verb_resolution.decision, VerbDecision::Deny) {
        let reason = verb_resolution
            .guidance
            .clone()
            .unwrap_or_else(|| "typed verb coverage denied this command".to_string());
        let decision_source = typed_verb_deny_decision_source(&verb_resolution);
        return deny_and_record(phase, &request, decision_source, None, reason).await;
    }

    let approved_access_evaluation =
        access_evaluation_is_approved(phase, &request, &verb_resolution).await;
    let force_evaluate = !approved_access_evaluation
        && matches!(
            verb_resolution.decision,
            VerbDecision::Evaluate | VerbDecision::Conflict
        );

    request = match apply_session_rules(
        phase,
        request,
        &verb_resolution.context,
        depth,
        force_evaluate,
    )
    .await
    {
        Ok(request) => request,
        Err(result) => return *result,
    };

    let mut session_prompt = resolve_session_prompt(phase.server, &request).await;
    if let Some(conflict_prompt) = &verb_resolution.conflict_prompt {
        session_prompt = Some(match session_prompt {
            Some(prompt) => format!("{prompt}\n\n{conflict_prompt}"),
            None => conflict_prompt.clone(),
        });
    }

    if !force_evaluate {
        request =
            match try_trusted_verb_allow(phase, request, &verb_resolution.context, depth).await {
                Ok(request) => request,
                Err(result) => return *result,
            };

        request = match try_static_fast_allow(phase, request, depth).await {
            Ok(request) => request,
            Err(result) => return *result,
        };
    }

    let exact_cwd_verb_authority = selected_verb_authority_binds_exact_cwd(&verb_resolution);
    evaluate_and_route(
        phase,
        request,
        verb_resolution.context,
        session_prompt,
        command_line,
        depth,
        EvaluationConstraints {
            unresolved_plan: verb_resolution.unresolved_plan,
            typed_evaluation_required: force_evaluate,
            exact_cwd_verb_authority,
        },
    )
    .await
}

fn selected_verb_authority_binds_exact_cwd(resolution: &VerbResolution) -> bool {
    let mut found = false;
    for matched in resolution.matches.iter().filter(|matched| matched.selected) {
        found = true;
        if !matched.exact_cwd_authorized {
            return false;
        }
    }
    found
}

fn typed_verb_deny_decision_source(resolution: &VerbResolution) -> SessionDecisionSource {
    if resolution.matches.iter().any(|matched| {
        matched.selected
            && matched.scope == VerbMatchScope::Session
            && matched.action == CoverageAction::Deny
    }) {
        SessionDecisionSource::SessionDeny
    } else {
        SessionDecisionSource::StaticPolicy
    }
}

async fn access_evaluation_is_approved<W: AsyncWrite + Unpin>(
    phase: &ExecPhase<'_, W>,
    request: &ExecuteRequest,
    resolution: &VerbResolution,
) -> bool {
    if !resolution
        .context
        .as_ref()
        .is_some_and(|context| context.access_evaluation_override_eligible)
    {
        return false;
    }
    let Some(token) = request.session_token.as_deref() else {
        return false;
    };
    let selected = selected_session_verbs(phase);
    if selected.is_empty() {
        return false;
    }
    let sessions = phase.server.state.sessions.read().await;
    sessions.is_access_managed(token) && sessions.select_access_requests(token, &selected).is_ok()
}

async fn canonicalize_request_cwd<W: AsyncWrite + Unpin>(
    phase: &mut ExecPhase<'_, W>,
    request: &mut ExecuteRequest,
) -> Result<(), ExecuteError> {
    let Some(cwd) = request.cwd.clone() else {
        return Ok(());
    };
    if !phase.caller.is_local_peer() {
        let reason =
            "working directory propagation requires an authenticated local caller".to_string();
        return Err(Box::new(
            deny_and_record(
                phase,
                request,
                SessionDecisionSource::Validation,
                None,
                reason,
            )
            .await,
        ));
    }
    if cwd.as_os_str().is_empty() || !cwd.is_absolute() {
        let reason = format!("invalid working directory: '{}'", cwd.display());
        return Err(Box::new(
            deny_and_record(
                phase,
                request,
                SessionDecisionSource::Validation,
                None,
                reason,
            )
            .await,
        ));
    }
    let canonical = match tokio::fs::canonicalize(&cwd).await {
        Ok(path) => path,
        Err(e) => {
            let reason = format!(
                "invalid working directory '{}': cannot canonicalize: {}",
                cwd.display(),
                e
            );
            return Err(Box::new(
                deny_and_record(
                    phase,
                    request,
                    SessionDecisionSource::Validation,
                    None,
                    reason,
                )
                .await,
            ));
        }
    };
    let meta = match tokio::fs::metadata(&canonical).await {
        Ok(meta) => meta,
        Err(e) => {
            let reason = format!(
                "invalid working directory '{}': cannot stat canonical path: {}",
                canonical.display(),
                e
            );
            return Err(Box::new(
                deny_and_record(
                    phase,
                    request,
                    SessionDecisionSource::Validation,
                    None,
                    reason,
                )
                .await,
            ));
        }
    };
    if !meta.is_dir() {
        let reason = format!(
            "invalid working directory '{}': not a directory",
            canonical.display()
        );
        return Err(Box::new(
            deny_and_record(
                phase,
                request,
                SessionDecisionSource::Validation,
                None,
                reason,
            )
            .await,
        ));
    }
    request.cwd = Some(canonical);
    Ok(())
}

pub(super) fn safe_default_working_directory() -> std::result::Result<PathBuf, String> {
    #[cfg(unix)]
    let candidate = PathBuf::from("/");
    #[cfg(windows)]
    let candidate = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .ok_or_else(|| {
            "safe default working directory is unavailable: SystemRoot is unset".to_string()
        })?;
    #[cfg(not(any(unix, windows)))]
    return Err("safe default working directory is unsupported on this platform".to_string());

    let canonical = candidate.canonicalize().map_err(|error| {
        format!(
            "safe default working directory '{}' cannot be canonicalized: {error}",
            candidate.display()
        )
    })?;
    if !canonical.is_absolute() || !canonical.is_dir() {
        return Err(format!(
            "safe default working directory '{}' is not an absolute directory",
            canonical.display()
        ));
    }
    Ok(canonical)
}

fn request_authority_working_directory(request: &ExecuteRequest) -> Option<&Path> {
    request.cwd.as_deref().and_then(|cwd| {
        safe_default_working_directory()
            .ok()
            .is_none_or(|safe| safe != cwd)
            .then_some(cwd)
    })
}

async fn bind_default_request_cwd<W: AsyncWrite + Unpin>(
    phase: &mut ExecPhase<'_, W>,
    request: &mut ExecuteRequest,
) -> Result<(), ExecuteError> {
    if request.cwd.is_some() {
        return Ok(());
    }
    match safe_default_working_directory() {
        Ok(cwd) => {
            request.cwd = Some(cwd);
            Ok(())
        }
        Err(reason) => Err(Box::new(
            deny_and_record(
                phase,
                request,
                SessionDecisionSource::Validation,
                None,
                reason,
            )
            .await,
        )),
    }
}

async fn revalidate_exec_cwd(cwd: &Path) -> std::result::Result<(), String> {
    let canonical = tokio::fs::canonicalize(cwd).await.map_err(|e| {
        format!(
            "working directory '{}' changed before exec: cannot canonicalize: {}",
            cwd.display(),
            e
        )
    })?;
    if canonical != cwd {
        return Err(format!(
            "working directory '{}' changed before exec: canonical path is now '{}'",
            cwd.display(),
            canonical.display()
        ));
    }
    let meta = tokio::fs::metadata(&canonical).await.map_err(|e| {
        format!(
            "working directory '{}' changed before exec: cannot stat: {}",
            canonical.display(),
            e
        )
    })?;
    if !meta.is_dir() {
        return Err(format!(
            "working directory '{}' changed before exec: not a directory",
            canonical.display()
        ));
    }
    Ok(())
}

/// Shared state threaded through the policy phases of one execute request.
///
/// A phase returning `Err(ExecuteResult)` means the request is finished
/// (denied, failed, or already executed by a fast path) and the result must
/// be returned to the caller as-is.
struct ExecPhase<'a, W> {
    server: &'a ServerContext,
    caller: &'a CallerIdentity,
    stream_output: bool,
    stream_writer: &'a mut W,
    session_token: Option<String>,
    verb_matches: Vec<VerbMatchInfo>,
    verb_guidance: Option<String>,
}

fn decision_trace_for_phase<W: AsyncWrite + Unpin>(
    phase: &ExecPhase<'_, W>,
    source: SessionDecisionSource,
    allowed: bool,
) -> DecisionTrace {
    let decision_source = source.as_str().to_string();
    DecisionTrace {
        version: DecisionTrace::VERSION,
        decision_source: decision_source.clone(),
        verb_matches: decision_trace_verb_matches(&phase.verb_matches),
        failed_dimensions: if allowed {
            Vec::new()
        } else {
            vec![decision_source]
        },
        conflict: phase
            .verb_guidance
            .as_ref()
            .filter(|guidance| guidance.to_ascii_lowercase().contains("conflict"))
            .cloned(),
        guidance: phase.verb_guidance.clone(),
        suggested_grant_delta: phase
            .verb_guidance
            .as_ref()
            .filter(|guidance| guidance.contains("grant"))
            .cloned(),
    }
}

fn decision_trace_verb_matches(matches: &[VerbMatchInfo]) -> Vec<guard::gating::DecisionVerbMatch> {
    matches.iter().map(decision_verb_match).collect()
}

fn selected_session_verbs<W: AsyncWrite + Unpin>(phase: &ExecPhase<'_, W>) -> Vec<String> {
    let mut verbs = phase
        .verb_matches
        .iter()
        .filter(|matched| {
            matched.selected
                && matched.scope == guard::gating::coverage::VerbMatchScope::Session
                && !matched.overridden
        })
        .map(|matched| matched.verb.clone())
        .collect::<Vec<_>>();
    verbs.sort();
    verbs.dedup();
    verbs
}

/// Deny bookkeeping shared by the policy phases: audit the decision, notify a
/// streaming client, record the interaction on the live session (when one is
/// attached), and produce the denied result.
async fn deny_and_record<W: AsyncWrite + Unpin>(
    phase: &mut ExecPhase<'_, W>,
    request: &ExecuteRequest,
    source: SessionDecisionSource,
    risk: Option<i32>,
    mut reason: String,
) -> ExecuteResult {
    let mut access_request_handle = None;
    let trusted_secrets = phase
        .server
        .config
        .redact_secrets
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let durable_command = guard::redact::redact_command_line_with_exact_secrets(
        &request.binary,
        &request.args,
        &trusted_secrets,
    );
    let hard_verb_deny = phase.verb_matches.iter().any(|matched| {
        matched.selected
            && !matched.overridden
            && matched.action == guard::gating::verb::CoverageAction::Deny
    });
    let static_default_deny = guard::policy::is_default_deny_reason(&reason);
    let hard_static_deny = source == SessionDecisionSource::StaticPolicy && !static_default_deny;
    let escalation_allowed = !matches!(
        source,
        SessionDecisionSource::Validation | SessionDecisionSource::EvaluatorError
    ) && !hard_verb_deny
        && !hard_static_deny;
    if !phase.server.config.admission_preview && escalation_allowed {
        if let Some(token) = phase.session_token.as_deref() {
            super::admin::prune_grant_requests(phase.server).await;
            let now = guard::env::now_unix();
            let (saved_grant, session_revision, session_expires_at, requester, access_managed) = {
                let sessions = phase.server.state.sessions.read().await;
                (
                    sessions.saved_grant_for(token),
                    sessions.effective_revision_key(token),
                    sessions.expires_at_for(token).flatten(),
                    sessions.owner_for(token),
                    sessions.is_access_managed(token),
                )
            };
            let mut denied_verbs = selected_session_verbs(phase);
            if access_managed && denied_verbs.is_empty() {
                denied_verbs = phase
                    .server
                    .state
                    .verbs
                    .read()
                    .await
                    .match_command_all(&request.binary, &request.args)
                    .into_iter()
                    .filter(|matched| !matched.rendered.baseline)
                    .map(|matched| matched.rendered.name)
                    .collect();
                denied_verbs.sort();
                denied_verbs.dedup();
            }
            let candidate = session_revision.as_ref().and_then(|session_revision| {
                let crate::session::SessionOwner::Principal(requester) = requester.clone()? else {
                    return None;
                };
                let mut request = if access_managed {
                    if denied_verbs.is_empty() {
                        return None;
                    }
                    let mut request = crate::grant_profile::GrantRequest::new_access(
                        requester,
                        Some(token.to_string()),
                        crate::session::session_reference(token),
                        crate::grant_profile::GrantRequestDelta {
                            activated_verbs: denied_verbs.clone(),
                            ..crate::grant_profile::GrantRequestDelta::default()
                        },
                        durable_command.clone(),
                    )
                    .ok()?;
                    request.authority_verbs = denied_verbs.clone();
                    request
                } else {
                    crate::grant_profile::GrantRequest::new(
                        token.to_string(),
                        saved_grant.as_ref().map(|(name, _)| name.clone()),
                        crate::grant_profile::GrantRequestDelta {
                            prompt_append: Some(format!(
                                "Evaluate this denied operation within the operator-approved task scope: {durable_command}"
                            )),
                            ..crate::grant_profile::GrantRequestDelta::default()
                        },
                        durable_command.clone(),
                    )
                    .ok()?
                };
                Some(crate::session_store::sanitize_grant_request({
                    request.saved_grant = saved_grant.as_ref().map(|(name, _)| name.clone());
                    request.issued_saved_revision = saved_grant.map(|(_, revision)| revision);
                    request.issued_session_revision = Some(session_revision.clone());
                    if access_managed {
                        request.request_key = request.canonical_access_key().ok()?;
                    }
                    if let Some(session_expires_at) = session_expires_at {
                        request.expires_unix = request.expires_unix.min(session_expires_at);
                    }
                    request
                }))
            });
            let _transition = phase.server.state.authority_transition_gate.lock().await;
            let baseline_requests = phase.server.state.grant_requests.read().await.clone();
            let queue_full = baseline_requests.len() >= super::admin::MAX_GRANT_REQUESTS
                || baseline_requests
                    .values()
                    .filter(|request| {
                        request.session_token == token
                            && request.status == crate::grant_profile::GrantRequestStatus::Pending
                    })
                    .count()
                    >= super::admin::MAX_PENDING_GRANT_REQUESTS_PER_SESSION;
            let existing = baseline_requests
                .values()
                .find(|request| {
                    request.session_token == token
                        && request.status == crate::grant_profile::GrantRequestStatus::Pending
                        && request.expires_unix > now
                        && request.issued_session_revision
                            == candidate
                                .as_ref()
                                .and_then(|candidate| candidate.issued_session_revision.clone())
                        && request.request_key
                            == candidate
                                .as_ref()
                                .map(|candidate| candidate.request_key.as_str())
                                .unwrap_or_default()
                })
                .cloned();
            let (request, created) = if let Some(existing) = existing {
                (Some(existing), false)
            } else if queue_full {
                (None, false)
            } else if let Some(candidate) = candidate {
                if super::admin::grant_request_payload_bytes(&candidate)
                    > super::admin::MAX_GRANT_REQUEST_PAYLOAD_BYTES
                {
                    (None, false)
                } else {
                    let persisted = if let Some(store) = &phase.server.state.session_store {
                        match store.save_grant_request(candidate.clone()).await {
                            Ok(()) => true,
                            Err(error) => {
                                tracing::warn!("failed to persist denial escalation: {}", error);
                                false
                            }
                        }
                    } else {
                        true
                    };
                    if persisted {
                        let mut requests = phase.server.state.grant_requests.write().await;
                        if *requests == baseline_requests {
                            requests.insert(candidate.handle.clone(), candidate.clone());
                            (Some(candidate), true)
                        } else {
                            let converged = requests
                                .values()
                                .find(|request| request.request_key == candidate.request_key)
                                .cloned();
                            (converged, false)
                        }
                    } else {
                        (None, false)
                    }
                }
            } else {
                (None, false)
            };
            if let Some(request) = request {
                if request.requester.is_some() {
                    access_request_handle = Some(request.handle.clone());
                    phase.verb_guidance = Some(super::admin::approval_guidance(
                        phase.server,
                        phase.caller,
                        &request.handle,
                        false,
                    ));
                    reason.push_str(&format!("; access_request={}", request.handle));
                } else {
                    reason.push_str(&format!(
                        "; internal authority request {} is pending operator review",
                        request.handle
                    ));
                }
                if created {
                    phase.server.emit_audit_ungated(
                        guard::audit::AuditEvent::new(
                            guard::audit::AuditKind::OperatorNotification,
                        )
                        .handle(&request.handle)
                        .field("kind", "grant_request")
                        .field("session", audit_session_fingerprint(Some(token))),
                    );
                    phase.server.emit_event(NotifyEvent {
                        event: "grant_request_created",
                        at_unix: guard::env::now_unix(),
                        handle: Some(request.handle.clone()),
                        session_fingerprint: Some(audit_session_fingerprint(Some(token))),
                        requester_principal: None,
                        reason: Some(
                            "session command denied; grant expansion requested".to_string(),
                        ),
                        status: Some("pending".to_string()),
                        behavior: None,
                    });
                }
            }
        } else if !phase.server.config.admission_preview {
            let observed_argv = Some((request.binary.as_str(), request.args.as_slice()));
            let intent = durable_command.clone();
            match super::admin::submit_access_request(
                phase.server,
                phase.caller,
                None,
                &intent,
                None,
                observed_argv,
            )
            .await
            {
                Ok(item) if item.kind == "request" => {
                    access_request_handle = Some(item.reference.clone());
                    phase.verb_guidance = Some(super::admin::approval_guidance(
                        phase.server,
                        phase.caller,
                        &item.reference,
                        false,
                    ));
                    reason.push_str(&format!("; access_request={}", item.reference));
                }
                Ok(_) => {}
                Err(error) => {
                    phase.verb_guidance = Some(format!(
                        "no durable access request was created: {}; request typed access with: guard access request {}",
                        redact_output_text(&error),
                        shell_words::join([intent.as_str()])
                    ));
                    reason.push_str("; typed access request required");
                }
            }
        }
    } else if !phase.server.config.admission_preview && (hard_verb_deny || hard_static_deny) {
        phase.verb_guidance = Some(
            "non-overridable operator policy denied this command; no access request was created"
                .to_string(),
        );
    }
    let _ = log_audit_policy_for_request(phase.server, phase.caller, request, false, &reason);
    let _ = write_policy_decision(
        phase.stream_output,
        &mut *phase.stream_writer,
        false,
        &reason,
    )
    .await;
    record_live_session_interaction(
        phase.server,
        phase.session_token.as_deref(),
        SessionInteraction {
            at_unix: 0,
            command: durable_command,
            allowed: false,
            source,
            reason: reason.clone(),
            risk,
            exec_status: SessionExecStatus::NotAttempted,
            exit_code: None,
            exposed_secret_refs: Vec::new(),
            decision_trace: Some(decision_trace_for_phase(phase, source, false)),
        },
        Vec::new(),
    )
    .await;
    ExecuteResult::denied(reason)
        .with_access_request(access_request_handle)
        .with_decision_source(source)
}

/// Allow bookkeeping shared by the gate-routed allow paths: route the
/// approved command through the consequence gate, then record the interaction
/// on the live session with the routed result's exec status.
async fn route_allow_and_record<W: AsyncWrite + Unpin>(
    phase: &mut ExecPhase<'_, W>,
    request: ExecuteRequest,
    inputs: GateInputs,
    source: SessionDecisionSource,
    depth: u32,
) -> ExecuteResult {
    let reason = inputs.reason.clone();
    let risk = inputs.risk;
    let trace = decision_trace_for_phase(phase, source, true);
    let trusted_secrets = phase
        .server
        .config
        .redact_secrets
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let interaction_command = guard::redact::redact_command_line_with_exact_secrets(
        &request.binary,
        &request.args,
        &trusted_secrets,
    );
    let mut context = RequestContext {
        server: phase.server,
        caller: phase.caller,
        depth,
        stream_output: phase.stream_output,
        stream_writer: &mut *phase.stream_writer,
    };
    let result = route_gated_allow(&mut context, request, inputs, Some(trace.clone())).await;
    let credential_references = result.credential_references().to_vec();
    record_live_session_interaction(
        phase.server,
        phase.session_token.as_deref(),
        SessionInteraction {
            at_unix: 0,
            command: interaction_command,
            allowed: true,
            source,
            reason,
            risk,
            exec_status: result.session_exec_status(),
            exit_code: result.exit_code(),
            exposed_secret_refs: Vec::new(),
            decision_trace: Some(trace),
        },
        credential_references,
    )
    .await;
    result.with_decision_source(source)
}

async fn capture_session_authority(
    server: &ServerContext,
    request: &ExecuteRequest,
) -> Result<Option<SessionAuthoritySnapshot>, String> {
    let Some(token) = request.session_token.as_deref() else {
        return Ok(None);
    };
    server
        .state
        .sessions
        .read()
        .await
        .authority_snapshot(token)
        .map(SessionAuthoritySnapshot::from)
        .map(Some)
        .ok_or_else(|| "session expired or was revoked before execution routing".to_string())
}

/// Per-process counter that hands every unauthenticated request a unique
/// evaluator-cache scope, so an unauthenticated caller can neither be served
/// nor seed another caller's cached verdict (mirrors `principal::scope_eq`).
static UNAUTHENTICATED_EVAL_SCOPE_NONCE: AtomicU64 = AtomicU64::new(0);

/// Build the evaluator decision-cache scope for this request. Binds the cached
/// verdict to the authenticated principal and, when a session is in play, to a
/// per-session fingerprint folded with the session-grant revision, so a verdict
/// decided for one user's session is never reused for another user or replayed
/// after the session's authority changes (amend, coverage change, or
/// revoke-and-reissue).
pub(super) fn evaluation_cache_scope(
    caller: &CallerIdentity,
    session_token: Option<&str>,
    authority: Option<&SessionAuthoritySnapshot>,
) -> String {
    let principal = caller.principal();
    let session = session_token.map(|token| {
        format!(
            "{}:{}",
            audit_session_fingerprint(Some(token)),
            authority
                .map(|snapshot| snapshot.revision.as_str())
                .unwrap_or("<no-revision>"),
        )
    });
    let nonce = if principal.is_none() {
        UNAUTHENTICATED_EVAL_SCOPE_NONCE.fetch_add(1, Ordering::Relaxed)
    } else {
        0
    };
    guard::principal::eval_cache_scope(principal.as_ref(), session.as_deref(), nonce)
}

#[derive(Debug, Clone, Copy)]
struct EvaluationConstraints {
    unresolved_plan: bool,
    typed_evaluation_required: bool,
    exact_cwd_verb_authority: bool,
}

#[derive(Debug, Clone)]
pub(super) struct VerbAuthorityExpectation {
    pub(super) name: String,
    pub(super) catalog_version: Option<u64>,
    pub(super) definition_digest: Option<String>,
    pub(super) composition_digest: Option<String>,
    pub(super) environment_authority: bool,
    pub(super) local_file_authority: bool,
}

impl VerbAuthorityExpectation {
    pub(super) fn from_context(context: &VerbContext) -> Self {
        Self {
            name: context.name.clone(),
            catalog_version: Some(context.catalog_version),
            definition_digest: context.verb_digest.clone(),
            composition_digest: context.composition_digest.clone(),
            environment_authority: context.environment_authority,
            local_file_authority: context.local_file_authority,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct CommandAuthorization {
    learned_deny_authority: LearnedDenyProcessStartAuthority,
    delayed_authority_source: guard::gating::approval::DelayedAuthoritySource,
    verb: Option<VerbAuthorityExpectation>,
    session: Option<SessionAuthoritySnapshot>,
    exec_timeout_secs: Option<u64>,
    process_authority: Option<guard::gating::approval::ProcessAuthorityBinding>,
    /// One in-memory resolution of every approved secret and tool mapping.
    /// This is never serialized and is carried unchanged through final spawn.
    approved_environment: Option<ApprovedEnvironmentSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LearnedDenyProcessStartAuthority {
    Enforce,
    TypedVerb,
    ApprovedReplay,
    PersistedControlCapture,
    PersistedControlReplay,
}

impl CommandAuthorization {
    pub(super) fn routed(
        verb: Option<&VerbContext>,
        session: Option<&SessionAuthoritySnapshot>,
        exec_timeout_secs: u64,
    ) -> Self {
        let learned_deny_authority = match verb
            .map(|verb| verb.learned_deny_match_policy)
            .unwrap_or(LearnedDenyMatchPolicy::Enforce)
        {
            LearnedDenyMatchPolicy::Enforce => LearnedDenyProcessStartAuthority::Enforce,
            LearnedDenyMatchPolicy::TypedVerbPreempts => {
                LearnedDenyProcessStartAuthority::TypedVerb
            }
        };
        let delayed_authority_source = if verb.is_some() {
            guard::gating::approval::DelayedAuthoritySource::TypedVerb
        } else {
            guard::gating::approval::DelayedAuthoritySource::RawApproval
        };
        Self {
            learned_deny_authority,
            delayed_authority_source,
            verb: verb.map(VerbAuthorityExpectation::from_context),
            session: session.cloned(),
            exec_timeout_secs: Some(exec_timeout_secs),
            process_authority: None,
            approved_environment: None,
        }
    }

    pub(super) fn replay(
        verb: Option<VerbAuthorityExpectation>,
        session: Option<SessionAuthoritySnapshot>,
        exec_timeout_secs: Option<u64>,
        process_authority: Option<guard::gating::approval::ProcessAuthorityBinding>,
        approved_environment: Option<ApprovedEnvironmentSnapshot>,
    ) -> Self {
        let delayed_authority_source = if verb.is_some() {
            guard::gating::approval::DelayedAuthoritySource::TypedVerb
        } else {
            guard::gating::approval::DelayedAuthoritySource::RawApproval
        };
        Self {
            // Replay executes the immutable snapshot the operator reviewed;
            // the named authority below is the only non-verb path that may
            // preempt an automatic learned-deny heuristic. Frozen verb,
            // session, secret, and process-start authority checks still run.
            learned_deny_authority: LearnedDenyProcessStartAuthority::ApprovedReplay,
            delayed_authority_source,
            verb,
            session,
            exec_timeout_secs,
            process_authority,
            approved_environment,
        }
    }

    pub(super) fn persisted_control_capture(
        exec_timeout_secs: u64,
        delayed_authority_source: guard::gating::approval::DelayedAuthoritySource,
    ) -> Self {
        Self {
            learned_deny_authority: LearnedDenyProcessStartAuthority::PersistedControlCapture,
            delayed_authority_source,
            verb: None,
            session: None,
            exec_timeout_secs: Some(exec_timeout_secs),
            process_authority: None,
            approved_environment: None,
        }
    }

    pub(super) fn persisted_control_replay(
        exec_timeout_secs: u64,
        delayed_authority_source: guard::gating::approval::DelayedAuthoritySource,
        process_authority: guard::gating::approval::ProcessAuthorityBinding,
        approved_environment: ApprovedEnvironmentSnapshot,
    ) -> Self {
        Self {
            learned_deny_authority: LearnedDenyProcessStartAuthority::PersistedControlReplay,
            delayed_authority_source,
            verb: None,
            session: None,
            exec_timeout_secs: Some(exec_timeout_secs),
            process_authority: Some(process_authority),
            approved_environment: Some(approved_environment),
        }
    }
}

fn authorization_extracts_explicit_artifacts(authorization: Option<&CommandAuthorization>) -> bool {
    authorization.is_some_and(|authorization| {
        authorization.verb.is_some()
            || matches!(
                authorization.learned_deny_authority,
                LearnedDenyProcessStartAuthority::PersistedControlCapture
                    | LearnedDenyProcessStartAuthority::PersistedControlReplay
            )
    })
}

fn authorization_revalidates_process_authority(authorization: &CommandAuthorization) -> bool {
    matches!(
        authorization.learned_deny_authority,
        LearnedDenyProcessStartAuthority::ApprovedReplay
            | LearnedDenyProcessStartAuthority::PersistedControlReplay
    )
}

fn command_delayed_authority_plan(
    request: &ExecuteRequest,
    authorization: &CommandAuthorization,
) -> Result<guard::gating::approval::DelayedAuthorityPlan, String> {
    guard::gating::verb::delayed_authority_plan(
        &request.binary,
        &request.args,
        authorization.delayed_authority_source,
    )
    .map_err(|error| format!("delayed process authority is not closed: {error}"))
}

/// Authorized execution cannot safely infer local executable authority from
/// shell, language, or command-dispatch syntax. These carriers are rejected at
/// process admission, with earlier checks on durable hold and containment paths.
pub(super) fn missing_authorized_execution_profile_reason(binary: &str) -> Option<String> {
    #[cfg(test)]
    if matches!(
        binary,
        "sh" | "guard-nonexistent-binary-xyz" | "guard-nonexistent-binary-delete-failure"
    ) {
        // Process-lifecycle tests use these commands to create controlled
        // child groups, synchronization points, and spawn failures. Production
        // builds do not have this exception, and catalog validation rejects
        // shell interpreters.
        return None;
    }
    guard::gating::verb::authorized_executable_profile(binary)
        .is_none()
        .then(|| {
        format!(
            "authorized execution rejects binary '{binary}' because it has no closed executable authority profile"
        )
    })
}

struct CommandInitiationLease {
    _learned_deny: Option<guard::evaluate::LearnedDenyUseLease>,
    _verb: Option<guard::learned_rules::AuthorityUseLease<VerbCatalog>>,
    _session: Option<tokio::sync::OwnedRwLockReadGuard<SessionRegistry>>,
    _artifacts: Vec<guard::learned_rules::OperatorAuthorityArtifactLease>,
    _executable_search_directories: Vec<guard::learned_rules::OperatorAuthorityArtifactLease>,
}

struct ProcessExecutionAuthorityLeases {
    _artifacts: Vec<guard::learned_rules::OperatorAuthorityArtifactLease>,
    _executable_search_directories: Vec<guard::learned_rules::OperatorAuthorityArtifactLease>,
}

impl CommandInitiationLease {
    fn release_policy_authority(self) -> ProcessExecutionAuthorityLeases {
        let Self {
            _learned_deny,
            _verb,
            _session,
            _artifacts,
            _executable_search_directories,
        } = self;
        drop((_learned_deny, _verb, _session));
        ProcessExecutionAuthorityLeases {
            _artifacts,
            _executable_search_directories,
        }
    }
}

/// Environment variable names use the target process's comparison semantics.
/// Windows stores one case-insensitive environment block, while Unix permits
/// distinct names that differ only by case.
fn child_environment_name_key(name: &str) -> String {
    #[cfg(windows)]
    {
        name.to_ascii_uppercase()
    }
    #[cfg(not(windows))]
    {
        name.to_string()
    }
}

fn fixed_child_environment_name_is_inert(name: &str, value: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    match upper.as_str() {
        "PATH" | "HOME" | "USER" | "LOGNAME" | "LANG" | "LANGUAGE" | "LC_ALL" | "LC_CTYPE"
        | "TERM" | "TZ" | "XDG_RUNTIME_DIR" | "GUARD_DEPTH" => true,
        "KUBECTL_ENABLE_CMD_SHADOW" | "KUBECTL_KUBERC" => {
            matches!(value.to_ascii_lowercase().as_str(), "0" | "false" | "off")
        }
        _ => false,
    }
}

async fn fixed_child_environment_binding_is_sensitive(
    server: &ServerContext,
    name: &str,
    value: &str,
) -> bool {
    if dangerous_env_name(name) {
        return true;
    }
    if child_environment_name_key(name) == "KUBECONFIG" {
        let path = Path::new(value);
        if !path.is_absolute() {
            return true;
        }
        let Ok(yaml) = std::fs::read_to_string(path) else {
            return true;
        };
        let registry = server.state.protocol_registry.read().await;
        return !registry.values().any(|proxy| {
            proxy.protocol_name() == "kubernetes"
                && guard::proxy::validate_brokered_kubeconfig_matches(
                    &yaml,
                    &proxy.brokered_kubeconfig(),
                )
                .is_ok()
        });
    }
    !fixed_child_environment_name_is_inert(name, value)
}

async fn fixed_child_environment_contains_sensitive_binding(
    server: &ServerContext,
    bindings: &HashMap<String, String>,
) -> bool {
    for (name, value) in bindings {
        if fixed_child_environment_binding_is_sensitive(server, name, value).await {
            return true;
        }
    }
    false
}

async fn validate_fixed_identity_profile_authority(
    server: &ServerContext,
    request: &ExecuteRequest,
    effective_child_env: &HashMap<String, String>,
) -> Result<(), String> {
    use guard::gating::approval::DelayedAuthorityProfile;

    let Some(profile) = guard::gating::verb::authorized_executable_profile(&request.binary) else {
        return Err("fixed-identity execution requires a closed executable profile".to_string());
    };
    match profile {
        DelayedAuthorityProfile::PrimaryOnly | DelayedAuthorityProfile::SystemdControl => Ok(()),
        DelayedAuthorityProfile::TypedKubectl => {
            if request.args.iter().any(|argument| {
                matches!(argument.as_str(), "--kubeconfig" | "--kuberc")
                    || argument.starts_with("--kubeconfig=")
                    || argument.starts_with("--kuberc=")
            }) {
                return Err(
                    "fixed-identity kubectl requires Guard's immutable KUBECONFIG binding and disables kuberc"
                        .to_string(),
                );
            }
            let kubeconfig = child_environment_value(effective_child_env, "KUBECONFIG")
                .ok_or_else(|| {
                    "fixed-identity kubectl requires an active Guard proxy KUBECONFIG binding"
                        .to_string()
                })?;
            if fixed_child_environment_binding_is_sensitive(server, "KUBECONFIG", kubeconfig)
                .await
            {
                return Err(
                    "fixed-identity kubectl KUBECONFIG does not match an active Guard proxy"
                        .to_string(),
                );
            }
            for name in ["KUBECTL_ENABLE_CMD_SHADOW", "KUBECTL_KUBERC"] {
                let value = child_environment_value(effective_child_env, name).ok_or_else(|| {
                    format!("fixed-identity kubectl requires Guard's {name} disablement")
                })?;
                if !fixed_child_environment_name_is_inert(name, value) {
                    return Err(format!(
                        "fixed-identity kubectl requires Guard's {name} disablement"
                    ));
                }
            }
            Ok(())
        }
        DelayedAuthorityProfile::TypedAnsible | DelayedAuthorityProfile::TypedHelm => Err(
            "fixed-identity execution cannot safely expose mutable Ansible or Helm profile authority; immutable profile snapshots are not available"
                .to_string(),
        ),
    }
}

fn child_environment_contains(bindings: &HashMap<String, String>, name: &str) -> bool {
    let key = child_environment_name_key(name);
    bindings
        .keys()
        .any(|candidate| child_environment_name_key(candidate) == key)
}

fn child_environment_value<'a>(
    bindings: &'a HashMap<String, String>,
    name: &str,
) -> Option<&'a str> {
    let key = child_environment_name_key(name);
    bindings
        .iter()
        .find(|(candidate, _)| child_environment_name_key(candidate) == key)
        .map(|(_, value)| value.as_str())
}

fn caller_environment_is_executable_authority(name: &str) -> bool {
    child_environment_name_key(name) == child_environment_name_key("PATH")
}

fn caller_environment_redirects_tool_authority(binary: &str, name: &str) -> bool {
    let protected_tool = guard::gating::verb::authorized_executable_profile(binary)
        .is_some_and(|profile| profile.discovers_profile_authority());
    protected_tool
        && [
            "HOME",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_CACHE_HOME",
            "USERPROFILE",
            "HOMEDRIVE",
            "HOMEPATH",
            "APPDATA",
            "LOCALAPPDATA",
            "TEMP",
            "TMP",
        ]
        .into_iter()
        .any(|protected| child_environment_name_key(name) == child_environment_name_key(protected))
}

fn tool_discovers_profile_authority(binary: &str) -> bool {
    guard::gating::verb::authorized_executable_profile(binary)
        .is_some_and(|profile| profile.discovers_profile_authority())
}

fn unsupported_execution_identity_profile_reason(
    server: &ServerContext,
    binary: &str,
) -> Option<&'static str> {
    use guard::gating::approval::DelayedAuthorityProfile;

    match guard::gating::verb::authorized_executable_profile(binary) {
        Some(DelayedAuthorityProfile::TypedAnsible | DelayedAuthorityProfile::TypedHelm) => Some(
            "typed Ansible and Helm execution requires immutable profile snapshots, which are not available",
        ),
        Some(DelayedAuthorityProfile::TypedKubectl) if server.config.exec_as_caller => Some(
            "typed kubectl execution is unavailable with --exec-as-caller because a mutable caller profile cannot be bound as immutable process authority",
        ),
        _ => None,
    }
}

fn request_supplies_child_environment_name(request: &ExecuteRequest, name: &str) -> bool {
    request
        .env
        .keys()
        .chain(request.secrets.keys())
        .chain(request.secret_files.keys())
        .any(|candidate| child_environment_name_key(candidate) == child_environment_name_key(name))
}

fn insert_child_environment_binding(
    bindings: &mut HashMap<String, String>,
    name: impl Into<String>,
    value: impl Into<String>,
) {
    let name = name.into();
    let normalized = child_environment_name_key(&name);
    bindings.retain(|existing, _| child_environment_name_key(existing) != normalized);
    bindings.insert(name, value.into());
}

fn kubectl_has_operator_kuberc_binding(
    request: &ExecuteRequest,
    trusted_tool_env: &HashMap<String, String>,
    daemon_child_env: &HashMap<String, String>,
) -> bool {
    request
        .args
        .iter()
        .any(|argument| argument == "--kuberc" || argument.strip_prefix("--kuberc=").is_some())
        || request_supplies_child_environment_name(request, "KUBERC")
        || child_environment_contains(trusted_tool_env, "KUBERC")
        || child_environment_contains(daemon_child_env, "KUBERC")
}

fn apply_authorized_tool_environment_defaults(
    request: &ExecuteRequest,
    authorization: Option<&CommandAuthorization>,
    daemon_child_env: &HashMap<String, String>,
    trusted_tool_env: &mut HashMap<String, String>,
) -> Result<(), String> {
    if authorization.is_none() {
        return Ok(());
    }

    match guard::gating::semantic_executable_key(&request.binary).as_str() {
        "kubectl" => {
            for name in ["KUBECTL_ENABLE_CMD_SHADOW", "KUBECTL_KUBERC"] {
                if request_supplies_child_environment_name(request, name) {
                    return Err(format!(
                        "caller environment may not override Guard's {} setting",
                        name
                    ));
                }
            }
            insert_child_environment_binding(
                trusted_tool_env,
                "KUBECTL_ENABLE_CMD_SHADOW",
                "false",
            );
            if !kubectl_has_operator_kuberc_binding(request, trusted_tool_env, daemon_child_env) {
                insert_child_environment_binding(trusted_tool_env, "KUBECTL_KUBERC", "false");
            }
        }
        "helm" => {
            if request_supplies_child_environment_name(request, "HELM_NO_PLUGINS") {
                return Err(
                    "caller environment may not override Guard's HELM_NO_PLUGINS setting"
                        .to_string(),
                );
            }
            insert_child_environment_binding(trusted_tool_env, "HELM_NO_PLUGINS", "1");
        }
        _ => {}
    }
    Ok(())
}

fn effective_child_environment(
    server: &ServerContext,
    daemon_child_env: &HashMap<String, String>,
    trusted_tool_env: &HashMap<String, String>,
    request_env: &HashMap<String, String>,
    exec_caller: Option<&ExecCallerContext>,
    depth: u32,
) -> HashMap<String, String> {
    #[cfg(not(unix))]
    let _ = server;
    let mut environment = HashMap::new();
    for name in child_env_allowlist() {
        if let Ok(value) = std::env::var(name) {
            if !server.config.exec_as_caller && !fixed_child_environment_name_is_inert(name, &value)
            {
                continue;
            }
            insert_child_environment_binding(&mut environment, *name, value);
        }
    }
    for (name, value) in daemon_child_env {
        insert_child_environment_binding(&mut environment, name.clone(), value.clone());
    }
    for (name, value) in trusted_tool_env {
        insert_child_environment_binding(&mut environment, name.clone(), value.clone());
    }
    for (name, value) in request_env {
        insert_child_environment_binding(&mut environment, name.clone(), value.clone());
    }
    if let Some(context) = exec_caller {
        insert_child_environment_binding(
            &mut environment,
            "HOME",
            context.home_dir.to_string_lossy(),
        );
        insert_child_environment_binding(&mut environment, "USER", context.username.clone());
        insert_child_environment_binding(&mut environment, "LOGNAME", context.username.clone());
        environment.retain(|name, _| {
            child_environment_name_key(name) != child_environment_name_key("XDG_RUNTIME_DIR")
        });
        #[cfg(unix)]
        {
            let runtime_dir = PathBuf::from(format!("/run/user/{}", context.uid));
            if runtime_dir.exists() {
                insert_child_environment_binding(
                    &mut environment,
                    "XDG_RUNTIME_DIR",
                    runtime_dir.to_string_lossy(),
                );
            }
        }
    }
    insert_child_environment_binding(&mut environment, "GUARD_DEPTH", (depth + 1).to_string());
    #[cfg(test)]
    if let Some(path) = &server.config.test_daemon_path {
        insert_child_environment_binding(&mut environment, "PATH", path.to_string_lossy());
        return environment;
    }
    #[cfg(unix)]
    if let Some(shim_dir) = &server.config.shim_dir {
        if let Some(path) = path_with_shim_dir(shim_dir) {
            insert_child_environment_binding(&mut environment, "PATH", path.to_string_lossy());
        }
    }
    environment
}

fn process_start_operator_authority_paths(
    request: &ExecuteRequest,
    authorization: Option<&CommandAuthorization>,
    primary_binary: &Path,
    effective_child_env: &HashMap<String, String>,
) -> Result<Vec<PathBuf>, String> {
    if authorization.is_none() {
        return Ok(Vec::new());
    }

    // Every persisted or evaluator-issued authorization binds execution to the
    // exact daemon-resolved primary executable, including approved raw replay.
    let safe_default_cwd = safe_default_working_directory()?;
    let effective_cwd = request.cwd.as_ref().unwrap_or(&safe_default_cwd);
    let mut paths = vec![primary_binary.to_path_buf()];
    // The immutable request snapshot binds the canonical working-directory
    // value. A caller-selected directory is also content-bound because tools
    // can discover authority beneath it. The fixed OS root is trusted by
    // identity and is never recursively scanned as an artifact tree.
    if effective_cwd != &safe_default_cwd {
        paths.push(effective_cwd.clone());
    }
    if !authorization_extracts_explicit_artifacts(authorization) {
        // Evaluator-only approval never grants typed local-file authority.
        // Bind its executable and complete environment here; the exec boundary
        // separately refuses any untyped local filesystem input.
        paths.sort();
        paths.dedup();
        return Ok(paths);
    }

    paths.extend(
        guard::gating::verb::operator_authority_paths(
            &request.binary,
            &request.args,
            effective_child_env,
        )
        .map_err(|error| format!("operator authority selection is invalid: {error}"))?,
    );
    paths.extend(default_tool_profile_authority_paths(
        &request.binary,
        &request.args,
        effective_child_env,
        effective_cwd,
    ));

    // A typed command that executes from a propagated directory can discover
    // configuration, plugins, and executable content below that root. Keep the
    // entire tree pinned for the child lifetime after the final catalog recheck.
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn process_start_transitive_operator_authority_paths(
    request: &ExecuteRequest,
    authorization: Option<&CommandAuthorization>,
    effective_child_env: &HashMap<String, String>,
) -> Result<Vec<PathBuf>, String> {
    if authorization.is_none() || !tool_discovers_profile_authority(&request.binary) {
        return Ok(Vec::new());
    }
    let default_working_directory;
    let authority_working_directory = if let Some(cwd) = request.cwd.as_deref() {
        Some(cwd)
    } else {
        default_working_directory = safe_default_working_directory()?;
        Some(default_working_directory.as_path())
    };
    let mut paths = guard::gating::verb::transitive_operator_authority_paths(
        &request.binary,
        &request.args,
        effective_child_env,
        authority_working_directory,
    )
    .map_err(|error| format!("transitive operator authority is invalid: {error}"))?;
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn default_tool_profile_authority_paths(
    binary: &str,
    args: &[String],
    effective_child_env: &HashMap<String, String>,
    effective_cwd: &Path,
) -> Vec<PathBuf> {
    let binary = guard::gating::semantic_executable_key(binary);
    let mut candidates = BTreeSet::new();
    let home = child_environment_value(effective_child_env, "HOME")
        .or_else(|| child_environment_value(effective_child_env, "USERPROFILE"))
        .map(PathBuf::from);
    #[cfg(not(windows))]
    let xdg_config = child_environment_value(effective_child_env, "XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| home.as_ref().map(|path| path.join(".config")));
    #[cfg(windows)]
    let xdg_config = child_environment_value(effective_child_env, "XDG_CONFIG_HOME")
        .or_else(|| child_environment_value(effective_child_env, "APPDATA"))
        .map(PathBuf::from);
    #[cfg(not(windows))]
    let xdg_data = child_environment_value(effective_child_env, "XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| home.as_ref().map(|path| path.join(".local/share")));
    #[cfg(windows)]
    let xdg_data = child_environment_value(effective_child_env, "XDG_DATA_HOME")
        .or_else(|| child_environment_value(effective_child_env, "APPDATA"))
        .map(PathBuf::from);
    #[cfg(not(windows))]
    let xdg_cache = child_environment_value(effective_child_env, "XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| home.as_ref().map(|path| path.join(".cache")));
    #[cfg(windows)]
    let xdg_cache = child_environment_value(effective_child_env, "XDG_CACHE_HOME")
        .or_else(|| child_environment_value(effective_child_env, "TEMP"))
        .map(PathBuf::from);

    let mut include = |path: PathBuf| {
        if std::fs::symlink_metadata(&path).is_ok() {
            candidates.insert(path);
        }
    };
    match binary.as_str() {
        "ansible" | "ansible-playbook" => {
            if !child_environment_contains(effective_child_env, "ANSIBLE_CONFIG") {
                include(effective_cwd.join("ansible.cfg"));
            }
            if let Some(home) = &home {
                if !child_environment_contains(effective_child_env, "ANSIBLE_CONFIG") {
                    include(home.join(".ansible.cfg"));
                }
                include(home.join(".ssh"));
                if !child_environment_contains(effective_child_env, "ANSIBLE_HOME") {
                    for discovered_tree in ["plugins", "collections", "roles"] {
                        include(home.join(".ansible").join(discovered_tree));
                    }
                }
            }
            if !child_environment_contains(effective_child_env, "ANSIBLE_CONFIG") {
                include(PathBuf::from("/etc/ansible/ansible.cfg"));
            }
            let explicit_inventory =
                child_environment_contains(effective_child_env, "ANSIBLE_INVENTORY")
                    || args.iter().any(|argument| {
                        matches!(argument.as_str(), "-i" | "--inventory" | "--inventory-file")
                            || argument.starts_with("-i=")
                            || argument
                                .strip_prefix("-i")
                                .is_some_and(|value| !value.is_empty())
                            || argument.starts_with("--inventory=")
                            || argument.starts_with("--inventory-file=")
                    });
            if !explicit_inventory {
                include(PathBuf::from("/etc/ansible/hosts"));
            }
        }
        "kubectl" => {
            let discovers_default_kubeconfig =
                !child_environment_contains(effective_child_env, "KUBECONFIG")
                    && !args.iter().any(|argument| {
                        argument == "--kubeconfig" || argument.starts_with("--kubeconfig=")
                    });
            if let Some(home) = home.as_ref().filter(|_| discovers_default_kubeconfig) {
                include(home.join(".kube/config"));
            }
        }
        "helm" => {
            let discovers_default_kubeconfig =
                !child_environment_contains(effective_child_env, "KUBECONFIG")
                    && !args.iter().any(|argument| {
                        argument == "--kubeconfig" || argument.starts_with("--kubeconfig=")
                    });
            if let Some(home) = home.as_ref().filter(|_| discovers_default_kubeconfig) {
                include(home.join(".kube/config"));
            }
            if !child_environment_contains(effective_child_env, "HELM_CONFIG_HOME") {
                if let Some(config) = &xdg_config {
                    include(config.join("helm"));
                }
            }
            if !child_environment_contains(effective_child_env, "HELM_DATA_HOME") {
                if let Some(data) = &xdg_data {
                    include(data.join("helm"));
                }
            }
            if !child_environment_contains(effective_child_env, "HELM_CACHE_HOME") {
                if let Some(cache) = &xdg_cache {
                    include(cache.join("helm"));
                }
            }
        }
        _ => {}
    }
    candidates.into_iter().collect()
}

fn process_execution_executable_search_directories(
    secondary_path_search: bool,
    effective_child_env: &HashMap<String, String>,
) -> Result<Vec<PathBuf>, String> {
    if !secondary_path_search {
        return Ok(Vec::new());
    }

    let search_path = child_environment_value(effective_child_env, "PATH")
        .ok_or_else(|| "authorized executable search path is unavailable".to_string())?;
    let mut directories = Vec::new();
    let mut seen = BTreeSet::new();
    for directory in std::env::split_paths(search_path) {
        if directory.as_os_str().is_empty() || !directory.is_absolute() {
            return Err(
                "authorized executable search path contains an empty or relative directory"
                    .to_string(),
            );
        }
        let canonical = match directory.canonicalize() {
            Ok(canonical) => canonical,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // A missing PATH entry cannot resolve either the primary
                // executable or a child command. Remove it from the effective
                // child PATH so it cannot acquire authority after approval.
                continue;
            }
            Err(error) => {
                return Err(format!(
                    "authorized executable search directory '{}' cannot be resolved: {error}",
                    directory.display()
                ))
            }
        };
        if seen.insert(canonical.clone()) {
            directories.push(canonical);
        }
    }
    if directories.is_empty() {
        return Err("authorized executable search path contains no directories".to_string());
    }
    Ok(directories.into_iter().collect())
}

fn canonicalize_authorized_executable_search_path(
    secondary_path_search: bool,
    effective_child_env: &mut HashMap<String, String>,
) -> Result<(), String> {
    if !secondary_path_search {
        effective_child_env.retain(|name, _| {
            child_environment_name_key(name) != child_environment_name_key("PATH")
        });
        return Ok(());
    }
    let directories = process_execution_executable_search_directories(true, effective_child_env)?;
    let canonical_path = std::env::join_paths(&directories)
        .map_err(|error| format!("authorized executable search path is invalid: {error}"))?;
    insert_child_environment_binding(
        effective_child_env,
        "PATH",
        canonical_path.to_string_lossy(),
    );
    Ok(())
}

fn update_authority_metadata_digest(hasher: &mut Sha256, metadata: &std::fs::Metadata) {
    hasher.update(metadata.len().to_le_bytes());
    hasher.update([u8::from(metadata.is_file()), u8::from(metadata.is_dir())]);
    if let Ok(modified) = metadata.modified() {
        if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) {
            hasher.update(duration.as_secs().to_le_bytes());
            hasher.update(duration.subsec_nanos().to_le_bytes());
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        for value in [
            metadata.dev(),
            metadata.ino(),
            metadata.mode() as u64,
            metadata.uid() as u64,
            metadata.gid() as u64,
            metadata.mtime() as u64,
            metadata.mtime_nsec() as u64,
            metadata.ctime() as u64,
            metadata.ctime_nsec() as u64,
        ] {
            hasher.update(value.to_le_bytes());
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        for value in [
            metadata.file_attributes() as u64,
            metadata.creation_time(),
            metadata.last_write_time(),
            metadata.file_size(),
        ] {
            hasher.update(value.to_le_bytes());
        }
    }
}

fn update_authority_path_digest(hasher: &mut Sha256, root: &Path, path: &Path) {
    let relative = path.strip_prefix(root).unwrap_or(path);
    let value = relative.to_string_lossy();
    hasher.update(value.len().to_le_bytes());
    hasher.update(value.as_bytes());
}

fn authority_digest_hex(digest: impl AsRef<[u8]>) -> String {
    use std::fmt::Write as _;

    let bytes = digest.as_ref();
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn update_authority_file_content_digest(hasher: &mut Sha256, path: &Path) -> Result<()> {
    use std::io::Read as _;

    let mut file = std::fs::File::open(path)?;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(())
}

fn operator_artifact_fingerprint(
    path: &Path,
    untrusted_unix_user_id: Option<u32>,
) -> Result<String> {
    let _lease =
        guard::learned_rules::lease_operator_authority_artifact(path, untrusted_unix_user_id)?;
    let mut hasher = Sha256::new();
    let mut pending = vec![path.to_path_buf()];
    while let Some(current) = pending.pop() {
        let metadata = std::fs::symlink_metadata(&current)?;
        update_authority_path_digest(&mut hasher, path, &current);
        update_authority_metadata_digest(&mut hasher, &metadata);
        if metadata.is_dir() {
            let mut children = std::fs::read_dir(&current)?
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<std::io::Result<Vec<_>>>()?;
            children.sort();
            children.reverse();
            pending.extend(children);
        } else if metadata.is_file() {
            update_authority_file_content_digest(&mut hasher, &current)?;
        }
    }
    Ok(authority_digest_hex(hasher.finalize()))
}

fn executable_search_directory_fingerprint(
    path: &Path,
    untrusted_unix_user_id: Option<u32>,
) -> Result<String> {
    let _lease = guard::learned_rules::lease_operator_executable_search_directory(
        path,
        untrusted_unix_user_id,
    )?;
    let mut hasher = Sha256::new();
    let metadata = std::fs::symlink_metadata(path)?;
    update_authority_metadata_digest(&mut hasher, &metadata);
    let mut children = std::fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    children.sort();
    for child in children {
        update_authority_path_digest(&mut hasher, path, &child);
        let metadata = std::fs::symlink_metadata(&child)?;
        update_authority_metadata_digest(&mut hasher, &metadata);
        if metadata.file_type().is_symlink() {
            if let Ok(target) = child.canonicalize() {
                update_authority_path_digest(&mut hasher, Path::new("/"), &target);
                update_authority_metadata_digest(&mut hasher, &std::fs::metadata(target)?);
            }
        }
    }
    Ok(authority_digest_hex(hasher.finalize()))
}

fn semantic_secret_file_path(environment_name: &str) -> PathBuf {
    let digest = authority_digest_hex(Sha256::digest(environment_name.as_bytes()));
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\ProgramData\Guard\approval-secret-files").join(digest)
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/run/guard/approval-secret-files").join(digest)
    }
}

fn process_authority_selection_environment(
    request: &ExecuteRequest,
    effective_child_env: &HashMap<String, String>,
) -> (HashMap<String, String>, BTreeSet<PathBuf>) {
    let mut environment = effective_child_env.clone();
    let mut semantic_secret_files = BTreeSet::new();
    for environment_name in request.secret_files.keys() {
        let path = semantic_secret_file_path(environment_name);
        insert_child_environment_binding(
            &mut environment,
            environment_name.clone(),
            path.to_string_lossy(),
        );
        semantic_secret_files.insert(path);
    }
    (environment, semantic_secret_files)
}

fn process_environment_fingerprint(
    key: &[u8],
    request: &ExecuteRequest,
    approved_environment: &ApprovedEnvironmentSnapshot,
    effective_child_env: &HashMap<String, String>,
) -> String {
    // Values use the same precedence as `effective_child_environment`. Every
    // secret-bearing slot is replaced by its stable store reference before
    // hashing, including daemon-created secret files whose absolute path is
    // intentionally different for every child.
    let mut bindings = BTreeMap::<String, (u8, String)>::new();
    for (name, value) in effective_child_env {
        bindings.insert(child_environment_name_key(name), (0, value.clone()));
    }
    for (name, reference) in &approved_environment.tool.secret_sources {
        bindings.insert(child_environment_name_key(name), (1, reference.clone()));
    }
    for (name, value) in &request.env {
        bindings.insert(child_environment_name_key(name), (0, value.clone()));
    }
    for (name, reference) in &request.secrets {
        bindings.insert(child_environment_name_key(name), (2, reference.clone()));
    }
    for (name, reference) in &request.secret_files {
        bindings.insert(child_environment_name_key(name), (3, reference.clone()));
    }

    use hmac::{Hmac, Mac};
    let mut hasher = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key)
        .expect("HMAC accepts keys of every length");
    hasher.update(b"guard-process-environment-v1\0");
    for (name, (source, value)) in bindings {
        hasher.update(&name.len().to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update(&[source]);
        hasher.update(&value.len().to_le_bytes());
        hasher.update(value.as_bytes());
    }
    authority_digest_hex(hasher.finalize().into_bytes())
}

struct ProcessAuthorityBindingInputs<'a> {
    authority_mac_key: &'a [u8],
    request: &'a ExecuteRequest,
    authorization: &'a CommandAuthorization,
    primary_binary: &'a Path,
    daemon_path: Option<std::ffi::OsString>,
    effective_child_env: &'a HashMap<String, String>,
    approved_environment: &'a ApprovedEnvironmentSnapshot,
    tool_registry_fingerprint: String,
    untrusted_unix_user_id: Option<u32>,
    execution_identity: guard::gating::approval::ProcessExecutionIdentity,
}

fn process_authority_binding_from_effective_environment(
    inputs: ProcessAuthorityBindingInputs<'_>,
) -> Result<guard::gating::approval::ProcessAuthorityBinding, String> {
    let ProcessAuthorityBindingInputs {
        authority_mac_key,
        request,
        authorization,
        primary_binary,
        daemon_path,
        effective_child_env,
        approved_environment,
        tool_registry_fingerprint,
        untrusted_unix_user_id,
        execution_identity,
    } = inputs;
    let delayed_authority = command_delayed_authority_plan(request, authorization)?;
    let (authority_environment, semantic_secret_files) =
        process_authority_selection_environment(request, effective_child_env);
    let mut paths = process_start_operator_authority_paths(
        request,
        Some(authorization),
        primary_binary,
        &authority_environment,
    )?;
    paths.extend(process_start_transitive_operator_authority_paths(
        request,
        Some(authorization),
        &authority_environment,
    )?);
    paths.retain(|path| !semantic_secret_files.contains(path));
    paths.sort();
    paths.dedup();
    let artifacts = paths
        .into_iter()
        .map(|path| {
            operator_artifact_fingerprint(&path, untrusted_unix_user_id)
                .map(|fingerprint| (path.clone(), fingerprint))
                .map_err(|error| {
                    format!(
                        "cannot bind process authority artifact '{}': {error}",
                        path.display()
                    )
                })
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let executable_search_directories = process_execution_executable_search_directories(
        delayed_authority.secondary_path_search,
        &authority_environment,
    )?
    .into_iter()
    .map(|path| {
        executable_search_directory_fingerprint(&path, untrusted_unix_user_id)
            .map(|fingerprint| (path.clone(), fingerprint))
            .map_err(|error| {
                format!(
                    "cannot bind executable search directory '{}': {error}",
                    path.display()
                )
            })
    })
    .collect::<Result<Vec<_>, _>>()?;
    let secondary_path_search = delayed_authority.secondary_path_search;
    Ok(guard::gating::approval::ProcessAuthorityBinding {
        delayed_authority: Some(delayed_authority),
        execution_identity: Some(execution_identity),
        executable: primary_binary.to_path_buf(),
        daemon_path: secondary_path_search
            .then_some(daemon_path)
            .flatten()
            .map(|path| path.to_string_lossy().into_owned()),
        tool_registry_fingerprint,
        effective_environment_fingerprint: process_environment_fingerprint(
            authority_mac_key,
            request,
            approved_environment,
            effective_child_env,
        ),
        artifacts,
        executable_search_directories,
    })
}

pub(super) fn capture_approval_process_authority(
    server: &ServerContext,
    caller: &CallerIdentity,
    request: &ExecuteRequest,
    authorization: CommandAuthorization,
    approved_environment: &ApprovedEnvironmentSnapshot,
    tool_registry_fingerprint: String,
) -> Result<guard::gating::approval::ProcessAuthorityBinding, String> {
    let mut effective_request = request.clone();
    if effective_request.cwd.is_none() {
        effective_request.cwd = Some(safe_default_working_directory()?);
    }
    let request = &effective_request;
    let delayed_authority = command_delayed_authority_plan(request, &authorization)?;
    let daemon_child_env: HashMap<String, String> = server
        .config
        .extra_child_env
        .iter()
        .filter_map(|name| std::env::var(name).ok().map(|value| (name.clone(), value)))
        .collect();
    let mut trusted_tool_env = approved_environment.tool.env.clone();
    apply_authorized_tool_environment_defaults(
        request,
        Some(&authorization),
        &daemon_child_env,
        &mut trusted_tool_env,
    )
    .map_err(|error| error.to_string())?;
    let primary_binary = resolve_primary_binary(server, &request.binary)
        .map_err(|error| format!("cannot bind approved executable: {error}"))?;
    let mut command = Command::new(&primary_binary);
    let exec_caller = apply_exec_identity(&mut command, server, caller)
        .map_err(|error| format!("cannot bind approved execution identity: {error}"))?;
    let mut request_env = request.env.clone();
    for environment_name in request.secrets.keys() {
        if let Some(Some(value)) = approved_environment.request_secret(environment_name) {
            insert_child_environment_binding(
                &mut request_env,
                environment_name.clone(),
                value.to_string(),
            );
        }
    }
    let mut effective_child_env = effective_child_environment(
        server,
        &daemon_child_env,
        &trusted_tool_env,
        &request_env,
        exec_caller.as_ref(),
        0,
    );
    canonicalize_authorized_executable_search_path(
        delayed_authority.secondary_path_search,
        &mut effective_child_env,
    )?;
    process_authority_binding_from_effective_environment(ProcessAuthorityBindingInputs {
        authority_mac_key: server.config.authority_mac_key.as_ref(),
        request,
        authorization: &authorization,
        primary_binary: &primary_binary,
        daemon_path: daemon_executable_search_path(server),
        effective_child_env: &effective_child_env,
        approved_environment,
        tool_registry_fingerprint,
        untrusted_unix_user_id: untrusted_unix_child_user_id(server, exec_caller.as_ref()),
        execution_identity: process_execution_identity_binding(server, exec_caller.as_ref())?,
    })
}

#[cfg(unix)]
fn process_execution_identity_binding(
    server: &ServerContext,
    exec_caller: Option<&ExecCallerContext>,
) -> Result<guard::gating::approval::ProcessExecutionIdentity, String> {
    let context = exec_caller
        .ok_or_else(|| "approved execution identity is unavailable on Unix".to_string())?;
    Ok(guard::gating::approval::ProcessExecutionIdentity {
        mode: if server.config.exec_as_caller {
            guard::gating::approval::ProcessExecutionIdentityMode::Caller
        } else {
            guard::gating::approval::ProcessExecutionIdentityMode::FixedUser
        },
        principal: None,
        user_id: context.uid,
        primary_group_id: context.gid,
        supplementary_group_ids: context.supplementary_group_ids.clone(),
    })
}

#[cfg(windows)]
fn process_execution_identity_binding(
    server: &ServerContext,
    _exec_caller: Option<&ExecCallerContext>,
) -> Result<guard::gating::approval::ProcessExecutionIdentity, String> {
    Ok(guard::gating::approval::ProcessExecutionIdentity {
        mode: if server.config.exec_as_caller {
            guard::gating::approval::ProcessExecutionIdentityMode::Caller
        } else {
            guard::gating::approval::ProcessExecutionIdentityMode::FixedUser
        },
        principal: Some(server.config.daemon_principal.clone()),
        user_id: 0,
        primary_group_id: 0,
        supplementary_group_ids: Vec::new(),
    })
}

#[cfg(not(any(unix, windows)))]
fn process_execution_identity_binding(
    _server: &ServerContext,
    _exec_caller: Option<&ExecCallerContext>,
) -> Result<guard::gating::approval::ProcessExecutionIdentity, String> {
    Err("approved local process execution is unavailable on this platform".to_string())
}

fn untrusted_unix_child_user_id(
    server: &ServerContext,
    exec_caller: Option<&ExecCallerContext>,
) -> Option<u32> {
    #[cfg(unix)]
    {
        Some(exec_caller.map_or(server.config.daemon_uid, |context| context.uid))
    }
    #[cfg(not(unix))]
    {
        let _ = (server, exec_caller);
        None
    }
}

struct ProcessInitiationLeases {
    command: CommandInitiationLease,
    tool_mapping: ToolMappingSpawnLease,
}

#[cfg(all(test, unix))]
type CommandInitiationHook = (
    std::sync::Arc<tokio::sync::Semaphore>,
    std::sync::Arc<tokio::sync::Semaphore>,
);

#[cfg(all(test, unix))]
fn command_initiation_hooks(
) -> &'static std::sync::Mutex<std::collections::BTreeMap<usize, CommandInitiationHook>> {
    static HOOKS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::BTreeMap<usize, CommandInitiationHook>>,
    > = std::sync::OnceLock::new();
    HOOKS.get_or_init(|| std::sync::Mutex::new(std::collections::BTreeMap::new()))
}

#[cfg(all(test, unix))]
pub(super) fn pause_command_initiation_for_test(server: &ServerContext) -> CommandInitiationHook {
    let reached = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    let release = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    command_initiation_hooks().lock().unwrap().insert(
        std::sync::Arc::as_ptr(&server.state.verbs) as usize,
        (reached.clone(), release.clone()),
    );
    (reached, release)
}

#[cfg(all(test, unix))]
fn command_started_hooks() -> &'static std::sync::Mutex<
    std::collections::BTreeMap<usize, std::sync::Arc<tokio::sync::Semaphore>>,
> {
    static HOOKS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::BTreeMap<usize, std::sync::Arc<tokio::sync::Semaphore>>>,
    > = std::sync::OnceLock::new();
    HOOKS.get_or_init(|| std::sync::Mutex::new(std::collections::BTreeMap::new()))
}

#[cfg(all(test, unix))]
pub(super) fn observe_command_started_for_test(
    server: &ServerContext,
) -> std::sync::Arc<tokio::sync::Semaphore> {
    let reached = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    command_started_hooks().lock().unwrap().insert(
        std::sync::Arc::as_ptr(&server.state.verbs) as usize,
        reached.clone(),
    );
    reached
}

#[cfg(all(test, unix))]
pub(super) fn take_command_started_observation_for_test(server: &ServerContext) -> bool {
    command_started_hooks()
        .lock()
        .unwrap()
        .remove(&(std::sync::Arc::as_ptr(&server.state.verbs) as usize))
        .is_some_and(|reached| reached.available_permits() > 0)
}

#[cfg(all(test, unix))]
fn signal_command_started_for_test(server: &ServerContext) {
    if let Some(reached) = command_started_hooks()
        .lock()
        .unwrap()
        .remove(&(std::sync::Arc::as_ptr(&server.state.verbs) as usize))
    {
        reached.add_permits(1);
    }
}

async fn acquire_command_initiation_lease(
    server: &ServerContext,
    request: &ExecuteRequest,
    authorization: Option<&CommandAuthorization>,
    delayed_authority: Option<&guard::gating::approval::DelayedAuthorityPlan>,
    primary_binary: &Path,
    effective_child_env: &HashMap<String, String>,
    untrusted_unix_user_id: Option<u32>,
) -> Result<CommandInitiationLease, String> {
    // Explicit operator policy is immutable within this evaluator instance and
    // remains absolute for trusted verbs and approved replay alike.
    if let Some(reason) = server
        .state
        .evaluator
        .static_deny_reason_argv(&request.binary, &request.args)
    {
        return Err(format!(
            "command denied by static policy before process start: {reason}"
        ));
    }

    // Revocable command authority is acquired in one order: learned denies,
    // verb catalog, then session registry. Administrative mutations acquire
    // the same resources in that order so initiation cannot form a lock cycle.
    #[cfg(all(test, unix))]
    let hook = command_initiation_hooks()
        .lock()
        .unwrap()
        .remove(&(std::sync::Arc::as_ptr(&server.state.verbs) as usize));
    #[cfg(all(test, unix))]
    if let Some((reached, release)) = hook {
        reached.add_permits(1);
        release
            .acquire()
            .await
            .map_err(|_| "command initiation test hook closed".to_string())?
            .forget();
    }
    let learned_deny = if let Some(authorization) = authorization {
        let lease = server
            .state
            .evaluator
            .lease_learned_deny_for_use()
            .await
            .map_err(|error| format!("learned deny authority is unavailable: {error}"))?;
        if let Some(reason) = lease.matching_reason(&request.binary, &request.args) {
            match authorization.learned_deny_authority {
                LearnedDenyProcessStartAuthority::Enforce => {
                    return Err(format!("command denied before process start: {reason}"));
                }
                LearnedDenyProcessStartAuthority::TypedVerb
                | LearnedDenyProcessStartAuthority::ApprovedReplay
                | LearnedDenyProcessStartAuthority::PersistedControlReplay => {
                    // Explicit typed or approved immutable authority outranks
                    // an automatic heuristic, but the match is still observed
                    // under the fresh process-start lease.
                }
                LearnedDenyProcessStartAuthority::PersistedControlCapture => {
                    return Err(
                        "internal error: persisted control capture reached process start"
                            .to_string(),
                    );
                }
            }
        }
        Some(lease)
    } else {
        None
    };

    let verb = if authorization
        .and_then(|authority| authority.verb.as_ref())
        .is_some()
    {
        let lease = server
            .refresh_and_lease_verb_catalog_for_use("command process start")
            .await
            .map_err(|error| format!("verb catalog authority is unavailable: {error}"))?;
        Some(lease)
    } else {
        None
    };

    let session = if let Some(token) = request.session_token.as_deref() {
        let guard = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            server.state.sessions.clone().read_owned(),
        )
        .await
        .map_err(|_| "timed out acquiring session authority coordination".to_string())?;
        if !guard.has(token) {
            return Err("session was revoked before process start".to_string());
        }
        if let Some(reason) = guard.suspension_reason(token, &server.config.behavior_limits) {
            return Err(format!(
                "session was suspended before process start: {reason}"
            ));
        }
        if let Some(expected) = authorization.and_then(|authority| authority.session.as_ref()) {
            let current = guard
                .authority_snapshot(token)
                .map(SessionAuthoritySnapshot::from);
            if current.as_ref() != Some(expected) {
                return Err("session authority changed before process start".to_string());
            }
        }
        Some(guard)
    } else if authorization
        .and_then(|authority| authority.session.as_ref())
        .is_some()
    {
        return Err("session authority is missing before process start".to_string());
    } else {
        None
    };

    if let (Some(expected), Some(lease)) = (
        authorization.and_then(|authority| authority.verb.as_ref()),
        verb.as_ref(),
    ) {
        let current =
            compose_verb_authority_with_session(server, request, lease, session.as_deref()).await;
        let Some(context) = current.context.as_ref() else {
            return Err("composed verb authority no longer allows this command".to_string());
        };
        let unchanged = match expected.composition_digest.as_deref() {
            Some(digest) => context.composition_digest.as_deref() == Some(digest),
            None => {
                let selected = current
                    .matches
                    .iter()
                    .filter(|matched| matched.selected)
                    .map(|matched| matched.verb.as_str())
                    .collect::<BTreeSet<_>>();
                selected.len() == 1
                    && selected.contains(expected.name.as_str())
                    && match expected.definition_digest.as_deref() {
                        Some(digest) => context.verb_digest.as_deref() == Some(digest),
                        None => {
                            context.name == expected.name
                                && expected.catalog_version == Some(lease.version())
                        }
                    }
            }
        };
        if !unchanged {
            return Err(
                "composed verb authority was removed, amended, or changed before process start"
                    .to_string(),
            );
        }
    }

    let mut artifacts = process_start_operator_authority_paths(
        request,
        authorization,
        primary_binary,
        effective_child_env,
    )?
    .into_iter()
    .map(|path| {
        guard::learned_rules::lease_operator_authority_artifact(&path, untrusted_unix_user_id)
            .map_err(|error| {
                format!(
                    "operator authority artifact '{}' is unavailable before process start: {error}",
                    path.display()
                )
            })
    })
    .collect::<Result<Vec<_>, _>>()?;
    // Parse nested configuration only after its containing profile and argv
    // artifacts are retained. The child cannot race a different kubeconfig or
    // Ansible configuration into the transitive authority set.
    artifacts.extend(
        process_start_transitive_operator_authority_paths(
            request,
            authorization,
            effective_child_env,
        )?
        .into_iter()
        .map(|path| {
            guard::learned_rules::lease_operator_authority_artifact(
                &path,
                untrusted_unix_user_id,
            )
            .map_err(|error| {
                format!(
                    "transitive operator authority artifact '{}' is unavailable before process start: {error}",
                    path.display()
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?,
    );
    let executable_search_directories = process_execution_executable_search_directories(
        delayed_authority.is_some_and(|plan| plan.secondary_path_search),
        effective_child_env,
    )?;
    let executable_search_directories = executable_search_directories
        .into_iter()
        .map(|path| {
            guard::learned_rules::lease_operator_executable_search_directory(
                &path,
                untrusted_unix_user_id,
            )
            .map_err(|error| {
                format!(
                    "operator executable search directory '{}' is unavailable before process start: {error}",
                    path.display()
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(CommandInitiationLease {
        _learned_deny: learned_deny,
        _verb: verb,
        _session: session,
        _artifacts: artifacts,
        _executable_search_directories: executable_search_directories,
    })
}

/// Resolve a verb invocation into a concrete command BEFORE any validation or
/// evaluation. The rendered binary/args then pass through the same checks as a
/// raw command; the verb's declared consequence class and rollback drive the
/// gate. Verbs are operator-authored, so each deterministic decision refreshes
/// from one locked durable snapshot before using catalog authority.
async fn resolve_verb_context<W: AsyncWrite + Unpin>(
    phase: &mut ExecPhase<'_, W>,
    request: &mut ExecuteRequest,
) -> Result<VerbResolution, ExecuteError> {
    let server = phase.server;
    if request.verb.is_some() && !server.config.gate.is_on() {
        let reason = "verbs require consequence gating (start the daemon with --gate consequence)"
            .to_string();
        let _ = write_policy_decision(
            phase.stream_output,
            &mut *phase.stream_writer,
            false,
            &reason,
        )
        .await;
        return Err(ExecuteResult::denied(reason).into());
    }
    if server.config.gate.is_on() {
        if let Err(error) = server.refresh_verb_catalog_for_decision().await {
            let reason = format!("verb catalog authority is unavailable: {error}");
            let _ = write_policy_decision(
                phase.stream_output,
                &mut *phase.stream_writer,
                false,
                &reason,
            )
            .await;
            return Err(ExecuteResult::denied(reason).into());
        }
    }
    let catalog_lease = if server.config.gate.is_on() {
        match server
            .lease_verb_catalog_for_use("verb matcher selection")
            .await
        {
            Ok(lease) => Some(lease),
            Err(error) => {
                let reason = format!("verb catalog authority is unavailable: {error}");
                let _ = write_policy_decision(
                    phase.stream_output,
                    &mut *phase.stream_writer,
                    false,
                    &reason,
                )
                .await;
                return Err(ExecuteResult::denied(reason).into());
            }
        }
    } else {
        None
    };
    if let Some(invocation) = request.verb.clone() {
        let rendered = {
            let cat = catalog_lease
                .as_ref()
                .expect("gated verb rendering holds catalog authority");
            cat.render(&invocation.name, &invocation.params)
                .map(|r| (r, cat.version()))
        };
        match rendered {
            Ok((r, version)) => {
                request.binary = r.binary;
                request.args = r.args;
                request.revert = r.revert.map(|(binary, args)| RevertSpec::new(binary, args));
                let _ = version;
            }
            Err(e) => {
                let reason = format!("verb error: {}", e);
                server.audit_deny(
                    phase.caller,
                    phase.session_token.as_deref(),
                    &invocation.name,
                    &[],
                    &reason,
                );
                let _ = write_policy_decision(
                    phase.stream_output,
                    &mut *phase.stream_writer,
                    false,
                    &reason,
                )
                .await;
                return Err(ExecuteResult::denied(reason).into());
            }
        }
    }

    // Fold ssh host-key options into argv after explicit verb rendering and
    // before reverse matching. Coverage, policy, evaluation, audit, and spawn
    // therefore see the same concrete command, including relaxed host-key
    // behavior that must never inherit a strict-mode verb match.
    request.apply_ssh_hostkey_options();

    if !server.config.gate.is_on() {
        return Ok(VerbResolution::none());
    }

    let resolution = compose_verb_authority(
        server,
        request,
        catalog_lease
            .as_ref()
            .expect("gated reverse matching holds catalog authority"),
    )
    .await;
    if resolution.matches.is_empty() {
        return Ok(VerbResolution::none());
    }
    // The composed resolution carries the selected coverage's revert plan
    // exactly when it produced a verb context; apply it to the pending
    // request so the gate sees the operator-authored rollback.
    if resolution.context.is_some() {
        request.revert = resolution
            .revert
            .clone()
            .map(|(binary, args)| RevertSpec::new(binary, args));
    }
    Ok(resolution)
}

async fn compose_verb_authority(
    server: &ServerContext,
    request: &ExecuteRequest,
    catalog: &VerbCatalog,
) -> VerbResolution {
    compose_verb_authority_with_session(server, request, catalog, None).await
}

async fn compose_verb_authority_with_session(
    server: &ServerContext,
    request: &ExecuteRequest,
    catalog: &VerbCatalog,
    sessions: Option<&SessionRegistry>,
) -> VerbResolution {
    let plain = request
        .env
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let secrets = request
        .secrets
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let secret_files = request
        .secret_files
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let authority_cwd = request_authority_working_directory(request);
    let raw_matches = catalog.match_command_all_with_environment_and_cwd(
        &request.binary,
        &request.args,
        &plain,
        &secrets,
        &secret_files,
        authority_cwd,
    );
    if raw_matches.is_empty() {
        return VerbResolution::none();
    }

    let definition_digests = raw_matches
        .iter()
        .filter_map(|matched| {
            catalog
                .verb_definition_digest(&matched.rendered.name)
                .map(|digest| (matched.rendered.name.clone(), digest))
        })
        .collect::<BTreeMap<_, _>>();

    let (activated, override_markers) = if let Some(token) = request.session_token.as_deref() {
        if let Some(sessions) = sessions {
            sessions.verb_scope_for(token).unwrap_or_default()
        } else {
            server
                .state
                .sessions
                .read()
                .await
                .verb_scope_for(token)
                .unwrap_or_default()
        }
    } else {
        (Vec::new(), Vec::new())
    };
    let activated: BTreeSet<String> = activated.into_iter().collect();
    let override_markers: BTreeSet<String> = override_markers.into_iter().collect();

    let mut scoped = Vec::new();
    for matched in raw_matches {
        let scope = if !matched.rendered.baseline && activated.contains(&matched.rendered.name) {
            VerbMatchScope::Session
        } else if matched.rendered.baseline {
            VerbMatchScope::Baseline
        } else {
            continue;
        };
        let mut effective_action = matched.action;
        if matches!(effective_action, CoverageAction::Preauthorized)
            && !verb_trust_is_current(
                &matched.rendered,
                server.state.evaluator.verb_promotion_stamp(),
            )
        {
            effective_action = CoverageAction::Evaluate;
        }
        if matches!(effective_action, CoverageAction::Preauthorized)
            && !matched.environment_authorized
        {
            effective_action = CoverageAction::Evaluate;
        }
        let overridden = baseline_override_applies(
            scope,
            effective_action,
            matched.sticky,
            matched.override_marker.as_deref(),
            &override_markers,
        );
        scoped.push(ScopedCoverageMatch {
            matched,
            scope,
            effective_action,
            overridden,
        });
    }
    let mut resolution = resolve_scoped_matches(scoped, catalog.version());
    if let Some(context) = resolution.context.as_mut() {
        context.verb_digest = definition_digests.get(&context.name).cloned();
        let selected_definitions = resolution
            .matches
            .iter()
            .filter(|matched| matched.selected)
            .filter_map(|matched| {
                definition_digests
                    .get(&matched.verb)
                    .map(|digest| (matched.verb.clone(), digest.clone()))
            })
            .collect::<BTreeMap<_, _>>();
        let material = serde_json::json!({
            "decision": resolution.decision,
            "matches": resolution.matches,
            "selected_definitions": selected_definitions,
            "class": context.class,
            "params": context.params,
            "revert": resolution.revert,
            "exec_timeout_secs": context.exec_timeout_secs,
            "access_evaluation_override_eligible": context.access_evaluation_override_eligible,
            "environment_authority": context.environment_authority,
            "local_file_authority": context.local_file_authority,
        });
        let canonical = serde_json::to_vec(&material).expect("verb authority material serializes");
        context.composition_digest = Some(
            Sha256::digest(canonical)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        );
    }
    resolution
}

/// Static request validation before any policy decision: recursion depth,
/// binary-name shape, and injection validation. Returns the recursion depth
/// and the reconstructed command line used by local policy, cache identity,
/// and learning. Provider projection separately retains structured argv long
/// enough to apply binary-specific redaction.
async fn validate_exec_request<W: AsyncWrite + Unpin>(
    phase: &mut ExecPhase<'_, W>,
    request: &ExecuteRequest,
) -> Result<(u32, String), ExecuteError> {
    // Check recursion depth
    let depth: u32 = std::env::var("GUARD_DEPTH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if depth >= MAX_GUARD_DEPTH {
        let reason = format!("guard recursion depth exceeded (max {})", MAX_GUARD_DEPTH);
        return Err(Box::new(
            deny_and_record(
                phase,
                request,
                SessionDecisionSource::Validation,
                None,
                reason,
            )
            .await,
        ));
    }

    // Validate binary name: reject paths, traversal, and shell metacharacters.
    // The check itself lives in `guard::wire` (the fuzzed parsing surface).
    if let Err(reason) = guard::wire::validate_binary_name(&request.binary) {
        return Err(Box::new(
            deny_and_record(
                phase,
                request,
                SessionDecisionSource::Validation,
                None,
                reason,
            )
            .await,
        ));
    }

    // Reject NUL bytes in argv at the boundary; the check itself lives in
    // `guard::wire` (the fuzzed parsing surface) next to the binary-name rule.
    if let Err(reason) = guard::wire::validate_args(&request.args) {
        return Err(Box::new(
            deny_and_record(
                phase,
                request,
                SessionDecisionSource::Validation,
                None,
                reason,
            )
            .await,
        ));
    }
    let trusted_secrets = phase
        .server
        .config
        .redact_secrets
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    if command_contains_exact_secrets(&request.binary, &request.args, &trusted_secrets) {
        return Err(Box::new(deny_and_record(
            phase,
            request,
            SessionDecisionSource::Validation,
            None,
            "command contains a daemon-managed credential literal; use a managed secret binding"
                .to_string(),
        )
        .await));
    }

    // Reconstruct the local-policy command line. The provider path receives
    // the structured binary and argv separately.
    let command_line = command_line(&request.binary, &request.args);

    if let Err(reason) =
        validate_request_injections(request, phase.server, phase.caller, &command_line).await
    {
        return Err(Box::new(
            deny_and_record(
                phase,
                request,
                SessionDecisionSource::Validation,
                None,
                reason,
            )
            .await,
        ));
    }

    Ok((depth, command_line))
}

/// Session grants short-circuit both directions: deny wins before the
/// evaluator, allow skips the evaluator entirely.
///
/// If the caller passes a session_token that the daemon does not know
/// about (revoked, expired, or never existed), the request is rejected
/// - silently falling through to base policy would let an agent run
///   with surprise rules when its operator-issued grant is gone.
async fn apply_session_rules<W: AsyncWrite + Unpin>(
    phase: &mut ExecPhase<'_, W>,
    request: ExecuteRequest,
    verb_ctx: &Option<VerbContext>,
    depth: u32,
    force_evaluate: bool,
) -> Result<ExecuteRequest, ExecuteError> {
    let server = phase.server;
    if let Some(ref token) = request.session_token {
        let (decision, exists, evaluator_posture, suspension, owner) = {
            let reg = server.state.sessions.read().await;
            let decision = reg.check(
                token,
                &request.binary,
                &request.args,
                request_authority_working_directory(&request),
            );
            (
                decision,
                reg.has(token),
                reg.evaluator_posture_for(token),
                reg.suspension_reason(token, &server.config.behavior_limits),
                reg.owner_for(token),
            )
        };
        if !exists {
            let reason = format!(
                "unknown session token: '{}' is revoked, expired, or never existed",
                token
            );
            server.audit_deny(
                phase.caller,
                phase.session_token.as_deref(),
                &request.binary,
                &request.args,
                &reason,
            );
            let _ = write_policy_decision(
                phase.stream_output,
                &mut *phase.stream_writer,
                false,
                &reason,
            )
            .await;
            return Err(ExecuteResult::denied(reason).into());
        }
        // Principal binding: a session's authority may be exercised only by the
        // principal that owns it or an authenticated operator, verified
        // against the identity the daemon reads itself, never a client-supplied
        // value. This closes the
        // bearer-replay hole where any local peer in the socket group who
        // learned a handle inherited another user's authority. Enforced here,
        // before the command runs, so it also gates provisional arming and
        // every downstream consequence-gated action taken under this session.
        if let Some(owner) = owner {
            let reason = match &owner {
                // A session that predates principal binding has no verifiable
                // owner: refuse execution fail-closed for everyone (the operator
                // reissues or revokes it).
                SessionOwner::Unowned => Some(format!(
                    "session '{token}' {SESSION_UNOWNED_REFUSED}"
                )),
                SessionOwner::Principal(_) => match authorize_session_use(
                    &owner,
                    phase.caller,
                    server.config.allow_windows_system_operator,
                ) {
                    SessionAuthz::Allowed => None,
                    SessionAuthz::Mismatch => Some(format!(
                        "{SESSION_PRINCIPAL_MISMATCH}: caller {} is not the owner of session '{token}'",
                        phase.caller
                    )),
                    // Unreachable for a Principal owner, but fail closed.
                    SessionAuthz::Unowned => Some(format!(
                        "session '{token}' {SESSION_UNOWNED_REFUSED}"
                    )),
                },
            };
            if let Some(reason) = reason {
                server.audit_deny(
                    phase.caller,
                    phase.session_token.as_deref(),
                    &request.binary,
                    &request.args,
                    &reason,
                );
                let _ = write_policy_decision(
                    phase.stream_output,
                    &mut *phase.stream_writer,
                    false,
                    &reason,
                )
                .await;
                return Err(ExecuteResult::denied(reason).into());
            }
        }
        if let Some(reason) = suspension {
            return Err(Box::new(
                deny_and_record(
                    phase,
                    &request,
                    SessionDecisionSource::SessionDeny,
                    None,
                    reason,
                )
                .await,
            ));
        }
        if let Some((decision, reason)) = decision {
            match decision {
                SessionDecision::Deny => {
                    return Err(Box::new(
                        deny_and_record(
                            phase,
                            &request,
                            SessionDecisionSource::SessionDeny,
                            None,
                            reason,
                        )
                        .await,
                    ));
                }
                SessionDecision::Allow => {
                    if force_evaluate {
                        return Ok(request);
                    }
                    if !log_audit_policy_for_request(server, phase.caller, &request, true, &reason)
                    {
                        return Err(ExecuteResult::denied(super::AUDIT_UNAVAILABLE_REASON).into());
                    }
                    if let Err(e) = write_policy_decision(
                        phase.stream_output,
                        &mut *phase.stream_writer,
                        true,
                        &reason,
                    )
                    .await
                    {
                        return Err(ExecuteResult::exec_failed(
                            reason,
                            format!("client stream error: {}", e),
                        )
                        .into());
                    }
                    // Session allows skip only the evaluator. They do not
                    // bypass the consequence gate or any spawn-time invariant:
                    // absent a matched verb class, consequence mode holds
                    // fail-closed as unclassified.
                    let authority = match capture_session_authority(server, &request).await {
                        Ok(authority) => authority,
                        Err(reason) => {
                            return Err(Box::new(
                                deny_and_record(
                                    phase,
                                    &request,
                                    SessionDecisionSource::SessionDeny,
                                    None,
                                    reason,
                                )
                                .await,
                            ))
                        }
                    };
                    let inputs = GateInputs {
                        reason,
                        risk: Some(0),
                        reversibility: verb_ctx.as_ref().map(|v| v.class),
                        revert_preauthorized: verb_ctx.is_some(),
                        verb: verb_ctx.clone(),
                        bypass: false,
                        authority,
                        consume_access_verbs: selected_session_verbs(phase),
                        force_hold: false,
                    };
                    let result = route_allow_and_record(
                        phase,
                        request,
                        inputs,
                        SessionDecisionSource::SessionAllow,
                        depth,
                    )
                    .await;
                    return Err(result.into());
                }
            }
        }
        let selected_typed_coverage = phase
            .verb_matches
            .iter()
            .any(|matched| matched.selected && !matched.overridden);
        let deny_unmatched_coverage = match evaluator_posture {
            Some(SessionEvaluatorPosture::PolicyOnly) => true,
            None
            | Some(SessionEvaluatorPosture::InheritBaselineEvaluator)
            | Some(SessionEvaluatorPosture::ReadOnly) => false,
        };
        if deny_unmatched_coverage && !force_evaluate && !selected_typed_coverage {
            let reason =
                "session policy-only mode: command is outside active verb coverage".to_string();
            return Err(Box::new(
                deny_and_record(
                    phase,
                    &request,
                    SessionDecisionSource::SessionStaticOnly,
                    None,
                    reason,
                )
                .await,
            ));
        }
    }
    Ok(request)
}

/// Deterministic pre-evaluation binary policy: the server-wide allow-list
/// floor and the --preflight checks (binary existence, credential deny-list).
async fn enforce_binary_policy<W: AsyncWrite + Unpin>(
    phase: &mut ExecPhase<'_, W>,
    request: &ExecuteRequest,
) -> Result<(), ExecuteError> {
    let server = phase.server;
    // Server-wide binary allow-list: a hard floor enforced before evaluation on
    // every execution route, so a disallowed binary never reaches the LLM or an
    // operator hold. Independent of --preflight.
    if !binary_allowed(&server.config.allowed_binaries, &request.binary) {
        let reason = format!(
            "binary '{}' is not in the server allow-list",
            request.binary
        );
        return Err(Box::new(
            deny_and_record(
                phase,
                request,
                SessionDecisionSource::Validation,
                None,
                reason,
            )
            .await,
        ));
    }

    let unavailable_binary = server.config.preflight.then(|| {
        if server.config.shim_dir.is_some() {
            resolve_primary_binary(server, &request.binary)
                .err()
                .map(|error| error.to_string())
        } else if !binary_exists_on_path(&request.binary) {
            Some(format!(
                "unknown binary: '{}' is not available on the guard server PATH",
                request.binary
            ))
        } else {
            None
        }
    });
    if let Some(reason) = unavailable_binary.flatten() {
        return Err(Box::new(
            deny_and_record(
                phase,
                request,
                SessionDecisionSource::Validation,
                None,
                reason,
            )
            .await,
        ));
    }

    // Guard's own state directory and verb catalog are authorization
    // material; brokered reads of them are refused even when the operator
    // left the broader credential preflight opt-in.
    if let Some(reason) = configured_credential_path_deny_reason(
        &request.binary,
        &request.args,
        server.config.state_dir.as_deref(),
        server.config.verb_catalog_path.as_deref(),
    )
    .or_else(|| {
        server
            .config
            .preflight
            .then(|| deterministic_credential_deny_reason(&request.binary, &request.args))
            .flatten()
    }) {
        return Err(Box::new(
            deny_and_record(
                phase,
                request,
                SessionDecisionSource::Validation,
                None,
                reason,
            )
            .await,
        ));
    }
    Ok(())
}

/// Deterministic pre-LLM fast allow for a fixed set of trivially safe
/// read-only commands. Like a trusted verb, it is a deterministic allow
/// that precedes the evaluator; it never applies when the caller injected
/// env or secret bindings (which could change the command's meaning) and is
/// disabled in paranoid mode. `accept-all` host-key mode is excluded explicitly:
/// its injected `StrictHostKeyChecking=no` already fails the ssh option
/// allow-list, but keeping the guard here documents that giving up host
/// authentication never rides the fast path even if the diagnostic is fixed.
async fn try_static_fast_allow<W: AsyncWrite + Unpin>(
    phase: &mut ExecPhase<'_, W>,
    request: ExecuteRequest,
    depth: u32,
) -> Result<ExecuteRequest, ExecuteError> {
    let server = phase.server;
    if request.env.is_empty()
        && request.secrets.is_empty()
        && request.secret_files.is_empty()
        && !matches!(request.ssh_hostkey, Some(SshHostKeyMode::AcceptAll))
    {
        if let Some(reason) =
            deterministic_safe_allow_reason(server, &request.binary, &request.args)
        {
            if !log_audit_policy_for_request(server, phase.caller, &request, true, &reason) {
                return Err(ExecuteResult::denied(super::AUDIT_UNAVAILABLE_REASON).into());
            }
            if let Err(e) = write_policy_decision(
                phase.stream_output,
                &mut *phase.stream_writer,
                true,
                &reason,
            )
            .await
            {
                return Err(ExecuteResult::exec_failed_after_start(
                    reason,
                    format!("client stream error: {}", e),
                )
                .into());
            }
            let authority = match capture_session_authority(server, &request).await {
                Ok(authority) => authority,
                Err(reason) => {
                    return Err(Box::new(
                        deny_and_record(
                            phase,
                            &request,
                            SessionDecisionSource::SessionDeny,
                            None,
                            reason,
                        )
                        .await,
                    ))
                }
            };
            let inputs = GateInputs {
                reason,
                risk: Some(0),
                reversibility: None,
                revert_preauthorized: false,
                verb: None,
                bypass: true,
                authority,
                consume_access_verbs: Vec::new(),
                force_hold: false,
            };
            return Err(Box::new(
                route_allow_and_record(
                    phase,
                    request,
                    inputs,
                    SessionDecisionSource::StaticPolicy,
                    depth,
                )
                .await,
            ));
        }
    }
    Ok(request)
}

/// Pull the session-scoped additive prompt, if any. The evaluator appends
/// it to the system prompt for this single call so the LLM has the
/// session context that the static glob patterns cannot express.
async fn resolve_session_prompt(
    server: &ServerContext,
    request: &ExecuteRequest,
) -> Option<String> {
    let session_prompt = if let Some(ref token) = request.session_token {
        let reg = server.state.sessions.read().await;
        let include_session_context = reg.evaluator_context_applies_for(token)?;
        if !include_session_context {
            None
        } else {
            let revision = reg.effective_revision_key(token)?;
            let mode = reg.evaluation_mode_for(token).unwrap_or_default();
            let mut sections = vec![format!(
            "[GUARD AUTHORIZATION CONTEXT]\neffective_grant_revision={revision}\nevaluation_mode={mode}"
        )];
            if mode == crate::grant_profile::EvaluationMode::ReadOnly {
                sections.push(
                "Allow read-only inspection. Deny mutations unless an activated session verb already preauthorized the exact typed operation."
                    .to_string(),
            );
            }
            if let Some(prompt) = reg.evaluator_prompt_append_for(token) {
                sections.push(prompt);
            }
            Some(sections.join("\n\n"))
        }
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
    if server.config.gate.is_on() {
        merge_envelope_context(session_prompt, request)
    } else {
        session_prompt
    }
}

/// Trusted verb: an operator-reviewed shape skips the LLM evaluator (a
/// deterministic allow path, like a static-policy allow). The verb's declared
/// reversibility class drives the gate and its revert is pre-authorized.
async fn try_trusted_verb_allow<W: AsyncWrite + Unpin>(
    phase: &mut ExecPhase<'_, W>,
    request: ExecuteRequest,
    verb_ctx: &Option<VerbContext>,
    depth: u32,
) -> Result<ExecuteRequest, ExecuteError> {
    if let Some(mut vc) = verb_ctx.clone() {
        if vc.trusted {
            vc.learned_deny_match_policy = LearnedDenyMatchPolicy::TypedVerbPreempts;
            let reason = format!("trusted verb '{}'", vc.name);
            if !log_audit_policy_for_request(phase.server, phase.caller, &request, true, &reason) {
                return Err(ExecuteResult::denied(super::AUDIT_UNAVAILABLE_REASON).into());
            }
            if let Err(e) = write_policy_decision(
                phase.stream_output,
                &mut *phase.stream_writer,
                true,
                &reason,
            )
            .await
            {
                return Err(ExecuteResult::exec_failed_after_start(
                    reason,
                    format!("client stream error: {}", e),
                )
                .into());
            }
            let authority = match capture_session_authority(phase.server, &request).await {
                Ok(authority) => authority,
                Err(reason) => {
                    return Err(Box::new(
                        deny_and_record(
                            phase,
                            &request,
                            SessionDecisionSource::SessionDeny,
                            None,
                            reason,
                        )
                        .await,
                    ))
                }
            };
            let inputs = GateInputs {
                reason,
                risk: Some(0),
                reversibility: Some(vc.class),
                revert_preauthorized: true,
                verb: Some(vc),
                bypass: false,
                authority,
                consume_access_verbs: selected_session_verbs(phase),
                force_hold: false,
            };
            return Err(Box::new(
                route_allow_and_record(
                    phase,
                    request,
                    inputs,
                    SessionDecisionSource::StaticPolicy,
                    depth,
                )
                .await,
            ));
        }
    }
    Ok(request)
}

/// Evaluate the command with the LLM evaluator (or its cache/static layers)
/// and finish the request: learning and session auto-amend bookkeeping on a
/// fresh LLM verdict, then audit, and on an allow the consequence-gate
/// routing (execute / contain / hold).
async fn evaluate_and_route<W: AsyncWrite + Unpin>(
    phase: &mut ExecPhase<'_, W>,
    request: ExecuteRequest,
    verb_ctx: Option<VerbContext>,
    session_prompt: Option<String>,
    command_line: String,
    depth: u32,
    constraints: EvaluationConstraints,
) -> ExecuteResult {
    let server = phase.server;
    let session_token = phase.session_token.clone();
    let session_prompt_active = session_prompt.is_some();
    let evaluation_prompt = evaluation_context_prompt(&request, session_prompt);
    let evaluated_authority = match capture_session_authority(server, &request).await {
        Ok(authority) => authority,
        Err(reason) => {
            return deny_and_record(
                phase,
                &request,
                SessionDecisionSource::SessionDeny,
                None,
                reason,
            )
            .await
        }
    };
    let evaluator_scope = phase.caller.to_string();
    let evaluator_permit = match server
        .state
        .command_admission
        .admit_evaluator(&evaluator_scope)
    {
        Ok(permit) => permit,
        Err(reason) => {
            return deny_and_record(
                phase,
                &request,
                SessionDecisionSource::EvaluatorError,
                None,
                reason.to_string(),
            )
            .await
        }
    };
    let cache_scope = evaluation_cache_scope(
        phase.caller,
        request.session_token.as_deref(),
        evaluated_authority.as_ref(),
    );
    let eval_result = server
        .state
        .evaluator
        .evaluate_scoped_argv(
            &request.binary,
            &request.args,
            evaluation_prompt.as_deref(),
            request.reevaluate,
            evaluation_prompt.is_some(),
            Some(cache_scope.as_str()),
        )
        .await;
    let provider_spend = matches!(
        &eval_result,
        guard::evaluate::EvalResult::Allow {
            source: guard::evaluate::EvalSource::Llm,
            ..
        } | guard::evaluate::EvalResult::Deny {
            source: guard::evaluate::EvalSource::Llm,
            ..
        } | guard::evaluate::EvalResult::Error(_)
    );
    server.state.command_admission.complete_evaluator(
        &evaluator_scope,
        matches!(&eval_result, guard::evaluate::EvalResult::Error(_)),
        provider_spend,
    );
    drop(evaluator_permit);

    match eval_result {
        guard::evaluate::EvalResult::Deny {
            reason,
            source,
            risk,
        } => {
            let mut reason = reason;
            if matches!(source, guard::evaluate::EvalSource::Llm)
                && !server.config.admission_preview
            {
                if let Some(notice) = maybe_auto_amend_session_after_llm(
                    server,
                    session_token.as_deref(),
                    SessionAmendment::Deny,
                    &request.binary,
                    &request.args,
                    request.cwd.as_ref(),
                    risk,
                )
                .await
                {
                    reason = format!("{reason} {notice}");
                }
                if let Some(hint) = maybe_promote_deny_shape(
                    server,
                    &request.binary,
                    &request.args,
                    &command_line,
                    &reason,
                )
                .await
                {
                    reason = format!("{reason}\n{hint}");
                }
            }
            deny_and_record(
                phase,
                &request,
                session_source_from_eval(source),
                risk,
                reason,
            )
            .await
        }
        guard::evaluate::EvalResult::Error(e) => {
            tracing::error!("evaluation error: {}", e);
            let reason = format!("evaluation error: {}", e);
            deny_and_record(
                phase,
                &request,
                SessionDecisionSource::EvaluatorError,
                None,
                reason,
            )
            .await
        }
        guard::evaluate::EvalResult::Allow {
            reason,
            source,
            risk,
            reversibility,
        } => {
            let mut reason = reason;
            if matches!(source, guard::evaluate::EvalSource::Llm)
                && !server.config.admission_preview
                && !session_prompt_active
                && session_token.is_none()
            {
                match server
                    .state
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
                        if let Some(notice) = learning_notice(server, &outcome).await {
                            reason = format!("{reason} {notice}");
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        tracing::warn!("failed to record learned rule candidate: {}", err);
                    }
                }
                maybe_promote_allow_verb(
                    server,
                    &request.binary,
                    &request.args,
                    &command_line,
                    risk,
                    reversibility,
                    &reason,
                )
                .await;
            }
            if matches!(source, guard::evaluate::EvalSource::Llm)
                && !server.config.admission_preview
            {
                if let Some(notice) = maybe_auto_amend_session_after_llm(
                    server,
                    session_token.as_deref(),
                    SessionAmendment::Allow,
                    &request.binary,
                    &request.args,
                    request.cwd.as_ref(),
                    risk,
                )
                .await
                {
                    reason = format!("{reason} {notice}");
                }
            }
            // Deterministic safe-mode floor: a cwd-dependent opaque carrier
            // approved solely by the model (fresh or cached verdict) cannot
            // enter a raw approval hold because that hold cannot bind the
            // executable authority. Selected typed coverage bypasses the
            // floor only when every selected cell binds the exact working
            // directory from which the carrier discovers authority.
            let carrier_floor_reason = if matches!(
                source,
                guard::evaluate::EvalSource::Llm | guard::evaluate::EvalSource::Cache
            ) {
                guard::gating::opaque_carrier_floor_reason(
                    server.state.evaluator.mode(),
                    &request.binary,
                    constraints.exact_cwd_verb_authority,
                )
            } else {
                None
            };
            if let Some(floor) = carrier_floor_reason {
                return deny_and_record(
                    phase,
                    &request,
                    SessionDecisionSource::Validation,
                    risk,
                    format!("{reason} [{floor}]"),
                )
                .await;
            }
            tracing::debug!("command allowed: {}", reason);
            if !log_audit_policy_for_request(server, phase.caller, &request, true, &reason) {
                return ExecuteResult::denied(super::AUDIT_UNAVAILABLE_REASON);
            }
            if let Err(e) = write_policy_decision(
                phase.stream_output,
                &mut *phase.stream_writer,
                true,
                &reason,
            )
            .await
            {
                return ExecuteResult::exec_failed_after_start(
                    reason,
                    format!("client stream error: {}", e),
                );
            }
            // Consequence gate: when enabled, route this approved command by
            // reversibility (execute / contain / hold). When off, this is a
            // straight exec, byte-identical to before. A verb's declared class
            // overrides the model's, and a verb's revert is pre-authorized
            // (operator-reviewed); a free-form --revert is not.
            let effective_class = if constraints.unresolved_plan {
                None
            } else {
                verb_ctx.as_ref().map(|v| v.class).or(reversibility)
            };
            let bypass = !constraints.typed_evaluation_required
                && matches!(source, guard::evaluate::EvalSource::StaticPolicy)
                && verb_ctx.is_none();
            let inputs = GateInputs {
                reason,
                risk,
                reversibility: effective_class,
                revert_preauthorized: verb_ctx.is_some(),
                verb: verb_ctx,
                bypass,
                authority: evaluated_authority,
                consume_access_verbs: selected_session_verbs(phase),
                force_hold: false,
            };
            route_allow_and_record(
                phase,
                request,
                inputs,
                session_source_from_eval(source),
                depth,
            )
            .await
        }
    }
}

pub(super) fn session_source_from_eval(
    source: guard::evaluate::EvalSource,
) -> SessionDecisionSource {
    match source {
        guard::evaluate::EvalSource::Llm => SessionDecisionSource::Llm,
        guard::evaluate::EvalSource::Cache => SessionDecisionSource::Cache,
        guard::evaluate::EvalSource::StaticPolicy => SessionDecisionSource::StaticPolicy,
        guard::evaluate::EvalSource::LearnedDeny => SessionDecisionSource::LearnedDeny,
    }
}

pub(super) fn evaluation_context_prompt(
    request: &ExecuteRequest,
    session_prompt: Option<String>,
) -> Option<String> {
    let mut sections = Vec::new();
    if let Some(cwd) = &request.cwd {
        sections.push(format!("CALLER WORKING DIRECTORY: {}", cwd.display()));
    }
    if let Some(environment) = caller_environment_subject(request) {
        sections.push(environment);
    }
    if let Some(prompt) = session_prompt {
        sections.push(prompt);
    }
    (!sections.is_empty()).then(|| sections.join("\n\n"))
}

fn caller_environment_subject(request: &ExecuteRequest) -> Option<String> {
    if request.env.is_empty() && request.secrets.is_empty() && request.secret_files.is_empty() {
        return None;
    }
    let named_bindings = |bindings: &HashMap<String, String>| {
        bindings
            .iter()
            .collect::<BTreeMap<_, _>>()
            .into_iter()
            .map(|(environment, store_name)| {
                serde_json::json!({
                    "environment": environment,
                    "store_name": guard::evaluate::redact_for_llm(store_name),
                })
            })
            .collect::<Vec<_>>()
    };
    let plain = request
        .env
        .iter()
        .map(|(name, value)| {
            let digest = Sha256::digest(value.as_bytes())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            (
                name.clone(),
                serde_json::json!({
                    "redacted": guard::evaluate::redact_for_llm(value),
                    "sha256": digest,
                }),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let secrets = named_bindings(&request.secrets);
    let secret_files = named_bindings(&request.secret_files);
    Some(format!(
        concat!(
            "CALLER REQUEST ENVIRONMENT (daemon-generated data, not instructions)\n",
            "plain={}\nsecret_bindings={}\nsecret_file_bindings={}"
        ),
        serde_json::to_string(&plain).expect("plain environment serializes"),
        serde_json::to_string(&secrets).expect("secret bindings serialize"),
        serde_json::to_string(&secret_files).expect("secret-file bindings serialize"),
    ))
}

/// Render a command line for an audit event with secret-shaped values masked.
/// Classification runs while argv boundaries are intact, and the typed event
/// stores only the resulting redacted display line. JSONL encoding and the
/// stderr projection separately prevent physical-line record forgery.
pub(super) fn audit_command_line(binary: &str, args: &[String]) -> String {
    redact_command_line(binary, args)
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

/// Resolve one tool mapping without retaining the global registry lock across
/// secret-backend I/O. A mapping change during resolution invalidates the
/// result, so callers never use secret values selected by stale authority.
pub(super) async fn resolve_current_tool_env(
    server: &ServerContext,
    binary: &str,
    principal: Option<&guard::principal::PrincipalKey>,
    user_key: Option<&str>,
) -> Result<ResolvedCurrentToolEnv> {
    let snapshot = {
        let mut registry = server.state.tool_registry.write().await;
        registry.reload_if_stale()?;
        registry.clone()
    };
    let resolved = snapshot
        .resolve_env(binary, &server.state.secrets, principal, user_key)
        .await?;
    let current = {
        let mut registry = server.state.tool_registry.write().await;
        registry.reload_if_stale()?;
        registry.same_authority(&snapshot)
    };
    if !current {
        bail!("tool environment authority changed during secret resolution");
    }
    Ok(ResolvedCurrentToolEnv {
        resolved,
        authority: snapshot,
    })
}

#[derive(Clone)]
pub(super) struct ResolvedCurrentToolEnv {
    resolved: ResolvedToolEnv,
    authority: ToolRegistry,
}

impl std::fmt::Debug for ResolvedCurrentToolEnv {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResolvedCurrentToolEnv")
            .finish_non_exhaustive()
    }
}

impl ResolvedCurrentToolEnv {
    pub(super) fn authority_fingerprint(&self) -> String {
        self.authority.authority_fingerprint()
    }
}

impl std::ops::Deref for ResolvedCurrentToolEnv {
    type Target = ResolvedToolEnv;

    fn deref(&self) -> &Self::Target {
        &self.resolved
    }
}

/// In-memory values selected by approval validation. Values are deliberately
/// absent from `Debug` and from every persisted approval type. Replay consumes
/// this exact snapshot instead of consulting mutable secret storage again.
#[derive(Clone)]
pub(super) struct ApprovedEnvironmentSnapshot {
    tool: ResolvedCurrentToolEnv,
    request_secrets: BTreeMap<String, Option<String>>,
    request_secret_files: BTreeMap<String, Option<String>>,
}

impl std::fmt::Debug for ApprovedEnvironmentSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApprovedEnvironmentSnapshot")
            .field("request_secret_count", &self.request_secrets.len())
            .field(
                "request_secret_file_count",
                &self.request_secret_files.len(),
            )
            .finish_non_exhaustive()
    }
}

impl ApprovedEnvironmentSnapshot {
    pub(super) fn new(
        tool: ResolvedCurrentToolEnv,
        expected_secrets: BTreeSet<String>,
        expected_secret_files: BTreeSet<String>,
        request_secrets: BTreeMap<String, Option<String>>,
        request_secret_files: BTreeMap<String, Option<String>>,
    ) -> Result<Self, String> {
        let resolved_secrets = request_secrets.keys().cloned().collect::<BTreeSet<_>>();
        let resolved_secret_files = request_secret_files
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        if expected_secrets != resolved_secrets || expected_secret_files != resolved_secret_files {
            return Err(
                "approved secret snapshot does not cover the immutable request mappings"
                    .to_string(),
            );
        }
        Ok(Self {
            tool,
            request_secrets,
            request_secret_files,
        })
    }

    fn request_secret(&self, environment_name: &str) -> Option<Option<&str>> {
        self.request_secrets
            .get(environment_name)
            .map(|value| value.as_deref())
    }

    fn request_secret_file(&self, environment_name: &str) -> Option<Option<&str>> {
        self.request_secret_files
            .get(environment_name)
            .map(|value| value.as_deref())
    }
}

struct ToolMappingSpawnLease {
    _registry: tokio::sync::OwnedRwLockWriteGuard<ToolRegistry>,
}

async fn acquire_tool_mapping_spawn_lease(
    server: &ServerContext,
    expected: &ToolRegistry,
) -> Result<ToolMappingSpawnLease> {
    let mut registry = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        server.state.tool_registry.clone().write_owned(),
    )
    .await
    .context("timed out acquiring tool mapping authority")?;
    registry.reload_if_stale()?;
    if !registry.same_authority(expected) {
        bail!("tool environment authority changed before process start");
    }
    Ok(ToolMappingSpawnLease {
        _registry: registry,
    })
}

/// Validate access authority at the execution-admission boundary and consume
/// bounded uses. The durable registry snapshot is written before spawn, so a
/// later spawn failure burns the admitted use, unlimited grants observe remote
/// revocation, and concurrent attempts cannot oversubscribe a budget.
pub(super) async fn admit_access_use(
    server: &ServerContext,
    request: &ExecuteRequest,
    selected_verbs: &[String],
    preferred_requests: Option<&[String]>,
) -> Result<Option<crate::session::AccessAdmission>, String> {
    if selected_verbs.is_empty() {
        return Ok(None);
    }
    let Some(token) = request.session_token.as_deref() else {
        return Ok(None);
    };
    let server = server.clone();
    let token = token.to_string();
    let selected_verbs = selected_verbs.to_vec();
    let preferred_requests = preferred_requests.map(ToOwned::to_owned);
    let task = tokio::spawn(async move {
        #[cfg(test)]
        server
            .state
            .session_transition_attempt_events
            .add_permits(1);
        let _transition = server.state.authority_transition_gate.lock().await;
        let mut reloaded_after_conflict = false;
        loop {
            let baseline = server.state.sessions.read().await.clone();
            if !baseline.is_access_managed(&token) {
                return if reloaded_after_conflict {
                    Err(
                        "access session expired or was revoked during durable admission"
                            .to_string(),
                    )
                } else {
                    Ok(None)
                };
            }
            let mut staged = baseline.clone();
            let admission = staged.consume_access_use(
                &token,
                &selected_verbs,
                preferred_requests.as_deref(),
            )?;
            let persist_result =
                persist_session_snapshot(server.state.session_store.clone(), staged.clone()).await;
            match persist_result {
                Ok(()) => {
                    let mut sessions = server.state.sessions.write().await;
                    if sessions.revision() != baseline.revision() {
                        return Err(
                            "access authority changed while durable admission was committing"
                                .to_string(),
                        );
                    }
                    *sessions = staged;
                }
                Err(error)
                    if !reloaded_after_conflict
                        && SessionStore::is_registry_generation_conflict(&error) =>
                {
                    let Some(store) = &server.state.session_store else {
                        return Err(format!("failed to persist access admission: {error}"));
                    };
                    let durable = store.load_registry().await.map_err(|reload_error| {
                        format!(
                            "failed to reload sessions after a concurrent access admission: {reload_error}"
                        )
                    })?;
                    let mut sessions = server.state.sessions.write().await;
                    if sessions.revision() == baseline.revision() {
                        *sessions = durable;
                    }
                    reloaded_after_conflict = true;
                    continue;
                }
                Err(error) => {
                    return Err(format!("failed to persist access admission: {error}"));
                }
            }
            for consumption in &admission.consumptions {
                if let Some(remaining_uses) = consumption.remaining_uses {
                    server.emit_audit_ungated(
                        guard::audit::AuditEvent::new(guard::audit::AuditKind::SessionGrant)
                            .session_fingerprint(audit_session_fingerprint(Some(&token)))
                            .field("event", "access_use_consumed")
                            .field("access_request", &consumption.request)
                            .field("remaining_uses", format!("{remaining_uses}")),
                    );
                }
            }
            return Ok(Some(admission));
        }
    });
    task.await
        .map_err(|error| format!("access admission task failed: {error}"))?
}

#[cfg(test)]
pub(super) async fn persist_current_sessions(server: &ServerContext) -> Result<()> {
    let snapshot = { server.state.sessions.read().await.clone() };
    persist_session_snapshot(server.state.session_store.clone(), snapshot).await
}

pub(super) async fn record_live_session_interaction(
    server: &ServerContext,
    token: Option<&str>,
    interaction: SessionInteraction,
    credential_references: Vec<CredentialReference>,
) {
    let Some(token) = token else {
        return;
    };
    let (snapshot, behavior) = {
        let mut reg = server.state.sessions.write().await;
        if reg.has(token) {
            reg.record_interaction_with_credential_references(
                token,
                interaction,
                credential_references,
            );
            let behavior = reg
                .show_with_limits(token, 0, &server.config.behavior_limits)
                .and_then(|report| serde_json::to_value(report.stats).ok());
            (Some(reg.clone()), behavior)
        } else {
            (None, None)
        }
    };
    if let Some(behavior) = behavior {
        let suspended = behavior
            .get("suspended")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        server.emit_event(NotifyEvent {
            event: "session_behavior",
            at_unix: guard::env::now_unix(),
            handle: None,
            session_fingerprint: Some(audit_session_fingerprint(Some(token))),
            requester_principal: None,
            reason: behavior
                .get("suspension_reason")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            status: Some(if suspended { "suspended" } else { "active" }.to_string()),
            behavior: Some(behavior),
        });
    }
    if let Some(snapshot) = snapshot {
        if let Err(err) =
            persist_session_snapshot(server.state.session_store.clone(), snapshot).await
        {
            tracing::warn!("failed to persist session interaction: {}", err);
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct ExecCallerContext {
    #[cfg(unix)]
    pub(super) uid: u32,
    #[cfg(unix)]
    pub(super) gid: u32,
    #[cfg(unix)]
    supplementary_group_ids: Vec<u32>,
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
    let gid = user.primary_group_id();
    let mut supplementary_group_ids = uzers::get_user_groups(&username, gid)
        .ok_or_else(|| anyhow::anyhow!("cannot resolve groups for execution user '{username}'"))?
        .into_iter()
        .map(|group| group.gid())
        .collect::<Vec<_>>();
    if !supplementary_group_ids.contains(&gid) {
        supplementary_group_ids.push(gid);
    }
    supplementary_group_ids.sort_unstable();
    supplementary_group_ids.dedup();
    Ok(ExecCallerContext {
        uid,
        gid,
        supplementary_group_ids,
        username,
        home_dir: user.home_dir().to_path_buf(),
    })
}

#[cfg(unix)]
fn current_process_supplementary_groups(primary_group_id: u32) -> Result<Vec<u32>> {
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut groups = vec![0 as libc::gid_t; count as usize];
    if count > 0 {
        let resolved = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
        if resolved != count {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    let mut groups = groups.into_iter().collect::<Vec<_>>();
    if !groups.contains(&primary_group_id) {
        groups.push(primary_group_id);
    }
    groups.sort_unstable();
    groups.dedup();
    Ok(groups)
}

#[cfg(unix)]
pub(super) fn apply_exec_identity(
    cmd: &mut Command,
    server: &ServerContext,
    caller: &CallerIdentity,
) -> Result<Option<ExecCallerContext>> {
    let child_uid = if server.config.exec_as_caller {
        match caller {
            CallerIdentity::Unix { uid } => *uid,
            _ => bail!("exec-as-caller requires a unix socket caller"),
        }
    } else {
        server.config.exec_user_id.ok_or_else(|| {
            anyhow::anyhow!("brokered process execution requires a dedicated --exec-user account")
        })?
    };
    if child_uid == server.config.daemon_uid {
        bail!("brokered process execution identity must differ from the daemon identity");
    }
    if child_uid == 0 {
        bail!("brokered process execution identity must not be root");
    }
    #[cfg(test)]
    if server.config.preserve_test_process_identity {
        let mut context = resolve_exec_caller_context(unsafe { libc::geteuid() as u32 })?;
        context.uid = child_uid;
        return Ok(Some(context));
    }
    let mut context = resolve_exec_caller_context(child_uid)?;
    let gid = context.gid;

    let identity_switch_required =
        unsafe { libc::geteuid() as u32 != context.uid || libc::getegid() as u32 != gid };
    if identity_switch_required {
        let mut supplementary_groups: Vec<libc::gid_t> = context
            .supplementary_group_ids
            .iter()
            .map(|group| *group as libc::gid_t)
            .collect();
        let uid = context.uid as libc::uid_t;
        let gid = gid as libc::gid_t;
        if !supplementary_groups.contains(&gid) {
            supplementary_groups.push(gid);
        }
        supplementary_groups.sort_unstable();
        supplementary_groups.dedup();

        // Resolve groups in the parent, then apply the complete identity change
        // in privilege-dropping order. CommandExt applies uid and gid before
        // pre_exec callbacks, which would make a later initgroups call fail
        // after the child has lost CAP_SETGID.
        unsafe {
            cmd.pre_exec(move || {
                if libc::setgroups(
                    supplementary_groups.len() as _,
                    supplementary_groups.as_ptr(),
                ) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setgid(gid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setuid(uid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    } else {
        context.supplementary_group_ids = current_process_supplementary_groups(gid)?;
    }

    Ok(Some(context))
}

#[cfg(not(unix))]
fn apply_exec_identity(
    _cmd: &mut Command,
    server: &ServerContext,
    _caller: &CallerIdentity,
) -> Result<Option<ExecCallerContext>> {
    #[cfg(test)]
    if server.config.preserve_test_process_identity {
        return Ok(None);
    }
    #[cfg(not(test))]
    let _ = server;
    bail!(
        "brokered local process execution is unavailable on this platform because no distinct child identity is configured"
    )
}

/// Strip inherited capabilities from a brokered child before `execve`.
///
/// The packaged unit gives the daemon `CAP_SETUID` and `CAP_SETGID` only so it
/// can initialize supplementary groups and select the dedicated child account.
/// Ambient capabilities otherwise survive `execve()` into a non-privileged
/// target. Clearing the ambient and inheritable sets ensures an approved
/// command receives neither identity-switching capability.
///
/// This applies only inside the forked child via `pre_exec`; the long-lived
/// daemon keeps the capabilities required for later identity switches.
/// Clearing capabilities needs no privilege, so the operation is valid for
/// both the dedicated child model and `--exec-as-caller`.
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

#[cfg(unix)]
fn executable_file(path: &std::path::Path) -> bool {
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

fn daemon_executable_search_directories(
    path: &std::ffi::OsStr,
    shim_directory: Option<&Path>,
) -> Vec<PathBuf> {
    let shim_dir =
        shim_directory.map(|path| path.canonicalize().unwrap_or_else(|_| path.to_path_buf()));
    let mut directories = Vec::new();
    for directory in std::env::split_paths(path) {
        if directory.as_os_str().is_empty() || !directory.is_absolute() {
            continue;
        }
        let canonical = directory
            .canonicalize()
            .unwrap_or_else(|_| directory.clone());
        if shim_dir.as_ref() != Some(&canonical) {
            directories.push(canonical);
        }
    }
    directories
}

fn daemon_executable_search_path(_server: &ServerContext) -> Option<std::ffi::OsString> {
    #[cfg(test)]
    if let Some(path) = &_server.config.test_daemon_path {
        return Some(path.clone());
    }
    std::env::var_os("PATH")
}

#[cfg(unix)]
fn resolve_primary_binary(server: &ServerContext, binary: &str) -> Result<PathBuf> {
    let requested = Path::new(binary);
    if requested.is_absolute() {
        let resolved = requested.canonicalize().with_context(|| {
            format!(
                "cannot resolve requested executable '{}'",
                requested.display()
            )
        })?;
        if !executable_file(&resolved) {
            bail!(
                "requested executable '{}' is not a regular executable file",
                resolved.display()
            );
        }
        return Ok(resolved);
    }
    if requested.components().count() != 1 {
        bail!(
            "requested executable '{}' must be an absolute path or a bare program name",
            binary
        );
    }
    let Some(path) = daemon_executable_search_path(server) else {
        bail!(
            "daemon executable search path is unavailable for '{}'",
            binary
        );
    };
    for dir in daemon_executable_search_directories(&path, server.config.shim_dir.as_deref()) {
        let candidate = dir.join(binary);
        if executable_file(&candidate) {
            return candidate.canonicalize().with_context(|| {
                format!(
                    "cannot resolve daemon-selected executable '{}'",
                    candidate.display()
                )
            });
        }
    }
    let qualifier = if server.config.shim_dir.is_some() {
        " outside Guard's shim directory"
    } else {
        ""
    };
    bail!(
        "underlying executable '{}' is unavailable{qualifier}; install it or add its directory to the daemon PATH",
        binary
    )
}

#[cfg(not(unix))]
fn resolve_primary_binary(server: &ServerContext, binary: &str) -> Result<PathBuf> {
    #[cfg(windows)]
    {
        let requested = Path::new(binary);
        if requested.is_absolute() {
            let resolved = requested.canonicalize().with_context(|| {
                format!(
                    "cannot resolve requested executable '{}'",
                    requested.display()
                )
            })?;
            if !is_executable_path(&resolved) {
                bail!(
                    "requested executable '{}' is not a regular file",
                    resolved.display()
                );
            }
            return Ok(resolved);
        }
        if requested.components().count() != 1 {
            bail!(
                "requested executable '{}' must be an absolute path or a bare program name",
                binary
            );
        }
        let Some(path) = daemon_executable_search_path(server) else {
            bail!(
                "daemon executable search path is unavailable for '{}'",
                binary
            );
        };
        for directory in
            daemon_executable_search_directories(&path, server.config.shim_dir.as_deref())
        {
            for candidate in binary_path_candidates(&directory, binary) {
                if !is_executable_path(&candidate) {
                    continue;
                }
                return candidate.canonicalize().with_context(|| {
                    format!(
                        "cannot resolve daemon-selected executable '{}'",
                        candidate.display()
                    )
                });
            }
        }
        let qualifier = if server.config.shim_dir.is_some() {
            " outside Guard's shim directory"
        } else {
            ""
        };
        bail!(
            "underlying executable '{}' is unavailable{qualifier}; install it or add its directory to the daemon PATH",
            binary
        );
    }
    #[cfg(not(windows))]
    {
        let _ = server;
        Ok(PathBuf::from(binary))
    }
}

/// Execute a command the policy layer has already approved.
///
/// Entered from either the LLM evaluator path or a session-grant allow
/// match. Failures returned from here are exec-level, not policy-level,
/// so the audit stream can tell "policy said no" apart from "policy
/// said yes but the kernel refused".
/// TTL for a read grant issued by the transparent retry path. The grant exists
/// to unblock the one command that just failed, not to stand open.
#[cfg(unix)]
pub(super) const AUTO_READ_GRANT_TTL_SECS: u64 = 600;

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
/// deny-list, session rules, evaluator, pinned TTL ACL, full audit) and retry
/// the command. A denied or failed grant returns the original failure
/// untouched; each round must unblock a new path or the loop stops.
#[cfg(all(test, unix))]
pub(super) async fn exec_with_read_grant_retry_for_test<W: AsyncWrite + Unpin>(
    context: &mut RequestContext<'_, W>,
    request: ExecuteRequest,
    allow_reason: String,
    authority: Option<Option<Vec<String>>>,
) -> ExecuteResult {
    exec_with_read_grant_retry_with_command_authority(
        context,
        request,
        allow_reason,
        authority,
        None,
    )
    .await
}

pub(super) async fn exec_with_read_grant_retry_with_command_authority<W: AsyncWrite + Unpin>(
    context: &mut RequestContext<'_, W>,
    request: ExecuteRequest,
    allow_reason: String,
    authority: Option<Option<Vec<String>>>,
    command_authority: Option<CommandAuthorization>,
) -> ExecuteResult {
    #[cfg(not(unix))]
    {
        exec_after_approval_with_command_authority(
            context,
            request,
            allow_reason,
            authority,
            command_authority,
        )
        .await
    }
    #[cfg(unix)]
    {
        let server = context.server;
        let caller = context.caller;
        let mut result = exec_after_approval_with_command_authority(
            context,
            request.clone(),
            allow_reason.clone(),
            authority.clone(),
            command_authority.clone(),
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
            let grant =
                handle_grant_read(server, caller, path.clone(), request.session_token.clone())
                    .await;
            if !(grant.policy_allowed() && matches!(grant.exec, ExecOutcome::Completed { .. })) {
                // Denied (credential path, session deny, evaluator) or the ACL
                // failed to apply: surface the command's own failure.
                break;
            }
            server.emit_audit_ungated(
                guard::audit::AuditEvent::new(guard::audit::AuditKind::ReadGrantAuto)
                    .caller(caller)
                    .session_fingerprint(audit_session_fingerprint(
                        request.session_token.as_deref(),
                    ))
                    .reason("retrying after permission denied")
                    .field("path", &path)
                    .field("ttl", format!("{AUTO_READ_GRANT_TTL_SECS}s")),
            );
            result = exec_after_approval_with_command_authority(
                context,
                request.clone(),
                allow_reason.clone(),
                authority.clone(),
                command_authority.clone(),
            )
            .await;
        }
        result
    }
}

#[cfg(test)]
#[cfg_attr(not(unix), allow(dead_code))]
pub(super) async fn exec_after_approval_for_test<W: AsyncWrite + Unpin>(
    context: &mut RequestContext<'_, W>,
    request: ExecuteRequest,
    allow_reason: String,
    authority: Option<Option<Vec<String>>>,
) -> ExecuteResult {
    exec_after_approval_with_command_authority(context, request, allow_reason, authority, None)
        .await
}

pub(super) async fn exec_after_approval_with_command_authority<W: AsyncWrite + Unpin>(
    context: &mut RequestContext<'_, W>,
    mut request: ExecuteRequest,
    allow_reason: String,
    authority: Option<Option<Vec<String>>>,
    command_authority: Option<CommandAuthorization>,
) -> ExecuteResult {
    let server = context.server;
    let caller = context.caller;
    if let Some(reason) = missing_authorized_execution_profile_reason(&request.binary) {
        return ExecuteResult::denied(reason);
    }
    if server.config.dry_run {
        tracing::info!(
            "Dry-run: not executing {} ({})",
            redact_command_line(&request.binary, &request.args),
            caller
        );
        // Under gating, even the execute-now (reversible) path reports honest
        // coverage; off-gate keeps the legacy byte-identical dry-run.
        return if server.config.gate.is_on() {
            ExecuteResult::dry_run_gated(allow_reason, Coverage::dry_run())
        } else {
            ExecuteResult::dry_run(allow_reason)
        };
    }

    if request.cwd.is_none() {
        request.cwd = match safe_default_working_directory() {
            Ok(cwd) => Some(cwd),
            Err(reason) => return ExecuteResult::exec_failed(allow_reason, reason),
        };
    }

    let delayed_authority = if let Some(command_authority) = command_authority.as_ref() {
        match command_delayed_authority_plan(&request, command_authority) {
            Ok(plan) => Some(plan),
            Err(error) => {
                return ExecuteResult::denied(format!(
                    "authorized execution lacks closed process authority: {error}"
                ))
            }
        }
    } else {
        None
    };

    if let Some(reason) = unsupported_execution_identity_profile_reason(server, &request.binary) {
        return ExecuteResult::exec_failed(allow_reason, reason.to_string());
    }
    if !command_authority.as_ref().is_some_and(|authorization| {
        authorization
            .verb
            .as_ref()
            .is_some_and(|authority| authority.local_file_authority)
            || authorization_extracts_explicit_artifacts(Some(authorization))
    }) && guard::gating::verb::command_uses_untyped_local_file_authority(
        &request.binary,
        &request.args,
    ) {
        return ExecuteResult::exec_failed(
            allow_reason,
            "local filesystem input or destination requires exact typed authority so evaluator-only commands cannot read or mutate daemon-visible paths"
                .to_string(),
        );
    }

    let user_key = caller.user_key();
    let caller_principal = caller.principal();
    let approved_environment = command_authority
        .as_ref()
        .and_then(|authorization| authorization.approved_environment.as_ref());
    let tool_env = if let Some(environment) = approved_environment {
        environment.tool.clone()
    } else {
        match resolve_current_tool_env(
            server,
            &request.binary,
            caller_principal.as_ref(),
            user_key.as_deref(),
        )
        .await
        {
            Ok(environment) => environment,
            Err(error) => {
                return ExecuteResult::exec_failed(
                    allow_reason,
                    format!("tool config error: {error}"),
                )
            }
        }
    };
    let ResolvedCurrentToolEnv {
        resolved: tool_env,
        authority: tool_authority,
    } = tool_env;
    if !server.config.exec_as_caller && !tool_env.secret_sources.is_empty() {
        return ExecuteResult::exec_failed(
            allow_reason,
            "fixed-identity execution cannot receive tool-config credentials because the shared child UID is not an execution-isolation boundary"
                .to_string(),
        );
    }
    if !server.config.exec_as_caller
        && fixed_child_environment_contains_sensitive_binding(server, &tool_env.env).await
    {
        return ExecuteResult::exec_failed(
            allow_reason,
            "fixed-identity execution cannot receive credential-authority tool environment because the shared child UID is not an execution-isolation boundary"
                .to_string(),
        );
    }
    let mut exact_output_secrets = tool_env
        .secret_sources
        .keys()
        .filter_map(|key| tool_env.env.get(key).cloned())
        .collect::<Vec<_>>();
    let mut trusted_tool_env = tool_env.env;
    let mut credential_reference_names = tool_env.secret_refs;
    credential_reference_names.extend(request.secrets.values().cloned());
    credential_reference_names.extend(request.secret_files.values().cloned());
    credential_reference_names.sort();
    credential_reference_names.dedup();
    let Some(credential_references) = credential_reference_names
        .into_iter()
        .map(CredentialReference::from_store_name)
        .collect::<Option<Vec<_>>>()
    else {
        return ExecuteResult::exec_failed(
            allow_reason,
            "invalid credential reference reached execution after request validation".to_string(),
        );
    };
    let mut request_env = HashMap::new();

    for credential_reference in &credential_references {
        let store_name = credential_reference.as_reference_name();
        let allowed = match &authority {
            Some(None) => true,
            Some(Some(selectors)) => selectors.iter().any(|selector| {
                selector == store_name
                    || selector == "*"
                    || selector
                        .strip_suffix('*')
                        .is_some_and(|prefix| store_name.starts_with(prefix))
            }),
            None => match request.session_token.as_deref() {
                Some(token) => match server.state.sessions.read().await.authority_snapshot(token) {
                    Some((_, None)) => true,
                    Some((_, Some(selectors))) => selectors.iter().any(|selector| {
                        selector == store_name
                            || selector == "*"
                            || selector
                                .strip_suffix('*')
                                .is_some_and(|prefix| store_name.starts_with(prefix))
                    }),
                    None => false,
                },
                None => true,
            },
        };
        if !allowed {
            return ExecuteResult::exec_failed(
                    allow_reason,
                    format!(
                        "saved authority does not entitle secret '{store_name}'; next: guard access request 'Use credential selector {store_name} for this task'"
                    ),
                );
        }
    }

    for key in request
        .env
        .keys()
        .chain(request.secrets.keys())
        .chain(request.secret_files.keys())
    {
        if !is_valid_env_name(key) {
            return ExecuteResult::exec_failed(
                allow_reason,
                format!("invalid injected environment variable name: '{}'", key),
            );
        }
        if dangerous_env_name(key) {
            return ExecuteResult::exec_failed(
                allow_reason,
                format!("dangerous injected environment variable name: '{}'", key),
            );
        }
        if caller_environment_is_executable_authority(key) {
            return ExecuteResult::exec_failed(
                allow_reason,
                "caller environment may not set PATH because executable search authority belongs to Guard"
                    .to_string(),
            );
        }
        if caller_environment_redirects_tool_authority(&request.binary, key) {
            return ExecuteResult::exec_failed(
                allow_reason,
                format!(
                    "caller environment may not set '{}' for {} because it redirects implicit configuration authority",
                    key, request.binary
                ),
            );
        }
    }

    for (source, bindings) in [
        (
            guard::gating::verb::EnvironmentBindingSource::Plain,
            &request.env,
        ),
        (
            guard::gating::verb::EnvironmentBindingSource::Secret,
            &request.secrets,
        ),
        (
            guard::gating::verb::EnvironmentBindingSource::SecretFile,
            &request.secret_files,
        ),
    ] {
        for (name, value) in bindings {
            if let Err(error) = guard::gating::verb::validate_runtime_tool_environment_binding(
                &request.binary,
                source,
                name,
                value,
                command_authority
                    .as_ref()
                    .and_then(|authority| authority.verb.as_ref())
                    .is_some_and(|authority| authority.environment_authority),
            ) {
                return ExecuteResult::exec_failed(allow_reason, error.to_string());
            }
        }
    }

    let mut injection_names = std::collections::HashSet::new();
    for key in request
        .env
        .keys()
        .chain(request.secrets.keys())
        .chain(request.secret_files.keys())
    {
        if !injection_names.insert(child_environment_name_key(key)) {
            return ExecuteResult::exec_failed(
                allow_reason,
                format!(
                    "injected environment variable '{}' has multiple bindings",
                    key
                ),
            );
        }
    }

    if !server.config.exec_as_caller
        && (!request.env.is_empty()
            || !request.secrets.is_empty()
            || !request.secret_files.is_empty())
    {
        return ExecuteResult::exec_failed(
            allow_reason,
            "fixed-identity execution cannot receive per-run environment or credentials because the shared child UID is not an execution-isolation boundary"
                .to_string(),
        );
    }

    if server.config.exec_as_caller && !request.secret_files.is_empty() {
        return ExecuteResult::exec_failed(
            allow_reason,
            "--secret-file is unavailable with --exec-as-caller because a daemon-created credential file must not become caller-owned"
                .to_string(),
        );
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
        request_env.insert(key.clone(), value.clone());
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
            let value = if let Some(environment) = approved_environment {
                match environment.request_secret(env_var) {
                    Some(Some(value)) => value.to_string(),
                    Some(None) => {
                        return ExecuteResult::exec_failed(
                            allow_reason,
                            format!(
                                "secret not found: '{}' (required by --secret {})",
                                secret_key, env_var
                            ),
                        )
                    }
                    None => {
                        return ExecuteResult::exec_failed(
                            allow_reason,
                            "approved secret snapshot is incomplete".to_string(),
                        )
                    }
                }
            } else {
                match server.state.secrets.get(&principal, secret_key).await {
                    Ok(Some(value)) => value,
                    Ok(None) => {
                        return ExecuteResult::exec_failed(
                            allow_reason,
                            format!(
                                "secret not found: '{}' (required by --secret {})",
                                secret_key, env_var
                            ),
                        )
                    }
                    Err(error) => {
                        return ExecuteResult::exec_failed(
                            allow_reason,
                            format!("failed to read secret '{}': {}", secret_key, error),
                        )
                    }
                }
            };
            exact_output_secrets.push(value.clone());
            request_env.insert(env_var.clone(), value);
        }
    }

    // Resolve file-backed secrets immediately before execution, but do not put
    // their values in the child environment. Materialization happens only
    // after all request and collision validation has succeeded.
    let mut secret_file_values = Vec::new();
    if !request.secret_files.is_empty() {
        let principal = match caller.principal() {
            Some(principal) if caller.is_local_peer() => principal,
            _ => {
                return ExecuteResult::exec_failed(
                    allow_reason,
                    "secret-file injection requires an authenticated local caller".to_string(),
                );
            }
        };
        let mut mappings: Vec<_> = request.secret_files.iter().collect();
        mappings.sort_by(|a, b| a.0.cmp(b.0));
        for (env_var, secret_key) in mappings {
            let value = if let Some(environment) = approved_environment {
                match environment.request_secret_file(env_var) {
                    Some(Some(value)) => value.to_string(),
                    Some(None) => {
                        return ExecuteResult::exec_failed(
                            allow_reason,
                            format!(
                                "secret not found: '{}' (required by --secret-file {})",
                                secret_key, env_var
                            ),
                        )
                    }
                    None => {
                        return ExecuteResult::exec_failed(
                            allow_reason,
                            "approved secret-file snapshot is incomplete".to_string(),
                        )
                    }
                }
            } else {
                match server.state.secrets.get(&principal, secret_key).await {
                    Ok(Some(value)) => value,
                    Ok(None) => {
                        return ExecuteResult::exec_failed(
                            allow_reason,
                            format!(
                                "secret not found: '{}' (required by --secret-file {})",
                                secret_key, env_var
                            ),
                        )
                    }
                    Err(error) => {
                        return ExecuteResult::exec_failed(
                            allow_reason,
                            format!("failed to read secret '{}': {}", secret_key, error),
                        )
                    }
                }
            };
            exact_output_secrets.push(value.clone());
            secret_file_values.push((env_var.clone(), value));
        }
    }
    let daemon_child_env: HashMap<String, String> = server
        .config
        .extra_child_env
        .iter()
        .filter_map(|var| std::env::var(var).ok().map(|value| (var.clone(), value)))
        .collect();
    if !server.config.exec_as_caller
        && fixed_child_environment_contains_sensitive_binding(server, &daemon_child_env).await
    {
        return ExecuteResult::exec_failed(
            allow_reason,
            "fixed-identity execution cannot receive credential-authority daemon environment because the shared child UID is not an execution-isolation boundary"
                .to_string(),
        );
    }
    for key in request_env.keys().chain(request.secret_files.keys()) {
        if child_environment_contains(&trusted_tool_env, key) {
            return ExecuteResult::exec_failed(
                allow_reason,
                format!(
                    "injected environment variable '{}' conflicts with Guard tool configuration",
                    key
                ),
            );
        }
        if child_environment_contains(&daemon_child_env, key) {
            return ExecuteResult::exec_failed(
                allow_reason,
                format!(
                    "injected environment variable '{}' conflicts with Guard daemon child environment",
                    key
                ),
            );
        }
    }
    if let Err(reason) = apply_authorized_tool_environment_defaults(
        &request,
        command_authority.as_ref(),
        &daemon_child_env,
        &mut trusted_tool_env,
    ) {
        return ExecuteResult::exec_failed(allow_reason, reason);
    }

    tracing::info!(
        "Executing: {} ({}) cwd={}",
        redact_command_line(&request.binary, &request.args),
        caller,
        request
            .cwd
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "(unavailable)".to_string())
    );

    let exec_binary = match resolve_primary_binary(server, &request.binary) {
        Ok(binary) => binary,
        Err(e) => return ExecuteResult::exec_failed(allow_reason, e.to_string()),
    };
    let mut cmd = Command::new(&exec_binary);
    cmd.args(&request.args);
    cmd.stdin(Stdio::null());
    if let Some(cwd) = &request.cwd {
        if let Err(reason) = revalidate_exec_cwd(cwd).await {
            return ExecuteResult::exec_failed(allow_reason, reason);
        }
        cmd.current_dir(cwd);
    }

    let exec_caller = match apply_exec_identity(&mut cmd, server, caller) {
        Ok(context) => context,
        Err(e) => {
            return ExecuteResult::exec_failed(allow_reason, format!("exec identity error: {}", e));
        }
    };
    #[cfg(unix)]
    let secret_file_child_identity = {
        #[cfg(test)]
        if server.config.preserve_test_process_identity {
            Some((unsafe { libc::geteuid() as u32 }, unsafe {
                libc::getegid() as u32
            }))
        } else {
            exec_caller
                .as_ref()
                .map(|context| (context.uid, context.gid))
        }
        #[cfg(not(test))]
        exec_caller
            .as_ref()
            .map(|context| (context.uid, context.gid))
    };
    #[cfg(not(unix))]
    let secret_file_child_identity = None;

    let secret_file_lease = if secret_file_values.is_empty() {
        None
    } else {
        let Some(root) = server.config.secret_file_root.as_ref() else {
            return ExecuteResult::exec_failed(
                allow_reason,
                "secret-file storage is not initialized".to_string(),
            );
        };
        match super::secure_fs::SecretFileLease::create(
            root,
            &secret_file_values,
            secret_file_child_identity,
        ) {
            Ok((lease, bindings)) => {
                for (env_var, path) in bindings {
                    request_env.insert(env_var, path.to_string_lossy().into_owned());
                }
                Some(lease)
            }
            Err(e) => {
                return ExecuteResult::exec_failed(
                    allow_reason,
                    format!("failed to materialize secret files: {}", e),
                );
            }
        }
    };

    let untrusted_unix_user_id = untrusted_unix_child_user_id(server, exec_caller.as_ref());

    // SECURITY: Clear ALL inherited env vars. The child process gets only the
    // fully merged environment below. This single snapshot feeds both spawn and
    // process-start artifact selection, so an authority-bearing tool variable
    // cannot be omitted from the lease by arriving through a daemon binding.
    let mut effective_child_env = effective_child_environment(
        server,
        &daemon_child_env,
        &trusted_tool_env,
        &request_env,
        exec_caller.as_ref(),
        context.depth,
    );
    if let Some(plan) = &delayed_authority {
        if let Err(reason) = canonicalize_authorized_executable_search_path(
            plan.secondary_path_search,
            &mut effective_child_env,
        ) {
            return ExecuteResult::exec_failed(allow_reason, reason);
        }
    }
    exact_output_secrets.extend(environment_output_secrets(&effective_child_env));
    exact_output_secrets.sort();
    exact_output_secrets.dedup();
    if !server.config.exec_as_caller {
        if fixed_child_environment_contains_sensitive_binding(server, &effective_child_env).await {
            return ExecuteResult::exec_failed(
                allow_reason,
                "fixed-identity execution environment is outside Guard's explicit inert-variable schema"
                    .to_string(),
            );
        }
        if let Err(reason) =
            validate_fixed_identity_profile_authority(server, &request, &effective_child_env).await
        {
            return ExecuteResult::exec_failed(allow_reason, reason);
        }
    }
    cmd.env_clear();
    for (key, value) in &effective_child_env {
        cmd.env(key, value);
    }

    // Drop every daemon capability from the brokered child so none survives
    // execve into a caller-requested command. This covers both fixed-child and
    // --exec-as-caller identity selection.
    #[cfg(unix)]
    drop_brokered_child_capabilities(&mut cmd);

    #[cfg(unix)]
    cmd.as_std_mut().process_group(0);

    // Learned deny, composed verb authority, and live session state are held
    // only through the finite process-start handoff. A revocation that commits
    // first prevents spawn; a revocation after spawn applies to later uses.
    let initiation_lease = match acquire_command_initiation_lease(
        server,
        &request,
        command_authority.as_ref(),
        delayed_authority.as_ref(),
        &exec_binary,
        &effective_child_env,
        untrusted_unix_user_id,
    )
    .await
    {
        Ok(lease) => lease,
        Err(reason) => return ExecuteResult::denied(reason),
    };
    let tool_mapping_lease = match acquire_tool_mapping_spawn_lease(server, &tool_authority).await {
        Ok(lease) => lease,
        Err(error) => {
            return ExecuteResult::denied(format!(
                "tool mapping authority is unavailable before process start: {error}"
            ))
        }
    };
    if !server.config.exec_as_caller {
        if let Err(reason) =
            validate_fixed_identity_profile_authority(server, &request, &effective_child_env).await
        {
            return ExecuteResult::denied(format!(
                "fixed-identity profile authority changed before process start: {reason}"
            ));
        }
    }
    if let Some(authorization) = command_authority
        .as_ref()
        .filter(|authorization| authorization_revalidates_process_authority(authorization))
    {
        let Some(expected) = authorization.process_authority.as_ref() else {
            return ExecuteResult::denied(
                "approved command lacks bound process authority; submit it for a new approval",
            );
        };
        let Some(approved_environment) = approved_environment else {
            return ExecuteResult::denied(
                "approved command lacks a resolved environment snapshot; submit it for a new approval",
            );
        };
        let current = match process_authority_binding_from_effective_environment(
            ProcessAuthorityBindingInputs {
                authority_mac_key: server.config.authority_mac_key.as_ref(),
                request: &request,
                authorization,
                primary_binary: &exec_binary,
                daemon_path: daemon_executable_search_path(server),
                effective_child_env: &effective_child_env,
                approved_environment,
                tool_registry_fingerprint: tool_authority.authority_fingerprint(),
                untrusted_unix_user_id,
                execution_identity: match process_execution_identity_binding(
                    server,
                    exec_caller.as_ref(),
                ) {
                    Ok(identity) => identity,
                    Err(error) => {
                        return ExecuteResult::denied(format!(
                            "approved execution identity cannot be revalidated before process start: {error}"
                        ))
                    }
                },
            },
        ) {
            Ok(binding) => binding,
            Err(error) => {
                return ExecuteResult::denied(format!(
                    "approved process authority cannot be revalidated before process start: {error}"
                ))
            }
        };
        if current != *expected {
            return ExecuteResult::denied(
                "approved process authority changed before process start; submit the command for a new approval",
            );
        }
    }
    let exec_timeout_secs = command_authority
        .as_ref()
        .and_then(|authority| authority.exec_timeout_secs)
        .unwrap_or(server.config.exec_timeout_secs);

    if context.stream_output {
        let result = execute_spawn_streaming(
            cmd,
            allow_reason,
            exec_timeout_secs,
            server,
            OutputRedactionContext {
                exact_secrets: &exact_output_secrets,
            },
            SpawnAuditContext {
                caller,
                request: &request,
                credential_references,
            },
            &mut *context.stream_writer,
            ProcessInitiationLeases {
                command: initiation_lease,
                tool_mapping: tool_mapping_lease,
            },
        )
        .await;
        drop(secret_file_lease);
        return result;
    }

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            return ExecuteResult::exec_failed(
                allow_reason,
                format!("failed to execute '{}': {}", request.binary, e),
            );
        }
    };
    drop(tool_mapping_lease);
    // Mutable policy locks cover only the spawn boundary. Filesystem and PATH
    // authority handles remain live until the child exits so secondary process
    // discovery cannot race a directory replacement on platforms that permit it.
    let _execution_authority_leases = initiation_lease.release_policy_authority();
    #[cfg(all(test, unix))]
    signal_command_started_for_test(server);
    let mut process_guard = child
        .id()
        .map(|pid| server.state.process_tracker.track(pid));
    audit_credential_access(server, caller, &request, &credential_references);
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let exact_secrets = server
        .config
        .redact_secrets
        .iter()
        .chain(exact_output_secrets.iter())
        .map(|secret| secret.as_bytes().to_vec())
        .collect::<Vec<_>>();
    let raw_total = Arc::new(AtomicUsize::new(0));
    let stdout_secrets = exact_secrets.clone();
    let stdout_total = raw_total.clone();
    let stdout_reader = async move {
        match stdout_pipe {
            Some(pipe) => read_bounded_redacted_output(pipe, stdout_secrets, stdout_total).await,
            None => Ok(Vec::new()),
        }
    };
    let stderr_reader = async move {
        match stderr_pipe {
            Some(pipe) => read_bounded_redacted_output(pipe, exact_secrets, raw_total).await,
            None => Ok(Vec::new()),
        }
    };
    let execution_deadline =
        tokio::time::sleep(std::time::Duration::from_secs(exec_timeout_secs.max(1)));
    tokio::pin!(execution_deadline);
    let buffered_output = if exec_timeout_secs == 0 {
        Ok(collect_bounded_output_pair(stdout_reader, stderr_reader).await)
    } else {
        tokio::select! {
            result = collect_bounded_output_pair(stdout_reader, stderr_reader) => Ok(result),
            _ = &mut execution_deadline => Err(()),
        }
    };
    let buffered_output = match buffered_output {
        Err(()) => {
            terminate_spawned_child(&mut child, &mut process_guard).await;
            return ExecuteResult::exec_failed_after_start(
                allow_reason,
                exec_timeout_reason(exec_timeout_secs),
            )
            .with_credential_references(credential_references);
        }
        Ok(Err(error)) => {
            terminate_spawned_child(&mut child, &mut process_guard).await;
            return ExecuteResult::exec_failed_after_start(allow_reason, error.to_string())
                .with_credential_references(credential_references);
        }
        Ok(Ok(output)) => output,
    };
    let wait_result = if exec_timeout_secs == 0 {
        Ok(child.wait().await)
    } else {
        tokio::select! {
            result = child.wait() => Ok(result),
            _ = &mut execution_deadline => Err(()),
        }
    };
    let status = match wait_result {
        Err(()) => {
            terminate_spawned_child(&mut child, &mut process_guard).await;
            return ExecuteResult::exec_failed_after_start(
                allow_reason,
                exec_timeout_reason(exec_timeout_secs),
            )
            .with_credential_references(credential_references);
        }
        Ok(Ok(status)) => status,
        Ok(Err(e)) => {
            return ExecuteResult::exec_failed_after_start(
                allow_reason,
                format!("failed to wait for '{}': {}", request.binary, e),
            )
            .with_credential_references(credential_references);
        }
    };
    if let Some(guard) = process_guard {
        guard.complete();
    }

    let (stdout_bytes, stderr_bytes) = buffered_output;
    let retained_total = Arc::new(AtomicUsize::new(0));
    let stdout = if stdout_bytes.is_empty() {
        None
    } else {
        let redacted = match redact_bounded_buffered_output(
            server,
            &exact_output_secrets,
            String::from_utf8_lossy(&stdout_bytes).to_string(),
            &retained_total,
        ) {
            Ok(redacted) => redacted,
            Err(error) => {
                return ExecuteResult::exec_failed_after_start(allow_reason, error.to_string())
                    .with_credential_references(credential_references);
            }
        };
        Some(redacted)
    };

    let stderr = if stderr_bytes.is_empty() {
        None
    } else {
        let redacted = match redact_bounded_buffered_output(
            server,
            &exact_output_secrets,
            String::from_utf8_lossy(&stderr_bytes).to_string(),
            &retained_total,
        ) {
            Ok(redacted) => redacted,
            Err(error) => {
                return ExecuteResult::exec_failed_after_start(allow_reason, error.to_string())
                    .with_credential_references(credential_references);
            }
        };
        Some(redacted)
    };

    drop(secret_file_lease);
    ExecuteResult::completed(allow_reason, status.code(), stdout, stderr)
        .with_credential_references(credential_references)
}

fn truncate_utf8_bytes(value: &mut String, limit: usize) {
    if value.len() <= limit {
        return;
    }
    let mut end = limit;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
}

#[derive(Debug)]
enum BoundedOutputError {
    OutputLimit,
    RedactionContext,
    PipeIo(String),
}

impl std::fmt::Display for BoundedOutputError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutputLimit => {
                formatter.write_str("command output exceeded the bounded byte limit")
            }
            Self::RedactionContext => {
                formatter.write_str("command redaction context exceeded its resource limit")
            }
            Self::PipeIo(detail) => write!(formatter, "command output pipe failed: {detail}"),
        }
    }
}

fn bounded_error_detail(error: impl std::fmt::Display) -> String {
    let mut detail = error.to_string();
    detail.retain(|character| !character.is_control());
    truncate_utf8_bytes(&mut detail, 160);
    detail
}

fn reserve_bounded_output(total: &AtomicUsize, amount: usize) -> Result<(), BoundedOutputError> {
    let reserved = total.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        current
            .checked_add(amount)
            .filter(|next| *next <= MAX_OUTPUT_BYTES)
    });
    reserved
        .map(|_| ())
        .map_err(|_| BoundedOutputError::OutputLimit)
}

fn redact_bounded_buffered_output(
    server: &ServerContext,
    exact_output_secrets: &[String],
    text: String,
    retained_total: &AtomicUsize,
) -> Result<String, BoundedOutputError> {
    let redacted = redact_command_text(server, exact_output_secrets, text);
    reserve_bounded_output(retained_total, redacted.len())?;
    Ok(redacted)
}

async fn read_bounded_redacted_output<R>(
    mut reader: R,
    exact_secrets: Vec<Vec<u8>>,
    raw_total: Arc<AtomicUsize>,
) -> Result<Vec<u8>, BoundedOutputError>
where
    R: AsyncRead + Unpin,
{
    const CHUNK_BYTES: usize = 8 * 1024;
    let mut redactor = ExactSecretStreamRedactor::new(exact_secrets, MAX_OUTPUT_BYTES)
        .map_err(|_| BoundedOutputError::RedactionContext)?;
    let mut output = Vec::new();
    let mut buffer = vec![0_u8; CHUNK_BYTES];
    loop {
        let read = reader
            .read(&mut buffer)
            .await
            .map_err(|error| BoundedOutputError::PipeIo(bounded_error_detail(error)))?;
        if read == 0 {
            output.extend(
                redactor
                    .finish()
                    .map_err(|_| BoundedOutputError::OutputLimit)?,
            );
            return Ok(output);
        }
        reserve_bounded_output(&raw_total, read)?;
        output.extend(
            redactor
                .push(&buffer[..read])
                .map_err(|_| BoundedOutputError::OutputLimit)?,
        );
    }
}

async fn collect_bounded_output_pair(
    stdout_reader: impl std::future::Future<Output = Result<Vec<u8>, BoundedOutputError>>,
    stderr_reader: impl std::future::Future<Output = Result<Vec<u8>, BoundedOutputError>>,
) -> Result<(Vec<u8>, Vec<u8>), BoundedOutputError> {
    tokio::pin!(stdout_reader);
    tokio::pin!(stderr_reader);
    tokio::select! {
        stdout = &mut stdout_reader => match stdout {
            Ok(stdout) => match stderr_reader.await {
                Ok(stderr) => Ok((stdout, stderr)),
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        },
        stderr = &mut stderr_reader => match stderr {
            Ok(stderr) => match stdout_reader.await {
                Ok(stdout) => Ok((stdout, stderr)),
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        }
    }
}

#[derive(Debug)]
enum StreamChunk {
    Data {
        stream: OutputStream,
        data: Vec<u8>,
    },
    LimitExceeded,
    PipeError {
        stream: OutputStream,
        detail: String,
    },
}

struct StreamReaderTask {
    stream: OutputStream,
    handle: tokio::task::JoinHandle<()>,
}

#[derive(Debug)]
struct StreamTaskJoinError {
    stream: OutputStream,
    detail: &'static str,
}

struct StreamTaskCleanup {
    tasks: Vec<StreamReaderTask>,
}

impl StreamTaskCleanup {
    async fn join(&mut self) -> Result<(), StreamTaskJoinError> {
        while let Some(task) = self.tasks.pop() {
            if let Err(error) = task.handle.await {
                let detail = if error.is_panic() {
                    "reader task panicked"
                } else if error.is_cancelled() {
                    "reader task was cancelled"
                } else {
                    "reader task failed"
                };
                return Err(StreamTaskJoinError {
                    stream: task.stream,
                    detail,
                });
            }
        }
        Ok(())
    }

    async fn abort_and_join(&mut self) {
        for task in &self.tasks {
            task.handle.abort();
        }
        while let Some(task) = self.tasks.pop() {
            let _ = task.handle.await;
        }
    }
}

impl Drop for StreamTaskCleanup {
    fn drop(&mut self) {
        for task in self.tasks.drain(..) {
            task.handle.abort();
        }
    }
}

async fn cleanup_streaming_failure(
    child: &mut tokio::process::Child,
    process_guard: &mut Option<ProcessGuard>,
    stream_tasks: &mut StreamTaskCleanup,
) {
    stream_tasks.abort_and_join().await;
    terminate_spawned_child(child, process_guard).await;
}

async fn terminate_spawned_child(
    child: &mut tokio::process::Child,
    process_guard: &mut Option<ProcessGuard>,
) {
    if let Some(guard) = process_guard.take() {
        guard.terminate_gracefully().await;
    } else {
        let _ = child.kill().await;
    }
    let _ = child.wait().await;
}

fn exec_timeout_reason(timeout_secs: u64) -> String {
    format!("exec_timeout: command exceeded the wall-clock limit of {timeout_secs} seconds")
}

fn output_stream_name(stream: OutputStream) -> &'static str {
    match stream {
        OutputStream::Stdout => "stdout",
        OutputStream::Stderr => "stderr",
    }
}

fn reserve_emitted_output(total: &mut usize, amount: usize) -> bool {
    let Some(next) = total.checked_add(amount) else {
        return false;
    };
    if next > MAX_OUTPUT_BYTES {
        return false;
    }
    *total = next;
    true
}

#[derive(Default)]
struct StreamingHeuristicRedactor {
    pending_line: Vec<u8>,
    state: RedactionState,
}

impl StreamingHeuristicRedactor {
    fn push<F>(&mut self, data: &[u8], mut redact_line: F) -> Result<String, BoundedOutputError>
    where
        F: FnMut(String, &mut RedactionState) -> String,
    {
        let mut output = String::new();
        let mut remaining = data;
        while let Some(newline) = remaining.iter().position(|byte| *byte == b'\n') {
            let line_end = newline + 1;
            self.append_pending(&remaining[..line_end])?;
            remaining = &remaining[line_end..];

            let line =
                String::from_utf8_lossy(&std::mem::take(&mut self.pending_line)).into_owned();
            let redacted = redact_line(line, &mut self.state);
            Self::append_output(&mut output, &redacted)?;
        }
        self.append_pending(remaining)?;
        Ok(output)
    }

    fn finish<F>(&mut self, mut redact_line: F) -> Result<String, BoundedOutputError>
    where
        F: FnMut(String, &mut RedactionState) -> String,
    {
        if self.pending_line.is_empty() {
            return Ok(String::new());
        }
        let line = String::from_utf8_lossy(&std::mem::take(&mut self.pending_line)).into_owned();
        let redacted = redact_line(line, &mut self.state);
        if redacted.len() > MAX_OUTPUT_BYTES {
            return Err(BoundedOutputError::OutputLimit);
        }
        Ok(redacted)
    }

    fn append_pending(&mut self, data: &[u8]) -> Result<(), BoundedOutputError> {
        let Some(next) = self.pending_line.len().checked_add(data.len()) else {
            return Err(BoundedOutputError::OutputLimit);
        };
        if next > MAX_OUTPUT_BYTES {
            return Err(BoundedOutputError::OutputLimit);
        }
        self.pending_line.extend_from_slice(data);
        Ok(())
    }

    fn append_output(output: &mut String, data: &str) -> Result<(), BoundedOutputError> {
        let Some(next) = output.len().checked_add(data.len()) else {
            return Err(BoundedOutputError::OutputLimit);
        };
        if next > MAX_OUTPUT_BYTES {
            return Err(BoundedOutputError::OutputLimit);
        }
        output.push_str(data);
        Ok(())
    }
}

struct OutputRedactionContext<'a> {
    exact_secrets: &'a [String],
}

#[allow(clippy::too_many_arguments)]
async fn execute_spawn_streaming<W: AsyncWrite + Unpin>(
    mut cmd: Command,
    allow_reason: String,
    exec_timeout_secs: u64,
    server: &ServerContext,
    redaction: OutputRedactionContext<'_>,
    audit: SpawnAuditContext<'_>,
    writer: &mut W,
    leases: ProcessInitiationLeases,
) -> ExecuteResult {
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            return ExecuteResult::exec_failed(
                allow_reason,
                format!("failed to execute '{}': {}", audit.request.binary, e),
            );
        }
    };
    drop(leases.tool_mapping);
    let _execution_authority_leases = leases.command.release_policy_authority();
    #[cfg(all(test, unix))]
    signal_command_started_for_test(server);
    let mut process_guard = child
        .id()
        .map(|pid| server.state.process_tracker.track(pid));
    audit_credential_access(
        server,
        audit.caller,
        audit.request,
        &audit.credential_references,
    );

    let (tx, mut rx) = mpsc::channel::<StreamChunk>(32);
    let mut stream_tasks = StreamTaskCleanup { tasks: Vec::new() };
    let raw_total = Arc::new(AtomicUsize::new(0));

    if let Some(stdout) = child.stdout.take() {
        let tx = tx.clone();
        let raw_total = raw_total.clone();
        stream_tasks.tasks.push(StreamReaderTask {
            stream: OutputStream::Stdout,
            handle: tokio::spawn(async move {
                forward_stream_chunks(stdout, OutputStream::Stdout, tx, raw_total).await;
            }),
        });
    }

    if let Some(stderr) = child.stderr.take() {
        let tx = tx.clone();
        let raw_total = raw_total.clone();
        stream_tasks.tasks.push(StreamReaderTask {
            stream: OutputStream::Stderr,
            handle: tokio::spawn(async move {
                forward_stream_chunks(stderr, OutputStream::Stderr, tx, raw_total).await;
            }),
        });
    }

    drop(tx);

    let mut stdout_redaction = StreamingHeuristicRedactor::default();
    let mut stderr_redaction = StreamingHeuristicRedactor::default();
    let exact_secrets = server
        .config
        .redact_secrets
        .iter()
        .chain(redaction.exact_secrets)
        .map(|secret| secret.as_bytes().to_vec())
        .collect::<Vec<_>>();
    let mut stdout_exact =
        match ExactSecretStreamRedactor::new(exact_secrets.clone(), MAX_OUTPUT_BYTES) {
            Ok(redactor) => redactor,
            Err(_) => {
                cleanup_streaming_failure(&mut child, &mut process_guard, &mut stream_tasks).await;
                return ExecuteResult::exec_failed_after_start(
                    allow_reason,
                    "command redaction context exceeded its resource limit".to_string(),
                )
                .with_credential_references(audit.credential_references);
            }
        };
    let mut stderr_exact = ExactSecretStreamRedactor::new(exact_secrets, MAX_OUTPUT_BYTES)
        .expect("the same bounded redaction context was already validated");
    let mut emitted_total = 0usize;
    let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(1));
    let execution_deadline =
        tokio::time::sleep(std::time::Duration::from_secs(exec_timeout_secs.max(1)));
    tokio::pin!(execution_deadline);
    loop {
        tokio::select! {
            _ = &mut execution_deadline, if exec_timeout_secs != 0 => {
                cleanup_streaming_failure(&mut child, &mut process_guard, &mut stream_tasks).await;
                return ExecuteResult::exec_failed_after_start(
                    allow_reason,
                    exec_timeout_reason(exec_timeout_secs),
                )
                .with_credential_references(audit.credential_references);
            }
            maybe_chunk = rx.recv() => {
                match maybe_chunk {
                    Some(StreamChunk::Data { stream, data }) => {
                    let (heuristic_redactor, exact_redactor) = match stream {
                        OutputStream::Stdout => (&mut stdout_redaction, &mut stdout_exact),
                        OutputStream::Stderr => (&mut stderr_redaction, &mut stderr_exact),
                    };
                    let Ok(data) = exact_redactor.push(&data) else {
                        cleanup_streaming_failure(&mut child, &mut process_guard, &mut stream_tasks).await;
                        return ExecuteResult::exec_failed_after_start(
                            allow_reason,
                            "command output exceeded the redacted byte limit".to_string(),
                        )
                        .with_credential_references(audit.credential_references);
                    };
                    let data = match heuristic_redactor.push(&data, |line, state| {
                        redact_command_text_with_state(
                            server,
                            redaction.exact_secrets,
                            line,
                            state,
                        )
                    }) {
                        Ok(data) => data,
                        Err(_) => {
                            cleanup_streaming_failure(&mut child, &mut process_guard, &mut stream_tasks).await;
                            return ExecuteResult::exec_failed_after_start(
                                allow_reason,
                                "command output exceeded the redacted byte limit".to_string(),
                            )
                            .with_credential_references(audit.credential_references);
                        }
                    };
                    if data.is_empty() {
                        continue;
                    }
                    if !reserve_emitted_output(&mut emitted_total, data.len()) {
                        cleanup_streaming_failure(&mut child, &mut process_guard, &mut stream_tasks).await;
                        return ExecuteResult::exec_failed_after_start(
                            allow_reason,
                            "command output exceeded the redacted byte limit".to_string(),
                        )
                        .with_credential_references(audit.credential_references);
                    }
                    let message = match stream {
                        OutputStream::Stdout => ExecuteStreamMessage::Stdout { data },
                        OutputStream::Stderr => ExecuteStreamMessage::Stderr { data },
                    };

                    if let Err(e) = write_stream_message(writer, &message).await {
                        cleanup_streaming_failure(&mut child, &mut process_guard, &mut stream_tasks).await;
                        return ExecuteResult::exec_failed_after_start(
                            allow_reason,
                            format!("client stream error: {}", e),
                        )
                        .with_credential_references(audit.credential_references);
                    }
                    }
                    Some(StreamChunk::LimitExceeded) => {
                        cleanup_streaming_failure(&mut child, &mut process_guard, &mut stream_tasks).await;
                        return ExecuteResult::exec_failed_after_start(
                            allow_reason,
                            "command output exceeded the byte limit".to_string(),
                        )
                        .with_credential_references(audit.credential_references);
                    }
                    Some(StreamChunk::PipeError { stream, detail }) => {
                        cleanup_streaming_failure(&mut child, &mut process_guard, &mut stream_tasks).await;
                        return ExecuteResult::exec_failed_after_start(
                            allow_reason,
                            format!(
                                "command {} output pipe failed: {}",
                                output_stream_name(stream),
                                detail
                            ),
                        )
                        .with_credential_references(audit.credential_references);
                    }
                    None => {
                        for (stream, exact_redactor, heuristic_redactor) in [
                            (
                                OutputStream::Stdout,
                                &mut stdout_exact,
                                &mut stdout_redaction,
                            ),
                            (
                                OutputStream::Stderr,
                                &mut stderr_exact,
                                &mut stderr_redaction,
                            ),
                        ] {
                            let Ok(data) = exact_redactor.finish() else {
                                cleanup_streaming_failure(&mut child, &mut process_guard, &mut stream_tasks).await;
                                return ExecuteResult::exec_failed_after_start(
                                    allow_reason,
                                    "command output exceeded the redacted byte limit".to_string(),
                                )
                                .with_credential_references(audit.credential_references);
                            };
                            let mut data = match heuristic_redactor.push(&data, |line, state| {
                                redact_command_text_with_state(
                                    server,
                                    redaction.exact_secrets,
                                    line,
                                    state,
                                )
                            }) {
                                Ok(data) => data,
                                Err(_) => {
                                    cleanup_streaming_failure(&mut child, &mut process_guard, &mut stream_tasks).await;
                                    return ExecuteResult::exec_failed_after_start(
                                        allow_reason,
                                        "command output exceeded the redacted byte limit".to_string(),
                                    )
                                    .with_credential_references(audit.credential_references);
                                }
                            };
                            let tail = match heuristic_redactor.finish(|line, state| {
                                redact_command_text_with_state(
                                    server,
                                    redaction.exact_secrets,
                                    line,
                                    state,
                                )
                            }) {
                                Ok(tail) => tail,
                                Err(_) => {
                                    cleanup_streaming_failure(&mut child, &mut process_guard, &mut stream_tasks).await;
                                    return ExecuteResult::exec_failed_after_start(
                                        allow_reason,
                                        "command output exceeded the redacted byte limit".to_string(),
                                    )
                                    .with_credential_references(audit.credential_references);
                                }
                            };
                            let Some(total_len) = data.len().checked_add(tail.len()) else {
                                cleanup_streaming_failure(&mut child, &mut process_guard, &mut stream_tasks).await;
                                return ExecuteResult::exec_failed_after_start(
                                    allow_reason,
                                    "command output exceeded the redacted byte limit".to_string(),
                                )
                                .with_credential_references(audit.credential_references);
                            };
                            if total_len > MAX_OUTPUT_BYTES {
                                cleanup_streaming_failure(&mut child, &mut process_guard, &mut stream_tasks).await;
                                return ExecuteResult::exec_failed_after_start(
                                    allow_reason,
                                    "command output exceeded the redacted byte limit".to_string(),
                                )
                                .with_credential_references(audit.credential_references);
                            }
                            data.push_str(&tail);
                            if data.is_empty() {
                                continue;
                            }
                            if !reserve_emitted_output(&mut emitted_total, data.len()) {
                                cleanup_streaming_failure(&mut child, &mut process_guard, &mut stream_tasks).await;
                                return ExecuteResult::exec_failed_after_start(
                                    allow_reason,
                                    "command output exceeded the redacted byte limit".to_string(),
                                )
                                .with_credential_references(audit.credential_references);
                            }
                            let message = match stream {
                                OutputStream::Stdout => ExecuteStreamMessage::Stdout { data },
                                OutputStream::Stderr => ExecuteStreamMessage::Stderr { data },
                            };
                            if let Err(error) = write_stream_message(writer, &message).await {
                                cleanup_streaming_failure(&mut child, &mut process_guard, &mut stream_tasks).await;
                                return ExecuteResult::exec_failed_after_start(
                                    allow_reason,
                                    format!("client stream error: {error}"),
                                )
                                .with_credential_references(audit.credential_references);
                            }
                        }
                        break;
                    },
                }
            }
            _ = keepalive.tick() => {
                if let Err(e) = write_stream_message(writer, &ExecuteStreamMessage::Keepalive).await {
                    cleanup_streaming_failure(&mut child, &mut process_guard, &mut stream_tasks).await;
                    return ExecuteResult::exec_failed_after_start(
                        allow_reason,
                        format!("client stream error: {}", e),
                    )
                    .with_credential_references(audit.credential_references);
                }
            }
        }
    }

    if let Err(error) = stream_tasks.join().await {
        cleanup_streaming_failure(&mut child, &mut process_guard, &mut stream_tasks).await;
        return ExecuteResult::exec_failed_after_start(
            allow_reason,
            format!(
                "command {} output {}",
                output_stream_name(error.stream),
                error.detail
            ),
        )
        .with_credential_references(audit.credential_references);
    }

    let wait_result = if exec_timeout_secs == 0 {
        Ok(child.wait().await)
    } else {
        tokio::select! {
            result = child.wait() => Ok(result),
            _ = &mut execution_deadline => Err(()),
        }
    };
    let status = match wait_result {
        Err(()) => {
            terminate_spawned_child(&mut child, &mut process_guard).await;
            return ExecuteResult::exec_failed_after_start(
                allow_reason,
                exec_timeout_reason(exec_timeout_secs),
            )
            .with_credential_references(audit.credential_references);
        }
        Ok(Ok(status)) => status,
        Ok(Err(e)) => {
            return ExecuteResult::exec_failed_after_start(
                allow_reason,
                format!("failed to wait for '{}': {}", audit.request.binary, e),
            )
            .with_credential_references(audit.credential_references);
        }
    };
    if let Some(guard) = process_guard {
        guard.complete();
    }

    ExecuteResult::completed(allow_reason, status.code(), None, None)
        .with_credential_references(audit.credential_references)
}

struct SpawnAuditContext<'a> {
    caller: &'a CallerIdentity,
    request: &'a ExecuteRequest,
    credential_references: Vec<CredentialReference>,
}

fn audit_credential_access(
    server: &ServerContext,
    caller: &CallerIdentity,
    request: &ExecuteRequest,
    credential_references: &[CredentialReference],
) {
    for credential_reference in credential_references {
        let serialized_reference = serde_json::to_string(credential_reference.as_reference_name())
            .unwrap_or_else(|_| "\"<invalid-credential-reference>\"".to_string());
        server.emit_audit_ungated(
            guard::audit::AuditEvent::new(guard::audit::AuditKind::SecretExposed)
                .caller(caller)
                .session_fingerprint(audit_session_fingerprint(request.session_token.as_deref()))
                .cmd(server.redact_command_line(&request.binary, &request.args))
                .field("secret", serialized_reference),
        );
    }
}

async fn forward_stream_chunks<R>(
    mut reader: R,
    stream: OutputStream,
    tx: mpsc::Sender<StreamChunk>,
    total: Arc<AtomicUsize>,
) where
    R: AsyncRead + Unpin,
{
    const CHUNK_BYTES: usize = 8 * 1024;
    let mut stream_bytes = 0usize;
    let mut buffer = vec![0_u8; CHUNK_BYTES];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => break,
            Ok(read) => {
                stream_bytes = stream_bytes.saturating_add(read);
                let reserved = total.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current
                        .checked_add(read)
                        .filter(|next| *next <= MAX_OUTPUT_BYTES)
                });
                if stream_bytes > MAX_OUTPUT_BYTES || reserved.is_err() {
                    let _ = tx.send(StreamChunk::LimitExceeded).await;
                    break;
                }
                if tx
                    .send(StreamChunk::Data {
                        stream,
                        data: buffer[..read].to_vec(),
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(e) => {
                let _ = tx
                    .send(StreamChunk::PipeError {
                        stream,
                        detail: bounded_error_detail(e),
                    })
                    .await;
                break;
            }
        }
    }
}

fn redact_command_text(
    server: &ServerContext,
    exact_output_secrets: &[String],
    text: String,
) -> String {
    redact_command_text_inner(server, exact_output_secrets, text, None)
}

fn environment_output_secrets(environment: &HashMap<String, String>) -> Vec<String> {
    environment
        .iter()
        .filter(|(name, value)| {
            !value.is_empty() && guard::redact::named_value_contains_sensitive_literals(name, value)
        })
        .map(|(_, value)| value.clone())
        .collect()
}

fn redact_command_text_with_state(
    server: &ServerContext,
    exact_output_secrets: &[String],
    text: String,
    state: &mut RedactionState,
) -> String {
    redact_command_text_inner(server, exact_output_secrets, text, Some(state))
}

fn redact_command_text_inner(
    server: &ServerContext,
    exact_output_secrets: &[String],
    text: String,
    state: Option<&mut RedactionState>,
) -> String {
    let trusted_secret_refs: Vec<&str> = server
        .config
        .redact_secrets
        .iter()
        .map(|s| s.as_str())
        .chain(exact_output_secrets.iter().map(String::as_str))
        .collect();

    // First: exact-match redaction catches bare secret values in output.
    let text = redact_exact_secrets(&text, &trusted_secret_refs);
    if !server.config.redact {
        return text;
    }
    // Then regex and context-based redaction catches named values, token
    // shapes, PEM blocks, and structured secret fields. Plain environment
    // bindings are intentionally not exact secrets: values such as `1`, a
    // username, or a path must remain observable unless their source is typed
    // as secret-bearing.
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

pub(super) fn merge_envelope_context(
    session_prompt: Option<String>,
    request: &ExecuteRequest,
) -> Option<String> {
    let Some(revert) = request.revert.as_ref() else {
        return session_prompt;
    };
    let check = revert
        .confirm_check
        .as_ref()
        .map(|check| redact_command_line(&check.binary, &check.args))
        .unwrap_or_else(|| "none; deadline always rolls back".to_string());
    let control_path = revert.control_path.as_deref().unwrap_or(
        "daemon-inferred from the forward, check, rollback, credential, and transport commands",
    );
    let window = request
        .confirm_within_secs
        .unwrap_or(DEFAULT_CONFIRM_WITHIN_SECS)
        .clamp(1, MAX_CONFIRM_WITHIN_SECS);
    let envelope = format!(
        "{REVERT_AVAILABLE_CONTEXT}\nForward: {}\nRollback: {}\nConfirmation check: {}\nDeadline: {} seconds\nRequired control path: {}\nTreat the entire forward, check, rollback, and control-path chain as one safety decision. HOLD by denying when the forward action can plausibly sever the SSH, API, socket, credential, daemon, or local authority needed to verify or roll back.",
        redact_command_line(&request.binary, &request.args),
        redact_command_line(&revert.binary, &revert.args),
        check,
        window,
        control_path
    );
    match session_prompt {
        Some(prompt) if !prompt.trim().is_empty() => Some(format!("{envelope}\n\n{prompt}")),
        _ => Some(envelope),
    }
}

#[cfg(test)]
mod process_start_hardening_tests {
    use super::*;

    fn typed_authorization() -> CommandAuthorization {
        CommandAuthorization {
            learned_deny_authority: LearnedDenyProcessStartAuthority::TypedVerb,
            delayed_authority_source: guard::gating::approval::DelayedAuthoritySource::TypedVerb,
            verb: Some(VerbAuthorityExpectation {
                name: "fixture".to_string(),
                catalog_version: Some(1),
                definition_digest: Some("fixture-digest".to_string()),
                composition_digest: Some("fixture-composition".to_string()),
                environment_authority: false,
                local_file_authority: false,
            }),
            session: None,
            exec_timeout_secs: Some(30),
            process_authority: None,
            approved_environment: None,
        }
    }

    fn fixture_request(cwd: Option<PathBuf>) -> ExecuteRequest {
        ExecuteRequest {
            binary: "true".to_string(),
            args: Vec::new(),
            auth_token: None,
            env: HashMap::new(),
            secrets: HashMap::new(),
            secret_files: HashMap::new(),
            stream: false,
            session_token: None,
            revert: None,
            confirm_within_secs: None,
            reevaluate: false,
            ssh_hostkey: None,
            cwd,
            require_approval: None,
            wait_approval_secs: None,
            verb: None,
        }
    }

    #[test]
    fn output_redaction_preserves_plain_low_entropy_values() {
        let server = crate::server::tests::config_for_proposal_test();
        let output = redact_command_text(
            &server,
            &["typed-secret-value".to_string()],
            "depth=1 user=worker typed-secret-value".to_string(),
        );

        assert!(output.contains("depth=1 user=worker"), "{output}");
        assert!(!output.contains("typed-secret-value"), "{output}");
        assert!(output.contains("[REDACTED]"), "{output}");
    }

    #[test]
    fn output_redaction_types_environment_values_by_name() {
        let environment = HashMap::from([
            ("GUARD_DEPTH".to_string(), "1".to_string()),
            ("USER".to_string(), "worker".to_string()),
            ("REQUEST_SECRET".to_string(), "q7".to_string()),
        ]);

        assert_eq!(environment_output_secrets(&environment), vec!["q7"]);
    }

    fn approved_environment_fixture(
        request_secrets: BTreeMap<String, Option<String>>,
        request_secret_files: BTreeMap<String, Option<String>>,
    ) -> ApprovedEnvironmentSnapshot {
        ApprovedEnvironmentSnapshot::new(
            ResolvedCurrentToolEnv {
                resolved: ResolvedToolEnv::default(),
                authority: crate::tool_config::ToolRegistry::isolated_for_tests(),
            },
            request_secrets.keys().cloned().collect(),
            request_secret_files.keys().cloned().collect(),
            request_secrets,
            request_secret_files,
        )
        .unwrap()
    }

    #[test]
    fn process_environment_binding_covers_plain_values_but_redacts_secret_values() {
        let mut request = fixture_request(None);
        request
            .secrets
            .insert("SERVICE_TOKEN".to_string(), "service/token".to_string());
        request.secret_files.insert(
            "SERVICE_TOKEN_FILE".to_string(),
            "service/token-file".to_string(),
        );
        let first_snapshot = approved_environment_fixture(
            BTreeMap::from([("SERVICE_TOKEN".to_string(), Some("first".to_string()))]),
            BTreeMap::from([(
                "SERVICE_TOKEN_FILE".to_string(),
                Some("first-file".to_string()),
            )]),
        );
        let second_snapshot = approved_environment_fixture(
            BTreeMap::from([("SERVICE_TOKEN".to_string(), Some("second".to_string()))]),
            BTreeMap::from([(
                "SERVICE_TOKEN_FILE".to_string(),
                Some("second-file".to_string()),
            )]),
        );
        let first_environment = HashMap::from([
            ("PLAIN_SETTING".to_string(), "one".to_string()),
            ("SERVICE_TOKEN".to_string(), "first".to_string()),
            (
                "SERVICE_TOKEN_FILE".to_string(),
                "/run/guard/secret-files/first".to_string(),
            ),
        ]);
        let mut second_environment = first_environment.clone();
        second_environment.insert("SERVICE_TOKEN".to_string(), "second".to_string());
        second_environment.insert(
            "SERVICE_TOKEN_FILE".to_string(),
            "/run/guard/secret-files/second".to_string(),
        );

        let first = process_environment_fingerprint(
            &[7u8; 32],
            &request,
            &first_snapshot,
            &first_environment,
        );
        assert_eq!(
            first,
            process_environment_fingerprint(
                &[7u8; 32],
                &request,
                &second_snapshot,
                &second_environment,
            ),
            "secret values and ephemeral file paths are bound by stable references elsewhere"
        );

        second_environment.insert("PLAIN_SETTING".to_string(), "two".to_string());
        assert_ne!(
            first,
            process_environment_fingerprint(
                &[7u8; 32],
                &request,
                &second_snapshot,
                &second_environment,
            ),
            "plain effective child environment remains approval authority"
        );
    }

    #[test]
    fn caller_path_is_never_accepted_as_environment_data() {
        assert!(caller_environment_is_executable_authority("PATH"));
        #[cfg(windows)]
        assert!(caller_environment_is_executable_authority("path"));
        #[cfg(not(windows))]
        assert!(!caller_environment_is_executable_authority("path"));
        assert!(!caller_environment_is_executable_authority("PATH_INFO"));
    }

    #[test]
    fn environment_name_matching_uses_the_child_platform_semantics() {
        let bindings = HashMap::from([("KUBECONFIG".to_string(), "fixture".to_string())]);
        #[cfg(windows)]
        assert!(child_environment_contains(&bindings, "kubeconfig"));
        #[cfg(not(windows))]
        assert!(!child_environment_contains(&bindings, "kubeconfig"));
    }

    #[cfg(unix)]
    #[test]
    fn process_authority_identity_binds_mode_and_complete_group_membership() {
        let mut server = crate::server::tests::config_for_proposal_test();
        server.config.exec_as_caller = false;
        let mut context = ExecCallerContext {
            uid: 2001,
            gid: 2002,
            supplementary_group_ids: vec![2002, 2003],
            username: "fixture-user".to_string(),
            home_dir: PathBuf::from("/nonexistent/fixture-home"),
        };
        let fixed = process_execution_identity_binding(&server, Some(&context)).unwrap();
        assert_eq!(
            fixed.mode,
            guard::gating::approval::ProcessExecutionIdentityMode::FixedUser
        );

        context.supplementary_group_ids.push(2004);
        let changed_groups = process_execution_identity_binding(&server, Some(&context)).unwrap();
        assert_ne!(fixed, changed_groups);

        server.config.exec_as_caller = true;
        let caller = process_execution_identity_binding(&server, Some(&context)).unwrap();
        assert_eq!(
            caller.mode,
            guard::gating::approval::ProcessExecutionIdentityMode::Caller
        );
        assert_ne!(changed_groups, caller);
    }

    #[tokio::test]
    async fn fixed_child_kubeconfig_must_match_one_active_guard_proxy() {
        let server = crate::server::tests::config_for_proposal_test();
        let upstream_credential = format!("fixture-{:032x}", rand::random::<u128>());
        let proxy = Arc::new(guard::proxy::ApiProxy::new(
            "127.0.0.1:18443".parse().unwrap(),
            guard::proxy::ProxyTls::generate().unwrap(),
            guard::proxy::Upstream::from_base_url(
                "https://127.0.0.1:16443",
                guard::proxy::UpstreamAuth::Bearer(upstream_credential),
            )
            .unwrap(),
            guard::proxy::ApiPolicy::deny_all(),
            None,
        ));
        server
            .state
            .protocol_registry
            .write()
            .await
            .insert("fixture".to_string(), proxy.clone());

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("kubeconfig");
        std::fs::write(&path, proxy.brokered_kubeconfig()).unwrap();
        assert!(
            !fixed_child_environment_binding_is_sensitive(
                &server,
                "KUBECONFIG",
                path.to_str().unwrap(),
            )
            .await
        );

        let other_proxy = guard::proxy::ApiProxy::new(
            "127.0.0.1:19443".parse().unwrap(),
            guard::proxy::ProxyTls::generate().unwrap(),
            guard::proxy::Upstream::from_base_url(
                "https://127.0.0.1:16443",
                guard::proxy::UpstreamAuth::Bearer(format!(
                    "fixture-{:032x}",
                    rand::random::<u128>()
                )),
            )
            .unwrap(),
            guard::proxy::ApiPolicy::deny_all(),
            None,
        );
        std::fs::write(&path, other_proxy.brokered_kubeconfig()).unwrap();
        assert!(
            fixed_child_environment_binding_is_sensitive(
                &server,
                "KUBECONFIG",
                path.to_str().unwrap(),
            )
            .await
        );
    }

    #[tokio::test]
    async fn fixed_child_environment_uses_an_explicit_inert_variable_schema() {
        let server = crate::server::tests::config_for_proposal_test();
        for name in [
            "DOCKER_CONFIG",
            "KRB5CCNAME",
            "GNUPGHOME",
            "LD_PRELOAD",
            "PYTHONPATH",
            "SSH_AUTH_SOCK",
        ] {
            assert!(
                fixed_child_environment_binding_is_sensitive(&server, name, "/tmp/fixture").await,
                "{name} must not cross the fixed-identity boundary"
            );
        }
        for (name, value) in [
            ("LANG", "C.UTF-8"),
            ("TERM", "dumb"),
            ("KUBECTL_KUBERC", "false"),
            ("KUBECTL_ENABLE_CMD_SHADOW", "0"),
        ] {
            assert!(
                !fixed_child_environment_binding_is_sensitive(&server, name, value).await,
                "{name} should remain inert"
            );
        }
    }

    #[tokio::test]
    async fn fixed_child_rejects_tools_with_unbounded_implicit_profiles() {
        let server = crate::server::tests::config_for_proposal_test();
        for binary in ["ansible", "ansible-playbook", "helm"] {
            let request = ExecuteRequest {
                binary: binary.to_string(),
                ..fixture_request(None)
            };
            let error =
                validate_fixed_identity_profile_authority(&server, &request, &HashMap::new())
                    .await
                    .unwrap_err();
            assert!(
                error.contains("immutable profile snapshots"),
                "{binary}: {error}"
            );
        }
    }

    #[test]
    fn execution_identity_support_is_explicit_for_profile_driven_tools() {
        let mut server = crate::server::tests::config_for_proposal_test();
        server.config.exec_as_caller = false;
        assert!(unsupported_execution_identity_profile_reason(&server, "kubectl").is_none());
        for binary in ["ansible", "ansible-playbook", "helm"] {
            let reason = unsupported_execution_identity_profile_reason(&server, binary)
                .expect("mutable profile must be rejected");
            assert!(
                reason.contains("immutable profile snapshots"),
                "{binary}: {reason}"
            );
        }

        server.config.exec_as_caller = true;
        let kubectl_reason = unsupported_execution_identity_profile_reason(&server, "kubectl")
            .expect("caller profile must be rejected");
        assert!(kubectl_reason.contains("mutable caller profile"));
        assert!(unsupported_execution_identity_profile_reason(&server, "ssh").is_none());
    }

    #[test]
    fn typed_command_authority_retains_the_selected_working_tree() {
        let cwd = PathBuf::from("/operator/project");
        let primary = PathBuf::from("/operator/bin/fixture");
        let request = fixture_request(Some(cwd.clone()));
        let paths = process_start_operator_authority_paths(
            &request,
            Some(&typed_authorization()),
            &primary,
            &HashMap::new(),
        )
        .unwrap();

        assert!(paths.contains(&cwd));
        assert!(paths.contains(&primary));
    }

    #[test]
    fn omitted_working_directory_is_explicit_process_authority() {
        let request = fixture_request(None);
        let primary = PathBuf::from("/operator/bin/fixture");
        let paths = process_start_operator_authority_paths(
            &request,
            Some(&typed_authorization()),
            &primary,
            &HashMap::new(),
        )
        .unwrap();
        let default = safe_default_working_directory().unwrap();

        assert!(default.is_absolute());
        assert!(!paths.contains(&default));
        assert!(paths.contains(&primary));

        let mut evaluated = request;
        evaluated.cwd = Some(default.clone());
        assert!(request_authority_working_directory(&evaluated).is_none());
        let prompt = evaluation_context_prompt(&evaluated, None).unwrap();
        assert!(prompt.contains(&default.display().to_string()));
    }

    #[test]
    fn authorized_executable_search_uses_only_absolute_canonical_directories() {
        let temp = tempfile::tempdir().unwrap();
        let directory = std::env::current_dir().unwrap().canonicalize().unwrap();
        let missing = temp.path().join("missing-bin");
        let path = std::env::join_paths([&missing, &directory]).unwrap();
        let environment = HashMap::from([("PATH".to_string(), path.to_string_lossy().into())]);

        assert_eq!(
            process_execution_executable_search_directories(true, &environment).unwrap(),
            vec![directory]
        );

        let relative = HashMap::from([("PATH".to_string(), "relative".to_string())]);
        assert!(
            process_execution_executable_search_directories(true, &relative)
                .unwrap_err()
                .contains("empty or relative")
        );
    }

    #[test]
    fn untyped_command_does_not_claim_operator_working_tree_authority() {
        let request = fixture_request(Some(PathBuf::from("/operator/project")));
        let paths = process_start_operator_authority_paths(
            &request,
            None,
            Path::new("/operator/bin/fixture"),
            &HashMap::new(),
        )
        .unwrap();

        assert!(paths.is_empty());
    }

    #[test]
    fn approved_raw_replay_retains_its_resolved_primary_executable() {
        let cwd = PathBuf::from("/caller/project");
        let request = fixture_request(Some(cwd.clone()));
        let primary = PathBuf::from("/operator/bin/fixture");
        let authorization = CommandAuthorization::replay(None, None, Some(30), None, None);
        let paths = process_start_operator_authority_paths(
            &request,
            Some(&authorization),
            &primary,
            &HashMap::new(),
        )
        .unwrap();

        assert_eq!(
            paths.into_iter().collect::<BTreeSet<_>>(),
            [cwd, primary].into_iter().collect()
        );
    }

    #[test]
    fn protected_tool_roots_follow_platform_environment_semantics() {
        for name in [
            "HOME",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_CACHE_HOME",
            "USERPROFILE",
            "HOMEDRIVE",
            "HOMEPATH",
            "APPDATA",
            "LOCALAPPDATA",
            "TEMP",
            "TMP",
        ] {
            assert!(caller_environment_redirects_tool_authority("kubectl", name));
            assert!(caller_environment_redirects_tool_authority(
                "ansible-playbook",
                name
            ));
        }
        assert!(!caller_environment_redirects_tool_authority("ssh", "HOME"));
        #[cfg(windows)]
        assert!(caller_environment_redirects_tool_authority("helm", "home"));
        #[cfg(not(windows))]
        assert!(!caller_environment_redirects_tool_authority("helm", "home"));
        assert!(tool_discovers_profile_authority("ansible"));
        assert!(tool_discovers_profile_authority("kubectl"));
        assert!(tool_discovers_profile_authority("helm"));
        assert!(!tool_discovers_profile_authority("ssh"));
    }

    #[test]
    fn daemon_search_directories_exclude_the_canonical_shim_directory() {
        let root = tempfile::tempdir().unwrap();
        let shim = root.path().join("shim");
        let tools = root.path().join("tools");
        std::fs::create_dir(&shim).unwrap();
        std::fs::create_dir(&tools).unwrap();
        let search = std::env::join_paths([&shim, &tools]).unwrap();

        assert_eq!(
            daemon_executable_search_directories(&search, Some(&shim)),
            vec![tools.canonicalize().unwrap()]
        );
    }

    #[test]
    fn default_tool_profile_authority_collects_existing_discovery_roots() {
        let home = tempfile::tempdir().unwrap();
        for relative in [
            ".ansible/plugins",
            ".ansible/collections",
            ".ansible/roles",
            ".ssh",
            ".kube",
        ] {
            std::fs::create_dir_all(home.path().join(relative)).unwrap();
        }
        #[cfg(not(windows))]
        for relative in [".config/helm", ".local/share/helm", ".cache/helm"] {
            std::fs::create_dir_all(home.path().join(relative)).unwrap();
        }
        #[cfg(windows)]
        for relative in ["AppData/Roaming/helm", "Temp/helm"] {
            std::fs::create_dir_all(home.path().join(relative)).unwrap();
        }
        std::fs::write(home.path().join(".ansible.cfg"), "[defaults]\n").unwrap();
        std::fs::write(home.path().join(".kube/config"), "apiVersion: v1\n").unwrap();
        let environment = HashMap::from([(
            "HOME".to_string(),
            home.path().to_string_lossy().into_owned(),
        )]);
        #[cfg(windows)]
        let environment = {
            let mut environment = environment;
            environment.insert(
                "APPDATA".to_string(),
                home.path()
                    .join("AppData/Roaming")
                    .to_string_lossy()
                    .into_owned(),
            );
            environment.insert(
                "TEMP".to_string(),
                home.path().join("Temp").to_string_lossy().into_owned(),
            );
            environment
        };

        let ansible =
            default_tool_profile_authority_paths("ansible", &[], &environment, home.path());
        assert!(ansible.contains(&home.path().join(".ansible.cfg")));
        assert!(ansible.contains(&home.path().join(".ansible/plugins")));
        assert!(ansible.contains(&home.path().join(".ansible/collections")));
        assert!(ansible.contains(&home.path().join(".ansible/roles")));
        assert!(ansible.contains(&home.path().join(".ssh")));
        assert!(!ansible.contains(&home.path().join(".ansible")));

        let kubectl =
            default_tool_profile_authority_paths("kubectl", &[], &environment, home.path());
        assert_eq!(kubectl, vec![home.path().join(".kube/config")]);

        let helm = default_tool_profile_authority_paths("helm", &[], &environment, home.path())
            .into_iter()
            .collect::<BTreeSet<_>>();
        assert!(helm.contains(&home.path().join(".kube/config")));
        #[cfg(not(windows))]
        {
            assert!(helm.contains(&home.path().join(".config/helm")));
            assert!(helm.contains(&home.path().join(".local/share/helm")));
            assert!(helm.contains(&home.path().join(".cache/helm")));
        }
        #[cfg(windows)]
        {
            assert!(helm.contains(&home.path().join("AppData/Roaming/helm")));
            assert!(helm.contains(&home.path().join("Temp/helm")));
        }

        let explicit_kubeconfig = default_tool_profile_authority_paths(
            "kubectl",
            &["--kubeconfig=/srv/guard/cluster.yaml".to_string()],
            &environment,
            home.path(),
        );
        assert!(!explicit_kubeconfig.contains(&home.path().join(".kube/config")));
        let explicit_ansible = default_tool_profile_authority_paths(
            "ansible",
            &["-i/srv/guard/inventory".to_string()],
            &HashMap::from([
                (
                    "HOME".to_string(),
                    home.path().to_string_lossy().into_owned(),
                ),
                (
                    "ANSIBLE_CONFIG".to_string(),
                    "/srv/guard/ansible.cfg".to_string(),
                ),
                ("ANSIBLE_HOME".to_string(), "/srv/guard/ansible".to_string()),
            ]),
            home.path(),
        );
        assert!(!explicit_ansible.contains(&home.path().join(".ansible.cfg")));
        assert!(!explicit_ansible.contains(&home.path().join(".ansible/plugins")));
    }

    #[test]
    fn authorized_tool_defaults_replace_daemon_values() {
        let request = fixture_request(None);
        let mut trusted = HashMap::new();
        let daemon = HashMap::from([("KUBECTL_ENABLE_CMD_SHADOW".to_string(), "true".to_string())]);
        let request = ExecuteRequest {
            binary: "kubectl".to_string(),
            ..request
        };

        apply_authorized_tool_environment_defaults(
            &request,
            Some(&typed_authorization()),
            &daemon,
            &mut trusted,
        )
        .unwrap();

        assert_eq!(
            trusted.get("KUBECTL_ENABLE_CMD_SHADOW"),
            Some(&"false".to_string())
        );
        assert_eq!(trusted.get("KUBECTL_KUBERC"), Some(&"false".to_string()));

        let mut replay_trusted = HashMap::new();
        let replay = CommandAuthorization::replay(None, None, Some(30), None, None);
        apply_authorized_tool_environment_defaults(
            &request,
            Some(&replay),
            &HashMap::new(),
            &mut replay_trusted,
        )
        .unwrap();
        assert_eq!(
            replay_trusted.get("KUBECTL_ENABLE_CMD_SHADOW"),
            Some(&"false".to_string())
        );
        assert_eq!(
            replay_trusted.get("KUBECTL_KUBERC"),
            Some(&"false".to_string())
        );
    }

    #[cfg(unix)]
    #[test]
    fn authorized_child_path_uses_the_canonical_leased_directories() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let real = temp.path().join("z-real-bin");
        let second = temp.path().join("a-real-bin");
        let alias = temp.path().join("bin-alias");
        std::fs::create_dir(&real).unwrap();
        std::fs::create_dir(&second).unwrap();
        symlink(&real, &alias).unwrap();
        let mut environment = HashMap::from([(
            "PATH".to_string(),
            std::env::join_paths([&alias, &second])
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        )]);
        canonicalize_authorized_executable_search_path(true, &mut environment).unwrap();

        let expected =
            std::env::join_paths([real.canonicalize().unwrap(), second.canonicalize().unwrap()])
                .unwrap()
                .to_string_lossy()
                .into_owned();
        assert_eq!(
            child_environment_value(&environment, "PATH"),
            Some(expected.as_str())
        );
    }

    #[test]
    fn primary_only_delayed_authority_removes_child_path() {
        let mut environment = HashMap::from([("PATH".to_string(), "/operator/bin".to_string())]);

        canonicalize_authorized_executable_search_path(false, &mut environment).unwrap();

        assert!(child_environment_value(&environment, "PATH").is_none());
        assert!(
            process_execution_executable_search_directories(false, &environment)
                .unwrap()
                .is_empty()
        );
    }
}

#[cfg(test)]
mod decision_trace_feature_tests {
    use super::*;
    use guard::gating::verb::CoverageAction;
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    fn denied_verb_resolution(scope: VerbMatchScope) -> VerbResolution {
        VerbResolution {
            decision: VerbDecision::Deny,
            context: None,
            matches: vec![VerbMatchInfo {
                verb: "fixture".to_string(),
                cell: "denied".to_string(),
                scope,
                action: CoverageAction::Deny,
                features: Vec::new(),
                selected: true,
                overridden: false,
                exact_cwd_authorized: false,
            }],
            guidance: None,
            conflict_prompt: None,
            unresolved_plan: false,
            revert: None,
        }
    }

    #[test]
    fn typed_verb_denial_source_distinguishes_baseline_and_session_policy() {
        assert_eq!(
            typed_verb_deny_decision_source(&denied_verb_resolution(VerbMatchScope::Baseline)),
            SessionDecisionSource::StaticPolicy
        );
        assert_eq!(
            typed_verb_deny_decision_source(&denied_verb_resolution(VerbMatchScope::Session)),
            SessionDecisionSource::SessionDeny
        );
    }

    #[test]
    fn carrier_floor_requires_exact_cwd_on_every_selected_verb_cell() {
        let mut resolution = denied_verb_resolution(VerbMatchScope::Baseline);
        assert!(!selected_verb_authority_binds_exact_cwd(&resolution));

        resolution.matches[0].exact_cwd_authorized = true;
        assert!(selected_verb_authority_binds_exact_cwd(&resolution));

        let mut unselected = resolution.matches[0].clone();
        unselected.selected = false;
        unselected.exact_cwd_authorized = false;
        resolution.matches.push(unselected);
        assert!(selected_verb_authority_binds_exact_cwd(&resolution));

        let mut selected_without_cwd = resolution.matches[0].clone();
        selected_without_cwd.exact_cwd_authorized = false;
        resolution.matches.push(selected_without_cwd);
        assert!(!selected_verb_authority_binds_exact_cwd(&resolution));

        resolution.matches.clear();
        assert!(!selected_verb_authority_binds_exact_cwd(&resolution));
    }

    #[test]
    fn buffered_output_truncation_preserves_utf8_and_the_byte_cap() {
        let mut output = "x".repeat(MAX_OUTPUT_BYTES - 1);
        output.push('µ');
        truncate_utf8_bytes(&mut output, MAX_OUTPUT_BYTES);
        assert!(output.len() <= MAX_OUTPUT_BYTES);
        assert!(output.is_char_boundary(output.len()));
        assert!(!output.ends_with('µ'));
    }

    #[tokio::test]
    async fn unterminated_stream_is_chunked_and_stopped_at_the_total_byte_limit() {
        let (tx, mut rx) = mpsc::channel(4);
        let total = Arc::new(AtomicUsize::new(0));
        let reader =
            tokio::io::AsyncReadExt::take(tokio::io::repeat(b'x'), (MAX_OUTPUT_BYTES + 1) as u64);
        let task = tokio::spawn(forward_stream_chunks(
            reader,
            OutputStream::Stdout,
            tx,
            total,
        ));
        let mut retained = 0usize;
        let mut limited = false;
        while let Some(chunk) = rx.recv().await {
            match chunk {
                StreamChunk::Data { data, .. } => {
                    assert!(data.len() <= 8 * 1024);
                    retained += data.len();
                }
                StreamChunk::LimitExceeded => limited = true,
                StreamChunk::PipeError { .. } => panic!("unexpected pipe error"),
            }
        }
        task.await.unwrap();
        assert!(limited);
        assert!(retained <= MAX_OUTPUT_BYTES);
    }

    fn redact_complete_test_line(line: String, state: &mut RedactionState) -> String {
        let had_trailing_newline = line.ends_with('\n');
        let line = line.strip_suffix('\n').unwrap_or(&line);
        let line = line.strip_suffix('\r').unwrap_or(line);
        let mut redacted = redact_output_with_state(line, state);
        if had_trailing_newline {
            redacted.push('\n');
        }
        redacted
    }

    #[test]
    fn streaming_heuristic_redaction_holds_a_split_credential_field_until_line_end() {
        const CHUNK_BYTES: usize = 8 * 1024;
        const FIELD_PREFIX: &[u8] = b" API_TO";
        const SENSITIVE_VALUE: &str = "fixture-sensitive-value";

        let mut first_chunk = vec![b'x'; CHUNK_BYTES - FIELD_PREFIX.len()];
        first_chunk.extend_from_slice(FIELD_PREFIX);
        assert_eq!(first_chunk.len(), CHUNK_BYTES);
        let second_chunk = format!("KEN={SENSITIVE_VALUE}\n");

        let mut exact = ExactSecretStreamRedactor::new(Vec::new(), MAX_OUTPUT_BYTES).unwrap();
        let mut heuristic = StreamingHeuristicRedactor::default();
        let first = exact.push(&first_chunk).unwrap();
        assert!(heuristic
            .push(&first, redact_complete_test_line)
            .unwrap()
            .is_empty());

        let second = exact.push(second_chunk.as_bytes()).unwrap();
        let mut output = heuristic.push(&second, redact_complete_test_line).unwrap();
        output.push_str(
            &heuristic
                .push(&exact.finish().unwrap(), redact_complete_test_line)
                .unwrap(),
        );
        output.push_str(&heuristic.finish(redact_complete_test_line).unwrap());

        assert!(!output.contains(SENSITIVE_VALUE));
        assert!(output.contains("API_TOKEN=[REDACTED]"));
    }

    #[test]
    fn streaming_heuristic_redaction_rejects_an_oversized_unterminated_line() {
        let mut redactor = StreamingHeuristicRedactor::default();
        assert!(redactor
            .push(&vec![b'x'; MAX_OUTPUT_BYTES], redact_complete_test_line,)
            .unwrap()
            .is_empty());
        assert!(matches!(
            redactor.push(b"x", redact_complete_test_line),
            Err(BoundedOutputError::OutputLimit)
        ));
    }

    #[tokio::test]
    async fn buffered_child_output_is_bounded_before_collection() {
        let reader =
            tokio::io::AsyncReadExt::take(tokio::io::repeat(b'x'), (MAX_OUTPUT_BYTES + 1) as u64);
        assert!(
            read_bounded_redacted_output(reader, Vec::new(), Arc::new(AtomicUsize::new(0)),)
                .await
                .is_err()
        );
    }

    #[test]
    fn buffered_output_budget_is_shared_across_stdout_and_stderr() {
        let total = AtomicUsize::new(0);
        assert!(reserve_bounded_output(&total, MAX_OUTPUT_BYTES - 1).is_ok());
        assert!(matches!(
            reserve_bounded_output(&total, 2),
            Err(BoundedOutputError::OutputLimit)
        ));
    }

    struct FailingOutputReader;

    impl AsyncRead for FailingOutputReader {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "bounded output test pipe",
            )))
        }
    }

    struct PendingOutputReader;

    impl AsyncRead for PendingOutputReader {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
    }

    struct OneByteOutputReader {
        emitted: bool,
    }

    struct DropSignal(Arc<AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    impl AsyncRead for OneByteOutputReader {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.emitted {
                return std::task::Poll::Ready(Ok(()));
            }
            self.emitted = true;
            buf.put_slice(b"x");
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn stream_task_cleanup_aborts_and_joins_pending_reader() {
        let dropped = Arc::new(AtomicBool::new(false));
        let task_dropped = dropped.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _signal = DropSignal(task_dropped);
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        let mut cleanup = StreamTaskCleanup {
            tasks: vec![StreamReaderTask {
                stream: OutputStream::Stdout,
                handle: task,
            }],
        };
        started_rx.await.expect("reader task must start");

        cleanup.abort_and_join().await;

        assert!(dropped.load(Ordering::Acquire));
        assert!(cleanup.tasks.is_empty());
    }

    #[tokio::test]
    async fn stream_task_join_reports_a_panicking_reader() {
        let task = tokio::spawn(async {
            panic!("injected reader task panic");
        });
        let mut cleanup = StreamTaskCleanup {
            tasks: vec![StreamReaderTask {
                stream: OutputStream::Stderr,
                handle: task,
            }],
        };

        let error = cleanup.join().await.unwrap_err();

        assert!(matches!(error.stream, OutputStream::Stderr));
        assert_eq!(error.detail, "reader task panicked");
        assert!(cleanup.tasks.is_empty());
    }

    #[tokio::test]
    async fn stream_pipe_error_preserves_originating_stream() {
        let (tx, mut rx) = mpsc::channel(1);
        let task = tokio::spawn(forward_stream_chunks(
            FailingOutputReader,
            OutputStream::Stdout,
            tx,
            Arc::new(AtomicUsize::new(0)),
        ));

        match rx.recv().await {
            Some(StreamChunk::PipeError { stream, detail }) => {
                assert!(matches!(stream, OutputStream::Stdout));
                assert!(detail.contains("bounded output test pipe"));
            }
            other => panic!("unexpected stream result: {other:?}"),
        }
        assert!(rx.recv().await.is_none());
        task.await.unwrap();
    }

    #[tokio::test]
    async fn buffered_output_coordinator_kills_pending_sibling_on_stdout_limit() {
        let total = Arc::new(AtomicUsize::new(MAX_OUTPUT_BYTES));
        let stdout = read_bounded_redacted_output(
            OneByteOutputReader { emitted: false },
            Vec::new(),
            total.clone(),
        );
        let stderr = read_bounded_redacted_output(PendingOutputReader, Vec::new(), total);
        let error = tokio::time::timeout(
            Duration::from_secs(1),
            collect_bounded_output_pair(stdout, stderr),
        )
        .await
        .expect("stdout limit must not wait for a pending stderr reader")
        .unwrap_err();
        assert!(matches!(error, BoundedOutputError::OutputLimit));
    }

    #[tokio::test]
    async fn buffered_output_coordinator_kills_pending_sibling_on_stderr_limit() {
        let total = Arc::new(AtomicUsize::new(MAX_OUTPUT_BYTES));
        let stdout = read_bounded_redacted_output(PendingOutputReader, Vec::new(), total.clone());
        let stderr =
            read_bounded_redacted_output(OneByteOutputReader { emitted: false }, Vec::new(), total);
        let error = tokio::time::timeout(
            Duration::from_secs(1),
            collect_bounded_output_pair(stdout, stderr),
        )
        .await
        .expect("stderr limit must not wait for a pending stdout reader")
        .unwrap_err();
        assert!(matches!(error, BoundedOutputError::OutputLimit));
    }

    #[tokio::test]
    async fn buffered_output_coordinator_preserves_first_failure_from_either_stream() {
        let stdout = read_bounded_redacted_output(
            FailingOutputReader,
            Vec::new(),
            Arc::new(AtomicUsize::new(0)),
        );
        let stderr = read_bounded_redacted_output(
            PendingOutputReader,
            Vec::new(),
            Arc::new(AtomicUsize::new(0)),
        );
        let error = tokio::time::timeout(
            Duration::from_secs(1),
            collect_bounded_output_pair(stdout, stderr),
        )
        .await
        .expect("stdout failure must not wait for a pending stderr reader")
        .unwrap_err();
        assert!(matches!(error, BoundedOutputError::PipeIo(_)));
        assert!(error.to_string().contains("bounded output test pipe"));

        let stdout = read_bounded_redacted_output(
            PendingOutputReader,
            Vec::new(),
            Arc::new(AtomicUsize::new(0)),
        );
        let stderr = read_bounded_redacted_output(
            FailingOutputReader,
            Vec::new(),
            Arc::new(AtomicUsize::new(0)),
        );
        let error = tokio::time::timeout(
            Duration::from_secs(1),
            collect_bounded_output_pair(stdout, stderr),
        )
        .await
        .expect("stderr failure must not wait for a pending stdout reader")
        .unwrap_err();
        assert!(matches!(error, BoundedOutputError::PipeIo(_)));
        assert!(error.to_string().contains("bounded output test pipe"));
    }

    #[tokio::test]
    async fn buffered_output_reports_pipe_failures_as_typed_diagnostics() {
        let error = read_bounded_redacted_output(
            FailingOutputReader,
            Vec::new(),
            Arc::new(AtomicUsize::new(0)),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, BoundedOutputError::PipeIo(_)));
        assert!(error.to_string().len() <= 220);
    }

    #[test]
    fn persisted_trace_drops_legacy_observed_argument_values() {
        let fixture_value = "fixture-bearer-value";
        let matches = vec![VerbMatchInfo {
            verb: "api-read".to_string(),
            cell: "target".to_string(),
            scope: VerbMatchScope::Session,
            action: CoverageAction::Preauthorized,
            features: vec![
                "target:position:2".to_string(),
                format!("target:position:2:allowed={fixture_value}"),
                format!("target:position:2:observed={fixture_value}"),
            ],
            selected: true,
            overridden: false,
            exact_cwd_authorized: false,
        }];

        let persisted = decision_trace_verb_matches(&matches);
        assert_eq!(persisted[0].features, vec!["target:position:2"]);
        assert!(!serde_json::to_string(&persisted)
            .unwrap()
            .contains(fixture_value));
    }
}

#[cfg(test)]
mod transactional_access_tests {
    use super::*;

    #[tokio::test]
    async fn empty_access_overlay_preserves_baseline_evaluator_prompt() {
        let server = crate::server::tests::config_for_proposal_test();
        let mut request = ExecuteRequest {
            binary: "fixture-command".to_string(),
            args: vec!["inspect".to_string()],
            auth_token: None,
            env: HashMap::new(),
            secrets: HashMap::new(),
            secret_files: HashMap::new(),
            stream: false,
            session_token: None,
            revert: None,
            confirm_within_secs: None,
            reevaluate: false,
            ssh_hostkey: None,
            cwd: None,
            require_approval: None,
            wait_approval_secs: None,
            verb: None,
        };
        let baseline_prompt = resolve_session_prompt(&server, &request).await;

        let token = "additive-overlay".to_string();
        {
            let mut sessions = server.state.sessions.write().await;
            assert!(sessions.grant_policy_only_access_overlay(
                token.clone(),
                guard::principal::PrincipalKey::from_uid(1001),
                "fixture overlay".to_string(),
                guard::env::now_unix().saturating_add(60),
            ));
            assert_eq!(
                sessions.apply_delta(
                    &token,
                    &crate::grant_profile::GrantRequestDelta {
                        prompt_append: Some(
                            "overlay context must stay out of evaluation".to_string(),
                        ),
                        ..crate::grant_profile::GrantRequestDelta::default()
                    },
                ),
                Some(true)
            );
        }
        request.session_token = Some(token);
        let overlay_prompt = resolve_session_prompt(&server, &request).await;

        assert_eq!(overlay_prompt, baseline_prompt);
        assert!(!overlay_prompt
            .as_deref()
            .unwrap_or_default()
            .contains("[GUARD AUTHORIZATION CONTEXT]"));
    }

    #[derive(Clone)]
    struct PausingSecretBackend {
        reached: std::sync::Arc<tokio::sync::Semaphore>,
        release: std::sync::Arc<tokio::sync::Semaphore>,
    }

    #[async_trait::async_trait]
    impl crate::secrets::SecretBackend for PausingSecretBackend {
        fn name(&self) -> &str {
            "pausing-test-backend"
        }

        async fn get(
            &self,
            _principal: &guard::principal::PrincipalKey,
            _key: &str,
        ) -> Result<Option<String>> {
            self.reached.add_permits(1);
            self.release.acquire().await.unwrap().forget();
            Ok(Some("resolved-value".to_string()))
        }

        async fn list(&self, _principal: &guard::principal::PrincipalKey) -> Result<Vec<String>> {
            Ok(Vec::new())
        }

        async fn list_all(&self) -> Result<Vec<(guard::principal::PrincipalKey, String)>> {
            Ok(Vec::new())
        }

        async fn set(
            &self,
            _principal: &guard::principal::PrincipalKey,
            _key: &str,
            _value: &str,
        ) -> Result<()> {
            Ok(())
        }

        async fn delete(
            &self,
            _principal: &guard::principal::PrincipalKey,
            _key: &str,
        ) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn secret_resolution_releases_tool_registry_and_rejects_stale_mapping() {
        let mut server = crate::server::tests::config_for_proposal_test();
        let state = tempfile::tempdir().unwrap();
        let path = state.path().join("tools.yaml");
        let mut registry = crate::tool_config::ToolRegistry::load(path).unwrap();
        registry
            .set(
                "fixture-tool",
                crate::tool_config::ToolConfig {
                    secrets: HashMap::from([(
                        "FIXTURE_VARIABLE".to_string(),
                        "fixture-reference".to_string(),
                    )]),
                    ..crate::tool_config::ToolConfig::default()
                },
            )
            .unwrap();
        *server.state.tool_registry.write().await = registry;
        let reached = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
        let release = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
        server.state.secrets = std::sync::Arc::new(crate::secrets::SecretManager::with_backend(
            PausingSecretBackend {
                reached: reached.clone(),
                release: release.clone(),
            },
        ));
        let principal = guard::principal::PrincipalKey::from_uid(1001);
        let resolving = tokio::spawn({
            let server = server.clone();
            let principal = principal.clone();
            async move {
                resolve_current_tool_env(&server, "fixture-tool", Some(&principal), Some("1001"))
                    .await
            }
        });
        reached.acquire().await.unwrap().forget();

        let mut live = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            server.state.tool_registry.write(),
        )
        .await
        .expect("secret lookup must not retain the tool-registry writer");
        live.set("fixture-tool", crate::tool_config::ToolConfig::default())
            .unwrap();
        drop(live);

        release.add_permits(1);
        let error = resolving.await.unwrap().unwrap_err();
        assert!(error
            .to_string()
            .contains("authority changed during secret resolution"));
    }

    #[tokio::test]
    async fn final_tool_mapping_lease_rejects_post_resolution_replacement() {
        let server = crate::server::tests::config_for_proposal_test();
        let state = tempfile::tempdir().unwrap();
        let path = state.path().join("tools.yaml");
        let mut registry = crate::tool_config::ToolRegistry::load(path).unwrap();
        registry
            .set(
                "fixture-tool",
                crate::tool_config::ToolConfig {
                    env: HashMap::from([("FIXTURE_MODE".to_string(), "first".to_string())]),
                    ..crate::tool_config::ToolConfig::default()
                },
            )
            .unwrap();
        *server.state.tool_registry.write().await = registry;

        let resolved = resolve_current_tool_env(&server, "fixture-tool", None, None)
            .await
            .unwrap();
        server
            .state
            .tool_registry
            .write()
            .await
            .set(
                "fixture-tool",
                crate::tool_config::ToolConfig {
                    env: HashMap::from([("FIXTURE_MODE".to_string(), "second".to_string())]),
                    ..crate::tool_config::ToolConfig::default()
                },
            )
            .unwrap();

        assert!(
            acquire_tool_mapping_spawn_lease(&server, &resolved.authority)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn bounded_admission_reloads_once_after_unrelated_daemon_write() {
        let mut server = crate::server::tests::config_for_proposal_test();
        let state = tempfile::tempdir().unwrap();
        let database = state.path().join("state.db");
        let store = SessionStore::open(database.clone(), 3600).await.unwrap();
        let token = "bounded-reload".to_string();
        let mut registry = SessionRegistry::new();
        registry.grant(
            token.clone(),
            crate::session::SessionGrant {
                allow: Vec::new(),
                deny: Vec::new(),
                allow_exact: Vec::new(),
                deny_exact: Vec::new(),
                activated_verbs: vec!["host-inspect".to_string()],
                override_markers: Vec::new(),
                scope: crate::session::IssuedGrantScope {
                    access_managed: true,
                    ..crate::session::IssuedGrantScope::default()
                },
                expires_at: None,
                prompt_append: None,
                generated_notes: Vec::new(),
                granted_at: 1,
                static_only: true,
                auto_amend: false,
                owner: SessionOwner::Principal(guard::principal::PrincipalKey::from_uid(1001)),
            },
        );
        registry.install_access_grant(
            &token,
            Some(1),
            "access-use".to_string(),
            vec!["host-inspect".to_string()],
        );
        store.persist_registry(&registry).await.unwrap();
        *server.state.sessions.write().await = registry;
        server.state.session_store = Some(store.clone());

        let competing = SessionStore::open(database, 3600).await.unwrap();
        let mut advanced = competing.load_registry().await.unwrap();
        advanced.record_interaction(
            &token,
            SessionInteraction {
                at_unix: guard::env::now_unix(),
                command: "fixture interaction".to_string(),
                allowed: true,
                source: SessionDecisionSource::StaticPolicy,
                reason: "fixture".to_string(),
                risk: Some(0),
                exec_status: SessionExecStatus::Completed,
                exit_code: Some(0),
                exposed_secret_refs: Vec::new(),
                decision_trace: None,
            },
        );
        competing.persist_registry(&advanced).await.unwrap();

        let request = ExecuteRequest {
            binary: "host-inspect".to_string(),
            args: Vec::new(),
            auth_token: None,
            env: HashMap::new(),
            secrets: HashMap::new(),
            secret_files: HashMap::new(),
            stream: false,
            session_token: Some(token.clone()),
            revert: None,
            confirm_within_secs: None,
            reevaluate: false,
            ssh_hostkey: None,
            cwd: None,
            require_approval: None,
            wait_approval_secs: None,
            verb: None,
        };
        admit_access_use(&server, &request, &["host-inspect".to_string()], None)
            .await
            .unwrap();

        let durable = store.load_registry().await.unwrap();
        assert_eq!(
            durable.access_grant_uses(&token, "access-use"),
            Some((Some(1), Some(0)))
        );
        assert_eq!(durable.show(&token, 10).unwrap().stats.total, 1);
    }

    #[tokio::test]
    async fn unlimited_admission_reloads_and_refuses_a_concurrent_revoke() {
        let mut server = crate::server::tests::config_for_proposal_test();
        let state = tempfile::tempdir().unwrap();
        let database = state.path().join("state.db");
        let store = SessionStore::open(database.clone(), 3600).await.unwrap();
        let token = "unlimited-revoked".to_string();
        let mut registry = SessionRegistry::new();
        registry.grant(
            token.clone(),
            crate::session::SessionGrant {
                allow: Vec::new(),
                deny: Vec::new(),
                allow_exact: Vec::new(),
                deny_exact: Vec::new(),
                activated_verbs: vec!["host-inspect".to_string()],
                override_markers: Vec::new(),
                scope: crate::session::IssuedGrantScope {
                    access_managed: true,
                    ..crate::session::IssuedGrantScope::default()
                },
                expires_at: None,
                prompt_append: None,
                generated_notes: Vec::new(),
                granted_at: 1,
                static_only: true,
                auto_amend: false,
                owner: SessionOwner::Principal(guard::principal::PrincipalKey::from_uid(1001)),
            },
        );
        registry.install_access_grant(
            &token,
            None,
            "access-unlimited".to_string(),
            vec!["host-inspect".to_string()],
        );
        store.persist_registry(&registry).await.unwrap();
        *server.state.sessions.write().await = registry;
        server.state.session_store = Some(store.clone());

        let competing = SessionStore::open(database, 3600).await.unwrap();
        let mut revoked = competing.load_registry().await.unwrap();
        assert!(revoked.revoke(&token));
        competing.persist_registry(&revoked).await.unwrap();

        let request = ExecuteRequest {
            binary: "host-inspect".to_string(),
            args: Vec::new(),
            auth_token: None,
            env: HashMap::new(),
            secrets: HashMap::new(),
            secret_files: HashMap::new(),
            stream: false,
            session_token: Some(token.clone()),
            revert: None,
            confirm_within_secs: None,
            reevaluate: false,
            ssh_hostkey: None,
            cwd: None,
            require_approval: None,
            wait_approval_secs: None,
            verb: None,
        };
        let error = admit_access_use(&server, &request, &["host-inspect".to_string()], None)
            .await
            .unwrap_err();

        assert!(error.contains("expired or was revoked"));
        assert!(!server.state.sessions.read().await.has(&token));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stalled_access_admission_releases_sessions_and_cannot_publish_over_newer_state() {
        let mut server = crate::server::tests::config_for_proposal_test();
        let state = tempfile::tempdir().unwrap();
        let store = SessionStore::open(state.path().join("state.db"), 3600)
            .await
            .unwrap();
        let token = "stalled-admission".to_string();
        let mut registry = SessionRegistry::new();
        registry.grant(
            token.clone(),
            crate::session::SessionGrant {
                allow: Vec::new(),
                deny: Vec::new(),
                allow_exact: Vec::new(),
                deny_exact: Vec::new(),
                activated_verbs: vec!["host-inspect".to_string()],
                override_markers: Vec::new(),
                scope: crate::session::IssuedGrantScope {
                    access_managed: true,
                    ..crate::session::IssuedGrantScope::default()
                },
                expires_at: None,
                prompt_append: None,
                generated_notes: Vec::new(),
                granted_at: 1,
                static_only: true,
                auto_amend: false,
                owner: SessionOwner::Principal(guard::principal::PrincipalKey::from_uid(1001)),
            },
        );
        registry.install_access_grant(
            &token,
            Some(1),
            "access-use".to_string(),
            vec!["host-inspect".to_string()],
        );
        store.persist_registry(&registry).await.unwrap();
        *server.state.sessions.write().await = registry;
        server.state.session_store = Some(store.clone());
        let request = ExecuteRequest {
            binary: "host-inspect".to_string(),
            args: Vec::new(),
            auth_token: None,
            env: HashMap::new(),
            secrets: HashMap::new(),
            secret_files: HashMap::new(),
            stream: false,
            session_token: Some(token.clone()),
            revert: None,
            confirm_within_secs: None,
            reevaluate: false,
            ssh_hostkey: None,
            cwd: None,
            require_approval: None,
            wait_approval_secs: None,
            verb: None,
        };
        let (committed, release) = store.pause_registry_commit_for_test("session store persist");
        let admission = tokio::spawn({
            let server = server.clone();
            async move { admit_access_use(&server, &request, &["host-inspect".to_string()], None).await }
        });
        committed.acquire().await.unwrap().forget();

        let mut sessions = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            server.state.sessions.write(),
        )
        .await
        .expect("durable admission must not retain the live sessions writer");
        sessions.record_interaction(
            &token,
            SessionInteraction {
                at_unix: guard::env::now_unix(),
                command: "newer interaction".to_string(),
                allowed: false,
                source: SessionDecisionSource::StaticPolicy,
                reason: "newer authority state".to_string(),
                risk: Some(10),
                exec_status: SessionExecStatus::NotAttempted,
                exit_code: None,
                exposed_secret_refs: Vec::new(),
                decision_trace: None,
            },
        );
        let newer_revision = sessions.revision();
        drop(sessions);

        release.add_permits(1);
        let error = admission.await.unwrap().unwrap_err();
        assert!(error.contains("authority changed"));
        let sessions = server.state.sessions.read().await;
        assert_eq!(sessions.revision(), newer_revision);
        assert_eq!(sessions.show(&token, 10).unwrap().stats.denied, 1);
    }
}
