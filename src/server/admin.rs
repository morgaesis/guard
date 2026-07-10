use crate::grant_rules::{compile_session_grant_rules, CompiledGrantRules};
use crate::redact::redact_output;
use crate::secrets::legacy_sentinel;
use crate::session::{
    HistoricalGrant, SessionAmendment, SessionDecision, SessionDecisionSource, SessionExecStatus,
    SessionGrant, SessionGrantSummary, SessionInteraction, SessionReport,
};
use guard::principal::{scope_eq, PrincipalKey};

use super::execute::{
    allow_session_auto_amend_candidate, amend_session_exact_rule, audit_token, command_line,
    deny_session_auto_amend_candidate, persist_current_sessions, persist_session_snapshot,
    record_live_session_interaction, session_source_from_eval,
    validate_session_exact_rule_candidate,
};
use super::gate_runtime::{
    execute_snapshot, finish_revert, forget_proxy_provenance, now_unix, persist_approval,
    persist_provisional, API_PROXY_SENTINEL_BINARY,
};
use super::wire::{
    verb_effective_trust, AdminRequest, AdminResponse, ApprovalSummary, CallerIdentity,
    ExecOutcome, ProvisionalSummary, SecretDetail, ServerStatus, VerbSummary,
};
use super::{is_valid_secret_key, ServerConfig};

fn merge_unique(target: &mut Vec<String>, additions: Vec<String>) {
    for value in additions {
        if !target.iter().any(|existing| existing == &value) {
            target.push(value);
        }
    }
}

fn combine_session_prompt(
    prompt_append: Option<String>,
    prose: Option<&str>,
    _compiled: &CompiledGrantRules,
) -> Option<String> {
    let mut sections = Vec::new();
    let prompt_append = prompt_append
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if let Some(prose) = prose.map(str::trim).filter(|value| !value.is_empty()) {
        sections.push(format!("Session grant prose:\n{prose}"));
    }
    if sections.is_empty() {
        return prompt_append;
    }
    if let Some(prompt) = prompt_append {
        sections.push(format!("Additional session context:\n{prompt}"));
    }
    Some(sections.join("\n\n"))
}

fn caller_is_session_admin(config: &ServerConfig, caller: &CallerIdentity) -> bool {
    matches!(caller.principal(), Some(ref p) if config.daemon_principal.eq_ci(p))
        || matches!(caller, CallerIdentity::TcpAdmin { .. })
}

fn caller_can_view_session(
    config: &ServerConfig,
    caller: &CallerIdentity,
    token: &str,
    visible_token: Option<&str>,
) -> bool {
    caller_is_session_admin(config, caller) || visible_token == Some(token)
}

fn redact_session_summary_for_list(grant: &mut SessionGrantSummary, admin: bool, can_view: bool) {
    if !admin {
        grant.token = if can_view {
            "(current)".to_string()
        } else {
            "(hidden)".to_string()
        };
    }
    if !can_view {
        grant.allow.clear();
        grant.deny.clear();
        grant.allow_exact.clear();
        grant.deny_exact.clear();
        grant.generated_notes.clear();
        if grant.prompt_append.is_some() {
            grant.prompt_append = Some("(hidden)".to_string());
        }
    }
}

fn redact_historical_grant_for_list(grant: &mut HistoricalGrant, admin: bool, can_view: bool) {
    if !admin {
        grant.token = if can_view {
            "(current)".to_string()
        } else {
            "(hidden)".to_string()
        };
    }
    if !can_view {
        grant.allow.clear();
        grant.deny.clear();
        grant.allow_exact.clear();
        grant.deny_exact.clear();
        grant.generated_notes.clear();
        if grant.prompt_append.is_some() {
            grant.prompt_append = Some("(hidden)".to_string());
        }
    }
}

/// Mask the raw bearer token in a session report shown to its own holder. The
/// grant contents (rules, prompt, stats) are intentionally left intact for
/// self-diagnosis; only the token string is hidden so it is not echoed back.
fn mask_session_report_token(report: &mut SessionReport) {
    if let Some(active) = &mut report.active {
        active.token = "(current)".to_string();
    }
    for grant in &mut report.history {
        grant.token = "(current)".to_string();
    }
}

async fn handle_session_appeal(
    config: &ServerConfig,
    caller: &CallerIdentity,
    token: String,
    binary: String,
    args: Vec<String>,
) -> AdminResponse {
    if token.is_empty() {
        return AdminResponse::Error {
            message: "session token must not be empty".to_string(),
        };
    }
    let command_line = command_line(&binary, &args);
    if let Err(reason) = validate_session_exact_rule_candidate(&binary, &args) {
        return AdminResponse::SessionAppeal {
            allowed: false,
            amended: false,
            pattern: None,
            reason,
            risk: None,
        };
    }

    let (exists, decision, session_prompt) = {
        let reg = config.sessions.read().await;
        (
            reg.has(&token),
            reg.check(&token, &binary, &args),
            reg.prompt_append_for(&token),
        )
    };
    if !exists {
        return AdminResponse::Error {
            message: format!(
                "unknown session token: '{}' is revoked, expired, or never existed",
                token
            ),
        };
    }
    if let Some((decision, reason)) = decision {
        return match decision {
            SessionDecision::Allow => AdminResponse::SessionAppeal {
                allowed: true,
                amended: false,
                pattern: Some(command_line),
                reason: format!("already allowed by session rule: {reason}"),
                risk: None,
            },
            SessionDecision::Deny => AdminResponse::SessionAppeal {
                allowed: false,
                amended: false,
                pattern: Some(command_line),
                reason: format!("already denied by session rule: {reason}"),
                risk: None,
            },
        };
    }

    // An appeal is itself a request for a fresh look: it always bypasses the
    // auto-learned deny-shape fast path (never the operator PolicyEngine
    // deny rules, which `evaluate_with_reevaluate` never skips either way).
    let eval_result = config
        .evaluator
        .evaluate_with_reevaluate(&command_line, session_prompt.as_deref(), true)
        .await;

    match eval_result {
        crate::evaluate::EvalResult::Allow {
            reason,
            source,
            risk,
            reversibility: _,
        } => {
            if !matches!(source, crate::evaluate::EvalSource::Llm) {
                return AdminResponse::SessionAppeal {
                    allowed: false,
                    amended: false,
                    pattern: Some(command_line),
                    reason: format!(
                        "appeal not amended: evaluator source was {source:?}, not fresh LLM"
                    ),
                    risk,
                };
            }
            if let Err(skip) = allow_session_auto_amend_candidate(&binary, &args, risk) {
                record_live_session_interaction(
                    config,
                    Some(&token),
                    SessionInteraction {
                        at_unix: 0,
                        command: command_line.clone(),
                        allowed: false,
                        source: SessionDecisionSource::Llm,
                        reason: format!(
                            "appeal denied for static amendment: {skip}; LLM reason: {reason}"
                        ),
                        risk,
                        exec_status: SessionExecStatus::NotAttempted,
                    },
                )
                .await;
                return AdminResponse::SessionAppeal {
                    allowed: false,
                    amended: false,
                    pattern: Some(command_line),
                    reason: format!(
                        "appeal denied for static amendment: {skip}; LLM reason: {reason}"
                    ),
                    risk,
                };
            }

            let amended = match amend_session_exact_rule(
                config,
                &token,
                SessionAmendment::Allow,
                binary.clone(),
                args.clone(),
            )
            .await
            {
                Ok(amended) => amended,
                Err(err) => {
                    return AdminResponse::Error {
                        message: format!("failed to persist appeal allow amendment: {err}"),
                    };
                }
            };
            let final_reason = if amended {
                format!("appeal approved; amended exact session allow. LLM reason: {reason}")
            } else {
                format!(
                    "appeal approved; exact session allow already existed. LLM reason: {reason}"
                )
            };
            record_live_session_interaction(
                config,
                Some(&token),
                SessionInteraction {
                    at_unix: 0,
                    command: command_line.clone(),
                    allowed: true,
                    source: SessionDecisionSource::Llm,
                    reason: final_reason.clone(),
                    risk,
                    exec_status: SessionExecStatus::NotAttempted,
                },
            )
            .await;
            tracing::info!(
                "[AUDIT] SESSION_APPEAL caller={} token={} allowed=true amended={} cmd={}",
                caller,
                audit_token(&token),
                amended,
                redact_output(&command_line)
            );
            AdminResponse::SessionAppeal {
                allowed: true,
                amended,
                pattern: Some(command_line),
                reason: final_reason,
                risk,
            }
        }
        crate::evaluate::EvalResult::Deny {
            reason,
            source,
            risk,
        } => {
            let mut amended = false;
            if matches!(source, crate::evaluate::EvalSource::Llm)
                && deny_session_auto_amend_candidate(&binary, &args, risk).is_ok()
            {
                match amend_session_exact_rule(
                    config,
                    &token,
                    SessionAmendment::Deny,
                    binary.clone(),
                    args.clone(),
                )
                .await
                {
                    Ok(value) => amended = value,
                    Err(err) => {
                        return AdminResponse::Error {
                            message: format!("failed to persist appeal deny amendment: {err}"),
                        };
                    }
                }
            }
            let final_reason = if amended {
                format!("appeal denied; amended exact session deny. LLM reason: {reason}")
            } else {
                format!("appeal denied. LLM reason: {reason}")
            };
            record_live_session_interaction(
                config,
                Some(&token),
                SessionInteraction {
                    at_unix: 0,
                    command: command_line.clone(),
                    allowed: false,
                    source: session_source_from_eval(source),
                    reason: final_reason.clone(),
                    risk,
                    exec_status: SessionExecStatus::NotAttempted,
                },
            )
            .await;
            tracing::info!(
                "[AUDIT] SESSION_APPEAL caller={} token={} allowed=false amended={} cmd={}",
                caller,
                audit_token(&token),
                amended,
                redact_output(&command_line)
            );
            AdminResponse::SessionAppeal {
                allowed: false,
                amended,
                pattern: Some(command_line),
                reason: final_reason,
                risk,
            }
        }
        crate::evaluate::EvalResult::Error(err) => AdminResponse::SessionAppeal {
            allowed: false,
            amended: false,
            pattern: Some(command_line),
            reason: format!("appeal evaluation error: {err}"),
            risk: None,
        },
    }
}

pub(super) async fn handle_admin_request(
    config: &ServerConfig,
    caller: &CallerIdentity,
    request: AdminRequest,
) -> AdminResponse {
    if request.requires_daemon_uid() {
        if let Err(e) = config.validate_admin(caller) {
            tracing::warn!("[AUDIT] ADMIN_REJECTED caller={} reason=\"{}\"", caller, e);
            return AdminResponse::Error {
                message: e.to_string(),
            };
        }
    }

    match request {
        AdminRequest::SessionGrant {
            token,
            mut allow,
            mut deny,
            mut ttl_secs,
            prompt_append,
            prose,
            profile,
            static_only,
            auto_amend,
        } => {
            if token.is_empty() {
                return AdminResponse::Error {
                    message: "session token must not be empty".to_string(),
                };
            }
            // Expand a named operator profile into this grant before the usual
            // prose compilation. An unknown name fails loudly rather than
            // minting an empty (unrestricted) grant. The profile only seeds the
            // same fields an operator would type; the grant is installed on the
            // identical path below, so it is no separate trust boundary.
            let mut profile_prompt: Option<String> = None;
            if let Some(name) = profile.as_deref() {
                match config.profiles.get(name) {
                    Some(p) => {
                        merge_unique(&mut allow, p.allow.clone());
                        merge_unique(&mut deny, p.deny.clone());
                        ttl_secs = ttl_secs.or(p.ttl_secs);
                        profile_prompt = p.prompt_append.clone();
                    }
                    None => {
                        return AdminResponse::Error {
                            message: format!("unknown session profile: '{}'", name),
                        };
                    }
                }
            }
            let compiled = prose
                .as_deref()
                .map(compile_session_grant_rules)
                .unwrap_or_default();
            merge_unique(&mut allow, compiled.allow.clone());
            merge_unique(&mut deny, compiled.deny.clone());
            // Fold the profile's evaluator context in with any request/prose prompt.
            let base_prompt = match (prompt_append, profile_prompt) {
                (Some(request), Some(profile)) => Some(format!("{request}\n\n{profile}")),
                (some, None) | (None, some) => some,
            };
            let prompt_append = combine_session_prompt(base_prompt, prose.as_deref(), &compiled);
            let auto_amend = auto_amend && !static_only;
            let expires_at = ttl_secs.map(|secs| now_unix() + secs);
            let mut generated_notes = compiled.notes.clone();
            if let Some(name) = profile.as_deref() {
                generated_notes.push(format!("session minted from profile '{name}'"));
            }
            let grant = SessionGrant {
                allow,
                deny,
                allow_exact: Vec::new(),
                deny_exact: Vec::new(),
                expires_at,
                prompt_append,
                generated_notes,
                static_only,
                auto_amend,
                granted_at: 0, // SessionRegistry::grant fills the current time
            };
            let (before, after) = {
                let mut reg = config.sessions.write().await;
                reg.purge_expired();
                let before = reg.clone();
                reg.grant(token.clone(), grant);
                (before, reg.clone())
            };
            if let Err(err) = persist_session_snapshot(config.session_store.clone(), after).await {
                *config.sessions.write().await = before;
                return AdminResponse::Error {
                    message: format!("failed to persist session grant: {}", err),
                };
            }
            tracing::info!(
                "[AUDIT] SESSION_GRANT caller={} token={} profile={:?} ttl={:?} static_only={} auto_amend={} generated_allow={} generated_deny={}",
                caller,
                audit_token(&token),
                profile,
                ttl_secs,
                static_only,
                auto_amend,
                compiled.allow.len(),
                compiled.deny.len()
            );
            AdminResponse::Ok
        }
        AdminRequest::SessionAppeal {
            token,
            binary,
            args,
        } => handle_session_appeal(config, caller, token, binary, args).await,
        AdminRequest::SessionRevoke { token } => {
            let (removed, before, after) = {
                let mut reg = config.sessions.write().await;
                let before = reg.clone();
                let removed = reg.revoke(&token);
                (removed, before, reg.clone())
            };
            if let Err(err) = persist_session_snapshot(config.session_store.clone(), after).await {
                *config.sessions.write().await = before;
                return AdminResponse::Error {
                    message: format!("failed to persist session revoke: {}", err),
                };
            }
            tracing::info!(
                "[AUDIT] SESSION_REVOKE caller={} token={} existed={}",
                caller,
                audit_token(&token),
                removed
            );
            AdminResponse::Ok
        }
        AdminRequest::SessionList {
            include_history,
            since_unix,
            visible_token,
        } => {
            // Opportunistic purge so list shows fresh state and history
            // bookkeeping stays bounded.
            {
                let mut reg = config.sessions.write().await;
                reg.purge_expired();
            }
            if let Err(err) = persist_current_sessions(config).await {
                tracing::warn!("failed to persist purged session state: {}", err);
            }
            let reg = config.sessions.read().await;
            let is_admin = caller_is_session_admin(config, caller);
            let visible_token = visible_token.as_deref();
            let grants = reg
                .list()
                .into_iter()
                .map(|mut grant| {
                    let can_view =
                        caller_can_view_session(config, caller, &grant.token, visible_token);
                    redact_session_summary_for_list(&mut grant, is_admin, can_view);
                    grant
                })
                .collect();
            let history = if include_history {
                reg.list_history(since_unix)
                    .into_iter()
                    .map(|mut grant| {
                        let can_view =
                            caller_can_view_session(config, caller, &grant.token, visible_token);
                        redact_historical_grant_for_list(&mut grant, is_admin, can_view);
                        grant
                    })
                    .collect()
            } else {
                Vec::new()
            };
            AdminResponse::SessionList { grants, history }
        }
        AdminRequest::SessionShow {
            token,
            limit,
            caller_token,
        } => {
            {
                let mut reg = config.sessions.write().await;
                reg.purge_expired();
            }
            if let Err(err) = persist_current_sessions(config).await {
                tracing::warn!("failed to persist purged session state: {}", err);
            }
            let is_admin = caller_is_session_admin(config, caller);
            // A non-admin caller may inspect only the grant on its own token: the
            // token it presents as its identity ($GUARD_SESSION) must equal the
            // token it is asking about. That token is the same bearer credential
            // used for session auth, so equality is proof the caller holds it.
            // Merely naming another session's token is not enough -- that path
            // returns a denial, never the grant's contents.
            let is_self = !token.is_empty() && caller_token.as_deref() == Some(token.as_str());
            if !is_admin && !is_self {
                tracing::warn!(
                    "[AUDIT] SESSION_SHOW_REJECTED caller={} reason=\"not the token holder\"",
                    caller
                );
                return AdminResponse::Error {
                    message: "not authorized: a session token may only inspect its own grant"
                        .to_string(),
                };
            }
            let reg = config.sessions.read().await;
            match reg.show(&token, limit.unwrap_or(20)) {
                Some(mut report) => {
                    // A self-inspecting holder sees the full grant (rules, prompt,
                    // expiry) but never has its own raw bearer token echoed back.
                    if !is_admin {
                        mask_session_report_token(&mut report);
                    }
                    AdminResponse::SessionShow { report }
                }
                None => AdminResponse::Error {
                    message: format!("unknown session token: '{}'", token),
                },
            }
        }
        AdminRequest::SecretSet { key, value } => {
            if !is_valid_secret_key(&key) {
                return AdminResponse::Error {
                    message: format!("invalid secret key: '{}'", key),
                };
            }
            let principal = match caller.principal() {
                Some(principal) if caller.is_local_peer() => principal,
                _ => {
                    return AdminResponse::Error {
                        message: "secret ops require an authenticated local caller".to_string(),
                    };
                }
            };
            match config.secrets.set(&principal, &key, &value).await {
                Ok(()) => {
                    tracing::info!(
                        "[AUDIT] SECRET_SET caller={} principal={} key={}",
                        caller,
                        principal,
                        key
                    );
                    AdminResponse::Ok
                }
                Err(e) => AdminResponse::Error {
                    message: format!("failed to store secret '{}': {}", key, e),
                },
            }
        }
        AdminRequest::SecretDelete { key } => {
            if !is_valid_secret_key(&key) {
                return AdminResponse::Error {
                    message: format!("invalid secret key: '{}'", key),
                };
            }
            let principal = match caller.principal() {
                Some(principal) if caller.is_local_peer() => principal,
                _ => {
                    return AdminResponse::Error {
                        message: "secret ops require an authenticated local caller".to_string(),
                    };
                }
            };
            match config.secrets.delete(&principal, &key).await {
                Ok(()) => {
                    tracing::info!(
                        "[AUDIT] SECRET_DELETE caller={} principal={} key={}",
                        caller,
                        principal,
                        key
                    );
                    AdminResponse::Ok
                }
                Err(e) => AdminResponse::Error {
                    message: format!("failed to remove secret '{}': {}", key, e),
                },
            }
        }
        AdminRequest::SecretExists { key } => {
            if !is_valid_secret_key(&key) {
                return AdminResponse::Error {
                    message: format!("invalid secret key: '{}'", key),
                };
            }
            let principal = match caller.principal() {
                Some(principal) if caller.is_local_peer() => principal,
                _ => {
                    return AdminResponse::Error {
                        message: "secret ops require an authenticated local caller".to_string(),
                    };
                }
            };
            match config.secrets.get(&principal, &key).await {
                Ok(value) => AdminResponse::SecretExists {
                    exists: value.is_some(),
                },
                Err(e) => AdminResponse::Error {
                    message: format!("failed to inspect secret '{}': {}", key, e),
                },
            }
        }
        AdminRequest::SecretList => {
            let principal = match caller.principal() {
                Some(principal) if caller.is_local_peer() => principal,
                _ => {
                    return AdminResponse::Error {
                        message: "secret ops require an authenticated local caller".to_string(),
                    };
                }
            };
            if config.daemon_principal.eq_ci(&principal) {
                match config.secrets.list_all().await {
                    Ok(pairs) => {
                        let mut keys: Vec<String> = pairs.into_iter().map(|(_, key)| key).collect();
                        keys.sort();
                        AdminResponse::SecretList { keys }
                    }
                    Err(e) => AdminResponse::Error {
                        message: format!("failed to list secrets: {}", e),
                    },
                }
            } else {
                match config.secrets.list(&principal).await {
                    Ok(keys) => AdminResponse::SecretList { keys },
                    Err(e) => AdminResponse::Error {
                        message: format!("failed to list secrets: {}", e),
                    },
                }
            }
        }
        AdminRequest::SecretListDetailed => match config.secrets.list_all().await {
            Ok(pairs) => {
                let legacy = legacy_sentinel();
                let mut items: Vec<SecretDetail> = pairs
                    .into_iter()
                    .map(|(principal, key)| {
                        let is_legacy = principal.eq_ci(&legacy);
                        SecretDetail {
                            key,
                            // The display uid field is populated only for a pure
                            // uid principal; SID and legacy entries carry no uid.
                            uid: if is_legacy {
                                None
                            } else {
                                principal.as_str().parse::<u32>().ok()
                            },
                            principal: if is_legacy {
                                None
                            } else {
                                Some(principal.into_string())
                            },
                            legacy: is_legacy,
                        }
                    })
                    .collect();
                items.sort_by(|a, b| {
                    a.legacy
                        .cmp(&b.legacy)
                        .then_with(|| a.principal.cmp(&b.principal))
                        .then_with(|| a.key.cmp(&b.key))
                });
                AdminResponse::SecretListDetailed { items }
            }
            Err(e) => AdminResponse::Error {
                message: format!("failed to list secrets: {}", e),
            },
        },
        AdminRequest::Ping => {
            let now = now_unix();
            let mode = config
                .evaluator
                .mode()
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| "readonly".to_string());
            AdminResponse::Ping {
                version: env!("CARGO_PKG_VERSION").to_string(),
                uptime_secs: now.saturating_sub(config.started_at_unix),
                mode,
                dry_run: config.dry_run,
            }
        }
        AdminRequest::Status => {
            let now = now_unix();
            let session_count = config.sessions.read().await.list().len();
            let cache_size = config.evaluator.cache_size().await;
            let learned_rule_count = config.evaluator.learned_rule_count().await;
            let deny_shape_count = config.evaluator.deny_shape_count().await;
            let allow_promotion_observation_count =
                config.evaluator.allow_promotion_observation_count().await;
            let mode = config
                .evaluator
                .mode()
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| "readonly".to_string());

            AdminResponse::Status {
                status: ServerStatus {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    started_at_unix: config.started_at_unix,
                    uptime_secs: now.saturating_sub(config.started_at_unix),
                    socket_path: config.socket_path.as_ref().map(|p| p.display().to_string()),
                    tcp_port: config.tcp_port,
                    mode,
                    llm_enabled: config.evaluator.llm_enabled(),
                    llm_model_chain: config.evaluator.llm_model_chain(),
                    static_policy: config.evaluator.has_static_policy(),
                    preflight: config.preflight,
                    redact: config.redact,
                    dry_run: config.dry_run,
                    cache_enabled: config.evaluator.cache_enabled(),
                    cache_size,
                    learning_enabled: config.evaluator.learning_enabled(),
                    learned_rule_count,
                    deny_learning_enabled: config.evaluator.deny_learning_enabled(),
                    deny_shape_count,
                    allow_promotion_enabled: config.evaluator.allow_promotion_enabled(),
                    allow_promotion_observation_count,
                    session_count,
                    daemon_uid: config.daemon_uid,
                    exec_identity: if config.exec_as_caller {
                        "caller".to_string()
                    } else {
                        "daemon".to_string()
                    },
                    state_db_path: config
                        .state_db_path
                        .as_ref()
                        .map(|path| path.display().to_string()),
                    secret_backend: config.secrets.backend_name().to_string(),
                    gate: config.gate.as_str().to_string(),
                    pending_provisionals: config.provisional.read().await.outstanding(),
                    pending_approvals: config.approvals.read().await.outstanding(),
                },
            }
        }
        AdminRequest::Confirm { handle } => handle_confirm(config, caller, &handle).await,
        AdminRequest::Revert { handle } => handle_manual_revert(config, caller, &handle).await,
        AdminRequest::Approve { handle } => handle_approve(config, caller, &handle).await,
        AdminRequest::Deny { handle } => handle_deny(config, caller, &handle).await,
        AdminRequest::Provisionals => {
            let (is_daemon, caller_key) = caller_scope(config, caller);
            let items = config
                .provisional
                .read()
                .await
                .list()
                .iter()
                .filter(|p| is_daemon || scope_eq(&p.principal, &caller_key))
                .map(ProvisionalSummary::from_row)
                .collect();
            AdminResponse::Provisionals { items }
        }
        AdminRequest::ApprovalList => {
            let (is_daemon, caller_key) = caller_scope(config, caller);
            let items = config
                .approvals
                .read()
                .await
                .list()
                .iter()
                .filter(|a| is_daemon || scope_eq(&a.snapshot.principal, &caller_key))
                .map(ApprovalSummary::from_row)
                .collect();
            AdminResponse::Approvals { items }
        }
        AdminRequest::ApprovalShow { handle } => {
            let (is_daemon, caller_key) = caller_scope(config, caller);
            let found = config.approvals.read().await.get(&handle).cloned();
            match found {
                // Handle is an unguessable bearer secret; the owner (or daemon)
                // may read its status and result. Others get NotFound, not a
                // leak of existence.
                Some(a) if is_daemon || scope_eq(&a.snapshot.principal, &caller_key) => {
                    AdminResponse::ApprovalShow {
                        item: ApprovalSummary::from_row(&a),
                    }
                }
                _ => AdminResponse::Error {
                    message: format!("no approval with handle '{}'", handle),
                },
            }
        }
        AdminRequest::ApprovalNote { handle, text } => {
            handle_approval_note(config, caller, &handle, &text).await
        }
        AdminRequest::VerbList => {
            let items = {
                let mut cat = config.verbs.write().await;
                if let Err(e) = cat.reload_if_stale() {
                    tracing::warn!("verb catalog reload failed: {}", e);
                }
                let current_stamp = config.evaluator.verb_promotion_stamp();
                cat.list()
                    .iter()
                    .map(|v| VerbSummary {
                        name: v.name.clone(),
                        description: v.description.clone(),
                        binary: v.binary.clone(),
                        consequence: v.consequence.as_str().to_string(),
                        trusted: verb_effective_trust(v, current_stamp),
                        has_revert: v.revert.is_some(),
                        params: v
                            .params
                            .iter()
                            .map(|(k, spec)| (k.clone(), spec.pattern.clone()))
                            .collect(),
                        auto_promoted: v.auto_promoted,
                        evidence: v.evidence.clone(),
                    })
                    .collect()
            };
            AdminResponse::Verbs { items }
        }
        AdminRequest::VerbCreate {
            prose,
            binary_hint,
            preview,
        } => {
            let prose_norm = normalize_ws(&prose);
            if prose_norm.is_empty() {
                return AdminResponse::Error {
                    message: "verb create requires non-empty --prompt prose".to_string(),
                };
            }
            let mut verb = match config
                .evaluator
                .synthesize_verb(&prose, binary_hint.as_deref())
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    return AdminResponse::Error {
                        message: format!("verb synthesis failed: {e}"),
                    }
                }
            };
            // Record provenance verbatim (tidied to one line); the model's
            // evidence is metadata only and never affects rendering.
            verb.source_prose = Some(prose_norm);
            if let Some(ev) = verb.evidence.take() {
                verb.evidence = Some(normalize_ws(&ev));
            }
            // The model chose this shape, so do not trust its safety-critical
            // fields: a synthesized verb is never `trusted` (the LLM still
            // evaluates the rendered command at run time), and the shape must
            // pass the synthesis safety gate (no shell/interpreter binary, no
            // over-broad parameter pattern, kebab-case name).
            verb.trusted = false;
            if let Err(e) = guard::gating::verb::validate_synthesized_safety(&verb) {
                return AdminResponse::Error {
                    message: format!("synthesized verb rejected by the safety gate: {e}"),
                };
            }
            let mut cat = config.verbs.write().await;
            let result = if preview {
                cat.validate_candidate(&verb)
            } else {
                cat.append_verb(&verb)
            };
            match result {
                Ok(()) => {
                    if !preview {
                        tracing::info!(
                            "[AUDIT] VERB_CREATED name={} consequence={} trusted={}",
                            verb.name,
                            verb.consequence.as_str(),
                            verb.trusted
                        );
                    }
                    AdminResponse::VerbCreated {
                        verb,
                        persisted: !preview,
                    }
                }
                Err(e) => AdminResponse::Error {
                    message: format!("synthesized verb rejected by validation: {e}"),
                },
            }
        }
    }
}

/// Collapse runs of whitespace (incl. newlines) to single spaces, so prose and
/// evidence persist as a tidy single line in the YAML catalog.
fn normalize_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Returns `(is_daemon, caller_principal)` for read-scoping. A caller is the
/// daemon (operator) when its principal equals the daemon's; row visibility is
/// then either daemon-wide or scoped to the caller's own principal via
/// `scope_eq` (so two unauthenticated `None` callers never share rows).
fn caller_scope(config: &ServerConfig, caller: &CallerIdentity) -> (bool, Option<PrincipalKey>) {
    let p = caller.principal();
    (
        matches!(p, Some(ref k) if config.daemon_principal.eq_ci(k)),
        p,
    )
}

async fn handle_confirm(
    config: &ServerConfig,
    caller: &CallerIdentity,
    handle: &str,
) -> AdminResponse {
    let updated = {
        let mut reg = config.provisional.write().await;
        reg.confirm(handle)
    };
    match updated {
        Ok(p) => {
            persist_provisional(config, &p).await;
            forget_proxy_provenance(config, handle).await;
            tracing::info!("[AUDIT] CONFIRM handle={} caller={}", handle, caller);
            AdminResponse::GateAction {
                message: format!("provisional {} confirmed; change kept", handle),
                exit_code: None,
                stdout: None,
                stderr: None,
            }
        }
        Err(e) => AdminResponse::Error {
            message: e.to_string(),
        },
    }
}

async fn handle_manual_revert(
    config: &ServerConfig,
    caller: &CallerIdentity,
    handle: &str,
) -> AdminResponse {
    let claimed = {
        let mut reg = config.provisional.write().await;
        reg.begin_revert(handle)
    };
    let p = match claimed {
        Ok(p) => p,
        Err(e) => {
            return AdminResponse::Error {
                message: e.to_string(),
            }
        }
    };
    persist_provisional(config, &p).await;
    let outcome = finish_revert(config, &p, caller, "manual").await;
    AdminResponse::GateAction {
        message: outcome.0,
        exit_code: outcome.1,
        stdout: None,
        stderr: None,
    }
}

async fn handle_approve(
    config: &ServerConfig,
    caller: &CallerIdentity,
    handle: &str,
) -> AdminResponse {
    let snapshot = {
        let mut reg = config.approvals.write().await;
        reg.begin_approve(handle)
    };
    let snapshot = match snapshot {
        Ok(s) => s,
        Err(e) => {
            return AdminResponse::Error {
                message: e.to_string(),
            }
        }
    };
    // An API-proxy hold carries no executable snapshot: approving it releases
    // the API request parked in the proxy (the proxy waiter forwards it), it
    // never spawns a process. A caller cannot steer a real command into this
    // branch by naming the sentinel binary, because the row must also be owned
    // by the daemon principal, which peer credentials assign only to the
    // daemon's own gate sink.
    if snapshot.binary == API_PROXY_SENTINEL_BINARY
        && matches!(&snapshot.principal, Some(p) if config.daemon_principal.eq_ci(p))
    {
        let now = now_unix();
        {
            let mut reg = config.approvals.write().await;
            reg.set_result(handle, now, None, None, None);
        }
        if let Some(a) = config.approvals.read().await.get(handle).cloned() {
            persist_approval(config, &a).await;
        }
        tracing::info!(
            "[AUDIT] APPROVED handle={} caller={} (api-proxy request released)",
            handle,
            caller
        );
        return AdminResponse::GateAction {
            message: format!("approved held API request {handle}; the proxy is forwarding it"),
            exit_code: None,
            stdout: None,
            stderr: None,
        };
    }
    // Gate-on-prediction: if this hold came from a verb and the catalog changed
    // since it was held, the approved artifact may no longer mean what the
    // operator reviewed. Void the approval rather than execute a stale rendering.
    if let Some(vname) = &snapshot.verb_name {
        let current = config.verbs.read().await.version();
        if snapshot.catalog_version != Some(current) {
            let now = now_unix();
            let detail = format!(
                "verb catalog changed since '{}' was held; approval voided (re-issue the command)",
                vname
            );
            {
                let mut reg = config.approvals.write().await;
                reg.set_exec_failed(handle, now, detail.clone());
            }
            if let Some(a) = config.approvals.read().await.get(handle).cloned() {
                persist_approval(config, &a).await;
            }
            tracing::warn!(
                "[AUDIT] APPROVE_VOIDED handle={} caller={} {}",
                handle,
                caller,
                detail
            );
            return AdminResponse::Error { message: detail };
        }
    }
    // Persist the Approving transition before exec so an interrupted exec is
    // recoverable (startup recovery routes Approving -> ExecFailed).
    if let Some(a) = config.approvals.read().await.get(handle).cloned() {
        persist_approval(config, &a).await;
    }
    let reason = format!("operator-approved held command {}", handle);
    let result = execute_snapshot(config, &snapshot, &reason).await;
    let now = now_unix();
    let (message, exit, stdout, stderr) = match result.exec {
        ExecOutcome::Completed {
            exit_code,
            stdout,
            stderr,
        } => {
            {
                let mut reg = config.approvals.write().await;
                reg.set_result(handle, now, exit_code, stdout.clone(), stderr.clone());
            }
            tracing::info!(
                "[AUDIT] APPROVED handle={} caller={} exit={:?}",
                handle,
                caller,
                exit_code
            );
            (
                format!("approved and executed {} (exit {:?})", handle, exit_code),
                exit_code,
                stdout,
                stderr,
            )
        }
        ExecOutcome::Failed { reason: detail, .. } => {
            {
                let mut reg = config.approvals.write().await;
                reg.set_exec_failed(handle, now, detail.clone());
            }
            tracing::error!(
                "[AUDIT] APPROVE_EXEC_FAILED handle={} caller={} detail={}",
                handle,
                caller,
                detail
            );
            (
                format!("approved {} but execution failed: {}", handle, detail),
                None,
                None,
                None,
            )
        }
        _ => (
            format!("approved {} (unexpected outcome)", handle),
            None,
            None,
            None,
        ),
    };
    if let Some(a) = config.approvals.read().await.get(handle).cloned() {
        persist_approval(config, &a).await;
    }
    AdminResponse::GateAction {
        message,
        exit_code: exit,
        stdout,
        stderr,
    }
}

/// Append a note to a held command's discussion thread, turning the gate into a
/// short operator<->requester conversation before a decision. The operator may
/// note any hold; the hold's original requester (a local peer whose principal
/// matches the snapshot) may note its own; nobody else. Returns the updated hold
/// view (including the thread) so the caller can render it.
pub(super) async fn handle_approval_note(
    config: &ServerConfig,
    caller: &CallerIdentity,
    handle: &str,
    text: &str,
) -> AdminResponse {
    let text = text.trim();
    if text.is_empty() {
        return AdminResponse::Error {
            message: "note text must not be empty".to_string(),
        };
    }
    let (is_operator, caller_key) = caller_scope(config, caller);
    let author = {
        let reg = config.approvals.read().await;
        match reg.get(handle) {
            Some(_) if is_operator => "operator",
            Some(a) if caller.is_local_peer() && scope_eq(&a.snapshot.principal, &caller_key) => {
                "requester"
            }
            // Unknown handle, or a caller who is neither operator nor owner:
            // return NotFound, never leaking the hold's existence.
            _ => {
                return AdminResponse::Error {
                    message: format!("no approval with handle '{}'", handle),
                };
            }
        }
    };
    let now = now_unix();
    let result = {
        let mut reg = config.approvals.write().await;
        reg.add_note(handle, author, text, now)
    };
    match result {
        Ok(()) => {
            let updated = config.approvals.read().await.get(handle).cloned();
            match updated {
                Some(a) => {
                    persist_approval(config, &a).await;
                    tracing::info!(
                        "[AUDIT] APPROVAL_NOTE handle={} author={} caller={}",
                        handle,
                        author,
                        caller
                    );
                    AdminResponse::ApprovalShow {
                        item: ApprovalSummary::from_row(&a),
                    }
                }
                None => AdminResponse::Error {
                    message: format!("no approval with handle '{}'", handle),
                },
            }
        }
        Err(e) => AdminResponse::Error {
            message: e.to_string(),
        },
    }
}

async fn handle_deny(
    config: &ServerConfig,
    caller: &CallerIdentity,
    handle: &str,
) -> AdminResponse {
    let now = now_unix();
    let result = {
        let mut reg = config.approvals.write().await;
        reg.deny(handle, now, "operator denied".to_string())
    };
    match result {
        Ok(()) => {
            if let Some(a) = config.approvals.read().await.get(handle).cloned() {
                persist_approval(config, &a).await;
            }
            tracing::info!("[AUDIT] DENIED_HOLD handle={} caller={}", handle, caller);
            AdminResponse::GateAction {
                message: format!("held command {} denied", handle),
                exit_code: None,
                stdout: None,
                stderr: None,
            }
        }
        Err(e) => AdminResponse::Error {
            message: e.to_string(),
        },
    }
}
