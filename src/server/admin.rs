use crate::grant_profile::{EvaluationMode, GrantRequest, GrantRequestStatus};
use crate::redact::redact_output;
use crate::secrets::legacy_sentinel;
use crate::session::{
    HistoricalGrant, IssuedGrantScope, SessionAmendment, SessionDecision, SessionDecisionSource,
    SessionExecStatus, SessionGrant, SessionGrantSummary, SessionInteraction, SessionReport,
};
use guard::gating::verb::{
    CoverageAction, CoverageProbe, CoverageProvenance, Verb, VerbCoverageCell,
};
use guard::principal::{scope_eq, PrincipalKey};

use super::execute::{
    allow_session_auto_amend_candidate, amend_session_exact_rule, audit_session_fingerprint,
    command_line, deny_session_auto_amend_candidate, persist_current_sessions,
    persist_session_snapshot, record_live_session_interaction, session_source_from_eval,
    validate_session_exact_rule_candidate,
};
use super::gate_runtime::{
    execute_snapshot, finish_revert, forget_proxy_provenance, is_api_proxy_sentinel, now_unix,
    persist_approval, persist_provisional, remove_revert_body,
};
use super::runtime::NotifyEvent;
use super::wire::{
    verb_effective_trust, AdminRequest, AdminResponse, ApprovalSummary, CallerIdentity,
    ExecOutcome, ProvisionalSummary, SecretDetail, ServerStatus, VerbSummary,
};
use super::{is_valid_secret_key, ServerConfig};

pub(super) const MAX_GRANT_REQUESTS: usize = 1024;
pub(super) const MAX_PENDING_GRANT_REQUESTS_PER_SESSION: usize = 32;
pub(super) const MAX_GRANT_REQUEST_PAYLOAD_BYTES: usize = 64 * 1024;

#[derive(serde::Serialize, serde::Deserialize)]
struct RegenerationProposal {
    name: String,
    source_revision: u64,
    regime: String,
    prompt: String,
    candidate: Verb,
}

#[cfg(test)]
mod regeneration_proposal_tests {
    use super::*;
    use std::collections::BTreeMap;

    fn candidate() -> Verb {
        Verb {
            name: "generated:test".to_string(),
            description: "test".to_string(),
            binary: "echo".to_string(),
            args: vec!["ok".to_string()],
            baseline: false,
            coverage: Vec::new(),
            credential_plan: None,
            params: BTreeMap::new(),
            consequence: guard::gating::Reversibility::Reversible,
            revert: None,
            trusted: false,
            prompt_context: None,
            source_prose: Some("test".to_string()),
            evidence: None,
            auto_promoted: false,
            promotion_stamp: Some("regime-a".to_string()),
        }
    }

    fn proposal() -> RegenerationProposal {
        RegenerationProposal {
            name: "saved".to_string(),
            source_revision: 7,
            regime: "regime-a".to_string(),
            prompt: "bounded".to_string(),
            candidate: candidate(),
        }
    }

    #[test]
    fn proposal_round_trip_preserves_exact_candidate_and_bindings() {
        let proposal = proposal();
        let id = encode_regeneration_proposal(&proposal).unwrap();
        let decoded = decode_regeneration_proposal(&id).unwrap();
        assert_eq!(decoded.name, "saved");
        assert_eq!(decoded.source_revision, 7);
        assert_eq!(decoded.regime, "regime-a");
        assert_eq!(
            serde_json::to_value(decoded.candidate).unwrap(),
            serde_json::to_value(proposal.candidate).unwrap()
        );
    }

    #[test]
    fn proposal_tampering_fails_integrity_check() {
        let mut id = encode_regeneration_proposal(&proposal()).unwrap();
        let last = id.pop().unwrap();
        id.push(if last == '0' { '1' } else { '0' });
        assert!(decode_regeneration_proposal(&id).is_err());
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("invalid regeneration proposal".to_string());
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| "invalid regeneration proposal".to_string())
        })
        .collect()
}

fn encode_regeneration_proposal(proposal: &RegenerationProposal) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(proposal).map_err(|error| error.to_string())?;
    let digest = encode_hex(&Sha256::digest(&bytes));
    Ok(format!("rg1-{digest}-{}", encode_hex(&bytes)))
}

fn decode_regeneration_proposal(value: &str) -> Result<RegenerationProposal, String> {
    use sha2::{Digest, Sha256};
    let rest = value
        .strip_prefix("rg1-")
        .ok_or_else(|| "invalid regeneration proposal version".to_string())?;
    let (expected, payload) = rest
        .split_once('-')
        .ok_or_else(|| "invalid regeneration proposal".to_string())?;
    let bytes = decode_hex(payload)?;
    if encode_hex(&Sha256::digest(&bytes)) != expected {
        return Err("regeneration proposal integrity check failed".to_string());
    }
    serde_json::from_slice(&bytes).map_err(|_| "invalid regeneration proposal".to_string())
}

pub(super) fn grant_request_payload_bytes(request: &GrantRequest) -> usize {
    request.justification.len()
        + request
            .delta
            .activated_verbs
            .iter()
            .map(String::len)
            .sum::<usize>()
        + request
            .delta
            .override_markers
            .iter()
            .map(String::len)
            .sum::<usize>()
        + request
            .delta
            .secret_names
            .iter()
            .map(String::len)
            .sum::<usize>()
        + request.delta.prompt_append.as_deref().map_or(0, str::len)
}

fn merge_unique(target: &mut Vec<String>, additions: Vec<String>) {
    for value in additions {
        if !target.iter().any(|existing| existing == &value) {
            target.push(value);
        }
    }
}

fn combine_session_prompt(prompt_append: Option<String>, prose: Option<&str>) -> Option<String> {
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

fn stamp_generated_verb(
    mut verb: Verb,
    grant_name: &str,
    prompt: &str,
    stamp: &str,
    sticky: Vec<VerbCoverageCell>,
) -> Verb {
    verb.name = format!(
        "grant-{grant_name}-{}",
        verb.name.trim_start_matches("grant-")
    );
    verb.baseline = false;
    verb.trusted = false;
    verb.source_prose = Some(normalize_ws(prompt));
    let evidence = verb
        .evidence
        .clone()
        .unwrap_or_else(|| normalize_ws(prompt));
    let fixed_args = verb
        .args
        .iter()
        .filter(|arg| !(arg.starts_with('{') && arg.ends_with('}')))
        .cloned()
        .collect::<Vec<_>>();
    let provenance = CoverageProvenance {
        source: "saved_grant_evaluator".to_string(),
        evidence: vec![evidence],
        regime_stamp: stamp.to_string(),
        prompt_stamp: stamp.to_string(),
        model_stamp: stamp.to_string(),
        generated_unix: now_unix(),
        probes: vec![
            CoverageProbe {
                dimension: "generated_example".to_string(),
                args: verb.args.clone(),
                expected_match: true,
                observed_match: true,
            },
            CoverageProbe {
                dimension: "outside_generated_boundary".to_string(),
                args: vec!["--guard-outside-coverage".to_string()],
                expected_match: false,
                observed_match: false,
            },
        ],
    };
    verb.coverage = vec![VerbCoverageCell {
        name: "generated".to_string(),
        action: CoverageAction::Evaluate,
        required_args: fixed_args,
        forbidden_args: Vec::new(),
        min_args: None,
        max_args: None,
        options: Vec::new(),
        target: None,
        inventory: None,
        namespace: None,
        fanout: None,
        environment: Vec::new(),
        override_marker: None,
        sticky: false,
        provenance: Some(provenance),
    }];
    verb.coverage.extend(sticky);
    verb
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
        grant.activated_verbs.clear();
        grant.override_markers.clear();
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
        grant.activated_verbs.clear();
        grant.override_markers.clear();
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
            // Appeals are command-shape requests and do not carry authenticated
            // caller cwd authority. Cwd-bound grants are checked on ExecuteRequest.
            reg.check(&token, &binary, &args, None),
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
                reason: format!("already allowed by session coverage: {reason}"),
                risk: None,
            },
            SessionDecision::Deny => AdminResponse::SessionAppeal {
                allowed: false,
                amended: false,
                pattern: Some(command_line),
                reason: format!("already denied by session coverage: {reason}"),
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
                        exit_code: None,
                        exposed_secret_refs: Vec::new(),
                        decision_trace: Some(guard::gating::DecisionTrace::source(
                            format!("{source:?}").to_ascii_lowercase(),
                        )),
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
                None,
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
                    exit_code: None,
                    exposed_secret_refs: Vec::new(),
                    decision_trace: Some(guard::gating::DecisionTrace::source(
                        format!("{source:?}").to_ascii_lowercase(),
                    )),
                },
            )
            .await;
            tracing::info!(target: "guard::audit",
                "[AUDIT] SESSION_APPEAL caller={} token_fingerprint={} allowed=true amended={} cmd={}",
                caller,
                audit_session_fingerprint(Some(&token)),
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
                    None,
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
                    exit_code: None,
                    exposed_secret_refs: Vec::new(),
                    decision_trace: Some(guard::gating::DecisionTrace::source(
                        format!("{source:?}").to_ascii_lowercase(),
                    )),
                },
            )
            .await;
            tracing::info!(target: "guard::audit",
                "[AUDIT] SESSION_APPEAL caller={} token_fingerprint={} allowed=false amended={} cmd={}",
                caller,
                audit_session_fingerprint(Some(&token)),
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
            tracing::warn!(target: "guard::audit", "[AUDIT] ADMIN_REJECTED caller={} reason=\"{}\"", caller, e);
            return AdminResponse::Error {
                message: e.to_string(),
            };
        }
    }

    match request {
        AdminRequest::SessionGrant {
            token,
            allow,
            deny,
            mut activated_verbs,
            mut override_markers,
            mut ttl_secs,
            prompt_append,
            prose,
            saved_grant,
            profile,
            evaluation_mode,
            static_only,
            auto_amend,
        } => {
            if token.is_empty() {
                return AdminResponse::Error {
                    message: "session token must not be empty".to_string(),
                };
            }
            // Expand a saved grant before normal validation and installation.
            // Unknown names fail instead of minting an empty session.
            let mut saved_scope = IssuedGrantScope::default();
            let saved_grant = match (saved_grant, profile) {
                (Some(canonical), Some(legacy)) if canonical != legacy => {
                    return AdminResponse::Error {
                        message: "conflicting saved grant names were supplied".to_string(),
                    };
                }
                (Some(canonical), _) => Some(canonical),
                (None, legacy) => legacy,
            };
            let mut saved_prompt: Option<String> = None;
            if let Some(name) = saved_grant.as_deref() {
                let selected = config.saved_grants.read().await.get(name).cloned();
                match selected {
                    Some(p) => {
                        let generated = p.generated_verb_names();
                        merge_unique(&mut activated_verbs, p.all_activated_verbs());
                        merge_unique(&mut override_markers, p.override_markers.clone());
                        ttl_secs = ttl_secs.or(p.ttl_secs);
                        saved_prompt = p.prompt_append.clone();
                        saved_scope = IssuedGrantScope {
                            label: p.label.clone(),
                            saved_grant: Some(p.name.clone()),
                            saved_revision: p.revision,
                            secret_names: p.secret_names.clone(),
                            evaluation_mode: p.evaluation_mode,
                        };
                        let mut catalog = config.verbs.write().await;
                        for verb in &p.generated_verbs {
                            if let Err(error) = catalog.upsert_saved_grant_verb(verb.clone()) {
                                return AdminResponse::Error {
                                    message: format!(
                                        "saved grant '{}' has invalid generated coverage: {}",
                                        name, error
                                    ),
                                };
                            }
                        }
                        debug_assert!(generated.iter().all(|name| activated_verbs.contains(name)));
                    }
                    None => {
                        return AdminResponse::Error {
                            message: format!("unknown saved grant: '{}'", name),
                        };
                    }
                }
            }
            if !activated_verbs.is_empty() || !override_markers.is_empty() {
                let mut catalog = config.verbs.write().await;
                if let Err(error) = catalog.reload_if_stale() {
                    tracing::warn!("verb catalog reload failed, using previous: {}", error);
                }
                for name in &activated_verbs {
                    let Some(verb) = catalog.get(name) else {
                        return AdminResponse::Error {
                            message: format!("unknown session verb: '{}'", name),
                        };
                    };
                    if verb.baseline {
                        return AdminResponse::Error {
                            message: format!(
                                "session verb '{}' is already baseline; only baseline: false verbs can be activated",
                                name
                            ),
                        };
                    }
                }
                let declared_markers = catalog
                    .list()
                    .into_iter()
                    .filter(|verb| verb.baseline)
                    .flat_map(|verb| verb.coverage)
                    .filter(|cell| {
                        matches!(cell.action, CoverageAction::Evaluate | CoverageAction::Deny)
                    })
                    .filter_map(|cell| cell.override_marker)
                    .collect::<std::collections::BTreeSet<_>>();
                for marker in &override_markers {
                    if !declared_markers.contains(marker) {
                        return AdminResponse::Error {
                            message: format!(
                                "unknown verb override marker: '{}'; the marker must be declared by a baseline evaluate or deny coverage cell",
                                marker
                            ),
                        };
                    }
                }
            }
            // Prose is evaluator context. It never creates static complement
            // denies or broad allow patterns. Legacy explicit --allow/--deny
            // inputs remain accepted only for compatibility.
            // Fold saved evaluator context in with compatibility request prose.
            let base_prompt = match (prompt_append, saved_prompt) {
                (Some(request), Some(saved)) => Some(format!("{request}\n\n{saved}")),
                (some, None) | (None, some) => some,
            };
            if let Some(mode) = evaluation_mode {
                saved_scope.evaluation_mode = mode;
            }
            let prompt_append = combine_session_prompt(base_prompt, prose.as_deref());
            if static_only {
                saved_scope.evaluation_mode = EvaluationMode::PolicyOnly;
            }
            let auto_amend =
                auto_amend && !matches!(saved_scope.evaluation_mode, EvaluationMode::PolicyOnly);
            let expires_at = ttl_secs.map(|secs| now_unix() + secs);
            let effective_evaluation_mode = saved_scope.evaluation_mode;
            let mut generated_notes = Vec::new();
            if let Some(name) = saved_grant.as_deref() {
                generated_notes.push(format!("issued from saved grant '{name}'"));
            }
            let grant = SessionGrant {
                allow,
                deny,
                allow_exact: Vec::new(),
                deny_exact: Vec::new(),
                activated_verbs,
                override_markers,
                scope: saved_scope,
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
            tracing::info!(target: "guard::audit",
                "[AUDIT] SESSION_GRANT caller={} token_fingerprint={} saved_grant={:?} ttl={:?} evaluation_mode={} auto_amend={}",
                caller,
                audit_session_fingerprint(Some(&token)),
                saved_grant,
                ttl_secs,
                effective_evaluation_mode,
                auto_amend,
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
            tracing::info!(target: "guard::audit",
                "[AUDIT] SESSION_REVOKE caller={} token_fingerprint={} existed={}",
                caller,
                audit_session_fingerprint(Some(&token)),
                removed
            );
            AdminResponse::Ok
        }
        AdminRequest::SessionExtend { token, ttl_secs } => {
            let (before, changed, after) = {
                let mut registry = config.sessions.write().await;
                let before = registry.clone();
                let changed = registry.extend(&token, ttl_secs).is_some();
                (before, changed, registry.clone())
            };
            if !changed {
                return AdminResponse::Error {
                    message: format!("unknown active session: '{token}'"),
                };
            }
            if let Err(error) = persist_session_snapshot(config.session_store.clone(), after).await
            {
                *config.sessions.write().await = before;
                return AdminResponse::Error {
                    message: format!("failed to persist session extension: {error}"),
                };
            }
            AdminResponse::Ok
        }
        AdminRequest::SessionLabel { token, label } => {
            let label = (!label.trim().is_empty()).then(|| label.trim().to_string());
            let (before, changed, after) = {
                let mut registry = config.sessions.write().await;
                let before = registry.clone();
                let changed = registry.set_label(&token, label).is_some();
                (before, changed, registry.clone())
            };
            if !changed {
                return AdminResponse::Error {
                    message: format!("unknown active session: '{token}'"),
                };
            }
            if let Err(error) = persist_session_snapshot(config.session_store.clone(), after).await
            {
                *config.sessions.write().await = before;
                return AdminResponse::Error {
                    message: format!("failed to persist session label: {error}"),
                };
            }
            AdminResponse::Ok
        }
        AdminRequest::SessionRevokeFiltered { label, saved_grant } => {
            if label.is_none() && saved_grant.is_none() {
                return AdminResponse::Error {
                    message: "bulk revoke requires --label or --saved-grant".to_string(),
                };
            }
            let (before, count, after) = {
                let mut registry = config.sessions.write().await;
                let before = registry.clone();
                let count = registry.revoke_filtered(label.as_deref(), saved_grant.as_deref());
                (before, count, registry.clone())
            };
            if let Err(error) = persist_session_snapshot(config.session_store.clone(), after).await
            {
                *config.sessions.write().await = before;
                return AdminResponse::Error {
                    message: format!("failed to persist bulk revoke: {error}"),
                };
            }
            AdminResponse::SessionBulkRevoked { count }
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
                tracing::warn!(target: "guard::audit",
                    "[AUDIT] SESSION_SHOW_REJECTED caller={} reason=\"not the token holder\"",
                    caller
                );
                return AdminResponse::Error {
                    message: "not authorized: a session token may only inspect its own grant"
                        .to_string(),
                };
            }
            let reg = config.sessions.read().await;
            match reg.show_with_limits(&token, limit.unwrap_or(20), &config.behavior_limits) {
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
        AdminRequest::SessionStatus {
            token,
            caller_token,
        } => {
            let is_admin = caller_is_session_admin(config, caller);
            let is_self = !token.is_empty() && caller_token.as_deref() == Some(token.as_str());
            if !is_admin && !is_self {
                return AdminResponse::Error {
                    message: "not authorized: a session token may only inspect its own status"
                        .to_string(),
                };
            }
            let Some(mut report) =
                config
                    .sessions
                    .read()
                    .await
                    .show_with_limits(&token, 20, &config.behavior_limits)
            else {
                return AdminResponse::Error {
                    message: format!("unknown session token: '{token}'"),
                };
            };
            if !is_admin {
                mask_session_report_token(&mut report);
            }
            let fingerprint = audit_session_fingerprint(Some(&token));
            let approvals = config
                .approvals
                .read()
                .await
                .list()
                .iter()
                .filter(|approval| {
                    approval.snapshot.session_fingerprint.as_deref() == Some(fingerprint.as_str())
                })
                .map(ApprovalSummary::from_row)
                .collect();
            let provisionals = config
                .provisional
                .read()
                .await
                .list()
                .iter()
                .filter(|provisional| {
                    provisional.session_fingerprint.as_deref() == Some(fingerprint.as_str())
                })
                .map(ProvisionalSummary::from_row)
                .collect();
            let requests = config
                .grant_requests
                .read()
                .await
                .values()
                .filter(|request| request.session_token == token)
                .cloned()
                .map(redact_grant_request)
                .collect();
            AdminResponse::SessionStatus {
                report,
                approvals,
                provisionals,
                requests,
            }
        }
        AdminRequest::KubeconfigIssue {
            endpoint,
            session_token,
        } => {
            let Some(principal) = caller.principal().filter(|_| caller.is_local_peer()) else {
                return AdminResponse::Error {
                    message: "brokered kubeconfig issuance requires an authenticated local caller"
                        .to_string(),
                };
            };
            let expires_at = {
                let sessions = config.sessions.read().await;
                if let Some(reason) =
                    sessions.suspension_reason(&session_token, &config.behavior_limits)
                {
                    return AdminResponse::Error { message: reason };
                }
                match sessions.expires_at_for(&session_token) {
                    Some(Some(expires_at)) if expires_at > now_unix() => expires_at,
                    Some(None) => return AdminResponse::Error {
                        message:
                            "brokered kubeconfig issuance requires a session with a finite expiry"
                                .to_string(),
                    },
                    _ => {
                        return AdminResponse::Error {
                            message: "unknown, expired, or revoked session".to_string(),
                        }
                    }
                }
            };
            let proxy = config
                .protocol_registry
                .read()
                .await
                .get(&endpoint)
                .cloned();
            let Some(proxy) = proxy else {
                return AdminResponse::Error {
                    message: format!("unknown API endpoint: '{endpoint}'"),
                };
            };
            if proxy.protocol_name() != "kubernetes" {
                return AdminResponse::Error {
                    message: format!("API endpoint '{endpoint}' is not Kubernetes"),
                };
            }
            let yaml = proxy.brokered_kubeconfig_with_session(&session_token);
            if let Err(error) =
                guard::proxy::validate_brokered_kubeconfig_with_session(&yaml, &session_token)
            {
                tracing::error!("failed to validate brokered kubeconfig: {error}");
                return AdminResponse::Error {
                    message: "brokered kubeconfig generation failed closed".to_string(),
                };
            }
            tracing::info!(target: "guard::audit",
                "[AUDIT] KUBECONFIG_ISSUED caller={} principal={} endpoint={} session_fingerprint={} expires_at={}",
                caller,
                principal,
                endpoint,
                audit_session_fingerprint(Some(&session_token)),
                expires_at
            );
            AdminResponse::KubeconfigIssued { yaml, expires_at }
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
                    tracing::info!(target: "guard::audit",
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
                    tracing::info!(target: "guard::audit",
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
            let (verb_catalog_hash, verb_catalog_changed_unix) = {
                let mut catalog = config.verbs.write().await;
                if let Err(error) = catalog.reload_if_stale() {
                    tracing::warn!("verb catalog reload failed during status: {}", error);
                }
                (catalog.short_hash(), catalog.changed_unix())
            };

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
                    verb_catalog_hash,
                    verb_catalog_changed_unix,
                    command_admission: config.command_admission.snapshot(),
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
                        baseline: v.baseline,
                        coverage: v.coverage.clone(),
                        credential_plan: v.credential_plan.clone(),
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
        AdminRequest::VerbShow { name } => {
            let mut catalog = config.verbs.write().await;
            if let Err(error) = catalog.reload_if_stale() {
                tracing::warn!("verb catalog reload failed: {}", error);
            }
            match catalog.get(&name).cloned() {
                Some(verb) => AdminResponse::VerbCreated {
                    verb,
                    persisted: true,
                },
                None => AdminResponse::Error {
                    message: format!("unknown verb: '{name}'"),
                },
            }
        }
        AdminRequest::VerbDelete { name } => match config.verbs.write().await.delete_verb(&name) {
            Ok(_) => AdminResponse::Ok,
            Err(error) => AdminResponse::Error {
                message: error.to_string(),
            },
        },
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
                        tracing::info!(target: "guard::audit",
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
        AdminRequest::VerbCoverageList => {
            let items = match &config.api_coverage {
                Some(store) => store.read().await.coverage(),
                None => Vec::new(),
            };
            AdminResponse::VerbCoverage { items }
        }
        AdminRequest::VerbCoverageClear => {
            let Some(store) = &config.api_coverage else {
                return AdminResponse::VerbCoverageCleared { removed: 0 };
            };
            match store.write().await.clear_generated() {
                Ok(removed) => {
                    tracing::info!(target: "guard::audit", "[AUDIT] API_VERB_COVERAGE_CLEARED removed={}", removed);
                    AdminResponse::VerbCoverageCleared { removed }
                }
                Err(error) => AdminResponse::Error {
                    message: format!("failed to clear generated API verb coverage: {error}"),
                },
            }
        }
        AdminRequest::SavedGrantList => AdminResponse::SavedGrants {
            items: config.saved_grants.read().await.list(),
        },
        AdminRequest::SavedGrantShow { name } => {
            match config.saved_grants.read().await.get(&name).cloned() {
                Some(grant) => AdminResponse::SavedGrant { grant },
                None => AdminResponse::Error {
                    message: format!("unknown saved grant: '{name}'"),
                },
            }
        }
        AdminRequest::SavedGrantSave { grant } => {
            let before = config.saved_grants.read().await.clone();
            let result = config.saved_grants.write().await.insert(grant);
            match result {
                Ok(grant) => {
                    if let Some(store) = &config.session_store {
                        if let Err(error) = store.save_saved_grant(grant.clone()).await {
                            *config.saved_grants.write().await = before;
                            return AdminResponse::Error {
                                message: format!("failed to persist saved grant: {error}"),
                            };
                        }
                    }
                    AdminResponse::SavedGrant { grant }
                }
                Err(error) => AdminResponse::Error {
                    message: error.to_string(),
                },
            }
        }
        AdminRequest::SavedGrantEdit {
            name,
            description,
            activated_verbs,
            clear_verbs,
            override_markers,
            clear_override_markers,
            secret_names,
            clear_secrets,
            ceiling_verbs,
            clear_ceiling_verbs,
            ceiling_secrets,
            clear_ceiling_secrets,
            ceiling_ttl_secs,
            clear_ceiling_ttl,
            ceiling_modes,
            clear_ceiling_modes,
            allow_prompt_append,
            ttl_secs,
            clear_ttl,
            prompt_append,
            evaluation_mode,
            auto_approve_requests,
        } => {
            let before = config.saved_grants.read().await.clone();
            let result = {
                let mut catalog = config.saved_grants.write().await;
                let Some(mut grant) = catalog.get(&name).cloned() else {
                    return AdminResponse::Error {
                        message: format!("unknown saved grant: '{name}'"),
                    };
                };
                if let Some(description) = description {
                    grant.description = description;
                }
                if clear_verbs {
                    grant.activated_verbs.clear();
                    grant.ceiling.verbs.clear();
                } else if !activated_verbs.is_empty() {
                    grant.activated_verbs = activated_verbs.clone();
                    grant.ceiling.verbs = activated_verbs;
                }
                if clear_override_markers {
                    grant.override_markers.clear();
                } else if !override_markers.is_empty() {
                    grant.override_markers = override_markers;
                }
                if clear_secrets {
                    grant.secret_names.clear();
                    grant.ceiling.secret_names.clear();
                } else if !secret_names.is_empty() {
                    grant.secret_names = secret_names.clone();
                    grant.ceiling.secret_names = secret_names;
                }
                if clear_ceiling_verbs {
                    grant.ceiling.verbs.clear();
                } else if !ceiling_verbs.is_empty() {
                    grant.ceiling.verbs = ceiling_verbs;
                }
                if clear_ceiling_secrets {
                    grant.ceiling.secret_names.clear();
                } else if !ceiling_secrets.is_empty() {
                    grant.ceiling.secret_names = ceiling_secrets;
                }
                if clear_ceiling_ttl {
                    grant.ceiling.max_ttl_secs = None;
                } else if let Some(ttl) = ceiling_ttl_secs {
                    grant.ceiling.max_ttl_secs = Some(ttl);
                }
                if clear_ceiling_modes {
                    grant.ceiling.evaluation_modes.clear();
                } else if !ceiling_modes.is_empty() {
                    grant.ceiling.evaluation_modes = ceiling_modes;
                }
                if let Some(allow) = allow_prompt_append {
                    grant.ceiling.allow_prompt_append = allow;
                }
                if clear_ttl {
                    grant.ttl_secs = None;
                    grant.ceiling.max_ttl_secs = None;
                } else if let Some(ttl_secs) = ttl_secs {
                    grant.ttl_secs = Some(ttl_secs);
                    grant.ceiling.max_ttl_secs = Some(ttl_secs);
                }
                if let Some(prompt_append) = prompt_append {
                    grant.prompt_append =
                        (!prompt_append.trim().is_empty()).then_some(prompt_append);
                }
                if let Some(evaluation_mode) = evaluation_mode {
                    grant.evaluation_mode = evaluation_mode;
                    grant.ceiling.evaluation_modes = vec![evaluation_mode];
                }
                if let Some(auto_approve_requests) = auto_approve_requests {
                    grant.auto_approve_requests = auto_approve_requests;
                }
                catalog.replace(grant)
            };
            match result {
                Ok(grant) => {
                    if let Some(store) = &config.session_store {
                        if let Err(error) = store.save_saved_grant(grant.clone()).await {
                            *config.saved_grants.write().await = before;
                            return AdminResponse::Error {
                                message: format!("failed to persist saved grant: {error}"),
                            };
                        }
                    }
                    AdminResponse::SavedGrant { grant }
                }
                Err(error) => AdminResponse::Error {
                    message: error.to_string(),
                },
            }
        }
        AdminRequest::SavedGrantDelete { name } => {
            let mut staged_grants = config.saved_grants.read().await.clone();
            if staged_grants.remove(&name).is_none() {
                return AdminResponse::Error {
                    message: format!("unknown saved grant: '{name}'"),
                };
            }
            let mut staged_verbs = config.verbs.read().await.clone();
            if let Err(error) = staged_verbs.remove_saved_grant_verbs(&name) {
                return AdminResponse::Error {
                    message: error.to_string(),
                };
            }
            if let Some(store) = &config.session_store {
                if let Err(error) = store.delete_saved_grant(name).await {
                    return AdminResponse::Error {
                        message: format!("failed to delete saved grant: {error}"),
                    };
                }
            }
            *config.saved_grants.write().await = staged_grants;
            *config.verbs.write().await = staged_verbs;
            AdminResponse::Ok
        }
        AdminRequest::SavedGrantRegenerate {
            name,
            prompt,
            proposal_id,
        } => {
            let Some(existing) = config.saved_grants.read().await.get(&name).cloned() else {
                return AdminResponse::Error {
                    message: format!("unknown saved grant: '{name}'"),
                };
            };
            let regime = config.evaluator.verb_promotion_stamp().to_string();
            let (prompt, synthesized, is_apply) = if let Some(proposal_id) = proposal_id {
                let proposal = match decode_regeneration_proposal(&proposal_id) {
                    Ok(proposal) => proposal,
                    Err(message) => return AdminResponse::Error { message },
                };
                if proposal.name != name || proposal.source_revision != existing.revision {
                    return AdminResponse::Error {
                        message: "regeneration proposal is stale: saved grant revision changed"
                            .to_string(),
                    };
                }
                if proposal.regime != regime {
                    return AdminResponse::Error {
                        message: "regeneration proposal is stale: evaluator regime changed"
                            .to_string(),
                    };
                }
                (proposal.prompt, proposal.candidate, true)
            } else {
                let prompt = prompt
                    .or(existing.prompt_append.clone())
                    .filter(|value| !value.trim().is_empty());
                let Some(prompt) = prompt else {
                    return AdminResponse::Error {
                        message: "regeneration requires --prompt or a saved prompt".to_string(),
                    };
                };
                let synthesized = match config.evaluator.synthesize_verb(&prompt, None).await {
                    Ok(verb) => verb,
                    Err(error) => {
                        return AdminResponse::Error {
                            message: format!("saved grant regeneration failed: {error}"),
                        }
                    }
                };
                (prompt, synthesized, false)
            };
            if !sticky_coverage_is_compatible(&existing.generated_verbs, &synthesized) {
                return AdminResponse::Error {
                    message: "regeneration changed the binary or argv template beneath sticky coverage; edit the operator boundary explicitly before regenerating"
                        .to_string(),
                };
            }
            let sticky = existing
                .generated_verbs
                .iter()
                .flat_map(|verb| verb.coverage.iter())
                .filter(|cell| cell.sticky)
                .cloned()
                .collect();
            // Applying a proposal installs the exact candidate the operator
            // previewed. Re-stamping it would change its name, provenance, and
            // generated timestamp after approval.
            let verb = if is_apply {
                synthesized
            } else {
                stamp_generated_verb(synthesized, &name, &prompt, &regime, sticky)
            };
            let mut updated = existing.clone();
            updated.prompt_append = Some(prompt.clone());
            updated.generated_verbs = vec![verb.clone()];
            let staged = stage_saved_grant_regeneration(
                &*config.saved_grants.read().await,
                &*config.verbs.read().await,
                &name,
                updated,
                verb.clone(),
            );
            let (staged_grants, staged_verbs, updated, added, removed, changed) = match staged {
                Ok(staged) => staged,
                Err(message) => return AdminResponse::Error { message },
            };
            if !is_apply {
                let proposal = RegenerationProposal {
                    name: name.clone(),
                    source_revision: existing.revision,
                    regime: regime.clone(),
                    prompt,
                    candidate: verb.clone(),
                };
                let proposal_id = match encode_regeneration_proposal(&proposal) {
                    Ok(id) => id,
                    Err(message) => return AdminResponse::Error { message },
                };
                return AdminResponse::SavedGrantRegenerationProposal {
                    name,
                    source_revision: existing.revision,
                    regime,
                    proposal_id,
                    candidate: verb,
                    added,
                    removed,
                    changed,
                };
            }
            if let Some(store) = &config.session_store {
                if let Err(error) = store.save_saved_grant(updated.clone()).await {
                    return AdminResponse::Error {
                        message: format!("failed to persist regenerated saved grant: {error}"),
                    };
                }
            }
            *config.saved_grants.write().await = staged_grants;
            *config.verbs.write().await = staged_verbs;
            AdminResponse::SavedGrantRegenerated {
                grant: updated,
                added,
                removed,
                changed,
            }
        }
        AdminRequest::GrantRequestSubmit {
            session_token,
            caller_token,
            saved_grant,
            prompt,
            delta,
        } => {
            if !caller_is_session_admin(config, caller)
                && caller_token.as_deref() != Some(session_token.as_str())
            {
                return AdminResponse::Error {
                    message: "not authorized: a session may only request changes to itself"
                        .to_string(),
                };
            }
            prune_grant_requests(config).await;
            let (
                issued_saved_grant,
                issued_saved_revision,
                issued_session_revision,
                session_expires_at,
            ) = {
                let registry = config.sessions.read().await;
                if !registry.has(&session_token) {
                    return AdminResponse::Error {
                        message: format!("unknown active session: '{session_token}'"),
                    };
                }
                if let Some(reason) =
                    registry.suspension_reason(&session_token, &config.behavior_limits)
                {
                    return AdminResponse::Error {
                        message: format!("session is suspended: {reason}"),
                    };
                }
                let issued = registry.saved_grant_for(&session_token);
                (
                    issued.as_ref().map(|(name, _)| name.clone()),
                    issued.as_ref().map(|(_, revision)| *revision),
                    registry.effective_revision_key(&session_token),
                    registry.expires_at_for(&session_token).flatten(),
                )
            };
            if saved_grant.is_some() && saved_grant != issued_saved_grant {
                return AdminResponse::Error {
                    message: "requested saved grant does not match the session's issued grant"
                        .to_string(),
                };
            }
            let mut request = match GrantRequest::new(
                session_token.clone(),
                issued_saved_grant.clone(),
                delta,
                prompt,
            ) {
                Ok(request) => request,
                Err(error) => {
                    return AdminResponse::Error {
                        message: error.to_string(),
                    }
                }
            };
            request.issued_saved_revision = issued_saved_revision;
            request.issued_session_revision = issued_session_revision;
            if grant_request_payload_bytes(&request) > MAX_GRANT_REQUEST_PAYLOAD_BYTES {
                return AdminResponse::Error {
                    message: format!(
                        "grant request payload exceeds the {} byte limit",
                        MAX_GRANT_REQUEST_PAYLOAD_BYTES
                    ),
                };
            }
            if let Some(session_expires_at) = session_expires_at {
                request.expires_unix = request.expires_unix.min(session_expires_at);
            }
            let selected = match issued_saved_grant.as_deref() {
                Some(name) => config.saved_grants.read().await.get(name).cloned(),
                None => None,
            };
            let auto_approved = selected.is_some_and(|grant| {
                Some(grant.revision) == request.issued_saved_revision
                    && grant.auto_approve_requests
                    && grant.contains_delta(&request.delta)
            });
            let _transition = config.grant_request_transition_gate.lock().await;
            {
                let mut requests = config.grant_requests.write().await;
                if requests.len() >= MAX_GRANT_REQUESTS {
                    return AdminResponse::Error {
                        message: "grant request queue is full; wait for an existing request to be decided or expire"
                            .to_string(),
                    };
                }
                if requests
                    .values()
                    .filter(|existing| {
                        existing.session_token == session_token
                            && existing.status == GrantRequestStatus::Pending
                    })
                    .count()
                    >= MAX_PENDING_GRANT_REQUESTS_PER_SESSION
                {
                    return AdminResponse::Error {
                        message: format!(
                            "session grant request queue is full; at most {} pending requests are allowed per session",
                            MAX_PENDING_GRANT_REQUESTS_PER_SESSION
                        ),
                    };
                }
                requests.insert(request.handle.clone(), request.clone());
            }
            if let Some(store) = &config.session_store {
                if let Err(error) = store.save_grant_request(request.clone()).await {
                    config.grant_requests.write().await.remove(&request.handle);
                    return AdminResponse::Error {
                        message: format!("failed to persist grant request: {error}"),
                    };
                }
            }
            if auto_approved {
                let pending = request.clone();
                let mut approved = request.clone();
                approved.status = GrantRequestStatus::Approved;
                approved.decided_unix = Some(now_unix());
                approved.decided_reason =
                    Some("within the saved grant auto-approval ceiling".to_string());
                approved.next_action = "guard session status".to_string();
                if let Err(message) =
                    apply_and_persist_grant_request_delta_if_current(config, &pending, &approved)
                        .await
                {
                    return AdminResponse::Error { message };
                }
                request = approved;
            }
            config
                .grant_requests
                .write()
                .await
                .insert(request.handle.clone(), request.clone());
            emit_grant_request_event(config, &request, "grant_request_submitted");
            AdminResponse::GrantRequest {
                request: redact_grant_request(request),
            }
        }
        AdminRequest::GrantRequestList {
            session_token,
            caller_token,
        } => {
            prune_grant_requests(config).await;
            let is_admin = caller_is_session_admin(config, caller);
            if !is_admin {
                let Some(target) = session_token.as_deref() else {
                    return AdminResponse::Error {
                        message: "grant request list requires GUARD_SESSION".to_string(),
                    };
                };
                if caller_token.as_deref() != Some(target) {
                    return AdminResponse::Error {
                        message: "not authorized: a session may only list its own grant requests"
                            .to_string(),
                    };
                }
                if !config.sessions.read().await.has(target) {
                    return AdminResponse::Error {
                        message: format!("unknown active session: '{target}'"),
                    };
                }
            }
            let items = config
                .grant_requests
                .read()
                .await
                .values()
                .filter(|request| {
                    is_admin
                        || session_token
                            .as_deref()
                            .is_some_and(|token| request.session_token == token)
                })
                .cloned()
                .map(redact_grant_request)
                .collect();
            AdminResponse::GrantRequests { items }
        }
        AdminRequest::GrantRequestShow {
            handle,
            session_token,
        } => {
            prune_grant_requests(config).await;
            let request = config.grant_requests.read().await.get(&handle).cloned();
            match request.filter(|request| {
                caller_is_session_admin(config, caller)
                    || session_token
                        .as_deref()
                        .is_some_and(|token| token == request.session_token)
            }) {
                Some(request) => AdminResponse::GrantRequest {
                    request: redact_grant_request(request),
                },
                None => AdminResponse::Error {
                    message: "unknown or unauthorized grant request".to_string(),
                },
            }
        }
        AdminRequest::GrantRequestApprove { handle } => {
            decide_grant_request(config, &handle, true, "approved by operator").await
        }
        AdminRequest::GrantRequestDeny { handle, reason } => {
            decide_grant_request(config, &handle, false, &reason).await
        }
        AdminRequest::GrantRequestWithdraw {
            handle,
            session_token,
        } => {
            prune_grant_requests(config).await;
            let _transition = config.grant_request_transition_gate.lock().await;
            let current = config.grant_requests.read().await.get(&handle).cloned();
            let Some(current) = current else {
                return AdminResponse::Error {
                    message: format!("unknown grant request: '{handle}'"),
                };
            };
            if !caller_is_session_admin(config, caller)
                && session_token
                    .as_deref()
                    .is_none_or(|token| token != current.session_token)
            {
                return AdminResponse::Error {
                    message: "unknown or unauthorized grant request".to_string(),
                };
            }
            if current.status != GrantRequestStatus::Pending {
                return AdminResponse::Error {
                    message: format!(
                        "grant request transition conflict: '{handle}' is already {}",
                        current.status.as_str()
                    ),
                };
            }
            let mut request = current.clone();
            request.status = GrantRequestStatus::Withdrawn;
            request.decided_unix = Some(now_unix());
            request.next_action = format!("guard grant request show {handle}");
            if let Some(store) = &config.session_store {
                if let Err(error) = store
                    .compare_and_swap_grant_request(current.clone(), request.clone())
                    .await
                {
                    reconcile_grant_request_from_store(config, &handle).await;
                    return AdminResponse::Error {
                        message: format!("grant request transition conflict: {error}"),
                    };
                }
            }
            config
                .grant_requests
                .write()
                .await
                .insert(handle, request.clone());
            emit_grant_request_event(config, &request, "grant_request_withdrawn");
            AdminResponse::GrantRequest {
                request: redact_grant_request(request),
            }
        }
        AdminRequest::EvaluateBatch {
            session_token,
            caller_token,
            commands,
        } => {
            if commands.is_empty() || commands.len() > 64 {
                return AdminResponse::Error {
                    message: "evaluation batch requires 1 to 64 commands".to_string(),
                };
            }
            let is_admin = caller_is_session_admin(config, caller);
            if !is_admin && session_token.is_none() {
                return AdminResponse::Error {
                    message: "batch evaluation requires an active caller-owned session".to_string(),
                };
            }
            if !is_admin && caller_token.as_deref() != session_token.as_deref() {
                return AdminResponse::Error {
                    message: "not authorized: a session may only batch-evaluate for itself"
                        .to_string(),
                };
            }
            if let Some(token) = session_token.as_deref() {
                let registry = config.sessions.read().await;
                if !registry.has(token) {
                    return AdminResponse::Error {
                        message: format!("unknown active session: '{token}'"),
                    };
                }
                if let Some(reason) = registry.suspension_reason(token, &config.behavior_limits) {
                    return AdminResponse::Error {
                        message: format!("session is suspended: {reason}"),
                    };
                }
            }
            // The preview uses the production admission pipeline with execution
            // disabled and isolated mutable registries. It therefore shares
            // validation, cwd, session revision, policy, typed coverage,
            // environment/secret authorization, and evaluator cache context
            // with a subsequent real run without creating holds or history.
            let mut preview = config.clone();
            preview.dry_run = true;
            preview.admission_preview = true;
            preview.session_store = None;
            preview.sessions = std::sync::Arc::new(tokio::sync::RwLock::new(
                config.sessions.read().await.clone(),
            ));
            preview.verbs =
                std::sync::Arc::new(tokio::sync::RwLock::new(config.verbs.read().await.clone()));
            preview.saved_grants = std::sync::Arc::new(tokio::sync::RwLock::new(
                config.saved_grants.read().await.clone(),
            ));
            preview.grant_requests =
                std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::BTreeMap::new()));
            preview.grant_request_transition_gate =
                std::sync::Arc::new(tokio::sync::Mutex::new(()));
            preview.provisional = std::sync::Arc::new(tokio::sync::RwLock::new(
                guard::gating::provisional::ProvisionalRegistry::new(),
            ));
            preview.approvals = std::sync::Arc::new(tokio::sync::RwLock::new(
                guard::gating::approval::ApprovalRegistry::new(),
            ));
            preview.read_grants = std::sync::Arc::new(tokio::sync::RwLock::new(
                guard::gating::read_grant::GrantReadRegistry::new(),
            ));
            preview.notify_hook = None;
            let mut items = Vec::with_capacity(commands.len());
            for command in commands {
                let rendered = command_line(&command.binary, &command.args);
                let response = super::execute::execute_command(
                    super::wire::ExecuteRequest {
                        binary: command.binary,
                        args: command.args,
                        auth_token: None,
                        env: command.env,
                        secrets: command.secrets,
                        secret_files: command.secret_files,
                        stream: false,
                        session_token: session_token.clone(),
                        revert: None,
                        confirm_within_secs: None,
                        require_approval: None,
                        wait_approval_secs: None,
                        verb: None,
                        reevaluate: false,
                        ssh_hostkey: None,
                        cwd: command.cwd,
                    },
                    &preview,
                    caller,
                )
                .await
                .into_response();
                items.push(super::wire::BatchEvaluation {
                    command: rendered,
                    allowed: response.allowed,
                    reason: response.reason,
                    risk: None,
                    decision_source: response.decision_source,
                    verb_matches: response.verb_matches,
                    guidance: response.verb_guidance,
                });
            }
            AdminResponse::EvaluationBatch { items }
        }
    }
}

/// Collapse runs of whitespace (incl. newlines) to single spaces, so prose and
/// evidence persist as a tidy single line in the YAML catalog.
fn normalize_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn generated_verb_delta(old: &[Verb], new: &[Verb]) -> (Vec<String>, Vec<String>, Vec<String>) {
    let old = old
        .iter()
        .map(|verb| {
            (
                verb.name.clone(),
                serde_json::to_vec(verb).unwrap_or_default(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let new = new
        .iter()
        .map(|verb| {
            (
                verb.name.clone(),
                serde_json::to_vec(verb).unwrap_or_default(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let added = new
        .keys()
        .filter(|name| !old.contains_key(*name))
        .cloned()
        .collect();
    let removed = old
        .keys()
        .filter(|name| !new.contains_key(*name))
        .cloned()
        .collect();
    let changed = new
        .iter()
        .filter(|(name, body)| old.get(*name).is_some_and(|old_body| old_body != *body))
        .map(|(name, _)| name.clone())
        .collect();
    (added, removed, changed)
}

fn sticky_coverage_is_compatible(existing: &[Verb], candidate: &Verb) -> bool {
    existing
        .iter()
        .filter(|verb| verb.coverage.iter().any(|cell| cell.sticky))
        .all(|verb| {
            verb.binary == candidate.binary
                && verb.args == candidate.args
                && verb.credential_plan == candidate.credential_plan
                && serde_json::to_vec(&verb.params).ok()
                    == serde_json::to_vec(&candidate.params).ok()
        })
}

type RegenerationStage = (
    crate::grant_profile::SavedGrantCatalog,
    guard::gating::verb::VerbCatalog,
    crate::grant_profile::SavedGrant,
    Vec<String>,
    Vec<String>,
    Vec<String>,
);

fn stage_saved_grant_regeneration(
    grants: &crate::grant_profile::SavedGrantCatalog,
    verbs: &guard::gating::verb::VerbCatalog,
    name: &str,
    updated: crate::grant_profile::SavedGrant,
    verb: Verb,
) -> Result<RegenerationStage, String> {
    let old_generated = grants
        .get(name)
        .map(|grant| grant.generated_verbs.clone())
        .ok_or_else(|| format!("unknown saved grant: '{name}'"))?;
    let mut staged_grants = grants.clone();
    let updated = staged_grants
        .replace(updated)
        .map_err(|error| error.to_string())?;
    let mut staged_verbs = verbs.clone();
    staged_verbs
        .remove_saved_grant_verbs(name)
        .map_err(|error| error.to_string())?;
    staged_verbs
        .upsert_saved_grant_verb(verb)
        .map_err(|error| error.to_string())?;
    let (added, removed, changed) = generated_verb_delta(&old_generated, &updated.generated_verbs);
    Ok((
        staged_grants,
        staged_verbs,
        updated,
        added,
        removed,
        changed,
    ))
}

async fn decide_grant_request(
    config: &ServerConfig,
    handle: &str,
    approve: bool,
    reason: &str,
) -> AdminResponse {
    let _transition = config.grant_request_transition_gate.lock().await;
    let request = config.grant_requests.read().await.get(handle).cloned();
    let Some(mut request) = request else {
        return AdminResponse::Error {
            message: format!("unknown grant request: '{handle}'"),
        };
    };
    if request.status != GrantRequestStatus::Pending {
        return AdminResponse::Error {
            message: format!(
                "grant request transition conflict: '{handle}' is already {}",
                request.status.as_str()
            ),
        };
    }
    if request.expires_unix == 0 || now_unix() >= request.expires_unix {
        config.grant_requests.write().await.remove(handle);
        if let Some(store) = &config.session_store {
            if let Err(error) = store.delete_grant_requests(vec![handle.to_string()]).await {
                return AdminResponse::Error {
                    message: format!("failed to retire expired grant request: {error}"),
                };
            }
        }
        return AdminResponse::Error {
            message: format!("grant request '{handle}' expired; submit a new request"),
        };
    }
    let pending = request.clone();
    if approve {
        if let Err(message) = validate_grant_request_for_approval(config, &request).await {
            return AdminResponse::Error { message };
        }
        request.status = GrantRequestStatus::Approved;
        request.next_action = "guard session status".to_string();
    } else {
        request.status = GrantRequestStatus::Denied;
        request.next_action = format!(
            "ask the operator to edit a saved grant, then run `guard grant request show {handle}`"
        );
    }
    request.decided_unix = Some(now_unix());
    request.decided_reason = Some(reason.to_string());
    if approve {
        if let Err(message) =
            apply_and_persist_grant_request_delta_if_current(config, &pending, &request).await
        {
            reconcile_grant_request_from_store(config, handle).await;
            return AdminResponse::Error { message };
        }
    } else if let Some(store) = &config.session_store {
        if let Err(error) = store
            .compare_and_swap_grant_request(pending, request.clone())
            .await
        {
            reconcile_grant_request_from_store(config, handle).await;
            return AdminResponse::Error {
                message: format!("grant request transition conflict: {error}"),
            };
        }
    }
    config
        .grant_requests
        .write()
        .await
        .insert(handle.to_string(), request.clone());
    emit_grant_request_event(config, &request, "grant_request_decided");
    AdminResponse::GrantRequest {
        request: redact_grant_request(request),
    }
}

async fn reconcile_grant_request_from_store(config: &ServerConfig, handle: &str) {
    let Some(store) = &config.session_store else {
        return;
    };
    match store.load_grant_request(handle.to_string()).await {
        Ok(Some(durable)) => {
            config
                .grant_requests
                .write()
                .await
                .insert(handle.to_string(), durable);
        }
        Ok(None) => {
            config.grant_requests.write().await.remove(handle);
        }
        Err(error) => tracing::warn!(
            "failed to reconcile grant request '{}' after transition conflict: {}",
            handle,
            error
        ),
    }
}

async fn apply_and_persist_grant_request_delta_if_current(
    config: &ServerConfig,
    pending: &GrantRequest,
    approved: &GrantRequest,
) -> Result<(), String> {
    let mut sessions = config.sessions.write().await;
    if sessions.effective_revision_key(&pending.session_token) != pending.issued_session_revision {
        return Err(format!(
            "grant request '{}' no longer matches the issued session revision; submit a new request",
            pending.handle
        ));
    }
    let issued = sessions.saved_grant_for(&pending.session_token);
    let issued_matches = match (&pending.saved_grant, pending.issued_saved_revision, issued) {
        (Some(expected_name), Some(expected_revision), Some((name, revision))) => {
            expected_name == &name && expected_revision == revision
        }
        (None, None, None) => true,
        _ => false,
    };
    if !issued_matches {
        return Err(format!(
            "grant request '{}' no longer matches the issued session revision; submit a new request",
            pending.handle
        ));
    }
    let mut staged = sessions.clone();
    staged
        .apply_delta(&pending.session_token, &pending.delta)
        .ok_or_else(|| format!("unknown active session: '{}'", pending.session_token))?;
    if let Some(store) = &config.session_store {
        store
            .commit_grant_request_approval(pending.clone(), approved.clone(), staged.clone())
            .await
            .map_err(|error| format!("failed to persist approved grant request: {error}"))?;
    }
    *sessions = staged;
    Ok(())
}

async fn validate_grant_request_for_approval(
    config: &ServerConfig,
    request: &GrantRequest,
) -> Result<(), String> {
    if request.expires_unix == 0 || now_unix() >= request.expires_unix {
        return Err(format!(
            "grant request '{}' expired; submit a new request",
            request.handle
        ));
    }
    let sessions = config.sessions.read().await;
    let current_session_revision = sessions.effective_revision_key(&request.session_token);
    if current_session_revision != request.issued_session_revision {
        return Err(format!(
            "grant request '{}' no longer matches the issued session revision; submit a new request",
            request.handle
        ));
    }
    let issued = sessions.saved_grant_for(&request.session_token);
    drop(sessions);
    match (&request.saved_grant, request.issued_saved_revision, issued) {
        (Some(expected_name), Some(expected_revision), Some((name, revision)))
            if expected_name == &name && expected_revision == revision => {}
        (None, None, None) => {}
        _ => {
            return Err(format!(
                "grant request '{}' no longer matches the issued session revision; submit a new request",
                request.handle
            ))
        }
    }
    if let (Some(name), Some(revision)) = (
        request.saved_grant.as_deref(),
        request.issued_saved_revision,
    ) {
        let current = config.saved_grants.read().await.get(name).cloned();
        if current.as_ref().map(|grant| grant.revision) != Some(revision) {
            return Err(format!(
                "saved grant '{name}' changed after request issuance; submit a new request"
            ));
        }
    }
    if !request.delta.override_markers.is_empty() {
        let available = config
            .verbs
            .read()
            .await
            .list()
            .into_iter()
            .flat_map(|verb| verb.coverage)
            .filter_map(|cell| cell.override_marker)
            .collect::<std::collections::BTreeSet<_>>();
        if let Some(marker) = request
            .delta
            .override_markers
            .iter()
            .find(|marker| !available.contains(*marker))
        {
            return Err(format!("unknown verb override marker: '{marker}'"));
        }
    }
    Ok(())
}

pub(super) async fn prune_grant_requests(config: &ServerConfig) {
    let now = now_unix();
    let mut requests = config.grant_requests.write().await;
    let mut removed = requests
        .iter()
        .filter(|(_, request)| {
            request.status == GrantRequestStatus::Pending
                && (request.expires_unix == 0 || request.expires_unix <= now)
        })
        .map(|(handle, _)| handle.clone())
        .collect::<Vec<_>>();
    let retained_after_expiry = requests.len().saturating_sub(removed.len());
    let mut retained_count = retained_after_expiry;
    while retained_count >= MAX_GRANT_REQUESTS {
        let oldest_terminal = requests
            .iter()
            .filter(|(handle, _)| !removed.contains(handle))
            .filter(|(_, request)| request.status != GrantRequestStatus::Pending)
            .min_by_key(|(handle, request)| (request.created_unix, *handle))
            .map(|(handle, _)| handle.clone());
        let Some(handle) = oldest_terminal else {
            break;
        };
        removed.push(handle);
        retained_count = retained_count.saturating_sub(1);
    }
    if !removed.is_empty() {
        if let Some(store) = &config.session_store {
            if let Err(error) = store.delete_grant_requests(removed.clone()).await {
                tracing::warn!("failed to prune expired grant requests: {error}");
                return;
            }
        }
        for handle in removed {
            requests.remove(&handle);
        }
    }
}

fn redact_grant_request(mut request: GrantRequest) -> GrantRequest {
    request.session_token = audit_session_fingerprint(Some(&request.session_token));
    request
}

fn emit_grant_request_event(config: &ServerConfig, request: &GrantRequest, event: &'static str) {
    config.emit_event(NotifyEvent {
        event,
        at_unix: now_unix(),
        handle: Some(request.handle.clone()),
        session_fingerprint: Some(audit_session_fingerprint(Some(&request.session_token))),
        reason: request.decided_reason.clone(),
        status: Some(request.status.as_str().to_string()),
        behavior: None,
    });
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
            // The change is kept and the revert will never fire; drop its
            // persisted body so a secret-bearing snapshot is not left on disk.
            remove_revert_body(&p);
            tracing::info!(target: "guard::audit", "[AUDIT] CONFIRM handle={} caller={}", handle, caller);
            config.emit_event(NotifyEvent {
                event: "decision_made",
                at_unix: now_unix(),
                handle: Some(handle.to_string()),
                session_fingerprint: p.session_fingerprint.clone(),
                reason: Some("operator confirmed provisional".to_string()),
                status: Some("confirmed".to_string()),
                behavior: None,
            });
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

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod regeneration_tests {
    use super::*;
    use crate::grant_profile::SavedGrantCatalog;
    use guard::gating::verb::VerbCatalog;

    fn fixture() -> (SavedGrantCatalog, VerbCatalog) {
        let grants = SavedGrantCatalog::from_yaml(
            "profiles:\n  - name: atomic\n    allow: ['kubectl get pods']\n",
        )
        .unwrap();
        let mut verbs = VerbCatalog::empty();
        for verb in &grants.get("atomic").unwrap().generated_verbs {
            verbs.upsert_saved_grant_verb(verb.clone()).unwrap();
        }
        (grants, verbs)
    }

    #[test]
    fn regeneration_stages_atomically_and_reports_deterministic_delta() {
        let (grants, verbs) = fixture();
        let original_grant = grants.get("atomic").unwrap().clone();
        let original_names = verbs.names();
        let mut changed = original_grant.generated_verbs[0].clone();
        changed.description = "regenerated".to_string();
        let mut updated = original_grant.clone();
        updated.generated_verbs = vec![changed.clone()];

        let (_, _, _, added, removed, changed_names) =
            stage_saved_grant_regeneration(&grants, &verbs, "atomic", updated, changed).unwrap();
        assert!(added.is_empty() && removed.is_empty());
        assert_eq!(changed_names, original_names);
        assert_eq!(
            grants.get("atomic").unwrap().revision,
            original_grant.revision
        );
        assert_eq!(verbs.names(), original_names);

        let mut cross_binary = original_grant.generated_verbs[0].clone();
        cross_binary.binary = "ansible-playbook".to_string();
        assert!(!sticky_coverage_is_compatible(
            &original_grant.generated_verbs,
            &cross_binary
        ));
        let mut changed_template = original_grant.generated_verbs[0].clone();
        changed_template.args.push("--check".to_string());
        assert!(!sticky_coverage_is_compatible(
            &original_grant.generated_verbs,
            &changed_template
        ));

        let mut invalid = original_grant.generated_verbs[0].clone();
        invalid.name = "outside-reserved-namespace".to_string();
        let mut invalid_update = original_grant.clone();
        invalid_update.generated_verbs = vec![invalid.clone()];
        assert!(
            stage_saved_grant_regeneration(&grants, &verbs, "atomic", invalid_update, invalid,)
                .is_err()
        );
        assert_eq!(
            grants.get("atomic").unwrap().revision,
            original_grant.revision
        );
        assert_eq!(verbs.names(), original_names);
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
    if is_api_proxy_sentinel(&snapshot.binary)
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
        tracing::info!(target: "guard::audit",
            "[AUDIT] APPROVED handle={} caller={} (api-proxy request released)",
            handle,
            caller
        );
        config.emit_event(NotifyEvent {
            event: "decision_made",
            at_unix: now,
            handle: Some(handle.to_string()),
            session_fingerprint: snapshot.session_fingerprint.clone(),
            reason: Some("operator approved held API request".to_string()),
            status: Some("approved".to_string()),
            behavior: None,
        });
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
            tracing::warn!(target: "guard::audit",
                "[AUDIT] APPROVE_VOIDED handle={} caller={} session_fingerprint={} {}",
                handle,
                caller,
                snapshot
                    .session_fingerprint
                    .as_deref()
                    .unwrap_or("none"),
                detail
            );
            config.emit_event(NotifyEvent {
                event: "decision_made",
                at_unix: now,
                handle: Some(handle.to_string()),
                session_fingerprint: snapshot.session_fingerprint.clone(),
                reason: Some(detail.clone()),
                status: Some("voided".to_string()),
                behavior: None,
            });
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
            tracing::info!(target: "guard::audit",
                "[AUDIT] APPROVED handle={} caller={} session_fingerprint={} exit={:?}",
                handle,
                caller,
                snapshot
                    .session_fingerprint
                    .as_deref()
                    .unwrap_or("none"),
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
            tracing::error!(target: "guard::audit",
                "[AUDIT] APPROVE_EXEC_FAILED handle={} caller={} session_fingerprint={} detail={}",
                handle,
                caller,
                snapshot
                    .session_fingerprint
                    .as_deref()
                    .unwrap_or("none"),
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
    config.emit_event(NotifyEvent {
        event: "decision_made",
        at_unix: now,
        handle: Some(handle.to_string()),
        session_fingerprint: snapshot.session_fingerprint.clone(),
        reason: Some(message.clone()),
        status: Some(
            if exit.is_some() {
                "approved"
            } else {
                "exec_failed"
            }
            .to_string(),
        ),
        behavior: None,
    });
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
                    tracing::info!(target: "guard::audit",
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
            let session_fingerprint =
                if let Some(a) = config.approvals.read().await.get(handle).cloned() {
                    let session_fingerprint = a.snapshot.session_fingerprint.clone();
                    persist_approval(config, &a).await;
                    session_fingerprint
                } else {
                    None
                };
            tracing::info!(target: "guard::audit",
                "[AUDIT] DENIED_HOLD handle={} caller={} session_fingerprint={}",
                handle,
                caller,
                session_fingerprint.as_deref().unwrap_or("none")
            );
            config.emit_event(NotifyEvent {
                event: "decision_made",
                at_unix: now,
                handle: Some(handle.to_string()),
                session_fingerprint,
                reason: Some("operator denied held command".to_string()),
                status: Some("denied".to_string()),
                behavior: None,
            });
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
