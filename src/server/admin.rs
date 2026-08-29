#[cfg(test)]
use crate::grant_profile::EvaluationMode;
use crate::grant_profile::{
    normalize_access_intent, GrantRequest, GrantRequestDelta, GrantRequestStatus,
};
use crate::secrets::legacy_sentinel;
use crate::session::{
    session_reference, SessionGrantSummary, SessionOwner, SessionRegistry, SessionReport,
};
#[cfg(test)]
use crate::session::{
    HistoricalGrant, IssuedGrantScope, SessionAmendment, SessionDecision, SessionDecisionSource,
    SessionExecStatus, SessionGrant, SessionInteraction,
};
use guard::audit::{AuditEvent, AuditKind};
use guard::gating::semantic_executable_key;
use guard::gating::verb::{
    canonical_generated_access_consequence, generated_access_matcher_digest,
    generated_access_matcher_shape, generated_access_verb_name, Verb, VerbCatalog,
};
#[cfg(test)]
use guard::gating::verb::{
    CoverageAction, CoverageObservationReplay, CoverageProvenance, VerbCoverageCell,
};
use guard::principal::{scope_eq, PrincipalKey};
#[cfg(test)]
use guard::redact::redact_output;
use guard::redact::{redact_command_line, redact_output_text};

use super::execute::audit_session_fingerprint;
#[cfg(test)]
use super::execute::{
    persist_current_sessions, persist_session_snapshot, record_live_session_interaction,
    session_source_from_eval,
};
use super::gate_runtime::{
    bound_persisted_transcript, finish_revert, forget_proxy_provenance, is_api_proxy_sentinel,
    now_unix, persist_approval, persist_provisional_transition,
    persist_terminal_provisional_with_body_cleanup, resume_approval,
};
#[cfg(test)]
use super::learning::{
    allow_session_auto_amend_candidate, amend_session_exact_rule,
    deny_session_auto_amend_candidate, validate_session_exact_rule_candidate,
};
use super::runtime::NotifyEvent;
use super::wire::{
    approval_is_armed, authorize_session_use, grant_class_wait_refusal, verb_effective_trust,
    AccessCapability, AccessDecisionResult, AccessItem, AccessWaitResult, AdminRequest,
    AdminResponse, ApprovalSummary, CallerIdentity, ExecOutcome, ExecuteRequest,
    OwnedAdminResponse, ProvisionalSummary, SecretDetail, ServerStatus, SessionAuthz,
    VerbInvocation, VerbMenuItem, VerbSummary, APPROVAL_ARMED_REASON, CONSEQUENCE_ARM,
    CONSEQUENCE_GRANT, CONSEQUENCE_RELEASE, SESSION_PRINCIPAL_MISMATCH, SESSION_UNOWNED_REFUSED,
};
use super::{is_valid_secret_key, ServerContext};
use guard::gating::approval::{Approval, ApprovalSnapshot, ApprovalStatus};

pub(super) const MAX_GRANT_REQUESTS: usize = 1024;
pub(super) const MAX_PENDING_GRANT_REQUESTS_PER_SESSION: usize = 32;
pub(super) const MAX_GRANT_REQUEST_PAYLOAD_BYTES: usize = 64 * 1024;

struct AccessTargetSnapshot {
    requester: PrincipalKey,
    target: String,
    active_verbs: Vec<String>,
    usable_access_verbs: Vec<String>,
    revision: Option<String>,
    expires_at: Option<u64>,
}

fn access_target_snapshot(
    sessions: &SessionRegistry,
    token: &str,
) -> Result<AccessTargetSnapshot, String> {
    let owner = sessions
        .owner_for(token)
        .ok_or_else(|| "access target expired while resolving".to_string())?;
    let SessionOwner::Principal(requester) = owner else {
        return Err("legacy unowned sessions cannot be extended".to_string());
    };
    let summary = sessions
        .list()
        .into_iter()
        .find(|summary| summary.token == token)
        .ok_or_else(|| "access target expired while resolving".to_string())?;
    let usable_access_verbs = summary
        .scope
        .access_grants
        .iter()
        .filter(|grant| {
            !grant.pending && grant.remaining_uses.is_none_or(|remaining| remaining > 0)
        })
        .flat_map(|grant| grant.verbs.iter().cloned())
        .collect();
    Ok(AccessTargetSnapshot {
        requester,
        target: summary
            .scope
            .label
            .clone()
            .unwrap_or_else(|| session_reference(token)),
        active_verbs: summary.activated_verbs,
        usable_access_verbs,
        revision: sessions.effective_revision_key(token),
        expires_at: summary.expires_at,
    })
}

fn proposed_verbs_for_missing_authority(proposed: Vec<Verb>, missing: &[String]) -> Vec<Verb> {
    proposed
        .into_iter()
        .filter(|verb| missing.iter().any(|name| name == &verb.name))
        .collect()
}

#[derive(serde::Serialize, serde::Deserialize)]
#[cfg(test)]
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

    const KEY_A: [u8; 32] = [0x11; 32];
    const KEY_B: [u8; 32] = [0x22; 32];

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
            hold: false,
            trusted: false,
            prompt_context: None,
            exec_timeout_secs: None,
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

    fn access_grant(owner: PrincipalKey, granted_at: u64) -> SessionGrant {
        SessionGrant {
            allow: Vec::new(),
            deny: Vec::new(),
            allow_exact: Vec::new(),
            deny_exact: Vec::new(),
            activated_verbs: vec!["host-inspect".to_string()],
            override_markers: Vec::new(),
            scope: IssuedGrantScope {
                access_managed: true,
                ..IssuedGrantScope::default()
            },
            expires_at: None,
            prompt_append: None,
            generated_notes: Vec::new(),
            granted_at,
            static_only: true,
            auto_amend: false,
            owner: SessionOwner::Principal(owner),
        }
    }

    fn held_approval(handle: &str) -> Approval {
        Approval {
            handle: handle.to_string(),
            snapshot: guard::gating::approval::ApprovalSnapshot {
                binary: "host-maintain".to_string(),
                args: Vec::new(),
                cwd: None,
                env: BTreeMap::new(),
                secret_keys: BTreeMap::new(),
                session_fingerprint: None,
                session_revision: None,
                secret_entitlements: None,
                secret_file_keys: BTreeMap::new(),
                verb_name: None,
                verb_params: BTreeMap::new(),
                catalog_version: None,
                verb_digest: None,
                verb_composition_digest: None,
                verb_environment_authority: false,
                verb_local_file_authority: false,
                exec_timeout_secs: None,
                access_verbs: Vec::new(),
                access_requests: Vec::new(),
                principal: Some(PrincipalKey::from_uid(1001)),
                secret_binding: None,
                process_authority: None,
            },
            reason: "operator decision required".to_string(),
            risk: Some(9),
            reversibility: Some(guard::gating::Reversibility::Irreversible),
            decision_trace: None,
            created_unix: 1,
            ttl_secs: u64::MAX - 1,
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
    fn proposal_round_trip_preserves_exact_candidate_and_bindings() {
        let proposal = proposal();
        let id = encode_regeneration_proposal(&proposal, &KEY_A).unwrap();
        let decoded = decode_regeneration_proposal(&id, &KEY_A).unwrap();
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
        let mut id = encode_regeneration_proposal(&proposal(), &KEY_A).unwrap();
        let last = id.pop().unwrap();
        id.push(if last == '0' { '1' } else { '0' });
        assert!(decode_regeneration_proposal(&id, &KEY_A).is_err());
    }

    #[test]
    fn proposal_recomputed_under_another_key_is_rejected() {
        let forged = encode_regeneration_proposal(&proposal(), &KEY_B).unwrap();
        assert!(decode_regeneration_proposal(&forged, &KEY_A).is_err());
    }

    #[test]
    fn server_context_clones_share_proposal_authentication_authority() {
        let server = crate::server::tests::config_for_proposal_test();
        let preview = server.clone();
        assert!(std::sync::Arc::ptr_eq(
            &server.config.regeneration_proposal_key,
            &preview.config.regeneration_proposal_key
        ));
        let id = encode_regeneration_proposal(
            &proposal(),
            server.config.regeneration_proposal_key.as_ref(),
        )
        .unwrap();
        assert!(decode_regeneration_proposal(
            &id,
            preview.config.regeneration_proposal_key.as_ref()
        )
        .is_ok());
    }

    #[test]
    fn mixed_case_sid_selects_one_canonical_access_session() {
        let upper = PrincipalKey::from_sid("S-1-5-21-10-20-30-1001");
        let lower = PrincipalKey::from_sid("s-1-5-21-10-20-30-1001");
        let mut registry = crate::session::SessionRegistry::new();
        registry.grant("later".to_string(), access_grant(lower.clone(), 20));
        registry.grant("first".to_string(), access_grant(upper, 10));

        assert_eq!(
            access_token_for_principal_ci(&registry, &lower).as_deref(),
            Some("first")
        );
    }

    #[test]
    fn mixed_case_sid_requests_have_the_same_convergence_key() {
        let upper = PrincipalKey::from_sid("S-1-5-21-10-20-30-1001");
        let lower = PrincipalKey::from_sid("s-1-5-21-10-20-30-1001");
        let mut first = GrantRequest::new_access_with_uses(
            upper,
            Some("session".to_string()),
            "agent".to_string(),
            GrantRequestDelta {
                activated_verbs: vec!["host-inspect".to_string()],
                ..GrantRequestDelta::default()
            },
            "inspect host".to_string(),
            Some(3),
        )
        .unwrap();
        first.authority_verbs = vec!["host-inspect".to_string()];
        first.request_key = first.canonical_access_key().unwrap();
        let mut second = first.clone();
        second.requester = Some(lower);
        second.request_key = second.canonical_access_key().unwrap();

        assert_ne!(first.request_key, second.request_key);
        assert!(access_request_key_eq_ci(&first, &second));
    }

    #[test]
    fn access_target_snapshot_rebases_to_the_current_revision() {
        let owner = PrincipalKey::from_uid(1001);
        let mut registry = crate::session::SessionRegistry::new();
        registry.grant("session".to_string(), access_grant(owner, 10));
        let before = access_target_snapshot(&registry, "session").unwrap();

        registry
            .apply_delta(
                "session",
                &GrantRequestDelta {
                    activated_verbs: vec!["host-maintain".to_string()],
                    ..GrantRequestDelta::default()
                },
            )
            .unwrap();
        let after = access_target_snapshot(&registry, "session").unwrap();

        assert_ne!(before.revision, after.revision);
        assert!(after.active_verbs.contains(&"host-maintain".to_string()));
    }

    #[test]
    fn active_generated_authority_does_not_restage_unreferenced_coverage() {
        let generated = candidate();
        assert!(proposed_verbs_for_missing_authority(vec![generated.clone()], &[]).is_empty());
        assert_eq!(
            proposed_verbs_for_missing_authority(vec![generated], &["generated:test".to_string()])
                .len(),
            1
        );
    }

    #[test]
    fn held_replay_selects_only_the_originating_session_revision() {
        let owner = PrincipalKey::from_sid("S-1-5-21-10-20-30-1001");
        let caller = PrincipalKey::from_sid("s-1-5-21-10-20-30-1001");
        let mut registry = crate::session::SessionRegistry::new();
        registry.grant("origin".to_string(), access_grant(owner.clone(), 10));
        registry.grant("other".to_string(), access_grant(owner, 20));
        let snapshot = guard::gating::approval::ApprovalSnapshot {
            binary: "host-inspect".to_string(),
            args: Vec::new(),
            cwd: None,
            env: BTreeMap::new(),
            secret_keys: BTreeMap::new(),
            session_fingerprint: Some(audit_session_fingerprint(Some("origin"))),
            session_revision: registry.effective_revision_key("origin"),
            secret_entitlements: None,
            secret_file_keys: BTreeMap::new(),
            verb_name: Some("host-inspect".to_string()),
            verb_params: BTreeMap::new(),
            catalog_version: Some(1),
            verb_digest: None,
            verb_composition_digest: None,
            verb_environment_authority: false,
            verb_local_file_authority: false,
            exec_timeout_secs: None,
            access_verbs: vec!["host-inspect".to_string()],
            access_requests: Vec::new(),
            principal: Some(caller),
            secret_binding: None,
            process_authority: None,
        };

        assert_eq!(
            session_token_for_approval_snapshot(&registry, &snapshot).as_deref(),
            Some("origin")
        );
    }

    #[test]
    fn tcp_admin_is_in_operator_caller_scope() {
        let server = crate::server::tests::config_for_proposal_test();
        let caller = CallerIdentity::TcpAdmin {
            token: "fixture-admin".to_string(),
        };
        assert!(caller_scope(&server, &caller).0);
    }

    #[tokio::test]
    async fn held_denial_reconciles_a_concurrent_approval_claim() {
        let mut server = crate::server::tests::config_for_proposal_test();
        let state = tempfile::tempdir().unwrap();
        let database = state.path().join("state.db");
        let store = crate::session_store::SessionStore::open(database.clone(), 3600)
            .await
            .unwrap();
        let other = crate::session_store::SessionStore::open(database, 3600)
            .await
            .unwrap();
        server.state.session_store = Some(store.clone());
        let pending = held_approval("held-race");
        store.save_approval(pending.clone()).await.unwrap();
        server
            .state
            .approvals
            .write()
            .await
            .enqueue(pending.clone());
        let mut approving = pending.clone();
        approving.status = ApprovalStatus::Approving;
        other
            .compare_and_swap_approval_claim(pending, approving)
            .await
            .unwrap();

        let response = handle_deny(
            &server,
            &CallerIdentity::TcpAdmin {
                token: "fixture-admin".to_string(),
            },
            "held-race",
            "deny",
        )
        .await;

        assert!(matches!(response, AdminResponse::Error { .. }));
        assert_eq!(
            server
                .state
                .approvals
                .read()
                .await
                .get("held-race")
                .unwrap()
                .status,
            ApprovalStatus::Approving
        );
    }

    #[tokio::test]
    async fn api_waiter_is_not_released_when_approved_terminal_cas_fails() {
        let mut server = crate::server::tests::config_for_proposal_test();
        let state = tempfile::tempdir().unwrap();
        let store = crate::session_store::SessionStore::open(state.path().join("state.db"), 3600)
            .await
            .unwrap();
        server.state.session_store = Some(store.clone());
        let mut pending = held_approval("api-terminal-cas");
        pending.snapshot.binary = super::super::gate_runtime::API_PROXY_SENTINEL_BINARY.to_string();
        pending.snapshot.principal = Some(server.config.daemon_principal.clone());
        store.save_approval(pending.clone()).await.unwrap();
        let notified = server.state.approvals.write().await.enqueue(pending);
        let snapshot = claim_approval(&server, "api-terminal-cas").await.unwrap();
        store.fail_next_write_for_test();

        let response = handle_approve_claimed(
            &server,
            &CallerIdentity::TcpAdmin {
                token: "fixture-admin".to_string(),
            },
            "api-terminal-cas",
            snapshot,
        )
        .await;

        assert!(
            matches!(response, AdminResponse::Error { message } if message.contains("failed to persist terminal approval"))
        );
        assert_eq!(
            server
                .state
                .approvals
                .read()
                .await
                .get("api-terminal-cas")
                .unwrap()
                .status,
            ApprovalStatus::Approving
        );
        assert_eq!(
            store.load_approvals().await.unwrap()[0].status,
            ApprovalStatus::Approving
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), notified.notified())
                .await
                .is_err(),
            "the parked API request must remain blocked until Approved is durable"
        );
    }
}

#[cfg(test)]
fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
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

#[cfg(test)]
fn encode_regeneration_proposal(
    proposal: &RegenerationProposal,
    key: &[u8],
) -> Result<String, String> {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    let bytes = serde_json::to_vec(proposal).map_err(|error| error.to_string())?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| "invalid regeneration proposal signing key".to_string())?;
    mac.update(&bytes);
    let signature = encode_hex(&mac.finalize().into_bytes());
    Ok(format!("rg2-{signature}-{}", encode_hex(&bytes)))
}

#[cfg(test)]
fn decode_regeneration_proposal(value: &str, key: &[u8]) -> Result<RegenerationProposal, String> {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    let rest = value
        .strip_prefix("rg2-")
        .ok_or_else(|| "invalid regeneration proposal version".to_string())?;
    let (signature, payload) = rest
        .split_once('-')
        .ok_or_else(|| "invalid regeneration proposal".to_string())?;
    let bytes = decode_hex(payload)?;
    let signature = decode_hex(signature)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| "invalid regeneration proposal signing key".to_string())?;
    mac.update(&bytes);
    mac.verify_slice(&signature)
        .map_err(|_| "regeneration proposal authentication failed".to_string())?;
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
        + request
            .authority_verbs
            .iter()
            .map(String::len)
            .sum::<usize>()
        + request
            .proposed_verbs
            .iter()
            .map(|verb| verb.to_string().len())
            .sum::<usize>()
        + request.delta.prompt_append.as_deref().map_or(0, str::len)
}

#[cfg(test)]
fn merge_unique(target: &mut Vec<String>, additions: Vec<String>) {
    for value in additions {
        if !target.iter().any(|existing| existing == &value) {
            target.push(value);
        }
    }
}

#[cfg(test)]
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

const DEFAULT_ACCESS_TTL_SECS: u64 = 3_600;

fn default_access_ttl_secs() -> u64 {
    std::env::var("GUARD_ACCESS_TTL_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_ACCESS_TTL_SECS)
}

fn authenticated_local_principal(caller: &CallerIdentity) -> Result<PrincipalKey, String> {
    if !caller.is_local_peer() {
        return Err("access requests require an authenticated local caller".to_string());
    }
    caller
        .principal()
        .ok_or_else(|| "access requests require an authenticated local principal".to_string())
}

fn validate_access_intent(intent: &str) -> Result<String, String> {
    let normalized = intent.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        return Err("access intent must not be empty".to_string());
    }
    if normalized.len() > MAX_GRANT_REQUEST_PAYLOAD_BYTES {
        return Err("access intent exceeds the request size limit".to_string());
    }
    let redacted = redact_output_text(&normalized);
    if redacted != normalized {
        return Err(
            "access intent appears to contain credential material; name the credential selector without including its value"
                .to_string(),
        );
    }
    Ok(normalized)
}

fn validate_access_denial_reason(reason: &str) -> Result<String, String> {
    let normalized = reason.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        return Err("access denial reason must not be empty".to_string());
    }
    if normalized.len() > MAX_GRANT_REQUEST_PAYLOAD_BYTES {
        return Err("access denial reason exceeds the request size limit".to_string());
    }
    if redact_output_text(&normalized) != normalized {
        return Err("access denial reason appears to contain credential material".to_string());
    }
    Ok(normalized)
}

fn intent_matches_verb(intent: &str, verb: &Verb) -> bool {
    if intent.trim().eq_ignore_ascii_case(&verb.name) {
        return true;
    }
    let intent = normalize_access_intent(intent);
    let name = normalize_access_intent(&verb.name.replace('-', " "));
    let description = normalize_access_intent(&verb.description);
    let source = verb
        .source_prose
        .as_deref()
        .map(normalize_access_intent)
        .unwrap_or_default();
    intent == name || (!description.is_empty() && intent == description) || intent == source
}

fn intent_mentions_verb_name(intent: &str, verb: &Verb) -> bool {
    if intent.trim().eq_ignore_ascii_case(&verb.name) {
        return true;
    }
    let intent_lower = intent.to_ascii_lowercase();
    let name_lower = verb.name.to_ascii_lowercase();
    let quoted_names = [
        format!("\"{name_lower}\""),
        format!("'{name_lower}'"),
        format!("`{name_lower}`"),
    ];
    if quoted_names
        .iter()
        .any(|pattern| intent_lower.contains(pattern))
    {
        return true;
    }
    (verb.name.contains('-') || verb.name.contains('_'))
        && intent
            .split(|character: char| {
                !(character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
            })
            .any(|token| token.eq_ignore_ascii_case(&verb.name))
}

fn access_intent_clauses(intent: &str) -> Vec<String> {
    intent
        .to_ascii_lowercase()
        .replace([',', ';'], "\n")
        .replace(" and ", "\n")
        .replace(" plus ", "\n")
        .replace(" then ", "\n")
        .replace(" before ", "\n")
        .replace(" after ", "\n")
        .replace(" with ", "\n")
        .lines()
        .map(str::trim)
        .filter(|clause| !clause.is_empty())
        .map(str::to_string)
        .collect()
}

fn explicitly_named_verbs_in_clause<'a>(clause: &str, verbs: &'a [Verb]) -> Vec<&'a Verb> {
    let direct = verbs
        .iter()
        .filter(|verb| intent_mentions_verb_name(clause, verb))
        .collect::<Vec<_>>();
    if !direct.is_empty() {
        return direct;
    }

    const REQUEST_TERMS: &[&str] = &[
        "a", "access", "allow", "an", "catalog", "command", "commands", "for", "i", "in", "is",
        "my", "need", "of", "on", "our", "please", "task", "tasks", "that", "the", "this", "to",
        "use", "verb", "verbs", "want", "whether", "with", "work",
    ];
    let terms = clause
        .split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        })
        .filter(|term| !term.is_empty())
        .filter(|term| !REQUEST_TERMS.contains(&term.to_ascii_lowercase().as_str()))
        .collect::<Vec<_>>();
    if let [name] = terms.as_slice() {
        return verbs
            .iter()
            .filter(|verb| verb.name.eq_ignore_ascii_case(name))
            .collect();
    }
    Vec::new()
}

fn clause_without_verb_names(clause: &str, verbs: &[&Verb]) -> String {
    clause
        .split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        })
        .filter(|token| {
            !token.is_empty()
                && !verbs
                    .iter()
                    .any(|verb| token.eq_ignore_ascii_case(&verb.name))
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn semantic_intent_terms(value: &str) -> std::collections::BTreeSet<String> {
    const STOP_WORDS: &[&str] = &[
        "a", "an", "for", "in", "is", "of", "on", "please", "that", "the", "this", "to", "whether",
    ];
    value
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|term| !term.is_empty())
        .map(str::to_ascii_lowercase)
        .filter(|term| !STOP_WORDS.contains(&term.as_str()))
        .map(|term| match term.as_str() {
            "check" | "checking" | "get" | "show" | "view" => "inspect".to_string(),
            "healthy" | "health" => "status".to_string(),
            _ if term.len() > 4 && term.ends_with('s') => term[..term.len() - 1].to_string(),
            _ => term,
        })
        .collect()
}

fn semantic_intent_score(intent: &str, verb: &Verb) -> Option<usize> {
    let intent = semantic_intent_terms(intent);
    if intent.len() < 2 {
        return None;
    }
    [
        verb.name.replace('-', " "),
        verb.description.clone(),
        verb.source_prose.clone().unwrap_or_default(),
    ]
    .into_iter()
    .filter_map(|candidate| {
        let candidate = semantic_intent_terms(&candidate);
        let intersection = intent.intersection(&candidate).count();
        let union = intent.union(&candidate).count();
        (intersection >= 2 && intersection * 100 >= union * 70)
            .then_some(intersection * 1_000 / union.max(1))
    })
    .max()
}

fn unique_semantic_intent_match<'a>(intent: &str, verbs: &'a [Verb]) -> Option<&'a Verb> {
    let mut semantic = verbs
        .iter()
        .filter_map(|verb| semantic_intent_score(intent, verb).map(|score| (score, verb)))
        .collect::<Vec<_>>();
    semantic.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| left.1.name.cmp(&right.1.name))
    });
    let (best_score, best) = semantic.first()?;
    semantic
        .get(1)
        .is_none_or(|second| second.0 < *best_score)
        .then_some(*best)
}

#[cfg(test)]
mod semantic_intent_tests {
    use super::*;

    fn fixture_verb(name: &str, description: &str) -> Verb {
        Verb {
            name: name.to_string(),
            description: description.to_string(),
            binary: "fixture-tool".to_string(),
            args: Vec::new(),
            baseline: false,
            coverage: Vec::new(),
            credential_plan: None,
            params: std::collections::BTreeMap::new(),
            consequence: guard::gating::Reversibility::Reversible,
            revert: None,
            hold: false,
            trusted: true,
            prompt_context: None,
            exec_timeout_secs: None,
            source_prose: None,
            evidence: None,
            auto_promoted: false,
            promotion_stamp: None,
        }
    }

    #[test]
    fn paraphrase_selects_existing_inspection_verb() {
        let inspect = fixture_verb("ssh-inspect", "Inspect the fake SSH service");
        assert!(
            semantic_intent_score("Check whether the fake SSH service is healthy", &inspect)
                .is_some()
        );
    }

    #[test]
    fn distinct_action_does_not_reuse_inspection_verb() {
        let inspect = fixture_verb("ssh-inspect", "Inspect the fake SSH service");
        assert!(semantic_intent_score("Restart the fake SSH service", &inspect).is_none());
    }

    #[test]
    fn prose_can_select_multiple_catalog_verbs_by_exact_name() {
        let inspect = fixture_verb("inspect-service", "Inspect the service");
        let restart = fixture_verb("restart-service", "Restart the service");
        let intent = "Use `inspect-service` and restart-service for this task.";
        assert!(intent_mentions_verb_name(intent, &inspect));
        assert!(intent_mentions_verb_name(intent, &restart));
    }
}

async fn reduce_access_intent(
    server: &ServerContext,
    caller: &CallerIdentity,
    evaluator_scope: &str,
    intent: &str,
    observed_argv: Option<(&str, &[String])>,
) -> Result<(Vec<Verb>, Vec<Verb>), String> {
    if let Some((binary, args)) = observed_argv {
        preflight_synthesized_api_policy(server, binary, args).await?;
        let candidate = guard::gating::verb::Verb {
            name: "access-generated-pending".to_string(),
            description: String::new(),
            binary: binary.to_string(),
            args: args.to_vec(),
            baseline: false,
            coverage: Vec::new(),
            credential_plan: None,
            params: std::collections::BTreeMap::new(),
            consequence: guard::gating::Reversibility::Irreversible,
            revert: None,
            hold: false,
            trusted: false,
            prompt_context: None,
            exec_timeout_secs: None,
            source_prose: None,
            evidence: None,
            auto_promoted: false,
            promotion_stamp: None,
        };
        return reduce_generated_access_candidate(server, caller, candidate, false).await;
    }
    let catalog = server
        .refresh_and_lease_verb_catalog_for_use("access proposal selection")
        .await
        .map_err(|error| format!("verb catalog authority is unavailable: {error}"))?;
    let existing = catalog
        .list()
        .into_iter()
        .map(|verb| {
            if !verb.name.starts_with("access-generated-") {
                return Ok(verb);
            }
            let mut proposal = verb;
            proposal.trusted = false;
            let supplied = proposal.consequence;
            let canonical = catalog
                .canonical_generated_access_verb(proposal)
                .map_err(|error| {
                    format!("stored generated access coverage was rejected: {error}")
                })?;
            if supplied != canonical.consequence {
                return Err(
                    "stored generated access coverage consequence is not canonical".to_string(),
                );
            }
            Ok(canonical)
        })
        .collect::<Result<Vec<_>, String>>()?;
    let clauses = access_intent_clauses(intent);
    let named_by_clause = clauses
        .iter()
        .map(|clause| explicitly_named_verbs_in_clause(clause, &existing))
        .collect::<Vec<_>>();
    let mut selected = named_by_clause
        .iter()
        .flatten()
        .map(|verb| verb.name.clone())
        .collect::<std::collections::BTreeSet<_>>();
    if !selected.is_empty() {
        const FILLER_TERMS: &[&str] = &[
            "access", "allow", "catalog", "command", "commands", "i", "need", "please", "run",
            "task", "tasks", "to", "use", "verb", "verbs", "want", "with", "work",
        ];
        for (clause, named) in clauses.iter().zip(named_by_clause.iter()) {
            let residual = clause_without_verb_names(clause, named);
            let terms = semantic_intent_terms(&residual);
            if terms.is_empty()
                || terms
                    .iter()
                    .all(|term| FILLER_TERMS.contains(&term.as_str()))
            {
                continue;
            }
            let exact = existing
                .iter()
                .filter(|verb| {
                    let residual_is_name = residual.trim().eq_ignore_ascii_case(&verb.name);
                    intent_matches_verb(&residual, verb)
                        && (!residual_is_name || named.iter().any(|named| named.name == verb.name))
                })
                .collect::<Vec<_>>();
            if !exact.is_empty() {
                selected.extend(exact.into_iter().map(|verb| verb.name.clone()));
                continue;
            }
            if let Some(verb) = unique_semantic_intent_match(&residual, &existing) {
                selected.insert(verb.name.clone());
                continue;
            }
            return Err(
                "access intent mixes explicit verb names with unresolved prose; name every required catalog verb explicitly or submit separate requests"
                    .to_string(),
            );
        }
        return access_reduction(
            existing
                .into_iter()
                .filter(|verb| selected.contains(&verb.name))
                .collect(),
        );
    }
    let matched = existing
        .iter()
        .filter(|verb| intent_matches_verb(intent, verb))
        .cloned()
        .collect::<Vec<_>>();
    if !matched.is_empty() {
        return access_reduction(matched);
    }
    if let Some(best) = unique_semantic_intent_match(intent, &existing) {
        return access_reduction(vec![best.clone()]);
    }

    drop(catalog);
    let admission_scope = format!("access-synthesis:{evaluator_scope}");
    let evaluator_permit = server
        .state
        .command_admission
        .admit_evaluator(&admission_scope)
        .map_err(|reason| format!("access request synthesis throttled: {reason}"))?;
    let candidate_result = server
        .state
        .evaluator
        .synthesize_verb(intent, None, &[])
        .await;
    server.state.command_admission.complete_evaluator(
        &admission_scope,
        candidate_result.is_err(),
        true,
    );
    drop(evaluator_permit);
    let candidate = candidate_result.map_err(|error| {
        format!("access intent could not be reduced to typed coverage: {error}")
    })?;
    reduce_generated_access_candidate(server, caller, candidate, true).await
}

async fn reduce_generated_access_candidate(
    server: &ServerContext,
    _caller: &CallerIdentity,
    mut candidate: Verb,
    run_admission_preflight: bool,
) -> Result<(Vec<Verb>, Vec<Verb>), String> {
    candidate.baseline = false;
    candidate.trusted = false;
    candidate = guard::gating::verb::normalize_generated_access_verb(candidate)
        .map_err(|error| format!("synthesized access coverage was rejected: {error}"))?;
    // A pending request must carry the fail-closed consequence derived from
    // the generated matcher alone. Operator coverage can refine the class
    // when approved and installed, but must not make an unreviewed proposal
    // look safer than its own executable shape proves.
    candidate.consequence = canonical_generated_access_consequence(&candidate);

    let catalog = server
        .refresh_and_lease_verb_catalog_for_use("generated access proposal validation")
        .await
        .map_err(|error| format!("verb catalog authority is unavailable: {error}"))?;
    let existing = catalog
        .list()
        .into_iter()
        .map(|verb| {
            if !verb.name.starts_with("access-generated-") {
                return Ok(verb);
            }
            let mut proposal = verb;
            proposal.trusted = false;
            let supplied = proposal.consequence;
            let proposal = catalog
                .canonical_generated_access_verb(proposal)
                .map_err(|error| {
                    format!("stored generated access coverage was rejected: {error}")
                })?;
            if supplied != proposal.consequence {
                return Err(
                    "stored generated access coverage consequence is not canonical".to_string(),
                );
            }
            Ok(proposal)
        })
        .collect::<Result<Vec<_>, String>>()?;
    candidate.name = generated_access_verb_name(&candidate);
    if let Some(reused) = existing.iter().find(|verb| {
        generated_access_matcher_shape(verb) == generated_access_matcher_shape(&candidate)
    }) {
        if run_admission_preflight {
            preflight_synthesized_verb_structural(server, reused).await?;
        }
        return access_reduction(vec![reused.clone()]);
    }
    catalog
        .validate_candidate(&candidate)
        .map_err(|error| format!("invalid non-baseline access coverage: {error}"))?;
    if run_admission_preflight {
        preflight_synthesized_verb_structural(server, &candidate).await?;
    }
    Ok((vec![candidate.clone()], vec![candidate]))
}

/// Split a reduction into the coverage it authorizes and the coverage that has
/// to be reviewed again. Generated matchers are request-owned authority rather
/// than operator-authored catalog policy, so an intent that resolves to one
/// retains it as a proposal however the reduction found it: by explicit name,
/// by matching prose, or by an identical matcher shape.
fn access_reduction(matched: Vec<Verb>) -> Result<(Vec<Verb>, Vec<Verb>), String> {
    let mut proposed = Vec::new();
    let mut reduced = Vec::with_capacity(matched.len());
    for verb in matched {
        if !verb.name.starts_with("access-generated-") {
            reduced.push(verb);
            continue;
        }
        let mut proposal = verb;
        proposal.trusted = false;
        let proposal = guard::gating::verb::normalize_generated_access_verb(proposal)
            .map_err(|error| format!("stored generated access coverage was rejected: {error}"))?;
        proposed.push(proposal.clone());
        reduced.push(proposal);
    }
    Ok((reduced, proposed))
}

fn access_capability(catalog: &VerbCatalog, verb: &Verb) -> Option<AccessCapability> {
    let mut projected = verb.clone();
    if verb.name.starts_with("access-generated-") {
        let mut proposal = verb.clone();
        proposal.trusted = false;
        let serialized = serde_json::to_value(proposal).ok()?;
        let proposal =
            guard::gating::verb::parse_normalized_generated_access_verb(&serialized).ok()?;
        projected = catalog.canonical_generated_access_verb(proposal).ok()?;
        if projected.consequence != verb.consequence {
            return None;
        }
    }
    let matcher = generated_access_matcher_shape(&projected);
    Some(AccessCapability {
        verb: projected.name.clone(),
        description: redact_output_text(&projected.description),
        matcher_digest: generated_access_matcher_digest(&matcher),
        matcher,
        consequence: projected.consequence.as_str().to_string(),
        credential_plan: projected.credential_plan.clone(),
        baseline: projected.baseline,
        trusted: verb.trusted,
        has_revert: projected.revert.is_some(),
        evidence: projected.evidence.as_deref().map(redact_output_text),
    })
}

#[cfg(test)]
mod access_capability_tests {
    use super::*;
    use guard::gating::verb::ParamSpec;

    #[test]
    fn generated_capability_uses_only_the_canonical_proposal_envelope() {
        let value = ["q", "7"].concat();
        let mut verb = Verb {
            name: "access-generated-fixture".to_string(),
            description: format!("password={value}"),
            binary: "printf".to_string(),
            args: vec!["status".to_string()],
            baseline: true,
            coverage: Vec::new(),
            credential_plan: None,
            params: std::collections::BTreeMap::new(),
            consequence: guard::gating::Reversibility::Irreversible,
            revert: Some(guard::gating::verb::VerbCommand {
                binary: "printf".to_string(),
                args: vec!["undo".to_string()],
            }),
            hold: false,
            trusted: true,
            prompt_context: Some(format!("password={value}")),
            exec_timeout_secs: None,
            source_prose: Some(format!("password={value}")),
            evidence: Some(format!("password={value}")),
            auto_promoted: true,
            promotion_stamp: Some(format!("password={value}")),
        };
        verb = guard::gating::verb::normalize_generated_access_verb(verb).unwrap();
        verb.name = generated_access_verb_name(&verb);
        let capability = access_capability(&VerbCatalog::empty(), &verb).unwrap();
        let projection = serde_json::to_string(&capability).unwrap();
        assert!(!projection.contains(&value));
        assert_eq!(capability.description, verb.description);
        assert!(!capability.baseline);
        assert!(!capability.trusted);
        assert!(!capability.has_revert);
        assert!(capability.evidence.is_none());
    }

    #[test]
    fn generated_capability_projection_omits_sensitive_parameter_authority() {
        let value = ["q", "7"].concat();
        let mut verb = Verb {
            name: "access-generated-fixture".to_string(),
            description: "fixture".to_string(),
            binary: "printf".to_string(),
            args: vec!["inspect".to_string(), "{password}".to_string()],
            baseline: false,
            coverage: Vec::new(),
            credential_plan: None,
            params: std::collections::BTreeMap::from([(
                "password".to_string(),
                ParamSpec {
                    pattern: "^[a-z0-9]+$".to_string(),
                    required: false,
                    default: Some(value.clone()),
                    allow_dash: false,
                },
            )]),
            consequence: guard::gating::Reversibility::Irreversible,
            revert: None,
            hold: false,
            trusted: false,
            prompt_context: None,
            exec_timeout_secs: None,
            source_prose: None,
            evidence: None,
            auto_promoted: false,
            promotion_stamp: None,
        };
        verb.name = generated_access_verb_name(&verb);
        assert!(access_capability(&VerbCatalog::empty(), &verb).is_none());
    }

    #[test]
    fn generated_capability_projection_omits_sensitive_provenance_stamps() {
        let value = ["q", "7"].concat();
        let mut verb = Verb {
            name: "access-generated-fixture".to_string(),
            description: "fixture".to_string(),
            binary: "printf".to_string(),
            args: vec!["status".to_string()],
            baseline: false,
            coverage: vec![VerbCoverageCell {
                name: "exact".to_string(),
                action: CoverageAction::Evaluate,
                command_path: Vec::new(),
                required_args: Vec::new(),
                forbidden_args: Vec::new(),
                min_args: Some(1),
                max_args: Some(1),
                options: Vec::new(),
                target: None,
                inventory: None,
                namespace: None,
                fanout: None,
                cwd: None,
                environment: Vec::new(),
                override_marker: None,
                sticky: false,
                provenance: Some(CoverageProvenance {
                    source: "fixture".to_string(),
                    evidence: Vec::new(),
                    regime_stamp: format!("password={value}"),
                    prompt_stamp: "safe-prompt".to_string(),
                    model_stamp: "safe-model".to_string(),
                    generated_unix: 1,
                    probes: Vec::new(),
                    observation_replays: Vec::new(),
                }),
            }],
            credential_plan: None,
            params: std::collections::BTreeMap::new(),
            consequence: guard::gating::Reversibility::Irreversible,
            revert: None,
            hold: false,
            trusted: false,
            prompt_context: None,
            exec_timeout_secs: None,
            source_prose: None,
            evidence: None,
            auto_promoted: false,
            promotion_stamp: None,
        };
        verb.name = generated_access_verb_name(&verb);
        assert!(access_capability(&VerbCatalog::empty(), &verb).is_none());
    }
}

async fn capabilities_for(server: &ServerContext, names: &[String]) -> Vec<AccessCapability> {
    let catalog = server.state.verbs.read().await;
    names
        .iter()
        .filter_map(|name| catalog.get(name))
        .filter_map(|verb| access_capability(&catalog, verb))
        .collect()
}

async fn capabilities_for_request(
    server: &ServerContext,
    request: &GrantRequest,
) -> Vec<AccessCapability> {
    let Ok(proposed) = proposed_access_verbs(request) else {
        tracing::warn!("invalid proposed access coverage; omitting request capabilities");
        return Vec::new();
    };
    let proposed = proposed
        .into_iter()
        .map(|verb| (verb.name.clone(), verb))
        .collect::<std::collections::BTreeMap<_, _>>();
    let catalog = server.state.verbs.read().await;
    request
        .authority_verbs
        .iter()
        .filter_map(|name| catalog.get(name).or_else(|| proposed.get(name)))
        .filter_map(|verb| access_capability(&catalog, verb))
        .collect()
}

pub(super) async fn install_approved_access_verbs(server: &ServerContext) -> Result<(), String> {
    let active_tokens = server
        .state
        .sessions
        .read()
        .await
        .list()
        .into_iter()
        .map(|summary| summary.token)
        .collect::<std::collections::BTreeSet<_>>();
    let proposals = {
        let requests = server.state.grant_requests.read().await;
        let mut proposals = Vec::new();
        for request in requests.values().filter(|request| {
            request.status == GrantRequestStatus::Approved
                && active_tokens.contains(&request.session_token)
        }) {
            proposals.extend(proposed_access_verbs(request)?);
        }
        proposals
    };
    let mut catalog = server.state.verbs.write().await;
    for verb in proposals {
        catalog
            .upsert_access_verb(verb)
            .map_err(|error| format!("failed to restore approved access coverage: {error}"))?;
    }
    Ok(())
}

pub(super) async fn validate_durable_access_provenance(
    server: &ServerContext,
) -> Result<(), String> {
    let requests = server.state.grant_requests.read().await.clone();
    let sessions = server.state.sessions.read().await.grants_snapshot();
    for (token, grant) in sessions {
        if !grant.scope.access_managed {
            return Err(format!(
                "active legacy bearer session {} has no principal-bound access provenance; revoke it and use guard access request",
                session_reference(&token)
            ));
        }
        let SessionOwner::Principal(owner) = &grant.owner else {
            return Err(format!(
                "access session {} has no authenticated owner",
                session_reference(&token)
            ));
        };
        if grant.scope.access_grants.is_empty() {
            return Err(format!(
                "access session {} has no approved request provenance",
                session_reference(&token)
            ));
        }
        let mut seen_requests = std::collections::BTreeSet::new();
        for access in &grant.scope.access_grants {
            if !seen_requests.insert(access.request.as_str()) {
                return Err(format!(
                    "access session {} contains duplicate request provenance {}",
                    session_reference(&token),
                    access.request
                ));
            }
            if access.pending {
                return Err(format!(
                    "access session {} contains an uncommitted request grant {}",
                    session_reference(&token),
                    access.request
                ));
            }
            let request = requests.get(&access.request).ok_or_else(|| {
                format!(
                    "access session {} references missing request {}",
                    session_reference(&token),
                    access.request
                )
            })?;
            validate_access_request_shape(request).map_err(|error| {
                format!(
                    "access session {} rejected durable request {}: {error}",
                    session_reference(&token),
                    access.request
                )
            })?;
            if request.status != GrantRequestStatus::Approved
                || request.session_token != token
                || request
                    .requester
                    .as_ref()
                    .is_none_or(|requester| !requester.eq_ci(owner))
            {
                return Err(format!(
                    "access session {} disagrees with approved request {}",
                    session_reference(&token),
                    access.request
                ));
            }
            let mut expected_verbs = request.authority_verbs.clone();
            expected_verbs.sort();
            expected_verbs.dedup();
            let valid_use_policy = match (access.use_limit, access.remaining_uses) {
                (None, None) => true,
                (Some(limit), Some(remaining)) => remaining <= limit,
                _ => false,
            };
            if access.verbs != expected_verbs
                || access.use_limit != request.requested_uses
                || !valid_use_policy
            {
                return Err(format!(
                    "access session {} use policy disagrees with approved request {}",
                    session_reference(&token),
                    access.request
                ));
            }
        }
        if grant.activated_verbs.iter().any(|verb| {
            !grant
                .scope
                .access_grants
                .iter()
                .any(|access| access.verbs.contains(verb))
        }) {
            return Err(format!(
                "access session {} contains authority without request provenance",
                session_reference(&token)
            ));
        }
    }
    Ok(())
}

fn approval_options(handle: &str, audience: &AccessAudience, one_shot: bool) -> Vec<String> {
    if !audience.is_operator {
        return vec![format!(
            "ask your admin to approve request {handle} (see guard access show {handle})"
        )];
    }

    if one_shot {
        return vec![format!("guard access approve {handle} --once")];
    }

    vec![
        format!("guard access approve {handle}"),
        format!("guard access approve {handle} --once"),
        format!("guard access approve {handle} --uses 3"),
    ]
}

pub(super) fn approval_guidance(
    server: &ServerContext,
    caller: &CallerIdentity,
    handle: &str,
    one_shot: bool,
) -> String {
    let audience = AccessAudience::from_caller(server, caller);
    let options = approval_options(handle, &audience, one_shot);
    if audience.is_operator && !one_shot {
        format!(
            "approve: {}\nonce: {}\nbounded: {}",
            options[0], options[1], options[2]
        )
    } else if audience.is_operator {
        format!("approve: {}", options[0])
    } else {
        options[0].clone()
    }
}

/// Canonical access-managed session for a principal. Principal identity is
/// case-insensitive so Windows SID casing cannot split one owner into multiple
/// authority scopes.
pub(super) fn access_token_for_principal_ci(
    registry: &crate::session::SessionRegistry,
    principal: &PrincipalKey,
) -> Option<String> {
    let case_insensitive = registry
        .list()
        .into_iter()
        .filter(|summary| {
            summary.scope.access_managed
                && matches!(
                    &summary.owner,
                    SessionOwner::Principal(owner) if owner.eq_ci(principal)
                )
        })
        .min_by(|left, right| {
            left.granted_at
                .cmp(&right.granted_at)
                .then(left.token.cmp(&right.token))
        })
        .map(|summary| summary.token);
    // Keep the registry's exact-case selector exercised as a compatibility
    // fallback. The case-insensitive scan remains authoritative and
    // deterministic when SID casing differs.
    case_insensitive.or_else(|| registry.access_token_for_principal(principal))
}

fn access_request_key_eq_ci(existing: &GrantRequest, request: &GrantRequest) -> bool {
    if !scope_eq(&existing.requester, &request.requester) {
        return false;
    }
    let mut normalized = existing.clone();
    normalized.requester = request.requester.clone();
    matches!(
        (
            normalized.canonical_access_key(),
            request.canonical_access_key()
        ),
        (Ok(left), Ok(right)) if left == right
    )
}

pub(super) fn session_token_for_approval_snapshot(
    registry: &crate::session::SessionRegistry,
    snapshot: &guard::gating::approval::ApprovalSnapshot,
) -> Option<String> {
    let fingerprint = snapshot.session_fingerprint.as_deref()?;
    let revision = snapshot.session_revision.as_deref()?;
    let principal = snapshot.principal.as_ref()?;
    registry.list().into_iter().find_map(|summary| {
        let owned = matches!(
            &summary.owner,
            SessionOwner::Principal(owner) if owner.eq_ci(principal)
        );
        (owned
            && audit_session_fingerprint(Some(&summary.token)) == fingerprint
            && registry.effective_revision_key(&summary.token).as_deref() == Some(revision))
        .then_some(summary.token)
    })
}

fn approval_has_live_command_session_binding(approval: &Approval) -> bool {
    approval.snapshot.session_fingerprint.is_some()
        && !super::gate_runtime::is_api_proxy_sentinel(&approval.snapshot.binary)
}

fn access_use_policy(uses: Option<(Option<u64>, Option<u64>)>) -> &'static str {
    match uses {
        Some((Some(_), _)) => "bounded",
        Some((None, _)) => "unlimited",
        None => "unavailable",
    }
}

#[derive(Clone)]
pub(super) struct AccessAudience {
    is_operator: bool,
    principal: Option<PrincipalKey>,
}

impl AccessAudience {
    pub(super) fn from_caller(server: &ServerContext, caller: &CallerIdentity) -> Self {
        Self {
            is_operator: caller_is_session_admin(server, caller),
            principal: caller.principal(),
        }
    }

    pub(super) fn is_operator(&self) -> bool {
        self.is_operator
    }

    fn can_view_principal(&self, owner: &Option<PrincipalKey>) -> bool {
        owner.is_some() && (self.is_operator || scope_eq(owner, &self.principal))
    }

    fn can_view_session(&self, summary: &SessionGrantSummary) -> bool {
        self.is_operator
            || matches!(
                &summary.owner,
                SessionOwner::Principal(owner)
                    if self.principal.as_ref().is_some_and(|caller| owner.eq_ci(caller))
            )
    }
}

async fn approved_access_request_is_usable(server: &ServerContext, request: &GrantRequest) -> bool {
    if request.status != GrantRequestStatus::Approved || request.session_token.is_empty() {
        return false;
    }
    matches!(
        server
            .state
            .sessions
            .read()
            .await
            .access_grant_uses(&request.session_token, &request.handle),
        Some((None, None)) | Some((Some(_), Some(1..)))
    )
}

/// A release-class hold carries no executable snapshot: it is an API request
/// parked in the proxy under the daemon's own principal, and approving it
/// releases that request rather than spawning anything. A caller cannot steer a
/// real command into the class by naming the sentinel binary, because the row
/// must also be owned by the daemon principal, which peer credentials assign
/// only to the daemon's own gate sink.
fn is_release_class(server: &ServerContext, snapshot: &ApprovalSnapshot) -> bool {
    is_api_proxy_sentinel(&snapshot.binary)
        && matches!(
            &snapshot.principal,
            Some(principal) if server.config.daemon_principal.eq_ci(principal)
        )
}

/// The consequence class of approving one hold. Holds are never grant-class:
/// they either arm a frozen snapshot or release a parked API request.
fn approval_consequence(server: &ServerContext, approval: &Approval) -> &'static str {
    if is_release_class(server, &approval.snapshot) {
        CONSEQUENCE_RELEASE
    } else {
        CONSEQUENCE_ARM
    }
}

/// Consequence class of one reference, resolved from daemon state. Grant
/// requests are grant-class; holds are arm- or release-class. An unknown
/// reference has no class.
async fn consequence_for_reference(server: &ServerContext, reference: &str) -> String {
    if server
        .state
        .grant_requests
        .read()
        .await
        .contains_key(reference)
    {
        return CONSEQUENCE_GRANT.to_string();
    }
    match server.state.approvals.read().await.get(reference) {
        Some(approval) => approval_consequence(server, approval).to_string(),
        None => String::new(),
    }
}

/// The next command this audience should run against a hold. The operator
/// decides and then reads the transcript; the requester waits and then resumes.
fn hold_next_action(handle: &str, state: &str, is_operator: bool) -> String {
    match (state, is_operator) {
        ("pending", true) => format!("guard access approve {handle} --once"),
        ("pending", false) => format!("guard approval show {handle} --wait"),
        ("armed", true) => format!("guard approval show {handle} --wait"),
        ("armed", false) => format!("guard approval resume {handle}"),
        _ => format!("guard approval show {handle}"),
    }
}

async fn access_item_for_approval(
    server: &ServerContext,
    approval: &Approval,
    audience: &AccessAudience,
) -> AccessItem {
    debug_assert!(audience.can_view_principal(&approval.snapshot.principal));
    let projected_expired =
        approval.status == ApprovalStatus::Pending && now_unix() >= approval.deadline_unix();
    let requester = approval
        .snapshot
        .principal
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_else(|| "unknown".to_string());
    let scope = approval
        .snapshot
        .verb_name
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let session = if approval_has_live_command_session_binding(approval) {
        let sessions = server.state.sessions.read().await;
        session_token_for_approval_snapshot(&sessions, &approval.snapshot).and_then(|token| {
            sessions
                .list()
                .into_iter()
                .find(|summary| summary.token == token)
        })
    } else {
        None
    };
    let projected_revoked = approval.status == ApprovalStatus::Pending
        && approval_has_live_command_session_binding(approval)
        && session.is_none();
    let projected_state = if projected_revoked {
        "revoked"
    } else if projected_expired {
        "expired"
    } else if approval_is_armed(approval) {
        "armed"
    } else {
        approval.status.as_str()
    };
    let target = session
        .as_ref()
        .map(|summary| session_reference(&summary.token))
        .unwrap_or_else(|| format!("agent:{requester}"));
    let grant_uses = if let Some(summary) = session.as_ref() {
        server
            .state
            .sessions
            .read()
            .await
            .access_grant_uses(&summary.token, &approval.handle)
    } else {
        None
    };
    let remaining_uses = grant_uses.and_then(|(_, remaining)| remaining);
    let expires_unix = session
        .as_ref()
        .and_then(|summary| summary.expires_at)
        .or_else(|| Some(approval.deadline_unix()));
    let awaiting_decision = approval.status == ApprovalStatus::Pending
        && !projected_expired
        && !projected_revoked
        && !approval_is_armed(approval);
    AccessItem {
        reference: approval.handle.clone(),
        kind: "hold".to_string(),
        requester: requester.clone(),
        target,
        effective_scope: scope.clone(),
        expires_unix,
        remaining_uses,
        // Preserve the baseline budget contract. A pending hold is
        // unselected with a bounded one-use default; the consequence explains
        // that approval arms the snapshot rather than replacing the budget.
        use_policy: if awaiting_decision {
            "unselected"
        } else {
            access_use_policy(grant_uses)
        }
        .to_string(),
        consequence: approval_consequence(server, approval).to_string(),
        default_use_policy: awaiting_decision.then(|| "bounded".to_string()),
        default_uses: awaiting_decision.then_some(1),
        state: projected_state.to_string(),
        next_action: hold_next_action(&approval.handle, projected_state, audience.is_operator),
        approval_options: if awaiting_decision {
            approval_options(&approval.handle, audience, true)
        } else {
            Vec::new()
        },
        intent: Some(redact_output_text(&approval.reason)),
        capabilities: capabilities_for(server, &scope).await,
        decided_reason: if projected_revoked {
            Some("originating access session was revoked".to_string())
        } else {
            approval.decided_reason.as_deref().map(redact_output_text)
        },
    }
}

async fn access_item_for_request(
    server: &ServerContext,
    request: &GrantRequest,
    audience: &AccessAudience,
) -> AccessItem {
    debug_assert!(audience.can_view_principal(&request.requester));
    let mut target = request
        .target
        .clone()
        .unwrap_or_else(|| "unassigned".to_string());
    let mut remaining_uses = None;
    let mut grant_uses = None;
    let mut expires_unix = Some(request.expires_unix);
    let mut active_session_found = false;
    if !request.session_token.is_empty() {
        if let Some(summary) = server
            .state
            .sessions
            .read()
            .await
            .list()
            .into_iter()
            .find(|summary| summary.token == request.session_token)
        {
            active_session_found = true;
            target = summary
                .scope
                .label
                .clone()
                .unwrap_or_else(|| session_reference(&summary.token));
            grant_uses = server
                .state
                .sessions
                .read()
                .await
                .access_grant_uses(&summary.token, &request.handle);
            remaining_uses = grant_uses.and_then(|(_, remaining)| remaining);
            expires_unix = summary.expires_at;
        }
    }
    let expired = request.status == GrantRequestStatus::Pending
        && (request.expires_unix == 0 || now_unix() >= request.expires_unix);
    let orphaned = request.status == GrantRequestStatus::Approved
        && !request.session_token.is_empty()
        && !active_session_found;
    let state = if expired {
        "expired"
    } else if orphaned {
        "orphaned"
    } else {
        request.status.as_str()
    };
    let awaiting_decision = request.status == GrantRequestStatus::Pending && !expired;
    AccessItem {
        reference: request.handle.clone(),
        kind: "request".to_string(),
        requester: request
            .requester
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "legacy-session".to_string()),
        target,
        effective_scope: request.authority_verbs.clone(),
        expires_unix,
        remaining_uses,
        use_policy: if awaiting_decision {
            "unselected"
        } else {
            access_use_policy(grant_uses)
        }
        .to_string(),
        consequence: CONSEQUENCE_GRANT.to_string(),
        // These fields preserve the old-daemon detail fallback while the
        // consequence-aware use policy tells new clients what is pending.
        default_use_policy: awaiting_decision.then(|| {
            if request.requested_uses.is_some() {
                "bounded".to_string()
            } else {
                "unlimited".to_string()
            }
        }),
        default_uses: awaiting_decision
            .then_some(request.requested_uses)
            .flatten(),
        state: state.to_string(),
        next_action: if request.status == GrantRequestStatus::Pending
            && !expired
            && audience.is_operator
        {
            format!("guard access approve {}", request.handle)
        } else {
            format!("guard access show {}", request.handle)
        },
        approval_options: if awaiting_decision {
            approval_options(&request.handle, audience, false)
        } else {
            Vec::new()
        },
        intent: Some(redact_output_text(&request.justification)),
        capabilities: capabilities_for_request(server, request).await,
        decided_reason: if orphaned {
            Some("approved authority is no longer attached to an active access session".to_string())
        } else {
            request.decided_reason.as_deref().map(redact_output_text)
        },
    }
}

async fn access_item_for_session(
    server: &ServerContext,
    summary: &SessionGrantSummary,
    audience: &AccessAudience,
) -> AccessItem {
    debug_assert!(audience.can_view_session(summary));
    let reference = session_reference(&summary.token);
    let target = summary
        .scope
        .label
        .clone()
        .unwrap_or_else(|| reference.clone());
    let aggregate_uses = server
        .state
        .sessions
        .read()
        .await
        .aggregate_access_uses(&summary.token);
    let remaining_uses = aggregate_uses.flatten();
    let state = if remaining_uses == Some(0) {
        "exhausted"
    } else {
        "active"
    };
    let mut intents = server
        .state
        .grant_requests
        .read()
        .await
        .values()
        .filter(|request| {
            request.status == GrantRequestStatus::Approved && request.session_token == summary.token
        })
        .map(|request| redact_output_text(&request.justification))
        .collect::<Vec<_>>();
    intents.sort();
    intents.dedup();
    AccessItem {
        reference: reference.clone(),
        kind: "session".to_string(),
        requester: summary.owner.label(),
        target,
        effective_scope: summary.activated_verbs.clone(),
        expires_unix: summary.expires_at,
        remaining_uses,
        use_policy: match aggregate_uses {
            Some(Some(_)) => "bounded",
            Some(None) => "unlimited",
            None => "unavailable",
        }
        .to_string(),
        consequence: String::new(),
        default_use_policy: None,
        default_uses: None,
        state: state.to_string(),
        next_action: format!("guard access show {reference}"),
        approval_options: Vec::new(),
        intent: (!intents.is_empty()).then(|| intents.join("; ")),
        capabilities: capabilities_for(server, &summary.activated_verbs).await,
        decided_reason: None,
    }
}

pub(super) async fn submit_access_request(
    server: &ServerContext,
    caller: &CallerIdentity,
    explicit_target: Option<&str>,
    intent: &str,
    requested_uses: Option<u64>,
    observed_argv: Option<(&str, &[String])>,
) -> Result<AccessItem, String> {
    let audience = AccessAudience::from_caller(server, caller);
    let intent = validate_access_intent(intent)?;
    let intent = redact_output_text(&intent);
    let caller_principal = if explicit_target.is_none() {
        Some(authenticated_local_principal(caller)?)
    } else {
        caller.principal()
    };
    let (
        session_token,
        requester,
        mut target,
        mut active_verbs,
        mut usable_access_verbs,
        mut session_revision,
        mut session_expiry,
    ) = {
        let sessions = server.state.sessions.read().await;
        let token = match explicit_target {
            Some(target) => sessions
                .token_for_access_target(target)?
                .ok_or_else(|| format!("unknown access target: '{target}'"))?,
            None => access_token_for_principal_ci(
                &sessions,
                caller_principal.as_ref().ok_or_else(|| {
                    "access requests require an authenticated local principal".to_string()
                })?,
            )
            .unwrap_or_default(),
        };
        if token.is_empty() {
            let caller_principal = caller_principal.clone().ok_or_else(|| {
                "access requests require an authenticated local principal".to_string()
            })?;
            (
                None,
                caller_principal.clone(),
                format!("agent:{caller_principal}"),
                Vec::new(),
                Vec::new(),
                None,
                None,
            )
        } else {
            if explicit_target.is_some() && !sessions.is_access_managed(&token) {
                return Err(
                    "access extend accepts access-managed targets only; request a new access session"
                        .to_string(),
                );
            }
            let snapshot = access_target_snapshot(&sessions, &token)?;
            (
                Some(token.clone()),
                snapshot.requester,
                snapshot.target,
                snapshot.active_verbs,
                snapshot.usable_access_verbs,
                snapshot.revision,
                snapshot.expires_at,
            )
        }
    };

    if observed_argv.is_none() && requested_uses.is_some() {
        if let Some(existing) = server
            .state
            .grant_requests
            .read()
            .await
            .values()
            .find(|existing| {
                existing
                    .requester
                    .as_ref()
                    .is_some_and(|principal| principal.eq_ci(&requester))
                    && existing.session_token == session_token.as_deref().unwrap_or_default()
                    && normalize_access_intent(&existing.justification)
                        == normalize_access_intent(&intent)
                    && existing.requested_uses == requested_uses
                    && existing.status == GrantRequestStatus::Approved
            })
            .cloned()
        {
            if explicit_target.is_some()
                || approved_access_request_is_usable(server, &existing).await
            {
                return Ok(access_item_for_request(server, &existing, &audience).await);
            }
        }
    }

    prune_grant_requests(server).await;
    {
        let _transition = server.state.authority_transition_gate.lock().await;
        if let Some(token) = session_token.as_deref() {
            let sessions = server.state.sessions.read().await;
            let snapshot = access_target_snapshot(&sessions, token)?;
            if !snapshot.requester.eq_ci(&requester) {
                return Err("access target belongs to a different principal".to_string());
            }
            target = snapshot.target;
            active_verbs = snapshot.active_verbs;
            usable_access_verbs = snapshot.usable_access_verbs;
            session_revision = snapshot.revision;
            session_expiry = snapshot.expires_at;
        }
        if observed_argv.is_none() {
            let requests = server.state.grant_requests.read().await;
            if let Some(existing) = requests
                .values()
                .find(|existing| {
                    existing
                        .requester
                        .as_ref()
                        .is_some_and(|principal| principal.eq_ci(&requester))
                        && existing.session_token == session_token.as_deref().unwrap_or_default()
                        && normalize_access_intent(&existing.justification)
                            == normalize_access_intent(&intent)
                        && existing.requested_uses == requested_uses
                        && existing.issued_session_revision == session_revision
                        && existing.status == GrantRequestStatus::Pending
                })
                .cloned()
            {
                drop(requests);
                return Ok(access_item_for_request(server, &existing, &audience).await);
            }
            if requests.len() >= MAX_GRANT_REQUESTS {
                return Err("access request queue is full".to_string());
            }
            let pending = requests
                .values()
                .filter(|existing| {
                    existing
                        .requester
                        .as_ref()
                        .is_some_and(|principal| principal.eq_ci(&requester))
                        && existing.status == GrantRequestStatus::Pending
                })
                .count();
            if pending >= MAX_PENDING_GRANT_REQUESTS_PER_SESSION {
                return Err("access request queue is full for this principal".to_string());
            }
        }
    }

    let evaluator_scope = requester.to_string();
    let (reduced, proposed_verbs) =
        reduce_access_intent(server, caller, &evaluator_scope, &intent, observed_argv).await?;
    let _transition = server.state.authority_transition_gate.lock().await;
    if let Some(token) = session_token.as_deref() {
        let sessions = server.state.sessions.read().await;
        let snapshot = access_target_snapshot(&sessions, token)?;
        if !snapshot.requester.eq_ci(&requester) {
            return Err("access target belongs to a different principal".to_string());
        }
        target = snapshot.target;
        active_verbs = snapshot.active_verbs;
        usable_access_verbs = snapshot.usable_access_verbs;
        session_revision = snapshot.revision;
        session_expiry = snapshot.expires_at;
    }
    let mut missing = reduced
        .iter()
        .filter(|verb| {
            !verb.baseline
                && (!active_verbs.contains(&verb.name) || !usable_access_verbs.contains(&verb.name))
        })
        .map(|verb| verb.name.clone())
        .collect::<Vec<_>>();
    missing.sort();
    missing.dedup();
    let proposed_verbs = proposed_verbs_for_missing_authority(proposed_verbs, &missing);
    if missing.is_empty() && requested_uses.is_none() {
        if let Some(existing) = server
            .state
            .grant_requests
            .read()
            .await
            .values()
            .find(|existing| {
                existing
                    .requester
                    .as_ref()
                    .is_some_and(|principal| principal.eq_ci(&requester))
                    && normalize_access_intent(&existing.justification)
                        == normalize_access_intent(&intent)
                    && existing.status == GrantRequestStatus::Approved
                    && session_token
                        .as_ref()
                        .is_some_and(|token| existing.session_token == *token)
            })
            .cloned()
        {
            return Ok(access_item_for_request(server, &existing, &audience).await);
        }
        if let Some(token) = session_token {
            let summary = server
                .state
                .sessions
                .read()
                .await
                .list()
                .into_iter()
                .find(|summary| summary.token == token)
                .ok_or_else(|| "access target expired while resolving".to_string())?;
            return Ok(access_item_for_session(server, &summary, &audience).await);
        }
        let catalog = server.state.verbs.read().await;
        return Ok(AccessItem {
            reference: "baseline".to_string(),
            kind: "effective".to_string(),
            requester: requester.to_string(),
            target: "daemon-baseline".to_string(),
            effective_scope: reduced.iter().map(|verb| verb.name.clone()).collect(),
            expires_unix: None,
            remaining_uses: None,
            use_policy: "unlimited".to_string(),
            consequence: String::new(),
            default_use_policy: None,
            default_uses: None,
            state: "active".to_string(),
            next_action: "guard access list".to_string(),
            approval_options: Vec::new(),
            intent: Some(intent),
            capabilities: reduced
                .iter()
                .filter_map(|verb| access_capability(&catalog, verb))
                .collect(),
            decided_reason: None,
        });
    }

    let authority_verbs = reduced
        .iter()
        .map(|verb| verb.name.clone())
        .collect::<Vec<_>>();
    let mut request = GrantRequest::new_access_with_uses(
        requester.clone(),
        session_token.clone(),
        target,
        GrantRequestDelta {
            activated_verbs: missing,
            ..GrantRequestDelta::default()
        },
        intent,
        requested_uses,
    )
    .map_err(|error| error.to_string())?;
    request.authority_verbs = authority_verbs;
    request.proposed_verbs = proposed_verbs
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("failed to encode proposed access coverage: {error}"))?;
    request.issued_session_revision = session_revision.clone();
    request.request_key = request
        .canonical_access_key()
        .map_err(|error| error.to_string())?;
    if let Some(expiry) = session_expiry {
        request.expires_unix = request.expires_unix.min(expiry);
    }
    if grant_request_payload_bytes(&request) > MAX_GRANT_REQUEST_PAYLOAD_BYTES {
        return Err("access request exceeds the request size limit".to_string());
    }

    if let Some(existing) = server
        .state
        .grant_requests
        .read()
        .await
        .values()
        .find(|existing| access_request_key_eq_ci(existing, &request))
        .cloned()
    {
        let reusable = (existing.status == GrantRequestStatus::Pending
            && existing.issued_session_revision == session_revision)
            || approved_access_request_is_usable(server, &existing).await;
        if reusable {
            return Ok(access_item_for_request(server, &existing, &audience).await);
        }
    }
    {
        let requests = server.state.grant_requests.read().await;
        if requests.len() >= MAX_GRANT_REQUESTS {
            return Err("access request queue is full".to_string());
        }
        let pending = requests
            .values()
            .filter(|existing| {
                existing
                    .requester
                    .as_ref()
                    .is_some_and(|principal| principal.eq_ci(&requester))
                    && existing.status == GrantRequestStatus::Pending
            })
            .count();
        if pending >= MAX_PENDING_GRANT_REQUESTS_PER_SESSION {
            return Err("access request queue is full for this principal".to_string());
        }
    }
    if let Some(store) = &server.state.session_store {
        store
            .save_grant_request(request.clone())
            .await
            .map_err(|error| format!("failed to persist access request: {error}"))?;
    }
    server
        .state
        .grant_requests
        .write()
        .await
        .insert(request.handle.clone(), request.clone());
    emit_grant_request_event(server, &request, "access_request_submitted");
    Ok(access_item_for_request(server, &request, &audience).await)
}

fn proposed_access_verbs(request: &GrantRequest) -> Result<Vec<Verb>, String> {
    if request.has_access_projection() {
        request
            .validate_principal_access_shape()
            .map_err(|error| error.to_string())
    } else {
        request
            .validated_generated_access_proposals()
            .map_err(|error| error.to_string())
    }
}

#[cfg(all(test, unix))]
type AccessApprovalLockHook = (
    std::sync::Arc<tokio::sync::Semaphore>,
    std::sync::Arc<tokio::sync::Semaphore>,
);

#[cfg(all(test, unix))]
fn access_approval_lock_hooks(
) -> &'static std::sync::Mutex<std::collections::BTreeMap<usize, AccessApprovalLockHook>> {
    static HOOKS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::BTreeMap<usize, AccessApprovalLockHook>>,
    > = std::sync::OnceLock::new();
    HOOKS.get_or_init(|| std::sync::Mutex::new(std::collections::BTreeMap::new()))
}

#[cfg(all(test, unix))]
pub(super) fn pause_access_approval_before_verb_lock_for_test(
    server: &ServerContext,
) -> AccessApprovalLockHook {
    let reached = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    let release = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    access_approval_lock_hooks().lock().unwrap().insert(
        std::sync::Arc::as_ptr(&server.state.verbs) as usize,
        (reached.clone(), release.clone()),
    );
    (reached, release)
}

#[cfg(all(test, unix))]
async fn pause_access_approval_before_verb_lock(server: &ServerContext) {
    let hook = access_approval_lock_hooks()
        .lock()
        .unwrap()
        .remove(&(std::sync::Arc::as_ptr(&server.state.verbs) as usize));
    if let Some((reached, release)) = hook {
        reached.add_permits(1);
        release.acquire().await.unwrap().forget();
    }
}

async fn reload_sessions_after_registry_conflict(
    server: &ServerContext,
    error: &anyhow::Error,
    already_retried: bool,
    operation: &str,
    baseline_revision: u64,
) -> Result<bool, String> {
    if already_retried
        || !crate::session_store::SessionStore::is_registry_generation_conflict(error)
    {
        return Ok(false);
    }
    let Some(store) = &server.state.session_store else {
        return Ok(false);
    };
    let durable = store.load_registry().await.map_err(|reload_error| {
        format!("failed to reload sessions after concurrent {operation}: {reload_error}")
    })?;
    let mut sessions = server.state.sessions.write().await;
    if sessions.revision() == baseline_revision {
        *sessions = durable;
    }
    Ok(true)
}

fn validate_access_request_shape(request: &GrantRequest) -> Result<(), String> {
    request
        .validate_principal_access_shape()
        .map(|_| ())
        .map_err(|error| error.to_string())
}

async fn approve_access_request(
    server: &ServerContext,
    handle: &str,
    uses: Option<u64>,
    audience: &AccessAudience,
) -> AccessDecisionResult {
    let owned_server = server.clone();
    let owned_handle = handle.to_string();
    let owned_audience = audience.clone();
    match tokio::spawn(async move {
        approve_access_request_owned(&owned_server, &owned_handle, uses, &owned_audience).await
    })
    .await
    {
        Ok(result) => result,
        Err(error) => AccessDecisionResult {
            request: handle.to_string(),
            success: false,
            state: "error".to_string(),
            target: None,
            remaining_uses: None,
            use_policy: "unavailable".to_string(),
            message: format!("access approval coordination failed: {error}"),
            consequence: String::new(),
        },
    }
}

async fn approve_access_request_owned(
    server: &ServerContext,
    handle: &str,
    uses: Option<u64>,
    audience: &AccessAudience,
) -> AccessDecisionResult {
    let _transition = server.state.authority_transition_gate.lock().await;
    let Some(pending) = server
        .state
        .grant_requests
        .read()
        .await
        .get(handle)
        .cloned()
    else {
        return AccessDecisionResult {
            request: handle.to_string(),
            success: false,
            state: "not_found".to_string(),
            target: None,
            remaining_uses: None,
            use_policy: "unavailable".to_string(),
            message: "unknown access request".to_string(),
            consequence: String::new(),
        };
    };
    if pending.requester.is_none() {
        return AccessDecisionResult {
            request: handle.to_string(),
            success: false,
            state: pending.status.as_str().to_string(),
            target: pending.target.clone(),
            remaining_uses: None,
            use_policy: "unavailable".to_string(),
            message: "legacy grant requests use the hidden compatibility command".to_string(),
            consequence: String::new(),
        };
    }
    if let Err(message) = validate_access_request_shape(&pending) {
        return AccessDecisionResult {
            request: handle.to_string(),
            success: false,
            state: "rejected".to_string(),
            target: pending.target.clone(),
            remaining_uses: None,
            use_policy: "unavailable".to_string(),
            message,
            consequence: String::new(),
        };
    }
    if pending.status == GrantRequestStatus::Approved {
        let item = access_item_for_request(server, &pending, audience).await;
        return AccessDecisionResult {
            request: handle.to_string(),
            success: true,
            state: "approved".to_string(),
            target: Some(item.target),
            remaining_uses: item.remaining_uses,
            use_policy: item.use_policy,
            message: "already approved; authority unchanged".to_string(),
            consequence: String::new(),
        };
    }
    if pending.status != GrantRequestStatus::Pending {
        return AccessDecisionResult {
            request: handle.to_string(),
            success: false,
            state: pending.status.as_str().to_string(),
            target: pending.target.clone(),
            remaining_uses: None,
            use_policy: "unavailable".to_string(),
            message: format!("request is already {}", pending.status.as_str()),
            consequence: String::new(),
        };
    }
    if pending.expires_unix == 0 || now_unix() >= pending.expires_unix {
        return AccessDecisionResult {
            request: handle.to_string(),
            success: false,
            state: "expired".to_string(),
            target: pending.target.clone(),
            remaining_uses: None,
            use_policy: "unavailable".to_string(),
            message: "access request expired".to_string(),
            consequence: String::new(),
        };
    }
    let proposed_verbs = match proposed_access_verbs(&pending) {
        Ok(proposed) => proposed,
        Err(message) => {
            return AccessDecisionResult {
                request: handle.to_string(),
                success: false,
                state: "rejected".to_string(),
                target: pending.target.clone(),
                remaining_uses: None,
                use_policy: "unavailable".to_string(),
                message,
                consequence: String::new(),
            }
        }
    };
    #[cfg(all(test, unix))]
    pause_access_approval_before_verb_lock(server).await;

    let mut generation_retry = false;
    loop {
        let requester = pending.requester.clone().expect("checked above");
        if let Err(error) = server.refresh_verb_catalog_for_decision().await {
            return AccessDecisionResult {
                request: handle.to_string(),
                success: false,
                state: "stale".to_string(),
                target: pending.target.clone(),
                remaining_uses: None,
                use_policy: "unavailable".to_string(),
                message: format!("verb catalog authority is unavailable: {error}"),
                consequence: String::new(),
            };
        }
        let baseline_verbs = server.state.verbs.read().await.clone();
        let mut staged_verbs = baseline_verbs.clone();
        if let Some(error) = proposed_verbs.iter().find_map(|verb| {
            staged_verbs
                .upsert_access_verb(verb.clone())
                .err()
                .map(|error| format!("failed to stage approved access coverage: {error}"))
        }) {
            return AccessDecisionResult {
                request: handle.to_string(),
                success: false,
                state: "stale".to_string(),
                target: pending.target.clone(),
                remaining_uses: None,
                use_policy: "unavailable".to_string(),
                message: error,
                consequence: String::new(),
            };
        }
        if let Some(message) = pending.delta.activated_verbs.iter().find_map(|name| {
            staged_verbs.get(name).map_or_else(
                || Some(format!("access request references unknown verb: '{name}'")),
                |verb| {
                    verb.baseline
                        .then(|| format!("access request may not activate baseline verb: '{name}'"))
                },
            )
        }) {
            return AccessDecisionResult {
                request: handle.to_string(),
                success: false,
                state: "rejected".to_string(),
                target: pending.target.clone(),
                remaining_uses: None,
                use_policy: "unavailable".to_string(),
                message,
                consequence: String::new(),
            };
        }
        let baseline_sessions = server.state.sessions.read().await.clone();
        let mut staged = baseline_sessions.clone();
        staged.purge_expired();
        let token = if pending.session_token.is_empty() {
            access_token_for_principal_ci(&staged, &requester)
                .unwrap_or_else(|| format!("{:032x}", rand::random::<u128>()))
        } else {
            pending.session_token.clone()
        };
        if !pending.session_token.is_empty() && !staged.has(&token) {
            return AccessDecisionResult {
                request: handle.to_string(),
                success: false,
                state: "revoked".to_string(),
                target: pending.target.clone(),
                remaining_uses: None,
                use_policy: "unavailable".to_string(),
                message: "access target expired or was revoked after request submission"
                    .to_string(),
                consequence: String::new(),
            };
        }
        if staged.has(&token) {
            if !matches!(
                staged.owner_for(&token),
                Some(SessionOwner::Principal(ref owner)) if owner.eq_ci(&requester)
            ) {
                return AccessDecisionResult {
                    request: handle.to_string(),
                    success: false,
                    state: "rejected".to_string(),
                    target: pending.target.clone(),
                    remaining_uses: None,
                    use_policy: "unavailable".to_string(),
                    message: "access target belongs to a different principal".to_string(),
                    consequence: String::new(),
                };
            }
            if !pending.session_token.is_empty()
                && staged.effective_revision_key(&token) != pending.issued_session_revision
            {
                return AccessDecisionResult {
                    request: handle.to_string(),
                    success: false,
                    state: "stale".to_string(),
                    target: pending.target.clone(),
                    remaining_uses: None,
                    use_policy: "unavailable".to_string(),
                    message: "access target changed after request submission".to_string(),
                    consequence: String::new(),
                };
            }
            if staged.apply_delta(&token, &pending.delta).is_none() {
                return AccessDecisionResult {
                    request: handle.to_string(),
                    success: false,
                    state: "stale".to_string(),
                    target: pending.target.clone(),
                    remaining_uses: None,
                    use_policy: "unavailable".to_string(),
                    message: "access target expired during approval".to_string(),
                    consequence: String::new(),
                };
            }
        } else {
            let expiry = now_unix().saturating_add(
                pending
                    .delta
                    .ttl_secs
                    .unwrap_or_else(default_access_ttl_secs),
            );
            let label = pending
                .target
                .clone()
                .unwrap_or_else(|| format!("agent:{requester}"));
            if !staged.grant_policy_only_access_overlay(
                token.clone(),
                requester.clone(),
                label,
                expiry,
            ) {
                return AccessDecisionResult {
                    request: handle.to_string(),
                    success: false,
                    state: "rejected".to_string(),
                    target: pending.target.clone(),
                    remaining_uses: None,
                    use_policy: "unavailable".to_string(),
                    message: "generated access token collided with an issued token".to_string(),
                    consequence: String::new(),
                };
            }
            let _ = staged.apply_delta(&token, &pending.delta);
        }
        let effective_uses = uses.or(pending.requested_uses);
        let _ = staged.install_access_grant(
            &token,
            effective_uses,
            handle.to_string(),
            pending.authority_verbs.clone(),
        );

        let mut approved = pending.clone();
        approved.session_token = token.clone();
        approved.target = Some(session_reference(&token));
        approved.requested_uses = effective_uses;
        approved.status = GrantRequestStatus::Approved;
        approved.decided_unix = Some(now_unix());
        approved.decided_reason = Some("approved by operator".to_string());
        approved.next_action = format!("guard access show {}", approved.handle);
        let next_revision = staged.effective_revision_key(&token);
        let requests = server.state.grant_requests.read().await;
        let siblings = requests
            .values()
            .filter(|sibling| sibling.handle != handle)
            .filter(|sibling| sibling.status == GrantRequestStatus::Pending)
            .filter(|sibling| {
                if pending.session_token.is_empty() {
                    sibling.session_token.is_empty()
                        && sibling
                            .requester
                            .as_ref()
                            .zip(pending.requester.as_ref())
                            .is_some_and(|(left, right)| left.eq_ci(right))
                } else {
                    sibling.session_token == pending.session_token
                        && sibling.issued_session_revision == pending.issued_session_revision
                }
            })
            .cloned()
            .collect::<Vec<_>>();
        drop(requests);
        let mut rebased_pending = Vec::with_capacity(siblings.len());
        for original in siblings {
            let mut rebased = original.clone();
            rebased.session_token = token.clone();
            rebased.issued_session_revision = next_revision.clone();
            rebased.request_key = match rebased.canonical_access_key() {
                Ok(request_key) => request_key,
                Err(error) => {
                    return AccessDecisionResult {
                        request: handle.to_string(),
                        success: false,
                        state: "error".to_string(),
                        target: pending.target.clone(),
                        remaining_uses: None,
                        use_policy: "unavailable".to_string(),
                        message: format!("failed to rebase sibling access request: {error}"),
                        consequence: String::new(),
                    };
                }
            };
            rebased_pending.push((original, rebased));
        }
        if let Some(store) = &server.state.session_store {
            if let Err(error) = store
                .commit_grant_request_approval(
                    pending.clone(),
                    approved.clone(),
                    staged.clone(),
                    rebased_pending.clone(),
                )
                .await
            {
                match reload_sessions_after_registry_conflict(
                    server,
                    &error,
                    generation_retry,
                    "access approval",
                    baseline_sessions.revision(),
                )
                .await
                {
                    Ok(true) => {
                        generation_retry = true;
                        continue;
                    }
                    Err(message) => {
                        return AccessDecisionResult {
                            request: handle.to_string(),
                            success: false,
                            state: "error".to_string(),
                            target: pending.target.clone(),
                            remaining_uses: None,
                            use_policy: "unavailable".to_string(),
                            message,
                            consequence: String::new(),
                        };
                    }
                    Ok(false) => {}
                }
                reconcile_grant_request_from_store(server, handle).await;
                return AccessDecisionResult {
                    request: handle.to_string(),
                    success: false,
                    state: "error".to_string(),
                    target: pending.target.clone(),
                    remaining_uses: None,
                    use_policy: "unavailable".to_string(),
                    message: format!("failed to persist access approval: {error}"),
                    consequence: String::new(),
                };
            }
        }
        let grant_uses = staged.access_grant_uses(&token, handle);
        let remaining_uses = grant_uses.and_then(|(_, remaining)| remaining);
        {
            let mut live_verbs = server.state.verbs.write().await;
            if live_verbs.version() == baseline_verbs.version() {
                *live_verbs = staged_verbs;
            } else if proposed_verbs
                .iter()
                .any(|verb| live_verbs.upsert_access_verb(verb.clone()).is_err())
            {
                return AccessDecisionResult {
                    request: handle.to_string(),
                    success: false,
                    state: "stale".to_string(),
                    target: approved.target.clone(),
                    remaining_uses,
                    use_policy: "unavailable".to_string(),
                    message: "verb catalog changed while access approval was committing"
                        .to_string(),
                    consequence: String::new(),
                };
            }
        }
        {
            let mut live_sessions = server.state.sessions.write().await;
            if live_sessions.revision() != baseline_sessions.revision() {
                return AccessDecisionResult {
                    request: handle.to_string(),
                    success: false,
                    state: "stale".to_string(),
                    target: approved.target.clone(),
                    remaining_uses,
                    use_policy: "unavailable".to_string(),
                    message: "session authority changed while access approval was committing"
                        .to_string(),
                    consequence: String::new(),
                };
            }
            *live_sessions = staged;
        }
        {
            let mut requests = server.state.grant_requests.write().await;
            for (_, rebased) in rebased_pending {
                requests.insert(rebased.handle.clone(), rebased);
            }
            requests.insert(handle.to_string(), approved.clone());
        }
        #[cfg(test)]
        server.state.session_publication_events.add_permits(1);
        emit_grant_request_event(server, &approved, "access_request_approved");
        return AccessDecisionResult {
            request: handle.to_string(),
            success: true,
            state: "approved".to_string(),
            target: approved.target,
            remaining_uses,
            use_policy: access_use_policy(grant_uses).to_string(),
            message: "access approved".to_string(),
            consequence: String::new(),
        };
    }
}

async fn revoke_access_target(
    server: &ServerContext,
    caller: &CallerIdentity,
    target: String,
) -> AdminResponse {
    let owned_server = server.clone();
    let owned_caller = caller.clone();
    match tokio::spawn(async move {
        revoke_access_target_owned(&owned_server, &owned_caller, &target).await
    })
    .await
    {
        Ok(response) => response,
        Err(error) => AdminResponse::Error {
            message: format!("access revoke coordination failed: {error}"),
        },
    }
}

async fn revoke_access_target_owned(
    server: &ServerContext,
    caller: &CallerIdentity,
    target: &str,
) -> AdminResponse {
    let _transition = server.state.authority_transition_gate.lock().await;
    let mut generation_retry = false;
    loop {
        let baseline_sessions = server.state.sessions.read().await.clone();
        let (token, access_managed) = match baseline_sessions.token_for_access_target(target) {
            Ok(Some(token)) if baseline_sessions.is_access_managed(&token) => (token, true),
            Ok(Some(token))
                if matches!(
                    baseline_sessions.owner_for(&token),
                    Some(SessionOwner::Unowned)
                ) =>
            {
                (token, false)
            }
            Ok(Some(_)) => {
                return AdminResponse::Error {
                    message: "access revoke only accepts access-managed or legacy unowned sessions"
                        .to_string(),
                }
            }
            Ok(None) => {
                return AdminResponse::Error {
                    message: format!("unknown active access target: '{target}'"),
                }
            }
            Err(message) => return AdminResponse::Error { message },
        };
        let reference = session_reference(&token);
        let expected_revision = baseline_sessions.effective_revision_key(&token);
        let mut staged = baseline_sessions.clone();
        if !staged.revoke(&token) {
            return AdminResponse::Error {
                message: format!("unknown active access target: '{target}'"),
            };
        }
        let baseline_requests = server.state.grant_requests.read().await.clone();
        let withdrawals = baseline_requests
            .values()
            .filter(|request| {
                request.status == GrantRequestStatus::Pending && request.session_token == token
            })
            .cloned()
            .map(|pending| {
                let mut withdrawn = pending.clone();
                withdrawn.status = GrantRequestStatus::Withdrawn;
                withdrawn.decided_unix = Some(now_unix());
                withdrawn.decided_reason = Some("target access session was revoked".to_string());
                withdrawn.next_action = format!("guard access show {}", withdrawn.handle);
                (pending, withdrawn)
            })
            .collect::<Vec<_>>();
        let revoked_at = now_unix();
        let session_fingerprint = audit_session_fingerprint(Some(&token));
        let approval_denials = if let Some(store) = &server.state.session_store {
            match store
                .commit_access_revoke(
                    token.clone(),
                    expected_revision.clone(),
                    staged.clone(),
                    withdrawals.clone(),
                )
                .await
            {
                Ok(denied) => denied,
                Err(error) => {
                    match reload_sessions_after_registry_conflict(
                        server,
                        &error,
                        generation_retry,
                        "access revoke",
                        baseline_sessions.revision(),
                    )
                    .await
                    {
                        Ok(true) => {
                            generation_retry = true;
                            continue;
                        }
                        Err(message) => return AdminResponse::Error { message },
                        Ok(false) => {}
                    }
                    return AdminResponse::Error {
                        message: format!("failed to persist access revoke: {error}"),
                    };
                }
            }
        } else {
            server
                .state
                .approvals
                .read()
                .await
                .list()
                .into_iter()
                .filter(|approval| {
                    approval.status == ApprovalStatus::Pending
                        && approval.snapshot.session_fingerprint.as_deref()
                            == Some(session_fingerprint.as_str())
                        && approval.snapshot.session_revision.as_deref()
                            == expected_revision.as_deref()
                })
                .map(|mut denied| {
                    denied.status = ApprovalStatus::Denied;
                    denied.decided_unix = Some(revoked_at);
                    denied.decided_reason =
                        Some("originating access session was revoked".to_string());
                    denied
                })
                .collect::<Vec<_>>()
        };
        {
            let mut live_sessions = server.state.sessions.write().await;
            if live_sessions.revision() != baseline_sessions.revision() {
                return AdminResponse::Error {
                    message:
                        "session authority changed while access revocation was committing; durable revocation remains authoritative"
                            .to_string(),
                };
            }
            *live_sessions = staged;
        }
        {
            let mut live_requests = server.state.grant_requests.write().await;
            for (pending, withdrawn) in &withdrawals {
                if live_requests.get(&pending.handle) == Some(pending) {
                    live_requests.insert(withdrawn.handle.clone(), withdrawn.clone());
                }
            }
        }
        {
            let mut live_approvals = server.state.approvals.write().await;
            for denied in &approval_denials {
                live_approvals.install_persisted(denied.clone(), true);
            }
        }
        #[cfg(test)]
        server.state.session_publication_events.add_permits(1);
        for (_, withdrawn) in &withdrawals {
            emit_grant_request_event(server, withdrawn, "grant_request_withdrawn");
        }
        for denied in &approval_denials {
            server.emit_event(NotifyEvent {
                event: "decision_made",
                at_unix: revoked_at,
                handle: Some(denied.handle.clone()),
                session_fingerprint: denied.snapshot.session_fingerprint.clone(),
                requester_principal: denied.snapshot.principal.as_ref().map(ToString::to_string),
                reason: denied.decided_reason.clone(),
                status: Some("denied".to_string()),
                behavior: None,
            });
        }
        server.emit_audit_ungated(
            AuditEvent::new(AuditKind::SessionRevoke)
                .caller(caller)
                .field("token_fingerprint", &reference)
                .field("access_managed", access_managed),
        );
        return AdminResponse::AccessDecisions {
            items: vec![AccessDecisionResult {
                request: reference.clone(),
                success: true,
                state: "revoked".to_string(),
                target: Some(reference),
                remaining_uses: None,
                use_policy: "unavailable".to_string(),
                message: "access revoked".to_string(),
                consequence: String::new(),
            }],
            wait: None,
        };
    }
}

async fn approve_held_access(
    server: &ServerContext,
    caller: &CallerIdentity,
    handle: &str,
    uses: Option<u64>,
    audience: &AccessAudience,
) -> AccessDecisionResult {
    let transition = server.state.authority_transition_gate.lock().await;
    let Some(approval) = server.state.approvals.read().await.get(handle).cloned() else {
        return AccessDecisionResult {
            request: handle.to_string(),
            success: false,
            state: "not_found".to_string(),
            target: None,
            remaining_uses: None,
            use_policy: "unavailable".to_string(),
            message: "unknown access request".to_string(),
            consequence: String::new(),
        };
    };
    let originating_session_active = if approval.status == ApprovalStatus::Pending
        && approval_has_live_command_session_binding(&approval)
    {
        let sessions = server.state.sessions.read().await;
        session_token_for_approval_snapshot(&sessions, &approval.snapshot).is_some()
    } else {
        true
    };
    if !originating_session_active {
        let requester = approval
            .snapshot
            .principal
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "unknown".to_string());
        return match terminalize_revoked_session_approval(server, approval).await {
            Ok(()) => AccessDecisionResult {
                request: handle.to_string(),
                success: false,
                state: "revoked".to_string(),
                target: Some(format!("agent:{requester}")),
                remaining_uses: None,
                use_policy: "unavailable".to_string(),
                message: "originating access session expired or was revoked".to_string(),
                consequence: String::new(),
            },
            Err(message) => AccessDecisionResult {
                request: handle.to_string(),
                success: false,
                state: "error".to_string(),
                target: Some(format!("agent:{requester}")),
                remaining_uses: None,
                use_policy: "unavailable".to_string(),
                message,
                consequence: String::new(),
            },
        };
    }
    if approval_is_armed(&approval) {
        let item = access_item_for_approval(server, &approval, audience).await;
        return AccessDecisionResult {
            request: handle.to_string(),
            success: false,
            state: "armed".to_string(),
            target: Some(item.target),
            remaining_uses: item.remaining_uses,
            use_policy: item.use_policy,
            message: "held request is already armed for requester resume".to_string(),
            consequence: String::new(),
        };
    }
    if approval.status != ApprovalStatus::Pending {
        let item = access_item_for_approval(server, &approval, audience).await;
        return AccessDecisionResult {
            request: handle.to_string(),
            success: false,
            state: approval.status.as_str().to_string(),
            target: Some(item.target),
            remaining_uses: item.remaining_uses,
            use_policy: item.use_policy,
            message: format!(
                "held request is already {}; the immutable snapshot was not re-executed",
                approval.status.as_str()
            ),
            consequence: String::new(),
        };
    }
    if now_unix() >= approval.deadline_unix() {
        let now = now_unix();
        server.state.approvals.write().await.expire_due(now);
        if let Some(expired) = server.state.approvals.read().await.get(handle).cloned() {
            let _ = persist_approval(server, &expired).await;
        }
        return AccessDecisionResult {
            request: handle.to_string(),
            success: false,
            state: "expired".to_string(),
            target: Some(format!(
                "agent:{}",
                approval
                    .snapshot
                    .principal
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "unknown".to_string())
            )),
            remaining_uses: None,
            use_policy: "unavailable".to_string(),
            message: "expired without operator approval".to_string(),
            consequence: String::new(),
        };
    }
    // A hold replays one immutable snapshot, so one use is the only legal
    // budget. `--once` states it explicitly and no use flag means the same
    // thing; any other count is a request the snapshot cannot honour.
    if !matches!(uses, None | Some(1)) {
        return AccessDecisionResult {
            request: handle.to_string(),
            success: false,
            state: "rejected".to_string(),
            target: approval
                .snapshot
                .principal
                .as_ref()
                .map(|principal| format!("agent:{principal}")),
            remaining_uses: None,
            use_policy: "unavailable".to_string(),
            message: "held requests execute one immutable snapshot; approve them with --once"
                .to_string(),
            consequence: String::new(),
        };
    }
    if is_release_class(server, &approval.snapshot) {
        let snapshot = match claim_approval(server, handle).await {
            Ok(snapshot) => snapshot,
            Err(message) => {
                return AccessDecisionResult {
                    request: handle.to_string(),
                    success: false,
                    state: "error".to_string(),
                    target: None,
                    remaining_uses: None,
                    use_policy: "unavailable".to_string(),
                    message,
                    consequence: String::new(),
                }
            }
        };
        drop(transition);
        return match handle_approve_claimed(server, caller, handle, snapshot).await {
            AdminResponse::GateAction { message, .. } => AccessDecisionResult {
                request: handle.to_string(),
                success: true,
                state: "approved".to_string(),
                target: None,
                remaining_uses: None,
                use_policy: "unavailable".to_string(),
                message,
                consequence: String::new(),
            },
            AdminResponse::Error { message } => AccessDecisionResult {
                request: handle.to_string(),
                success: false,
                state: "error".to_string(),
                target: None,
                remaining_uses: None,
                use_policy: "unavailable".to_string(),
                message,
                consequence: String::new(),
            },
            _ => AccessDecisionResult {
                request: handle.to_string(),
                success: false,
                state: "error".to_string(),
                target: None,
                remaining_uses: None,
                use_policy: "unavailable".to_string(),
                message: "unexpected API approval response".to_string(),
                consequence: String::new(),
            },
        };
    }
    let Some(requester) = approval.snapshot.principal.clone() else {
        return AccessDecisionResult {
            request: handle.to_string(),
            success: false,
            state: "rejected".to_string(),
            target: None,
            remaining_uses: None,
            use_policy: "unavailable".to_string(),
            message: "held access request has no authenticated requester".to_string(),
            consequence: String::new(),
        };
    };
    let originating_access_token = if approval.snapshot.session_fingerprint.is_none() {
        None
    } else {
        let sessions = server.state.sessions.read().await;
        match session_token_for_approval_snapshot(&sessions, &approval.snapshot) {
            Some(token) => Some(token),
            None => {
                let terminalized =
                    terminalize_revoked_session_approval(server, approval.clone()).await;
                return AccessDecisionResult {
                    request: handle.to_string(),
                    success: false,
                    state: if terminalized.is_ok() {
                        "revoked".to_string()
                    } else {
                        "error".to_string()
                    },
                    target: Some(format!("agent:{requester}")),
                    remaining_uses: None,
                    use_policy: "unavailable".to_string(),
                    message: terminalized.err().unwrap_or_else(|| {
                        "originating access session expired or was revoked".to_string()
                    }),
                    consequence: String::new(),
                };
            }
        }
    };

    let response = arm_held_command(server, caller, approval).await;
    drop(transition);
    let aggregate = match originating_access_token.as_deref() {
        Some(token) => server
            .state
            .sessions
            .read()
            .await
            .aggregate_access_uses(token),
        None => None,
    };
    let (success, state, message) = match response {
        AdminResponse::GateAction { message, .. } => (true, "armed", message),
        AdminResponse::Error { message } => (false, "error", message),
        _ => (
            false,
            "error",
            "unexpected held access response".to_string(),
        ),
    };
    AccessDecisionResult {
        request: handle.to_string(),
        success,
        state: state.to_string(),
        target: originating_access_token
            .as_deref()
            .map(session_reference)
            .or_else(|| Some(format!("agent:{requester}"))),
        remaining_uses: aggregate.flatten(),
        use_policy: match aggregate {
            Some(Some(_)) => "bounded",
            Some(None) => "unlimited",
            None => "unavailable",
        }
        .to_string(),
        message,
        consequence: String::new(),
    }
}

fn access_decision_from_response(handle: &str, response: AdminResponse) -> AccessDecisionResult {
    match response {
        AdminResponse::GrantRequest { request } => AccessDecisionResult {
            request: handle.to_string(),
            success: request.status == GrantRequestStatus::Denied,
            state: request.status.as_str().to_string(),
            target: request.target,
            remaining_uses: None,
            use_policy: "unavailable".to_string(),
            message: request
                .decided_reason
                .unwrap_or_else(|| "access request denied".to_string()),
            consequence: String::new(),
        },
        AdminResponse::Error { message } => AccessDecisionResult {
            request: handle.to_string(),
            success: false,
            state: "error".to_string(),
            target: None,
            remaining_uses: None,
            use_policy: "unavailable".to_string(),
            message,
            consequence: String::new(),
        },
        AdminResponse::GateAction { message, .. } => AccessDecisionResult {
            request: handle.to_string(),
            success: true,
            state: "denied".to_string(),
            target: None,
            remaining_uses: None,
            use_policy: "unavailable".to_string(),
            message,
            consequence: String::new(),
        },
        _ => AccessDecisionResult {
            request: handle.to_string(),
            success: false,
            state: "error".to_string(),
            target: None,
            remaining_uses: None,
            use_policy: "unavailable".to_string(),
            message: "unexpected access decision response".to_string(),
            consequence: String::new(),
        },
    }
}

async fn retire_invalid_durable_access_request(
    server: &ServerContext,
    handle: &str,
) -> Option<AccessDecisionResult> {
    let store = server.state.session_store.as_ref()?;
    match store.retire_invalid_grant_request(handle.to_string()).await {
        Ok(true) => Some(AccessDecisionResult {
            request: handle.to_string(),
            success: true,
            state: "retired".to_string(),
            target: None,
            remaining_uses: None,
            use_policy: "unavailable".to_string(),
            consequence: String::new(),
            message: "invalid durable access request was retired".to_string(),
        }),
        Ok(false) => None,
        Err(error) => Some(AccessDecisionResult {
            request: handle.to_string(),
            success: false,
            state: "error".to_string(),
            target: None,
            remaining_uses: None,
            use_policy: "unavailable".to_string(),
            consequence: String::new(),
            message: format!("failed to retire invalid durable access request: {error}"),
        }),
    }
}

#[cfg(test)]
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
        probes: Vec::new(),
        // Replayed from the generated template itself; no probe was executed
        // against the finished matcher, so this must not claim one was.
        observation_replays: vec![
            CoverageObservationReplay {
                dimension: "generated_example".to_string(),
                args: verb.args.clone(),
                template_match: true,
            },
            CoverageObservationReplay {
                dimension: "outside_generated_boundary".to_string(),
                args: vec!["--guard-outside-coverage".to_string()],
                template_match: false,
            },
        ],
    };
    verb.coverage = vec![VerbCoverageCell {
        name: "generated".to_string(),
        action: CoverageAction::Evaluate,
        command_path: Vec::new(),
        required_args: fixed_args,
        forbidden_args: Vec::new(),
        min_args: None,
        max_args: None,
        options: Vec::new(),
        target: None,
        inventory: None,
        namespace: None,
        fanout: None,
        cwd: None,
        environment: Vec::new(),
        override_marker: None,
        sticky: false,
        provenance: Some(provenance),
    }];
    verb.coverage.extend(sticky);
    verb
}

fn caller_is_session_admin(server: &ServerContext, caller: &CallerIdentity) -> bool {
    server.caller_is_admin(caller)
}

/// Whether `caller` may see a session's full detail: the operator sees every
/// session, and a non-operator peer sees only sessions it owns (its
/// server-read principal equals the session owner). This is the visibility half
/// of principal binding - a leaked token no longer lets a different local peer
/// read another user's grant.
#[cfg(test)]
fn caller_can_view_session(
    server: &ServerContext,
    caller: &CallerIdentity,
    owner: &SessionOwner,
) -> bool {
    matches!(
        authorize_session_use(owner, caller, server.config.allow_windows_system_operator),
        SessionAuthz::Allowed
    )
}

/// Authorize a non-admin caller to inspect a specific session through an
/// internal session or public access/status projection. The caller must be the
/// session's bound owner, verified
/// against the principal the daemon reads itself. Emits a `SESSION_SHOW_REJECTED`
/// audit event carrying the greppable principal-mismatch reason on refusal, and
/// never confirms the session's existence to a non-owner.
#[cfg(test)]
async fn authorize_session_inspection(
    server: &ServerContext,
    caller: &CallerIdentity,
    token: &str,
) -> Result<(), String> {
    let owner = server.state.sessions.read().await.owner_for(token);
    let decision = match &owner {
        Some(owner) => {
            authorize_session_use(owner, caller, server.config.allow_windows_system_operator)
        }
        // No active grant for this token: a non-owner must not learn whether the
        // session ever existed, and cannot prove ownership of a gone session.
        None => SessionAuthz::Mismatch,
    };
    match decision {
        SessionAuthz::Allowed => Ok(()),
        SessionAuthz::Unowned => {
            server.emit_audit_ungated(
                AuditEvent::new(AuditKind::SessionShowRejected)
                    .caller(caller)
                    .reason(SESSION_UNOWNED_REFUSED),
            );
            Err(format!("not authorized: {SESSION_UNOWNED_REFUSED}"))
        }
        SessionAuthz::Mismatch => {
            server.emit_audit_ungated(
                AuditEvent::new(AuditKind::SessionShowRejected)
                    .caller(caller)
                    .reason(SESSION_PRINCIPAL_MISMATCH),
            );
            Err(format!(
                "not authorized: {SESSION_PRINCIPAL_MISMATCH}; a session may only be inspected by its owning principal"
            ))
        }
    }
}

/// Enforce that `caller` owns `token` before an admin RPC exercises that
/// session's authority (kubeconfig issuance, batch evaluation). Returns `None`
/// when the caller is the owner or the operator; otherwise emits an
/// `ADMIN_REJECTED` audit event with the greppable reason and returns the error
/// response to send back. An unknown/expired token is reported as such. These
/// are authority-use paths, so an `Unowned` legacy session is refused for
/// everyone (including the operator), matching the execute path.
async fn enforce_session_owner_for_admin(
    server: &ServerContext,
    caller: &CallerIdentity,
    token: &str,
    context: &str,
) -> Option<AdminResponse> {
    let owner = server.state.sessions.read().await.owner_for(token);
    let Some(owner) = owner else {
        return Some(AdminResponse::Error {
            message: format!("unknown, expired, or revoked session for {context}"),
        });
    };
    if matches!(owner, SessionOwner::Unowned) {
        server.emit_audit_ungated(
            AuditEvent::new(AuditKind::AdminRejected)
                .caller(caller)
                .reason(SESSION_UNOWNED_REFUSED),
        );
        return Some(AdminResponse::Error {
            message: format!("{context} refused: {SESSION_UNOWNED_REFUSED}"),
        });
    }
    match authorize_session_use(&owner, caller, server.config.allow_windows_system_operator) {
        SessionAuthz::Allowed => None,
        SessionAuthz::Unowned => {
            server.emit_audit_ungated(
                AuditEvent::new(AuditKind::AdminRejected)
                    .caller(caller)
                    .reason(SESSION_UNOWNED_REFUSED),
            );
            Some(AdminResponse::Error {
                message: format!("{context} refused: {SESSION_UNOWNED_REFUSED}"),
            })
        }
        SessionAuthz::Mismatch => {
            server.emit_audit_ungated(
                AuditEvent::new(AuditKind::AdminRejected)
                    .caller(caller)
                    .reason(SESSION_PRINCIPAL_MISMATCH),
            );
            Some(AdminResponse::Error {
                message: format!("{context} refused: {SESSION_PRINCIPAL_MISMATCH}"),
            })
        }
    }
}

#[cfg(test)]
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
        grant.scope = IssuedGrantScope::default();
        // Do not reveal which principal owns another user's session.
        grant.owner = SessionOwner::Unowned;
        if grant.prompt_append.is_some() {
            grant.prompt_append = Some("(hidden)".to_string());
        }
    }
}

#[cfg(test)]
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
        grant.scope = IssuedGrantScope::default();
        // Do not reveal which principal owns another user's session.
        grant.owner = SessionOwner::Unowned;
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

#[cfg(test)]
async fn handle_session_appeal(
    server: &ServerContext,
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
    let command_line = redact_command_line(&binary, &args);
    if let Err(reason) = validate_session_exact_rule_candidate(&binary, &args) {
        return AdminResponse::SessionAppeal {
            allowed: false,
            amended: false,
            pattern: None,
            reason,
            risk: None,
        };
    }

    let (exists, access_managed, decision, session_prompt, owner) = {
        let reg = server.state.sessions.read().await;
        (
            reg.has(&token),
            reg.is_access_managed(&token),
            // Appeals are command-shape requests and do not carry authenticated
            // caller cwd authority. Cwd-bound grants are checked on ExecuteRequest.
            reg.check(&token, &binary, &args, None),
            reg.prompt_append_for(&token),
            reg.owner_for(&token),
        )
    };
    if access_managed {
        return AdminResponse::Error {
            message: "access-managed sessions use guard access extend, not session appeals"
                .to_string(),
        };
    }
    // An appeal amends session authority, so it is operator-gated
    // (`requires_admin_token`) and not part of the bearer-replay surface. A
    // session that predates principal binding still cannot be amended: refuse it
    // fail-closed so the operator reissues rather than silently extending a
    // session with no verifiable owner.
    if matches!(owner, Some(SessionOwner::Unowned)) {
        server.emit_audit_ungated(
            AuditEvent::new(AuditKind::AdminRejected)
                .caller(caller)
                .reason(SESSION_UNOWNED_REFUSED),
        );
        return AdminResponse::Error {
            message: format!("session appeal refused: {SESSION_UNOWNED_REFUSED}"),
        };
    }
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
    let eval_result = server
        .state
        .evaluator
        .evaluate_with_reevaluate(&command_line, session_prompt.as_deref(), true)
        .await;

    match eval_result {
        guard::evaluate::EvalResult::Allow {
            reason,
            source,
            risk,
            reversibility: _,
        } => {
            if !matches!(source, guard::evaluate::EvalSource::Llm) {
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
                    server,
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
                    Vec::new(),
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
                server,
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
                server,
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
                Vec::new(),
            )
            .await;
            server.emit_audit_ungated(
                AuditEvent::new(AuditKind::SessionAppeal)
                    .caller(caller)
                    .cmd(redact_output(&command_line))
                    .field("token_fingerprint", audit_session_fingerprint(Some(&token)))
                    .field("allowed", true)
                    .field("amended", amended),
            );
            AdminResponse::SessionAppeal {
                allowed: true,
                amended,
                pattern: Some(command_line),
                reason: final_reason,
                risk,
            }
        }
        guard::evaluate::EvalResult::Deny {
            reason,
            source,
            risk,
        } => {
            let mut amended = false;
            if matches!(source, guard::evaluate::EvalSource::Llm)
                && deny_session_auto_amend_candidate(&binary, &args, risk).is_ok()
            {
                match amend_session_exact_rule(
                    server,
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
                server,
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
                Vec::new(),
            )
            .await;
            server.emit_audit_ungated(
                AuditEvent::new(AuditKind::SessionAppeal)
                    .caller(caller)
                    .cmd(redact_output(&command_line))
                    .field("token_fingerprint", audit_session_fingerprint(Some(&token)))
                    .field("allowed", false)
                    .field("amended", amended),
            );
            AdminResponse::SessionAppeal {
                allowed: false,
                amended,
                pattern: Some(command_line),
                reason: final_reason,
                risk,
            }
        }
        guard::evaluate::EvalResult::Error(err) => AdminResponse::SessionAppeal {
            allowed: false,
            amended: false,
            pattern: Some(command_line),
            reason: format!("appeal evaluation error: {err}"),
            risk: None,
        },
    }
}

async fn list_access_items(server: &ServerContext, caller: &CallerIdentity) -> AdminResponse {
    let audience = AccessAudience::from_caller(server, caller);
    let requests = server
        .state
        .grant_requests
        .read()
        .await
        .values()
        .filter(|request| audience.can_view_principal(&request.requester))
        .cloned()
        .collect::<Vec<_>>();
    let sessions = server
        .state
        .sessions
        .read()
        .await
        .list()
        .into_iter()
        .filter(|summary| summary.scope.access_managed && audience.can_view_session(summary))
        .collect::<Vec<_>>();
    let approvals = server
        .state
        .approvals
        .read()
        .await
        .list()
        .into_iter()
        .filter(|approval| audience.can_view_principal(&approval.snapshot.principal))
        .collect::<Vec<_>>();
    let mut items = Vec::with_capacity(requests.len() + sessions.len() + approvals.len());
    for request in requests {
        items.push(access_item_for_request(server, &request, &audience).await);
    }
    for approval in approvals {
        items.push(access_item_for_approval(server, &approval, &audience).await);
    }
    for summary in sessions {
        items.push(access_item_for_session(server, &summary, &audience).await);
    }
    items.sort_by(|left, right| {
        left.requester
            .cmp(&right.requester)
            .then(left.kind.cmp(&right.kind))
            .then(left.reference.cmp(&right.reference))
    });
    AdminResponse::AccessItems { items }
}

/// Return the canonical active access-managed session for the kernel-authenticated
/// local caller. The response deliberately uses the standard `AccessItem`
/// projection, whose reference never contains the bearer token.
async fn access_whoami_item(server: &ServerContext, caller: &CallerIdentity) -> AdminResponse {
    let principal = match authenticated_local_principal(caller) {
        Ok(principal) => principal,
        Err(message) => return AdminResponse::Error { message },
    };
    let summary = {
        let sessions = server.state.sessions.read().await;
        access_token_for_principal_ci(&sessions, &principal).and_then(|token| {
            sessions
                .list()
                .into_iter()
                .find(|summary| summary.token == token)
        })
    };
    match summary {
        Some(summary) => {
            let audience = AccessAudience::from_caller(server, caller);
            let mut item = access_item_for_session(server, &summary, &audience).await;
            // `whoami` identifies the attached session without unexpectedly
            // expanding its reviewed matcher internals. Detailed access
            // inspection remains an explicit `access show` operation.
            item.intent = None;
            item.capabilities.clear();
            item.next_action = format!("guard access status {}", item.reference);
            AdminResponse::AccessItem { item }
        }
        None => AdminResponse::Error {
            message: "no active access-managed session for the authenticated local principal"
                .to_string(),
        },
    }
}

async fn show_access_item(
    server: &ServerContext,
    caller: &CallerIdentity,
    reference: &str,
) -> AdminResponse {
    let audience = AccessAudience::from_caller(server, caller);
    if let Some(request) = server
        .state
        .grant_requests
        .read()
        .await
        .get(reference)
        .filter(|request| audience.can_view_principal(&request.requester))
        .cloned()
    {
        AdminResponse::AccessItem {
            item: access_item_for_request(server, &request, &audience).await,
        }
    } else if let Some(approval) = server
        .state
        .approvals
        .read()
        .await
        .get(reference)
        .filter(|approval| audience.can_view_principal(&approval.snapshot.principal))
        .cloned()
    {
        AdminResponse::AccessItem {
            item: access_item_for_approval(server, &approval, &audience).await,
        }
    } else {
        let mut candidates = server
            .state
            .sessions
            .read()
            .await
            .list()
            .into_iter()
            .filter(|summary| summary.scope.access_managed && audience.can_view_session(summary))
            .filter(|summary| {
                summary.scope.label.as_deref() == Some(reference)
                    || session_reference(&summary.token) == reference
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| left.token.cmp(&right.token));
        match candidates.as_slice() {
            [summary] => AdminResponse::AccessItem {
                item: access_item_for_session(server, summary, &audience).await,
            },
            [] => AdminResponse::Error {
                message: "unknown or unauthorized access reference".to_string(),
            },
            _ => AdminResponse::Error {
                message: format!("access target '{reference}' is ambiguous"),
            },
        }
    }
}

async fn visible_activated_verbs(
    server: &ServerContext,
    caller: &CallerIdentity,
) -> std::collections::BTreeSet<String> {
    let Some(principal) = caller.principal().filter(|_| caller.is_local_peer()) else {
        return std::collections::BTreeSet::new();
    };
    let sessions = server.state.sessions.read().await;
    access_token_for_principal_ci(&sessions, &principal)
        .and_then(|token| {
            sessions.verb_scope_for(&token).map(|(activated, _)| {
                activated
                    .into_iter()
                    .filter(|name| {
                        sessions
                            .select_access_requests(&token, std::slice::from_ref(name))
                            .is_ok()
                    })
                    .collect()
            })
        })
        .unwrap_or_default()
}

fn verb_menu_item(verb: &Verb) -> VerbMenuItem {
    VerbMenuItem {
        name: verb.name.clone(),
        description: verb.description.clone(),
        params: verb.params.keys().cloned().collect(),
        consequence: verb.consequence.as_str().to_string(),
        hold: verb.hold,
        has_revert: verb.revert.is_some(),
    }
}

async fn access_session_token(
    server: &ServerContext,
    caller: &CallerIdentity,
    reference: &str,
) -> Result<String, String> {
    let admin = caller_is_session_admin(server, caller);
    let principal = caller.principal();
    let mut candidates = server
        .state
        .sessions
        .read()
        .await
        .list()
        .into_iter()
        .filter(|summary| {
            summary.scope.access_managed
                && (admin
                    || matches!(
                        &summary.owner,
                        SessionOwner::Principal(owner)
                            if principal.as_ref().is_some_and(|caller| owner.eq_ci(caller))
                    ))
        })
        .filter(|summary| {
            summary.scope.label.as_deref() == Some(reference)
                || session_reference(&summary.token) == reference
        })
        .map(|summary| summary.token)
        .collect::<Vec<_>>();
    candidates.sort();
    match candidates.as_slice() {
        [token] => Ok(token.clone()),
        [] => Err("unknown or unauthorized access session reference".to_string()),
        _ => Err(format!("access target '{reference}' is ambiguous")),
    }
}

async fn session_status_response(
    server: &ServerContext,
    token: &str,
    mask_token: bool,
) -> AdminResponse {
    let Some(mut report) = server.state.sessions.read().await.show_with_limits(
        token,
        20,
        &server.config.behavior_limits,
    ) else {
        return AdminResponse::Error {
            message: "access session is no longer active".to_string(),
        };
    };
    if mask_token {
        mask_session_report_token(&mut report);
    }
    report.redact_credentials();
    let fingerprint = audit_session_fingerprint(Some(token));
    let approvals = server
        .state
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
    let provisionals = server
        .state
        .provisional
        .read()
        .await
        .visible_list()
        .iter()
        .filter(|provisional| {
            provisional.session_fingerprint.as_deref() == Some(fingerprint.as_str())
        })
        .map(ProvisionalSummary::from_row)
        .collect();
    let requests = server
        .state
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

async fn dispatch_admin_request(
    server: &ServerContext,
    caller: &CallerIdentity,
    request: AdminRequest,
) -> AdminResponse {
    if request.requires_admin_token() {
        if let Err(e) = server.validate_admin(caller) {
            server.emit_audit_ungated(
                AuditEvent::new(AuditKind::AdminRejected)
                    .caller(caller)
                    .reason(e.to_string()),
            );
            return AdminResponse::Error {
                message: e.to_string(),
            };
        }
    }

    match request {
        #[cfg(test)]
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
            owner: owner_input,
        } => {
            if token.is_empty() {
                return AdminResponse::Error {
                    message: "session token must not be empty".to_string(),
                };
            }
            // Bind the session to a principal at creation. An operator can name
            // the consuming agent explicitly (the different-uid deployment); when
            // omitted the session is owned by the authenticated local operator
            // that issues it, or the daemon principal for an admin-token caller.
            let session_owner = if let Some(raw) = owner_input
                .as_deref()
                .map(str::trim)
                .filter(|raw| !raw.is_empty())
            {
                SessionOwner::Principal(PrincipalKey::from_raw(raw))
            } else if let Some(principal) = caller.principal().filter(|_| caller.is_local_peer()) {
                SessionOwner::Principal(principal)
            } else {
                SessionOwner::Principal(server.config.daemon_principal.clone())
            };
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
                let selected = server.state.saved_grants.read().await.get(name).cloned();
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
                            ..IssuedGrantScope::default()
                        };
                        let mut catalog = server.state.verbs.write().await;
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
                let catalog = match server
                    .refresh_and_lease_verb_catalog_for_use("session verb activation")
                    .await
                {
                    Ok(catalog) => catalog,
                    Err(error) => {
                        return AdminResponse::Error {
                            message: format!("verb catalog authority is unavailable: {error}"),
                        }
                    }
                };
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
            let owner_label = session_owner.label();
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
                owner: session_owner,
            };
            let _transition = server.state.authority_transition_gate.lock().await;
            let baseline = server.state.sessions.read().await.clone();
            let mut staged = baseline.clone();
            staged.purge_expired();
            if !staged.grant(token.clone(), grant) {
                return AdminResponse::Error {
                    message: "session token was already issued and cannot be reused".to_string(),
                };
            }
            if let Err(err) =
                persist_session_snapshot(server.state.session_store.clone(), staged.clone()).await
            {
                return AdminResponse::Error {
                    message: format!("failed to persist session grant: {err}"),
                };
            }
            let mut live = server.state.sessions.write().await;
            if live.revision() != baseline.revision() {
                return AdminResponse::Error {
                    message: "session authority changed while the durable grant was committing"
                        .to_string(),
                };
            }
            *live = staged;
            drop(live);
            server.emit_audit_ungated(
                AuditEvent::new(AuditKind::SessionGrant)
                    .caller(caller)
                    .field("token_fingerprint", audit_session_fingerprint(Some(&token)))
                    .field("saved_grant", format!("{saved_grant:?}"))
                    .field("ttl", format!("{ttl_secs:?}"))
                    .field("evaluation_mode", effective_evaluation_mode)
                    .field("auto_amend", auto_amend)
                    .field("owner", owner_label),
            );
            AdminResponse::Ok
        }
        #[cfg(test)]
        AdminRequest::SessionAppeal {
            token,
            binary,
            args,
        } => handle_session_appeal(server, caller, token, binary, args).await,
        #[cfg(test)]
        AdminRequest::SessionRevoke { token } => {
            let _transition = server.state.authority_transition_gate.lock().await;
            let baseline = server.state.sessions.read().await.clone();
            let mut staged = baseline.clone();
            let removed = staged.revoke(&token);
            if let Err(err) =
                persist_session_snapshot(server.state.session_store.clone(), staged.clone()).await
            {
                return AdminResponse::Error {
                    message: format!("failed to persist session revoke: {err}"),
                };
            }
            let mut live = server.state.sessions.write().await;
            if live.revision() != baseline.revision() {
                return AdminResponse::Error {
                    message:
                        "session authority changed while the durable revocation was committing"
                            .to_string(),
                };
            }
            *live = staged;
            drop(live);
            server.emit_audit_ungated(
                AuditEvent::new(AuditKind::SessionRevoke)
                    .caller(caller)
                    .field("token_fingerprint", audit_session_fingerprint(Some(&token)))
                    .field("existed", removed),
            );
            AdminResponse::Ok
        }
        #[cfg(test)]
        AdminRequest::SessionList {
            include_history,
            since_unix,
            visible_token,
        } => {
            // Opportunistic purge so list shows fresh state and history
            // bookkeeping stays bounded.
            {
                let mut reg = server.state.sessions.write().await;
                reg.purge_expired();
            }
            if let Err(err) = persist_current_sessions(server).await {
                tracing::warn!("failed to persist purged session state: {}", err);
            }
            let reg = server.state.sessions.read().await;
            let is_admin = caller_is_session_admin(server, caller);
            let _ = visible_token;
            let grants = reg
                .list()
                .into_iter()
                .filter(|grant| is_admin || caller_can_view_session(server, caller, &grant.owner))
                .map(|mut grant| {
                    let can_view = caller_can_view_session(server, caller, &grant.owner);
                    redact_session_summary_for_list(&mut grant, is_admin, can_view);
                    grant.redact_credentials();
                    grant
                })
                .collect();
            let history = if include_history {
                reg.list_history(since_unix)
                    .into_iter()
                    .filter(|grant| {
                        is_admin || caller_can_view_session(server, caller, &grant.owner)
                    })
                    .map(|mut grant| {
                        let can_view = caller_can_view_session(server, caller, &grant.owner);
                        redact_historical_grant_for_list(&mut grant, is_admin, can_view);
                        grant.redact_credentials();
                        grant
                    })
                    .collect()
            } else {
                Vec::new()
            };
            AdminResponse::SessionList { grants, history }
        }
        #[cfg(test)]
        AdminRequest::SessionShow {
            token,
            limit,
            caller_token,
        } => {
            {
                let mut reg = server.state.sessions.write().await;
                reg.purge_expired();
            }
            if let Err(err) = persist_current_sessions(server).await {
                tracing::warn!("failed to persist purged session state: {}", err);
            }
            let _ = caller_token;
            let is_admin = caller_is_session_admin(server, caller);
            // A non-admin caller may inspect only a session it owns: the
            // authenticated peer principal the daemon reads itself must equal the
            // session's bound owner. Presenting the bearer token is no longer
            // sufficient - a leaked token cannot be used by another local peer.
            if !is_admin {
                if let Err(message) = authorize_session_inspection(server, caller, &token).await {
                    return AdminResponse::Error { message };
                }
            }
            let reg = server.state.sessions.read().await;
            match reg.show_with_limits(&token, limit.unwrap_or(20), &server.config.behavior_limits)
            {
                Some(mut report) => {
                    // A self-inspecting holder sees the full grant (rules, prompt,
                    // expiry) but never has its own raw bearer token echoed back.
                    if !is_admin {
                        mask_session_report_token(&mut report);
                    }
                    // Command-derived text (recorded argv, learned rules,
                    // prompts) can carry credentials; no inspection surface
                    // may emit it un-redacted, in text or JSON, for any caller.
                    report.redact_credentials();
                    AdminResponse::SessionShow { report }
                }
                None => AdminResponse::Error {
                    message: format!("unknown session token: '{}'", token),
                },
            }
        }
        #[cfg(test)]
        AdminRequest::SessionStatus {
            token,
            caller_token,
        } => {
            let _ = caller_token;
            let is_admin = caller_is_session_admin(server, caller);
            if !is_admin {
                if let Err(message) = authorize_session_inspection(server, caller, &token).await {
                    return AdminResponse::Error { message };
                }
            }
            let Some(mut report) = server.state.sessions.read().await.show_with_limits(
                &token,
                20,
                &server.config.behavior_limits,
            ) else {
                return AdminResponse::Error {
                    message: format!("unknown session token: '{token}'"),
                };
            };
            if !is_admin {
                mask_session_report_token(&mut report);
            }
            report.redact_credentials();
            let fingerprint = audit_session_fingerprint(Some(&token));
            let approvals = server
                .state
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
            let provisionals = server
                .state
                .provisional
                .read()
                .await
                .visible_list()
                .iter()
                .filter(|provisional| {
                    provisional.session_fingerprint.as_deref() == Some(fingerprint.as_str())
                })
                .map(ProvisionalSummary::from_row)
                .collect();
            let requests = server
                .state
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
        #[cfg(test)]
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
            // Only the session's owning principal (or the operator) may mint a
            // kubeconfig that carries the session bearer. This binds API-proxy
            // authority to the same principal that owns the session.
            if let Some(response) = enforce_session_owner_for_admin(
                server,
                caller,
                &session_token,
                "brokered kubeconfig issuance",
            )
            .await
            {
                return response;
            }
            let expires_at = {
                let sessions = server.state.sessions.read().await;
                if sessions.is_access_managed(&session_token) {
                    return AdminResponse::Error {
                        message: "access-managed sessions authorize brokered commands, not reusable API credentials"
                            .to_string(),
                    };
                }
                if let Some(reason) =
                    sessions.suspension_reason(&session_token, &server.config.behavior_limits)
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
            let proxy = server
                .state
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
            server.emit_audit_ungated(
                AuditEvent::new(AuditKind::KubeconfigIssued)
                    .caller(caller)
                    .session_fingerprint(audit_session_fingerprint(Some(&session_token)))
                    .field("principal", &principal)
                    .field("endpoint", &endpoint)
                    .field("expires_at", expires_at),
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
            match server.state.secrets.set(&principal, &key, &value).await {
                Ok(()) => {
                    server.emit_audit_ungated(
                        AuditEvent::new(AuditKind::SecretSet)
                            .caller(caller)
                            .field("principal", &principal)
                            .field("key", &key),
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
            match server.state.secrets.delete(&principal, &key).await {
                Ok(()) => {
                    server.emit_audit_ungated(
                        AuditEvent::new(AuditKind::SecretDelete)
                            .caller(caller)
                            .field("principal", &principal)
                            .field("key", &key),
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
            match server.state.secrets.get(&principal, &key).await {
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
            if server.caller_is_admin(caller) {
                match server.state.secrets.list_all().await {
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
                match server.state.secrets.list(&principal).await {
                    Ok(keys) => AdminResponse::SecretList { keys },
                    Err(e) => AdminResponse::Error {
                        message: format!("failed to list secrets: {}", e),
                    },
                }
            }
        }
        AdminRequest::SecretListDetailed => match server.state.secrets.list_all().await {
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
            let mode = server
                .state
                .evaluator
                .mode()
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| "readonly".to_string());
            AdminResponse::Ping {
                version: env!("CARGO_PKG_VERSION").to_string(),
                uptime_secs: now.saturating_sub(server.config.started_at_unix),
                mode,
                dry_run: server.config.dry_run,
                capabilities: vec![
                    "approval-consequences-v1".to_string(),
                    super::wire::CAPABILITY_REQUESTER_VERB_SHOW_V1.to_string(),
                    super::wire::CAPABILITY_ACCESS_WHOAMI_V1.to_string(),
                ],
            }
        }
        AdminRequest::AuditVerify => {
            let Some(path) = server.config.audit_log_path.clone() else {
                return AdminResponse::Error {
                    message: "no audit log is configured (the daemon resolved no state directory)"
                        .to_string(),
                };
            };
            let display = path.display().to_string();
            match tokio::task::spawn_blocking(move || guard::audit::verify_chain(&path)).await {
                Ok(Ok(verification)) => AdminResponse::AuditVerification {
                    path: display,
                    verification,
                },
                Ok(Err(e)) => AdminResponse::Error {
                    message: format!("failed to read audit log {display}: {e}"),
                },
                Err(e) => AdminResponse::Error {
                    message: format!("audit verification task failed: {e}"),
                },
            }
        }
        AdminRequest::AuditTail { limit } => {
            let Some(path) = server.config.audit_log_path.clone() else {
                return AdminResponse::Error {
                    message: "no audit log is configured (the daemon resolved no state directory)"
                        .to_string(),
                };
            };
            let display = path.display().to_string();
            let limit = limit.unwrap_or(20).max(1);
            match tokio::task::spawn_blocking(move || guard::audit::tail_records(&path, limit))
                .await
            {
                Ok(Ok(items)) => AdminResponse::AuditRecords {
                    path: display,
                    items,
                },
                Ok(Err(e)) => AdminResponse::Error {
                    message: format!("failed to read audit log {display}: {e}"),
                },
                Err(e) => AdminResponse::Error {
                    message: format!("audit tail task failed: {e}"),
                },
            }
        }
        AdminRequest::Status => {
            if !AccessAudience::from_caller(server, caller).is_operator() {
                return AdminResponse::Error {
                    message: "full server status requires operator authority".to_string(),
                };
            }
            let now = now_unix();
            let session_count = server.state.sessions.read().await.list().len();
            let cache_size = server.state.evaluator.cache_size().await;
            let learned_rule_count = server.state.evaluator.learned_rule_count().await;
            let deny_shape_count = server.state.evaluator.deny_shape_count().await;
            let allow_promotion_observation_count = server
                .state
                .evaluator
                .allow_promotion_observation_count()
                .await;
            let mode = server
                .state
                .evaluator
                .mode()
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| "readonly".to_string());
            let (verb_catalog_hash, verb_catalog_changed_unix) = {
                let catalog = match server
                    .refresh_and_lease_verb_catalog_for_use("status catalog projection")
                    .await
                {
                    Ok(catalog) => catalog,
                    Err(error) => {
                        return AdminResponse::Error {
                            message: format!("verb catalog authority is unavailable: {error}"),
                        }
                    }
                };
                (catalog.short_hash(), catalog.changed_unix())
            };

            AdminResponse::Status {
                status: ServerStatus {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    started_at_unix: server.config.started_at_unix,
                    uptime_secs: now.saturating_sub(server.config.started_at_unix),
                    socket_path: server
                        .config
                        .socket_path
                        .as_ref()
                        .map(|p| p.display().to_string()),
                    tcp_port: server.config.tcp_port,
                    mode,
                    llm_enabled: server.state.evaluator.llm_enabled(),
                    llm_model_chain: server.state.evaluator.llm_model_chain(),
                    static_policy: server.state.evaluator.has_static_policy(),
                    preflight: server.config.preflight,
                    redact: server.config.redact,
                    dry_run: server.config.dry_run,
                    cache_enabled: server.state.evaluator.cache_enabled(),
                    cache_size,
                    learning_enabled: server.state.evaluator.learning_enabled(),
                    learned_rule_count,
                    deny_learning_enabled: server.state.evaluator.deny_learning_enabled(),
                    deny_shape_count,
                    allow_promotion_enabled: server.state.evaluator.allow_promotion_enabled(),
                    allow_promotion_observation_count,
                    session_count,
                    daemon_uid: server.config.daemon_uid,
                    exec_identity: if server.config.exec_as_caller {
                        "caller".to_string()
                    } else {
                        server
                            .config
                            .exec_user_id
                            .map(|uid| format!("fixed_uid:{uid}"))
                            .unwrap_or_else(|| "disabled".to_string())
                    },
                    state_db_path: server
                        .config
                        .state_db_path
                        .as_ref()
                        .map(|path| path.display().to_string()),
                    secret_backend: server.state.secrets.backend_name().to_string(),
                    gate: server.config.gate.as_str().to_string(),
                    pending_provisionals: server
                        .state
                        .provisional
                        .read()
                        .await
                        .visible_outstanding(),
                    pending_approvals: server.state.approvals.read().await.outstanding(),
                    verb_catalog_hash,
                    verb_catalog_changed_unix,
                    command_admission: server.state.command_admission.snapshot(),
                },
            }
        }
        AdminRequest::Confirm { handle } => handle_confirm(server, caller, &handle).await,
        AdminRequest::Revert { handle } => handle_manual_revert(server, caller, &handle).await,
        AdminRequest::Approve { handle } => handle_approve(server, caller, &handle).await,
        AdminRequest::Resume { handle } => handle_resume(server, caller, &handle).await,
        AdminRequest::Deny { handle } => {
            handle_deny(server, caller, &handle, "operator denied").await
        }
        AdminRequest::Provisionals => {
            let (is_daemon, caller_key) = caller_scope(server, caller);
            let items = server
                .state
                .provisional
                .read()
                .await
                .visible_list()
                .iter()
                .filter(|p| {
                    is_daemon
                        || scope_eq(&p.principal, &caller_key)
                        || scope_eq(&p.requester_principal, &caller_key)
                })
                .map(ProvisionalSummary::from_row)
                .collect();
            AdminResponse::Provisionals { items }
        }
        AdminRequest::ApprovalList => {
            let (is_daemon, caller_key) = caller_scope(server, caller);
            let items = server
                .state
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
            match approval_scope_check(server, caller, &handle).await {
                Ok((approval, _is_operator)) => AdminResponse::ApprovalShow {
                    item: ApprovalSummary::from_row(&approval),
                },
                Err(message) => AdminResponse::Error { message },
            }
        }
        AdminRequest::ApprovalWait {
            handle: _,
            timeout_secs: _,
        } => unreachable!("approval waits use the owned admin entry point"),
        AdminRequest::ApprovalNote { handle, text } => {
            handle_approval_note(server, caller, &handle, &text).await
        }
        AdminRequest::ApprovalWithdraw { handle } => {
            handle_approval_withdraw(server, caller, &handle).await
        }
        AdminRequest::VerbList => {
            let cat = match server
                .refresh_and_lease_verb_catalog_for_use("verb list projection")
                .await
            {
                Ok(catalog) => catalog,
                Err(error) => {
                    return AdminResponse::Error {
                        message: format!("verb catalog authority is unavailable: {error}"),
                    }
                }
            };
            if caller_is_session_admin(server, caller) {
                let current_stamp = server.state.evaluator.verb_promotion_stamp();
                let items = cat
                    .list()
                    .iter()
                    .map(|v| VerbSummary {
                        name: v.name.clone(),
                        description: v.description.clone(),
                        binary: v.binary.clone(),
                        baseline: v.baseline,
                        coverage: v.coverage.clone(),
                        credential_plan: v.credential_plan.clone(),
                        consequence: v.consequence.as_str().to_string(),
                        hold: v.hold,
                        trusted: verb_effective_trust(v, current_stamp),
                        has_revert: v.revert.is_some(),
                        params: v
                            .params
                            .iter()
                            .map(|(k, spec)| (k.clone(), spec.pattern_text().to_string()))
                            .collect(),
                        auto_promoted: v.auto_promoted,
                        evidence: v.evidence.clone(),
                    })
                    .collect();
                AdminResponse::Verbs { items }
            } else {
                let visible_session_verbs = visible_activated_verbs(server, caller).await;
                let items = cat
                    .list()
                    .iter()
                    .filter(|verb| verb.baseline || visible_session_verbs.contains(&verb.name))
                    .map(verb_menu_item)
                    .collect();
                AdminResponse::VerbMenu { items }
            }
        }
        AdminRequest::VerbShow { name } => {
            let catalog = match server
                .refresh_and_lease_verb_catalog_for_use("verb detail projection")
                .await
            {
                Ok(catalog) => catalog,
                Err(error) => {
                    return AdminResponse::Error {
                        message: format!("verb catalog authority is unavailable: {error}"),
                    }
                }
            };
            if caller_is_session_admin(server, caller) {
                return match catalog.get(&name).cloned() {
                    Some(verb) => AdminResponse::VerbCreated {
                        verb,
                        persisted: true,
                        preview_digest: None,
                    },
                    None => AdminResponse::Error {
                        message: format!("unknown verb: '{name}'"),
                    },
                };
            }
            let visible_session_verbs = visible_activated_verbs(server, caller).await;
            match catalog
                .get(&name)
                .filter(|verb| verb.baseline || visible_session_verbs.contains(&verb.name))
            {
                Some(verb) => AdminResponse::VerbMenu {
                    items: vec![verb_menu_item(verb)],
                },
                None => AdminResponse::Error {
                    message: "unknown or unavailable verb".to_string(),
                },
            }
        }
        AdminRequest::VerbAdd { verb } => {
            let candidate = verb.clone();
            let result = server
                .mutate_verb_catalog("operator verb catalog append", move |catalog| {
                    catalog.append_operator_verb(&candidate)
                })
                .await;
            match result {
                Ok(persisted_verb) => {
                    let definition_digest =
                        format!("sha256:{}", persisted_verb.definition_digest());
                    server.emit_audit_ungated(
                        AuditEvent::new(AuditKind::VerbCreated)
                            .caller(caller)
                            .field("name", &persisted_verb.name)
                            .field("definition_digest", &definition_digest)
                            .field("consequence", persisted_verb.consequence.as_str())
                            .field("trusted", persisted_verb.trusted)
                            .field("source", "operator_file"),
                    );
                    AdminResponse::VerbCreated {
                        verb: persisted_verb,
                        persisted: true,
                        preview_digest: None,
                    }
                }
                Err(error) => AdminResponse::Error {
                    message: format!("verb add rejected: {error}"),
                },
            }
        }
        AdminRequest::VerbDelete { name } => {
            let delete_name = name.clone();
            match server
                .mutate_verb_catalog("verb catalog deletion", move |catalog| {
                    catalog.delete_verb(&delete_name)
                })
                .await
            {
                Ok(_) => AdminResponse::Ok,
                Err(error) => AdminResponse::Error {
                    message: error.to_string(),
                },
            }
        }
        AdminRequest::VerbCreate {
            prose,
            binary_hint,
            preview,
            gate_feedback,
        } => {
            let prose_norm = normalize_ws(&prose);
            if prose_norm.is_empty() {
                return AdminResponse::Error {
                    message: "verb create requires non-empty --prompt prose".to_string(),
                };
            }
            let mut verb = match server
                .state
                .evaluator
                .synthesize_verb(&prose, binary_hint.as_deref(), &gate_feedback)
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    return AdminResponse::Error {
                        message: format!("verb synthesis failed: {e}"),
                    }
                }
            };
            // Explanatory provenance is normalized and sanitized before it
            // contributes to preview identity or durable catalog content.
            verb.source_prose = Some(prose_norm);
            if let Some(ev) = verb.evidence.take() {
                verb.evidence = Some(normalize_ws(&ev));
            }
            // Prose synthesis creates a capability for deliberate activation,
            // never daemon-wide baseline authority. Global promotion requires a
            // separate operator-authored catalog edit.
            verb.baseline = false;
            // The model chose this shape, so do not trust its safety-critical
            // fields: a synthesized verb is never `trusted` (the LLM still
            // evaluates the rendered command at run time), and the shape must
            // pass the synthesis safety gate (no shell/interpreter binary, no
            // over-broad parameter pattern, kebab-case name).
            verb.trusted = false;
            verb = match guard::gating::verb::canonicalize_synthesized_verb_envelope(verb) {
                Ok(verb) => verb,
                Err(e) => {
                    return AdminResponse::Error {
                        message: format!("synthesized verb rejected by the safety gate: {e}"),
                    }
                }
            };
            if let Err(e) = guard::gating::verb::validate_synthesized_safety(&verb) {
                return AdminResponse::Error {
                    message: format!("synthesized verb rejected by the safety gate: {e}"),
                };
            }
            if let Err(error) = server.state.verbs.read().await.validate_candidate(&verb) {
                return AdminResponse::Error {
                    message: format!("synthesized verb rejected by validation: {error}"),
                };
            }
            if !preview {
                if let Err(message) = preflight_synthesized_verb(server, caller, &verb).await {
                    return AdminResponse::Error { message };
                }
            }
            let result = if preview {
                Ok(())
            } else {
                let candidate = verb.clone();
                server
                    .mutate_verb_catalog("verb catalog append", move |catalog| {
                        catalog.append_verb(&candidate)
                    })
                    .await
            };
            match result {
                Ok(()) => {
                    if preview {
                        // Store the reviewed candidate so a later install can
                        // reproduce it exactly instead of synthesizing again.
                        let digest = verb.definition_digest();
                        server
                            .state
                            .verb_previews
                            .write()
                            .await
                            .insert(digest.clone(), verb.clone());
                        AdminResponse::VerbCreated {
                            verb,
                            persisted: false,
                            preview_digest: Some(digest),
                        }
                    } else {
                        server.emit_audit_ungated(
                            AuditEvent::new(AuditKind::VerbCreated)
                                .field("name", &verb.name)
                                .field("consequence", verb.consequence.as_str())
                                .field("trusted", verb.trusted),
                        );
                        AdminResponse::VerbCreated {
                            verb,
                            persisted: true,
                            preview_digest: None,
                        }
                    }
                }
                Err(e) => AdminResponse::Error {
                    message: format!("synthesized verb rejected by validation: {e}"),
                },
            }
        }
        AdminRequest::VerbCreateFromPreview { digest } => {
            let stored = server.state.verb_previews.read().await.lookup(&digest);
            let (full_digest, verb) = match stored {
                Ok(found) => found,
                Err(message) => return AdminResponse::Error { message },
            };
            // The gate re-runs at install time: the daemon's rules may have
            // tightened since the preview, and the stored shape must never
            // outrank a live rejection.
            if let Err(e) = guard::gating::verb::validate_canonical_synthesized_verb_envelope(&verb)
            {
                return AdminResponse::Error {
                    message: format!("previewed verb rejected by the safety gate: {e}"),
                };
            }
            if let Err(error) = server.state.verbs.read().await.validate_candidate(&verb) {
                return AdminResponse::Error {
                    message: format!("previewed verb rejected by validation: {error}"),
                };
            }
            if let Err(message) = preflight_synthesized_verb(server, caller, &verb).await {
                return AdminResponse::Error { message };
            }
            let candidate = verb.clone();
            let result = server
                .mutate_verb_catalog("previewed verb catalog append", move |catalog| {
                    catalog.append_verb(&candidate)
                })
                .await;
            match result {
                Ok(()) => {
                    server
                        .state
                        .verb_previews
                        .write()
                        .await
                        .remove(&full_digest);
                    server.emit_audit_ungated(
                        AuditEvent::new(AuditKind::VerbCreated)
                            .field("name", &verb.name)
                            .field("consequence", verb.consequence.as_str())
                            .field("trusted", verb.trusted)
                            .field("preview_digest", &full_digest),
                    );
                    AdminResponse::VerbCreated {
                        verb,
                        persisted: true,
                        preview_digest: Some(full_digest),
                    }
                }
                Err(e) => AdminResponse::Error {
                    message: format!("previewed verb rejected by validation: {e}"),
                },
            }
        }
        AdminRequest::VerbAmend {
            name,
            expected_digest,
            replacement,
        } => {
            let new_digest = replacement.definition_digest();
            let amend_name = name.clone();
            let amend_digest = expected_digest.clone();
            let amend_replacement = replacement.clone();
            let result = server
                .mutate_verb_catalog("verb catalog amendment", move |catalog| {
                    catalog.amend_verb_if_digest(&amend_name, &amend_digest, &amend_replacement)
                })
                .await;
            match result {
                Ok(previous) => {
                    debug_assert_eq!(previous.definition_digest(), expected_digest);
                    server.emit_audit_ungated(
                        AuditEvent::new(AuditKind::VerbAmended)
                            .field("name", &name)
                            .field("previous_digest", &expected_digest)
                            .field("digest", &new_digest),
                    );
                    AdminResponse::VerbAmended {
                        verb: *replacement,
                        previous_digest: expected_digest,
                        digest: new_digest,
                    }
                }
                Err(error) => AdminResponse::Error {
                    message: format!("verb amend rejected: {error}"),
                },
            }
        }
        AdminRequest::VerbCoverageList => {
            let items = match &server.state.api_coverage {
                Some(store) => {
                    if let Err(error) = super::api_judge::refresh_api_coverage_once(store).await {
                        return AdminResponse::Error {
                            message: format!("API coverage authority is unavailable: {error}"),
                        };
                    }
                    match super::api_judge::lease_api_coverage_for_decision(store).await {
                        Ok(lease) => lease.coverage(),
                        Err(error) => {
                            return AdminResponse::Error {
                                message: format!("API coverage authority is unavailable: {error}"),
                            }
                        }
                    }
                }
                None => Vec::new(),
            };
            AdminResponse::VerbCoverage { items }
        }
        AdminRequest::VerbCoverageClear => {
            let Some(store) = &server.state.api_coverage else {
                return AdminResponse::VerbCoverageCleared { removed: 0 };
            };
            match guard::learned_rules::run_async_durable_store_operation(
                store,
                "API coverage clear",
                |candidate| candidate.clear_generated(),
            )
            .await
            {
                Ok(removed) => {
                    server.emit_audit_ungated(
                        AuditEvent::new(AuditKind::ApiVerbCoverageCleared)
                            .field("removed", removed),
                    );
                    AdminResponse::VerbCoverageCleared { removed }
                }
                Err(error) => AdminResponse::Error {
                    message: format!("failed to clear generated API verb coverage: {error}"),
                },
            }
        }
        #[cfg(test)]
        AdminRequest::SavedGrantSave { grant } => {
            let before = server.state.saved_grants.read().await.clone();
            let result = server.state.saved_grants.write().await.insert(grant);
            match result {
                Ok(grant) => {
                    if let Some(store) = &server.state.session_store {
                        if let Err(error) = store.save_saved_grant(grant.clone()).await {
                            *server.state.saved_grants.write().await = before;
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
        #[cfg(test)]
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
            let before = server.state.saved_grants.read().await.clone();
            let result = {
                let mut catalog = server.state.saved_grants.write().await;
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
                    if let Some(store) = &server.state.session_store {
                        if let Err(error) = store.save_saved_grant(grant.clone()).await {
                            *server.state.saved_grants.write().await = before;
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
        #[cfg(test)]
        AdminRequest::SavedGrantRegenerate {
            name,
            prompt,
            proposal_id,
        } => {
            let Some(existing) = server.state.saved_grants.read().await.get(&name).cloned() else {
                return AdminResponse::Error {
                    message: format!("unknown saved grant: '{name}'"),
                };
            };
            let regime = server.state.evaluator.verb_promotion_stamp().to_string();
            let (prompt, synthesized, is_apply) = if let Some(proposal_id) = proposal_id {
                let proposal = match decode_regeneration_proposal(
                    &proposal_id,
                    server.config.regeneration_proposal_key.as_ref(),
                ) {
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
                let synthesized = match server
                    .state
                    .evaluator
                    .synthesize_verb(&prompt, None, &[])
                    .await
                {
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
                &*server.state.saved_grants.read().await,
                &*server.state.verbs.read().await,
                &name,
                updated,
                verb.clone(),
            );
            let (_staged_grants, _staged_verbs, updated, added, removed, changed) = match staged {
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
                let proposal_id = match encode_regeneration_proposal(
                    &proposal,
                    server.config.regeneration_proposal_key.as_ref(),
                ) {
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
            if let Some(store) = &server.state.session_store {
                if let Err(error) = store.save_saved_grant(updated.clone()).await {
                    return AdminResponse::Error {
                        message: format!("failed to persist regenerated saved grant: {error}"),
                    };
                }
            }
            let mut live_grants = server.state.saved_grants.write().await;
            if live_grants
                .get(&name)
                .is_none_or(|current| current.revision != existing.revision)
            {
                return AdminResponse::Error {
                    message: "regeneration proposal is stale: saved grant revision changed"
                        .to_string(),
                };
            }
            let mut live_verbs = server.state.verbs.write().await;
            let mut next_grants = live_grants.clone();
            let mut next_verbs = live_verbs.clone();
            let updated = match next_grants.replace(updated) {
                Ok(updated) => updated,
                Err(error) => {
                    return AdminResponse::Error {
                        message: error.to_string(),
                    }
                }
            };
            if let Err(error) = next_verbs.remove_saved_grant_verbs(&name) {
                return AdminResponse::Error {
                    message: error.to_string(),
                };
            }
            if let Err(error) = next_verbs.upsert_saved_grant_verb(verb) {
                return AdminResponse::Error {
                    message: error.to_string(),
                };
            }
            *live_grants = next_grants;
            *live_verbs = next_verbs;
            AdminResponse::SavedGrantRegenerated {
                grant: updated,
                added,
                removed,
                changed,
            }
        }
        #[cfg(test)]
        AdminRequest::GrantRequestSubmit {
            session_token,
            caller_token,
            saved_grant,
            prompt,
            delta,
        } => {
            let _ = caller_token;
            if let Some(response) = enforce_session_owner_for_admin(
                server,
                caller,
                &session_token,
                "grant request submission",
            )
            .await
            {
                return response;
            }
            prune_grant_requests(server).await;
            let (
                issued_saved_grant,
                issued_saved_revision,
                issued_session_revision,
                session_expires_at,
                requester,
            ) = {
                let registry = server.state.sessions.read().await;
                if !registry.has(&session_token) {
                    return AdminResponse::Error {
                        message: format!("unknown active session: '{session_token}'"),
                    };
                }
                if let Some(reason) =
                    registry.suspension_reason(&session_token, &server.config.behavior_limits)
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
                    registry.owner_for(&session_token),
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
            request.requester = match requester {
                Some(SessionOwner::Principal(principal)) => Some(principal),
                _ => None,
            };
            if grant_request_payload_bytes(&request) > MAX_GRANT_REQUEST_PAYLOAD_BYTES {
                return AdminResponse::Error {
                    message: format!(
                        "grant request payload exceeds the {} byte limit",
                        MAX_GRANT_REQUEST_PAYLOAD_BYTES
                    ),
                };
            }
            request = crate::session_store::sanitize_grant_request(request);
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
                Some(name) => server.state.saved_grants.read().await.get(name).cloned(),
                None => None,
            };
            let auto_approved = selected.is_some_and(|grant| {
                Some(grant.revision) == request.issued_saved_revision
                    && grant.auto_approve_requests
                    && grant.contains_delta(&request.delta)
            });
            let _transition = server.state.authority_transition_gate.lock().await;
            {
                let mut requests = server.state.grant_requests.write().await;
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
            if let Some(store) = &server.state.session_store {
                if let Err(error) = store.save_grant_request(request.clone()).await {
                    server
                        .state
                        .grant_requests
                        .write()
                        .await
                        .remove(&request.handle);
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
                approved.next_action = format!("guard access show {}", approved.handle);
                if let Err(message) =
                    apply_and_persist_grant_request_delta_if_current(server, &pending, &approved)
                        .await
                {
                    return AdminResponse::Error { message };
                }
                request = approved;
            }
            server
                .state
                .grant_requests
                .write()
                .await
                .insert(request.handle.clone(), request.clone());
            emit_grant_request_event(server, &request, "grant_request_submitted");
            AdminResponse::GrantRequest {
                request: redact_grant_request(request),
            }
        }
        #[cfg(test)]
        AdminRequest::GrantRequestList {
            session_token,
            caller_token,
        } => {
            let _ = caller_token;
            prune_grant_requests(server).await;
            let is_admin = caller_is_session_admin(server, caller);
            if !is_admin {
                let Some(target) = session_token.as_deref() else {
                    return AdminResponse::Error {
                        message: "grant request list requires GUARD_SESSION".to_string(),
                    };
                };
                if let Some(response) =
                    enforce_session_owner_for_admin(server, caller, target, "grant request listing")
                        .await
                {
                    return response;
                }
            }
            let items = server
                .state
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
        #[cfg(test)]
        AdminRequest::GrantRequestShow {
            handle,
            session_token,
        } => {
            prune_grant_requests(server).await;
            let request = server
                .state
                .grant_requests
                .read()
                .await
                .get(&handle)
                .cloned();
            let Some(request) = request else {
                return AdminResponse::Error {
                    message: "unknown or unauthorized grant request".to_string(),
                };
            };
            if !caller_is_session_admin(server, caller) {
                if session_token.as_deref() != Some(request.session_token.as_str()) {
                    return AdminResponse::Error {
                        message: "unknown or unauthorized grant request".to_string(),
                    };
                }
                if let Some(response) = enforce_session_owner_for_admin(
                    server,
                    caller,
                    &request.session_token,
                    "grant request inspection",
                )
                .await
                {
                    return response;
                }
            }
            AdminResponse::GrantRequest {
                request: redact_grant_request(request),
            }
        }
        #[cfg(test)]
        AdminRequest::GrantRequestApprove { handle } => {
            decide_grant_request(server, &handle, true, "approved by operator").await
        }
        #[cfg(test)]
        AdminRequest::GrantRequestDeny { handle, reason } => {
            decide_grant_request(server, &handle, false, &reason).await
        }
        #[cfg(test)]
        AdminRequest::GrantRequestWithdraw {
            handle,
            session_token,
        } => {
            prune_grant_requests(server).await;
            let _transition = server.state.authority_transition_gate.lock().await;
            let current = server
                .state
                .grant_requests
                .read()
                .await
                .get(&handle)
                .cloned();
            let Some(current) = current else {
                return AdminResponse::Error {
                    message: format!("unknown grant request: '{handle}'"),
                };
            };
            if !caller_is_session_admin(server, caller) {
                if session_token.as_deref() != Some(current.session_token.as_str()) {
                    return AdminResponse::Error {
                        message: "unknown or unauthorized grant request".to_string(),
                    };
                }
                if let Some(response) = enforce_session_owner_for_admin(
                    server,
                    caller,
                    &current.session_token,
                    "grant request withdrawal",
                )
                .await
                {
                    return response;
                }
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
            request.next_action = format!("guard access show {handle}");
            if let Some(store) = &server.state.session_store {
                if let Err(error) = store
                    .compare_and_swap_grant_request(current.clone(), request.clone())
                    .await
                {
                    reconcile_grant_request_from_store(server, &handle).await;
                    return AdminResponse::Error {
                        message: format!("grant request transition conflict: {error}"),
                    };
                }
            }
            server
                .state
                .grant_requests
                .write()
                .await
                .insert(handle, request.clone());
            emit_grant_request_event(server, &request, "grant_request_withdrawn");
            AdminResponse::GrantRequest {
                request: redact_grant_request(request),
            }
        }
        AdminRequest::AccessRequest { intent } => {
            match submit_access_request(server, caller, None, &intent, None, None).await {
                Ok(item) => AdminResponse::AccessItem { item },
                Err(message) => AdminResponse::Error { message },
            }
        }
        AdminRequest::AccessApprove {
            handles,
            uses,
            wait_secs,
        } => {
            if wait_secs.is_some() {
                return AdminResponse::Error {
                    message: "approval wait must use the one-RPC admin path".to_string(),
                };
            }
            let audience = AccessAudience::from_caller(server, caller);
            let mut items = Vec::with_capacity(handles.len());
            for handle in handles {
                // Resolve the class before deciding: approving a release-class
                // hold consumes the row, so the class is no longer readable
                // from state afterwards.
                let consequence = consequence_for_reference(server, &handle).await;
                let mut item = if server
                    .state
                    .grant_requests
                    .read()
                    .await
                    .contains_key(&handle)
                {
                    approve_access_request(server, &handle, uses, &audience).await
                } else {
                    approve_held_access(server, caller, &handle, uses, &audience).await
                };
                item.consequence = consequence;
                items.push(item);
            }
            AdminResponse::AccessDecisions { items, wait: None }
        }
        AdminRequest::AccessDeny { handles, reason } => {
            let reason = match reason {
                Some(reason) => match validate_access_denial_reason(&reason) {
                    Ok(reason) => reason,
                    Err(message) => return AdminResponse::Error { message },
                },
                None => "denied by operator".to_string(),
            };
            let mut items = Vec::with_capacity(handles.len());
            for handle in handles {
                let consequence = consequence_for_reference(server, &handle).await;
                let response = if server
                    .state
                    .grant_requests
                    .read()
                    .await
                    .contains_key(&handle)
                {
                    decide_grant_request(server, &handle, false, &reason).await
                } else if let Some(item) =
                    retire_invalid_durable_access_request(server, &handle).await
                {
                    items.push(item);
                    continue;
                } else {
                    handle_deny(server, caller, &handle, &reason).await
                };
                let mut item = access_decision_from_response(&handle, response);
                item.consequence = consequence;
                items.push(item);
            }
            AdminResponse::AccessDecisions { items, wait: None }
        }
        AdminRequest::AccessRevoke { target } => revoke_access_target(server, caller, target).await,
        AdminRequest::AccessExtend {
            target,
            intent,
            uses,
        } => {
            match submit_access_request(server, caller, Some(&target), &intent, uses, None).await {
                Ok(item) if item.kind == "request" => AdminResponse::AccessDecisions {
                    items: vec![
                        approve_access_request(
                            server,
                            &item.reference,
                            uses,
                            &AccessAudience::from_caller(server, caller),
                        )
                        .await,
                    ],
                    wait: None,
                },
                Ok(item) => AdminResponse::AccessDecisions {
                    items: vec![AccessDecisionResult {
                        request: item.reference,
                        success: true,
                        state: item.state,
                        target: Some(item.target),
                        remaining_uses: item.remaining_uses,
                        use_policy: item.use_policy,
                        message: "equivalent authority is already active; no change made"
                            .to_string(),
                        consequence: String::new(),
                    }],
                    wait: None,
                },
                Err(message) => AdminResponse::Error { message },
            }
        }
        AdminRequest::AccessList => Box::pin(list_access_items(server, caller)).await,
        AdminRequest::AccessWhoami => Box::pin(access_whoami_item(server, caller)).await,
        AdminRequest::AccessShow { reference } => {
            Box::pin(show_access_item(server, caller, &reference)).await
        }
        AdminRequest::AccessStatus { reference } => {
            let token = match Box::pin(access_session_token(server, caller, &reference)).await {
                Ok(token) => token,
                Err(message) => return AdminResponse::Error { message },
            };
            Box::pin(session_status_response(server, &token, true)).await
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
            let _ = caller_token;
            let is_admin = caller_is_session_admin(server, caller);
            if !is_admin && session_token.is_none() {
                return AdminResponse::Error {
                    message: "batch evaluation requires an active caller-owned session".to_string(),
                };
            }
            // A non-admin caller may batch-evaluate only against a session it
            // owns, verified by the daemon-read principal rather than by the
            // bearer token it presents.
            if let Some(token) = session_token.as_deref() {
                if let Some(response) =
                    enforce_session_owner_for_admin(server, caller, token, "batch evaluation").await
                {
                    return response;
                }
            }
            if let Some(token) = session_token.as_deref() {
                let registry = server.state.sessions.read().await;
                if !registry.has(token) {
                    return AdminResponse::Error {
                        message: format!("unknown active session: '{token}'"),
                    };
                }
                if let Some(reason) =
                    registry.suspension_reason(token, &server.config.behavior_limits)
                {
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
            let mut preview = server.clone();
            preview.config.dry_run = true;
            preview.config.admission_preview = true;
            preview.state.session_store = None;
            preview.state.sessions = std::sync::Arc::new(tokio::sync::RwLock::new(
                server.state.sessions.read().await.clone(),
            ));
            preview.state.verbs = std::sync::Arc::new(tokio::sync::RwLock::new(
                server.state.verbs.read().await.clone(),
            ));
            preview.state.saved_grants = std::sync::Arc::new(tokio::sync::RwLock::new(
                server.state.saved_grants.read().await.clone(),
            ));
            preview.state.grant_requests =
                std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::BTreeMap::new()));
            preview.state.authority_transition_gate =
                std::sync::Arc::new(tokio::sync::Mutex::new(()));
            preview.state.provisional = std::sync::Arc::new(tokio::sync::RwLock::new(
                guard::gating::provisional::ProvisionalRegistry::new(),
            ));
            preview.state.approvals = std::sync::Arc::new(tokio::sync::RwLock::new(
                guard::gating::approval::ApprovalRegistry::new(),
            ));
            preview.state.read_grants = std::sync::Arc::new(tokio::sync::RwLock::new(
                guard::gating::read_grant::GrantReadRegistry::new(),
            ));
            preview.state.notify_hook = None;
            let mut items = Vec::with_capacity(commands.len());
            for command in commands {
                let rendered = redact_command_line(&command.binary, &command.args);
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

#[cfg(test)]
mod status_response_tests {
    use super::*;

    #[tokio::test]
    async fn status_without_operator_authority_uses_the_compatible_error_shape() {
        let server = crate::server::tests::config_for_proposal_test();
        let response = dispatch_admin_request(
            &server,
            &CallerIdentity::Unix { uid: 1_001 },
            AdminRequest::Status,
        )
        .await;

        assert!(matches!(response, AdminResponse::Error { .. }));
    }
}

/// Structural mint-time preflight for synthesized access coverage: every
/// rendered candidate must be finite, renderable, and not categorically
/// refused by the live api-policy. Deliberately no dry-run execution: an
/// approved access request executes under preauthorized coverage, so a
/// mint-time evaluator verdict (or a provider failure) proves nothing about
/// the capability's usability and must not block the request.
async fn preflight_synthesized_verb_structural(
    server: &ServerContext,
    verb: &Verb,
) -> Result<VerbCatalog, String> {
    let parameter_sets = verb.finite_parameter_sets().ok_or_else(|| {
        format!(
            "synthesized verb admission preflight is incomplete: '{}' has a non-finite parameter pattern or more than 64 rendered candidates; enumerate bounded values before storage",
            verb.name
        )
    })?;
    let catalog = VerbCatalog::for_admission_preview(verb).map_err(|error| {
        format!("synthesized verb rejected before admission preflight: {error}")
    })?;
    for (index, params) in parameter_sets.into_iter().enumerate() {
        let rendered = catalog.render(&verb.name, &params).map_err(|error| {
            format!(
                "synthesized verb rejected before admission preflight for rendered candidate {}: {error}",
                index + 1
            )
        })?;
        preflight_synthesized_api_policy(server, &rendered.binary, &rendered.args).await?;
    }
    Ok(catalog)
}

async fn preflight_synthesized_verb(
    server: &ServerContext,
    caller: &CallerIdentity,
    verb: &Verb,
) -> Result<(), String> {
    let parameter_sets = verb.finite_parameter_sets().ok_or_else(|| {
        format!(
            "synthesized verb admission preflight is incomplete: '{}' has a non-finite parameter pattern or more than 64 rendered candidates; enumerate bounded values before storage",
            verb.name
        )
    })?;
    let catalog = preflight_synthesized_verb_structural(server, verb).await?;

    // Use the production admission pipeline with execution disabled and every
    // authority-bearing registry isolated. The candidate is baseline only in
    // this clone, which forces its untrusted typed coverage through evaluator
    // admission without granting a live session or mutating the real catalog.
    let mut preview = server.clone();
    preview.config.dry_run = true;
    preview.config.admission_preview = true;
    preview.config.gate = guard::gating::GateMode::Consequence;
    preview.state.session_store = None;
    preview.state.sessions = std::sync::Arc::new(tokio::sync::RwLock::new(SessionRegistry::new()));
    preview.state.verbs = std::sync::Arc::new(tokio::sync::RwLock::new(catalog.clone()));
    preview.state.saved_grants = std::sync::Arc::new(tokio::sync::RwLock::new(
        server.state.saved_grants.read().await.clone(),
    ));
    preview.state.grant_requests =
        std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::BTreeMap::new()));
    preview.state.authority_transition_gate = std::sync::Arc::new(tokio::sync::Mutex::new(()));
    preview.state.provisional = std::sync::Arc::new(tokio::sync::RwLock::new(
        guard::gating::provisional::ProvisionalRegistry::new(),
    ));
    preview.state.approvals = std::sync::Arc::new(tokio::sync::RwLock::new(
        guard::gating::approval::ApprovalRegistry::new(),
    ));
    preview.state.read_grants = std::sync::Arc::new(tokio::sync::RwLock::new(
        guard::gating::read_grant::GrantReadRegistry::new(),
    ));
    preview.state.notify_hook = None;

    for (index, params) in parameter_sets.into_iter().enumerate() {
        // Access-request synthesis reaches this preflight through the denial
        // escalation path, while execution can itself offer an access request.
        // Poll the boxed dry-run edge in a separate task so the mutually
        // recursive path has both a finite future size and a fresh stack.
        let request = ExecuteRequest {
            binary: String::new(),
            args: Vec::new(),
            auth_token: None,
            env: Default::default(),
            secrets: Default::default(),
            secret_files: Default::default(),
            stream: false,
            session_token: None,
            revert: None,
            confirm_within_secs: None,
            require_approval: None,
            wait_approval_secs: None,
            verb: Some(VerbInvocation {
                name: verb.name.clone(),
                params,
            }),
            reevaluate: true,
            ssh_hostkey: None,
            cwd: None,
        };
        let task_server = preview.clone();
        let task_caller = caller.clone();
        let runtime = tokio::runtime::Handle::current();
        let response = tokio::task::spawn_blocking(move || {
            runtime.block_on(async move {
                Box::pin(super::execute::execute_command(
                    request,
                    &task_server,
                    &task_caller,
                ))
                .await
                .into_response()
            })
        })
        .await
        .map_err(|error| format!("synthesized verb admission preflight failed: {error}"))?;
        if !response.allowed {
            return Err(format!(
                "synthesized verb rejected by admission preflight for rendered candidate {}: {}",
                index + 1,
                response.reason
            ));
        }
    }
    Ok(())
}

async fn preflight_synthesized_api_policy(
    server: &ServerContext,
    binary: &str,
    args: &[String],
) -> Result<(), String> {
    let Some(operation) = synthesized_kubectl_api_operation(binary, args) else {
        return Ok(());
    };
    let proxies = server
        .state
        .protocol_registry
        .read()
        .await
        .values()
        .filter(|proxy| proxy.protocol_name() == "kubernetes")
        .cloned()
        .collect::<Vec<_>>();
    if proxies.is_empty() {
        return Ok(());
    }

    let mut refusals = Vec::with_capacity(proxies.len());
    for proxy in proxies {
        match proxy.categorical_policy_refusal(&operation).await {
            Ok(Some(reason)) => refusals.push(reason),
            Ok(None) => return Ok(()),
            Err(error) => {
                return Err(format!(
                    "synthesized verb api-policy preflight failed: {error}"
                ))
            }
        }
    }
    let target = match operation.subresource.as_deref() {
        Some(subresource) => format!(
            "kubernetes subresource '{subresource}' on resource '{}'",
            operation.resource
        ),
        None => format!(
            "kubernetes {} on resource '{}'",
            operation.verb.as_str(),
            operation.resource
        ),
    };
    Err(format!(
        "api-policy refuses {target}: {}; approval would be unusable",
        refusals
            .first()
            .map(String::as_str)
            .unwrap_or("categorically denied")
    ))
}

fn synthesized_kubectl_api_operation(binary: &str, args: &[String]) -> Option<guard::proxy::ApiOp> {
    let binary = semantic_executable_key(binary);
    if binary != "kubectl" {
        return None;
    }

    let namespace = option_value(args, &["-n", "--namespace"]);
    let command_index = kubectl_command_index(args)?;
    let command = args[command_index].as_str();
    if command == "get" {
        if let Some(raw) = option_value(&args[command_index + 1..], &["--raw"]) {
            let (path, query) = raw.split_once('?').unwrap_or((raw.as_str(), ""));
            return guard::proxy::k8s::parse_api_op("GET", path, query);
        }
    }

    let target = kubectl_positional_after(args, command_index + 1);
    let (resource, name) = target
        .as_deref()
        .map(kubectl_resource_and_name)
        .unwrap_or_else(|| ("pods".to_string(), None));
    let explicit_subresource = option_value(args, &["--subresource"]);
    let (verb, resource, subresource) = match command {
        "proxy" => (
            guard::proxy::op::Verb::Get,
            resource,
            Some("proxy".to_string()),
        ),
        "exec" => (
            guard::proxy::op::Verb::Create,
            "pods".to_string(),
            Some("exec".to_string()),
        ),
        "attach" => (
            guard::proxy::op::Verb::Create,
            "pods".to_string(),
            Some("attach".to_string()),
        ),
        "port-forward" => (
            guard::proxy::op::Verb::Create,
            "pods".to_string(),
            Some("portforward".to_string()),
        ),
        "logs" => (
            guard::proxy::op::Verb::Get,
            "pods".to_string(),
            Some("log".to_string()),
        ),
        "get" | "describe" => (
            if args.iter().any(|argument| {
                matches!(argument.as_str(), "--watch" | "-w") || argument == "--watch=true"
            }) {
                guard::proxy::op::Verb::Watch
            } else if name.is_some() {
                guard::proxy::op::Verb::Get
            } else {
                guard::proxy::op::Verb::List
            },
            resource,
            explicit_subresource,
        ),
        "delete" => (
            if name.is_some() {
                guard::proxy::op::Verb::Delete
            } else {
                guard::proxy::op::Verb::DeleteCollection
            },
            resource,
            explicit_subresource,
        ),
        "patch" => (
            guard::proxy::op::Verb::Patch,
            resource,
            explicit_subresource,
        ),
        "replace" => (
            guard::proxy::op::Verb::Update,
            resource,
            explicit_subresource,
        ),
        _ => return None,
    };
    Some(guard::proxy::ApiOp {
        verb,
        group: String::new(),
        version: "v1".to_string(),
        resource,
        subresource,
        namespace,
        name,
        dry_run: args
            .iter()
            .any(|argument| argument == "--dry-run" || argument.starts_with("--dry-run=")),
        authority_selectors: Default::default(),
    })
}

fn option_value(args: &[String], options: &[&str]) -> Option<String> {
    for (index, argument) in args.iter().enumerate() {
        if options.contains(&argument.as_str()) {
            return args.get(index + 1).cloned();
        }
        for option in options {
            if let Some(value) = argument.strip_prefix(&format!("{option}=")) {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn kubectl_command_index(args: &[String]) -> Option<usize> {
    const GLOBAL_VALUE_OPTIONS: &[&str] = &[
        "-n",
        "--namespace",
        "--context",
        "--cluster",
        "--user",
        "--kubeconfig",
        "--request-timeout",
        "--server",
        "--token",
    ];
    let mut skip_value = false;
    for (index, argument) in args.iter().enumerate() {
        if skip_value {
            skip_value = false;
            continue;
        }
        if GLOBAL_VALUE_OPTIONS.contains(&argument.as_str()) {
            skip_value = true;
            continue;
        }
        if argument.starts_with('-') {
            continue;
        }
        return Some(index);
    }
    None
}

fn kubectl_positional_after(args: &[String], start: usize) -> Option<String> {
    const VALUE_OPTIONS: &[&str] = &[
        "-n",
        "--namespace",
        "-o",
        "--output",
        "-p",
        "--port",
        "--request-path",
        "--selector",
        "-l",
        "--field-selector",
        "--subresource",
        "--raw",
    ];
    let mut skip_value = false;
    for argument in &args[start..] {
        if skip_value {
            skip_value = false;
            continue;
        }
        if VALUE_OPTIONS.contains(&argument.as_str()) {
            skip_value = true;
            continue;
        }
        if argument.starts_with('-') {
            continue;
        }
        return Some(argument.clone());
    }
    None
}

fn kubectl_resource_and_name(target: &str) -> (String, Option<String>) {
    let (resource, name) = target
        .split_once('/')
        .map_or((target, None), |(resource, name)| (resource, Some(name)));
    let resource = match resource.to_ascii_lowercase().as_str() {
        "po" | "pod" => "pods",
        "svc" | "service" => "services",
        "deploy" | "deployment" => "deployments",
        "sts" | "statefulset" => "statefulsets",
        "ds" | "daemonset" => "daemonsets",
        "cm" | "configmap" => "configmaps",
        "secret" => "secrets",
        other => other,
    }
    .to_string();
    (resource, name.map(str::to_string))
}

/// Collapse runs of whitespace (incl. newlines) to single spaces, so prose and
/// evidence persist as a tidy single line in the YAML catalog.
fn normalize_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

const VERB_PREVIEW_CAPACITY: usize = 32;

/// Most recently previewed synthesis candidates, keyed by definition digest,
/// so `verb create --from-preview` installs exactly the candidate the operator
/// reviewed. Bounded and in-memory: a preview is a short-lived review aid, not
/// durable catalog state, and it does not survive a daemon restart.
#[derive(Default)]
pub(super) struct VerbPreviewCache {
    entries: std::collections::VecDeque<(String, Verb)>,
}

impl VerbPreviewCache {
    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Store one previewed candidate, most recent first. Re-previewing an
    /// identical candidate refreshes its position instead of duplicating it.
    pub(super) fn insert(&mut self, digest: String, verb: Verb) {
        self.entries.retain(|(existing, _)| existing != &digest);
        self.entries.push_front((digest, verb));
        self.entries.truncate(VERB_PREVIEW_CAPACITY);
    }

    /// Resolve a full digest or an unambiguous prefix to the stored candidate
    /// and its full digest. Unknown and ambiguous references are distinct,
    /// actionable errors.
    pub(super) fn lookup(&self, reference: &str) -> Result<(String, Verb), String> {
        if reference.is_empty() || !reference.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "'{reference}' is not a preview digest; pass the hex digest (or a prefix) printed by guard verb create --preview"
            ));
        }
        let matched: Vec<&(String, Verb)> = self
            .entries
            .iter()
            .filter(|(digest, _)| digest.starts_with(reference))
            .collect();
        match matched.as_slice() {
            [] => Err(format!(
                "no previewed candidate matches '{reference}'; previews live only for the daemon's lifetime, so run guard verb create --preview again"
            )),
            [(digest, verb)] => Ok((digest.clone(), verb.clone())),
            _ => Err(format!(
                "preview digest prefix '{reference}' is ambiguous; use more characters"
            )),
        }
    }

    /// Drop one stored candidate after it is installed.
    pub(super) fn remove(&mut self, digest: &str) {
        self.entries.retain(|(existing, _)| existing != digest);
    }
}

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
type RegenerationStage = (
    crate::grant_profile::SavedGrantCatalog,
    guard::gating::verb::VerbCatalog,
    crate::grant_profile::SavedGrant,
    Vec<String>,
    Vec<String>,
    Vec<String>,
);

#[cfg(test)]
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
    server: &ServerContext,
    handle: &str,
    approve: bool,
    reason: &str,
) -> AdminResponse {
    let owned_server = server.clone();
    let owned_handle = handle.to_string();
    let owned_reason = reason.to_string();
    match tokio::spawn(async move {
        decide_grant_request_owned(&owned_server, &owned_handle, approve, &owned_reason).await
    })
    .await
    {
        Ok(response) => response,
        Err(error) => AdminResponse::Error {
            message: format!("grant request coordination failed: {error}"),
        },
    }
}

async fn decide_grant_request_owned(
    server: &ServerContext,
    handle: &str,
    approve: bool,
    reason: &str,
) -> AdminResponse {
    let _transition = server.state.authority_transition_gate.lock().await;
    let request = server
        .state
        .grant_requests
        .read()
        .await
        .get(handle)
        .cloned();
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
        server.state.grant_requests.write().await.remove(handle);
        if let Some(store) = &server.state.session_store {
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
        if let Err(message) = validate_grant_request_for_approval(server, &request).await {
            return AdminResponse::Error { message };
        }
        request.status = GrantRequestStatus::Approved;
        request.next_action = format!("guard access show {}", request.handle);
    } else {
        request.status = GrantRequestStatus::Denied;
        request.next_action = format!(
            "ask the operator to review the saved authority, then run `guard access show {handle}`"
        );
    }
    request.decided_unix = Some(now_unix());
    request.decided_reason = Some(reason.to_string());
    if approve {
        if let Err(message) =
            apply_and_persist_grant_request_delta_if_current(server, &pending, &request).await
        {
            reconcile_grant_request_from_store(server, handle).await;
            return AdminResponse::Error { message };
        }
    } else if let Some(store) = &server.state.session_store {
        if let Err(error) = store
            .compare_and_swap_grant_request(pending, request.clone())
            .await
        {
            reconcile_grant_request_from_store(server, handle).await;
            return AdminResponse::Error {
                message: format!("grant request transition conflict: {error}"),
            };
        }
    }
    server
        .state
        .grant_requests
        .write()
        .await
        .insert(handle.to_string(), request.clone());
    emit_grant_request_event(server, &request, "grant_request_decided");
    AdminResponse::GrantRequest {
        request: redact_grant_request(request),
    }
}

async fn reconcile_grant_request_from_store(server: &ServerContext, handle: &str) {
    let Some(store) = &server.state.session_store else {
        return;
    };
    match store.load_grant_request(handle.to_string()).await {
        Ok(Some(durable)) => {
            server
                .state
                .grant_requests
                .write()
                .await
                .insert(handle.to_string(), durable);
        }
        Ok(None) => {
            server.state.grant_requests.write().await.remove(handle);
        }
        Err(error) => tracing::warn!(
            "failed to reconcile grant request '{}' after transition conflict: {}",
            handle,
            error
        ),
    }
}

async fn apply_and_persist_grant_request_delta_if_current(
    server: &ServerContext,
    pending: &GrantRequest,
    approved: &GrantRequest,
) -> Result<(), String> {
    let owned_server = server.clone();
    let owned_pending = pending.clone();
    let owned_approved = approved.clone();
    tokio::spawn(async move {
        apply_and_persist_grant_request_delta_owned(&owned_server, &owned_pending, &owned_approved)
            .await
    })
    .await
    .map_err(|error| format!("grant request coordination failed: {error}"))?
}

async fn apply_and_persist_grant_request_delta_owned(
    server: &ServerContext,
    pending: &GrantRequest,
    approved: &GrantRequest,
) -> Result<(), String> {
    let baseline = server.state.sessions.read().await.clone();
    if baseline.effective_revision_key(&pending.session_token) != pending.issued_session_revision {
        return Err(format!(
            "grant request '{}' no longer matches the issued session revision; submit a new request",
            pending.handle
        ));
    }
    let issued = baseline.saved_grant_for(&pending.session_token);
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
    let mut staged = baseline.clone();
    staged
        .apply_delta(&pending.session_token, &pending.delta)
        .ok_or_else(|| format!("unknown active session: '{}'", pending.session_token))?;
    if let Some(store) = &server.state.session_store {
        store
            .commit_grant_request_approval(
                pending.clone(),
                approved.clone(),
                staged.clone(),
                Vec::new(),
            )
            .await
            .map_err(|error| format!("failed to persist approved grant request: {error}"))?;
    }
    {
        let mut sessions = server.state.sessions.write().await;
        if sessions.revision() != baseline.revision() {
            return Err(
                "session authority changed while grant approval was committing; durable state remains authoritative"
                    .to_string(),
            );
        }
        *sessions = staged;
    }
    {
        let mut requests = server.state.grant_requests.write().await;
        if requests.get(&pending.handle) == Some(pending) {
            requests.insert(approved.handle.clone(), approved.clone());
        }
    }
    #[cfg(test)]
    server.state.session_publication_events.add_permits(1);
    Ok(())
}

async fn validate_grant_request_for_approval(
    server: &ServerContext,
    request: &GrantRequest,
) -> Result<(), String> {
    if request.expires_unix == 0 || now_unix() >= request.expires_unix {
        return Err(format!(
            "grant request '{}' expired; submit a new request",
            request.handle
        ));
    }
    let sessions = server.state.sessions.read().await;
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
        let current = server.state.saved_grants.read().await.get(name).cloned();
        if current.as_ref().map(|grant| grant.revision) != Some(revision) {
            return Err(format!(
                "saved grant '{name}' changed after request issuance; submit a new request"
            ));
        }
    }
    if !request.delta.override_markers.is_empty() {
        let available = server
            .state
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

pub(super) async fn prune_grant_requests(server: &ServerContext) {
    let _transition = server.state.authority_transition_gate.lock().await;
    let now = now_unix();
    let active_requests = server
        .state
        .sessions
        .read()
        .await
        .list()
        .into_iter()
        .flat_map(|summary| summary.scope.access_grants.into_iter())
        .map(|grant| grant.request)
        .collect::<std::collections::BTreeSet<_>>();
    let removed = {
        let requests = server.state.grant_requests.read().await;
        let mut removed = requests
            .iter()
            .filter(|(_, request)| {
                request.status == GrantRequestStatus::Pending
                    && (request.expires_unix == 0 || request.expires_unix <= now)
            })
            .map(|(handle, _)| handle.clone())
            .collect::<Vec<_>>();
        let mut retained_count = requests.len().saturating_sub(removed.len());
        while retained_count >= MAX_GRANT_REQUESTS {
            let oldest_terminal = requests
                .iter()
                .filter(|(handle, _)| !removed.contains(handle))
                .filter(|(_, request)| request.status != GrantRequestStatus::Pending)
                .filter(|(handle, _)| !active_requests.contains(handle.as_str()))
                .min_by_key(|(handle, request)| (request.created_unix, *handle))
                .map(|(handle, _)| handle.clone());
            let Some(handle) = oldest_terminal else {
                break;
            };
            removed.push(handle);
            retained_count = retained_count.saturating_sub(1);
        }
        removed
    };
    if !removed.is_empty() {
        if let Some(store) = &server.state.session_store {
            if let Err(error) = store.delete_grant_requests(removed.clone()).await {
                tracing::warn!("failed to prune expired grant requests: {error}");
                return;
            }
        }
        let mut requests = server.state.grant_requests.write().await;
        for handle in removed {
            requests.remove(&handle);
        }
    }
}

fn redact_grant_request(mut request: GrantRequest) -> GrantRequest {
    request.session_token = audit_session_fingerprint(Some(&request.session_token));
    // Requester-supplied free text may quote command lines that carry inline
    // credentials; redact before the request leaves the daemon.
    request.justification = redact_output_text(&request.justification);
    if let Some(prompt) = request.delta.prompt_append.take() {
        request.delta.prompt_append = Some(redact_output_text(&prompt));
    }
    if let Some(reason) = request.decided_reason.take() {
        request.decided_reason = Some(redact_output_text(&reason));
    }
    request
}

fn emit_grant_request_event(server: &ServerContext, request: &GrantRequest, event: &'static str) {
    server.emit_event(NotifyEvent {
        event,
        at_unix: now_unix(),
        handle: Some(request.handle.clone()),
        session_fingerprint: Some(audit_session_fingerprint(Some(&request.session_token))),
        requester_principal: None,
        reason: request.decided_reason.clone(),
        status: Some(request.status.as_str().to_string()),
        behavior: None,
    });
}

/// Returns `(is_operator, caller_principal)` for read-scoping. An authenticated
/// operator has deployment-wide visibility; other callers are scoped to their
/// own principal via
/// `scope_eq` (so two unauthenticated `None` callers never share rows).
fn caller_scope(server: &ServerContext, caller: &CallerIdentity) -> (bool, Option<PrincipalKey>) {
    let p = caller.principal();
    (caller_is_session_admin(server, caller), p)
}

async fn handle_confirm(
    server: &ServerContext,
    caller: &CallerIdentity,
    handle: &str,
) -> AdminResponse {
    // The CONFIRM record must be durable BEFORE the auto-revert is disarmed;
    // an unauditable confirm fails closed and leaves the revert armed.
    if !server.emit_audit(
        AuditEvent::new(AuditKind::Confirm)
            .handle(handle)
            .caller(caller),
    ) {
        return AdminResponse::Error {
            message: super::AUDIT_UNAVAILABLE_REASON.to_string(),
        };
    }
    let Some(expected) = server.state.provisional.read().await.get(handle).cloned() else {
        return AdminResponse::Error {
            message: format!("no provisional with handle '{}'", handle),
        };
    };
    let mut staged = guard::gating::provisional::ProvisionalRegistry::new();
    staged.insert(expected.clone());
    let next = match staged.confirm(handle) {
        Ok(next) => next,
        Err(error) => {
            return AdminResponse::Error {
                message: error.to_string(),
            }
        }
    };
    match persist_terminal_provisional_with_body_cleanup(server, expected, next.clone()).await {
        Ok(true) => {}
        Ok(false) => {
            return AdminResponse::Error {
                message: "provisional changed before confirmation; no decision was applied; retry the command".to_string(),
            }
        }
        Err(error) => {
            tracing::warn!(
                "failed to persist provisional confirmation for {}: {}",
                handle,
                error
            );
            return AdminResponse::Error {
                message: "cannot confirm provisional because its durable state is unavailable; no decision was applied; retry the command".to_string(),
            };
        }
    }
    forget_proxy_provenance(server, handle).await;
    server.emit_event(NotifyEvent {
        event: "decision_made",
        at_unix: now_unix(),
        handle: Some(handle.to_string()),
        session_fingerprint: next.session_fingerprint.clone(),
        requester_principal: None,
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

#[cfg(test)]
mod verb_preview_cache_tests {
    use super::*;

    fn candidate(name: &str) -> Verb {
        serde_yaml_ng::from_str(&format!(
            "name: {name}\nbinary: uptime\nargs: ['--version']\nconsequence: reversible\n"
        ))
        .unwrap()
    }

    #[test]
    fn synthesized_kubectl_preflight_uses_canonical_executable_names() {
        let operation = synthesized_kubectl_api_operation(
            "Kubectl.ExE",
            &["get".to_string(), "pods".to_string()],
        )
        .expect("mixed-case Windows executable names receive Kubernetes preflight");
        assert_eq!(operation.verb.as_str(), "list");
        assert_eq!(operation.resource, "pods");
    }

    #[test]
    fn lookup_resolves_full_digest_and_unambiguous_prefix() {
        let mut cache = VerbPreviewCache::default();
        let verb = candidate("check-compiler");
        let digest = verb.definition_digest();
        cache.insert(digest.clone(), verb);

        let (found, _) = cache.lookup(&digest).unwrap();
        assert_eq!(found, digest);
        let (found, _) = cache.lookup(&digest[..8]).unwrap();
        assert_eq!(found, digest);

        cache.remove(&digest);
        assert!(cache.lookup(&digest).unwrap_err().contains("no previewed"));
    }

    #[test]
    fn lookup_rejects_empty_ambiguous_and_non_hex_references() {
        let mut cache = VerbPreviewCache::default();
        // Two synthetic digests sharing a prefix make any shared prefix
        // ambiguous while full digests stay resolvable.
        cache.insert(format!("aa{}", "0".repeat(62)), candidate("first"));
        cache.insert(format!("ab{}", "0".repeat(62)), candidate("second"));

        assert!(cache
            .lookup("")
            .unwrap_err()
            .contains("not a preview digest"));
        assert!(cache
            .lookup("not-hex")
            .unwrap_err()
            .contains("not a preview digest"));
        assert!(cache.lookup("a").unwrap_err().contains("ambiguous"));
        assert!(cache.lookup("aa").is_ok());
    }

    #[test]
    fn capacity_evicts_the_oldest_preview() {
        let mut cache = VerbPreviewCache::default();
        for index in 0..=VERB_PREVIEW_CAPACITY {
            let digest = format!("{index:02x}{}", "f".repeat(62));
            cache.insert(digest, candidate("evict-probe"));
        }
        let oldest = format!("{:02x}{}", 0, "f".repeat(62));
        assert!(cache.lookup(&oldest).is_err(), "oldest entry must age out");
        let newest = format!("{:02x}{}", VERB_PREVIEW_CAPACITY, "f".repeat(62));
        assert!(cache.lookup(&newest).is_ok());
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
    server: &ServerContext,
    caller: &CallerIdentity,
    handle: &str,
) -> AdminResponse {
    let Some(expected) = server.state.provisional.read().await.get(handle).cloned() else {
        return AdminResponse::Error {
            message: format!("no provisional with handle '{}'", handle),
        };
    };
    let mut staged = guard::gating::provisional::ProvisionalRegistry::new();
    staged.insert(expected.clone());
    let claimed = match staged.begin_revert(handle) {
        Ok(claimed) => claimed,
        Err(error) => {
            return AdminResponse::Error {
                message: error.to_string(),
            }
        }
    };
    match persist_provisional_transition(server, expected, claimed.clone()).await {
        Ok(true) => {}
        Ok(false) => return AdminResponse::Error {
            message:
                "provisional changed before rollback; no rollback was started; retry the command"
                    .to_string(),
        },
        Err(error) => {
            tracing::warn!("failed to persist rollback claim for {}: {}", handle, error);
            return AdminResponse::Error {
                message: "cannot revert provisional because its durable state is unavailable; no rollback was started; retry the command".to_string(),
            };
        }
    }
    let outcome = finish_revert(server, &claimed, caller, "manual").await;
    AdminResponse::GateAction {
        message: outcome.0,
        exit_code: outcome.1,
        stdout: None,
        stderr: None,
    }
}

async fn claim_approval(
    server: &ServerContext,
    handle: &str,
) -> Result<guard::gating::approval::ApprovalSnapshot, String> {
    let now = now_unix();
    let pending = server.state.approvals.read().await.get(handle).cloned();
    let snapshot = {
        let mut reg = server.state.approvals.write().await;
        reg.begin_approve(handle, now)
    };
    let snapshot = match snapshot {
        Ok(s) => s,
        Err(e) => {
            if let Some(approval) = server.state.approvals.read().await.get(handle).cloned() {
                if approval.status == ApprovalStatus::Expired {
                    let _ = persist_approval(server, &approval).await;
                }
            }
            return Err(e.to_string());
        }
    };
    let approving = server.state.approvals.read().await.get(handle).cloned();
    if let (Some(store), Some(pending), Some(approving)) =
        (&server.state.session_store, pending, approving)
    {
        if let Err(error) = store
            .compare_and_swap_approval_claim(pending, approving)
            .await
        {
            reconcile_approval_from_store(server, handle).await;
            return Err(format!("failed to claim approval: {error}"));
        }
    }
    Ok(snapshot)
}

async fn reconcile_approval_from_store(server: &ServerContext, handle: &str) {
    let Some(store) = &server.state.session_store else {
        return;
    };
    match store.load_approvals().await {
        Ok(rows) => {
            if let Some(durable) = rows.into_iter().find(|approval| approval.handle == handle) {
                let wake = durable.status.is_decided();
                server
                    .state
                    .approvals
                    .write()
                    .await
                    .install_persisted(durable, wake);
            }
        }
        Err(error) => {
            tracing::warn!("failed to reconcile approval {handle}: {error}");
        }
    }
}

fn approval_result_row(
    mut approval: Approval,
    now: u64,
    exit: Option<i32>,
    stdout: Option<String>,
    stderr: Option<String>,
) -> Result<Approval, String> {
    if approval.status != ApprovalStatus::Approving {
        return Err(format!(
            "approval {} is {}, expected approving",
            approval.handle,
            approval.status.as_str()
        ));
    }
    approval.status = ApprovalStatus::Approved;
    approval.decided_unix = Some(now);
    approval.result_exit = exit;
    // Persisted transcripts are bounded per stream on every path that writes
    // them, so a row can never grow past the cap regardless of which approval
    // route produced the output.
    approval.result_stdout = bound_persisted_transcript(stdout);
    approval.result_stderr = bound_persisted_transcript(stderr);
    Ok(approval)
}

fn approval_exec_failed_row(
    mut approval: Approval,
    now: u64,
    detail: String,
) -> Result<Approval, String> {
    if approval.status != ApprovalStatus::Approving {
        return Err(format!(
            "approval {} is {}, expected approving",
            approval.handle,
            approval.status.as_str()
        ));
    }
    approval.status = ApprovalStatus::ExecFailed;
    approval.decided_unix = Some(now);
    approval.decided_reason = Some(detail);
    Ok(approval)
}

async fn commit_terminal_approval(
    server: &ServerContext,
    expected: Approval,
    next: Approval,
) -> Result<(), String> {
    let handle = expected.handle.clone();
    if let Some(store) = &server.state.session_store {
        if let Err(error) = store
            .compare_and_swap_approval(expected, next.clone())
            .await
        {
            reconcile_approval_from_store(server, &handle).await;
            return Err(format!(
                "failed to persist terminal approval {handle}: {error}"
            ));
        }
    }
    server
        .state
        .approvals
        .write()
        .await
        .install_persisted(next, true);
    Ok(())
}

async fn terminalize_revoked_session_approval(
    server: &ServerContext,
    expected: Approval,
) -> Result<(), String> {
    let mut denied = expected.clone();
    denied.status = ApprovalStatus::Denied;
    denied.decided_unix = Some(now_unix());
    denied.decided_reason = Some("originating access session was revoked".to_string());
    commit_terminal_approval(server, expected, denied).await
}

/// Why a verb-originated hold no longer binds to what the operator reviewed.
/// `CatalogChanged` applies only to rows written before per-verb digests
/// existed, where the whole-catalog version is the only available binding.
enum HeldVerbStaleness {
    Removed,
    Changed,
    CatalogChanged,
}

impl HeldVerbStaleness {
    fn clause(&self, verb_name: &str) -> String {
        match self {
            Self::Removed => format!("verb '{verb_name}' was removed since it was held"),
            Self::Changed => format!("verb '{verb_name}' changed since it was held"),
            Self::CatalogChanged => format!("verb catalog changed since '{verb_name}' was held"),
        }
    }
}

/// Gate-on-prediction staleness for a verb-originated hold: the approval is
/// bound to the matched verb's definition, so it survives unrelated catalog
/// changes and is voided only when that verb was removed or its definition
/// changed. Rows without a stored digest fall back to the whole-catalog
/// version comparison.
fn held_verb_staleness(
    snapshot: &guard::gating::approval::ApprovalSnapshot,
    verb_name: &str,
    catalog: &guard::gating::verb::VerbCatalog,
) -> Option<HeldVerbStaleness> {
    let Some(current_digest) = catalog.verb_definition_digest(verb_name) else {
        return Some(HeldVerbStaleness::Removed);
    };
    match snapshot.verb_digest.as_deref() {
        Some(held_digest) => (held_digest != current_digest).then_some(HeldVerbStaleness::Changed),
        None => (snapshot.catalog_version != Some(catalog.version()))
            .then_some(HeldVerbStaleness::CatalogChanged),
    }
}

/// Persist an operator decision without executing the held command. The row
/// remains `Pending` for storage compatibility, while `decided_reason` carries
/// the durable arm marker consumed by the requester-only resume path.
async fn arm_held_command(
    server: &ServerContext,
    caller: &CallerIdentity,
    approval: Approval,
) -> AdminResponse {
    let handle = approval.handle.clone();
    if approval.status == ApprovalStatus::Pending
        && approval_has_live_command_session_binding(&approval)
    {
        let active = {
            let sessions = server.state.sessions.read().await;
            session_token_for_approval_snapshot(&sessions, &approval.snapshot).is_some()
        };
        if !active {
            return match terminalize_revoked_session_approval(server, approval).await {
                Ok(()) => AdminResponse::Error {
                    message: "originating access session expired or was revoked".to_string(),
                },
                Err(message) => AdminResponse::Error { message },
            };
        }
    }
    if approval_is_armed(&approval) {
        return AdminResponse::Error {
            message: format!("held command {handle} is already armed for requester resume"),
        };
    }
    if approval.status != ApprovalStatus::Pending {
        return AdminResponse::Error {
            message: format!(
                "held command {handle} is already {}",
                approval.status.as_str()
            ),
        };
    }
    let now = now_unix();
    if now >= approval.deadline_unix() {
        let mut expired = approval.clone();
        expired.status = ApprovalStatus::Expired;
        expired.decided_unix = Some(now);
        expired.decided_reason = Some("expired without operator approval".to_string());
        return match commit_terminal_approval(server, approval, expired).await {
            Ok(()) => AdminResponse::Error {
                message: "expired without operator approval".to_string(),
            },
            Err(message) => AdminResponse::Error { message },
        };
    }
    let _held_verb_lease = if let Some(verb_name) = approval.snapshot.verb_name.as_deref() {
        let lease = match server
            .refresh_and_lease_verb_catalog_for_use("held command arming")
            .await
        {
            Ok(lease) => lease,
            Err(error) => {
                return AdminResponse::Error {
                    message: format!("verb catalog authority is unavailable: {error}"),
                }
            }
        };
        if let Some(staleness) = held_verb_staleness(&approval.snapshot, verb_name, &lease) {
            let message = format!(
                "{}; held approval voided, re-issue the command",
                staleness.clause(verb_name)
            );
            let mut voided = approval.clone();
            voided.status = ApprovalStatus::ExecFailed;
            voided.decided_unix = Some(now);
            voided.decided_reason = Some(message.clone());
            return match commit_terminal_approval(server, approval, voided).await {
                Ok(()) => AdminResponse::Error { message },
                Err(message) => AdminResponse::Error { message },
            };
        }
        Some(lease)
    } else {
        None
    };
    if approval.snapshot.principal.is_none() {
        return AdminResponse::Error {
            message: "held command has no authenticated requester".to_string(),
        };
    }
    if !server.emit_audit(
        AuditEvent::new(AuditKind::Approved)
            .handle(&handle)
            .caller(caller)
            .session_fingerprint(
                approval
                    .snapshot
                    .session_fingerprint
                    .as_deref()
                    .unwrap_or("none"),
            )
            .cmd(approval.snapshot.command_line())
            .reason("operator armed held command for requester resume"),
    ) {
        return AdminResponse::Error {
            message: super::AUDIT_UNAVAILABLE_REASON.to_string(),
        };
    }
    let mut armed = approval.clone();
    armed.decided_unix = Some(now);
    armed.decided_reason = Some(APPROVAL_ARMED_REASON.to_string());
    if let Err(message) = commit_terminal_approval(server, approval, armed.clone()).await {
        return AdminResponse::Error { message };
    }
    server.emit_event(NotifyEvent {
        event: "decision_made",
        at_unix: now,
        handle: Some(handle.clone()),
        session_fingerprint: armed.snapshot.session_fingerprint.clone(),
        requester_principal: armed.snapshot.principal.as_ref().map(ToString::to_string),
        reason: Some(APPROVAL_ARMED_REASON.to_string()),
        status: Some("armed".to_string()),
        behavior: None,
    });
    AdminResponse::GateAction {
        message: format!("approved held command {handle}; awaiting requester-bound resume"),
        exit_code: None,
        stdout: None,
        stderr: None,
    }
}

async fn handle_approve_claimed(
    server: &ServerContext,
    caller: &CallerIdentity,
    handle: &str,
    snapshot: guard::gating::approval::ApprovalSnapshot,
) -> AdminResponse {
    // An API-proxy hold carries no executable snapshot: approving it releases
    // the API request parked in the proxy (the proxy waiter forwards it), it
    // never spawns a process. A caller cannot steer a real command into this
    // branch by naming the sentinel binary, because the row must also be owned
    // by the daemon principal, which peer credentials assign only to the
    // daemon's own gate sink.
    if is_release_class(server, &snapshot) {
        let now = now_unix();
        // The APPROVED record must be durable BEFORE the parked API request is
        // released to the proxy waiter; fail closed otherwise.
        if !server.emit_audit(
            AuditEvent::new(AuditKind::Approved)
                .handle(handle)
                .caller(caller)
                .reason("operator authorized api-proxy request release"),
        ) {
            let Some(expected) = server.state.approvals.read().await.get(handle).cloned() else {
                return AdminResponse::Error {
                    message: format!("approval {handle} disappeared before terminal persistence"),
                };
            };
            let next = match approval_exec_failed_row(
                expected.clone(),
                now,
                super::AUDIT_UNAVAILABLE_REASON.to_string(),
            ) {
                Ok(next) => next,
                Err(message) => return AdminResponse::Error { message },
            };
            if let Err(message) = commit_terminal_approval(server, expected, next).await {
                return AdminResponse::Error { message };
            }
            return AdminResponse::Error {
                message: super::AUDIT_UNAVAILABLE_REASON.to_string(),
            };
        }
        let Some(expected) = server.state.approvals.read().await.get(handle).cloned() else {
            return AdminResponse::Error {
                message: format!("approval {handle} disappeared before terminal persistence"),
            };
        };
        let next = match approval_result_row(expected.clone(), now, None, None, None) {
            Ok(next) => next,
            Err(message) => return AdminResponse::Error { message },
        };
        if let Err(message) = commit_terminal_approval(server, expected, next).await {
            return AdminResponse::Error { message };
        }
        server.emit_event(NotifyEvent {
            event: "decision_made",
            at_unix: now,
            handle: Some(handle.to_string()),
            session_fingerprint: snapshot.session_fingerprint.clone(),
            requester_principal: snapshot.principal.as_ref().map(ToString::to_string),
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
    // Gate-on-prediction: if this hold came from a verb and that verb was
    // removed or its definition changed since it was held, the approved
    // artifact may no longer mean what the operator reviewed. Void the
    // approval rather than execute a stale rendering; unrelated catalog
    // changes leave the hold intact.
    let _held_verb_lease = if let Some(vname) = &snapshot.verb_name {
        let lease = match server
            .refresh_and_lease_verb_catalog_for_use("held command execution")
            .await
        {
            Ok(lease) => lease,
            Err(error) => {
                let detail =
                    format!("verb catalog authority is unavailable; approval voided: {error}");
                let now = now_unix();
                let Some(expected) = server.state.approvals.read().await.get(handle).cloned()
                else {
                    return AdminResponse::Error {
                        message: format!(
                            "approval {handle} disappeared before terminal persistence"
                        ),
                    };
                };
                let next = match approval_exec_failed_row(expected.clone(), now, detail.clone()) {
                    Ok(next) => next,
                    Err(message) => return AdminResponse::Error { message },
                };
                if let Err(message) = commit_terminal_approval(server, expected, next).await {
                    return AdminResponse::Error { message };
                }
                return AdminResponse::Error { message: detail };
            }
        };
        let staleness = held_verb_staleness(&snapshot, vname, &lease);
        if let Some(staleness) = staleness {
            let now = now_unix();
            let detail = format!(
                "{}; approval voided (re-issue the command)",
                staleness.clause(vname)
            );
            let Some(expected) = server.state.approvals.read().await.get(handle).cloned() else {
                return AdminResponse::Error {
                    message: format!("approval {handle} disappeared before terminal persistence"),
                };
            };
            let next = match approval_exec_failed_row(expected.clone(), now, detail.clone()) {
                Ok(next) => next,
                Err(message) => return AdminResponse::Error { message },
            };
            if let Err(message) = commit_terminal_approval(server, expected, next).await {
                return AdminResponse::Error { message };
            }
            server.emit_audit_ungated(
                AuditEvent::new(AuditKind::ApproveVoided)
                    .handle(handle)
                    .caller(caller)
                    .session_fingerprint(snapshot.session_fingerprint.as_deref().unwrap_or("none"))
                    .reason(&detail),
            );
            server.emit_event(NotifyEvent {
                event: "decision_made",
                at_unix: now,
                handle: Some(handle.to_string()),
                session_fingerprint: snapshot.session_fingerprint.clone(),
                requester_principal: snapshot.principal.as_ref().map(ToString::to_string),
                reason: Some(detail.clone()),
                status: Some("voided".to_string()),
                behavior: None,
            });
            return AdminResponse::Error { message: detail };
        }
        Some(lease)
    } else {
        None
    };
    // The exact Approving claim is already durable before this point. The
    // approval audit must also land before execution; otherwise the hold moves
    // durably to ExecFailed and no process starts.
    if !server.emit_audit(
        AuditEvent::new(AuditKind::Approved)
            .handle(handle)
            .caller(caller)
            .session_fingerprint(snapshot.session_fingerprint.as_deref().unwrap_or("none"))
            .cmd(snapshot.command_line()),
    ) {
        let now = now_unix();
        let Some(expected) = server.state.approvals.read().await.get(handle).cloned() else {
            return AdminResponse::Error {
                message: format!("approval {handle} disappeared before terminal persistence"),
            };
        };
        let next = match approval_exec_failed_row(
            expected.clone(),
            now,
            super::AUDIT_UNAVAILABLE_REASON.to_string(),
        ) {
            Ok(next) => next,
            Err(message) => return AdminResponse::Error { message },
        };
        if let Err(message) = commit_terminal_approval(server, expected, next).await {
            return AdminResponse::Error { message };
        }
        return AdminResponse::Error {
            message: super::AUDIT_UNAVAILABLE_REASON.to_string(),
        };
    }
    let reason = format!("operator-approved held command {}", handle);
    drop(_held_verb_lease);
    let result = super::gate_runtime::execute_snapshot(server, &snapshot, &reason).await;
    let now = now_unix();
    let Some(expected) = server.state.approvals.read().await.get(handle).cloned() else {
        return AdminResponse::Error {
            message: format!("approval {handle} disappeared before terminal persistence"),
        };
    };
    let (message, exit, stdout, stderr, next) = match result.exec {
        ExecOutcome::Completed {
            exit_code,
            stdout,
            stderr,
        } => {
            server.emit_audit_ungated(
                AuditEvent::new(AuditKind::ApprovedExecuted)
                    .handle(handle)
                    .caller(caller)
                    .session_fingerprint(snapshot.session_fingerprint.as_deref().unwrap_or("none"))
                    .field("exit", format!("{exit_code:?}")),
            );
            let next = match approval_result_row(
                expected.clone(),
                now,
                exit_code,
                stdout.clone(),
                stderr.clone(),
            ) {
                Ok(next) => next,
                Err(message) => return AdminResponse::Error { message },
            };
            (
                format!("approved and executed {} (exit {:?})", handle, exit_code),
                exit_code,
                stdout,
                stderr,
                next,
            )
        }
        ExecOutcome::Failed { reason: detail, .. } => {
            server.emit_audit_ungated(
                AuditEvent::new(AuditKind::ApproveExecFailed)
                    .handle(handle)
                    .caller(caller)
                    .session_fingerprint(snapshot.session_fingerprint.as_deref().unwrap_or("none"))
                    .field("detail", &detail),
            );
            let next = match approval_exec_failed_row(expected.clone(), now, detail.clone()) {
                Ok(next) => next,
                Err(message) => return AdminResponse::Error { message },
            };
            (
                format!("approved {} but execution failed: {}", handle, detail),
                None,
                None,
                None,
                next,
            )
        }
        _ => {
            let detail = "approved execution returned an unexpected non-terminal outcome";
            let next = match approval_exec_failed_row(expected.clone(), now, detail.to_string()) {
                Ok(next) => next,
                Err(message) => return AdminResponse::Error { message },
            };
            (
                format!("approved {} but execution failed: {}", handle, detail),
                None,
                None,
                None,
                next,
            )
        }
    };
    let terminal_status = next.status.as_str().to_string();
    if let Err(message) = commit_terminal_approval(server, expected, next).await {
        return AdminResponse::Error { message };
    }
    server.emit_event(NotifyEvent {
        event: "decision_made",
        at_unix: now,
        handle: Some(handle.to_string()),
        session_fingerprint: snapshot.session_fingerprint.clone(),
        requester_principal: snapshot.principal.as_ref().map(ToString::to_string),
        reason: Some(message.clone()),
        status: Some(terminal_status),
        behavior: None,
    });
    AdminResponse::GateAction {
        message,
        exit_code: exit,
        stdout,
        stderr,
    }
}

async fn handle_approve(
    server: &ServerContext,
    caller: &CallerIdentity,
    handle: &str,
) -> AdminResponse {
    let transition = server.state.authority_transition_gate.lock().await;
    let Some(approval) = server.state.approvals.read().await.get(handle).cloned() else {
        return AdminResponse::Error {
            message: format!("no approval with handle '{handle}'"),
        };
    };
    if !is_release_class(server, &approval.snapshot) {
        return arm_held_command(server, caller, approval).await;
    }
    let snapshot = match claim_approval(server, handle).await {
        Ok(snapshot) => snapshot,
        Err(message) => return AdminResponse::Error { message },
    };
    drop(transition);
    handle_approve_claimed(server, caller, handle, snapshot).await
}

/// Hard ceiling on one `ApprovalWait` park, in seconds.
const APPROVAL_WAIT_MAX_SECS: u64 = 3600;

fn approval_not_found(handle: &str) -> AdminResponse {
    AdminResponse::Error {
        message: approval_not_found_message(handle),
    }
}

fn approval_not_found_message(handle: &str) -> String {
    format!("no approval with handle '{handle}'")
}

/// Resolve one hold for a scoped reader, returning the row and whether the
/// caller holds operator authority. The handle is an unguessable bearer secret:
/// its owning principal may read its status and result, and the operator may
/// read any hold through the admin bearer. Every other caller gets the same
/// NotFound, so the response never reveals that the handle exists. Read paths
/// share this function so the check cannot drift between them.
async fn approval_scope_check(
    server: &ServerContext,
    caller: &CallerIdentity,
    handle: &str,
) -> Result<(Approval, bool), String> {
    let (is_operator, caller_key) = caller_scope(server, caller);
    let found = server.state.approvals.read().await.get(handle).cloned();
    match found {
        Some(approval) if is_operator || scope_eq(&approval.snapshot.principal, &caller_key) => {
            Ok((approval, is_operator))
        }
        _ => Err(approval_not_found_message(handle)),
    }
}

/// The refusal for waiting on a grant request, or `None` when the reference is
/// not a grant request this caller may see. The wording matches the client's
/// own pre-flight refusal so an operator reads one sentence either way.
async fn grant_request_wait_refusal(
    server: &ServerContext,
    caller: &CallerIdentity,
    handle: &str,
) -> Option<String> {
    let is_operator = caller_is_session_admin(server, caller);
    let principal = caller.principal();
    let request = server
        .state
        .grant_requests
        .read()
        .await
        .get(handle)
        .filter(|request| {
            request.requester.is_some() && (is_operator || scope_eq(&request.requester, &principal))
        })
        .cloned()?;
    let target = request
        .target
        .clone()
        .unwrap_or_else(|| "the requester's session".to_string());
    Some(grant_class_wait_refusal(handle, &target))
}

async fn handle_resume(
    server: &ServerContext,
    caller: &CallerIdentity,
    handle: &str,
) -> AdminResponse {
    let result = resume_approval(server, caller, handle).await;
    match result.exec.clone() {
        ExecOutcome::Completed {
            exit_code,
            stdout,
            stderr,
        } => AdminResponse::GateAction {
            message: format!("resumed held command {handle} (exit {exit_code:?})"),
            exit_code,
            stdout,
            stderr,
        },
        ExecOutcome::Failed { reason, .. } => AdminResponse::Error { message: reason },
        ExecOutcome::NotAttempted => AdminResponse::Error {
            message: result.policy_reason().to_string(),
        },
        _ => AdminResponse::Error {
            message: format!("held command {handle} did not produce a terminal execution result"),
        },
    }
}

/// Append a note to a held command's discussion thread, turning the gate into a
/// short operator<->requester conversation before a decision. The operator may
/// note any hold; the hold's original requester (a local peer whose principal
/// matches the snapshot) may note its own; nobody else. Returns the updated hold
/// view (including the thread) so the caller can render it.
pub(super) async fn handle_approval_note(
    server: &ServerContext,
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
    let _transition = server.state.authority_transition_gate.lock().await;
    let (is_operator, caller_key) = caller_scope(server, caller);
    let author = {
        let reg = server.state.approvals.read().await;
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
    let mut registry = server.state.approvals.write().await;
    let Some(expected) = registry.get(handle).cloned() else {
        return AdminResponse::Error {
            message: format!("no approval with handle '{}'", handle),
        };
    };
    let next = match registry.prepare_note(handle, author, text, now) {
        Ok(next) => next,
        Err(error) => {
            return AdminResponse::Error {
                message: error.to_string(),
            }
        }
    };
    if let Some(store) = &server.state.session_store {
        if let Err(error) = store
            .compare_and_swap_approval(expected, next.clone())
            .await
        {
            drop(registry);
            reconcile_approval_from_store(server, handle).await;
            return AdminResponse::Error {
                message: format!("failed to persist approval note: {error}"),
            };
        }
    }
    registry.install_persisted(next.clone(), false);
    drop(registry);
    server.emit_audit_ungated(
        AuditEvent::new(AuditKind::ApprovalNote)
            .handle(handle)
            .caller(caller)
            .field("author", author),
    );
    AdminResponse::ApprovalShow {
        item: ApprovalSummary::from_row(&next),
    }
}

async fn handle_approval_withdraw(
    server: &ServerContext,
    caller: &CallerIdentity,
    handle: &str,
) -> AdminResponse {
    let (_, caller_key) = caller_scope(server, caller);
    let owned = server
        .state
        .approvals
        .read()
        .await
        .get(handle)
        .is_some_and(|approval| {
            caller.is_local_peer() && scope_eq(&approval.snapshot.principal, &caller_key)
        });
    if !owned {
        return AdminResponse::Error {
            message: format!("no approval with handle '{handle}'"),
        };
    }
    handle_deny(server, caller, handle, "requester withdrew held command").await
}

async fn handle_deny(
    server: &ServerContext,
    caller: &CallerIdentity,
    handle: &str,
    reason: &str,
) -> AdminResponse {
    let _transition = server.state.authority_transition_gate.lock().await;
    let now = now_unix();
    let mut registry = server.state.approvals.write().await;
    let Some(expected) = registry.get(handle).cloned() else {
        return AdminResponse::Error {
            message: format!("no approval with handle '{}'", handle),
        };
    };
    let next = match registry.prepare_denial(handle, now, reason.to_string()) {
        Ok(next) => next,
        Err(error) => {
            return AdminResponse::Error {
                message: error.to_string(),
            }
        }
    };
    if let Some(store) = &server.state.session_store {
        if let Err(error) = store
            .compare_and_swap_approval(expected, next.clone())
            .await
        {
            drop(registry);
            reconcile_approval_from_store(server, handle).await;
            return AdminResponse::Error {
                message: format!("failed to persist held denial: {error}"),
            };
        }
    }
    registry.install_persisted(next.clone(), true);
    drop(registry);
    let session_fingerprint = next.snapshot.session_fingerprint.clone();
    server.emit_audit_ungated(
        AuditEvent::new(AuditKind::DeniedHold)
            .handle(handle)
            .caller(caller)
            .session_fingerprint(session_fingerprint.as_deref().unwrap_or("none")),
    );
    server.emit_event(NotifyEvent {
        event: "decision_made",
        at_unix: now,
        handle: Some(handle.to_string()),
        session_fingerprint,
        requester_principal: next.snapshot.principal.as_ref().map(ToString::to_string),
        reason: Some(reason.to_string()),
        status: Some("denied".to_string()),
        behavior: None,
    });
    AdminResponse::GateAction {
        message: reason.to_string(),
        exit_code: None,
        stdout: None,
        stderr: None,
    }
}

fn approval_wait_outcome(approval: &Approval) -> Option<&'static str> {
    if approval_is_armed(approval) {
        return Some("armed");
    }
    match approval.status {
        ApprovalStatus::Approved => Some("approved"),
        ApprovalStatus::Denied => Some("denied"),
        ApprovalStatus::Expired => Some("expired"),
        ApprovalStatus::ExecFailed => Some("exec_failed"),
        ApprovalStatus::Pending | ApprovalStatus::Approving => None,
    }
}

async fn observe_approval_with_lease(
    server: &ServerContext,
    handle: &str,
    notify: std::sync::Arc<tokio::sync::Notify>,
    timeout_secs: u64,
) -> Result<(ApprovalSummary, String), String> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        let notified = notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let current = server.state.approvals.read().await.get(handle).cloned();
        let Some(current) = current else {
            return Err(approval_not_found_message(handle));
        };
        if let Some(outcome) = approval_wait_outcome(&current) {
            return Ok((ApprovalSummary::from_row(&current), outcome.to_string()));
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Ok((ApprovalSummary::from_row(&current), "timed_out".to_string()));
        }
        tokio::select! {
            _ = &mut notified => {}
            _ = tokio::time::sleep(remaining) => {}
        }
    }
}

/// Transport-facing admin entry point. Side-effecting approval waits are
/// registered before mutation and return an owned response plus the lease that
/// the response writer must hold through framing and flush.
pub(super) async fn handle_admin_request_owned(
    server: &ServerContext,
    caller: &CallerIdentity,
    request: AdminRequest,
) -> OwnedAdminResponse {
    if let AdminRequest::ApprovalWait {
        handle,
        timeout_secs,
    } = request
    {
        if !(1..=APPROVAL_WAIT_MAX_SECS).contains(&timeout_secs) {
            return OwnedAdminResponse {
                response: AdminResponse::Error {
                    message: "approval wait timeout must be between 1 and 3600 seconds".to_string(),
                },
                waiter_lease: None,
            };
        }
        if let Err(scope_message) = approval_scope_check(server, caller, &handle).await {
            let response =
                if let Some(message) = grant_request_wait_refusal(server, caller, &handle).await {
                    AdminResponse::Error { message }
                } else {
                    AdminResponse::Error {
                        message: scope_message,
                    }
                };
            return OwnedAdminResponse {
                response,
                waiter_lease: None,
            };
        }
        let Some((notify, lease)) = server
            .state
            .approvals
            .write()
            .await
            .register_waiter(&handle)
        else {
            return OwnedAdminResponse {
                response: approval_not_found(&handle),
                waiter_lease: None,
            };
        };
        return match observe_approval_with_lease(server, &handle, notify, timeout_secs).await {
            Ok((item, _outcome)) => OwnedAdminResponse {
                response: AdminResponse::ApprovalWait {
                    wait: AccessWaitResult {
                        item,
                        outcome: _outcome,
                    },
                },
                waiter_lease: Some(lease),
            },
            Err(message) => OwnedAdminResponse {
                response: AdminResponse::Error { message },
                waiter_lease: Some(lease),
            },
        };
    }

    let AdminRequest::AccessApprove {
        handles,
        uses,
        wait_secs: Some(timeout_secs),
    } = request
    else {
        return OwnedAdminResponse {
            // The dispatcher contains every administrative response shape.
            // Keep its large async state machine off connection-task stacks.
            response: Box::pin(dispatch_admin_request(server, caller, request)).await,
            waiter_lease: None,
        };
    };

    if !(1..=APPROVAL_WAIT_MAX_SECS).contains(&timeout_secs) {
        return OwnedAdminResponse {
            response: AdminResponse::Error {
                message: "approval wait timeout must be between 1 and 3600 seconds".to_string(),
            },
            waiter_lease: None,
        };
    }
    if handles.len() != 1 {
        return OwnedAdminResponse {
            response: AdminResponse::Error {
                message: "approval wait accepts exactly one request reference".to_string(),
            },
            waiter_lease: None,
        };
    }
    let handle = handles.into_iter().next().expect("checked one handle");

    if let Err(scope_message) = approval_scope_check(server, caller, &handle).await {
        let response =
            if let Some(message) = grant_request_wait_refusal(server, caller, &handle).await {
                AdminResponse::Error { message }
            } else {
                AdminResponse::Error {
                    message: scope_message,
                }
            };
        return OwnedAdminResponse {
            response,
            waiter_lease: None,
        };
    }

    let Some((notify, lease)) = server
        .state
        .approvals
        .write()
        .await
        .register_waiter(&handle)
    else {
        return OwnedAdminResponse {
            response: AdminResponse::Error {
                message: "unknown access request".to_string(),
            },
            waiter_lease: None,
        };
    };

    let decision = Box::pin(dispatch_admin_request(
        server,
        caller,
        AdminRequest::AccessApprove {
            handles: vec![handle.clone()],
            uses,
            wait_secs: None,
        },
    ))
    .await;
    let AdminResponse::AccessDecisions { items, .. } = &decision else {
        return OwnedAdminResponse {
            response: decision,
            waiter_lease: Some(lease),
        };
    };
    let observed = observe_approval_with_lease(server, &handle, notify, timeout_secs).await;
    match observed {
        Ok((item, outcome)) => OwnedAdminResponse {
            response: AdminResponse::AccessDecisions {
                items: items.clone(),
                wait: Some(AccessWaitResult { item, outcome }),
            },
            waiter_lease: Some(lease),
        },
        Err(message) => OwnedAdminResponse {
            response: AdminResponse::Error { message },
            waiter_lease: Some(lease),
        },
    }
}

/// Test-only adapter for legacy direct handler tests. It serializes while the
/// waiter lease is alive, then explicitly consumes the lease before returning
/// the owned response value to the test.
#[cfg(test)]
pub(super) async fn handle_admin_request_for_test(
    server: &ServerContext,
    caller: &CallerIdentity,
    request: AdminRequest,
) -> AdminResponse {
    let OwnedAdminResponse {
        response,
        waiter_lease,
    } = handle_admin_request_owned(server, caller, request).await;
    serde_json::to_vec(&response).expect("admin response must serialize");
    drop(waiter_lease);
    response
}
