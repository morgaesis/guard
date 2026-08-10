use crate::grant_profile::{EvaluationMode, GrantRequestStatus, SavedGrantCatalog};
use crate::server::admin::{
    handle_admin_request_for_test, handle_admin_request_owned, install_approved_access_verbs,
    prune_grant_requests, validate_durable_access_provenance, MAX_GRANT_REQUESTS,
};
use crate::server::execute::{
    admit_access_use, evaluation_cache_scope, execute_command, session_source_from_eval,
};
use crate::server::gate_runtime::SessionAuthoritySnapshot;
use crate::server::learning::{
    allow_session_auto_amend_candidate, amend_session_exact_rule, deny_session_auto_amend_candidate,
};
use crate::server::transport::{claim_session_maintenance, session_maintenance_once};
use crate::server::wire::ExecOutcome;
use crate::server::wire::{AdminRequest, AdminResponse, CallerIdentity, ExecuteRequest};
use crate::session::{
    session_reference, AccessUseGrant, IssuedGrantScope, SessionAmendment, SessionDecisionSource,
    SessionExactRule, SessionExecStatus, SessionGrant, SessionInteraction,
};
use crate::session_store::SessionStore;
use guard::evaluate::{EvalConfig, Evaluator};
use guard::gating::verb::VerbCatalog;
use guard::gating::GateMode;
use guard::principal::PrincipalKey;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::{capture_async, make_test_config, run_verb_synthesis_llm};

fn granted_session(allow: Vec<String>, allow_exact: Vec<SessionExactRule>) -> SessionGrant {
    SessionGrant {
        allow,
        deny: Vec::new(),
        allow_exact,
        deny_exact: Vec::new(),
        activated_verbs: Vec::new(),
        override_markers: Vec::new(),
        scope: Default::default(),
        expires_at: None,
        prompt_append: None,
        generated_notes: Vec::new(),
        static_only: true,
        auto_amend: false,
        granted_at: 0,
        owner: crate::session::SessionOwner::Principal(guard::principal::PrincipalKey::from_uid(
            1000,
        )),
    }
}

fn granted_session_owned(
    owner_uid: u32,
    allow: Vec<String>,
    allow_exact: Vec<SessionExactRule>,
) -> SessionGrant {
    let mut grant = granted_session(allow, allow_exact);
    grant.owner = crate::session::SessionOwner::Principal(PrincipalKey::from_uid(owner_uid));
    grant
}

#[tokio::test]
async fn synthesized_verbs_default_to_session_scope() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(run_verb_synthesis_llm(listener));

    let (mut cfg, _) = make_test_config();
    cfg.state.evaluator = Arc::new(
        Evaluator::new(
            EvalConfig::default()
                .llm_api_key("test-key".to_string())
                .llm_api_url(url)
                .llm_retries(0),
        )
        .unwrap(),
    );
    cfg.config.daemon_principal = PrincipalKey::from_uid(cfg.config.daemon_uid);
    let daemon = CallerIdentity::UnixAdmin {
        uid: cfg.config.daemon_uid,
    };

    let response = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::VerbCreate {
            prose: "Inspect compiler version.".to_string(),
            binary_hint: Some("rustc".to_string()),
            preview: true,
            gate_feedback: Vec::new(),
        },
    )
    .await;
    let AdminResponse::VerbCreated { verb, .. } = response else {
        panic!("expected synthesized verb, got {response:?}");
    };
    assert!(
        !verb.baseline,
        "prose synthesis must not create daemon-wide authority"
    );
}

#[tokio::test]
async fn approved_synthesized_access_executes_deterministically_without_catalog_file() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(run_verb_synthesis_llm(listener));

    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.config.gate = GateMode::Consequence;
    cfg.state.evaluator = Arc::new(
        Evaluator::new(
            EvalConfig::default()
                .llm_api_key("test-key".to_string())
                .llm_api_url(url)
                .llm_retries(0),
        )
        .unwrap(),
    );
    let initial_catalog_version = cfg.state.verbs.read().await.version();
    let worker = CallerIdentity::Unix { uid: 1001 };
    let daemon = CallerIdentity::UnixAdmin { uid: 777 };
    let AdminResponse::AccessItem { item } = handle_admin_request_for_test(
        &cfg,
        &worker,
        AdminRequest::AccessRequest {
            intent: "Inspect compiler version with a synthesized diagnostic".to_string(),
        },
    )
    .await
    else {
        panic!("expected synthesized access request")
    };
    assert_eq!(
        cfg.state.verbs.read().await.version(),
        initial_catalog_version
    );
    assert!(
        cfg.state.grant_requests.read().await[&item.reference]
            .proposed_verbs
            .len()
            == 1
    );

    let grant_reference = item.reference.clone();
    let grant_target = item.target.clone();
    let refused = handle_admin_request_owned(
        &cfg,
        &daemon,
        AdminRequest::AccessApprove {
            handles: vec![grant_reference.clone()],
            uses: Some(1),
            wait_secs: Some(30),
        },
    )
    .await;
    assert!(matches!(
        refused.response,
        AdminResponse::Error { ref message }
            if message == &crate::server::grant_class_wait_refusal(
                &grant_reference,
                &grant_target
            )
    ));
    assert!(refused.waiter_lease.is_none());
    assert_eq!(
        cfg.state.grant_requests.read().await[&grant_reference].status,
        GrantRequestStatus::Pending
    );

    let AdminResponse::AccessDecisions { items, .. } = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::AccessApprove {
            handles: vec![item.reference],
            uses: Some(1),
            wait_secs: None,
        },
    )
    .await
    else {
        panic!("expected synthesized approval")
    };
    assert!(items[0].success, "approval failed: {:?}", items[0]);
    let generated = cfg
        .state
        .verbs
        .read()
        .await
        .list()
        .into_iter()
        .find(|verb| verb.name.starts_with("access-generated-"))
        .expect("approved generated coverage is installed");
    assert!(generated.trusted);
    assert!(!generated.baseline);
    let access_token = cfg
        .state
        .sessions
        .read()
        .await
        .access_token_for_principal(&PrincipalKey::from_uid(1001))
        .expect("approval creates a principal-bound access session");
    assert!(
        cfg.state
            .sessions
            .read()
            .await
            .verb_scope_for(&access_token)
            .expect("access session remains live")
            .0
            .contains(&generated.name),
        "approved generated coverage must be active in the access session"
    );
    assert_eq!(
        cfg.state
            .verbs
            .read()
            .await
            .match_command_all("rustc", &["--version".to_string()])
            .len(),
        1,
        "approved generated coverage must match its synthesized command"
    );

    let mut request =
        request_with_session("rustc", vec!["--version".to_string()], "unused".to_string());
    request.session_token = None;
    let first = execute_command(request.clone(), &cfg, &worker)
        .await
        .into_response();
    assert!(first.allowed, "first approved execution denied: {first:?}");
    assert_eq!(
        cfg.state
            .sessions
            .read()
            .await
            .aggregate_access_uses(&access_token),
        Some(Some(0)),
        "the once approval must be consumed at the first admission: {first:?}"
    );
    let denied = execute_command(request, &cfg, &worker)
        .await
        .into_response();
    assert!(!denied.allowed);
    assert!(denied.reason.contains("use limit is exhausted"));
    assert!(denied.handle.is_some());
}

fn synthesis_arguments_with_description(description: &str) -> serde_json::Value {
    serde_json::json!({
        "name": "check-compiler",
        "description": description,
        "binary": "rustc",
        "args": ["--version"],
        "params": {},
        "consequence": "reversible",
        "trusted": false,
        "evidence": "The exact compiler version command is read only."
    })
}

fn described_compiler_check_arguments(_request: &str) -> serde_json::Value {
    synthesis_arguments_with_description(
        "Runs rustc --version, which prints the installed compiler version and writes nothing.",
    )
}

fn undescribed_compiler_check_arguments(_request: &str) -> serde_json::Value {
    synthesis_arguments_with_description("")
}

async fn synthesized_access_capability_description(
    respond: fn(&str) -> serde_json::Value,
) -> (String, crate::server::wire::AccessItem) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(super::run_verb_synthesis_llm_with(listener, respond));

    let (mut cfg, _) = make_test_config();
    cfg.state.evaluator = Arc::new(
        Evaluator::new(
            EvalConfig::default()
                .llm_api_key("test-key".to_string())
                .llm_api_url(url)
                .llm_retries(0),
        )
        .unwrap(),
    );
    let AdminResponse::AccessItem { item } = handle_admin_request_for_test(
        &cfg,
        &CallerIdentity::Unix { uid: 1001 },
        AdminRequest::AccessRequest {
            intent: "Inspect compiler version with a synthesized diagnostic".to_string(),
        },
    )
    .await
    else {
        panic!("expected a synthesized access request")
    };
    let description = item
        .capabilities
        .first()
        .expect("the request proposes one capability")
        .description
        .clone();
    (description, item)
}

/// The displayed description is derived from the canonical matcher envelope,
/// independent of model-authored proposal prose.
#[tokio::test]
async fn synthesized_access_carries_the_described_grant() {
    let (description, item) =
        synthesized_access_capability_description(described_compiler_check_arguments).await;
    assert_eq!(
        description,
        "Runs rustc with pinned arguments --version and no caller-supplied values."
    );
    assert_ne!(
        Some(description.as_str()),
        item.intent.as_deref(),
        "the grant description must describe the matcher, not restate the intent"
    );
}

/// Model-authored description text does not affect the matcher-derived access
/// description.
#[tokio::test]
async fn undescribed_synthesis_uses_the_matcher_derived_description() {
    let (description, item) =
        synthesized_access_capability_description(undescribed_compiler_check_arguments).await;
    assert_eq!(
        description,
        "Runs rustc with pinned arguments --version and no caller-supplied values."
    );
    assert_eq!(item.use_policy, "unselected");
    assert_eq!(item.default_use_policy.as_deref(), Some("unlimited"));
    assert_eq!(item.default_uses, None);
}

#[tokio::test]
async fn equivalent_synthesized_access_converges_across_principals() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(run_verb_synthesis_llm(listener));

    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.config.gate = GateMode::Consequence;
    cfg.state.evaluator = Arc::new(
        Evaluator::new(
            EvalConfig::default()
                .llm_api_key("test-key".to_string())
                .llm_api_url(url)
                .llm_retries(0),
        )
        .unwrap(),
    );
    let daemon = CallerIdentity::UnixAdmin { uid: 777 };
    let first_principal = CallerIdentity::Unix { uid: 1001 };
    let second_principal = CallerIdentity::Unix { uid: 1002 };

    let AdminResponse::AccessItem { item: first } = handle_admin_request_for_test(
        &cfg,
        &first_principal,
        AdminRequest::AccessRequest {
            intent: "Inspect the first compiler version".to_string(),
        },
    )
    .await
    else {
        panic!("expected first generated request")
    };
    let AdminResponse::AccessItem { item: second } = handle_admin_request_for_test(
        &cfg,
        &second_principal,
        AdminRequest::AccessRequest {
            intent: "Check the compiler version on another independent host".to_string(),
        },
    )
    .await
    else {
        panic!("expected second generated request")
    };
    assert_eq!(first.capabilities.len(), 1);
    assert_eq!(second.capabilities.len(), 1);
    assert_eq!(first.capabilities[0].verb, second.capabilities[0].verb);
    assert_eq!(
        first.capabilities[0].matcher,
        second.capabilities[0].matcher
    );
    assert_eq!(first.capabilities[0].matcher_digest.len(), 64);
    assert_eq!(
        first.capabilities[0].matcher_digest,
        second.capabilities[0].matcher_digest
    );
    assert_eq!(
        cfg.state.grant_requests.read().await[&first.reference].proposed_verbs,
        cfg.state.grant_requests.read().await[&second.reference].proposed_verbs,
        "request-specific prose must not alter canonical generated authority"
    );

    let AdminResponse::AccessDecisions { items, .. } = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::AccessApprove {
            handles: vec![first.reference, second.reference],
            uses: Some(1),
            wait_secs: None,
        },
    )
    .await
    else {
        panic!("expected generated batch approval")
    };
    assert!(
        items.iter().all(|item| item.success),
        "equivalent approvals must converge: {items:?}"
    );
}

#[tokio::test]
async fn pending_reused_generated_access_survives_revoke_and_restart() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(run_verb_synthesis_llm(listener));

    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.config.gate = GateMode::Consequence;
    cfg.state.evaluator = Arc::new(
        Evaluator::new(
            EvalConfig::default()
                .llm_api_key("test-key".to_string())
                .llm_api_url(url)
                .llm_retries(0),
        )
        .unwrap(),
    );
    let temporary = tempfile::tempdir().unwrap();
    let state_db = temporary.path().join("state.db");
    let store = SessionStore::open(state_db.clone(), 3_600).await.unwrap();
    cfg.state.session_store = Some(store.clone());
    let daemon = CallerIdentity::UnixAdmin { uid: 777 };
    let worker = CallerIdentity::Unix { uid: 1001 };

    let AdminResponse::AccessItem { item: initial } = handle_admin_request_for_test(
        &cfg,
        &worker,
        AdminRequest::AccessRequest {
            intent: "Inspect the compiler version before maintenance".to_string(),
        },
    )
    .await
    else {
        panic!("expected initial generated request")
    };
    let generated_name = initial.capabilities[0].verb.clone();
    let AdminResponse::AccessDecisions { items, .. } = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::AccessApprove {
            handles: vec![initial.reference],
            uses: None,
            wait_secs: None,
        },
    )
    .await
    else {
        panic!("expected initial generated approval")
    };
    assert!(items[0].success, "initial approval failed: {items:?}");
    let target = items[0].target.clone().unwrap();
    let AdminResponse::AccessDecisions { items, .. } =
        handle_admin_request_for_test(&cfg, &daemon, AdminRequest::AccessRevoke { target }).await
    else {
        panic!("expected generated access revoke")
    };
    assert!(items[0].success);

    let response = handle_admin_request_for_test(
        &cfg,
        &worker,
        AdminRequest::AccessRequest {
            intent: "Check the maintenance compiler version".to_string(),
        },
    )
    .await;
    let AdminResponse::AccessItem { item: pending } = response else {
        panic!("expected reused generated request, got {response:?}")
    };
    assert_eq!(pending.capabilities[0].verb, generated_name);
    let durable_pending = store
        .load_grant_request(pending.reference.clone())
        .await
        .unwrap()
        .expect("pending generated request is durable");
    assert_eq!(
        durable_pending.status,
        crate::grant_profile::GrantRequestStatus::Pending
    );
    assert_eq!(durable_pending.proposed_verbs.len(), 1);

    let (mut restarted, _) = make_test_config();
    restarted.config.daemon_uid = 777;
    restarted.config.daemon_principal = PrincipalKey::from_uid(777);
    restarted.config.gate = GateMode::Consequence;
    let restarted_store = SessionStore::open(state_db, 3_600).await.unwrap();
    restarted.state.session_store = Some(restarted_store.clone());
    *restarted.state.sessions.write().await = restarted_store.load_registry().await.unwrap();
    *restarted.state.grant_requests.write().await = restarted_store
        .load_grant_requests()
        .await
        .unwrap()
        .into_iter()
        .map(|request| (request.handle.clone(), request))
        .collect();
    assert!(restarted
        .state
        .verbs
        .read()
        .await
        .get(&generated_name)
        .is_none());

    let AdminResponse::AccessDecisions { items, .. } = handle_admin_request_for_test(
        &restarted,
        &daemon,
        AdminRequest::AccessApprove {
            handles: vec![pending.reference],
            uses: Some(1),
            wait_secs: None,
        },
    )
    .await
    else {
        panic!("expected restarted generated approval")
    };
    assert!(items[0].success, "restart approval failed: {items:?}");
    assert!(restarted
        .state
        .verbs
        .read()
        .await
        .get(&generated_name)
        .is_some());
}

#[tokio::test]
async fn full_access_queue_rejects_before_synthesis_or_catalog_change() {
    let (mut cfg, _) = make_test_config();
    cfg.state.evaluator = Arc::new(
        Evaluator::new(
            EvalConfig::default()
                .llm_api_key("test-key".to_string())
                .llm_api_url("http://127.0.0.1:9".to_string())
                .llm_retries(0),
        )
        .unwrap(),
    );
    for index in 0..crate::server::admin::MAX_GRANT_REQUESTS {
        let request = crate::grant_profile::GrantRequest::new(
            format!("fixture-{index}"),
            None,
            crate::grant_profile::GrantRequestDelta {
                prompt_append: Some(format!("fixture-{index}")),
                ..Default::default()
            },
            format!("fixture-{index}"),
        )
        .unwrap();
        cfg.state
            .grant_requests
            .write()
            .await
            .insert(request.handle.clone(), request);
    }
    let before = cfg.state.verbs.read().await.version();
    let response = handle_admin_request_for_test(
        &cfg,
        &CallerIdentity::Unix { uid: 1001 },
        AdminRequest::AccessRequest {
            intent: "Run a novel diagnostic that has no catalog match".to_string(),
        },
    )
    .await;
    assert!(matches!(
        response,
        AdminResponse::Error { message } if message.contains("queue is full")
    ));
    assert_eq!(cfg.state.verbs.read().await.version(), before);
}

#[test]
fn access_request_is_principal_bound_coalesced_batched_and_bounded() {
    std::thread::Builder::new()
        .name("access-request-lifecycle".to_string())
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(access_request_is_principal_bound_coalesced_batched_and_bounded_body());
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn access_request_is_principal_bound_coalesced_batched_and_bounded_body() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.config.gate = GateMode::Consequence;
    cfg.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            "verbs:\n  - name: inspect-fixture\n    description: Inspect fixture\n    binary: rustc\n    args: [--version]\n    baseline: false\n    consequence: reversible\n    trusted: true\n  - name: operate-fixture\n    description: Operate fixture\n    binary: rustc\n    args: [--print, sysroot]\n    baseline: false\n    consequence: reversible\n    trusted: true\n  - name: baseline-fixture\n    description: Run baseline fixture\n    binary: rustc\n    args: [--print, target-libdir]\n    baseline: true\n    consequence: reversible\n    trusted: true\n  - name: missing-fixture\n    description: Run missing fixture binary\n    binary: guard-missing-fixture-binary\n    args: []\n    baseline: false\n    consequence: reversible\n    trusted: true\n",
        )
        .unwrap(),
    ));
    let tmp = tempfile::tempdir().unwrap();
    cfg.state.session_store = Some(
        SessionStore::open(tmp.path().join("state.db"), 3600)
            .await
            .unwrap(),
    );
    let daemon = CallerIdentity::UnixAdmin { uid: 777 };
    let worker = CallerIdentity::Unix { uid: 1001 };
    let other = CallerIdentity::Unix { uid: 1002 };

    let request = || AdminRequest::AccessRequest {
        intent: "Inspect fixture".to_string(),
    };
    let AdminResponse::AccessItem { item: first } =
        handle_admin_request_for_test(&cfg, &worker, request()).await
    else {
        panic!("expected access request")
    };
    let AdminResponse::AccessItem { item: retry } =
        handle_admin_request_for_test(&cfg, &worker, request()).await
    else {
        panic!("expected coalesced access request")
    };
    let AdminResponse::AccessItem { item: isolated } =
        handle_admin_request_for_test(&cfg, &other, request()).await
    else {
        panic!("expected isolated access request")
    };
    assert_eq!(first.reference, retry.reference);
    assert_ne!(first.reference, isolated.reference);
    assert_eq!(first.requester, "1001");
    assert_eq!(
        first.next_action,
        format!("guard access show {}", first.reference)
    );
    assert!(first
        .approval_options
        .contains(&format!("guard access approve {} --once", first.reference)));

    let AdminResponse::AccessDecisions { items, .. } = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::AccessApprove {
            handles: vec![first.reference.clone(), "missing-request".to_string()],
            uses: Some(1),
            wait_secs: None,
        },
    )
    .await
    else {
        panic!("expected per-item access decisions")
    };
    assert!(items[0].success);
    assert!(!items[1].success);
    assert_eq!(items[0].remaining_uses, Some(1));
    let AdminResponse::AccessItem {
        item: approved_retry,
    } = handle_admin_request_for_test(&cfg, &worker, request()).await
    else {
        panic!("expected approved request retry")
    };
    assert_eq!(approved_retry.reference, first.reference);
    assert_eq!(approved_retry.state, "approved");

    let worker_items = handle_admin_request_for_test(&cfg, &worker, AdminRequest::AccessList).await;
    let AdminResponse::AccessItems {
        items: worker_items,
    } = worker_items
    else {
        panic!("expected access list")
    };
    assert!(worker_items.iter().all(|item| item.requester == "1001"));
    assert!(!worker_items
        .iter()
        .any(|item| item.reference == isolated.reference));

    let mut baseline = request_with_session(
        "rustc",
        vec!["--print".to_string(), "target-libdir".to_string()],
        "unused".to_string(),
    );
    baseline.session_token = None;
    assert!(execute_command(baseline, &cfg, &worker)
        .await
        .policy_allowed());
    let remaining_before_access = {
        let sessions = cfg.state.sessions.read().await;
        let token = sessions
            .access_token_for_principal(&PrincipalKey::from_uid(1001))
            .unwrap();
        sessions.aggregate_access_uses(&token).flatten()
    };
    assert_eq!(remaining_before_access, Some(1));

    let mut reevaluate_escape = request_with_session(
        "rustc",
        vec!["--print".to_string(), "cfg".to_string()],
        "unused".to_string(),
    );
    reevaluate_escape.session_token = None;
    reevaluate_escape.reevaluate = true;
    let reevaluate_denied = execute_command(reevaluate_escape, &cfg, &worker).await;
    assert!(!reevaluate_denied.policy_allowed());
    assert!(
        reevaluate_denied
            .policy_reason()
            .contains("session policy-only mode"),
        "unexpected denial: {}",
        reevaluate_denied.policy_reason()
    );

    let mut execution =
        request_with_session("rustc", vec!["--version".to_string()], "unused".to_string());
    execution.session_token = None;
    // Keep the two large execute futures off the test thread's bounded stack.
    // Their simultaneous admission is the behavior under test, not their
    // placement in the generated test future.
    let first_execution = Box::pin(execute_command(execution.clone(), &cfg, &worker));
    let second_execution = Box::pin(execute_command(execution, &cfg, &worker));
    let (first_run, second_run) = tokio::join!(first_execution, second_execution);
    let admitted = [&first_run, &second_run]
        .into_iter()
        .filter(|result| result.policy_allowed())
        .count();
    assert_eq!(admitted, 1);
    let denied = [&first_run, &second_run]
        .into_iter()
        .find(|result| !result.policy_allowed())
        .unwrap();
    assert!(denied.policy_reason().contains("use limit is exhausted"));

    let AdminResponse::AccessItem {
        item: ordinary_request,
    } = handle_admin_request_for_test(
        &cfg,
        &worker,
        AdminRequest::AccessRequest {
            intent: "Operate fixture".to_string(),
        },
    )
    .await
    else {
        panic!("expected independent ordinary access request")
    };
    let AdminResponse::AccessDecisions { items, .. } = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::AccessApprove {
            handles: vec![ordinary_request.reference],
            uses: None,
            wait_secs: None,
        },
    )
    .await
    else {
        panic!("expected ordinary access approval")
    };
    assert!(items[0].success);
    for _ in 0..2 {
        let mut operate = request_with_session(
            "rustc",
            vec!["--print".to_string(), "sysroot".to_string()],
            "unused".to_string(),
        );
        operate.session_token = None;
        assert!(execute_command(operate, &cfg, &worker)
            .await
            .policy_allowed());
    }
    let mut exhausted_inspect =
        request_with_session("rustc", vec!["--version".to_string()], "unused".to_string());
    exhausted_inspect.session_token = None;
    let denied = execute_command(exhausted_inspect.clone(), &cfg, &worker)
        .await
        .into_response();
    assert!(!denied.allowed);
    assert!(denied.reason.contains("use limit is exhausted"));
    let followup = denied
        .handle
        .expect("an exhausted access session receives a new durable request");
    let pending_revision = cfg.state.grant_requests.read().await[&followup]
        .issued_session_revision
        .clone();
    let live_token = cfg
        .state
        .sessions
        .read()
        .await
        .access_token_for_principal(&PrincipalKey::from_uid(1001))
        .unwrap();
    assert_eq!(
        pending_revision,
        cfg.state
            .sessions
            .read()
            .await
            .effective_revision_key(&live_token),
        "the denial request must bind the post-admission authority revision"
    );
    let AdminResponse::AccessDecisions { items, .. } = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::AccessApprove {
            handles: vec![followup],
            uses: Some(1),
            wait_secs: None,
        },
    )
    .await
    else {
        panic!("expected follow-up access decision")
    };
    assert!(
        items[0].success,
        "follow-up approval failed: {:?}",
        items[0]
    );
    assert!(execute_command(exhausted_inspect, &cfg, &worker)
        .await
        .policy_allowed());

    let restored = cfg
        .state
        .session_store
        .as_ref()
        .unwrap()
        .load_registry()
        .await
        .unwrap();
    let restored_access = restored
        .list()
        .into_iter()
        .find(|summary| summary.owner.label() == "1001")
        .unwrap();
    assert!(restored.static_only_for(&restored_access.token));
    assert_eq!(
        restored
            .access_grant_uses(&restored_access.token, &first.reference)
            .and_then(|(_, remaining)| remaining),
        Some(0)
    );

    let AdminResponse::AccessItem {
        item: spawn_request,
    } = handle_admin_request_for_test(
        &cfg,
        &other,
        AdminRequest::AccessRequest {
            intent: "Run missing fixture binary".to_string(),
        },
    )
    .await
    else {
        panic!("expected spawn-failure access request")
    };
    let AdminResponse::AccessDecisions { items, .. } = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::AccessApprove {
            handles: vec![spawn_request.reference.clone()],
            uses: Some(1),
            wait_secs: None,
        },
    )
    .await
    else {
        panic!("expected spawn-failure approval")
    };
    assert!(items[0].success);
    let mut missing = request_with_session(
        "guard-missing-fixture-binary",
        Vec::new(),
        "unused".to_string(),
    );
    missing.session_token = None;
    let failed_spawn = execute_command(missing, &cfg, &other).await;
    assert!(failed_spawn.policy_allowed());
    assert!(matches!(
        failed_spawn.exec,
        ExecOutcome::Failed { started: false, .. }
    ));
    let restored = cfg
        .state
        .session_store
        .as_ref()
        .unwrap()
        .load_registry()
        .await
        .unwrap();
    let other_access = restored
        .list()
        .into_iter()
        .find(|summary| summary.owner.label() == "1002")
        .unwrap();
    assert_eq!(
        restored
            .access_grant_uses(&other_access.token, &spawn_request.reference)
            .and_then(|(_, remaining)| remaining),
        Some(0)
    );

    let target = "agent:1001".to_string();
    let extension = AdminRequest::AccessExtend {
        target: target.clone(),
        intent: "Inspect fixture".to_string(),
        uses: Some(2),
    };
    let AdminResponse::AccessDecisions {
        items: extended, ..
    } = handle_admin_request_for_test(&cfg, &daemon, extension.clone()).await
    else {
        panic!("expected access extension")
    };
    assert!(extended[0].success);
    assert_eq!(extended[0].remaining_uses, Some(2));
    let AdminResponse::AccessDecisions { items: retried, .. } =
        handle_admin_request_for_test(&cfg, &daemon, extension.clone()).await
    else {
        panic!("expected idempotent access extension")
    };
    assert_eq!(retried[0].request, extended[0].request);
    assert_eq!(retried[0].remaining_uses, Some(2));

    let mut one_use =
        request_with_session("rustc", vec!["--version".to_string()], "unused".to_string());
    one_use.session_token = None;
    assert!(execute_command(one_use, &cfg, &worker)
        .await
        .policy_allowed());
    let AdminResponse::AccessDecisions {
        items: retry_after_use,
        ..
    } = handle_admin_request_for_test(&cfg, &daemon, extension).await
    else {
        panic!("expected converged access extension")
    };
    assert_eq!(retry_after_use[0].remaining_uses, Some(1));

    assert!(matches!(
        handle_admin_request_for_test(
            &cfg,
            &worker,
            AdminRequest::AccessRevoke {
                target: target.clone()
            }
        )
        .await,
        AdminResponse::Error { .. }
    ));
    let AdminResponse::AccessDecisions { items, .. } =
        handle_admin_request_for_test(&cfg, &daemon, AdminRequest::AccessRevoke { target }).await
    else {
        panic!("expected access revoke result")
    };
    assert!(items[0].success);
    assert_eq!(items[0].state, "revoked");
    let restored = cfg
        .state
        .session_store
        .as_ref()
        .unwrap()
        .load_registry()
        .await
        .unwrap();
    assert!(restored
        .access_token_for_principal(&PrincipalKey::from_uid(1001))
        .is_none());
}

#[tokio::test]
async fn access_request_can_name_multiple_catalog_verbs() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.config.gate = GateMode::Consequence;
    cfg.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            "verbs:\n  - name: inspect-a\n    description: Inspect system A\n    binary: true\n    args: []\n    baseline: false\n    consequence: reversible\n    trusted: false\n  - name: inspect-b\n    description: Inspect system B\n    binary: printf\n    args: [b]\n    baseline: false\n    consequence: reversible\n    trusted: false\n  - name: run\n    description: Run a different operation\n    binary: printf\n    args: [run]\n    baseline: false\n    consequence: reversible\n    trusted: false\n  - name: stop\n    description: Stop a different operation\n    binary: printf\n    args: [stop]\n    baseline: false\n    consequence: reversible\n    trusted: false\n",
        )
        .unwrap(),
    ));
    let worker = CallerIdentity::Unix { uid: 1001 };
    let daemon = CallerIdentity::UnixAdmin { uid: 777 };

    let AdminResponse::AccessItem { item } = handle_admin_request_for_test(
        &cfg,
        &worker,
        AdminRequest::AccessRequest {
            intent: "Use inspect-a and `inspect-b` for this task".to_string(),
        },
    )
    .await
    else {
        panic!("expected multi-verb access request")
    };
    assert_eq!(item.effective_scope, vec!["inspect-a", "inspect-b"]);
    let mixed_worker = CallerIdentity::Unix { uid: 1002 };
    let AdminResponse::AccessItem { item: mixed } = handle_admin_request_for_test(
        &cfg,
        &mixed_worker,
        AdminRequest::AccessRequest {
            intent: "Use inspect-a and inspect system B".to_string(),
        },
    )
    .await
    else {
        panic!("expected mixed explicit and semantic access request")
    };
    assert_eq!(mixed.effective_scope, vec!["inspect-a", "inspect-b"]);
    let AdminResponse::AccessItem { item: semantic } = handle_admin_request_for_test(
        &cfg,
        &CallerIdentity::Unix { uid: 1003 },
        AdminRequest::AccessRequest {
            intent: "Use inspect-a and run a different operation".to_string(),
        },
    )
    .await
    else {
        panic!("expected ordinary one-word verb to resolve from its full description")
    };
    assert_eq!(semantic.effective_scope, vec!["inspect-a", "run"]);
    let AdminResponse::AccessItem { item: exact_clause } = handle_admin_request_for_test(
        &cfg,
        &CallerIdentity::Unix { uid: 1004 },
        AdminRequest::AccessRequest {
            intent: "Use inspect-a and run".to_string(),
        },
    )
    .await
    else {
        panic!("expected an exact one-word verb clause to be selected")
    };
    assert_eq!(exact_clause.effective_scope, vec!["inspect-a", "run"]);
    let AdminResponse::AccessItem {
        item: ordinary_names,
    } = handle_admin_request_for_test(
        &cfg,
        &CallerIdentity::Unix { uid: 1006 },
        AdminRequest::AccessRequest {
            intent: "Use run and stop".to_string(),
        },
    )
    .await
    else {
        panic!("expected two ordinary one-word verb clauses to be selected")
    };
    assert_eq!(ordinary_names.effective_scope, vec!["run", "stop"]);
    let AdminResponse::AccessItem { item: sequenced } = handle_admin_request_for_test(
        &cfg,
        &CallerIdentity::Unix { uid: 1007 },
        AdminRequest::AccessRequest {
            intent: "Use inspect-a then inspect-b".to_string(),
        },
    )
    .await
    else {
        panic!("expected sequencing prose between explicit verb names")
    };
    assert_eq!(sequenced.effective_scope, vec!["inspect-a", "inspect-b"]);
    let AdminResponse::AccessItem { item: combined } = handle_admin_request_for_test(
        &cfg,
        &CallerIdentity::Unix { uid: 1008 },
        AdminRequest::AccessRequest {
            intent: "Use inspect-a with run".to_string(),
        },
    )
    .await
    else {
        panic!("expected an ordinary verb joined to a distinctive verb with prose")
    };
    assert_eq!(combined.effective_scope, vec!["inspect-a", "run"]);
    let AdminResponse::AccessItem { item: suffixed } = handle_admin_request_for_test(
        &cfg,
        &CallerIdentity::Unix { uid: 1009 },
        AdminRequest::AccessRequest {
            intent: "Use inspect-a and run for this task".to_string(),
        },
    )
    .await
    else {
        panic!("expected request prose after an ordinary verb name")
    };
    assert_eq!(suffixed.effective_scope, vec!["inspect-a", "run"]);
    let AdminResponse::AccessItem { item: collision } = handle_admin_request_for_test(
        &cfg,
        &CallerIdentity::Unix { uid: 1005 },
        AdminRequest::AccessRequest {
            intent: "Run inspect-a".to_string(),
        },
    )
    .await
    else {
        panic!("expected the distinctive verb name without the ordinary-word collision")
    };
    assert_eq!(collision.effective_scope, vec!["inspect-a"]);
    let request_reference = mixed.reference.clone();
    let AdminResponse::AccessDecisions { items, .. } = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::AccessApprove {
            handles: vec![mixed.reference],
            uses: Some(2),
            wait_secs: None,
        },
    )
    .await
    else {
        panic!("expected multi-verb access approval")
    };
    assert!(items[0].success);

    let mut inspect_a = request_with_session("true", Vec::new(), "unused".to_string());
    inspect_a.session_token = None;
    let inspect_a = execute_command(inspect_a, &cfg, &mixed_worker).await;
    assert!(
        inspect_a.policy_allowed(),
        "first named verb denied: {}",
        inspect_a.policy_reason()
    );
    assert!(matches!(
        inspect_a.exec,
        ExecOutcome::Completed {
            exit_code: Some(0),
            ..
        }
    ));
    let mut inspect_b = request_with_session("printf", vec!["b".to_string()], "unused".to_string());
    inspect_b.session_token = None;
    let inspect_b = execute_command(inspect_b, &cfg, &mixed_worker).await;
    assert!(
        inspect_b.policy_allowed(),
        "second named verb denied: {}",
        inspect_b.policy_reason()
    );
    assert!(matches!(
        inspect_b.exec,
        ExecOutcome::Completed {
            exit_code: Some(0),
            ..
        }
    ));
    let sessions = cfg.state.sessions.read().await;
    let token = sessions
        .access_token_for_principal(&PrincipalKey::from_uid(1002))
        .unwrap();
    assert_eq!(
        sessions.access_grant_uses(&token, &request_reference),
        Some((Some(2), Some(0)))
    );
}

#[tokio::test]
async fn access_flow_converges_executes_extends_restarts_and_reports_truthfully() {
    let (mut cfg, _) = make_test_config();
    let state = tempfile::tempdir().unwrap();
    let state_db = state.path().join("state.db");
    cfg.state.session_store = Some(SessionStore::open(state_db.clone(), 3600).await.unwrap());
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.config.gate = GateMode::Consequence;
    cfg.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            r#"
verbs:
  - name: inspect-limited
    description: Inspect one bounded target group
    binary: echo
    args: ["--limit", "{limit}"]
    params:
      limit: { pattern: "^(group-a|group-b)$", required: true }
    baseline: false
    consequence: reversible
    trusted: true
  - name: inspect-b
    description: Inspect system B
    binary: echo
    args: [inspect-b]
    baseline: false
    consequence: reversible
    trusted: true
"#,
        )
        .unwrap(),
    ));
    let worker = CallerIdentity::Unix { uid: 1001 };
    let daemon = CallerIdentity::UnixAdmin { uid: 777 };

    let limited_request = |limit: &str| {
        let mut request = request_with_session(
            "echo",
            vec!["--limit".to_string(), limit.to_string()],
            "unused".to_string(),
        );
        request.session_token = None;
        request
    };
    let (first_denial, equivalent_denial) = tokio::join!(
        execute_command(limited_request("group-a"), &cfg, &worker),
        execute_command(limited_request("group-a"), &cfg, &worker),
    );
    let first_denial = first_denial.into_response();
    let equivalent_denial = equivalent_denial.into_response();
    assert!(!first_denial.allowed);
    assert!(!equivalent_denial.allowed);
    assert_eq!(first_denial.access_requests.len(), 1);
    assert_eq!(
        first_denial.access_requests,
        equivalent_denial.access_requests
    );
    let initial_reference = first_denial.access_requests[0].reference.clone();
    let durable_requests = cfg
        .state
        .session_store
        .as_ref()
        .unwrap()
        .load_grant_requests()
        .await
        .unwrap();
    assert_eq!(durable_requests.len(), 1);
    assert_eq!(durable_requests[0].handle, initial_reference);

    let AdminResponse::AccessItem { item: initial } = handle_admin_request_for_test(
        &cfg,
        &worker,
        AdminRequest::AccessShow {
            reference: initial_reference.clone(),
        },
    )
    .await
    else {
        panic!("expected the denied command's access request")
    };
    assert_eq!(initial.state, "pending");
    assert_eq!(initial.effective_scope, vec!["inspect-limited"]);

    let AdminResponse::AccessDecisions { items, .. } = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::AccessApprove {
            handles: vec![initial_reference.clone()],
            uses: Some(4),
            wait_secs: None,
        },
    )
    .await
    else {
        panic!("expected initial approval")
    };
    assert!(items[0].success);
    let original_token = cfg
        .state
        .sessions
        .read()
        .await
        .access_token_for_principal(&PrincipalKey::from_uid(1001))
        .unwrap();

    let mut stale_request = limited_request("group-a");
    stale_request.session_token = Some("retired-legacy-session".to_string());
    let first_execution = execute_command(stale_request, &cfg, &worker)
        .await
        .into_response();
    assert!(
        first_execution.allowed,
        "a stale handle must yield to the caller's principal session: {first_execution:?}"
    );
    assert_eq!(first_execution.exit_code, Some(0));
    assert_eq!(
        cfg.state
            .sessions
            .read()
            .await
            .access_grant_uses(&original_token, &initial_reference),
        Some((Some(4), Some(3)))
    );

    let varied_execution = execute_command(limited_request("group-b"), &cfg, &worker)
        .await
        .into_response();
    assert!(
        varied_execution.allowed,
        "the typed grant must cover another allowed parameter value: {varied_execution:?}"
    );
    assert_eq!(
        cfg.state
            .sessions
            .read()
            .await
            .access_grant_uses(&original_token, &initial_reference),
        Some((Some(4), Some(2)))
    );

    let AdminResponse::AccessDecisions { items, .. } = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::AccessExtend {
            target: "agent:1001".to_string(),
            intent: "Use inspect-b for this task".to_string(),
            uses: Some(2),
        },
    )
    .await
    else {
        panic!("expected access extension")
    };
    assert!(items[0].success);
    let extension_reference = items[0].request.clone();

    let preserved_execution = execute_command(limited_request("group-a"), &cfg, &worker)
        .await
        .into_response();
    assert!(
        preserved_execution.allowed,
        "extension must preserve the prior typed scope: {preserved_execution:?}"
    );
    let mut extension_execution =
        request_with_session("echo", vec!["inspect-b".to_string()], "unused".to_string());
    extension_execution.session_token = None;
    let extension_execution = execute_command(extension_execution, &cfg, &worker)
        .await
        .into_response();
    assert!(
        extension_execution.allowed,
        "extension must activate its added scope: {extension_execution:?}"
    );

    let sessions = cfg.state.sessions.read().await;
    assert_eq!(
        sessions
            .access_token_for_principal(&PrincipalKey::from_uid(1001))
            .as_deref(),
        Some(original_token.as_str())
    );
    assert!(sessions
        .access_grant_uses(&original_token, &initial_reference)
        .is_some());
    assert_eq!(
        sessions.access_grant_uses(&original_token, &initial_reference),
        Some((Some(4), Some(1)))
    );
    assert_eq!(
        sessions.access_grant_uses(&original_token, &extension_reference),
        Some((Some(2), Some(1)))
    );
    drop(sessions);
    let restored = cfg
        .state
        .session_store
        .as_ref()
        .unwrap()
        .load_registry()
        .await
        .unwrap();
    assert_eq!(
        restored
            .access_token_for_principal(&PrincipalKey::from_uid(1001))
            .as_deref(),
        Some(original_token.as_str())
    );
    assert_eq!(
        restored.access_grant_uses(&original_token, &initial_reference),
        Some((Some(4), Some(1)))
    );
    assert_eq!(
        restored.access_grant_uses(&original_token, &extension_reference),
        Some((Some(2), Some(1)))
    );
    assert!(restored
        .verb_scope_for(&original_token)
        .unwrap()
        .0
        .contains(&"inspect-b".to_string()));
    assert!(restored
        .verb_scope_for(&original_token)
        .unwrap()
        .0
        .contains(&"inspect-limited".to_string()));
    let restored_requests = cfg
        .state
        .session_store
        .as_ref()
        .unwrap()
        .load_grant_requests()
        .await
        .unwrap();
    *cfg.state.sessions.write().await = restored;
    *cfg.state.grant_requests.write().await = restored_requests
        .into_iter()
        .map(|request| (request.handle.clone(), request))
        .collect();
    let AdminResponse::AccessItems { items } =
        handle_admin_request_for_test(&cfg, &worker, AdminRequest::AccessList).await
    else {
        panic!("expected access list")
    };
    let session_intent = items
        .iter()
        .find(|item| item.kind == "session")
        .and_then(|item| item.intent.as_deref())
        .expect("the access session projects its approved intents");
    assert!(session_intent.contains("inspect-limited"));
    assert!(session_intent.contains("Use inspect-b for this task"));
    let initial_item = items
        .iter()
        .find(|item| item.reference == initial_reference)
        .expect("the initial approval remains visible");
    assert_eq!(initial_item.state, "approved");
    assert_eq!(initial_item.use_policy, "bounded");
    assert_eq!(initial_item.remaining_uses, Some(1));
    assert_eq!(initial_item.effective_scope, vec!["inspect-limited"]);
    let extension_item = items
        .iter()
        .find(|item| item.reference == extension_reference)
        .expect("the extension approval remains visible");
    assert_eq!(extension_item.state, "approved");
    assert_eq!(extension_item.use_policy, "bounded");
    assert_eq!(extension_item.remaining_uses, Some(1));
    assert_eq!(extension_item.effective_scope, vec!["inspect-b"]);
    let session_item = items
        .iter()
        .find(|item| item.kind == "session")
        .expect("the active session remains visible");
    assert_eq!(session_item.state, "active");
    assert!(session_item
        .effective_scope
        .contains(&"inspect-limited".to_string()));
    assert!(session_item
        .effective_scope
        .contains(&"inspect-b".to_string()));

    cfg.state.sessions.write().await.grant(
        "valid-foreign-session".to_string(),
        granted_session_owned(1002, vec!["echo *".to_string()], Vec::new()),
    );
    let foreign = execute_command(
        request_with_session(
            "echo",
            vec!["--limit".to_string(), "group-a".to_string()],
            "valid-foreign-session".to_string(),
        ),
        &cfg,
        &worker,
    )
    .await
    .into_response();
    assert!(!foreign.allowed);
    assert!(foreign.reason.contains("principal mismatch"));
}

#[tokio::test]
async fn approved_request_without_live_session_projects_as_orphaned() {
    let (mut cfg, _) = make_test_config();
    let state = tempfile::tempdir().unwrap();
    cfg.state.session_store = Some(
        SessionStore::open(state.path().join("state.db"), 3600)
            .await
            .unwrap(),
    );
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            "verbs:\n  - name: inspect-a\n    description: Inspect system A\n    binary: true\n    args: []\n    baseline: false\n    consequence: reversible\n    trusted: true\n",
        )
        .unwrap(),
    ));
    let worker = CallerIdentity::Unix { uid: 1001 };
    let daemon = CallerIdentity::UnixAdmin { uid: 777 };
    let AdminResponse::AccessItem { item: pending } = handle_admin_request_for_test(
        &cfg,
        &worker,
        AdminRequest::AccessRequest {
            intent: "Inspect system A".to_string(),
        },
    )
    .await
    else {
        panic!("expected access request")
    };
    let request_reference = pending.reference.clone();
    let AdminResponse::AccessDecisions { items, .. } = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::AccessApprove {
            handles: vec![pending.reference],
            uses: Some(1),
            wait_secs: None,
        },
    )
    .await
    else {
        panic!("expected access approval")
    };
    let target = items[0].target.clone().unwrap();
    let AdminResponse::AccessDecisions { items, .. } =
        handle_admin_request_for_test(&cfg, &daemon, AdminRequest::AccessRevoke { target }).await
    else {
        panic!("expected access revoke")
    };
    assert!(items[0].success);

    let AdminResponse::AccessItem { item: orphaned } = handle_admin_request_for_test(
        &cfg,
        &worker,
        AdminRequest::AccessShow {
            reference: request_reference,
        },
    )
    .await
    else {
        panic!("expected orphaned request projection")
    };
    assert_eq!(orphaned.state, "orphaned");
    assert_eq!(orphaned.use_policy, "unavailable");
    assert!(orphaned
        .decided_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("no longer attached")));
}

#[tokio::test]
async fn request_pruning_preserves_live_access_provenance() {
    let (mut cfg, _) = make_test_config();
    let state = tempfile::tempdir().unwrap();
    let state_db = state.path().join("state.db");
    cfg.state.session_store = Some(SessionStore::open(state_db.clone(), 3600).await.unwrap());
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            "verbs:\n  - name: inspect-a\n    description: Inspect system A\n    binary: true\n    args: []\n    baseline: false\n    consequence: reversible\n    trusted: true\n",
        )
        .unwrap(),
    ));
    let worker = CallerIdentity::Unix { uid: 1001 };
    let daemon = CallerIdentity::UnixAdmin { uid: 777 };
    let AdminResponse::AccessItem { item } = handle_admin_request_for_test(
        &cfg,
        &worker,
        AdminRequest::AccessRequest {
            intent: "Inspect system A".to_string(),
        },
    )
    .await
    else {
        panic!("expected access request")
    };
    let active_handle = item.reference.clone();
    let AdminResponse::AccessDecisions { items, .. } = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::AccessApprove {
            handles: vec![item.reference],
            uses: Some(1),
            wait_secs: None,
        },
    )
    .await
    else {
        panic!("expected access approval")
    };
    assert!(items[0].success);

    let template = {
        let mut requests = cfg.state.grant_requests.write().await;
        let active = requests.get_mut(&active_handle).unwrap();
        active.created_unix = 0;
        active.clone()
    };
    let mut terminal_requests = Vec::with_capacity(MAX_GRANT_REQUESTS - 1);
    for index in 0..MAX_GRANT_REQUESTS - 1 {
        let mut terminal = template.clone();
        terminal.handle = format!("terminal-{index:04}");
        terminal.status = GrantRequestStatus::Denied;
        terminal.session_token.clear();
        terminal.created_unix = 1;
        terminal_requests.push(terminal);
    }
    let durable_terminal_requests = terminal_requests.clone();
    tokio::task::spawn_blocking(move || {
        let mut connection = rusqlite::Connection::open(state_db).unwrap();
        let transaction = connection.transaction().unwrap();
        {
            let mut statement = transaction
                .prepare(
                    "INSERT OR REPLACE INTO grant_requests (handle, json, status, created_unix) VALUES (?1, ?2, ?3, ?4)",
                )
                .unwrap();
            for request in durable_terminal_requests {
                let handle = request.handle.clone();
                let json = serde_json::to_string(&request).unwrap();
                let status = request.status.as_str().to_string();
                let created_unix = i64::try_from(request.created_unix).unwrap();
                statement
                    .execute(rusqlite::params![
                        handle,
                        json,
                        status,
                        created_unix,
                    ])
                    .unwrap();
            }
        }
        transaction.commit().unwrap();
    })
    .await
    .unwrap();
    {
        let mut requests = cfg.state.grant_requests.write().await;
        for terminal in terminal_requests {
            requests.insert(terminal.handle.clone(), terminal);
        }
    }

    prune_grant_requests(&cfg).await;
    let requests = cfg.state.grant_requests.read().await;
    assert!(requests.contains_key(&active_handle));
    assert!(requests.len() < MAX_GRANT_REQUESTS);
    drop(requests);
    let store = cfg.state.session_store.as_ref().unwrap();
    assert!(store
        .load_grant_request(active_handle)
        .await
        .unwrap()
        .is_some());
    assert!(store
        .load_grant_request("terminal-0000".to_string())
        .await
        .unwrap()
        .is_none());
    let restored_registry = store.load_registry().await.unwrap();
    let restored_requests = store.load_grant_requests().await.unwrap();
    assert_eq!(restored_requests.len(), MAX_GRANT_REQUESTS - 1);
    let restored_session_reference = session_reference(
        &restored_registry
            .access_token_for_principal(&PrincipalKey::from_uid(1001))
            .unwrap(),
    );
    *cfg.state.sessions.write().await = restored_registry;
    *cfg.state.grant_requests.write().await = restored_requests
        .into_iter()
        .map(|request| (request.handle.clone(), request))
        .collect();
    assert!(validate_durable_access_provenance(&cfg).await.is_ok());
    let AdminResponse::AccessItem { item } = handle_admin_request_for_test(
        &cfg,
        &worker,
        AdminRequest::AccessShow {
            reference: restored_session_reference,
        },
    )
    .await
    else {
        panic!("expected restored access session")
    };
    assert!(item
        .intent
        .as_deref()
        .is_some_and(|intent| intent.contains("Inspect system A")));
}

#[tokio::test]
async fn sequential_approval_keeps_fresh_sibling_extensions_valid() {
    let (mut cfg, _) = make_test_config();
    let state = tempfile::tempdir().unwrap();
    cfg.state.session_store = Some(
        SessionStore::open(state.path().join("state.db"), 3600)
            .await
            .unwrap(),
    );
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            "verbs:\n  - name: inspect-a\n    description: Inspect system A\n    binary: true\n    args: []\n    baseline: false\n    consequence: reversible\n    trusted: true\n  - name: inspect-b\n    description: Inspect system B\n    binary: printf\n    args: [b]\n    baseline: false\n    consequence: reversible\n    trusted: true\n  - name: inspect-c\n    description: Inspect system C\n    binary: printf\n    args: [c]\n    baseline: false\n    consequence: reversible\n    trusted: true\n",
        )
        .unwrap(),
    ));
    let worker = CallerIdentity::Unix { uid: 1001 };
    let daemon = CallerIdentity::UnixAdmin { uid: 777 };
    let AdminResponse::AccessItem { item: initial } = handle_admin_request_for_test(
        &cfg,
        &worker,
        AdminRequest::AccessRequest {
            intent: "Inspect system A".to_string(),
        },
    )
    .await
    else {
        panic!("expected initial access request")
    };
    let AdminResponse::AccessDecisions { items, .. } = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::AccessApprove {
            handles: vec![initial.reference],
            uses: None,
            wait_secs: None,
        },
    )
    .await
    else {
        panic!("expected initial approval")
    };
    assert!(items[0].success);

    let mut pending = Vec::new();
    for intent in ["Inspect system B", "Inspect system C"] {
        let AdminResponse::AccessItem { item } = handle_admin_request_for_test(
            &cfg,
            &worker,
            AdminRequest::AccessRequest {
                intent: intent.to_string(),
            },
        )
        .await
        else {
            panic!("expected sibling extension request")
        };
        pending.push(item.reference);
    }
    let issued_revisions = {
        let requests = cfg.state.grant_requests.read().await;
        pending
            .iter()
            .map(|handle| requests[handle].issued_session_revision.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(issued_revisions[0], issued_revisions[1]);

    for handle in pending.clone() {
        let AdminResponse::AccessDecisions { items, .. } = handle_admin_request_for_test(
            &cfg,
            &daemon,
            AdminRequest::AccessApprove {
                handles: vec![handle],
                uses: Some(2),
                wait_secs: None,
            },
        )
        .await
        else {
            panic!("expected sibling decision")
        };
        assert!(
            items[0].success,
            "sequential sibling approval must rebase pending requests: {items:?}"
        );
    }
    let durable = cfg
        .state
        .session_store
        .as_ref()
        .unwrap()
        .load_grant_requests()
        .await
        .unwrap();
    assert!(durable.iter().all(|request| {
        !pending.contains(&request.handle)
            || request.status == crate::grant_profile::GrantRequestStatus::Approved
    }));
}

#[tokio::test]
async fn access_approval_and_revoke_retry_one_registry_generation_conflict() {
    let (mut cfg, _) = make_test_config();
    let state = tempfile::tempdir().unwrap();
    let database = state.path().join("state.db");
    cfg.state.session_store = Some(SessionStore::open(database.clone(), 3600).await.unwrap());
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            "verbs:\n  - name: inspect-a\n    description: Inspect system A\n    binary: true\n    args: []\n    baseline: false\n    consequence: reversible\n    trusted: true\n",
        )
        .unwrap(),
    ));
    let worker = CallerIdentity::Unix { uid: 1001 };
    let daemon = CallerIdentity::UnixAdmin { uid: 777 };
    let AdminResponse::AccessItem { item: pending } = handle_admin_request_for_test(
        &cfg,
        &worker,
        AdminRequest::AccessRequest {
            intent: "Inspect system A".to_string(),
        },
    )
    .await
    else {
        panic!("expected access request")
    };

    let competing = SessionStore::open(database.clone(), 3600).await.unwrap();
    let mut advanced = competing.load_registry().await.unwrap();
    advanced.grant(
        "unrelated-before-approval".to_string(),
        granted_session_owned(2001, Vec::new(), Vec::new()),
    );
    competing.persist_registry(&advanced).await.unwrap();

    let AdminResponse::AccessDecisions { items, .. } = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::AccessApprove {
            handles: vec![pending.reference],
            uses: None,
            wait_secs: None,
        },
    )
    .await
    else {
        panic!("expected access approval")
    };
    assert!(items[0].success, "approval did not retry: {items:?}");
    let target = items[0].target.clone().unwrap();
    assert!(cfg
        .state
        .sessions
        .read()
        .await
        .has("unrelated-before-approval"));

    let competing = SessionStore::open(database, 3600).await.unwrap();
    let mut advanced = competing.load_registry().await.unwrap();
    advanced.grant(
        "unrelated-before-revoke".to_string(),
        granted_session_owned(2002, Vec::new(), Vec::new()),
    );
    competing.persist_registry(&advanced).await.unwrap();

    let AdminResponse::AccessDecisions { items, .. } =
        handle_admin_request_for_test(&cfg, &daemon, AdminRequest::AccessRevoke { target }).await
    else {
        panic!("expected access revoke")
    };
    assert!(items[0].success, "revoke did not retry: {items:?}");
    assert!(cfg
        .state
        .sessions
        .read()
        .await
        .has("unrelated-before-revoke"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn aborted_admin_registry_transitions_finish_live_adoption() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    let state = tempfile::tempdir().unwrap();
    cfg.state.session_store = Some(
        SessionStore::open(state.path().join("state.db"), 3600)
            .await
            .unwrap(),
    );
    let store = cfg.state.session_store.as_ref().unwrap().clone();

    let token = "cancelled-approval".to_string();
    let approval_snapshot = {
        let mut sessions = cfg.state.sessions.write().await;
        assert!(sessions.grant(
            token.clone(),
            granted_session_owned(1001, Vec::new(), Vec::new()),
        ));
        sessions.clone()
    };
    store.persist_registry(&approval_snapshot).await.unwrap();
    let mut pending = crate::grant_profile::GrantRequest::new(
        token.clone(),
        None,
        crate::grant_profile::GrantRequestDelta {
            prompt_append: Some("bounded work".to_string()),
            ..Default::default()
        },
        "bounded work".to_string(),
    )
    .unwrap();
    pending.issued_session_revision = approval_snapshot.effective_revision_key(&token);
    store.save_grant_request(pending.clone()).await.unwrap();
    cfg.state
        .grant_requests
        .write()
        .await
        .insert(pending.handle.clone(), pending.clone());

    let (committed, release) =
        store.pause_registry_commit_for_test("grant request approval transaction");
    let approving = cfg.clone();
    let pending_handle = pending.handle.clone();
    let caller = tokio::spawn(async move {
        handle_admin_request_for_test(
            &approving,
            &CallerIdentity::UnixAdmin { uid: 777 },
            AdminRequest::GrantRequestApprove {
                handle: pending_handle,
            },
        )
        .await
    });
    committed.acquire().await.unwrap().forget();
    caller.abort();
    release.add_permits(1);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if cfg.state.grant_requests.read().await[&pending.handle].status
                == GrantRequestStatus::Approved
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached approval adopts durable session and request state");
    assert_eq!(
        cfg.state
            .sessions
            .read()
            .await
            .effective_revision_key(&token),
        store
            .load_registry()
            .await
            .unwrap()
            .effective_revision_key(&token)
    );

    let access_token = "cancelled-revoke".to_string();
    let revoke_snapshot = {
        let mut sessions = cfg.state.sessions.write().await;
        let mut grant = granted_session_owned(1001, Vec::new(), Vec::new());
        grant.scope = IssuedGrantScope {
            access_managed: true,
            ..IssuedGrantScope::default()
        };
        assert!(sessions.grant(access_token.clone(), grant));
        sessions.clone()
    };
    store.persist_registry(&revoke_snapshot).await.unwrap();
    let target = session_reference(&access_token);
    let (committed, release) = store.pause_registry_commit_for_test("access revoke transaction");
    let revoking = cfg.clone();
    let caller = tokio::spawn(async move {
        handle_admin_request_for_test(
            &revoking,
            &CallerIdentity::UnixAdmin { uid: 777 },
            AdminRequest::AccessRevoke { target },
        )
        .await
    });
    committed.acquire().await.unwrap().forget();
    caller.abort();
    release.add_permits(1);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if !cfg.state.sessions.read().await.has(&access_token) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached revoke adopts durable session state");
    assert!(!store.load_registry().await.unwrap().has(&access_token));
}

#[tokio::test]
async fn multi_request_admission_audits_every_consumed_budget() {
    let (mut cfg, _) = make_test_config();
    let (audit_directory, _audit) = super::attach_test_audit_log(&mut cfg);
    cfg.state.sessions.write().await.grant(
        "multi-budget".to_string(),
        SessionGrant {
            allow: Vec::new(),
            deny: Vec::new(),
            allow_exact: Vec::new(),
            deny_exact: Vec::new(),
            activated_verbs: vec!["verb-a".to_string(), "verb-b".to_string()],
            override_markers: Vec::new(),
            scope: IssuedGrantScope {
                access_managed: true,
                access_grants: vec![
                    AccessUseGrant {
                        request: "gr-budget-a".to_string(),
                        verbs: vec!["verb-a".to_string()],
                        use_limit: Some(1),
                        remaining_uses: Some(1),
                        pending: false,
                    },
                    AccessUseGrant {
                        request: "gr-budget-b".to_string(),
                        verbs: vec!["verb-b".to_string()],
                        use_limit: Some(2),
                        remaining_uses: Some(2),
                        pending: false,
                    },
                ],
                ..IssuedGrantScope::default()
            },
            expires_at: Some(crate::server::gate_runtime::now_unix().saturating_add(60)),
            prompt_append: None,
            generated_notes: Vec::new(),
            static_only: true,
            auto_amend: false,
            granted_at: 0,
            owner: crate::session::SessionOwner::Principal(PrincipalKey::from_uid(1001)),
        },
    );
    let request = request_with_session("true", Vec::new(), "multi-budget".to_string());
    let admission = admit_access_use(
        &cfg,
        &request,
        &["verb-a".to_string(), "verb-b".to_string()],
        None,
    )
    .await
    .expect("admission succeeds")
    .expect("access-managed admission is recorded");
    assert_eq!(admission.consumptions.len(), 2);

    let audit = std::fs::read_to_string(audit_directory.path().join("audit.jsonl")).unwrap();
    for request in ["gr-budget-a", "gr-budget-b"] {
        assert_eq!(
            audit
                .matches(&format!("[\"access_request\",\"{request}\"]"))
                .count(),
            1,
            "each decremented request receives an audit event: {audit}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_bounded_admission_finishes_publication_before_a_successor() {
    let (mut cfg, _) = make_test_config();
    let directory = tempfile::tempdir().unwrap();
    let store = SessionStore::open(directory.path().join("sessions.db"), 3600)
        .await
        .unwrap();
    cfg.state.session_store = Some(store.clone());
    let token = "cancel-safe-budget";
    cfg.state.sessions.write().await.grant(
        token.to_string(),
        SessionGrant {
            allow: Vec::new(),
            deny: Vec::new(),
            allow_exact: Vec::new(),
            deny_exact: Vec::new(),
            activated_verbs: vec!["bounded-verb".to_string()],
            override_markers: Vec::new(),
            scope: IssuedGrantScope {
                access_managed: true,
                access_grants: vec![AccessUseGrant {
                    request: "bounded-request".to_string(),
                    verbs: vec!["bounded-verb".to_string()],
                    use_limit: Some(1),
                    remaining_uses: Some(1),
                    pending: false,
                }],
                ..IssuedGrantScope::default()
            },
            expires_at: Some(crate::server::gate_runtime::now_unix().saturating_add(60)),
            prompt_append: None,
            generated_notes: Vec::new(),
            static_only: true,
            auto_amend: false,
            granted_at: 0,
            owner: crate::session::SessionOwner::Principal(PrincipalKey::from_uid(1001)),
        },
    );
    store
        .persist_registry(&cfg.state.sessions.read().await.clone())
        .await
        .unwrap();
    let request = request_with_session("true", Vec::new(), token.to_string());
    let (committed, release) = store.pause_registry_commit_for_test("session store persist");
    let first_server = cfg.clone();
    let first_request = request.clone();
    let first = tokio::spawn(async move {
        admit_access_use(
            &first_server,
            &first_request,
            &["bounded-verb".to_string()],
            None,
        )
        .await
    });
    committed.acquire().await.unwrap().forget();
    first.abort();

    let second_server = cfg.clone();
    let second = tokio::spawn(async move {
        admit_access_use(
            &second_server,
            &request,
            &["bounded-verb".to_string()],
            None,
        )
        .await
    });
    tokio::task::yield_now().await;
    assert!(
        !second.is_finished(),
        "a successor admission overtook detached durable publication"
    );
    release.add_permits(1);
    assert!(second.await.unwrap().is_err());
    assert_eq!(
        cfg.state
            .sessions
            .read()
            .await
            .access_grant_uses(token, "bounded-request"),
        Some((Some(1), Some(0)))
    );
    assert_eq!(
        store
            .load_registry()
            .await
            .unwrap()
            .access_grant_uses(token, "bounded-request"),
        Some((Some(1), Some(0)))
    );
}

#[tokio::test]
async fn access_list_and_show_project_expiry_without_mutating_durable_requests() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            "verbs:\n  - name: inspect-fixture\n    description: Inspect fixture\n    binary: true\n    args: []\n    baseline: false\n    consequence: reversible\n    trusted: true\n",
        )
        .unwrap(),
    ));
    let tmp = tempfile::tempdir().unwrap();
    cfg.state.session_store = Some(
        SessionStore::open(tmp.path().join("state.db"), 3600)
            .await
            .unwrap(),
    );
    let worker = CallerIdentity::Unix { uid: 1001 };
    let AdminResponse::AccessItem { item } = handle_admin_request_for_test(
        &cfg,
        &worker,
        AdminRequest::AccessRequest {
            intent: "Inspect fixture".to_string(),
        },
    )
    .await
    else {
        panic!("expected access request")
    };
    let mut expired = cfg.state.grant_requests.read().await[&item.reference].clone();
    expired.expires_unix = 1;
    cfg.state
        .grant_requests
        .write()
        .await
        .insert(item.reference.clone(), expired.clone());
    cfg.state
        .session_store
        .as_ref()
        .unwrap()
        .save_grant_request(expired)
        .await
        .unwrap();

    let AdminResponse::AccessItems { items } =
        handle_admin_request_for_test(&cfg, &worker, AdminRequest::AccessList).await
    else {
        panic!("expected access list")
    };
    let listed = items
        .iter()
        .find(|listed| listed.reference == item.reference)
        .expect("expired request remains visible");
    assert_eq!(listed.state, "expired");
    assert!(listed.approval_options.is_empty());

    let AdminResponse::AccessItem { item: shown } = handle_admin_request_for_test(
        &cfg,
        &worker,
        AdminRequest::AccessShow {
            reference: item.reference.clone(),
        },
    )
    .await
    else {
        panic!("expected access show")
    };
    assert_eq!(shown.state, "expired");
    assert!(cfg
        .state
        .grant_requests
        .read()
        .await
        .contains_key(&item.reference));
    assert!(cfg
        .state
        .session_store
        .as_ref()
        .unwrap()
        .load_grant_requests()
        .await
        .unwrap()
        .iter()
        .any(|stored| stored.handle == item.reference));
}

#[tokio::test]
async fn access_extend_rejects_legacy_session_authority() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.state.sessions.write().await.grant(
        "legacy-session".to_string(),
        granted_session_owned(1001, Vec::new(), Vec::new()),
    );
    let response = handle_admin_request_for_test(
        &cfg,
        &CallerIdentity::UnixAdmin { uid: 777 },
        AdminRequest::AccessExtend {
            target: crate::session::session_reference("legacy-session"),
            intent: "Inspect fixture".to_string(),
            uses: Some(1),
        },
    )
    .await;
    assert!(matches!(
        response,
        AdminResponse::Error { message } if message.contains("access-managed targets only")
    ));
}

#[tokio::test]
async fn revoked_access_session_cannot_be_resurrected_by_pending_extension() {
    let (mut cfg, _) = make_test_config();
    let state = tempfile::tempdir().unwrap();
    cfg.state.session_store = Some(
        SessionStore::open(state.path().join("state.db"), 3_600)
            .await
            .unwrap(),
    );
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            "verbs:\n  - name: inspect-fixture\n    description: Inspect fixture\n    binary: true\n    args: []\n    baseline: false\n    consequence: reversible\n    trusted: true\n  - name: operate-fixture\n    description: Operate fixture\n    binary: printf\n    args: [operate]\n    baseline: false\n    consequence: reversible\n    trusted: true\n",
        )
        .unwrap(),
    ));
    let worker = CallerIdentity::Unix { uid: 1001 };
    let daemon = CallerIdentity::UnixAdmin { uid: 777 };
    let AdminResponse::AccessItem { item: initial } = handle_admin_request_for_test(
        &cfg,
        &worker,
        AdminRequest::AccessRequest {
            intent: "Inspect fixture".to_string(),
        },
    )
    .await
    else {
        panic!("expected initial access request")
    };
    let AdminResponse::AccessDecisions { items, .. } = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::AccessApprove {
            handles: vec![initial.reference],
            uses: None,
            wait_secs: None,
        },
    )
    .await
    else {
        panic!("expected initial approval")
    };
    assert!(items[0].success);
    let target = items[0].target.clone().unwrap();

    let AdminResponse::AccessItem { item: extension } = handle_admin_request_for_test(
        &cfg,
        &worker,
        AdminRequest::AccessRequest {
            intent: "Operate fixture".to_string(),
        },
    )
    .await
    else {
        panic!("expected pending extension")
    };
    assert_eq!(extension.state, "pending");
    assert!(matches!(
        handle_admin_request_for_test(&cfg, &daemon, AdminRequest::AccessRevoke { target },).await,
        AdminResponse::AccessDecisions { .. }
    ));
    assert_eq!(
        cfg.state.grant_requests.read().await[&extension.reference].status,
        crate::grant_profile::GrantRequestStatus::Withdrawn
    );
    let durable_extension = cfg
        .state
        .session_store
        .as_ref()
        .unwrap()
        .load_grant_request(extension.reference.clone())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        durable_extension.status,
        crate::grant_profile::GrantRequestStatus::Withdrawn
    );
    let AdminResponse::AccessDecisions { items, .. } = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::AccessApprove {
            handles: vec![extension.reference],
            uses: Some(1),
            wait_secs: None,
        },
    )
    .await
    else {
        panic!("expected extension decision")
    };
    assert!(!items[0].success);
    assert_eq!(items[0].state, "withdrawn");
    assert!(cfg
        .state
        .sessions
        .read()
        .await
        .access_token_for_principal(&PrincipalKey::from_uid(1001))
        .is_none());
}

#[tokio::test]
async fn sessionless_denied_typed_command_returns_access_request_guidance() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.config.gate = GateMode::Consequence;
    cfg.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            "verbs:\n  - name: inspect-fixture\n    description: Inspect fixture\n    binary: fixture-inspect\n    args: [status]\n    baseline: false\n    consequence: reversible\n    trusted: true\n",
        )
        .unwrap(),
    ));
    let tmp = tempfile::tempdir().unwrap();
    cfg.state.session_store = Some(
        SessionStore::open(tmp.path().join("state.db"), 3600)
            .await
            .unwrap(),
    );
    let worker = CallerIdentity::Unix { uid: 1001 };
    let mut request = request_with_session(
        "fixture-inspect",
        vec!["status".to_string()],
        "unused".to_string(),
    );
    request.session_token = None;

    let response = execute_command(request.clone(), &cfg, &worker)
        .await
        .into_response();
    assert!(!response.allowed);
    let handle = response
        .handle
        .as_deref()
        .expect("denied typed command returns an access request");
    let guidance = response
        .verb_guidance
        .as_deref()
        .expect("denied typed command returns operator guidance");
    for command in [
        format!("guard access approve {handle}"),
        format!("guard access approve {handle} --once"),
        format!("guard access approve {handle} --uses 3"),
    ] {
        assert!(guidance.contains(&command), "missing {command}: {guidance}");
    }

    let retry = execute_command(request, &cfg, &worker)
        .await
        .into_response();
    assert_eq!(retry.handle.as_deref(), Some(handle));
}

#[tokio::test]
async fn sessionless_novel_denial_returns_exact_typed_request_guidance() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.state.verbs = Arc::new(RwLock::new(VerbCatalog::empty()));
    let temporary = tempfile::tempdir().unwrap();
    let state_db = temporary.path().join("state.db");
    let store = SessionStore::open(state_db.clone(), 3_600).await.unwrap();
    cfg.state.session_store = Some(store.clone());
    let worker = CallerIdentity::Unix { uid: 1001 };
    let daemon = CallerIdentity::UnixAdmin { uid: 777 };
    let mut request = request_with_session(
        "novel-fixture",
        vec![
            "--extra".to_string(),
            "value one".to_string(),
            "--extra".to_string(),
            "quoted \"value\" \\ π".to_string(),
        ],
        "unused".to_string(),
    );
    request.session_token = None;

    let response = execute_command(request.clone(), &cfg, &worker)
        .await
        .into_response();
    assert!(!response.allowed);
    let handle = response
        .handle
        .as_deref()
        .expect("novel denial preserves its authoritative argv in a typed request");
    let proposals = cfg.state.grant_requests.read().await[handle]
        .proposed_verbs
        .clone();
    let proposed_args = proposals
        .first()
        .and_then(|value| value.get("args"))
        .expect("typed request stores generated argv");
    assert_eq!(
        proposed_args,
        &serde_json::json!(["--extra", "value one", "--extra", "quoted \"value\" \\ π"]),
        "generated access coverage must preserve argv element boundaries"
    );
    let proposed_verb = guard::gating::verb::parse_normalized_generated_access_verb(
        proposals
            .first()
            .expect("typed request stores one proposal"),
    )
    .unwrap();
    let generated_name = proposed_verb.name.clone();
    let proposed_digest = proposed_verb.definition_digest();
    let guidance = response
        .verb_guidance
        .as_deref()
        .expect("novel denial explains how to request typed access");
    assert!(
        guidance.contains(&format!("guard access approve {handle}")),
        "{guidance}"
    );
    let original = request.args.clone();
    let split = original
        .iter()
        .flat_map(|arg| arg.split_whitespace().map(str::to_string))
        .collect::<Vec<_>>();
    let omitted_repeated_pair = original[2..].to_vec();

    let (mut approving, _) = make_test_config();
    approving.config.daemon_uid = 777;
    approving.config.daemon_principal = PrincipalKey::from_uid(777);
    approving.state.verbs = Arc::new(RwLock::new(VerbCatalog::empty()));
    let approving_store = SessionStore::open(state_db.clone(), 3_600).await.unwrap();
    approving.state.session_store = Some(approving_store.clone());
    *approving.state.sessions.write().await = approving_store.load_registry().await.unwrap();
    let pending_requests = approving_store.load_grant_requests().await.unwrap();
    let pending_request = pending_requests
        .iter()
        .find(|request| request.handle == handle)
        .expect("pending typed request survives restart");
    assert_eq!(pending_request.status, GrantRequestStatus::Pending);
    let pending_verb = guard::gating::verb::parse_normalized_generated_access_verb(
        pending_request
            .proposed_verbs
            .first()
            .expect("pending typed request keeps one proposal"),
    )
    .unwrap();
    assert_eq!(pending_verb.name, generated_name);
    assert_eq!(pending_verb.definition_digest(), proposed_digest);
    *approving.state.grant_requests.write().await = pending_requests
        .into_iter()
        .map(|request| (request.handle.clone(), request))
        .collect();
    validate_durable_access_provenance(&approving)
        .await
        .unwrap();
    install_approved_access_verbs(&approving).await.unwrap();
    let AdminResponse::AccessItem { item: pending_item } = handle_admin_request_for_test(
        &approving,
        &daemon,
        AdminRequest::AccessShow {
            reference: handle.to_string(),
        },
    )
    .await
    else {
        panic!("expected restarted pending typed access detail");
    };
    let matcher_digest = pending_item.capabilities[0].matcher_digest.clone();
    let AdminResponse::AccessDecisions { items, .. } = handle_admin_request_for_test(
        &approving,
        &daemon,
        AdminRequest::AccessApprove {
            handles: vec![handle.to_string()],
            uses: None,
            wait_secs: None,
        },
    )
    .await
    else {
        panic!("expected typed access approval");
    };
    assert!(
        items[0].success,
        "typed access approval failed: {:?}",
        items[0]
    );
    {
        let catalog = approving.state.verbs.read().await;
        let matches = catalog.match_command_all("novel-fixture", &original);
        assert_eq!(
            matches.len(),
            1,
            "approved generated access must select once"
        );
        assert_eq!(matches[0].rendered.binary, "novel-fixture");
        assert_eq!(matches[0].rendered.args, original);
        assert!(
            catalog
                .match_command_all("novel-fixture", &split)
                .is_empty(),
            "whitespace-split argv must not select exact generated access"
        );
        assert!(catalog
            .match_command_all("novel-fixture", &omitted_repeated_pair)
            .is_empty());
    }

    let (mut restarted, _) = make_test_config();
    restarted.config.daemon_uid = 777;
    restarted.config.daemon_principal = PrincipalKey::from_uid(777);
    restarted.state.verbs = Arc::new(RwLock::new(VerbCatalog::empty()));
    let restarted_store = SessionStore::open(state_db, 3_600).await.unwrap();
    restarted.state.session_store = Some(restarted_store.clone());
    *restarted.state.sessions.write().await = restarted_store.load_registry().await.unwrap();
    let durable_requests = restarted_store.load_grant_requests().await.unwrap();
    let durable_request = durable_requests
        .iter()
        .find(|request| request.handle == handle)
        .expect("approved typed request survives restart");
    assert_eq!(durable_request.status, GrantRequestStatus::Approved);
    let durable_verb = guard::gating::verb::parse_normalized_generated_access_verb(
        durable_request
            .proposed_verbs
            .first()
            .expect("durable typed request keeps one proposal"),
    )
    .unwrap();
    assert_eq!(durable_verb.name, generated_name);
    assert_eq!(durable_verb.definition_digest(), proposed_digest);
    *restarted.state.grant_requests.write().await = durable_requests
        .into_iter()
        .map(|request| (request.handle.clone(), request))
        .collect();
    validate_durable_access_provenance(&restarted)
        .await
        .unwrap();
    install_approved_access_verbs(&restarted).await.unwrap();
    let AdminResponse::AccessItem {
        item: restarted_item,
    } = handle_admin_request_for_test(
        &restarted,
        &daemon,
        AdminRequest::AccessShow {
            reference: handle.to_string(),
        },
    )
    .await
    else {
        panic!("expected restarted typed access detail");
    };
    assert_eq!(
        restarted_item.capabilities[0].matcher_digest,
        matcher_digest
    );
    {
        let catalog = restarted.state.verbs.read().await;
        let matches = catalog.match_command_all("novel-fixture", &original);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rendered.binary, "novel-fixture");
        assert_eq!(matches[0].rendered.args, original);
        assert!(catalog
            .match_command_all("novel-fixture", &split)
            .is_empty());
        assert!(catalog
            .match_command_all("novel-fixture", &omitted_repeated_pair)
            .is_empty());
    }
    let mut changed = original;
    changed
        .last_mut()
        .expect("fixture argv is non-empty")
        .push('!');
    assert!(restarted
        .state
        .verbs
        .read()
        .await
        .match_command_all("novel-fixture", &changed)
        .is_empty());
}

#[tokio::test]
async fn approved_matcher_name_tamper_fails_closed_across_restart_boundaries() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.state.verbs = Arc::new(RwLock::new(VerbCatalog::empty()));
    let temporary = tempfile::tempdir().unwrap();
    let state_db = temporary.path().join("state.db");
    let store = SessionStore::open(state_db.clone(), 3_600).await.unwrap();
    cfg.state.session_store = Some(store.clone());
    let worker = CallerIdentity::Unix { uid: 1001 };
    let daemon = CallerIdentity::UnixAdmin { uid: 777 };
    let mut execute = request_with_session(
        "novel-fixture",
        vec!["inspect".to_string(), "resource/example".to_string()],
        "unused".to_string(),
    );
    execute.session_token = None;
    let denied = execute_command(execute, &cfg, &worker)
        .await
        .into_response();
    let handle = denied.handle.expect("typed request is created");
    let AdminResponse::AccessDecisions { items, .. } = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::AccessApprove {
            handles: vec![handle.clone()],
            uses: None,
            wait_secs: None,
        },
    )
    .await
    else {
        panic!("expected typed access approval");
    };
    assert!(items[0].success);
    let durable_registry = store.load_registry().await.unwrap();

    let mut tampered = cfg.state.grant_requests.read().await[&handle].clone();
    assert_eq!(tampered.status, GrantRequestStatus::Approved);
    let mut proposal = serde_json::from_value::<guard::gating::verb::Verb>(
        tampered
            .proposed_verbs
            .first()
            .expect("approved request keeps generated coverage")
            .clone(),
    )
    .unwrap();
    let approved_name = proposal.name.clone();
    proposal
        .args
        .last_mut()
        .expect("fixture matcher has literal arguments")
        .push_str("-changed");
    assert_eq!(proposal.name, approved_name);
    tampered.proposed_verbs = vec![serde_json::to_value(proposal).unwrap()];
    assert!(tampered.validated_generated_access_proposals().is_err());

    let connection = rusqlite::Connection::open(&state_db).unwrap();
    connection
        .execute(
            "UPDATE grant_requests SET json = ?1 WHERE handle = ?2",
            rusqlite::params![serde_json::to_string(&tampered).unwrap(), handle],
        )
        .unwrap();
    drop(connection);
    assert!(store.load_grant_requests().await.is_err());
    assert!(store.load_registry().await.is_err());

    let (mut restarted, _) = make_test_config();
    restarted.config.daemon_uid = 777;
    restarted.config.daemon_principal = PrincipalKey::from_uid(777);
    restarted.state.verbs = Arc::new(RwLock::new(VerbCatalog::empty()));
    *restarted.state.sessions.write().await = durable_registry;
    restarted
        .state
        .grant_requests
        .write()
        .await
        .insert(tampered.handle.clone(), tampered);
    assert!(validate_durable_access_provenance(&restarted)
        .await
        .is_err());
    assert!(install_approved_access_verbs(&restarted).await.is_err());
}

async fn assert_sensitive_argv_rejected(binary: &str, args: Vec<String>, sensitive: &str) {
    let (mut cfg, _) = make_test_config();
    let (audit_directory, _audit) = super::attach_test_audit_log(&mut cfg);
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.state.verbs = Arc::new(RwLock::new(VerbCatalog::empty()));
    let temporary = tempfile::tempdir().unwrap();
    let store = SessionStore::open(temporary.path().join("state.db"), 3_600)
        .await
        .unwrap();
    cfg.state.session_store = Some(store.clone());
    let worker = CallerIdentity::Unix { uid: 1001 };
    let daemon = CallerIdentity::UnixAdmin { uid: 777 };
    let mut request = request_with_session(binary, args, "unused".to_string());
    request.session_token = None;

    let response = execute_command(request, &cfg, &worker)
        .await
        .into_response();
    assert!(!response.allowed);
    assert!(response.handle.is_none());
    assert!(cfg.state.grant_requests.read().await.is_empty());
    assert!(store.load_grant_requests().await.unwrap().is_empty());
    assert!(!response.reason.contains(sensitive));
    assert!(!response
        .stdout
        .as_deref()
        .is_some_and(|value| value.contains(sensitive)));
    assert!(!response
        .stderr
        .as_deref()
        .is_some_and(|value| value.contains(sensitive)));
    assert!(!response
        .verb_guidance
        .as_deref()
        .is_some_and(|value| value.contains(sensitive)));
    assert!(!serde_json::to_string(&response.verb_matches)
        .unwrap()
        .contains(sensitive));
    assert!(!serde_json::to_string(&response.decision_trace)
        .unwrap()
        .contains(sensitive));
    let response_json = serde_json::to_string(&response).unwrap();
    assert!(!response_json.contains(sensitive));
    let audit_json = std::fs::read_to_string(audit_directory.path().join("audit.jsonl")).unwrap();
    assert!(!audit_json.contains(sensitive));

    let access_list = handle_admin_request_for_test(&cfg, &daemon, AdminRequest::AccessList).await;
    let access_json = serde_json::to_string(&access_list).unwrap();
    assert!(!access_json.contains(sensitive));
    assert!(matches!(
        access_list,
        AdminResponse::AccessItems { items } if items.is_empty()
    ));
}

#[tokio::test]
async fn independently_sensitive_argv_does_not_create_or_expose_generated_access() {
    let sensitive = [["s", "k"].concat(), "-".to_string(), "Ab1".repeat(8)].concat();
    assert_ne!(guard::redact::redact_output_text(&sensitive), sensitive);
    assert_sensitive_argv_rejected(
        "novel-fixture",
        vec!["--credential".to_string(), sensitive.clone()],
        &sensitive,
    )
    .await;
}

#[tokio::test]
async fn split_and_inline_sensitive_argv_do_not_create_or_expose_generated_access() {
    let sensitive = ["low", "entropy"].concat();
    assert_eq!(guard::redact::redact_output_text(&sensitive), sensitive);
    assert_sensitive_argv_rejected(
        "novel-fixture",
        vec!["--api-token".to_string(), sensitive.clone()],
        &sensitive,
    )
    .await;
    assert_sensitive_argv_rejected(
        "novel-fixture",
        vec![format!("--api-token={sensitive}")],
        &sensitive,
    )
    .await;
}

#[tokio::test]
async fn strict_and_opaque_sensitive_argv_do_not_reach_durable_or_audit_surfaces() {
    let sensitive = ["q", "7"].concat();
    for (binary, args) in [
        (
            "novel-fixture",
            vec!["--key".to_string(), sensitive.clone()],
        ),
        ("novel-fixture", vec![format!("--pass={sensitive}")]),
        (
            "novel-fixture",
            vec![format!("--passphrase=\n{sensitive}\u{1}")],
        ),
        ("curl", vec!["-u".to_string(), sensitive.clone()]),
        ("curl", vec![format!("--user={sensitive}")]),
        (
            "curl",
            vec!["-H".to_string(), format!("Authorization: {sensitive}")],
        ),
        ("curl.EXE", vec![format!("-u{sensitive}")]),
        (
            "docker.CMD",
            vec!["login".to_string(), format!("-p:{sensitive}")],
        ),
    ] {
        assert_sensitive_argv_rejected(binary, args, &sensitive).await;
    }
}

#[tokio::test]
async fn split_sensitive_argv_is_redacted_in_live_and_durable_session_history() {
    let (mut cfg, _) = make_test_config();
    let (audit_directory, _audit) = super::attach_test_audit_log(&mut cfg);
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.config.admission_preview = true;
    let temporary = tempfile::tempdir().unwrap();
    let store = SessionStore::open(temporary.path().join("state.db"), 3_600)
        .await
        .unwrap();
    cfg.state.session_store = Some(store.clone());
    let token = "sensitive-history".to_string();
    let mut grant = granted_session_owned(1001, Vec::new(), Vec::new());
    grant.deny = vec!["curl*".to_string()];
    cfg.state.sessions.write().await.grant(token.clone(), grant);
    let initial_registry = cfg.state.sessions.read().await.clone();
    store.persist_registry(&initial_registry).await.unwrap();

    let sensitive = ["q", "7"].concat();
    let request = request_with_session("curl.EXE", vec![format!("-u{sensitive}")], token.clone());
    let response = execute_command(request, &cfg, &CallerIdentity::Unix { uid: 1001 })
        .await
        .into_response();
    assert!(!response.allowed);
    assert!(!serde_json::to_string(&response)
        .unwrap()
        .contains(&sensitive));

    let live_report = cfg.state.sessions.read().await.show(&token, 10).unwrap();
    assert!(!serde_json::to_string(&live_report)
        .unwrap()
        .contains(&sensitive));
    let durable_report = store
        .load_registry()
        .await
        .unwrap()
        .show(&token, 10)
        .unwrap();
    assert!(!serde_json::to_string(&durable_report)
        .unwrap()
        .contains(&sensitive));

    let show = handle_admin_request_for_test(
        &cfg,
        &CallerIdentity::UnixAdmin { uid: 777 },
        AdminRequest::SessionShow {
            token,
            limit: Some(10),
            caller_token: None,
        },
    )
    .await;
    assert!(!serde_json::to_string(&show).unwrap().contains(&sensitive));
    let audit_json = std::fs::read_to_string(audit_directory.path().join("audit.jsonl")).unwrap();
    assert!(!audit_json.contains(&sensitive));
}

#[tokio::test]
async fn allowed_sensitive_argv_is_redacted_in_live_and_durable_session_history() {
    let (mut cfg, _) = make_test_config();
    let (audit_directory, _audit) = super::attach_test_audit_log(&mut cfg);
    let temporary = tempfile::tempdir().unwrap();
    let store = SessionStore::open(temporary.path().join("state.db"), 3_600)
        .await
        .unwrap();
    cfg.state.session_store = Some(store.clone());
    let token = "allowed-sensitive-history".to_string();
    cfg.state.sessions.write().await.grant(
        token.clone(),
        granted_session_owned(1001, vec!["true*".to_string()], Vec::new()),
    );
    let initial_registry = cfg.state.sessions.read().await.clone();
    store.persist_registry(&initial_registry).await.unwrap();

    let sensitive = ["q", "7"].concat();
    let response = execute_command(
        request_with_session(
            "true",
            vec!["--pass".to_string(), sensitive.clone()],
            token.clone(),
        ),
        &cfg,
        &CallerIdentity::Unix { uid: 1001 },
    )
    .await
    .into_response();
    assert!(response.allowed);
    assert!(!serde_json::to_string(&response)
        .unwrap()
        .contains(&sensitive));

    let live_report = cfg.state.sessions.read().await.show(&token, 10).unwrap();
    assert!(!serde_json::to_string(&live_report)
        .unwrap()
        .contains(&sensitive));
    let durable_report = store
        .load_registry()
        .await
        .unwrap()
        .show(&token, 10)
        .unwrap();
    assert!(!serde_json::to_string(&durable_report)
        .unwrap()
        .contains(&sensitive));
    let audit_json = std::fs::read_to_string(audit_directory.path().join("audit.jsonl")).unwrap();
    assert!(!audit_json.contains(&sensitive));
}

#[tokio::test]
async fn display_colliding_argv_create_distinct_convergent_requests() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.state.verbs = Arc::new(RwLock::new(VerbCatalog::empty()));
    let temporary = tempfile::tempdir().unwrap();
    cfg.state.session_store = Some(
        SessionStore::open(temporary.path().join("state.db"), 3_600)
            .await
            .unwrap(),
    );
    let worker = CallerIdentity::Unix { uid: 1001 };
    let first_args = vec!["alpha beta".to_string()];
    let second_args = vec!["alpha".to_string(), "beta".to_string()];
    assert_eq!(
        guard::redact::command_line("novel-fixture", &first_args),
        guard::redact::command_line("novel-fixture", &second_args)
    );

    let deny = |args: Vec<String>| {
        let cfg = &cfg;
        let worker = &worker;
        async move {
            let mut request = request_with_session("novel-fixture", args, "unused".to_string());
            request.session_token = None;
            execute_command(request, cfg, worker).await.into_response()
        }
    };
    let first = deny(first_args.clone()).await;
    let second = deny(second_args.clone()).await;
    let first_handle = first.handle.expect("first argv creates a typed request");
    let second_handle = second.handle.expect("second argv creates a typed request");
    assert_ne!(first_handle, second_handle);

    let requests = cfg.state.grant_requests.read().await;
    let first_proposal = guard::gating::verb::parse_normalized_generated_access_verb(
        requests[&first_handle]
            .proposed_verbs
            .first()
            .expect("first request has generated coverage"),
    )
    .unwrap();
    let second_proposal = guard::gating::verb::parse_normalized_generated_access_verb(
        requests[&second_handle]
            .proposed_verbs
            .first()
            .expect("second request has generated coverage"),
    )
    .unwrap();
    assert_eq!(first_proposal.args, first_args);
    assert_eq!(second_proposal.args, second_args);
    assert_ne!(first_proposal.name, second_proposal.name);
    drop(requests);

    assert_eq!(
        deny(first_args).await.handle.as_deref(),
        Some(first_handle.as_str())
    );
    assert_eq!(
        deny(second_args).await.handle.as_deref(),
        Some(second_handle.as_str())
    );
}

#[tokio::test]
async fn structured_argv_converges_to_one_matcher_across_principals() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.state.verbs = Arc::new(RwLock::new(VerbCatalog::empty()));
    let args = vec!["inspect".to_string(), "resource with spaces".to_string()];

    let mut first_request =
        request_with_session("novel-fixture", args.clone(), "unused".to_string());
    first_request.session_token = None;
    let first = execute_command(first_request, &cfg, &CallerIdentity::Unix { uid: 1001 })
        .await
        .into_response();
    let mut second_request = request_with_session("novel-fixture", args, "unused".to_string());
    second_request.session_token = None;
    let second = execute_command(second_request, &cfg, &CallerIdentity::Unix { uid: 1002 })
        .await
        .into_response();
    let first_handle = first.handle.expect("first principal receives a request");
    let second_handle = second.handle.expect("second principal receives a request");
    assert_ne!(first_handle, second_handle);

    let requests = cfg.state.grant_requests.read().await;
    assert_ne!(
        requests[&first_handle].requester,
        requests[&second_handle].requester
    );
    let first_verb = guard::gating::verb::parse_normalized_generated_access_verb(
        requests[&first_handle]
            .proposed_verbs
            .first()
            .expect("first principal has generated coverage"),
    )
    .unwrap();
    let second_verb = guard::gating::verb::parse_normalized_generated_access_verb(
        requests[&second_handle]
            .proposed_verbs
            .first()
            .expect("second principal has generated coverage"),
    )
    .unwrap();
    let first_shape = guard::gating::verb::generated_access_matcher_shape(&first_verb);
    let second_shape = guard::gating::verb::generated_access_matcher_shape(&second_verb);
    assert_eq!(first_verb.name, second_verb.name);
    assert_eq!(first_shape, second_shape);
    assert_eq!(
        guard::gating::verb::generated_access_matcher_digest(&first_shape),
        guard::gating::verb::generated_access_matcher_digest(&second_shape)
    );
}

#[tokio::test]
async fn structured_argv_retries_converge_before_capacity_rejection() {
    let worker = CallerIdentity::Unix { uid: 1001 };
    let original = vec!["inspect".to_string(), "original".to_string()];
    let changed = vec!["inspect".to_string(), "changed".to_string()];

    let (mut global, _) = make_test_config();
    global.config.daemon_principal = PrincipalKey::from_uid(global.config.daemon_uid);
    global.state.verbs = Arc::new(RwLock::new(VerbCatalog::empty()));
    let deny_global = |args: Vec<String>| {
        let global = &global;
        let worker = &worker;
        async move {
            let mut request = request_with_session("novel-fixture", args, "unused".to_string());
            request.session_token = None;
            execute_command(request, global, worker)
                .await
                .into_response()
        }
    };
    let first = deny_global(original.clone()).await;
    let first_handle = first.handle.expect("initial exact request is created");
    let template = global.state.grant_requests.read().await[&first_handle].clone();
    {
        let mut requests = global.state.grant_requests.write().await;
        for index in 1..crate::server::admin::MAX_GRANT_REQUESTS {
            let mut filler = template.clone();
            filler.handle = format!("global-capacity-{index:04}");
            filler.requester = Some(PrincipalKey::from_uid(2000 + index as u32));
            filler.session_token = format!("global-capacity-session-{index:04}");
            filler.request_key = filler.canonical_access_key().unwrap();
            requests.insert(filler.handle.clone(), filler);
        }
        assert_eq!(requests.len(), crate::server::admin::MAX_GRANT_REQUESTS);
    }
    assert_eq!(
        deny_global(original.clone()).await.handle.as_deref(),
        Some(first_handle.as_str())
    );
    let rejected = deny_global(changed.clone()).await;
    assert!(rejected.handle.is_none());
    assert!(rejected
        .verb_guidance
        .as_deref()
        .is_some_and(|guidance| guidance.contains("queue is full")));

    let (mut principal, _) = make_test_config();
    principal.config.daemon_principal = PrincipalKey::from_uid(principal.config.daemon_uid);
    principal.state.verbs = Arc::new(RwLock::new(VerbCatalog::empty()));
    let deny_principal = |args: Vec<String>| {
        let principal = &principal;
        let worker = &worker;
        async move {
            let mut request = request_with_session("novel-fixture", args, "unused".to_string());
            request.session_token = None;
            execute_command(request, principal, worker)
                .await
                .into_response()
        }
    };
    let first = deny_principal(original.clone()).await;
    let first_handle = first.handle.expect("initial principal request is created");
    let template = principal.state.grant_requests.read().await[&first_handle].clone();
    {
        let mut requests = principal.state.grant_requests.write().await;
        for index in 1..crate::server::admin::MAX_PENDING_GRANT_REQUESTS_PER_SESSION {
            let mut filler = template.clone();
            filler.handle = format!("principal-capacity-{index:04}");
            filler.session_token = format!("principal-capacity-session-{index:04}");
            filler.request_key = filler.canonical_access_key().unwrap();
            requests.insert(filler.handle.clone(), filler);
        }
        assert_eq!(
            requests
                .values()
                .filter(|request| {
                    request
                        .requester
                        .as_ref()
                        .is_some_and(|requester| requester.eq_ci(&PrincipalKey::from_uid(1001)))
                        && request.status == GrantRequestStatus::Pending
                })
                .count(),
            crate::server::admin::MAX_PENDING_GRANT_REQUESTS_PER_SESSION
        );
    }
    assert_eq!(
        deny_principal(original).await.handle.as_deref(),
        Some(first_handle.as_str())
    );
    let rejected = deny_principal(changed).await;
    assert!(rejected.handle.is_none());
    assert!(rejected
        .verb_guidance
        .as_deref()
        .is_some_and(|guidance| guidance.contains("queue is full")));
}

#[tokio::test]
async fn observed_argv_is_not_replaced_by_a_similar_authored_verb() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            r#"
verbs:
  - name: inspect-similar-resource
    description: novel-fixture inspect target
    binary: novel-fixture
    args: ["inspect", "different-target"]
    consequence: reversible
"#,
        )
        .unwrap(),
    ));
    let worker = CallerIdentity::Unix { uid: 1001 };
    let expected = vec!["inspect".to_string(), "target".to_string()];
    let mut request = request_with_session("novel-fixture", expected.clone(), "unused".to_string());
    request.session_token = None;

    let response = execute_command(request, &cfg, &worker)
        .await
        .into_response();
    let handle = response
        .handle
        .expect("observed argv creates exact generated coverage");
    let requests = cfg.state.grant_requests.read().await;
    let request = &requests[&handle];
    assert!(!request
        .authority_verbs
        .iter()
        .any(|name| name == "inspect-similar-resource"));
    let proposal = guard::gating::verb::parse_normalized_generated_access_verb(
        request
            .proposed_verbs
            .first()
            .expect("observed argv has generated coverage"),
    )
    .unwrap();
    assert_eq!(proposal.args, expected);
}

#[tokio::test]
async fn hard_typed_denial_is_labeled_non_overridable_without_request() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.config.gate = GateMode::Consequence;
    cfg.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            r#"
verbs:
  - name: block-fixture
    binary: fixture-denied
    baseline: true
    consequence: reversible
    coverage:
      - name: protected
        action: deny
        required_args: ["status"]
        sticky: true
"#,
        )
        .unwrap(),
    ));
    let worker = CallerIdentity::Unix { uid: 1001 };
    let mut request = request_with_session(
        "fixture-denied",
        vec!["status".to_string()],
        "unused".to_string(),
    );
    request.session_token = None;

    let response = execute_command(request, &cfg, &worker)
        .await
        .into_response();
    assert!(!response.allowed);
    assert!(response.handle.is_none());
    assert!(response.access_requests.is_empty());
    assert!(
        response
            .verb_guidance
            .as_deref()
            .is_some_and(|guidance| guidance.contains("non-overridable operator policy")),
        "{response:?}"
    );
}

#[tokio::test]
async fn explicit_static_deny_text_cannot_become_an_access_request() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    let tmp = tempfile::tempdir().unwrap();
    let policy = tmp.path().join("policy.yaml");
    std::fs::write(
        &policy,
        r#"
policy:
  groups:
    - name: protected
      priority: 10
      rules:
        - patterns: ["fixture-denied*"]
          action: deny
          description: "explicit default-deny fixture"
"#,
    )
    .unwrap();
    cfg.state.evaluator = Arc::new(
        Evaluator::new(EvalConfig::default().llm_enabled(false).policy_path(policy)).unwrap(),
    );
    let worker = CallerIdentity::Unix { uid: 1001 };
    let mut request = request_with_session(
        "fixture-denied",
        vec!["status".to_string()],
        "unused".to_string(),
    );
    request.session_token = None;

    let response = execute_command(request, &cfg, &worker)
        .await
        .into_response();
    assert!(!response.allowed);
    assert!(response.reason.contains("explicit default-deny fixture"));
    assert!(response.handle.is_none());
    assert!(response.access_requests.is_empty());
    assert!(
        response
            .verb_guidance
            .as_deref()
            .is_some_and(|guidance| guidance.contains("non-overridable operator policy")),
        "{response:?}"
    );
}

#[tokio::test]
async fn kubeconfig_issuance_is_local_live_session_scoped_and_secret_free() {
    let (mut cfg, audit) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    let token = "finite-kube-session-token";
    let mut grant = granted_session(Vec::new(), Vec::new());
    grant.expires_at = Some(guard::env::now_unix() + 60);
    // The session is owned by uid 1001; only that principal (or the operator)
    // may mint a kubeconfig carrying its bearer.
    grant.owner = crate::session::SessionOwner::Principal(PrincipalKey::from_uid(1_001));
    cfg.state
        .sessions
        .write()
        .await
        .grant(token.to_string(), grant);

    let proxy = guard::proxy::ApiProxy::new(
        "127.0.0.1:18443".parse().unwrap(),
        guard::proxy::ProxyTls::generate().expect("proxy TLS"),
        guard::proxy::Upstream::from_base_url(
            "https://127.0.0.1:16443",
            guard::proxy::UpstreamAuth::Bearer("upstream-test-only".to_string()),
        )
        .expect("upstream"),
        guard::proxy::ApiPolicy::deny_all(),
        None,
    );
    cfg.state
        .protocol_registry
        .write()
        .await
        .insert("cluster-a".to_string(), Arc::new(proxy));

    let request = || AdminRequest::KubeconfigIssue {
        endpoint: "cluster-a".to_string(),
        session_token: token.to_string(),
    };
    // The owning principal (uid 1001) issues successfully.
    let (response, logs) = capture_async(
        &audit,
        handle_admin_request_for_test(&cfg, &CallerIdentity::Unix { uid: 1_001 }, request()),
    )
    .await;
    let AdminResponse::KubeconfigIssued { yaml, expires_at } = response else {
        panic!("expected kubeconfig issuance");
    };
    assert!(expires_at > guard::env::now_unix());
    guard::proxy::validate_brokered_kubeconfig_with_session(&yaml, token)
        .expect("only the Guard bearer is present");
    assert!(!yaml.contains("upstream-test-only"));
    assert!(
        !logs.contains(token),
        "raw session token entered audit output"
    );

    // A different local principal that merely knows the handle is denied with
    // the greppable principal-mismatch reason: this is the bearer-replay hole
    // the ownership binding closes.
    match handle_admin_request_for_test(&cfg, &CallerIdentity::Unix { uid: 1_002 }, request()).await
    {
        AdminResponse::Error { message } => {
            assert!(
                message.contains("session principal mismatch"),
                "expected principal mismatch, got: {message}"
            );
        }
        other => panic!("expected mismatch denial, got {other:?}"),
    }
    // An authenticated operator retains cross-session authority.
    assert!(matches!(
        handle_admin_request_for_test(&cfg, &CallerIdentity::UnixAdmin { uid: 777 }, request())
            .await,
        AdminResponse::KubeconfigIssued { .. }
    ));

    {
        let mut sessions = cfg.state.sessions.write().await;
        let mut access_managed = sessions.grants_snapshot().remove(token).unwrap();
        access_managed.scope.access_managed = true;
        sessions.grant("access-managed-kube".to_string(), access_managed);
    }
    match handle_admin_request_for_test(
        &cfg,
        &CallerIdentity::Unix { uid: 1_001 },
        AdminRequest::KubeconfigIssue {
            endpoint: "cluster-a".to_string(),
            session_token: "access-managed-kube".to_string(),
        },
    )
    .await
    {
        AdminResponse::Error { message } => assert!(message.contains("not reusable API")),
        other => panic!("access-managed session minted a kubeconfig: {other:?}"),
    }
    assert!(matches!(
        handle_admin_request_for_test(
            &cfg,
            &CallerIdentity::Tcp {
                token: "tcp-auth".to_string()
            },
            request()
        )
        .await,
        AdminResponse::Error { .. }
    ));

    cfg.state.sessions.write().await.revoke(token);
    assert!(matches!(
        handle_admin_request_for_test(&cfg, &CallerIdentity::Unix { uid: 1_001 }, request()).await,
        AdminResponse::Error { .. }
    ));

    let expired = "expired-kube-session";
    let mut expired_grant = granted_session(Vec::new(), Vec::new());
    expired_grant.expires_at = Some(guard::env::now_unix());
    cfg.state
        .sessions
        .write()
        .await
        .grant(expired.to_string(), expired_grant);
    assert!(matches!(
        handle_admin_request_for_test(
            &cfg,
            &CallerIdentity::Unix { uid: 1_001 },
            AdminRequest::KubeconfigIssue {
                endpoint: "cluster-a".to_string(),
                session_token: expired.to_string(),
            }
        )
        .await,
        AdminResponse::Error { .. }
    ));
}

#[tokio::test]
async fn session_grant_validates_activated_verbs_and_exact_override_markers() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            r#"
verbs:
  - name: baseline-review
    binary: kubectl
    consequence: reversible
    coverage:
      - name: apply
        action: evaluate
        required_args: ["apply"]
        override_marker: operator:apply
  - name: session-apply
    binary: kubectl
    baseline: false
    consequence: recoverable
    revert: { binary: kubectl, args: ["rollout", "undo", "deployment/web"] }
    trusted: true
    coverage:
      - name: web
        action: preauthorized
        required_args: ["apply"]
"#,
        )
        .expect("valid verb catalog"),
    ));
    let daemon = CallerIdentity::UnixAdmin { uid: 777 };

    let valid = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::SessionGrant {
            token: "typed-session".to_string(),
            allow: Vec::new(),
            deny: Vec::new(),
            activated_verbs: vec!["session-apply".to_string()],
            override_markers: vec!["operator:apply".to_string()],
            ttl_secs: None,
            prompt_append: None,
            prose: None,
            saved_grant: None,
            profile: None,
            evaluation_mode: None,
            static_only: false,
            auto_amend: false,
            owner: None,
        },
    )
    .await;
    assert!(matches!(valid, AdminResponse::Ok));

    let unknown_verb = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::SessionGrant {
            token: "unknown-verb".to_string(),
            allow: Vec::new(),
            deny: Vec::new(),
            activated_verbs: vec!["missing".to_string()],
            override_markers: Vec::new(),
            ttl_secs: None,
            prompt_append: None,
            prose: None,
            saved_grant: None,
            profile: None,
            evaluation_mode: None,
            static_only: false,
            auto_amend: false,
            owner: None,
        },
    )
    .await;
    assert!(matches!(
        unknown_verb,
        AdminResponse::Error { message } if message.contains("unknown session verb")
    ));

    let unknown_marker = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::SessionGrant {
            token: "unknown-marker".to_string(),
            allow: Vec::new(),
            deny: Vec::new(),
            activated_verbs: vec!["session-apply".to_string()],
            override_markers: vec!["operator:typo".to_string()],
            ttl_secs: None,
            prompt_append: None,
            prose: None,
            saved_grant: None,
            profile: None,
            evaluation_mode: None,
            static_only: false,
            auto_amend: false,
            owner: None,
        },
    )
    .await;
    assert!(matches!(
        unknown_marker,
        AdminResponse::Error { message } if message.contains("unknown verb override marker")
    ));
}

fn request_with_session(binary: &str, args: Vec<String>, token: String) -> ExecuteRequest {
    ExecuteRequest {
        binary: binary.to_string(),
        args,
        auth_token: None,
        env: HashMap::new(),
        secrets: HashMap::new(),
        secret_files: HashMap::new(),
        stream: false,
        session_token: Some(token),
        revert: None,
        confirm_within_secs: None,
        reevaluate: false,
        ssh_hostkey: None,
        cwd: None,
        require_approval: None,
        wait_approval_secs: None,
        verb: None,
    }
}

#[tokio::test]
async fn session_allow_cannot_bypass_binary_floor() {
    let (mut cfg, _) = make_test_config();
    cfg.config.allowed_binaries = Some(vec!["echo".to_string()]);
    let token = format!("binary-floor-glob-{}", std::process::id());
    cfg.state.sessions.write().await.grant(
        token.clone(),
        granted_session(vec!["sh *".to_string()], Vec::new()),
    );

    let result = execute_command(
        request_with_session("sh", vec!["-c".to_string(), "true".to_string()], token),
        &cfg,
        &CallerIdentity::Unix { uid: 1000 },
    )
    .await;

    assert!(!result.policy_allowed());
    assert!(result
        .policy_reason()
        .contains("not in the server allow-list"));
}

#[tokio::test]
async fn session_exact_allow_cannot_bypass_binary_floor() {
    let (mut cfg, _) = make_test_config();
    cfg.config.allowed_binaries = Some(vec!["echo".to_string()]);
    let token = format!("binary-floor-exact-{}", std::process::id());
    cfg.state.sessions.write().await.grant(
        token.clone(),
        granted_session(
            Vec::new(),
            vec![SessionExactRule::new(
                "sh",
                vec!["-c".to_string(), "true".to_string()],
            )],
        ),
    );

    let result = execute_command(
        request_with_session("sh", vec!["-c".to_string(), "true".to_string()], token),
        &cfg,
        &CallerIdentity::Unix { uid: 1000 },
    )
    .await;

    assert!(!result.policy_allowed());
    assert!(result
        .policy_reason()
        .contains("not in the server allow-list"));
}

#[tokio::test]
async fn session_allow_routes_through_consequence_gate() {
    let (mut cfg, _) = make_test_config();
    cfg.config.gate = GateMode::Consequence;
    let token = format!("session-gate-{}", std::process::id());
    cfg.state.sessions.write().await.grant(
        token.clone(),
        granted_session(vec!["true".to_string()], Vec::new()),
    );

    let result = execute_command(
        request_with_session("true", Vec::new(), token),
        &cfg,
        &CallerIdentity::Unix { uid: 1000 },
    )
    .await;

    assert!(result.policy_allowed(), "session allow is policy approval");
    assert!(
        matches!(result.exec, ExecOutcome::Held { .. }),
        "unclassified consequence-mode session allow must hold, got {:?}",
        result.exec
    );
}

#[tokio::test]
async fn cwd_request_does_not_match_legacy_session_allow_glob() {
    let (cfg, _) = make_test_config();
    let temp = tempfile::tempdir().unwrap();
    let token = format!("cwd-legacy-glob-{}", std::process::id());
    cfg.state.sessions.write().await.grant(
        token.clone(),
        granted_session(vec!["pwd".to_string()], Vec::new()),
    );

    let mut req = request_with_session("pwd", Vec::new(), token);
    req.cwd = Some(temp.path().canonicalize().unwrap());

    let result = execute_command(req, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;
    assert!(!result.policy_allowed());
    assert!(
        result.policy_reason().contains("session policy-only mode"),
        "expected cwd-bearing legacy allow to miss, got {}",
        result.policy_reason()
    );
}

#[tokio::test]
async fn cwd_request_matches_cwd_bound_exact_session_allow_only() {
    let (cfg, _) = make_test_config();
    let allowed = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let allowed_cwd = allowed.path().canonicalize().unwrap();
    let token = format!("cwd-exact-{}", std::process::id());
    cfg.state.sessions.write().await.grant(
        token.clone(),
        granted_session(
            Vec::new(),
            vec![SessionExactRule::with_cwd(
                "sh",
                vec![
                    "-c".to_string(),
                    "printf ok > cwd-exact-sentinel.txt".to_string(),
                ],
                allowed_cwd.clone(),
            )],
        ),
    );

    let mut req = request_with_session(
        "sh",
        vec![
            "-c".to_string(),
            "printf ok > cwd-exact-sentinel.txt".to_string(),
        ],
        token.clone(),
    );
    req.cwd = Some(allowed_cwd.clone());
    let result = execute_command(req, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;
    match result.exec {
        ExecOutcome::Completed {
            exit_code: Some(0), ..
        } => {
            let sentinel = allowed_cwd.join("cwd-exact-sentinel.txt");
            let content = std::fs::read_to_string(&sentinel);
            assert!(
                matches!(content.as_deref(), Ok("ok")),
                "sentinel content at {}: {:?}",
                sentinel.display(),
                content
            );
        }
        other => panic!("expected cwd-bound exact allow to execute, got {:?}", other),
    }

    let mut req = request_with_session(
        "sh",
        vec![
            "-c".to_string(),
            "printf ok > cwd-exact-sentinel.txt".to_string(),
        ],
        token,
    );
    req.cwd = Some(other.path().canonicalize().unwrap());
    let result = execute_command(req, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;
    assert!(!result.policy_allowed());
}

#[tokio::test]
async fn static_only_session_miss_denies_before_evaluator() {
    let (cfg, _) = make_test_config();
    let token = format!("static-only-{}", std::process::id());
    {
        let mut sessions = cfg.state.sessions.write().await;
        sessions.grant(
            token.clone(),
            SessionGrant {
                allow: vec!["kubectl -n grafana get pods*".into()],
                deny: Vec::new(),
                allow_exact: Vec::new(),
                deny_exact: Vec::new(),
                activated_verbs: Vec::new(),
                override_markers: Vec::new(),
                scope: Default::default(),
                expires_at: None,
                prompt_append: None,
                generated_notes: Vec::new(),
                static_only: true,
                auto_amend: false,
                granted_at: 0,
                owner: crate::session::SessionOwner::Principal(
                    guard::principal::PrincipalKey::from_uid(1000),
                ),
            },
        );
    }

    let req = ExecuteRequest {
        binary: "kubectl".to_string(),
        args: vec!["get".into(), "pods".into(), "-n".into(), "default".into()],
        auth_token: None,
        env: HashMap::new(),
        secrets: HashMap::new(),
        secret_files: HashMap::new(),
        stream: false,
        session_token: Some(token),
        revert: None,
        confirm_within_secs: None,
        reevaluate: false,
        ssh_hostkey: None,
        cwd: None,
        require_approval: None,
        wait_approval_secs: None,
        verb: None,
    };

    let result = execute_command(req, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;
    assert!(!result.policy_allowed());
    assert!(result.policy_reason().contains("policy-only mode"));
}

#[test]
fn session_auto_amend_allow_candidates_are_low_risk_and_simple() {
    assert!(allow_session_auto_amend_candidate("echo", &["ok".into()], Some(2)).is_ok());
    assert!(allow_session_auto_amend_candidate("echo", &["ok".into()], Some(3)).is_err());
    assert!(
        allow_session_auto_amend_candidate("sh", &["-c".into(), "id; whoami".into()], Some(1))
            .is_err()
    );
    assert!(allow_session_auto_amend_candidate("cat", &["/etc/shadow".into()], Some(1)).is_err());
}

#[test]
fn session_auto_amend_deny_candidates_are_high_risk_exact_rules() {
    assert!(deny_session_auto_amend_candidate(
        "kubectl",
        &["delete".into(), "pod/x".into()],
        Some(5)
    )
    .is_ok());
    assert!(deny_session_auto_amend_candidate(
        "kubectl",
        &["delete".into(), "pod/x".into()],
        Some(4)
    )
    .is_err());
    assert!(
        deny_session_auto_amend_candidate("kubectl", &["delete\npod/x".into()], Some(9)).is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exact_amendment_publishes_only_after_persistence_and_preserves_concurrent_state() {
    let (mut cfg, _) = make_test_config();
    let tmp = tempfile::tempdir().unwrap();
    let store = SessionStore::open(tmp.path().join("amendments.db"), 3600)
        .await
        .unwrap();
    cfg.state.session_store = Some(store.clone());
    let token = "exact-amendment-session";
    assert!(cfg.state.sessions.write().await.grant(
        token.to_string(),
        granted_session_owned(1000, Vec::new(), Vec::new()),
    ));
    store
        .persist_registry(&cfg.state.sessions.read().await.clone())
        .await
        .unwrap();

    store.fail_next_write_for_test();
    assert!(amend_session_exact_rule(
        &cfg,
        token,
        SessionAmendment::Allow,
        "echo".to_string(),
        vec!["failed".to_string()],
        None,
    )
    .await
    .is_err());
    assert!(cfg
        .state
        .sessions
        .read()
        .await
        .check(token, "echo", &["failed".to_string()], None)
        .is_none());

    let (committed, release) = store.pause_registry_commit_for_test("session store persist");
    let first_server = cfg.clone();
    let first = tokio::spawn(async move {
        amend_session_exact_rule(
            &first_server,
            token,
            SessionAmendment::Allow,
            "echo".to_string(),
            vec!["first".to_string()],
            None,
        )
        .await
    });
    committed.acquire().await.unwrap().forget();
    first.abort();
    let second_server = cfg.clone();
    let second = tokio::spawn(async move {
        amend_session_exact_rule(
            &second_server,
            token,
            SessionAmendment::Deny,
            "echo".to_string(),
            vec!["second".to_string()],
            None,
        )
        .await
    });
    tokio::task::yield_now().await;
    assert!(
        !second.is_finished(),
        "a successor amendment overtook detached durable publication"
    );
    release.add_permits(1);
    assert!(second.await.unwrap().unwrap());

    let live = cfg.state.sessions.read().await;
    assert!(live
        .check(token, "echo", &["first".to_string()], None)
        .is_some_and(|(decision, _)| decision == crate::session::SessionDecision::Allow));
    assert!(live
        .check(token, "echo", &["second".to_string()], None)
        .is_some_and(|(decision, _)| decision == crate::session::SessionDecision::Deny));
    drop(live);
    let durable = store.load_registry().await.unwrap();
    assert!(durable
        .check(token, "echo", &["first".to_string()], None)
        .is_some_and(|(decision, _)| decision == crate::session::SessionDecision::Allow));
    assert!(durable
        .check(token, "echo", &["second".to_string()], None)
        .is_some_and(|(decision, _)| decision == crate::session::SessionDecision::Deny));
}

// Synthetic test-fixture credential shapes (never real secrets): a
// kubernetes-style service-account bearer JWT and a --password= flag.
const FIXTURE_BEARER_JWT: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6IlN5bnRoZXRpYyJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50In0.SyntheticSignature123";
const FIXTURE_PASSWORD_FLAG: &str = "--password=SyntheticHunter2Value";

#[test]
fn session_auto_amend_refuses_credential_shaped_argv() {
    // A session exact rule persists argv verbatim; credential-shaped material
    // (bearer tokens, --password= flags, URL userinfo) must refuse amendment
    // on both the allow and the deny side.
    assert!(allow_session_auto_amend_candidate(
        "kubectl",
        &[format!("--token={FIXTURE_BEARER_JWT}"), "get".into()],
        Some(1)
    )
    .is_err());
    assert!(allow_session_auto_amend_candidate(
        "mysql",
        &["-u".into(), "root".into(), FIXTURE_PASSWORD_FLAG.into()],
        Some(1)
    )
    .is_err());
    assert!(deny_session_auto_amend_candidate(
        "psql",
        &["postgres://app:SyntheticDbPass1@db.internal/prod".into()],
        Some(9)
    )
    .is_err());
    // A credential-free command of the same shape still qualifies.
    assert!(
        allow_session_auto_amend_candidate("kubectl", &["get".into(), "pods".into()], Some(1))
            .is_ok()
    );
}

#[tokio::test]
async fn session_inspection_surfaces_redact_credentials_in_text_and_json() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    let daemon = CallerIdentity::UnixAdmin { uid: 777 };
    let token = "inspection-redaction-token".to_string();

    // Install rows the way a pre-sanitization daemon would have persisted
    // them: raw credential material in the grant prompt, a learned exact
    // rule, and recorded argv. from_parts loads state verbatim, so this
    // exercises the display boundary rather than storage-time sanitization.
    let mut grants = HashMap::new();
    grants.insert(
        token.clone(),
        crate::session::SessionGrant {
            allow: Vec::new(),
            deny: Vec::new(),
            allow_exact: vec![SessionExactRule::new(
                "kubectl",
                vec![format!("--token={FIXTURE_BEARER_JWT}"), "get".into()],
            )],
            deny_exact: Vec::new(),
            activated_verbs: Vec::new(),
            override_markers: Vec::new(),
            scope: Default::default(),
            expires_at: None,
            granted_at: 1,
            prompt_append: Some(format!("session context {FIXTURE_PASSWORD_FLAG}")),
            generated_notes: Vec::new(),
            static_only: false,
            auto_amend: false,
            owner: crate::session::SessionOwner::Principal(
                guard::principal::PrincipalKey::from_uid(1000),
            ),
        },
    );
    let registry = crate::session::SessionRegistry::from_parts(
        grants,
        Vec::new(),
        vec![(
            token.clone(),
            SessionInteraction {
                at_unix: guard::env::now_unix(),
                command: format!("kubectl --token={FIXTURE_BEARER_JWT} get pods"),
                allowed: true,
                source: SessionDecisionSource::Llm,
                reason: format!("allowed despite {FIXTURE_PASSWORD_FLAG}"),
                risk: Some(1),
                exec_status: SessionExecStatus::Completed,
                exit_code: Some(0),
                exposed_secret_refs: Vec::new(),
                decision_trace: None,
            },
        )],
        crate::session::DEFAULT_HISTORY_RETENTION_SECS,
    );
    *cfg.state.sessions.write().await = registry;

    let show = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::SessionShow {
            token: token.clone(),
            limit: Some(20),
            caller_token: None,
        },
    )
    .await;
    let show_json = serde_json::to_string(&show).unwrap();
    assert!(
        !show_json.contains("SyntheticSignature123"),
        "session show leaked the bearer token: {show_json}"
    );
    assert!(
        !show_json.contains("SyntheticHunter2Value"),
        "session show leaked the password: {show_json}"
    );
    assert!(
        show_json.contains("[REDACTED]"),
        "session show must keep the redaction marker: {show_json}"
    );
    let AdminResponse::SessionShow { report } = show else {
        panic!("expected session show");
    };
    let active = report.active.expect("active grant");
    assert!(
        active.allow_exact[0].args[0].contains("[REDACTED]"),
        "exact rule argv must be redacted even outside JSON serialization"
    );
    assert!(
        report.recent[0].command.contains("kubectl get")
            || report.recent[0].command.contains("kubectl")
    );

    let status = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::SessionStatus {
            token: token.clone(),
            caller_token: None,
        },
    )
    .await;
    let status_json = serde_json::to_string(&status).unwrap();
    assert!(
        !status_json.contains("SyntheticSignature123"),
        "{status_json}"
    );
    assert!(
        !status_json.contains("SyntheticHunter2Value"),
        "{status_json}"
    );
    assert!(status_json.contains("[REDACTED]"), "{status_json}");

    let list = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::SessionList {
            include_history: true,
            since_unix: None,
            visible_token: None,
        },
    )
    .await;
    let list_json = serde_json::to_string(&list).unwrap();
    assert!(!list_json.contains("SyntheticSignature123"), "{list_json}");
    assert!(!list_json.contains("SyntheticHunter2Value"), "{list_json}");
    assert!(list_json.contains("[REDACTED]"), "{list_json}");
}

#[test]
fn session_source_reports_cache_separately_from_static_policy() {
    assert_eq!(
        session_source_from_eval(guard::evaluate::EvalSource::Cache),
        SessionDecisionSource::Cache
    );
    assert_eq!(
        session_source_from_eval(guard::evaluate::EvalSource::StaticPolicy),
        SessionDecisionSource::StaticPolicy
    );
}

#[test]
fn tcp_admin_token_validation_is_separate_from_exec_token() {
    let (mut cfg, _) = make_test_config();
    cfg.config.auth_token = Some("exec-token".into());
    cfg.config.admin_token = Some("admin-token".into());

    assert!(cfg.validate_token(Some("exec-token")).is_ok());
    assert!(cfg.validate_admin_token(Some("admin-token")).is_ok());
    assert!(cfg.validate_admin_token(Some("exec-token")).is_err());
    assert!(cfg
        .validate_admin(&CallerIdentity::TcpAdmin {
            token: "admin-token".into(),
        })
        .is_ok());
    assert!(cfg
        .validate_admin(&CallerIdentity::Tcp {
            token: "exec-token".into(),
        })
        .is_err());

    cfg.config.daemon_principal = PrincipalKey::from_raw("exec-token");
    assert!(
        cfg.validate_admin(&CallerIdentity::Tcp {
            token: "exec-token".into(),
        })
        .is_err(),
        "an ordinary TCP bearer must not become operator authority by colliding with the daemon principal"
    );
}

#[cfg(unix)]
#[test]
fn unix_operator_denial_does_not_name_windows_authority() {
    let (cfg, _) = make_test_config();
    let error = cfg
        .validate_admin(&CallerIdentity::Unix { uid: 20_002 })
        .expect_err("ordinary Unix caller must lack operator authority")
        .to_string();
    assert_eq!(error, "admin RPC refused: caller lacks operator authority");
    assert!(!error.contains("Windows"));
}

#[cfg(windows)]
#[test]
fn authenticated_windows_system_is_an_operator_without_broadening_other_callers() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_principal = PrincipalKey::from_sid("S-1-5-80-12345");
    cfg.config.allow_windows_system_operator = true;

    assert!(cfg
        .validate_admin(&CallerIdentity::Windows {
            sid: "S-1-5-18".into(),
        })
        .is_ok());
    assert!(cfg
        .validate_admin(&CallerIdentity::Windows {
            sid: "S-1-5-19".into(),
        })
        .is_err());
    assert!(cfg
        .validate_admin(&CallerIdentity::Unix { uid: 0 })
        .is_err());
    assert!(cfg
        .validate_admin(&CallerIdentity::Tcp {
            token: "S-1-5-18".into(),
        })
        .is_err());
}

#[tokio::test]
async fn session_list_omits_foreign_sessions() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);

    let daemon = CallerIdentity::UnixAdmin { uid: 777 };
    let user = CallerIdentity::Unix { uid: 20_002 };
    let token = format!("session-{}", std::process::id());

    let grant = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::SessionGrant {
            token: token.clone(),
            allow: vec!["mkdir /tmp/work/*".into()],
            deny: Vec::new(),
            activated_verbs: Vec::new(),
            override_markers: Vec::new(),
            ttl_secs: None,
            prompt_append: Some("operator-only prompt".into()),
            prose: None,
            saved_grant: None,
            profile: None,
            evaluation_mode: None,
            static_only: false,
            auto_amend: false,
            owner: None,
        },
    )
    .await;
    assert!(matches!(grant, AdminResponse::Ok));

    let listed = handle_admin_request_for_test(
        &cfg,
        &user,
        AdminRequest::SessionList {
            include_history: false,
            since_unix: None,
            visible_token: None,
        },
    )
    .await;
    match listed {
        AdminResponse::SessionList { grants, history } => {
            assert!(grants.is_empty());
            assert!(history.is_empty());
        }
        other => panic!("unexpected {:?}", other),
    }
}

#[tokio::test]
async fn session_list_shows_current_session_details_without_raw_token_for_user() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);

    let daemon = CallerIdentity::UnixAdmin { uid: 777 };
    let user = CallerIdentity::Unix { uid: 20_002 };
    let token = format!("session-visible-{}", std::process::id());

    let grant = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::SessionGrant {
            token: token.clone(),
            allow: vec!["mkdir /tmp/work/*".into()],
            deny: Vec::new(),
            activated_verbs: Vec::new(),
            override_markers: Vec::new(),
            ttl_secs: None,
            prompt_append: Some("operator prompt".into()),
            prose: Some("kubernetes access for namespace nextcloud".into()),
            saved_grant: None,
            profile: None,
            evaluation_mode: None,
            static_only: false,
            auto_amend: false,
            owner: Some("20002".to_string()),
        },
    )
    .await;
    assert!(matches!(grant, AdminResponse::Ok));

    let listed = handle_admin_request_for_test(
        &cfg,
        &user,
        AdminRequest::SessionList {
            include_history: false,
            since_unix: None,
            visible_token: Some(token.clone()),
        },
    )
    .await;
    match listed {
        AdminResponse::SessionList { grants, .. } => {
            let visible = grants
                .iter()
                .find(|grant| grant.token == "(current)")
                .expect("current session grant visible to token holder");
            assert!(
                !visible.allow.is_empty(),
                "current token holder should see grant rules"
            );
            assert_eq!(
                    visible.prompt_append.as_deref(),
                    Some("Session grant prose:\nkubernetes access for namespace nextcloud\n\nAdditional session context:\noperator prompt")
                );
            assert!(visible.generated_notes.is_empty());
            assert!(
                grants.iter().all(|grant| grant.token != token),
                "non-admin list output must not echo raw bearer tokens"
            );
        }
        other => panic!("unexpected {:?}", other),
    }
}

#[tokio::test]
async fn non_owner_session_list_omits_active_and_historical_rows() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    let private_scope = IssuedGrantScope {
        label: Some("private-label".to_string()),
        saved_grant: Some("private-saved-grant".to_string()),
        saved_revision: 9,
        secret_names: vec!["private/credential".to_string()],
        access_managed: true,
        access_grants: vec![AccessUseGrant {
            request: "gr-private-request".to_string(),
            verbs: vec!["private-verb".to_string()],
            use_limit: Some(3),
            remaining_uses: Some(2),
            pending: false,
        }],
        ..IssuedGrantScope::default()
    };
    let make_grant = || SessionGrant {
        allow: Vec::new(),
        deny: Vec::new(),
        allow_exact: Vec::new(),
        deny_exact: Vec::new(),
        activated_verbs: vec!["private-verb".to_string()],
        override_markers: Vec::new(),
        scope: private_scope.clone(),
        expires_at: None,
        prompt_append: Some("private prompt".to_string()),
        generated_notes: Vec::new(),
        static_only: true,
        auto_amend: false,
        granted_at: 0,
        owner: crate::session::SessionOwner::Principal(PrincipalKey::from_uid(1001)),
    };
    {
        let mut sessions = cfg.state.sessions.write().await;
        assert!(sessions.grant("private-active".to_string(), make_grant()));
        assert!(sessions.grant("private-history".to_string(), make_grant()));
        assert!(sessions.revoke("private-history"));
    }

    let AdminResponse::SessionList { grants, history } = handle_admin_request_for_test(
        &cfg,
        &CallerIdentity::Unix { uid: 2002 },
        AdminRequest::SessionList {
            include_history: true,
            since_unix: None,
            visible_token: None,
        },
    )
    .await
    else {
        panic!("expected session list")
    };
    assert!(grants.is_empty());
    assert!(history.is_empty());
    let rendered = serde_json::to_string(&(grants, history)).unwrap();
    for private in [
        "private-label",
        "private-saved-grant",
        "private/credential",
        "private-verb",
        "gr-private-request",
    ] {
        assert!(!rendered.contains(private), "leaked {private}: {rendered}");
    }
}

#[tokio::test]
async fn archived_session_token_cannot_be_reissued_to_another_principal() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    let daemon = CallerIdentity::UnixAdmin { uid: 777 };
    let token = "archived-bearer".to_string();
    let grant_for = |owner: &str| AdminRequest::SessionGrant {
        token: token.clone(),
        allow: vec!["fixture-command".to_string()],
        deny: Vec::new(),
        activated_verbs: Vec::new(),
        override_markers: Vec::new(),
        ttl_secs: None,
        prompt_append: Some(format!("private owner {owner}")),
        prose: None,
        saved_grant: None,
        profile: None,
        evaluation_mode: None,
        static_only: true,
        auto_amend: false,
        owner: Some(owner.to_string()),
    };
    assert!(matches!(
        handle_admin_request_for_test(&cfg, &daemon, grant_for("1001")).await,
        AdminResponse::Ok
    ));
    assert!(matches!(
        handle_admin_request_for_test(
            &cfg,
            &daemon,
            AdminRequest::SessionRevoke {
                token: token.clone()
            }
        )
        .await,
        AdminResponse::Ok
    ));
    assert!(matches!(
        handle_admin_request_for_test(&cfg, &daemon, grant_for("2002")).await,
        AdminResponse::Error { message }
            if message.contains("already issued")
    ));
    assert!(matches!(
        handle_admin_request_for_test(
            &cfg,
            &CallerIdentity::Unix { uid: 2002 },
            AdminRequest::SessionShow {
                token,
                limit: Some(1),
                caller_token: None,
            }
        )
        .await,
        AdminResponse::Error { .. }
    ));
}

#[tokio::test]
async fn session_show_reports_recent_stats() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);

    let daemon = CallerIdentity::UnixAdmin { uid: 777 };
    let token = format!("session-show-{}", std::process::id());

    let grant = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::SessionGrant {
            token: token.clone(),
            allow: vec!["echo*".into()],
            deny: vec!["rm*".into()],
            activated_verbs: Vec::new(),
            override_markers: Vec::new(),
            ttl_secs: None,
            prompt_append: Some("operator context".into()),
            prose: None,
            saved_grant: None,
            profile: None,
            evaluation_mode: None,
            static_only: false,
            auto_amend: false,
            owner: None,
        },
    )
    .await;
    assert!(matches!(grant, AdminResponse::Ok));

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);

    {
        let mut reg = cfg.state.sessions.write().await;
        reg.record_interaction(
            &token,
            SessionInteraction {
                at_unix: now.saturating_sub(1),
                command: "echo hi".into(),
                allowed: true,
                source: SessionDecisionSource::Llm,
                reason: "safe".into(),
                risk: Some(1),
                exec_status: SessionExecStatus::Completed,
                exit_code: Some(0),
                exposed_secret_refs: vec!["service/token".into()],
                decision_trace: None,
            },
        );
        reg.record_interaction(
            &token,
            SessionInteraction {
                at_unix: now,
                command: "rm -rf /tmp/x".into(),
                allowed: false,
                source: SessionDecisionSource::SessionDeny,
                reason: "session deny pattern: rm*".into(),
                risk: None,
                exec_status: SessionExecStatus::NotAttempted,
                exit_code: None,
                exposed_secret_refs: Vec::new(),
                decision_trace: None,
            },
        );
    }

    let show = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::SessionShow {
            token: token.clone(),
            limit: Some(1),
            caller_token: None,
        },
    )
    .await;
    match show {
        AdminResponse::SessionShow { report } => {
            assert_eq!(report.stats.total, 2);
            assert_eq!(report.stats.allowed, 1);
            assert_eq!(report.stats.denied, 1);
            assert_eq!(report.stats.risk_histogram[1], 1);
            assert_eq!(report.recent.len(), 1);
            assert_eq!(report.recent[0].command, "rm -rf /tmp/x");
            assert_eq!(
                report.active.and_then(|grant| grant.prompt_append),
                Some("operator context".into())
            );
        }
        other => panic!("unexpected {:?}", other),
    }
}

#[tokio::test]
async fn session_show_self_token_sees_full_grant() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);

    let daemon = CallerIdentity::UnixAdmin { uid: 777 };
    let user = CallerIdentity::Unix { uid: 20_003 };
    let token = format!("session-self-{}", std::process::id());

    let grant = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::SessionGrant {
            token: token.clone(),
            allow: vec!["kubectl get pods*".into()],
            deny: vec!["rm*".into()],
            activated_verbs: Vec::new(),
            override_markers: Vec::new(),
            ttl_secs: Some(3600),
            prompt_append: Some("cert rotation context".into()),
            prose: None,
            saved_grant: None,
            profile: None,
            evaluation_mode: None,
            static_only: false,
            auto_amend: false,
            owner: Some("20003".to_string()),
        },
    )
    .await;
    assert!(matches!(grant, AdminResponse::Ok));

    // The owning principal inspects its own session.
    let show = handle_admin_request_for_test(
        &cfg,
        &user,
        AdminRequest::SessionShow {
            token: token.clone(),
            limit: Some(20),
            caller_token: Some(token.clone()),
        },
    )
    .await;
    match show {
        AdminResponse::SessionShow { report } => {
            let active = report.active.expect("holder sees its own active grant");
            assert_eq!(active.allow, vec!["kubectl get pods*".to_string()]);
            assert_eq!(active.deny, vec!["rm*".to_string()]);
            assert_eq!(
                active.prompt_append.as_deref(),
                Some("cert rotation context")
            );
            assert!(active.expires_at.is_some(), "remaining time is visible");
            assert_eq!(
                active.token, "(current)",
                "self view must not echo the raw bearer token"
            );
        }
        other => panic!("unexpected {:?}", other),
    }
}

#[tokio::test]
async fn session_status_self_view_redacts_bearer_and_keeps_decision_trace() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    let token = "status-bearer-must-not-be-returned".to_string();
    cfg.state
        .sessions
        .write()
        .await
        .grant(token.clone(), granted_session(Vec::new(), Vec::new()));
    cfg.state.sessions.write().await.record_interaction(
        &token,
        SessionInteraction {
            at_unix: guard::env::now_unix(),
            command: "uptime".to_string(),
            allowed: true,
            source: SessionDecisionSource::StaticPolicy,
            reason: "read-only check".to_string(),
            risk: Some(0),
            exec_status: SessionExecStatus::Completed,
            exit_code: Some(0),
            exposed_secret_refs: Vec::new(),
            decision_trace: Some(guard::gating::DecisionTrace::source("static_policy")),
        },
    );

    let response = handle_admin_request_for_test(
        &cfg,
        &CallerIdentity::Unix { uid: 1000 },
        AdminRequest::SessionStatus {
            token: token.clone(),
            caller_token: Some(token.clone()),
        },
    )
    .await;
    let AdminResponse::SessionStatus { report, .. } = &response else {
        panic!("expected session status, got {response:?}");
    };
    assert_eq!(report.active.as_ref().unwrap().token, "(current)");
    assert_eq!(
        report.recent[0]
            .decision_trace
            .as_ref()
            .map(|trace| trace.decision_source.as_str()),
        Some("static_policy")
    );
    let json = serde_json::to_string(&response).unwrap();
    assert!(!json.contains(&token));
    assert!(json.contains("decision_trace"));
}

#[tokio::test]
async fn session_show_other_token_denied_for_non_admin() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);

    let daemon = CallerIdentity::UnixAdmin { uid: 777 };
    let attacker = CallerIdentity::Unix { uid: 20_004 };
    let token_a = format!("session-a-{}", std::process::id());
    let token_b = format!("session-b-{}", std::process::id());

    for token in [&token_a, &token_b] {
        let grant = handle_admin_request_for_test(
            &cfg,
            &daemon,
            AdminRequest::SessionGrant {
                token: token.clone(),
                allow: vec!["echo*".into()],
                deny: Vec::new(),
                activated_verbs: Vec::new(),
                override_markers: Vec::new(),
                ttl_secs: None,
                prompt_append: Some("secret operator context".into()),
                prose: None,
                saved_grant: None,
                profile: None,
                evaluation_mode: None,
                static_only: false,
                auto_amend: false,
                owner: Some("778".to_string()),
            },
        )
        .await;
        assert!(matches!(grant, AdminResponse::Ok));
    }

    // Holder of A tries to inspect B's grant by naming B as the target.
    let show = handle_admin_request_for_test(
        &cfg,
        &attacker,
        AdminRequest::SessionShow {
            token: token_b.clone(),
            limit: Some(20),
            caller_token: Some(token_a.clone()),
        },
    )
    .await;
    match show {
        AdminResponse::Error { message } => {
            assert!(
                message.contains("session principal mismatch"),
                "expected a principal-mismatch denial, got: {message}"
            );
            assert!(
                !message.contains("secret operator context"),
                "denial must not leak the other grant's contents"
            );
        }
        other => panic!("expected denial, got {:?}", other),
    }
}

#[tokio::test]
async fn session_new_from_profile_mints_expected_grant() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.state.saved_grants = std::sync::Arc::new(tokio::sync::RwLock::new(
        SavedGrantCatalog::from_yaml(
            "profiles:\n  - name: cert-manager-rotation\n    ttl_secs: 1800\n    allow:\n      - \"kubectl get certificate *\"\n    deny:\n      - \"kubectl delete namespace *\"\n    prompt_append: \"rotating cert-manager certificates\"\n",
        )
        .expect("valid saved grant catalog"),
    ));

    let daemon = CallerIdentity::UnixAdmin { uid: 777 };
    let token = format!("session-profile-{}", std::process::id());

    // Profile-only: no explicit allow/deny/ttl/prompt on the request.
    let resp = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::SessionGrant {
            token: token.clone(),
            allow: Vec::new(),
            deny: Vec::new(),
            activated_verbs: Vec::new(),
            override_markers: Vec::new(),
            ttl_secs: None,
            prompt_append: None,
            prose: None,
            saved_grant: Some("cert-manager-rotation".into()),
            profile: None,
            evaluation_mode: None,
            static_only: false,
            auto_amend: false,
            owner: None,
        },
    )
    .await;
    assert!(matches!(resp, AdminResponse::Ok));

    let reg = cfg.state.sessions.read().await;
    let summary = reg
        .list()
        .into_iter()
        .find(|g| g.token == token)
        .expect("profile grant installed");
    assert!(summary.allow.is_empty());
    assert!(summary.deny.is_empty());
    assert_eq!(summary.activated_verbs.len(), 2);
    assert!(summary.expires_at.is_some(), "profile ttl applied");
    assert_eq!(
        summary.prompt_append.as_deref(),
        Some("rotating cert-manager certificates")
    );
    assert!(
        summary
            .generated_notes
            .iter()
            .any(|note| note.contains("cert-manager-rotation")),
        "grant records which profile minted it"
    );
}

#[tokio::test]
async fn session_new_unknown_profile_fails_clearly() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    // The profile catalog is left empty.

    let daemon = CallerIdentity::UnixAdmin { uid: 777 };
    let token = format!("session-badprofile-{}", std::process::id());
    let resp = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::SessionGrant {
            token: token.clone(),
            allow: Vec::new(),
            deny: Vec::new(),
            activated_verbs: Vec::new(),
            override_markers: Vec::new(),
            ttl_secs: None,
            prompt_append: None,
            prose: None,
            saved_grant: Some("does-not-exist".into()),
            profile: None,
            evaluation_mode: None,
            static_only: false,
            auto_amend: false,
            owner: None,
        },
    )
    .await;
    match resp {
        AdminResponse::Error { message } => {
            assert!(
                message.contains("unknown saved grant") && message.contains("does-not-exist"),
                "expected a clear unknown-saved-grant error, got: {message}"
            );
        }
        other => panic!("expected error, got {:?}", other),
    }
    // A failed lookup must not install an (empty, unrestricted) grant.
    let reg = cfg.state.sessions.read().await;
    assert!(
        reg.list().into_iter().all(|g| g.token != token),
        "no grant should be installed for an unknown profile"
    );
}

#[tokio::test]
async fn profile_grant_still_deny_short_circuits_and_falls_through() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.state.saved_grants = std::sync::Arc::new(tokio::sync::RwLock::new(
        SavedGrantCatalog::from_yaml(
            "profiles:\n  - name: scoped\n    allow:\n      - \"kubectl get *\"\n    deny:\n      - \"kubectl delete *\"\n",
        )
        .expect("valid saved grant catalog"),
    ));

    let daemon = CallerIdentity::UnixAdmin { uid: 777 };
    let token = format!("session-profcheck-{}", std::process::id());
    let resp = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::SessionGrant {
            token: token.clone(),
            allow: Vec::new(),
            deny: Vec::new(),
            activated_verbs: Vec::new(),
            override_markers: Vec::new(),
            ttl_secs: None,
            prompt_append: None,
            prose: None,
            saved_grant: Some("scoped".into()),
            profile: None,
            evaluation_mode: None,
            static_only: false,
            auto_amend: false,
            owner: None,
        },
    )
    .await;
    assert!(matches!(resp, AdminResponse::Ok));

    let reg = cfg.state.sessions.read().await;
    let summary = reg
        .list()
        .into_iter()
        .find(|grant| grant.token == token)
        .expect("saved grant issued");
    assert_eq!(summary.activated_verbs.len(), 2);
    assert!(summary.allow.is_empty() && summary.deny.is_empty());
}

#[tokio::test]
async fn grant_requests_use_the_issued_ceiling_and_redact_session_tokens() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.state.saved_grants = Arc::new(RwLock::new(
        SavedGrantCatalog::from_yaml(
            "grants:\n  - name: bounded\n    prompt_append: bounded task\n    ttl_secs: 300\n    auto_approve_requests: true\n  - name: other\n    prompt_append: other task\n    ttl_secs: 3600\n    auto_approve_requests: true\n",
        )
        .expect("saved grants"),
    ));
    let daemon = CallerIdentity::UnixAdmin { uid: 777 };
    let worker = CallerIdentity::Unix { uid: 778 };
    let token = "bounded-session".to_string();
    assert!(matches!(
        handle_admin_request_for_test(
            &cfg,
            &daemon,
            AdminRequest::SessionGrant {
                token: token.clone(),
                allow: Vec::new(),
                deny: Vec::new(),
                activated_verbs: Vec::new(),
                override_markers: Vec::new(),
                ttl_secs: None,
                prompt_append: None,
                prose: None,
                saved_grant: Some("bounded".to_string()),
                profile: None,
                evaluation_mode: None,
                static_only: false,
                auto_amend: false,
                owner: Some("778".to_string()),
            },
        )
        .await,
        AdminResponse::Ok
    ));

    let mismatched = handle_admin_request_for_test(
        &cfg,
        &worker,
        AdminRequest::GrantRequestSubmit {
            session_token: token.clone(),
            caller_token: Some(token.clone()),
            saved_grant: Some("other".to_string()),
            prompt: "extend work".to_string(),
            delta: crate::grant_profile::GrantRequestDelta {
                ttl_secs: Some(120),
                ..Default::default()
            },
        },
    )
    .await;
    assert!(matches!(
        mismatched,
        AdminResponse::Error { message } if message.contains("does not match")
    ));

    let approved = handle_admin_request_for_test(
        &cfg,
        &worker,
        AdminRequest::GrantRequestSubmit {
            session_token: token.clone(),
            caller_token: Some(token.clone()),
            saved_grant: None,
            prompt: "extend work".to_string(),
            delta: crate::grant_profile::GrantRequestDelta {
                ttl_secs: Some(120),
                ..Default::default()
            },
        },
    )
    .await;
    assert!(matches!(
        approved,
        AdminResponse::GrantRequest { request }
            if request.status == crate::grant_profile::GrantRequestStatus::Approved
                && request.session_token.starts_with("sha256:")
    ));
    cfg.state.sessions.write().await.grant(
        "other-live-session".to_string(),
        granted_session(Vec::new(), Vec::new()),
    );

    let unscoped = handle_admin_request_for_test(
        &cfg,
        &worker,
        AdminRequest::GrantRequestList {
            session_token: None,
            caller_token: None,
        },
    )
    .await;
    assert!(matches!(unscoped, AdminResponse::Error { .. }));
    let scoped = handle_admin_request_for_test(
        &cfg,
        &worker,
        AdminRequest::GrantRequestList {
            session_token: Some(token.clone()),
            caller_token: Some(token.clone()),
        },
    )
    .await;
    assert!(matches!(
        scoped,
        AdminResponse::GrantRequests { items }
            if items.len() == 1 && items[0].session_token.starts_with("sha256:")
    ));

    let replayed_caller_bearer = handle_admin_request_for_test(
        &cfg,
        &worker,
        AdminRequest::GrantRequestList {
            session_token: Some(token),
            caller_token: Some("other-live-session".to_string()),
        },
    )
    .await;
    assert!(matches!(
        replayed_caller_bearer,
        AdminResponse::GrantRequests { items } if items.len() == 1
    ));

    let admin = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::GrantRequestList {
            session_token: None,
            caller_token: None,
        },
    )
    .await;
    assert!(matches!(
        admin,
        AdminResponse::GrantRequests { items } if items.len() == 1
    ));
}

#[tokio::test]
async fn grant_request_submit_enforces_suspension_quota_and_aggregate_size() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.config.behavior_limits.max_denials = Some(1);
    let worker = CallerIdentity::Unix { uid: 778 };
    for token in ["suspended-request", "quota-request", "large-request"] {
        cfg.state.sessions.write().await.grant(
            token.to_string(),
            granted_session_owned(778, Vec::new(), Vec::new()),
        );
    }
    cfg.state.sessions.write().await.record_interaction(
        "suspended-request",
        SessionInteraction {
            command: "denied".to_string(),
            allowed: false,
            source: SessionDecisionSource::Llm,
            reason: "denied".to_string(),
            risk: Some(5),
            exec_status: SessionExecStatus::NotAttempted,
            exit_code: None,
            at_unix: guard::env::now_unix(),
            exposed_secret_refs: Vec::new(),
            decision_trace: None,
        },
    );
    let submit =
        |token: &str, prompt: String, delta_prompt: String| AdminRequest::GrantRequestSubmit {
            session_token: token.to_string(),
            caller_token: Some(token.to_string()),
            saved_grant: None,
            prompt,
            delta: crate::grant_profile::GrantRequestDelta {
                prompt_append: Some(delta_prompt),
                ..Default::default()
            },
        };
    assert!(matches!(
        handle_admin_request_for_test(
            &cfg,
            &worker,
            submit("suspended-request", "request".to_string(), "scope".to_string()),
        )
        .await,
        AdminResponse::Error { message } if message.contains("suspended")
    ));

    for index in 0..crate::server::admin::MAX_PENDING_GRANT_REQUESTS_PER_SESSION {
        let request = crate::grant_profile::GrantRequest::new(
            "quota-request".to_string(),
            None,
            crate::grant_profile::GrantRequestDelta {
                prompt_append: Some(format!("scope-{index}")),
                ..Default::default()
            },
            format!("request-{index}"),
        )
        .unwrap();
        cfg.state
            .grant_requests
            .write()
            .await
            .insert(request.handle.clone(), request);
    }
    assert!(matches!(
        handle_admin_request_for_test(
            &cfg,
            &worker,
            submit("quota-request", "one more".to_string(), "scope".to_string()),
        )
        .await,
        AdminResponse::Error { message } if message.contains("per session")
    ));

    let half = "x".repeat(crate::server::admin::MAX_GRANT_REQUEST_PAYLOAD_BYTES / 2 + 1);
    assert!(matches!(
        handle_admin_request_for_test(
            &cfg,
            &worker,
            submit("large-request", half.clone(), half),
        )
        .await,
        AdminResponse::Error { message } if message.contains("byte limit")
    ));
}

#[tokio::test]
async fn auto_and_operator_approval_fail_without_partial_session_authority() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.state.saved_grants = Arc::new(RwLock::new(
        SavedGrantCatalog::from_yaml(
            "grants:\n  - name: automatic\n    ttl_secs: 300\n    prompt_append: automatic work\n    auto_approve_requests: true\n  - name: reviewed\n    ttl_secs: 300\n    prompt_append: reviewed work\n    auto_approve_requests: false\n",
        )
        .unwrap(),
    ));
    let tmp = tempfile::tempdir().unwrap();
    cfg.state.session_store = Some(
        SessionStore::open(tmp.path().join("state.db"), 3600)
            .await
            .unwrap(),
    );
    let daemon = CallerIdentity::UnixAdmin { uid: 777 };
    let worker = CallerIdentity::Unix { uid: 778 };
    for (token, saved_grant) in [
        ("automatic-approval", "automatic"),
        ("operator-approval", "reviewed"),
    ] {
        assert!(matches!(
            handle_admin_request_for_test(
                &cfg,
                &daemon,
                AdminRequest::SessionGrant {
                    token: token.to_string(),
                    allow: Vec::new(),
                    deny: Vec::new(),
                    activated_verbs: Vec::new(),
                    override_markers: Vec::new(),
                    ttl_secs: None,
                    prompt_append: None,
                    prose: None,
                    saved_grant: Some(saved_grant.to_string()),
                    profile: None,
                    evaluation_mode: None,
                    static_only: false,
                    auto_amend: false,
                    owner: Some("778".to_string()),
                },
            )
            .await,
            AdminResponse::Ok
        ));
    }
    let submit = |token: &str| AdminRequest::GrantRequestSubmit {
        session_token: token.to_string(),
        caller_token: Some(token.to_string()),
        saved_grant: None,
        prompt: "shorten bounded work".to_string(),
        delta: crate::grant_profile::GrantRequestDelta {
            ttl_secs: Some(120),
            ..Default::default()
        },
    };

    let auto_revision = cfg
        .state
        .sessions
        .read()
        .await
        .effective_revision_key("automatic-approval");
    cfg.state
        .session_store
        .as_ref()
        .unwrap()
        .fail_next_approval_for_test();
    assert!(matches!(
        handle_admin_request_for_test(&cfg, &worker, submit("automatic-approval")).await,
        AdminResponse::Error { message } if message.contains("approval transaction failure")
    ));
    assert_eq!(
        cfg.state
            .sessions
            .read()
            .await
            .effective_revision_key("automatic-approval"),
        auto_revision
    );

    let reviewed_revision = cfg
        .state
        .sessions
        .read()
        .await
        .effective_revision_key("operator-approval");
    let response = handle_admin_request_for_test(&cfg, &worker, submit("operator-approval")).await;
    let AdminResponse::GrantRequest { request } = response else {
        panic!("expected pending request")
    };
    cfg.state
        .session_store
        .as_ref()
        .unwrap()
        .fail_next_approval_for_test();
    assert!(matches!(
        handle_admin_request_for_test(
            &cfg,
            &daemon,
            AdminRequest::GrantRequestApprove {
                handle: request.handle.clone(),
            },
        )
        .await,
        AdminResponse::Error { message } if message.contains("approval transaction failure")
    ));
    assert_eq!(
        cfg.state
            .sessions
            .read()
            .await
            .effective_revision_key("operator-approval"),
        reviewed_revision
    );
    assert_eq!(
        cfg.state.grant_requests.read().await[&request.handle].status,
        crate::grant_profile::GrantRequestStatus::Pending
    );
}

#[tokio::test]
async fn terminal_grant_request_races_have_one_durable_authority_outcome() {
    for competing_status in [
        crate::grant_profile::GrantRequestStatus::Withdrawn,
        crate::grant_profile::GrantRequestStatus::Denied,
    ] {
        let (mut cfg, _) = make_test_config();
        cfg.config.daemon_uid = 777;
        cfg.config.daemon_principal = PrincipalKey::from_uid(777);
        cfg.state.saved_grants = Arc::new(RwLock::new(
            SavedGrantCatalog::from_yaml(
                "grants:\n  - name: reviewed\n    ttl_secs: 300\n    prompt_append: reviewed work\n    auto_approve_requests: false\n",
            )
            .unwrap(),
        ));
        let tmp = tempfile::tempdir().unwrap();
        cfg.state.session_store = Some(
            SessionStore::open(tmp.path().join("state.db"), 3600)
                .await
                .unwrap(),
        );
        let token = format!("terminal-race-{}", competing_status.as_str());
        let daemon = CallerIdentity::UnixAdmin { uid: 777 };
        let worker = CallerIdentity::Unix { uid: 778 };
        assert!(matches!(
            handle_admin_request_for_test(
                &cfg,
                &daemon,
                AdminRequest::SessionGrant {
                    token: token.clone(),
                    allow: Vec::new(),
                    deny: Vec::new(),
                    activated_verbs: Vec::new(),
                    override_markers: Vec::new(),
                    ttl_secs: None,
                    prompt_append: None,
                    prose: None,
                    saved_grant: Some("reviewed".to_string()),
                    profile: None,
                    evaluation_mode: None,
                    static_only: false,
                    auto_amend: false,
                    owner: Some("778".to_string()),
                },
            )
            .await,
            AdminResponse::Ok
        ));
        let issued_revision = cfg
            .state
            .sessions
            .read()
            .await
            .effective_revision_key(&token);
        let submitted = handle_admin_request_for_test(
            &cfg,
            &worker,
            AdminRequest::GrantRequestSubmit {
                session_token: token.clone(),
                caller_token: Some(token.clone()),
                saved_grant: None,
                prompt: "shorten bounded work".to_string(),
                delta: crate::grant_profile::GrantRequestDelta {
                    ttl_secs: Some(120),
                    ..Default::default()
                },
            },
        )
        .await;
        let AdminResponse::GrantRequest { request } = submitted else {
            panic!("expected pending request, got {submitted:?}");
        };
        let handle = request.handle;
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let approve_cfg = cfg.clone();
        let approve_handle = handle.clone();
        let approve_barrier = barrier.clone();
        let approve = tokio::spawn(async move {
            approve_barrier.wait().await;
            handle_admin_request_for_test(
                &approve_cfg,
                &CallerIdentity::UnixAdmin { uid: 777 },
                AdminRequest::GrantRequestApprove {
                    handle: approve_handle,
                },
            )
            .await
        });
        let competing_cfg = cfg.clone();
        let competing_handle = handle.clone();
        let competing_token = token.clone();
        let competing_barrier = barrier.clone();
        let competing = tokio::spawn(async move {
            competing_barrier.wait().await;
            let request = match competing_status {
                crate::grant_profile::GrantRequestStatus::Withdrawn => {
                    AdminRequest::GrantRequestWithdraw {
                        handle: competing_handle,
                        session_token: Some(competing_token),
                    }
                }
                crate::grant_profile::GrantRequestStatus::Denied => {
                    AdminRequest::GrantRequestDeny {
                        handle: competing_handle,
                        reason: "operator denied".to_string(),
                    }
                }
                _ => unreachable!(),
            };
            handle_admin_request_for_test(
                &competing_cfg,
                &CallerIdentity::UnixAdmin { uid: 777 },
                request,
            )
            .await
        });
        barrier.wait().await;
        let responses = [approve.await.unwrap(), competing.await.unwrap()];
        assert_eq!(
            responses
                .iter()
                .filter(|response| matches!(response, AdminResponse::GrantRequest { .. }))
                .count(),
            1,
            "exactly one terminal transition must win: {responses:?}"
        );
        assert_eq!(
            responses
                .iter()
                .filter(|response| matches!(response, AdminResponse::Error { .. }))
                .count(),
            1,
            "the losing transition must report a conflict: {responses:?}"
        );

        let store = cfg.state.session_store.as_ref().unwrap();
        let durable = store
            .load_grant_request(handle.clone())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            durable.status,
            crate::grant_profile::GrantRequestStatus::Approved
                | crate::grant_profile::GrantRequestStatus::Denied
                | crate::grant_profile::GrantRequestStatus::Withdrawn
        ));
        assert_eq!(
            cfg.state.grant_requests.read().await[&handle].status,
            durable.status
        );
        let live_revision = cfg
            .state
            .sessions
            .read()
            .await
            .effective_revision_key(&token);
        let durable_revision = store
            .load_registry()
            .await
            .unwrap()
            .effective_revision_key(&token);
        assert_eq!(live_revision, durable_revision);
        assert_eq!(
            live_revision != issued_revision,
            durable.status == crate::grant_profile::GrantRequestStatus::Approved,
            "session authority must change if and only if approval wins"
        );
    }
}

#[tokio::test]
async fn saved_grant_edit_uses_explicit_clear_and_tristate_operations() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    let daemon = CallerIdentity::UnixAdmin { uid: 777 };
    let source = SavedGrantCatalog::from_yaml(
        "grants:\n  - name: editable\n    description: original\n    activated_verbs: [inspect]\n    override_markers: [operator:inspect]\n    secret_names: [service/*]\n    ttl_secs: 300\n    prompt_append: original prompt\n    auto_approve_requests: true\n",
    )
    .unwrap();
    let grant = source.get("editable").unwrap().clone();
    assert!(matches!(
        handle_admin_request_for_test(&cfg, &daemon, AdminRequest::SavedGrantSave { grant }).await,
        AdminResponse::SavedGrant { .. }
    ));

    let edited = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::SavedGrantEdit {
            name: "editable".to_string(),
            description: Some("updated".to_string()),
            activated_verbs: Vec::new(),
            clear_verbs: true,
            override_markers: Vec::new(),
            clear_override_markers: true,
            secret_names: Vec::new(),
            clear_secrets: true,
            ceiling_verbs: Vec::new(),
            clear_ceiling_verbs: false,
            ceiling_secrets: Vec::new(),
            clear_ceiling_secrets: false,
            ceiling_ttl_secs: None,
            clear_ceiling_ttl: false,
            ceiling_modes: Vec::new(),
            clear_ceiling_modes: false,
            allow_prompt_append: None,
            ttl_secs: None,
            clear_ttl: true,
            prompt_append: None,
            evaluation_mode: Some(EvaluationMode::PolicyOnly),
            auto_approve_requests: Some(false),
        },
    )
    .await;
    let AdminResponse::SavedGrant { grant } = edited else {
        panic!("expected edited saved grant, got {edited:?}");
    };
    assert_eq!(grant.description, "updated");
    assert!(grant.activated_verbs.is_empty());
    assert!(grant.override_markers.is_empty());
    assert!(grant.secret_names.is_empty());
    assert_eq!(grant.ttl_secs, None);
    assert_eq!(grant.prompt_append.as_deref(), Some("original prompt"));
    assert_eq!(grant.evaluation_mode, EvaluationMode::PolicyOnly);
    assert!(!grant.auto_approve_requests);
    assert_eq!(grant.revision, 2);

    let cleared_prompt = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::SavedGrantEdit {
            name: "editable".to_string(),
            description: None,
            activated_verbs: vec!["inspect".to_string()],
            clear_verbs: false,
            override_markers: vec!["operator:inspect".to_string()],
            clear_override_markers: false,
            secret_names: Vec::new(),
            clear_secrets: false,
            ceiling_verbs: Vec::new(),
            clear_ceiling_verbs: false,
            ceiling_secrets: Vec::new(),
            clear_ceiling_secrets: false,
            ceiling_ttl_secs: None,
            clear_ceiling_ttl: false,
            ceiling_modes: Vec::new(),
            clear_ceiling_modes: false,
            allow_prompt_append: None,
            ttl_secs: None,
            clear_ttl: false,
            prompt_append: Some(String::new()),
            evaluation_mode: None,
            auto_approve_requests: None,
        },
    )
    .await;
    let AdminResponse::SavedGrant { grant } = cleared_prompt else {
        panic!("expected prompt-cleared grant, got {cleared_prompt:?}");
    };
    assert_eq!(grant.prompt_append, None);
    assert_eq!(grant.activated_verbs, vec!["inspect"]);
    assert!(!grant.auto_approve_requests);
    assert_eq!(grant.revision, 3);
}

#[tokio::test]
async fn saved_grant_regeneration_previews_exact_apply_and_enforces_both_cas_keys() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(run_verb_synthesis_llm(listener));
    let evaluator = |model: &str| {
        Evaluator::new(
            EvalConfig::default()
                .llm_api_key("test-key".to_string())
                .llm_api_url(url.clone())
                .llm_model(model.to_string())
                .llm_retries(0),
        )
        .unwrap()
    };
    let (mut cfg, _) = make_test_config();
    cfg.state.evaluator = Arc::new(evaluator("regime-a"));
    cfg.state.saved_grants = Arc::new(RwLock::new(
        SavedGrantCatalog::from_yaml(
            "grants:\n  - name: bounded\n    prompt_append: inspect one host\n",
        )
        .unwrap(),
    ));
    cfg.config.daemon_principal = PrincipalKey::from_uid(cfg.config.daemon_uid);
    let daemon = CallerIdentity::UnixAdmin {
        uid: cfg.config.daemon_uid,
    };
    let preview = || AdminRequest::SavedGrantRegenerate {
        name: "bounded".to_string(),
        prompt: None,
        proposal_id: None,
    };
    let apply = |proposal_id: String| AdminRequest::SavedGrantRegenerate {
        name: "bounded".to_string(),
        prompt: None,
        proposal_id: Some(proposal_id),
    };
    let edit_description = || AdminRequest::SavedGrantEdit {
        name: "bounded".to_string(),
        description: Some("changed after preview".to_string()),
        activated_verbs: Vec::new(),
        clear_verbs: false,
        override_markers: Vec::new(),
        clear_override_markers: false,
        secret_names: Vec::new(),
        clear_secrets: false,
        ceiling_verbs: Vec::new(),
        clear_ceiling_verbs: false,
        ceiling_secrets: Vec::new(),
        clear_ceiling_secrets: false,
        ceiling_ttl_secs: None,
        clear_ceiling_ttl: false,
        ceiling_modes: Vec::new(),
        clear_ceiling_modes: false,
        allow_prompt_append: None,
        ttl_secs: None,
        clear_ttl: false,
        prompt_append: None,
        evaluation_mode: None,
        auto_approve_requests: None,
    };

    let response = handle_admin_request_for_test(&cfg, &daemon, preview()).await;
    let AdminResponse::SavedGrantRegenerationProposal {
        proposal_id,
        candidate,
        source_revision,
        regime,
        ..
    } = response
    else {
        panic!("expected regeneration proposal, got {response:?}");
    };
    assert_eq!(source_revision, 1);
    assert_eq!(regime, cfg.state.evaluator.verb_promotion_stamp());
    assert!(cfg
        .state
        .saved_grants
        .read()
        .await
        .get("bounded")
        .unwrap()
        .generated_verbs
        .is_empty());
    let applied = handle_admin_request_for_test(&cfg, &daemon, apply(proposal_id)).await;
    let AdminResponse::SavedGrantRegenerated { grant, .. } = applied else {
        panic!("expected exact regeneration apply, got {applied:?}");
    };
    assert_eq!(grant.revision, 2);
    assert_eq!(
        serde_json::to_value(&grant.generated_verbs[0]).unwrap(),
        serde_json::to_value(&candidate).unwrap(),
        "apply must install the exact previewed candidate"
    );

    let revision_preview = handle_admin_request_for_test(&cfg, &daemon, preview()).await;
    let AdminResponse::SavedGrantRegenerationProposal {
        proposal_id: stale_revision,
        ..
    } = revision_preview
    else {
        panic!()
    };
    assert!(matches!(
        handle_admin_request_for_test(&cfg, &daemon, edit_description()).await,
        AdminResponse::SavedGrant { .. }
    ));
    assert!(matches!(
        handle_admin_request_for_test(&cfg, &daemon, apply(stale_revision)).await,
        AdminResponse::Error { message } if message.contains("revision changed")
    ));

    let regime_preview = handle_admin_request_for_test(&cfg, &daemon, preview()).await;
    let AdminResponse::SavedGrantRegenerationProposal {
        proposal_id: stale_regime,
        ..
    } = regime_preview
    else {
        panic!()
    };
    cfg.state.evaluator = Arc::new(evaluator("regime-b"));
    assert!(matches!(
        handle_admin_request_for_test(&cfg, &daemon, apply(stale_regime)).await,
        AdminResponse::Error { message } if message.contains("evaluator regime changed")
    ));
}

#[tokio::test]
async fn grant_request_show_and_withdraw_require_the_issuing_session() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    let daemon = CallerIdentity::UnixAdmin { uid: 777 };
    let worker = CallerIdentity::Unix { uid: 778 };
    cfg.state.sessions.write().await.grant(
        "owner-session".to_string(),
        granted_session_owned(778, Vec::new(), Vec::new()),
    );
    cfg.state.sessions.write().await.grant(
        "victim-session".to_string(),
        granted_session_owned(779, Vec::new(), Vec::new()),
    );
    let cross_session = handle_admin_request_for_test(
        &cfg,
        &worker,
        AdminRequest::GrantRequestSubmit {
            session_token: "victim-session".to_string(),
            caller_token: Some("owner-session".to_string()),
            saved_grant: None,
            prompt: "modify another session".to_string(),
            delta: crate::grant_profile::GrantRequestDelta {
                activated_verbs: vec!["inspect".to_string()],
                ..Default::default()
            },
        },
    )
    .await;
    assert!(matches!(
        cross_session,
        AdminResponse::Error { message } if message.contains("session principal mismatch")
    ));
    assert!(matches!(
        handle_admin_request_for_test(
            &cfg,
            &daemon,
            AdminRequest::GrantRequestSubmit {
                session_token: "victim-session".to_string(),
                caller_token: None,
                saved_grant: None,
                prompt: "operator amendment".to_string(),
                delta: crate::grant_profile::GrantRequestDelta {
                    activated_verbs: vec!["inspect".to_string()],
                    ..Default::default()
                },
            },
        )
        .await,
        AdminResponse::GrantRequest { .. }
    ));
    let submitted = handle_admin_request_for_test(
        &cfg,
        &worker,
        AdminRequest::GrantRequestSubmit {
            session_token: "owner-session".to_string(),
            caller_token: Some("owner-session".to_string()),
            saved_grant: None,
            prompt: "request one verb".to_string(),
            delta: crate::grant_profile::GrantRequestDelta {
                activated_verbs: vec!["inspect".to_string()],
                ..Default::default()
            },
        },
    )
    .await;
    let AdminResponse::GrantRequest { request } = submitted else {
        panic!("expected pending request, got {submitted:?}");
    };
    let handle = request.handle;

    for response in [
        handle_admin_request_for_test(
            &cfg,
            &worker,
            AdminRequest::GrantRequestShow {
                handle: handle.clone(),
                session_token: Some("other-session".to_string()),
            },
        )
        .await,
        handle_admin_request_for_test(
            &cfg,
            &worker,
            AdminRequest::GrantRequestWithdraw {
                handle: handle.clone(),
                session_token: Some("other-session".to_string()),
            },
        )
        .await,
    ] {
        assert!(
            matches!(response, AdminResponse::Error { message } if message.contains("unauthorized"))
        );
    }
    assert!(matches!(
        handle_admin_request_for_test(
            &cfg,
            &daemon,
            AdminRequest::GrantRequestShow {
                handle: handle.clone(),
                session_token: None,
            },
        )
        .await,
        AdminResponse::GrantRequest { .. }
    ));
    assert!(matches!(
        handle_admin_request_for_test(
            &cfg,
            &worker,
            AdminRequest::GrantRequestWithdraw {
                handle,
                session_token: Some("owner-session".to_string()),
            },
        )
        .await,
        AdminResponse::GrantRequest { request }
            if request.status == crate::grant_profile::GrantRequestStatus::Withdrawn
    ));
}

#[tokio::test]
async fn withdraw_and_prune_keep_memory_when_persistence_fails() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    let tmp = tempfile::tempdir().unwrap();
    cfg.state.session_store = Some(
        SessionStore::open(tmp.path().join("state.db"), 3600)
            .await
            .unwrap(),
    );
    let token = "persisted-request-owner".to_string();
    cfg.state.sessions.write().await.grant(
        token.clone(),
        granted_session_owned(778, Vec::new(), Vec::new()),
    );
    let mut request = crate::grant_profile::GrantRequest::new(
        token.clone(),
        None,
        crate::grant_profile::GrantRequestDelta {
            prompt_append: Some("bounded request".to_string()),
            ..Default::default()
        },
        "bounded request".to_string(),
    )
    .unwrap();
    let handle = request.handle.clone();
    cfg.state
        .grant_requests
        .write()
        .await
        .insert(handle.clone(), request.clone());
    let store = cfg.state.session_store.as_ref().unwrap();
    store.save_grant_request(request.clone()).await.unwrap();
    store.fail_next_write_for_test();

    let response = handle_admin_request_for_test(
        &cfg,
        &CallerIdentity::Unix { uid: 778 },
        AdminRequest::GrantRequestWithdraw {
            handle: handle.clone(),
            session_token: Some(token),
        },
    )
    .await;
    assert!(matches!(response, AdminResponse::Error { .. }));
    assert_eq!(
        cfg.state.grant_requests.read().await[&handle].status,
        crate::grant_profile::GrantRequestStatus::Pending
    );
    assert_eq!(
        store.load_grant_requests().await.unwrap()[0].status,
        crate::grant_profile::GrantRequestStatus::Pending
    );

    request.expires_unix = 1;
    cfg.state
        .grant_requests
        .write()
        .await
        .insert(handle.clone(), request.clone());
    store.save_grant_request(request).await.unwrap();
    store.fail_next_write_for_test();
    crate::server::admin::prune_grant_requests(&cfg).await;
    assert!(cfg.state.grant_requests.read().await.contains_key(&handle));
    assert!(store
        .load_grant_requests()
        .await
        .unwrap()
        .iter()
        .any(|request| request.handle == handle));
}

#[tokio::test]
async fn evaluate_batch_requires_owned_live_unsuspended_session_or_admin() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.config.behavior_limits.max_denials = Some(1);
    let daemon = CallerIdentity::UnixAdmin { uid: 777 };
    let worker = CallerIdentity::Unix { uid: 778 };
    // batch-owner belongs to the worker; batch-victim belongs to another
    // principal, so the worker may batch-evaluate the former but not the latter.
    for (token, owner_uid) in [("batch-owner", 778u32), ("batch-victim", 999u32)] {
        let mut grant = granted_session(Vec::new(), Vec::new());
        grant.owner = crate::session::SessionOwner::Principal(PrincipalKey::from_uid(owner_uid));
        cfg.state
            .sessions
            .write()
            .await
            .grant(token.to_string(), grant);
    }
    let commands = vec![guard::wire::BatchCommand {
        binary: "true".to_string(),
        args: Vec::new(),
        env: std::collections::HashMap::new(),
        secrets: std::collections::HashMap::new(),
        secret_files: std::collections::HashMap::new(),
        cwd: None,
    }];
    let evaluate = |session_token, caller_token| AdminRequest::EvaluateBatch {
        session_token,
        caller_token,
        commands: commands.clone(),
    };
    assert!(matches!(
        handle_admin_request_for_test(&cfg, &worker, evaluate(None, None)).await,
        AdminResponse::Error { message } if message.contains("caller-owned session")
    ));
    assert!(matches!(
        handle_admin_request_for_test(
            &cfg,
            &worker,
            evaluate(Some("batch-victim".to_string()), Some("batch-owner".to_string())),
        )
        .await,
        AdminResponse::Error { message } if message.contains("session principal mismatch")
    ));
    let before = (
        cfg.state.approvals.read().await.list().len(),
        cfg.state.provisional.read().await.list().len(),
        cfg.state.read_grants.read().await.list().len(),
        cfg.state.grant_requests.read().await.len(),
        cfg.state.verbs.read().await.list().len(),
        cfg.state
            .sessions
            .read()
            .await
            .interactions_snapshot()
            .len(),
    );
    assert!(matches!(
        handle_admin_request_for_test(
            &cfg,
            &worker,
            evaluate(
                Some("batch-owner".to_string()),
                Some("batch-owner".to_string())
            ),
        )
        .await,
        AdminResponse::EvaluationBatch { .. }
    ));
    let after = (
        cfg.state.approvals.read().await.list().len(),
        cfg.state.provisional.read().await.list().len(),
        cfg.state.read_grants.read().await.list().len(),
        cfg.state.grant_requests.read().await.len(),
        cfg.state.verbs.read().await.list().len(),
        cfg.state
            .sessions
            .read()
            .await
            .interactions_snapshot()
            .len(),
    );
    assert_eq!(
        after, before,
        "batch preview must have no durable side effects"
    );
    assert!(matches!(
        handle_admin_request_for_test(&cfg, &daemon, evaluate(None, None)).await,
        AdminResponse::EvaluationBatch { .. }
    ));

    cfg.state.sessions.write().await.record_interaction(
        "batch-owner",
        SessionInteraction {
            command: "denied".to_string(),
            allowed: false,
            source: SessionDecisionSource::Llm,
            reason: "denied".to_string(),
            risk: Some(5),
            exec_status: SessionExecStatus::NotAttempted,
            exit_code: None,
            at_unix: guard::env::now_unix(),
            exposed_secret_refs: Vec::new(),
            decision_trace: None,
        },
    );
    assert!(matches!(
        handle_admin_request_for_test(
            &cfg,
            &worker,
            evaluate(Some("batch-owner".to_string()), Some("batch-owner".to_string())),
        )
        .await,
        AdminResponse::Error { message } if message.contains("suspended")
    ));
}

#[tokio::test]
async fn evaluate_batch_redacts_structured_alias_commands_before_projection() {
    let (cfg, _) = make_test_config();
    let token = "batch-redaction-owner".to_string();
    cfg.state
        .sessions
        .write()
        .await
        .grant(token.clone(), granted_session(Vec::new(), Vec::new()));
    let value = ["q", "7"].concat();
    let commands = vec![
        guard::wire::BatchCommand {
            binary: "curl.EXE".to_string(),
            args: vec![format!("-u{value}")],
            env: HashMap::new(),
            secrets: HashMap::new(),
            secret_files: HashMap::new(),
            cwd: None,
        },
        guard::wire::BatchCommand {
            binary: "docker.CMD".to_string(),
            args: vec!["login".to_string(), format!("-p:{value}")],
            env: HashMap::new(),
            secrets: HashMap::new(),
            secret_files: HashMap::new(),
            cwd: None,
        },
    ];

    let response = handle_admin_request_for_test(
        &cfg,
        &CallerIdentity::Unix { uid: 1000 },
        AdminRequest::EvaluateBatch {
            session_token: Some(token.clone()),
            caller_token: Some(token),
            commands,
        },
    )
    .await;
    let AdminResponse::EvaluationBatch { items } = response else {
        panic!("expected batch evaluation")
    };
    assert_eq!(items.len(), 2);
    assert!(items.iter().all(|item| item.command.contains("[REDACTED]")));
    assert!(items.iter().all(|item| !item.command.contains(&value)));
}

#[tokio::test]
async fn evaluate_batch_seeds_the_identical_real_run_cache_key() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(super::exec_policy::run_denying_llm(listener));

    let evaluator = Evaluator::new(
        EvalConfig::default()
            .llm_api_key("test-key".to_string())
            .llm_api_url(url)
            .llm_retries(0),
    )
    .unwrap();
    let (mut cfg, _) = make_test_config();
    cfg.state.evaluator = Arc::new(evaluator);
    let token = "batch-cache-owner".to_string();
    let mut grant = granted_session(Vec::new(), Vec::new());
    grant.static_only = false;
    cfg.state.sessions.write().await.grant(token.clone(), grant);
    let cwd = tempfile::tempdir().unwrap();
    let cwd = cwd.path().canonicalize().unwrap();
    let command = guard::wire::BatchCommand {
        binary: "echo".to_string(),
        args: vec!["delete-prod".to_string()],
        env: HashMap::from([("DEPLOY_SCOPE".to_string(), "alpha".to_string())]),
        secrets: HashMap::new(),
        secret_files: HashMap::new(),
        cwd: Some(cwd.clone()),
    };
    let worker = CallerIdentity::Unix { uid: 1000 };

    let response = handle_admin_request_for_test(
        &cfg,
        &worker,
        AdminRequest::EvaluateBatch {
            session_token: Some(token.clone()),
            caller_token: Some(token.clone()),
            commands: vec![command.clone()],
        },
    )
    .await;
    let AdminResponse::EvaluationBatch { items } = response else {
        panic!("expected batch evaluation")
    };
    assert_eq!(items[0].decision_source, "llm");

    let result = execute_command(
        ExecuteRequest {
            binary: command.binary.clone(),
            args: command.args.clone(),
            auth_token: None,
            env: command.env.clone(),
            secrets: command.secrets.clone(),
            secret_files: command.secret_files.clone(),
            stream: false,
            session_token: Some(token),
            revert: None,
            confirm_within_secs: None,
            reevaluate: false,
            ssh_hostkey: None,
            cwd: command.cwd.clone(),
            require_approval: None,
            wait_approval_secs: None,
            verb: None,
        },
        &cfg,
        &worker,
    )
    .await
    .into_response();
    assert_eq!(result.decision_source, "cache");

    let mut changed_environment = command.env;
    changed_environment.insert("DEPLOY_SCOPE".to_string(), "beta".to_string());
    let changed = execute_command(
        ExecuteRequest {
            binary: command.binary,
            args: command.args,
            auth_token: None,
            env: changed_environment,
            secrets: command.secrets,
            secret_files: command.secret_files,
            stream: false,
            session_token: Some("batch-cache-owner".to_string()),
            revert: None,
            confirm_within_secs: None,
            reevaluate: false,
            ssh_hostkey: None,
            cwd: command.cwd,
            require_approval: None,
            wait_approval_secs: None,
            verb: None,
        },
        &cfg,
        &worker,
    )
    .await
    .into_response();
    assert_eq!(
        changed.decision_source, "llm",
        "a different plain environment value must not reuse the preview cache entry"
    );
    let admission = cfg.state.command_admission.snapshot();
    assert_eq!(admission.handler_admitted, 3);
    assert_eq!(admission.evaluator_admitted, 3);
}

#[tokio::test]
async fn grant_request_approval_rejects_expiry_and_stale_saved_revision() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.state.saved_grants = Arc::new(RwLock::new(
        SavedGrantCatalog::from_yaml(
            "grants:\n  - name: reviewed\n    prompt_append: reviewed task\n    auto_approve_requests: false\n",
        )
        .unwrap(),
    ));
    let daemon = CallerIdentity::UnixAdmin { uid: 777 };
    let worker = CallerIdentity::Unix { uid: 778 };
    let token = "revision-session".to_string();
    assert!(matches!(
        handle_admin_request_for_test(
            &cfg,
            &daemon,
            AdminRequest::SessionGrant {
                token: token.clone(),
                allow: Vec::new(),
                deny: Vec::new(),
                activated_verbs: Vec::new(),
                override_markers: Vec::new(),
                ttl_secs: None,
                prompt_append: None,
                prose: None,
                saved_grant: Some("reviewed".to_string()),
                profile: None,
                evaluation_mode: None,
                static_only: false,
                auto_amend: false,
                owner: Some("778".to_string()),
            },
        )
        .await,
        AdminResponse::Ok
    ));
    let submit = |prompt: &str| AdminRequest::GrantRequestSubmit {
        session_token: token.clone(),
        caller_token: Some(token.clone()),
        saved_grant: None,
        prompt: prompt.to_string(),
        delta: crate::grant_profile::GrantRequestDelta {
            prompt_append: Some(prompt.to_string()),
            ..Default::default()
        },
    };
    let first = handle_admin_request_for_test(&cfg, &worker, submit("expired")).await;
    let AdminResponse::GrantRequest { request } = first else {
        panic!()
    };
    cfg.state
        .grant_requests
        .write()
        .await
        .get_mut(&request.handle)
        .unwrap()
        .expires_unix = 1;
    assert!(matches!(
        handle_admin_request_for_test(&cfg, &daemon, AdminRequest::GrantRequestApprove { handle: request.handle }).await,
        AdminResponse::Error { message } if message.contains("expired")
    ));

    let second = handle_admin_request_for_test(&cfg, &worker, submit("stale")).await;
    let AdminResponse::GrantRequest { request } = second else {
        panic!()
    };
    assert!(matches!(
        handle_admin_request_for_test(
            &cfg,
            &daemon,
            AdminRequest::SavedGrantEdit {
                name: "reviewed".to_string(),
                description: Some("new revision".to_string()),
                activated_verbs: Vec::new(),
                clear_verbs: false,
                override_markers: Vec::new(),
                clear_override_markers: false,
                secret_names: Vec::new(),
                clear_secrets: false,
                ceiling_verbs: Vec::new(),
                clear_ceiling_verbs: false,
                ceiling_secrets: Vec::new(),
                clear_ceiling_secrets: false,
                ceiling_ttl_secs: None,
                clear_ceiling_ttl: false,
                ceiling_modes: Vec::new(),
                clear_ceiling_modes: false,
                allow_prompt_append: None,
                ttl_secs: None,
                clear_ttl: false,
                prompt_append: None,
                evaluation_mode: None,
                auto_approve_requests: None,
            }
        )
        .await,
        AdminResponse::SavedGrant { .. }
    ));
    assert!(matches!(
        handle_admin_request_for_test(&cfg, &daemon, AdminRequest::GrantRequestApprove { handle: request.handle }).await,
        AdminResponse::Error { message } if message.contains("changed after request issuance")
    ));
}

#[tokio::test]
async fn grant_request_binds_unsaved_session_revision_and_prunes_expired_rows() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    let tmp = tempfile::tempdir().unwrap();
    cfg.state.session_store = Some(
        SessionStore::open(tmp.path().join("state.db"), 3600)
            .await
            .unwrap(),
    );
    let daemon = CallerIdentity::UnixAdmin { uid: 777 };
    let worker = CallerIdentity::Unix { uid: 778 };
    let token = "unsaved-revision".to_string();
    cfg.state.sessions.write().await.grant(
        token.clone(),
        granted_session_owned(778, Vec::new(), Vec::new()),
    );
    let submit = |prompt: &str| AdminRequest::GrantRequestSubmit {
        session_token: token.clone(),
        caller_token: Some(token.clone()),
        saved_grant: None,
        prompt: prompt.to_string(),
        delta: crate::grant_profile::GrantRequestDelta {
            activated_verbs: vec!["inspect".to_string()],
            ..Default::default()
        },
    };

    let stale = handle_admin_request_for_test(&cfg, &worker, submit("stale")).await;
    let AdminResponse::GrantRequest { request } = stale else {
        panic!()
    };
    cfg.state
        .sessions
        .write()
        .await
        .set_label(&token, Some("changed".to_string()));
    assert!(matches!(
        handle_admin_request_for_test(
            &cfg,
            &daemon,
            AdminRequest::GrantRequestApprove { handle: request.handle },
        )
        .await,
        AdminResponse::Error { message } if message.contains("session revision")
    ));

    let expired = handle_admin_request_for_test(&cfg, &worker, submit("expire")).await;
    let AdminResponse::GrantRequest { request } = expired else {
        panic!()
    };
    let mut expired_row = cfg
        .state
        .grant_requests
        .write()
        .await
        .get_mut(&request.handle)
        .unwrap()
        .clone();
    expired_row.expires_unix = 1;
    cfg.state
        .grant_requests
        .write()
        .await
        .insert(request.handle.clone(), expired_row.clone());
    cfg.state
        .session_store
        .as_ref()
        .unwrap()
        .save_grant_request(expired_row)
        .await
        .unwrap();
    let _ = handle_admin_request_for_test(
        &cfg,
        &worker,
        AdminRequest::GrantRequestList {
            session_token: Some(token.clone()),
            caller_token: Some(token),
        },
    )
    .await;
    assert!(!cfg
        .state
        .grant_requests
        .read()
        .await
        .contains_key(&request.handle));
    assert!(cfg
        .state
        .session_store
        .as_ref()
        .unwrap()
        .load_grant_requests()
        .await
        .unwrap()
        .iter()
        .all(|row| row.handle != request.handle));
}

#[tokio::test]
async fn grant_request_queue_is_bounded_and_recovers_capacity_from_expiry() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    let worker = CallerIdentity::Unix { uid: 778 };
    let token = "bounded-queue-0".to_string();
    cfg.state.sessions.write().await.grant(
        token.clone(),
        granted_session_owned(778, Vec::new(), Vec::new()),
    );
    for index in 0..1024 {
        let request = crate::grant_profile::GrantRequest::new(
            format!("bounded-queue-{}", index / 32),
            None,
            crate::grant_profile::GrantRequestDelta {
                activated_verbs: vec![format!("verb-{index}")],
                ..Default::default()
            },
            "queued".to_string(),
        )
        .unwrap();
        cfg.state
            .grant_requests
            .write()
            .await
            .insert(request.handle.clone(), request);
    }
    let submit = || AdminRequest::GrantRequestSubmit {
        session_token: token.clone(),
        caller_token: Some(token.clone()),
        saved_grant: None,
        prompt: "one more".to_string(),
        delta: crate::grant_profile::GrantRequestDelta {
            activated_verbs: vec!["one-more".to_string()],
            ..Default::default()
        },
    };
    assert!(matches!(
        handle_admin_request_for_test(&cfg, &worker, submit()).await,
        AdminResponse::Error { message } if message.contains("queue is full")
    ));
    cfg.state
        .grant_requests
        .write()
        .await
        .values_mut()
        .find(|request| request.session_token == token)
        .unwrap()
        .expires_unix = 1;
    assert!(matches!(
        handle_admin_request_for_test(&cfg, &worker, submit()).await,
        AdminResponse::GrantRequest { .. }
    ));
    assert_eq!(cfg.state.grant_requests.read().await.len(), 1024);
}

#[tokio::test]
async fn session_maintenance_has_one_owner_and_skips_noop_persistence() {
    let (mut cfg, _) = make_test_config();
    let tmp = tempfile::tempdir().expect("tempdir");
    cfg.state.session_store = Some(
        SessionStore::open(tmp.path().join("state.db"), 3600)
            .await
            .expect("open store"),
    );
    cfg.state.sessions.write().await.grant(
        "expired".into(),
        SessionGrant {
            allow: vec!["true".into()],
            deny: Vec::new(),
            allow_exact: Vec::new(),
            deny_exact: Vec::new(),
            activated_verbs: Vec::new(),
            override_markers: Vec::new(),
            scope: Default::default(),
            expires_at: Some(1),
            prompt_append: None,
            generated_notes: Vec::new(),
            granted_at: 0,
            static_only: false,
            auto_amend: false,
            owner: crate::session::SessionOwner::Principal(
                guard::principal::PrincipalKey::from_uid(1000),
            ),
        },
    );

    assert!(claim_session_maintenance(&cfg));
    assert!(!claim_session_maintenance(&cfg.clone()));
    assert!(session_maintenance_once(&cfg)
        .await
        .expect("prune expired state"));
    assert!(!session_maintenance_once(&cfg)
        .await
        .expect("skip unchanged state"));
}

// ---------------------------------------------------------------------------
// Principal binding: two-UID regression matrix.
//
// Every path that consumes a session's authority must accept the owning
// principal, deny a different local peer that merely holds the same handle with
// the greppable `session principal mismatch` reason, and keep the daemon
// (operator) principal cross-session. Legacy `Unowned` sessions are refused for
// execution fail-closed, and a revoked session is denied regardless of caller.
// ---------------------------------------------------------------------------

/// A live session that allows `true` and is bound to `owner_uid`.
fn session_owned_by(owner_uid: u32) -> crate::session::SessionGrant {
    let mut grant = granted_session(vec!["true".to_string()], Vec::new());
    grant.static_only = false;
    grant.owner = crate::session::SessionOwner::Principal(PrincipalKey::from_uid(owner_uid));
    grant
}

#[tokio::test]
async fn principal_binding_execute_owner_ok_other_denied_admin_ok() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    let token = format!("exec-owner-{}", std::process::id());
    cfg.state
        .sessions
        .write()
        .await
        .grant(token.clone(), session_owned_by(1001));

    // Owner executes.
    let owner = execute_command(
        request_with_session("true", Vec::new(), token.clone()),
        &cfg,
        &CallerIdentity::Unix { uid: 1001 },
    )
    .await;
    assert!(owner.policy_allowed(), "owner must execute its own session");

    // A different local peer that learned the handle is denied with the
    // greppable mismatch reason - the bearer-replay hole is closed.
    let other = execute_command(
        request_with_session("true", Vec::new(), token.clone()),
        &cfg,
        &CallerIdentity::Unix { uid: 1002 },
    )
    .await;
    assert!(!other.policy_allowed());
    assert!(
        other.policy_reason().contains("session principal mismatch"),
        "got: {}",
        other.policy_reason()
    );

    // An authenticated operator keeps cross-session authority.
    let admin = execute_command(
        request_with_session("true", Vec::new(), token.clone()),
        &cfg,
        &CallerIdentity::UnixAdmin { uid: 777 },
    )
    .await;
    assert!(admin.policy_allowed(), "operator retains cross-session use");

    // A TCP (principal-less) caller cannot satisfy owner==caller either.
    let tcp = execute_command(
        request_with_session("true", Vec::new(), token),
        &cfg,
        &CallerIdentity::Tcp {
            token: "exec-token".to_string(),
        },
    )
    .await;
    assert!(!tcp.policy_allowed());
    assert!(tcp.policy_reason().contains("session principal mismatch"));
}

#[tokio::test]
async fn principal_binding_unowned_session_refused_for_execute() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    let token = format!("exec-unowned-{}", std::process::id());
    let mut grant = session_owned_by(1001);
    grant.owner = crate::session::SessionOwner::Unowned;
    cfg.state.sessions.write().await.grant(token.clone(), grant);

    // Even the operator cannot execute an ownerless legacy session: it fails
    // closed and must be reissued.
    for caller in [
        CallerIdentity::Unix { uid: 1001 },
        CallerIdentity::UnixAdmin { uid: 777 },
    ] {
        let result = execute_command(
            request_with_session("true", Vec::new(), token.clone()),
            &cfg,
            &caller,
        )
        .await;
        assert!(!result.policy_allowed(), "unowned session must not execute");
        assert!(
            result
                .policy_reason()
                .contains("predates principal binding"),
            "got: {}",
            result.policy_reason()
        );
    }
}

#[tokio::test]
async fn principal_binding_revoked_session_denies_regardless_of_principal() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    let token = format!("exec-revoked-{}", std::process::id());
    cfg.state
        .sessions
        .write()
        .await
        .grant(token.clone(), session_owned_by(1001));
    assert!(cfg.state.sessions.write().await.revoke(&token));

    for caller in [
        CallerIdentity::Unix { uid: 1001 },
        CallerIdentity::UnixAdmin { uid: 777 },
    ] {
        let result = execute_command(
            request_with_session("true", Vec::new(), token.clone()),
            &cfg,
            &caller,
        )
        .await;
        assert!(!result.policy_allowed(), "revoked session must never run");
        assert!(result.policy_reason().contains("unknown session token"));
    }
}

#[tokio::test]
async fn principal_binding_show_and_status_two_uid() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    let token = format!("show-owner-{}", std::process::id());
    cfg.state
        .sessions
        .write()
        .await
        .grant(token.clone(), session_owned_by(1001));

    async fn show_as(cfg: &crate::server::ServerContext, uid: u32, token: &str) -> AdminResponse {
        handle_admin_request_for_test(
            cfg,
            &CallerIdentity::Unix { uid },
            AdminRequest::SessionShow {
                token: token.to_string(),
                limit: Some(20),
                caller_token: Some(token.to_string()),
            },
        )
        .await
    }
    async fn status_as(cfg: &crate::server::ServerContext, uid: u32, token: &str) -> AdminResponse {
        handle_admin_request_for_test(
            cfg,
            &CallerIdentity::Unix { uid },
            AdminRequest::SessionStatus {
                token: token.to_string(),
                caller_token: Some(token.to_string()),
            },
        )
        .await
    }

    // Owner sees its own grant.
    assert!(matches!(
        show_as(&cfg, 1001, &token).await,
        AdminResponse::SessionShow { .. }
    ));
    // A different peer with the same handle is denied with the mismatch reason.
    match show_as(&cfg, 1002, &token).await {
        AdminResponse::Error { message } => {
            assert!(
                message.contains("session principal mismatch"),
                "got: {message}"
            );
        }
        other => panic!("expected mismatch denial, got {other:?}"),
    }
    // The daemon uid has no implicit operator authority.
    assert!(matches!(
        show_as(&cfg, 777, &token).await,
        AdminResponse::Error { .. }
    ));

    // Status mirrors show.
    assert!(matches!(
        status_as(&cfg, 1001, &token).await,
        AdminResponse::SessionStatus { .. }
    ));
    assert!(matches!(
        status_as(&cfg, 1002, &token).await,
        AdminResponse::Error { .. }
    ));
    assert!(matches!(
        status_as(&cfg, 777, &token).await,
        AdminResponse::Error { .. }
    ));
}

#[tokio::test]
async fn principal_binding_hold_confirm_is_operator_only() {
    // Confirm, approve, and deny require authenticated operator authority. A
    // non-operator peer that holds a handle cannot confirm a provisional or
    // approve a hold. This keeps a corrupted agent from confirming its own
    // gated action.
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    let refused = handle_admin_request_for_test(
        &cfg,
        &CallerIdentity::Unix { uid: 1002 },
        AdminRequest::Confirm {
            handle: "any-handle".to_string(),
        },
    )
    .await;
    assert!(matches!(
        refused,
        AdminResponse::Error { message } if message.contains("operator authority")
    ));
}

#[tokio::test]
async fn principal_binding_appeal_refuses_unowned_session() {
    let (mut cfg, _) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    let token = format!("appeal-unowned-{}", std::process::id());
    let mut grant = session_owned_by(1001);
    grant.owner = crate::session::SessionOwner::Unowned;
    cfg.state.sessions.write().await.grant(token.clone(), grant);

    let appeal = handle_admin_request_for_test(
        &cfg,
        &CallerIdentity::UnixAdmin { uid: 777 },
        AdminRequest::SessionAppeal {
            token: token.clone(),
            binary: "true".to_string(),
            args: Vec::new(),
        },
    )
    .await;
    assert!(matches!(
        appeal,
        AdminResponse::Error { message } if message.contains("predates principal binding")
    ));
}

// The evaluator memoizes verdicts, so the executor must feed it a cache scope
// that a verdict decided for one user's session can never be reused for another
// user or replayed after the session's authority changes. This proves the
// scope the executor derives is distinct across the two-UID / two-session
// matrix and stable for an identical (principal, session, revision).
#[test]
fn evaluation_cache_scope_isolates_principals_and_sessions() {
    let user_a = CallerIdentity::Unix { uid: 1000 };
    let user_b = CallerIdentity::Unix { uid: 1001 };
    let rev1 = SessionAuthoritySnapshot::from(("rev1".to_string(), None));
    let rev2 = SessionAuthoritySnapshot::from(("rev2".to_string(), None));

    // (a) Same principal + same session token + same revision is stable.
    let a_s1 = evaluation_cache_scope(&user_a, Some("session-token-a1"), Some(&rev1));
    assert_eq!(
        a_s1,
        evaluation_cache_scope(&user_a, Some("session-token-a1"), Some(&rev1))
    );

    // (c) Distinct principal, otherwise identical inputs, must never collide.
    assert_ne!(
        a_s1,
        evaluation_cache_scope(&user_b, Some("session-token-a1"), Some(&rev1))
    );

    // (b) A distinct session (different token) for the same principal differs.
    assert_ne!(
        a_s1,
        evaluation_cache_scope(&user_a, Some("session-token-a2"), Some(&rev1))
    );

    // (d) A reissued/amended session bumps the revision suffix.
    assert_ne!(
        a_s1,
        evaluation_cache_scope(&user_a, Some("session-token-a1"), Some(&rev2))
    );

    // A sessionless request for the same principal is its own scope.
    assert_ne!(a_s1, evaluation_cache_scope(&user_a, None, None));

    // Unauthenticated callers never share a scope, even for the same command.
    assert_ne!(
        evaluation_cache_scope(&CallerIdentity::Unknown, None, None),
        evaluation_cache_scope(&CallerIdentity::Unknown, None, None)
    );
}
