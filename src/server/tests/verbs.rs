use crate::server::admin::handle_admin_request;
use crate::server::execute::execute_command;
use crate::server::wire::{
    AdminRequest, AdminResponse, CallerIdentity, ExecuteRequest, GateStatus, VerbInvocation,
};
use crate::server::ServerContext;
use crate::session::SessionGrant;
use guard::evaluate::{EvalConfig, Evaluator};
use guard::gating::verb::VerbCatalog;
use guard::gating::GateMode;
use guard::principal::PrincipalKey;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::make_test_config;

fn raw_request(binary: &str, args: &[&str], session_token: Option<&str>) -> ExecuteRequest {
    ExecuteRequest {
        binary: binary.to_string(),
        args: args.iter().map(|arg| (*arg).to_string()).collect(),
        auth_token: None,
        env: HashMap::new(),
        secrets: HashMap::new(),
        secret_files: HashMap::new(),
        stream: false,
        session_token: session_token.map(str::to_string),
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
async fn raw_command_collects_all_typed_matches_and_executes_selected_cell() {
    let (mut cfg, _buf) = make_test_config();
    cfg.config.gate = GateMode::Consequence;
    cfg.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            r#"
verbs:
  - name: broad-check
    binary: true
    consequence: reversible
    trusted: true
    coverage:
      - name: any-check
        action: preauthorized
        required_args: ["--check"]
  - name: narrow-check
    binary: true
    consequence: reversible
    trusted: true
    coverage:
      - name: explicit-safe
        action: preauthorized
        required_args: ["--check", "safe"]
"#,
        )
        .expect("valid typed catalog"),
    ));

    let response = execute_command(
        raw_request("true", &["--check", "safe"], None),
        &cfg,
        &CallerIdentity::Unix { uid: 1000 },
    )
    .await
    .into_response();

    assert!(response.allowed);
    assert_eq!(response.exit_code, Some(0));
    assert_eq!(response.verb_matches.len(), 2);
    assert!(!response.verb_matches[0].selected);
    assert!(response.verb_matches[1].selected);
    assert!(response.verb_guidance.is_none());
}

#[tokio::test]
async fn session_verb_needs_exact_marker_to_override_baseline_evaluation() {
    let (mut cfg, _buf) = make_test_config();
    cfg.config.gate = GateMode::Consequence;
    cfg.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            r#"
verbs:
  - name: baseline-review
    binary: true
    consequence: recoverable
    coverage:
      - name: apply
        action: evaluate
        required_args: ["apply"]
        override_marker: operator:apply
  - name: session-apply
    binary: true
    baseline: false
    consequence: reversible
    trusted: true
    coverage:
      - name: apply
        action: preauthorized
        required_args: ["apply"]
"#,
        )
        .expect("valid typed catalog"),
    ));

    let grant = |override_markers| SessionGrant {
        allow: Vec::new(),
        deny: Vec::new(),
        allow_exact: Vec::new(),
        deny_exact: Vec::new(),
        activated_verbs: vec!["session-apply".to_string()],
        override_markers,
        scope: Default::default(),
        expires_at: None,
        prompt_append: None,
        generated_notes: Vec::new(),
        static_only: false,
        auto_amend: false,
        granted_at: 0,
        owner: crate::session::SessionOwner::Principal(guard::principal::PrincipalKey::from_uid(
            1000,
        )),
    };
    cfg.state
        .sessions
        .write()
        .await
        .grant("typed".to_string(), grant(Vec::new()));

    let without_marker = execute_command(
        raw_request("true", &["apply"], Some("typed")),
        &cfg,
        &CallerIdentity::Unix { uid: 1000 },
    )
    .await
    .into_response();
    assert!(!without_marker.allowed);
    assert_eq!(without_marker.verb_matches.len(), 2);
    assert!(without_marker.verb_guidance.is_some());

    assert_eq!(
        cfg.state.sessions.write().await.apply_delta(
            "typed",
            &crate::grant_profile::GrantRequestDelta {
                override_markers: vec!["operator:apply".to_string()],
                ..crate::grant_profile::GrantRequestDelta::default()
            },
        ),
        Some(true)
    );
    let with_marker = execute_command(
        raw_request("true", &["apply"], Some("typed")),
        &cfg,
        &CallerIdentity::Unix { uid: 1000 },
    )
    .await
    .into_response();
    assert!(with_marker.allowed);
    assert_eq!(with_marker.exit_code, Some(0));
    assert!(with_marker.verb_matches[0].overridden);
    assert!(!with_marker.verb_matches[0].selected);
    assert!(with_marker.verb_matches[1].selected);
}

#[tokio::test]
async fn typed_evaluation_keeps_consequence_gate_after_static_policy_allow() {
    let (mut cfg, _buf) = make_test_config();
    cfg.config.gate = GateMode::Consequence;
    let tmp = tempfile::tempdir().expect("tempdir");
    let policy = tmp.path().join("policy.yaml");
    std::fs::write(
        &policy,
        "policy:\n  commands:\n    allow:\n      - \"true apply\"\n",
    )
    .expect("write policy");
    cfg.state.evaluator = Arc::new(
        Evaluator::new(EvalConfig::default().llm_enabled(false).policy_path(policy))
            .expect("build static evaluator"),
    );
    cfg.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            r#"
verbs:
  - name: reviewed-apply
    binary: true
    consequence: irreversible
    coverage:
      - name: apply
        action: evaluate
        required_args: ["apply"]
"#,
        )
        .expect("valid typed catalog"),
    ));

    let response = execute_command(
        raw_request("true", &["apply"], None),
        &cfg,
        &CallerIdentity::Unix { uid: 1000 },
    )
    .await
    .into_response();

    assert!(response.allowed, "the evaluator approved the command");
    assert_eq!(response.status, Some(GateStatus::Held));
    assert!(
        response.exit_code.is_none(),
        "the held command must not run"
    );
    assert!(response.verb_matches[0].selected);
}

#[tokio::test]
async fn approved_access_grant_executes_session_evaluate_verb_and_consumes_one_use() {
    let (mut cfg, _buf) = make_test_config();
    cfg.config.gate = GateMode::Consequence;
    cfg.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            r#"
verbs:
  - name: reviewed-check
    binary: true
    baseline: false
    consequence: reversible
    coverage:
      - name: check
        action: evaluate
        required_args: ["--check"]
"#,
        )
        .expect("valid typed catalog"),
    ));
    let mut grant = SessionGrant {
        allow: Vec::new(),
        deny: Vec::new(),
        allow_exact: Vec::new(),
        deny_exact: Vec::new(),
        activated_verbs: vec!["reviewed-check".to_string()],
        override_markers: Vec::new(),
        scope: Default::default(),
        expires_at: None,
        prompt_append: None,
        generated_notes: Vec::new(),
        static_only: false,
        auto_amend: false,
        granted_at: 0,
        owner: crate::session::SessionOwner::Principal(guard::principal::PrincipalKey::from_uid(
            1000,
        )),
    };
    grant.scope.access_managed = true;
    let mut sessions = cfg.state.sessions.write().await;
    sessions.grant("access".to_string(), grant);
    assert_eq!(
        sessions.install_access_grant(
            "access",
            Some(2),
            "gr-test".to_string(),
            vec!["reviewed-check".to_string()],
        ),
        Some(true)
    );
    drop(sessions);

    let response = execute_command(
        raw_request("true", &["--check"], Some("access")),
        &cfg,
        &CallerIdentity::Unix { uid: 1000 },
    )
    .await
    .into_response();

    assert!(
        response.allowed,
        "the approved typed grant must bypass reevaluation"
    );
    assert_eq!(response.exit_code, Some(0));
    assert_eq!(
        cfg.state
            .sessions
            .read()
            .await
            .access_grant_uses("access", "gr-test"),
        Some((Some(2), Some(1)))
    );
}

/// Trusted-verb + consequence-gate interaction: `trusted` only skips the
/// LLM evaluator (`bypass: false` in the `GateInputs` built for it, see
/// `try_trusted_verb_allow` in `server::execute`); it must NOT also skip
/// consequence routing. An irreversible trusted verb must still be held for operator
/// approval, never executed immediately, even though it never went
/// through the LLM.
#[tokio::test]
async fn trusted_verb_irreversible_still_holds_for_approval() {
    let (mut cfg, _buf) = make_test_config();
    cfg.config.gate = GateMode::Consequence;
    let catalog = VerbCatalog::from_yaml(
            "verbs:\n  - name: danger-op\n    binary: true\n    consequence: irreversible\n    trusted: true\n",
        )
        .unwrap();
    cfg.state.verbs = Arc::new(RwLock::new(catalog));

    let request = ExecuteRequest {
        binary: String::new(),
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
        cwd: None,
        require_approval: None,
        wait_approval_secs: None,
        verb: Some(VerbInvocation {
            name: "danger-op".to_string(),
            params: std::collections::BTreeMap::new(),
        }),
    };

    let result = execute_command(request, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;
    let response = result.into_response();
    assert!(response.allowed, "a held command is still policy-allowed");
    assert_eq!(
        response.status,
        Some(GateStatus::Held),
        "a trusted verb declared irreversible must be held, not executed, despite skipping \
             the LLM: got {:?}",
        response.status
    );
    assert!(
        response.exit_code.is_none(),
        "a held command must not have run"
    );
}

/// The other half of the same interaction: a trusted verb declared
/// reversible with a low (verb-forced) risk of 0 clears the gate at
/// execute-now, exactly like an LLM-approved reversible command would.
#[tokio::test]
async fn trusted_verb_reversible_executes_now() {
    let (mut cfg, _buf) = make_test_config();
    cfg.config.gate = GateMode::Consequence;
    let catalog = VerbCatalog::from_yaml(
            "verbs:\n  - name: safe-op\n    binary: true\n    consequence: reversible\n    trusted: true\n",
        )
        .unwrap();
    cfg.state.verbs = Arc::new(RwLock::new(catalog));

    let request = ExecuteRequest {
        binary: String::new(),
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
        cwd: None,
        require_approval: None,
        wait_approval_secs: None,
        verb: Some(VerbInvocation {
            name: "safe-op".to_string(),
            params: std::collections::BTreeMap::new(),
        }),
    };

    let result = execute_command(request, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;
    let response = result.into_response();
    assert!(response.allowed);
    assert!(
        response.status.is_none() || response.status == Some(GateStatus::Executed),
        "a trusted reversible verb should execute immediately, got {:?}",
        response.status
    );
    assert_eq!(
        response.exit_code,
        Some(0),
        "the verb should have actually run"
    );
}

/// A raw command (no explicit `--verb` invocation) that happens to match
/// a catalog verb's template picks up the verb's declared class and trust
/// the same way an explicit invocation would (`VerbCatalog::match_command`),
/// as long as the verb's trust is current (see the next test for the
/// stale case). This is what makes a catalog useful for gating a tool a
/// caller invokes normally, rather than only via `--verb name`.
#[tokio::test]
async fn raw_command_reverse_matches_trusted_verb_and_executes_now() {
    let (mut cfg, _buf) = make_test_config();
    cfg.config.gate = GateMode::Consequence;
    let catalog = VerbCatalog::from_yaml(
            "verbs:\n  - name: safe-op\n    binary: true\n    consequence: reversible\n    trusted: true\n",
        )
        .unwrap();
    cfg.state.verbs = Arc::new(RwLock::new(catalog));

    let request = ExecuteRequest {
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
        cwd: None,
        require_approval: None,
        wait_approval_secs: None,
        verb: None,
    };

    let result = execute_command(request, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;
    let response = result.into_response();
    assert!(
        response.allowed,
        "a raw command matching a trusted verb's template should be allowed"
    );
    assert_eq!(
        response.exit_code,
        Some(0),
        "should have executed immediately via the reverse-matched trusted verb"
    );
}

#[tokio::test]
async fn trusted_reverse_match_cannot_skip_evaluator_for_untyped_ansible_config() {
    let (mut cfg, _buf) = make_test_config();
    cfg.config.gate = GateMode::Consequence;
    cfg.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            r#"
verbs:
  - name: check-only
    binary: true
    consequence: reversible
    trusted: true
    coverage:
      - name: check
        action: preauthorized
        required_args: ["--check"]
"#,
        )
        .unwrap(),
    ));
    let mut request = raw_request("true", &["--check"], None);
    request.env.insert(
        "ANSIBLE_CONFIG".to_string(),
        "/tmp/caller-controlled.cfg".to_string(),
    );
    let response = execute_command(request, &cfg, &CallerIdentity::Unix { uid: 1000 })
        .await
        .into_response();
    assert!(!response.allowed);
    assert_eq!(
        response.verb_matches[0].action,
        guard::gating::verb::CoverageAction::Evaluate
    );
    let trace = response.decision_trace.as_ref().expect("decision trace");
    assert_eq!(trace.version, guard::gating::DecisionTrace::VERSION);
    assert_eq!(trace.decision_source, response.decision_source);
    assert_eq!(trace.verb_matches.len(), 1);
    assert_eq!(trace.verb_matches[0].action, "evaluate");
    assert!(!trace.failed_dimensions.is_empty());
    let admission = cfg.state.command_admission.snapshot();
    assert_eq!(admission.handler_admitted, 1);
    assert_eq!(admission.evaluator_admitted, 1);
}

#[tokio::test]
async fn trusted_reverse_match_accepts_exact_typed_ansible_config() {
    let (mut cfg, _buf) = make_test_config();
    cfg.config.gate = GateMode::Consequence;
    cfg.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            r#"
verbs:
  - name: check-only
    binary: true
    consequence: reversible
    trusted: true
    coverage:
      - name: check
        action: preauthorized
        required_args: ["--check"]
        environment:
          - name: ANSIBLE_CONFIG
            values: ["/srv/automation/ansible.cfg"]
"#,
        )
        .unwrap(),
    ));
    let mut request = raw_request("true", &["--check"], None);
    request.env.insert(
        "ANSIBLE_CONFIG".to_string(),
        "/srv/automation/ansible.cfg".to_string(),
    );
    let response = execute_command(request, &cfg, &CallerIdentity::Unix { uid: 1000 })
        .await
        .into_response();
    assert!(response.allowed, "{response:?}");
    assert_eq!(response.exit_code, Some(0));
    let trace = response.decision_trace.as_ref().expect("decision trace");
    assert_eq!(trace.version, guard::gating::DecisionTrace::VERSION);
    assert_eq!(trace.decision_source, response.decision_source);
    assert_eq!(trace.verb_matches.len(), 1);
    assert_eq!(trace.verb_matches[0].action, "preauthorized");
    assert!(trace.failed_dimensions.is_empty());
    let admission = cfg.state.command_admission.snapshot();
    assert_eq!(admission.handler_admitted, 1);
    assert_eq!(admission.evaluator_attempted, 0);
}

/// An auto-promoted verb (`gating::allow_promotion`) is trusted only as
/// long as its `promotion_stamp` matches the daemon's current model +
/// prompt stamp. A stale stamp must downgrade `trusted` to false rather
/// than continuing to trust a judgment made under a since-changed
/// evaluator -- with the LLM disabled and no static policy in this test
/// config, that downgrade is observable as a default-deny instead of an
/// immediate execution.
#[tokio::test]
async fn stale_auto_promoted_verb_is_not_trusted() {
    let (mut cfg, _buf) = make_test_config();
    cfg.config.gate = GateMode::Consequence;
    let catalog = VerbCatalog::from_yaml(
        "verbs:\n  - name: auto-op\n    binary: true\n    consequence: reversible\n    \
             trusted: true\n    auto_promoted: true\n    promotion_stamp: definitely-stale\n",
    )
    .unwrap();
    cfg.state.verbs = Arc::new(RwLock::new(catalog));
    assert_ne!(
        cfg.state.evaluator.verb_promotion_stamp(),
        "definitely-stale",
        "the fixture stamp must not accidentally collide with a real stamp"
    );

    let request = ExecuteRequest {
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
        cwd: None,
        require_approval: None,
        wait_approval_secs: None,
        verb: None,
    };

    let result = execute_command(request, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;
    let response = result.into_response();
    assert!(
        !response.allowed,
        "a stale auto-promoted verb must not skip the LLM (denied here since the test \
             evaluator has the LLM disabled and no static policy): got {:?}",
        response
    );
}

/// `guard verb list` must not misrepresent a stale auto-promoted verb as
/// still trusted: its reported `trusted` field has to reflect the same
/// staleness check `resolve_verb_context` applies, not the catalog's raw
/// `Verb.trusted` flag, or an operator reading the list would believe a
/// promotion is still fast-pathing when the daemon has actually stopped
/// honoring it. A current (non-stale, or non-auto-promoted) verb must
/// still report trusted, and `auto_promoted`/`evidence` must come through.
#[tokio::test]
async fn verb_list_reports_staleness_corrected_trust_and_provenance() {
    let (mut cfg, _buf) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    let current_stamp = cfg.state.evaluator.verb_promotion_stamp().to_string();
    let catalog = VerbCatalog::from_yaml(&format!(
        "verbs:\n\
             - name: fresh-auto\n  binary: true\n  consequence: reversible\n  trusted: true\n  \
             auto_promoted: true\n  promotion_stamp: {current_stamp}\n  evidence: fresh\n\
             - name: stale-auto\n  binary: true\n  consequence: reversible\n  trusted: true\n  \
             auto_promoted: true\n  promotion_stamp: definitely-stale\n  evidence: stale\n\
             - name: hand-authored\n  binary: true\n  consequence: reversible\n  trusted: true\n"
    ))
    .unwrap();
    cfg.state.verbs = Arc::new(RwLock::new(catalog));

    let response = handle_admin_request(
        &cfg,
        &CallerIdentity::UnixAdmin { uid: 777 },
        AdminRequest::VerbList,
    )
    .await;
    let AdminResponse::Verbs { items } = response else {
        panic!("expected Verbs response, got {response:?}");
    };
    let by_name = |name: &str| items.iter().find(|v| v.name == name).unwrap();

    let fresh = by_name("fresh-auto");
    assert!(fresh.trusted, "a current auto-promoted verb stays trusted");
    assert!(fresh.auto_promoted);
    assert_eq!(fresh.evidence.as_deref(), Some("fresh"));

    let stale = by_name("stale-auto");
    assert!(
        !stale.trusted,
        "a stale auto-promoted verb must be reported as untrusted, not just downgraded \
             silently at execution time"
    );
    assert!(stale.auto_promoted);

    let hand = by_name("hand-authored");
    assert!(hand.trusted, "a hand-authored verb has no staleness expiry");
    assert!(!hand.auto_promoted);
}

#[tokio::test]
async fn non_operator_verb_reads_expose_only_the_sanitized_menu() {
    let (mut cfg, _buf) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            r#"
verbs:
  - name: inspect-fixture
    description: Inspect one fixture
    binary: fixturectl
    args: ["show", "{target}"]
    params:
      target: { pattern: "^[a-z0-9-]+$" }
    consequence: reversible
    trusted: true
    evidence: operator-only provenance
"#,
        )
        .unwrap(),
    ));

    let response = handle_admin_request(
        &cfg,
        &CallerIdentity::Unix { uid: 1001 },
        AdminRequest::VerbList,
    )
    .await;
    let AdminResponse::VerbMenu { items } = &response else {
        panic!("non-operator must receive a sanitized verb menu: {response:?}");
    };
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].name, "inspect-fixture");
    assert_eq!(items[0].params, vec!["target"]);
    let encoded = serde_json::to_string(&response).unwrap();
    for private in [
        "fixturectl",
        "^[a-z0-9-]+$",
        "operator-only provenance",
        "trusted",
        "coverage",
        "credential_plan",
    ] {
        assert!(!encoded.contains(private), "leaked {private}: {encoded}");
    }

    assert!(AdminRequest::VerbShow {
        name: "inspect-fixture".to_string()
    }
    .requires_admin_token());
    assert!(matches!(
        handle_admin_request(
            &cfg,
            &CallerIdentity::UnixAdmin { uid: 777 },
            AdminRequest::VerbList,
        )
        .await,
        AdminResponse::Verbs { .. }
    ));
}

fn overbroad_until_gate_feedback_arrives(request: &str) -> serde_json::Value {
    // The gate complaint about the first candidate names its overbroad
    // pattern; once the daemon threads that complaint into the synthesis
    // request, answer with the corrected enumerated shape instead.
    let pattern = if request.contains("too permissive") {
        "^(nginx|sshd)$"
    } else {
        "^.+$"
    };
    serde_json::json!({
        "name": "show-unit-status",
        "description": "Show one systemd unit status",
        "binary": "systemctl",
        "args": ["status", "{unit}"],
        "params": {"unit": {"pattern": pattern}},
        "consequence": "reversible",
        "trusted": false,
        "evidence": "Status is read only."
    })
}

fn file_backed_catalog() -> (tempfile::TempDir, VerbCatalog) {
    let dir = tempfile::tempdir().expect("catalog test dir");
    let path = dir.path().join("verbs.yaml");
    std::fs::write(&path, "verbs: []\n").expect("write empty catalog");
    let catalog = VerbCatalog::load(&path).expect("load empty catalog");
    (dir, catalog)
}

fn synthesis_test_config(llm_url: String) -> (ServerContext, CallerIdentity) {
    let (mut cfg, _buf) = make_test_config();
    cfg.state.evaluator = Arc::new(
        Evaluator::new(
            EvalConfig::default()
                .llm_api_key("test-key".to_string())
                .llm_api_url(llm_url)
                .llm_retries(0),
        )
        .unwrap(),
    );
    cfg.config.daemon_principal = PrincipalKey::from_uid(cfg.config.daemon_uid);
    let daemon = CallerIdentity::UnixAdmin {
        uid: cfg.config.daemon_uid,
    };
    (cfg, daemon)
}

#[tokio::test]
async fn preview_digest_round_trip_installs_the_exact_reviewed_candidate() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(super::run_verb_synthesis_llm(listener));
    let (mut cfg, daemon) = synthesis_test_config(url);
    let (_dir, catalog) = file_backed_catalog();
    cfg.state.verbs = Arc::new(RwLock::new(catalog));

    let response = handle_admin_request(
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
    let AdminResponse::VerbCreated {
        verb: previewed,
        persisted,
        preview_digest,
    } = response
    else {
        panic!("expected previewed verb, got {response:?}");
    };
    assert!(!persisted);
    let digest = preview_digest.expect("a preview response carries its digest");
    assert_eq!(digest, previewed.definition_digest());

    let response = handle_admin_request(
        &cfg,
        &daemon,
        AdminRequest::VerbCreateFromPreview {
            digest: digest[..12].to_string(),
        },
    )
    .await;
    let AdminResponse::VerbCreated {
        verb: installed,
        persisted,
        preview_digest,
    } = response
    else {
        panic!("expected installed verb, got {response:?}");
    };
    assert!(persisted);
    assert_eq!(preview_digest.as_deref(), Some(digest.as_str()));
    assert_eq!(
        installed.definition_digest(),
        digest,
        "install must reproduce exactly the reviewed candidate"
    );
    let catalog_digest = cfg
        .state
        .verbs
        .read()
        .await
        .verb_definition_digest(&installed.name);
    assert_eq!(catalog_digest.as_deref(), Some(digest.as_str()));
}

#[tokio::test]
async fn from_preview_rejects_unknown_and_malformed_digests() {
    let (mut cfg, _buf) = make_test_config();
    cfg.config.daemon_principal = PrincipalKey::from_uid(cfg.config.daemon_uid);
    let daemon = CallerIdentity::UnixAdmin {
        uid: cfg.config.daemon_uid,
    };

    let response = handle_admin_request(
        &cfg,
        &daemon,
        AdminRequest::VerbCreateFromPreview {
            digest: "deadbeef".to_string(),
        },
    )
    .await;
    let AdminResponse::Error { message } = response else {
        panic!("expected an error for an unknown digest, got {response:?}");
    };
    assert!(
        message.contains("no previewed candidate matches 'deadbeef'"),
        "unhelpful unknown-digest error: {message}"
    );

    let response = handle_admin_request(
        &cfg,
        &daemon,
        AdminRequest::VerbCreateFromPreview {
            digest: "not-a-digest".to_string(),
        },
    )
    .await;
    let AdminResponse::Error { message } = response else {
        panic!("expected an error for a malformed digest, got {response:?}");
    };
    assert!(
        message.contains("is not a preview digest"),
        "unhelpful malformed-digest error: {message}"
    );
}

#[tokio::test]
async fn gate_feedback_threads_into_the_next_synthesis_request() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(super::run_verb_synthesis_llm_with(
        listener,
        overbroad_until_gate_feedback_arrives,
    ));
    let (cfg, daemon) = synthesis_test_config(url);

    // First attempt: the model proposes an overbroad pattern and the safety
    // gate rejects it before anything touches the catalog.
    let response = handle_admin_request(
        &cfg,
        &daemon,
        AdminRequest::VerbCreate {
            prose: "Show nginx or sshd unit status.".to_string(),
            binary_hint: Some("systemctl".to_string()),
            preview: true,
            gate_feedback: Vec::new(),
        },
    )
    .await;
    let AdminResponse::Error { message } = response else {
        panic!("expected a safety-gate rejection, got {response:?}");
    };
    let reason = message
        .strip_prefix("synthesized verb rejected by the safety gate: ")
        .unwrap_or_else(|| panic!("not a gate rejection: {message}"))
        .to_string();
    assert!(
        reason.contains("too permissive"),
        "unexpected reason: {reason}"
    );

    // Retry with the complaint threaded: the stub only corrects the shape when
    // the complaint reaches the synthesis request body.
    let response = handle_admin_request(
        &cfg,
        &daemon,
        AdminRequest::VerbCreate {
            prose: "Show nginx or sshd unit status.".to_string(),
            binary_hint: Some("systemctl".to_string()),
            preview: true,
            gate_feedback: vec![reason],
        },
    )
    .await;
    let AdminResponse::VerbCreated { verb, .. } = response else {
        panic!("expected a corrected candidate, got {response:?}");
    };
    assert_eq!(
        verb.params.get("unit").map(|spec| spec.pattern.as_str()),
        Some("^(nginx|sshd)$"),
        "the corrected candidate must reflect the threaded gate feedback"
    );
}
