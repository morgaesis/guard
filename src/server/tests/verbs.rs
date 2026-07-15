use crate::server::admin::handle_admin_request;
use crate::server::execute::execute_command;
use crate::server::wire::{
    AdminRequest, AdminResponse, CallerIdentity, ExecuteRequest, GateStatus, VerbInvocation,
};
use guard::gating::verb::VerbCatalog;
use guard::gating::GateMode;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::make_test_config;

/// Trusted-verb + consequence-gate interaction: `trusted` only skips the
/// LLM evaluator (`bypass: false` in the `GateInputs` built for it, see
/// `try_trusted_verb_allow` in `server::execute`); it must NOT also skip
/// consequence routing. An irreversible trusted verb must still be held for operator
/// approval, never executed immediately, even though it never went
/// through the LLM.
#[tokio::test]
async fn trusted_verb_irreversible_still_holds_for_approval() {
    let (mut cfg, _buf) = make_test_config();
    cfg.gate = GateMode::Consequence;
    let catalog = VerbCatalog::from_yaml(
            "verbs:\n  - name: danger-op\n    binary: true\n    consequence: irreversible\n    trusted: true\n",
        )
        .unwrap();
    cfg.verbs = Arc::new(RwLock::new(catalog));

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
    cfg.gate = GateMode::Consequence;
    let catalog = VerbCatalog::from_yaml(
            "verbs:\n  - name: safe-op\n    binary: true\n    consequence: reversible\n    trusted: true\n",
        )
        .unwrap();
    cfg.verbs = Arc::new(RwLock::new(catalog));

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
    cfg.gate = GateMode::Consequence;
    let catalog = VerbCatalog::from_yaml(
            "verbs:\n  - name: safe-op\n    binary: true\n    consequence: reversible\n    trusted: true\n",
        )
        .unwrap();
    cfg.verbs = Arc::new(RwLock::new(catalog));

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
    cfg.gate = GateMode::Consequence;
    let catalog = VerbCatalog::from_yaml(
        "verbs:\n  - name: auto-op\n    binary: true\n    consequence: reversible\n    \
             trusted: true\n    auto_promoted: true\n    promotion_stamp: definitely-stale\n",
    )
    .unwrap();
    cfg.verbs = Arc::new(RwLock::new(catalog));
    assert_ne!(
        cfg.evaluator.verb_promotion_stamp(),
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
    let current_stamp = cfg.evaluator.verb_promotion_stamp().to_string();
    let catalog = VerbCatalog::from_yaml(&format!(
        "verbs:\n\
             - name: fresh-auto\n  binary: true\n  consequence: reversible\n  trusted: true\n  \
             auto_promoted: true\n  promotion_stamp: {current_stamp}\n  evidence: fresh\n\
             - name: stale-auto\n  binary: true\n  consequence: reversible\n  trusted: true\n  \
             auto_promoted: true\n  promotion_stamp: definitely-stale\n  evidence: stale\n\
             - name: hand-authored\n  binary: true\n  consequence: reversible\n  trusted: true\n"
    ))
    .unwrap();
    cfg.verbs = Arc::new(RwLock::new(catalog));

    let response = handle_admin_request(
        &cfg,
        &CallerIdentity::Unix { uid: 1000 },
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
