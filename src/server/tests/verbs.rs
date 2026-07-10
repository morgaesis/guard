use crate::evaluate::{EvalConfig, Evaluator};
use crate::server::admin::handle_admin_request;
use crate::server::execute::execute_command;
use crate::server::wire::{
    AdminRequest, AdminResponse, CallerIdentity, ExecuteRequest, GateStatus, VerbInvocation,
};
use guard::gating::verb::VerbCatalog;
use guard::gating::GateMode;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;

use super::make_test_config;

async fn capture_llm_requests(
    listener: tokio::net::TcpListener,
    request_tx: tokio::sync::mpsc::UnboundedSender<String>,
    count: usize,
) {
    let response_body = r#"{
        "choices": [{
            "message": {
                "tool_calls": [{
                    "id": "call-1",
                    "type": "function",
                    "function": {
                        "name": "decide",
                        "arguments": "{\"decision\":\"DENY\",\"reason\":\"model denied\",\"risk\":8,\"reversibility\":\"irreversible\"}"
                    }
                }]
            }
        }]
    }"#;

    for _ in 0..count {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut chunk = [0u8; 2048];
        loop {
            let read = stream.read(&mut chunk).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n")
            else {
                continue;
            };
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or_default();
            if request.len() >= header_end + 4 + content_length {
                break;
            }
        }

        let request_text = String::from_utf8(request).unwrap();
        let body = request_text.split_once("\r\n\r\n").unwrap().1.to_string();
        request_tx.send(body).unwrap();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();
    }
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
        stream: false,
        session_token: None,
        revert: None,
        confirm_within_secs: None,
        reevaluate: false,
        ssh_hostkey: None,
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
        stream: false,
        session_token: None,
        revert: None,
        confirm_within_secs: None,
        reevaluate: false,
        ssh_hostkey: None,
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
        stream: false,
        session_token: None,
        revert: None,
        confirm_within_secs: None,
        reevaluate: false,
        ssh_hostkey: None,
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
        stream: false,
        session_token: None,
        revert: None,
        confirm_within_secs: None,
        reevaluate: false,
        ssh_hostkey: None,
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
    assert!(
        response.reason.starts_with("verb 'auto-op': "),
        "a reverse-matched untrusted verb must be named in the returned reason: {}",
        response.reason
    );
}

#[tokio::test]
async fn verb_prompt_context_reaches_evaluator_for_explicit_and_reverse_match_paths() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (request_tx, mut request_rx) = tokio::sync::mpsc::unbounded_channel();
    let mock = tokio::spawn(capture_llm_requests(listener, request_tx, 2));

    let (mut cfg, _buf) = make_test_config();
    cfg.gate = GateMode::Consequence;
    cfg.evaluator = Arc::new(
        Evaluator::new(
            EvalConfig::default()
                .llm_api_key("test-key".to_string())
                .llm_api_url(format!("http://127.0.0.1:{port}"))
                .llm_retries(0)
                .cache_enabled(false)
                .gate_mode(GateMode::Consequence),
        )
        .unwrap(),
    );
    cfg.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            "verbs:\n  - name: context-op\n    binary: context-command\n    consequence: irreversible\n    prompt_context: verb operator context\n",
        )
        .unwrap(),
    ));

    let explicit = ExecuteRequest {
        binary: String::new(),
        args: Vec::new(),
        auth_token: None,
        env: HashMap::new(),
        secrets: HashMap::new(),
        stream: false,
        session_token: None,
        revert: None,
        confirm_within_secs: None,
        reevaluate: false,
        ssh_hostkey: None,
        require_approval: None,
        wait_approval_secs: None,
        verb: Some(VerbInvocation {
            name: "context-op".to_string(),
            params: std::collections::BTreeMap::new(),
        }),
    };
    let reverse_match = ExecuteRequest {
        binary: "context-command".to_string(),
        verb: None,
        ..explicit.clone()
    };

    for request in [explicit, reverse_match] {
        let result = execute_command(request, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;
        assert!(!result.policy_allowed());
        assert!(
            result.policy_reason().starts_with("verb 'context-op': "),
            "untrusted verb reason did not name the verb: {}",
            result.policy_reason()
        );
    }

    for _ in 0..2 {
        let body: serde_json::Value =
            serde_json::from_str(&request_rx.recv().await.unwrap()).unwrap();
        let system_prompt = body["messages"][0]["content"].as_str().unwrap();
        assert!(
            system_prompt.contains("verb operator context"),
            "verb prompt_context missing from evaluator request"
        );
    }
    mock.await.unwrap();
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
