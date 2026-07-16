use crate::evaluate::{EvalConfig, Evaluator};
use crate::grant_profile::{EvaluationMode, SavedGrantCatalog};
use crate::server::admin::handle_admin_request;
use crate::server::execute::{
    allow_session_auto_amend_candidate, deny_session_auto_amend_candidate, execute_command,
    session_source_from_eval,
};
use crate::server::transport::{claim_session_maintenance, session_maintenance_once};
use crate::server::wire::ExecOutcome;
use crate::server::wire::{AdminRequest, AdminResponse, CallerIdentity, ExecuteRequest};
use crate::session::{
    SessionDecisionSource, SessionExactRule, SessionExecStatus, SessionGrant, SessionInteraction,
};
use crate::session_store::SessionStore;
use guard::gating::verb::VerbCatalog;
use guard::gating::GateMode;
use guard::principal::PrincipalKey;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;

use super::{capture_async, make_test_config};

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
    }
}

async fn run_verb_synthesis_llm(listener: tokio::net::TcpListener) {
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(stream) => stream,
            Err(_) => return,
        };
        tokio::spawn(async move {
            let mut request = Vec::new();
            let mut chunk = [0u8; 2048];
            while let Ok(read) = stream.read(&mut chunk).await {
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
                if let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let content_length = headers
                        .split("\r\n")
                        .find_map(|line| {
                            line.strip_prefix("Content-Length: ")
                                .or_else(|| line.strip_prefix("content-length: "))
                                .and_then(|value| value.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if request.len() >= header_end + 4 + content_length {
                        break;
                    }
                }
            }
            let arguments = serde_json::json!({
                "name": "check-host",
                "description": "Inspect one host",
                "binary": "uptime",
                "args": [],
                "params": {},
                "consequence": "reversible",
                "trusted": false,
                "evidence": "The exact uptime command is read only."
            })
            .to_string();
            let body = serde_json::json!({
                "choices": [{
                    "message": {
                        "tool_calls": [{
                            "id": "verb-1",
                            "type": "function",
                            "function": {
                                "name": "create_verb",
                                "arguments": arguments
                            }
                        }]
                    }
                }],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
            })
            .to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

#[tokio::test]
async fn kubeconfig_issuance_is_local_live_session_scoped_and_secret_free() {
    let (cfg, audit) = make_test_config();
    let token = "finite-kube-session-token";
    let mut grant = granted_session(Vec::new(), Vec::new());
    grant.expires_at = Some(guard::env::now_unix() + 60);
    cfg.sessions.write().await.grant(token.to_string(), grant);

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
    cfg.protocol_registry
        .write()
        .await
        .insert("cluster-a".to_string(), Arc::new(proxy));

    let request = || AdminRequest::KubeconfigIssue {
        endpoint: "cluster-a".to_string(),
        session_token: token.to_string(),
    };
    let (response, logs) = capture_async(
        &audit,
        handle_admin_request(&cfg, &CallerIdentity::Unix { uid: 1_001 }, request()),
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

    assert!(matches!(
        handle_admin_request(&cfg, &CallerIdentity::Unix { uid: 1_002 }, request()).await,
        AdminResponse::KubeconfigIssued { .. }
    ));
    assert!(matches!(
        handle_admin_request(
            &cfg,
            &CallerIdentity::Tcp {
                token: "tcp-auth".to_string()
            },
            request()
        )
        .await,
        AdminResponse::Error { .. }
    ));

    cfg.sessions.write().await.revoke(token);
    assert!(matches!(
        handle_admin_request(&cfg, &CallerIdentity::Unix { uid: 1_001 }, request()).await,
        AdminResponse::Error { .. }
    ));

    let expired = "expired-kube-session";
    let mut expired_grant = granted_session(Vec::new(), Vec::new());
    expired_grant.expires_at = Some(guard::env::now_unix());
    cfg.sessions
        .write()
        .await
        .grant(expired.to_string(), expired_grant);
    assert!(matches!(
        handle_admin_request(
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
    cfg.daemon_uid = 777;
    cfg.daemon_principal = PrincipalKey::from_uid(777);
    cfg.verbs = Arc::new(RwLock::new(
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
    let daemon = CallerIdentity::Unix { uid: 777 };

    let valid = handle_admin_request(
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
        },
    )
    .await;
    assert!(matches!(valid, AdminResponse::Ok));

    let unknown_verb = handle_admin_request(
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
        },
    )
    .await;
    assert!(matches!(
        unknown_verb,
        AdminResponse::Error { message } if message.contains("unknown session verb")
    ));

    let unknown_marker = handle_admin_request(
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
    cfg.allowed_binaries = Some(vec!["echo".to_string()]);
    let token = format!("binary-floor-glob-{}", std::process::id());
    cfg.sessions.write().await.grant(
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
    cfg.allowed_binaries = Some(vec!["echo".to_string()]);
    let token = format!("binary-floor-exact-{}", std::process::id());
    cfg.sessions.write().await.grant(
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
    cfg.gate = GateMode::Consequence;
    let token = format!("session-gate-{}", std::process::id());
    cfg.sessions.write().await.grant(
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
    cfg.sessions.write().await.grant(
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
    cfg.sessions.write().await.grant(
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
        let mut sessions = cfg.sessions.write().await;
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

#[test]
fn session_source_reports_cache_separately_from_static_policy() {
    assert_eq!(
        session_source_from_eval(crate::evaluate::EvalSource::Cache),
        SessionDecisionSource::Cache
    );
    assert_eq!(
        session_source_from_eval(crate::evaluate::EvalSource::StaticPolicy),
        SessionDecisionSource::StaticPolicy
    );
}

#[test]
fn tcp_admin_token_validation_is_separate_from_exec_token() {
    let (mut cfg, _) = make_test_config();
    cfg.auth_token = Some("exec-token".into());
    cfg.admin_token = Some("admin-token".into());

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
}

#[tokio::test]
async fn session_list_is_user_visible_but_prompt_is_hidden() {
    let (mut cfg, _) = make_test_config();
    cfg.daemon_uid = 777;
    cfg.daemon_principal = PrincipalKey::from_uid(777);

    let daemon = CallerIdentity::Unix { uid: 777 };
    let user = CallerIdentity::Unix { uid: 20_002 };
    let token = format!("session-{}", std::process::id());

    let grant = handle_admin_request(
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
        },
    )
    .await;
    assert!(matches!(grant, AdminResponse::Ok));

    let listed = handle_admin_request(
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
        AdminResponse::SessionList { grants, .. } => {
            let grant = grants.iter().find(|grant| grant.token == token).is_none();
            assert!(grant, "non-daemon callers must not receive bearer tokens");
            let hidden = grants
                .iter()
                .find(|grant| grant.token == "(hidden)")
                .expect("redacted session grant visible to user");
            assert!(hidden.allow.is_empty());
            assert!(hidden.deny.is_empty());
            assert!(hidden.allow_exact.is_empty());
            assert!(hidden.deny_exact.is_empty());
            assert_eq!(hidden.prompt_append.as_deref(), Some("(hidden)"));
            assert!(hidden.generated_notes.is_empty());
        }
        other => panic!("unexpected {:?}", other),
    }
}

#[tokio::test]
async fn session_list_shows_current_session_details_without_raw_token_for_user() {
    let (mut cfg, _) = make_test_config();
    cfg.daemon_uid = 777;
    cfg.daemon_principal = PrincipalKey::from_uid(777);

    let daemon = CallerIdentity::Unix { uid: 777 };
    let user = CallerIdentity::Unix { uid: 20_002 };
    let token = format!("session-visible-{}", std::process::id());

    let grant = handle_admin_request(
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
        },
    )
    .await;
    assert!(matches!(grant, AdminResponse::Ok));

    let listed = handle_admin_request(
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
async fn session_show_reports_recent_stats() {
    let (mut cfg, _) = make_test_config();
    cfg.daemon_uid = 777;
    cfg.daemon_principal = PrincipalKey::from_uid(777);

    let daemon = CallerIdentity::Unix { uid: 777 };
    let token = format!("session-show-{}", std::process::id());

    let grant = handle_admin_request(
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
        },
    )
    .await;
    assert!(matches!(grant, AdminResponse::Ok));

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);

    {
        let mut reg = cfg.sessions.write().await;
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

    let show = handle_admin_request(
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
    cfg.daemon_uid = 777;
    cfg.daemon_principal = PrincipalKey::from_uid(777);

    let daemon = CallerIdentity::Unix { uid: 777 };
    let user = CallerIdentity::Unix { uid: 20_003 };
    let token = format!("session-self-{}", std::process::id());

    let grant = handle_admin_request(
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
        },
    )
    .await;
    assert!(matches!(grant, AdminResponse::Ok));

    // The holder presents its own token as both identity and target.
    let show = handle_admin_request(
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
    cfg.daemon_uid = 777;
    cfg.daemon_principal = PrincipalKey::from_uid(777);
    let token = "status-bearer-must-not-be-returned".to_string();
    cfg.sessions
        .write()
        .await
        .grant(token.clone(), granted_session(Vec::new(), Vec::new()));
    cfg.sessions.write().await.record_interaction(
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

    let response = handle_admin_request(
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
    cfg.daemon_uid = 777;
    cfg.daemon_principal = PrincipalKey::from_uid(777);

    let daemon = CallerIdentity::Unix { uid: 777 };
    let attacker = CallerIdentity::Unix { uid: 20_004 };
    let token_a = format!("session-a-{}", std::process::id());
    let token_b = format!("session-b-{}", std::process::id());

    for token in [&token_a, &token_b] {
        let grant = handle_admin_request(
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
            },
        )
        .await;
        assert!(matches!(grant, AdminResponse::Ok));
    }

    // Holder of A tries to inspect B's grant by naming B as the target.
    let show = handle_admin_request(
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
                message.contains("only inspect its own grant"),
                "expected a clear authorization denial, got: {message}"
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
    cfg.daemon_uid = 777;
    cfg.daemon_principal = PrincipalKey::from_uid(777);
    cfg.saved_grants = std::sync::Arc::new(tokio::sync::RwLock::new(
        SavedGrantCatalog::from_yaml(
            "profiles:\n  - name: cert-manager-rotation\n    ttl_secs: 1800\n    allow:\n      - \"kubectl get certificate *\"\n    deny:\n      - \"kubectl delete namespace *\"\n    prompt_append: \"rotating cert-manager certificates\"\n",
        )
        .expect("valid saved grant catalog"),
    ));

    let daemon = CallerIdentity::Unix { uid: 777 };
    let token = format!("session-profile-{}", std::process::id());

    // Profile-only: no explicit allow/deny/ttl/prompt on the request.
    let resp = handle_admin_request(
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
        },
    )
    .await;
    assert!(matches!(resp, AdminResponse::Ok));

    let reg = cfg.sessions.read().await;
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
    cfg.daemon_uid = 777;
    cfg.daemon_principal = PrincipalKey::from_uid(777);
    // The profile catalog is left empty.

    let daemon = CallerIdentity::Unix { uid: 777 };
    let token = format!("session-badprofile-{}", std::process::id());
    let resp = handle_admin_request(
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
    let reg = cfg.sessions.read().await;
    assert!(
        reg.list().into_iter().all(|g| g.token != token),
        "no grant should be installed for an unknown profile"
    );
}

#[tokio::test]
async fn profile_grant_still_deny_short_circuits_and_falls_through() {
    let (mut cfg, _) = make_test_config();
    cfg.daemon_uid = 777;
    cfg.daemon_principal = PrincipalKey::from_uid(777);
    cfg.saved_grants = std::sync::Arc::new(tokio::sync::RwLock::new(
        SavedGrantCatalog::from_yaml(
            "profiles:\n  - name: scoped\n    allow:\n      - \"kubectl get *\"\n    deny:\n      - \"kubectl delete *\"\n",
        )
        .expect("valid saved grant catalog"),
    ));

    let daemon = CallerIdentity::Unix { uid: 777 };
    let token = format!("session-profcheck-{}", std::process::id());
    let resp = handle_admin_request(
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
        },
    )
    .await;
    assert!(matches!(resp, AdminResponse::Ok));

    let reg = cfg.sessions.read().await;
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
    cfg.daemon_uid = 777;
    cfg.daemon_principal = PrincipalKey::from_uid(777);
    cfg.saved_grants = Arc::new(RwLock::new(
        SavedGrantCatalog::from_yaml(
            "grants:\n  - name: bounded\n    prompt_append: bounded task\n    ttl_secs: 300\n    auto_approve_requests: true\n  - name: other\n    prompt_append: other task\n    ttl_secs: 3600\n    auto_approve_requests: true\n",
        )
        .expect("saved grants"),
    ));
    let daemon = CallerIdentity::Unix { uid: 777 };
    let worker = CallerIdentity::Unix { uid: 778 };
    let token = "bounded-session".to_string();
    assert!(matches!(
        handle_admin_request(
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
            },
        )
        .await,
        AdminResponse::Ok
    ));

    let mismatched = handle_admin_request(
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

    let approved = handle_admin_request(
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
    cfg.sessions.write().await.grant(
        "other-live-session".to_string(),
        granted_session(Vec::new(), Vec::new()),
    );

    let unscoped = handle_admin_request(
        &cfg,
        &worker,
        AdminRequest::GrantRequestList {
            session_token: None,
            caller_token: None,
        },
    )
    .await;
    assert!(matches!(unscoped, AdminResponse::Error { .. }));
    let scoped = handle_admin_request(
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

    let cross_session = handle_admin_request(
        &cfg,
        &worker,
        AdminRequest::GrantRequestList {
            session_token: Some(token),
            caller_token: Some("other-live-session".to_string()),
        },
    )
    .await;
    assert!(matches!(
        cross_session,
        AdminResponse::Error { message } if message.contains("only list its own")
    ));

    let admin = handle_admin_request(
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
    cfg.daemon_uid = 777;
    cfg.daemon_principal = PrincipalKey::from_uid(777);
    cfg.behavior_limits.max_denials = Some(1);
    let worker = CallerIdentity::Unix { uid: 778 };
    for token in ["suspended-request", "quota-request", "large-request"] {
        cfg.sessions
            .write()
            .await
            .grant(token.to_string(), granted_session(Vec::new(), Vec::new()));
    }
    cfg.sessions.write().await.record_interaction(
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
        handle_admin_request(
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
        cfg.grant_requests
            .write()
            .await
            .insert(request.handle.clone(), request);
    }
    assert!(matches!(
        handle_admin_request(
            &cfg,
            &worker,
            submit("quota-request", "one more".to_string(), "scope".to_string()),
        )
        .await,
        AdminResponse::Error { message } if message.contains("per session")
    ));

    let half = "x".repeat(crate::server::admin::MAX_GRANT_REQUEST_PAYLOAD_BYTES / 2 + 1);
    assert!(matches!(
        handle_admin_request(
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
    cfg.daemon_uid = 777;
    cfg.daemon_principal = PrincipalKey::from_uid(777);
    cfg.saved_grants = Arc::new(RwLock::new(
        SavedGrantCatalog::from_yaml(
            "grants:\n  - name: automatic\n    ttl_secs: 300\n    prompt_append: automatic work\n    auto_approve_requests: true\n  - name: reviewed\n    ttl_secs: 300\n    prompt_append: reviewed work\n    auto_approve_requests: false\n",
        )
        .unwrap(),
    ));
    let tmp = tempfile::tempdir().unwrap();
    cfg.session_store = Some(
        SessionStore::open(tmp.path().join("state.db"), 3600)
            .await
            .unwrap(),
    );
    let daemon = CallerIdentity::Unix { uid: 777 };
    let worker = CallerIdentity::Unix { uid: 778 };
    for (token, saved_grant) in [
        ("automatic-approval", "automatic"),
        ("operator-approval", "reviewed"),
    ] {
        assert!(matches!(
            handle_admin_request(
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
        .sessions
        .read()
        .await
        .effective_revision_key("automatic-approval");
    cfg.session_store
        .as_ref()
        .unwrap()
        .fail_next_approval_for_test();
    assert!(matches!(
        handle_admin_request(&cfg, &worker, submit("automatic-approval")).await,
        AdminResponse::Error { message } if message.contains("approval transaction failure")
    ));
    assert_eq!(
        cfg.sessions
            .read()
            .await
            .effective_revision_key("automatic-approval"),
        auto_revision
    );

    let reviewed_revision = cfg
        .sessions
        .read()
        .await
        .effective_revision_key("operator-approval");
    let response = handle_admin_request(&cfg, &worker, submit("operator-approval")).await;
    let AdminResponse::GrantRequest { request } = response else {
        panic!("expected pending request")
    };
    cfg.session_store
        .as_ref()
        .unwrap()
        .fail_next_approval_for_test();
    assert!(matches!(
        handle_admin_request(
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
        cfg.sessions
            .read()
            .await
            .effective_revision_key("operator-approval"),
        reviewed_revision
    );
    assert_eq!(
        cfg.grant_requests.read().await[&request.handle].status,
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
        cfg.daemon_uid = 777;
        cfg.daemon_principal = PrincipalKey::from_uid(777);
        cfg.saved_grants = Arc::new(RwLock::new(
            SavedGrantCatalog::from_yaml(
                "grants:\n  - name: reviewed\n    ttl_secs: 300\n    prompt_append: reviewed work\n    auto_approve_requests: false\n",
            )
            .unwrap(),
        ));
        let tmp = tempfile::tempdir().unwrap();
        cfg.session_store = Some(
            SessionStore::open(tmp.path().join("state.db"), 3600)
                .await
                .unwrap(),
        );
        let token = format!("terminal-race-{}", competing_status.as_str());
        let daemon = CallerIdentity::Unix { uid: 777 };
        let worker = CallerIdentity::Unix { uid: 778 };
        assert!(matches!(
            handle_admin_request(
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
                },
            )
            .await,
            AdminResponse::Ok
        ));
        let issued_revision = cfg.sessions.read().await.effective_revision_key(&token);
        let submitted = handle_admin_request(
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
            handle_admin_request(
                &approve_cfg,
                &CallerIdentity::Unix { uid: 777 },
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
            handle_admin_request(&competing_cfg, &CallerIdentity::Unix { uid: 777 }, request).await
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

        let store = cfg.session_store.as_ref().unwrap();
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
            cfg.grant_requests.read().await[&handle].status,
            durable.status
        );
        let live_revision = cfg.sessions.read().await.effective_revision_key(&token);
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
    cfg.daemon_uid = 777;
    cfg.daemon_principal = PrincipalKey::from_uid(777);
    let daemon = CallerIdentity::Unix { uid: 777 };
    let source = SavedGrantCatalog::from_yaml(
        "grants:\n  - name: editable\n    description: original\n    activated_verbs: [inspect]\n    override_markers: [operator:inspect]\n    secret_names: [service/*]\n    ttl_secs: 300\n    prompt_append: original prompt\n    auto_approve_requests: true\n",
    )
    .unwrap();
    let grant = source.get("editable").unwrap().clone();
    assert!(matches!(
        handle_admin_request(&cfg, &daemon, AdminRequest::SavedGrantSave { grant }).await,
        AdminResponse::SavedGrant { .. }
    ));

    let edited = handle_admin_request(
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

    let cleared_prompt = handle_admin_request(
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
    cfg.evaluator = Arc::new(evaluator("regime-a"));
    cfg.saved_grants = Arc::new(RwLock::new(
        SavedGrantCatalog::from_yaml(
            "grants:\n  - name: bounded\n    prompt_append: inspect one host\n",
        )
        .unwrap(),
    ));
    cfg.daemon_principal = PrincipalKey::from_uid(cfg.daemon_uid);
    let daemon = CallerIdentity::Unix {
        uid: cfg.daemon_uid,
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

    let response = handle_admin_request(&cfg, &daemon, preview()).await;
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
    assert_eq!(regime, cfg.evaluator.verb_promotion_stamp());
    assert!(cfg
        .saved_grants
        .read()
        .await
        .get("bounded")
        .unwrap()
        .generated_verbs
        .is_empty());
    let applied = handle_admin_request(&cfg, &daemon, apply(proposal_id)).await;
    let AdminResponse::SavedGrantRegenerated { grant, .. } = applied else {
        panic!("expected exact regeneration apply, got {applied:?}");
    };
    assert_eq!(grant.revision, 2);
    assert_eq!(
        serde_json::to_value(&grant.generated_verbs[0]).unwrap(),
        serde_json::to_value(&candidate).unwrap(),
        "apply must install the exact previewed candidate"
    );

    let revision_preview = handle_admin_request(&cfg, &daemon, preview()).await;
    let AdminResponse::SavedGrantRegenerationProposal {
        proposal_id: stale_revision,
        ..
    } = revision_preview
    else {
        panic!()
    };
    assert!(matches!(
        handle_admin_request(&cfg, &daemon, edit_description()).await,
        AdminResponse::SavedGrant { .. }
    ));
    assert!(matches!(
        handle_admin_request(&cfg, &daemon, apply(stale_revision)).await,
        AdminResponse::Error { message } if message.contains("revision changed")
    ));

    let regime_preview = handle_admin_request(&cfg, &daemon, preview()).await;
    let AdminResponse::SavedGrantRegenerationProposal {
        proposal_id: stale_regime,
        ..
    } = regime_preview
    else {
        panic!()
    };
    cfg.evaluator = Arc::new(evaluator("regime-b"));
    assert!(matches!(
        handle_admin_request(&cfg, &daemon, apply(stale_regime)).await,
        AdminResponse::Error { message } if message.contains("evaluator regime changed")
    ));
}

#[tokio::test]
async fn grant_request_show_and_withdraw_require_the_issuing_session() {
    let (mut cfg, _) = make_test_config();
    cfg.daemon_uid = 777;
    cfg.daemon_principal = PrincipalKey::from_uid(777);
    let daemon = CallerIdentity::Unix { uid: 777 };
    let worker = CallerIdentity::Unix { uid: 778 };
    cfg.sessions.write().await.grant(
        "owner-session".to_string(),
        granted_session(Vec::new(), Vec::new()),
    );
    cfg.sessions.write().await.grant(
        "victim-session".to_string(),
        granted_session(Vec::new(), Vec::new()),
    );
    let cross_session = handle_admin_request(
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
        AdminResponse::Error { message } if message.contains("only request changes to itself")
    ));
    assert!(matches!(
        handle_admin_request(
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
    let submitted = handle_admin_request(
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
        handle_admin_request(
            &cfg,
            &worker,
            AdminRequest::GrantRequestShow {
                handle: handle.clone(),
                session_token: Some("other-session".to_string()),
            },
        )
        .await,
        handle_admin_request(
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
        handle_admin_request(
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
        handle_admin_request(
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
    cfg.daemon_uid = 777;
    cfg.daemon_principal = PrincipalKey::from_uid(777);
    let tmp = tempfile::tempdir().unwrap();
    cfg.session_store = Some(
        SessionStore::open(tmp.path().join("state.db"), 3600)
            .await
            .unwrap(),
    );
    let token = "persisted-request-owner".to_string();
    cfg.sessions
        .write()
        .await
        .grant(token.clone(), granted_session(Vec::new(), Vec::new()));
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
    cfg.grant_requests
        .write()
        .await
        .insert(handle.clone(), request.clone());
    let store = cfg.session_store.as_ref().unwrap();
    store.save_grant_request(request.clone()).await.unwrap();
    store.fail_next_write_for_test();

    let response = handle_admin_request(
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
        cfg.grant_requests.read().await[&handle].status,
        crate::grant_profile::GrantRequestStatus::Pending
    );
    assert_eq!(
        store.load_grant_requests().await.unwrap()[0].status,
        crate::grant_profile::GrantRequestStatus::Pending
    );

    request.expires_unix = 1;
    cfg.grant_requests
        .write()
        .await
        .insert(handle.clone(), request.clone());
    store.save_grant_request(request).await.unwrap();
    store.fail_next_write_for_test();
    crate::server::admin::prune_grant_requests(&cfg).await;
    assert!(cfg.grant_requests.read().await.contains_key(&handle));
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
    cfg.daemon_uid = 777;
    cfg.daemon_principal = PrincipalKey::from_uid(777);
    cfg.behavior_limits.max_denials = Some(1);
    let daemon = CallerIdentity::Unix { uid: 777 };
    let worker = CallerIdentity::Unix { uid: 778 };
    for token in ["batch-owner", "batch-victim"] {
        cfg.sessions
            .write()
            .await
            .grant(token.to_string(), granted_session(Vec::new(), Vec::new()));
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
        handle_admin_request(&cfg, &worker, evaluate(None, None)).await,
        AdminResponse::Error { message } if message.contains("caller-owned session")
    ));
    assert!(matches!(
        handle_admin_request(
            &cfg,
            &worker,
            evaluate(Some("batch-victim".to_string()), Some("batch-owner".to_string())),
        )
        .await,
        AdminResponse::Error { message } if message.contains("only batch-evaluate for itself")
    ));
    let before = (
        cfg.approvals.read().await.list().len(),
        cfg.provisional.read().await.list().len(),
        cfg.read_grants.read().await.list().len(),
        cfg.grant_requests.read().await.len(),
        cfg.verbs.read().await.list().len(),
        cfg.sessions.read().await.interactions_snapshot().len(),
    );
    assert!(matches!(
        handle_admin_request(
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
        cfg.approvals.read().await.list().len(),
        cfg.provisional.read().await.list().len(),
        cfg.read_grants.read().await.list().len(),
        cfg.grant_requests.read().await.len(),
        cfg.verbs.read().await.list().len(),
        cfg.sessions.read().await.interactions_snapshot().len(),
    );
    assert_eq!(
        after, before,
        "batch preview must have no durable side effects"
    );
    assert!(matches!(
        handle_admin_request(&cfg, &daemon, evaluate(None, None)).await,
        AdminResponse::EvaluationBatch { .. }
    ));

    cfg.sessions.write().await.record_interaction(
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
        handle_admin_request(
            &cfg,
            &worker,
            evaluate(Some("batch-owner".to_string()), Some("batch-owner".to_string())),
        )
        .await,
        AdminResponse::Error { message } if message.contains("suspended")
    ));
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
    cfg.evaluator = Arc::new(evaluator);
    let token = "batch-cache-owner".to_string();
    let mut grant = granted_session(Vec::new(), Vec::new());
    grant.static_only = false;
    cfg.sessions.write().await.grant(token.clone(), grant);
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

    let response = handle_admin_request(
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
    let admission = cfg.command_admission.snapshot();
    assert_eq!(admission.handler_admitted, 3);
    assert_eq!(admission.evaluator_admitted, 3);
}

#[tokio::test]
async fn grant_request_approval_rejects_expiry_and_stale_saved_revision() {
    let (mut cfg, _) = make_test_config();
    cfg.daemon_uid = 777;
    cfg.daemon_principal = PrincipalKey::from_uid(777);
    cfg.saved_grants = Arc::new(RwLock::new(
        SavedGrantCatalog::from_yaml(
            "grants:\n  - name: reviewed\n    prompt_append: reviewed task\n    auto_approve_requests: false\n",
        )
        .unwrap(),
    ));
    let daemon = CallerIdentity::Unix { uid: 777 };
    let worker = CallerIdentity::Unix { uid: 778 };
    let token = "revision-session".to_string();
    assert!(matches!(
        handle_admin_request(
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
    let first = handle_admin_request(&cfg, &worker, submit("expired")).await;
    let AdminResponse::GrantRequest { request } = first else {
        panic!()
    };
    cfg.grant_requests
        .write()
        .await
        .get_mut(&request.handle)
        .unwrap()
        .expires_unix = 1;
    assert!(matches!(
        handle_admin_request(&cfg, &daemon, AdminRequest::GrantRequestApprove { handle: request.handle }).await,
        AdminResponse::Error { message } if message.contains("expired")
    ));

    let second = handle_admin_request(&cfg, &worker, submit("stale")).await;
    let AdminResponse::GrantRequest { request } = second else {
        panic!()
    };
    assert!(matches!(
        handle_admin_request(
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
        handle_admin_request(&cfg, &daemon, AdminRequest::GrantRequestApprove { handle: request.handle }).await,
        AdminResponse::Error { message } if message.contains("changed after request issuance")
    ));
}

#[tokio::test]
async fn grant_request_binds_unsaved_session_revision_and_prunes_expired_rows() {
    let (mut cfg, _) = make_test_config();
    cfg.daemon_uid = 777;
    cfg.daemon_principal = PrincipalKey::from_uid(777);
    let tmp = tempfile::tempdir().unwrap();
    cfg.session_store = Some(
        SessionStore::open(tmp.path().join("state.db"), 3600)
            .await
            .unwrap(),
    );
    let daemon = CallerIdentity::Unix { uid: 777 };
    let worker = CallerIdentity::Unix { uid: 778 };
    let token = "unsaved-revision".to_string();
    cfg.sessions
        .write()
        .await
        .grant(token.clone(), granted_session(Vec::new(), Vec::new()));
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

    let stale = handle_admin_request(&cfg, &worker, submit("stale")).await;
    let AdminResponse::GrantRequest { request } = stale else {
        panic!()
    };
    cfg.sessions
        .write()
        .await
        .set_label(&token, Some("changed".to_string()));
    assert!(matches!(
        handle_admin_request(
            &cfg,
            &daemon,
            AdminRequest::GrantRequestApprove { handle: request.handle },
        )
        .await,
        AdminResponse::Error { message } if message.contains("session revision")
    ));

    let expired = handle_admin_request(&cfg, &worker, submit("expire")).await;
    let AdminResponse::GrantRequest { request } = expired else {
        panic!()
    };
    let mut expired_row = cfg
        .grant_requests
        .write()
        .await
        .get_mut(&request.handle)
        .unwrap()
        .clone();
    expired_row.expires_unix = 1;
    cfg.grant_requests
        .write()
        .await
        .insert(request.handle.clone(), expired_row.clone());
    cfg.session_store
        .as_ref()
        .unwrap()
        .save_grant_request(expired_row)
        .await
        .unwrap();
    let _ = handle_admin_request(
        &cfg,
        &worker,
        AdminRequest::GrantRequestList {
            session_token: Some(token.clone()),
            caller_token: Some(token),
        },
    )
    .await;
    assert!(!cfg
        .grant_requests
        .read()
        .await
        .contains_key(&request.handle));
    assert!(cfg
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
    cfg.daemon_uid = 777;
    cfg.daemon_principal = PrincipalKey::from_uid(777);
    let worker = CallerIdentity::Unix { uid: 778 };
    let token = "bounded-queue-0".to_string();
    cfg.sessions
        .write()
        .await
        .grant(token.clone(), granted_session(Vec::new(), Vec::new()));
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
        cfg.grant_requests
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
        handle_admin_request(&cfg, &worker, submit()).await,
        AdminResponse::Error { message } if message.contains("queue is full")
    ));
    cfg.grant_requests
        .write()
        .await
        .values_mut()
        .find(|request| request.session_token == token)
        .unwrap()
        .expires_unix = 1;
    assert!(matches!(
        handle_admin_request(&cfg, &worker, submit()).await,
        AdminResponse::GrantRequest { .. }
    ));
    assert_eq!(cfg.grant_requests.read().await.len(), 1024);
}

#[tokio::test]
async fn session_maintenance_has_one_owner_and_skips_noop_persistence() {
    let (mut cfg, _) = make_test_config();
    let tmp = tempfile::tempdir().expect("tempdir");
    cfg.session_store = Some(
        SessionStore::open(tmp.path().join("state.db"), 3600)
            .await
            .expect("open store"),
    );
    cfg.sessions.write().await.grant(
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
