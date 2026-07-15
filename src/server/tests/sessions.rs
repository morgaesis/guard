use crate::grant_profile::ProfileCatalog;
use crate::server::admin::handle_admin_request;
use crate::server::execute::{
    allow_session_auto_amend_candidate, deny_session_auto_amend_candidate, execute_command,
    session_source_from_eval,
};
use crate::server::transport::{claim_session_maintenance, session_maintenance_once};
use crate::server::wire::ExecOutcome;
use crate::server::wire::{AdminRequest, AdminResponse, CallerIdentity, ExecuteRequest};
use crate::session::{
    SessionDecision, SessionDecisionSource, SessionExactRule, SessionExecStatus, SessionGrant,
    SessionInteraction,
};
use crate::session_store::SessionStore;
use guard::gating::verb::VerbCatalog;
use guard::gating::GateMode;
use guard::principal::PrincipalKey;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::make_test_config;

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
            profile: None,
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
            profile: None,
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
            profile: None,
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
        result.policy_reason().contains("session static-only"),
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
    assert!(result.policy_reason().contains("static-only"));
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
            profile: None,
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
            profile: None,
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
            assert!(!visible.generated_notes.is_empty());
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
            profile: None,
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
            profile: None,
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
                profile: None,
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
    cfg.profiles = ProfileCatalog::from_yaml(
            "profiles:\n  - name: cert-manager-rotation\n    ttl_secs: 1800\n    allow:\n      - \"kubectl get certificate*\"\n    deny:\n      - \"kubectl delete namespace*\"\n    prompt_append: \"rotating cert-manager certificates\"\n",
        )
        .expect("valid profile catalog");

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
            profile: Some("cert-manager-rotation".into()),
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
    assert_eq!(summary.allow, vec!["kubectl get certificate*".to_string()]);
    assert_eq!(summary.deny, vec!["kubectl delete namespace*".to_string()]);
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
            profile: Some("does-not-exist".into()),
            static_only: false,
            auto_amend: false,
        },
    )
    .await;
    match resp {
        AdminResponse::Error { message } => {
            assert!(
                message.contains("unknown session profile") && message.contains("does-not-exist"),
                "expected a clear unknown-profile error, got: {message}"
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
    cfg.profiles = ProfileCatalog::from_yaml(
            "profiles:\n  - name: scoped\n    allow:\n      - \"kubectl get*\"\n    deny:\n      - \"kubectl delete*\"\n",
        )
        .expect("valid profile catalog");

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
            profile: Some("scoped".into()),
            static_only: false,
            auto_amend: false,
        },
    )
    .await;
    assert!(matches!(resp, AdminResponse::Ok));

    let reg = cfg.sessions.read().await;
    // A profile-derived grant behaves exactly like any other grant: its deny
    // glob short-circuits to Deny...
    assert!(matches!(
        reg.check(&token, "kubectl", &["delete".into(), "pod".into()], None),
        Some((SessionDecision::Deny, _))
    ));
    // ...its allow glob short-circuits to Allow...
    assert!(matches!(
        reg.check(&token, "kubectl", &["get".into(), "pods".into()], None),
        Some((SessionDecision::Allow, _))
    ));
    // ...and a command matching neither falls through to normal evaluation.
    assert!(
        reg.check(&token, "helm", &["list".into()], None).is_none(),
        "an unmatched command must fall through to the evaluator"
    );
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
