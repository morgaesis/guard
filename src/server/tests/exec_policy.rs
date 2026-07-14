use crate::server::admin::handle_admin_request;
#[cfg(windows)]
use crate::server::binary_path_candidates;
use crate::server::execute::{audit_command_line, audit_token, execute_command};
use crate::server::gate_runtime::binary_allowed;
use crate::server::transport::emit_audit_events;
use crate::server::wire::{
    AdminRequest, AdminResponse, CallerIdentity, ExecOutcome, ExecuteRequest, ExecuteResult,
};
use crate::server::{
    binary_exists_on_path, dangerous_env_name, deterministic_credential_deny_reason,
    deterministic_safe_allow_reason, invalid_shell_secret_reference, is_valid_secret_key,
    validate_request_injections,
};
use crate::session::SessionGrant;
use guard::evaluate::{EvalConfig, Evaluator};
use guard::gating::deny_shape::{DenyLearningConfig, DenyShapeStore};
use guard::principal::PrincipalKey;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;

use super::{args, capture, make_test_config, paranoid_test_config};

#[test]
fn audit_command_line_masks_inline_credentials() {
    let line = audit_command_line(
        "mysql",
        &[
            "-u".to_string(),
            "root".to_string(),
            "--password=hunter2sekrit".to_string(),
        ],
    );
    assert!(!line.contains("hunter2sekrit"), "got: {line}");
    assert!(line.contains("mysql"), "command shape survives: {line}");

    let line = audit_command_line(
        "curl",
        &[
            "-H".to_string(),
            "Authorization: Bearer sk-live-abcdef1234567890".to_string(),
            "https://api.example.com".to_string(),
        ],
    );
    assert!(!line.contains("sk-live-abcdef1234567890"), "got: {line}");
    assert!(line.contains("curl"), "got: {line}");
}

/// Tokens in audit lines are truncated head/tail; short and multi-byte
/// values must not panic or leak.
#[test]
fn audit_token_truncates_and_is_char_safe() {
    assert_eq!(audit_token("abcdefghij"), "abcd...ghij");
    assert_eq!(audit_token("short"), "***");
    // Multi-byte chars: byte slicing would panic here.
    let t = audit_token("éééééééééé");
    assert!(t.starts_with("éééé"), "got: {t}");
    assert!(!t.contains("éééééééééé"), "full value never appears: {t}");
}

// ---- ExecuteResult result-shape tests -----------------------------------

#[test]
fn binary_exists_on_path_rejects_natural_language_token() {
    assert!(!binary_exists_on_path(
        "Give-this-should-not-exist-as-a-real-command"
    ));
}

#[cfg(windows)]
#[test]
fn binary_path_candidates_include_windows_pathext() {
    let candidates = binary_path_candidates(std::path::Path::new("C:\\Tools"), "ssh");
    assert!(candidates.iter().any(|path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .map(|name| name.eq_ignore_ascii_case("ssh.exe"))
            .unwrap_or(false)
    }));
}

#[test]
fn credential_preflight_denies_kubectl_raw_config_through_shell() {
    let args = vec![
        "-c".to_string(),
        "kubectl config view --raw >/dev/null && echo ok".to_string(),
    ];
    let reason = deterministic_credential_deny_reason("sh", &args)
        .expect("kubectl raw config should be denied");
    assert!(reason.contains("kubeconfig"));
}

#[test]
fn credential_preflight_denies_private_key_path() {
    let args = vec![
        "-c".to_string(),
        "cat /var/lib/guard/.ssh/guard-admin >/dev/null".to_string(),
    ];
    let reason = deterministic_credential_deny_reason("sh", &args)
        .expect("guard private key path should be denied");
    assert!(reason.contains("credential material"));
}

#[test]
fn credential_preflight_allows_basic_kubectl_inspection() {
    let args = vec!["get".to_string(), "namespaces".to_string()];
    assert!(deterministic_credential_deny_reason("kubectl", &args).is_none());
}

#[test]
fn binary_allowlist_none_allows_everything() {
    assert!(binary_allowed(&None, "kubectl"));
    assert!(binary_allowed(&None, "/tmp/whatever"));
}

#[test]
fn binary_allowlist_matches_bare_name_case_insensitively() {
    let allow = Some(vec!["kubectl".to_string(), "git".to_string()]);
    assert!(binary_allowed(&allow, "kubectl"));
    assert!(binary_allowed(&allow, "KUBECTL"));
    assert!(binary_allowed(&allow, "kubectl.exe"));
    assert!(binary_allowed(&allow, "git"));
    assert!(!binary_allowed(&allow, "helm"));
}

#[test]
fn binary_allowlist_rejects_path_qualified_spoof() {
    // A payload placed at an arbitrary path and named after an allowed tool
    // must NOT pass via basename matching; only an exact path entry allows
    // a path-qualified binary.
    let allow = Some(vec!["kubectl".to_string()]);
    assert!(!binary_allowed(&allow, "/tmp/evil/kubectl"));
    assert!(!binary_allowed(&allow, "./kubectl"));
    assert!(!binary_allowed(&allow, r"C:\tmp\kubectl.exe"));

    let allow_path = Some(vec!["/usr/bin/kubectl".to_string()]);
    assert!(binary_allowed(&allow_path, "/usr/bin/kubectl"));
    assert!(!binary_allowed(&allow_path, "kubectl"));
    assert!(!binary_allowed(&allow_path, "/tmp/kubectl"));
}

#[test]
fn binary_allowlist_empty_denies_everything() {
    let allow = Some(vec![]);
    assert!(!binary_allowed(&allow, "kubectl"));
    assert!(!binary_allowed(&allow, "/usr/bin/anything"));
}

#[test]
fn secret_key_validation_allows_namespaced_keys() {
    assert!(is_valid_secret_key("opnsense-apikey-secret"));
    assert!(is_valid_secret_key("atlas/opnsense-apikey"));
    assert!(!is_valid_secret_key("../opnsense"));
    assert!(!is_valid_secret_key("atlas/../opnsense"));
    assert!(!is_valid_secret_key("bad key"));
    assert!(!is_valid_secret_key("/absolute"));
}

#[test]
fn invalid_shell_secret_reference_points_to_injected_env() {
    let reason = invalid_shell_secret_reference(
        "echo '$opnsense-apikey-secret'",
        "OPNSENSE_APIKEY_SECRET",
        "opnsense-apikey-secret",
    )
    .expect("dashed shell-style reference should be rejected");
    assert!(reason.contains("$OPNSENSE_APIKEY_SECRET"));
}

#[tokio::test]
async fn env_and_secret_injections_cannot_target_same_env_var() {
    let (cfg, _) = make_test_config();
    let request = ExecuteRequest {
        binary: "echo".to_string(),
        args: vec!["ok".to_string()],
        auth_token: None,
        env: HashMap::from([("API_TOKEN".to_string(), "plain".to_string())]),
        secrets: HashMap::from([("API_TOKEN".to_string(), "api/token".to_string())]),
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

    let err = validate_request_injections(
        &request,
        &cfg,
        &CallerIdentity::Unix { uid: 1000 },
        "echo ok",
    )
    .await
    .unwrap_err();

    assert!(err.contains("conflicting injection for 'API_TOKEN'"));
}

#[tokio::test]
async fn injection_refuses_non_local_tcp_caller() {
    let (cfg, _) = make_test_config();
    let request = ExecuteRequest {
        binary: "echo".to_string(),
        args: vec!["ok".to_string()],
        auth_token: None,
        env: HashMap::new(),
        secrets: HashMap::from([("API_TOKEN".to_string(), "api/token".to_string())]),
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
    // A bearer-token TCP caller carries a token principal but is NOT a
    // kernel-verified local peer; secret/env injection must be refused so a
    // remote token-holder cannot control the child's environment.
    for caller in [
        CallerIdentity::Tcp {
            token: "exec-token".into(),
        },
        CallerIdentity::TcpAdmin {
            token: "admin-token".into(),
        },
        CallerIdentity::Unknown,
    ] {
        let err = validate_request_injections(&request, &cfg, &caller, "echo ok")
            .await
            .unwrap_err();
        assert!(
            err.contains("authenticated local caller"),
            "caller {caller:?} must be refused injection, got: {err}"
        );
    }
    // A local Unix caller passes the transport check (it fails later only if
    // the secret is absent, never with the local-caller refusal).
    if let Err(e) = validate_request_injections(
        &request,
        &cfg,
        &CallerIdentity::Unix { uid: 1000 },
        "echo ok",
    )
    .await
    {
        assert!(
            !e.contains("authenticated local caller"),
            "local caller wrongly refused: {e}"
        );
    }
}

#[tokio::test]
async fn missing_requested_secret_denies_before_policy_evaluation() {
    let (cfg, _) = make_test_config();
    let request = ExecuteRequest {
        binary: "echo".to_string(),
        args: vec!["$NONEXISTING_SEC".to_string()],
        auth_token: None,
        env: HashMap::new(),
        secrets: HashMap::from([("NONEXISTING_SEC".to_string(), "nonexisting_sec".to_string())]),
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
    assert!(!result.policy_allowed());
    assert!(result.policy_reason().contains("secret not found"));
}

#[tokio::test]
async fn invalid_secret_shell_reference_denies_before_policy_evaluation() {
    let (cfg, _) = make_test_config();
    cfg.secrets
        .set(
            &PrincipalKey::from_uid(1000),
            "opnsense-apikey-secret",
            "dummy_api_key_12345",
        )
        .await
        .unwrap();
    let request = ExecuteRequest {
        binary: "echo".to_string(),
        args: vec!["$opnsense-apikey-secret".to_string()],
        auth_token: None,
        env: HashMap::new(),
        secrets: HashMap::from([(
            "OPNSENSE_APIKEY_SECRET".to_string(),
            "opnsense-apikey-secret".to_string(),
        )]),
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
    assert!(!result.policy_allowed());
    assert!(result
        .policy_reason()
        .contains("invalid secret environment reference"));
}

async fn run_denying_llm(listener: tokio::net::TcpListener) {
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(stream) => stream,
            Err(_) => return,
        };
        tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut tmp = [0u8; 2048];
            while let Ok(n) = stream.read(&mut tmp).await {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&buf[..pos]);
                    let content_length = headers
                        .split("\r\n")
                        .find_map(|line| {
                            line.strip_prefix("Content-Length: ")
                                .or_else(|| line.strip_prefix("content-length: "))
                                .and_then(|value| value.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if buf.len() >= pos + 4 + content_length {
                        break;
                    }
                }
            }
            let args = serde_json::json!({
                "decision": "DENY",
                "reason": "destructive request",
                "risk": 9
            })
            .to_string();
            let body = serde_json::json!({
                "choices": [{
                    "message": {
                        "tool_calls": [{
                            "id": "c1",
                            "type": "function",
                            "function": {
                                "name": "decide",
                                "arguments": args
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

fn basic_request(binary: &str, args: Vec<String>) -> ExecuteRequest {
    ExecuteRequest {
        binary: binary.to_string(),
        args,
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
    }
}

#[tokio::test]
async fn repeated_llm_denials_append_count_hint_at_threshold_only() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(run_denying_llm(listener));

    let temp = tempfile::tempdir().unwrap();
    let mut deny_config = DenyLearningConfig::new(temp.path().join("deny.yaml"));
    deny_config.min_denials = 2;
    let deny_store = DenyShapeStore::load(deny_config).unwrap();
    let evaluator = Evaluator::new(
        EvalConfig::default()
            .cache_enabled(false)
            .llm_api_key("test-key".to_string())
            .llm_api_url(url)
            .llm_retries(0)
            .deny_shapes(Arc::new(RwLock::new(deny_store))),
    )
    .unwrap();

    let (mut cfg, _) = make_test_config();
    cfg.evaluator = Arc::new(evaluator);
    let caller = CallerIdentity::Unix { uid: 1000 };

    let first = execute_command(
        basic_request("echo", vec!["delete-prod".to_string()]),
        &cfg,
        &caller,
    )
    .await;
    assert!(!first.policy_allowed());
    assert!(!first.policy_reason().contains("guard has denied"));

    let second = execute_command(
        basic_request("echo", vec!["delete-prod".to_string()]),
        &cfg,
        &caller,
    )
    .await;
    let reason = second.policy_reason();
    assert!(reason.contains("destructive request"));
    assert!(reason.contains("guard has denied 2 similar echo commands; if this access is needed, ask your operator to broaden the session grant or add a profile"));
    for forbidden in ["promoted", "learned", "fast path"] {
        assert!(
            !reason.to_ascii_lowercase().contains(forbidden),
            "client-facing denial reason exposed {forbidden}: {reason}"
        );
    }

    let allowed = execute_command(basic_request("id", Vec::new()), &cfg, &caller).await;
    assert!(allowed.policy_allowed());
    assert!(!allowed.policy_reason().contains("guard has denied"));
}

#[test]
fn dangerous_env_name_blocks_code_injection_vectors() {
    for name in [
        "LD_PRELOAD",
        "ld_preload",
        "BASH_ENV",
        "GIT_SSH_COMMAND",
        "PYTHONPATH",
        "NODE_OPTIONS",
        "LD_AUDIT",
        "LD_AUDIT_2",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
        "DYLD_INSERT_LIBRARIES",
    ] {
        assert!(dangerous_env_name(name), "{name} must be blocked");
    }
    for name in ["PATH", "HOME", "AWS_PROFILE", "MY_TOKEN", "GIT_AUTHOR_NAME"] {
        assert!(!dangerous_env_name(name), "{name} must be allowed");
    }
}

#[test]
fn safe_allow_accepts_fixed_local_identity() {
    let (cfg, _buf) = make_test_config();
    assert!(deterministic_safe_allow_reason(&cfg, "id", &[]).is_some());
    assert!(deterministic_safe_allow_reason(&cfg, "whoami", &[]).is_some());
    assert!(deterministic_safe_allow_reason(&cfg, "hostname", &[]).is_some());
    assert!(deterministic_safe_allow_reason(&cfg, "uptime", &[]).is_some());
    // A non-fixed local command falls through to the LLM.
    assert!(deterministic_safe_allow_reason(&cfg, "cat", &args(&["/etc/passwd"])).is_none());
}

#[test]
fn safe_allow_disabled_in_paranoid_mode() {
    let cfg = paranoid_test_config();
    assert!(deterministic_safe_allow_reason(&cfg, "id", &[]).is_none());
}

/// Policy denial: only the POLICY event fires, never EXEC_FAILED.
/// Legacy grep patterns `[AUDIT] DENIED` still match.
#[test]
fn audit_policy_denied_emits_only_policy_event() {
    let (cfg, buf) = make_test_config();
    let caller = CallerIdentity::Unix { uid: 1000 };
    let result = ExecuteResult::denied("matched deny pattern: rm -rf /");

    let output = capture(&buf, || {
        emit_audit_events(&cfg, &caller, "rm", &["-rf".into(), "/".into()], &result);
    });

    assert!(
        output.contains("[AUDIT] DENIED"),
        "expected DENIED policy line, got: {output}"
    );
    assert!(
        !output.contains("EXEC_FAILED"),
        "policy denial must not produce EXEC_FAILED: {output}"
    );
}

/// Policy allows + exec fails: BOTH events fire. Legacy grep for
/// `[AUDIT] ALLOWED` still matches, and tooling that wants exec-failure
/// visibility can filter on EXEC_FAILED.
#[test]
fn audit_allowed_then_exec_failed_emits_both_events() {
    let (cfg, buf) = make_test_config();
    let caller = CallerIdentity::Unix { uid: 1000 };
    let result = ExecuteResult::exec_failed(
        "LLM approved: benign lookup",
        "failed to execute 'nonexistent-binary-xyz': No such file or directory",
    );

    let output = capture(&buf, || {
        emit_audit_events(&cfg, &caller, "nonexistent-binary-xyz", &[], &result);
    });

    assert!(
        output.contains("[AUDIT] ALLOWED"),
        "expected ALLOWED policy line (backward-compat format), got: {output}"
    );
    assert!(
        output.contains("[AUDIT] EXEC_FAILED"),
        "expected EXEC_FAILED line, got: {output}"
    );
    assert!(
        output.contains("nonexistent-binary-xyz"),
        "audit line should carry the binary name: {output}"
    );
    assert!(
        output.contains("No such file"),
        "EXEC_FAILED line should carry the exec error reason: {output}"
    );
}

/// Policy allows + exec succeeds: only the POLICY event fires.
#[test]
fn audit_allowed_and_completed_emits_only_policy_event() {
    let (cfg, buf) = make_test_config();
    let caller = CallerIdentity::Unix { uid: 42 };
    let result = ExecuteResult::completed("static allow", Some(0), None, None);

    let output = capture(&buf, || {
        emit_audit_events(&cfg, &caller, "echo", &["hi".into()], &result);
    });

    assert!(output.contains("[AUDIT] ALLOWED"));
    assert!(!output.contains("EXEC_FAILED"));
}

/// Regression: each user has an independent namespace. Two users
/// can store the same key name without collision; neither can see
/// the other's keys through the user-scoped list, but the daemon
/// UID sees both via the admin list_all path.
#[tokio::test]
async fn secret_list_is_per_user_namespaced() {
    let (mut cfg, _) = make_test_config();
    cfg.daemon_uid = 777;
    cfg.daemon_principal = PrincipalKey::from_uid(777);

    // Unique key so parallel tests sharing the EnvBackend don't
    // collide.
    let key = format!("NAMESPACED_{}", std::process::id());

    let user_a = CallerIdentity::Unix { uid: 20_000 };
    let user_b = CallerIdentity::Unix { uid: 20_001 };
    let daemon = CallerIdentity::Unix { uid: 777 };

    // Both users store the SAME key name with different values.
    let set_a = handle_admin_request(
        &cfg,
        &user_a,
        AdminRequest::SecretSet {
            key: key.clone(),
            value: "alice".into(),
        },
    )
    .await;
    assert!(matches!(set_a, AdminResponse::Ok));

    let set_b = handle_admin_request(
        &cfg,
        &user_b,
        AdminRequest::SecretSet {
            key: key.clone(),
            value: "bob".into(),
        },
    )
    .await;
    assert!(matches!(set_b, AdminResponse::Ok));

    // Each user sees only their own namespace.
    let list_a = handle_admin_request(&cfg, &user_a, AdminRequest::SecretList).await;
    match list_a {
        AdminResponse::SecretList { keys } => {
            let ours: Vec<_> = keys.iter().filter(|k| *k == &key).collect();
            assert_eq!(ours.len(), 1);
        }
        other => panic!("unexpected {:?}", other),
    }

    // Daemon aggregate view includes both entries, annotated with uid.
    let list_daemon = handle_admin_request(&cfg, &daemon, AdminRequest::SecretList).await;
    match list_daemon {
        AdminResponse::SecretList { keys } => {
            let ours: Vec<_> = keys.iter().filter(|k| *k == &key).collect();
            assert_eq!(ours.len(), 2, "daemon sees both namespaced copies");
        }
        other => panic!("unexpected {:?}", other),
    }

    // user B's delete touches only their own namespace.
    let del_b = handle_admin_request(
        &cfg,
        &user_b,
        AdminRequest::SecretDelete { key: key.clone() },
    )
    .await;
    assert!(matches!(del_b, AdminResponse::Ok));

    // A's secret still there, value "alice" intact.
    assert_eq!(
        cfg.secrets
            .get(&PrincipalKey::from_uid(20_000), &key)
            .await
            .unwrap()
            .as_deref(),
        Some("alice")
    );
    // B's is gone.
    assert_eq!(
        cfg.secrets
            .get(&PrincipalKey::from_uid(20_001), &key)
            .await
            .unwrap(),
        None
    );

    // Cleanup.
    let _ = handle_admin_request(
        &cfg,
        &user_a,
        AdminRequest::SecretDelete { key: key.clone() },
    )
    .await;
}

/// Regression: exec-time secret injection reads from the caller's
/// namespace. Another user cannot `--secret X` their way to our X.
#[tokio::test]
async fn exec_secret_injection_is_isolated_per_uid() {
    let (mut cfg, _) = make_test_config();
    cfg.daemon_uid = 777;
    let key = format!("EXEC_ISO_{}", std::process::id());

    // user_a stores THE secret.
    cfg.secrets
        .set(&PrincipalKey::from_uid(30_000), &key, "alice-value")
        .await
        .unwrap();

    // user_b asks to inject $key into their exec call.
    let mut secrets_map = HashMap::new();
    secrets_map.insert("INJECTED".to_string(), key.clone());
    let req = ExecuteRequest {
        binary: "echo".to_string(),
        args: vec!["hi".to_string()],
        auth_token: None,
        env: HashMap::new(),
        secrets: secrets_map,
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

    let result = execute_command(req, &cfg, &CallerIdentity::Unix { uid: 30_001 }).await;
    // user_b has no such key in their namespace -> secret not found.
    assert!(!result.policy_allowed());
    assert!(
        result.policy_reason().contains("secret not found"),
        "reason: {}",
        result.policy_reason()
    );

    // Cleanup.
    let _ = cfg
        .secrets
        .delete(&PrincipalKey::from_uid(30_000), &key)
        .await;
}

#[tokio::test]
async fn extra_child_env_forwards_named_var_to_child() {
    let (mut cfg, _) = make_test_config();
    // The daemon forwards GUARD_CHILD_TEST_PT to children only because it is
    // listed in extra_child_env; the value comes from the daemon's own env.
    std::env::set_var("GUARD_CHILD_TEST_PT", "brokered-value-xyz");
    cfg.extra_child_env = vec!["GUARD_CHILD_TEST_PT".to_string()];

    #[cfg(unix)]
    let (bin, args) = (
        "sh".to_string(),
        vec![
            "-c".to_string(),
            "printf %s \"$GUARD_CHILD_TEST_PT\"".to_string(),
        ],
    );
    #[cfg(windows)]
    let (bin, args) = (
        "cmd".to_string(),
        vec!["/c".to_string(), "echo %GUARD_CHILD_TEST_PT%".to_string()],
    );

    let token = format!("child-env-{}", std::process::id());
    {
        let mut sessions = cfg.sessions.write().await;
        sessions.grant(
            token.clone(),
            SessionGrant {
                allow: vec!["*".into()],
                deny: Vec::new(),
                allow_exact: Vec::new(),
                deny_exact: Vec::new(),
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
        binary: bin,
        args,
        auth_token: None,
        env: HashMap::new(),
        secrets: HashMap::new(),
        stream: false,
        session_token: Some(token),
        revert: None,
        confirm_within_secs: None,
        reevaluate: false,
        ssh_hostkey: None,
        require_approval: None,
        wait_approval_secs: None,
        verb: None,
    };
    let result = execute_command(req, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;
    match &result.exec {
        ExecOutcome::Completed { stdout, .. } => assert!(
            stdout
                .as_deref()
                .unwrap_or_default()
                .contains("brokered-value-xyz"),
            "child did not receive the forwarded var; stdout={:?}",
            stdout
        ),
        other => panic!("expected Completed, got {:?}", other),
    }
    std::env::remove_var("GUARD_CHILD_TEST_PT");
}

/// The revert-availability fragment reaches the evaluator prompt only when a
/// rollback was supplied under the gate, composes with a session prompt, and
/// never turns a no-context call into a cache-bypassing one.
#[test]
fn revert_context_merges_only_when_supplied() {
    use crate::server::execute::merge_revert_context;
    assert_eq!(merge_revert_context(None, false), None);
    let sp = merge_revert_context(Some("session ctx".to_string()), false);
    assert_eq!(sp.as_deref(), Some("session ctx"));
    let with = merge_revert_context(None, true).expect("fragment present");
    assert!(with.contains("REVERSIBILITY CONTEXT"));
    let both = merge_revert_context(Some("session ctx".to_string()), true).expect("merged");
    assert!(both.contains("REVERSIBILITY CONTEXT") && both.ends_with("session ctx"));
}
