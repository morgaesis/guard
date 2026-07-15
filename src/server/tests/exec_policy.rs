use crate::server::admin::handle_admin_request;
#[cfg(windows)]
use crate::server::binary_path_candidates;
#[cfg(unix)]
use crate::server::execute::exec_after_approval;
use crate::server::execute::{
    audit_command_line, audit_session_fingerprint, evaluation_context_prompt, execute_command,
    log_audit_policy_for_request,
};
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
#[cfg(unix)]
use crate::session::SessionExactRule;
use crate::session::SessionGrant;
use guard::evaluate::{EvalConfig, Evaluator};
use guard::gating::deny_shape::{DenyLearningConfig, DenyShapeStore};
use guard::principal::PrincipalKey;
use std::collections::HashMap;
#[cfg(unix)]
use std::ffi::OsString;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;

#[cfg(unix)]
use super::capture_async;
use super::{args, capture, make_test_config, paranoid_test_config};

#[cfg(unix)]
static TEST_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(unix)]
struct EnvRestore {
    key: &'static str,
    value: Option<OsString>,
}

#[cfg(unix)]
impl EnvRestore {
    fn capture(key: &'static str) -> Self {
        Self {
            key,
            value: std::env::var_os(key),
        }
    }
}

#[cfg(unix)]
impl Drop for EnvRestore {
    fn drop(&mut self) {
        match &self.value {
            Some(value) => std::env::set_var(self.key, value),
            None => std::env::remove_var(self.key),
        }
    }
}

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

/// Audit fingerprints are stable, distinct, 128-bit identifiers that do not
/// expose token bytes. Short and multi-byte values must also remain safe.
#[test]
fn audit_session_fingerprint_is_stable_distinct_and_non_reversible() {
    let first = audit_session_fingerprint(Some("abcdefghij"));
    assert_eq!(first, audit_session_fingerprint(Some("abcdefghij")));
    assert_ne!(first, audit_session_fingerprint(Some("abcdefghik")));
    assert!(first.starts_with("sha256:"));
    assert_eq!(first.len(), "sha256:".len() + 32);
    for token in ["abcdefghij", "short", "éééééééééé"] {
        let fingerprint = audit_session_fingerprint(Some(token));
        assert!(!fingerprint.contains(token), "got: {fingerprint}");
    }
    assert_eq!(audit_session_fingerprint(None), "none");
    assert_eq!(audit_session_fingerprint(Some("")), "none");
}

#[test]
fn cwd_is_included_in_audit_and_evaluation_context() {
    let (cfg, buf) = make_test_config();
    let cwd = std::env::current_dir().unwrap();
    let mut req = basic_request("pwd", Vec::new());
    req.cwd = Some(cwd.clone());
    req.session_token = Some("session-token-that-must-not-appear".into());

    let prompt = evaluation_context_prompt(&req, Some("SESSION CONTEXT".to_string()))
        .expect("cwd/session prompt");
    assert!(prompt.contains("CALLER WORKING DIRECTORY:"));
    assert!(prompt.contains(&cwd.display().to_string()));
    assert!(prompt.contains("SESSION CONTEXT"));

    let logs = capture(&buf, || {
        log_audit_policy_for_request(
            &cfg,
            &CallerIdentity::Unix { uid: 1000 },
            &req,
            true,
            "approved for test",
        );
    });
    assert!(logs.contains("[AUDIT] ALLOWED"), "logs={logs}");
    assert!(logs.contains("caller=uid=1000"), "logs={logs}");
    assert!(
        logs.contains(&format!("cwd=\"{}\"", cwd.display())),
        "logs={logs}"
    );
    assert!(logs.contains("cmd=\"pwd\""), "logs={logs}");
    assert!(
        logs.contains(&format!(
            "session_fingerprint={}",
            audit_session_fingerprint(req.session_token.as_deref())
        )),
        "logs={logs}"
    );
    assert!(!logs.contains("session-token-that-must-not-appear"));
}

#[cfg(unix)]
#[tokio::test]
async fn secret_exposure_is_audited_only_after_successful_spawn() {
    let caller = CallerIdentity::Unix { uid: 1000 };
    let principal = PrincipalKey::from_uid(1000);
    let token = "opaque-session-token-never-logged";

    let (cfg, buf) = make_test_config();
    cfg.secrets
        .set(&principal, "service/token", "secret-value-never-logged")
        .await
        .unwrap();
    let mut request = basic_request("/bin/true", Vec::new());
    request.session_token = Some(token.into());
    request
        .secrets
        .insert("SERVICE_TOKEN".into(), "service/token".into());
    let mut sink = tokio::io::sink();
    let (result, logs) = capture_async(
        &buf,
        exec_after_approval(
            request,
            &cfg,
            &caller,
            "test allow".into(),
            0,
            false,
            &mut sink,
        ),
    )
    .await;
    assert_eq!(result.exit_code(), Some(0));
    assert_eq!(result.exposed_secret_refs(), &["service/token"]);
    assert!(logs.contains("[AUDIT] SECRET_EXPOSED"), "logs={logs}");
    assert!(logs.contains("service/token"), "logs={logs}");
    assert!(
        logs.contains(&audit_session_fingerprint(Some(token))),
        "logs={logs}"
    );
    assert!(!logs.contains(token));
    assert!(!logs.contains("secret-value-never-logged"));

    let (cfg, buf) = make_test_config();
    cfg.secrets
        .set(&principal, "service/token", "another-secret-value")
        .await
        .unwrap();
    let mut request = basic_request("guard-command-that-does-not-exist", Vec::new());
    request.session_token = Some(token.into());
    request
        .secrets
        .insert("SERVICE_TOKEN".into(), "service/token".into());
    let mut sink = tokio::io::sink();
    let (result, logs) = capture_async(
        &buf,
        exec_after_approval(
            request,
            &cfg,
            &caller,
            "test allow".into(),
            0,
            false,
            &mut sink,
        ),
    )
    .await;
    assert!(result.exposed_secret_refs().is_empty());
    assert!(!logs.contains("SECRET_EXPOSED"), "logs={logs}");
}

#[cfg(unix)]
#[tokio::test]
async fn streaming_secret_exposure_is_recorded_even_on_nonzero_exit() {
    let caller = CallerIdentity::Unix { uid: 1000 };
    let principal = PrincipalKey::from_uid(1000);
    let (cfg, buf) = make_test_config();
    for (name, value) in [
        ("service/primary", "primary-value-never-logged"),
        ("service/secondary", "secondary-value-never-logged"),
    ] {
        cfg.secrets.set(&principal, name, value).await.unwrap();
    }

    let mut request = basic_request("/bin/false", Vec::new());
    request.session_token = Some("streaming-session-token-never-logged".into());
    request
        .secrets
        .insert("PRIMARY_TOKEN".into(), "service/primary".into());
    request
        .secrets
        .insert("SECONDARY_TOKEN".into(), "service/secondary".into());
    let mut sink = tokio::io::sink();
    let (result, logs) = capture_async(
        &buf,
        exec_after_approval(
            request,
            &cfg,
            &caller,
            "test allow".into(),
            0,
            true,
            &mut sink,
        ),
    )
    .await;

    assert_eq!(result.exit_code(), Some(1));
    assert_eq!(
        result.exposed_secret_refs(),
        &[
            "service/primary".to_string(),
            "service/secondary".to_string()
        ]
    );
    assert_eq!(
        logs.matches("[AUDIT] SECRET_EXPOSED").count(),
        2,
        "logs={logs}"
    );
    assert!(logs.contains("service/primary"), "logs={logs}");
    assert!(logs.contains("service/secondary"), "logs={logs}");
    assert!(!logs.contains("streaming-session-token-never-logged"));
    assert!(!logs.contains("primary-value-never-logged"));
    assert!(!logs.contains("secondary-value-never-logged"));
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
        cwd: None,
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
        cwd: None,
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
        cwd: None,
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
        cwd: None,
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
        cwd: None,
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
        cwd: None,
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
        cwd: None,
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

#[cfg(unix)]
#[tokio::test]
async fn local_caller_cwd_is_canonicalized_and_used_for_execution() {
    let _env_guard = TEST_ENV_LOCK.lock().await;
    let (cfg, _) = make_test_config();
    let temp = tempfile::tempdir().unwrap();
    let real = temp.path().join("real");
    let link = temp.path().join("link");
    std::fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let token = format!("cwd-session-{}", std::process::id());
    cfg.sessions.write().await.grant(
        token.clone(),
        SessionGrant {
            allow: Vec::new(),
            deny: Vec::new(),
            allow_exact: vec![SessionExactRule::with_cwd(
                "pwd",
                Vec::new(),
                real.canonicalize().unwrap(),
            )],
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

    let mut req = basic_request("pwd", Vec::new());
    req.session_token = Some(token);
    req.cwd = Some(link);

    let result = execute_command(req, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;
    match result.exec {
        ExecOutcome::Completed { stdout, .. } => {
            assert_eq!(
                stdout.as_deref().map(str::trim),
                Some(real.to_str().unwrap())
            );
        }
        other => panic!("expected cwd-backed execution, got {:?}", other),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn default_service_execution_does_not_forward_ssh_auth_sock() {
    let (cfg, _) = make_test_config();
    let _restore = EnvRestore::capture("SSH_AUTH_SOCK");
    std::env::set_var("SSH_AUTH_SOCK", "/tmp/fake-caller-agent.sock");

    let token = format!("ssh-auth-sock-{}", std::process::id());
    cfg.sessions.write().await.grant(
        token.clone(),
        SessionGrant {
            allow: vec!["sh *".into()],
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

    let mut req = basic_request(
        "sh",
        vec![
            "-c".to_string(),
            "test -z \"${SSH_AUTH_SOCK:-}\" && printf clean".to_string(),
        ],
    );
    req.session_token = Some(token);

    let result = execute_command(req, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;
    match result.exec {
        ExecOutcome::Completed { stdout, .. } => {
            assert_eq!(stdout.as_deref(), Some("clean"));
        }
        other => panic!("expected child without SSH_AUTH_SOCK, got {:?}", other),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn caller_env_cannot_supply_ssh_auth_sock() {
    let (cfg, _) = make_test_config();
    let token = format!("caller-ssh-auth-sock-{}", std::process::id());
    cfg.sessions.write().await.grant(
        token.clone(),
        SessionGrant {
            allow: vec!["sh *".into()],
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

    let mut req = basic_request(
        "sh",
        vec!["-c".to_string(), "printf should-not-run".to_string()],
    );
    req.session_token = Some(token);
    req.env.insert(
        "SSH_AUTH_SOCK".to_string(),
        "/tmp/caller-agent.sock".to_string(),
    );

    let result = execute_command(req, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;
    assert!(!result.policy_allowed());
    assert!(result
        .policy_reason()
        .contains("dangerous injected environment variable name: 'SSH_AUTH_SOCK'"));
}

#[cfg(unix)]
#[tokio::test]
async fn guard_configured_ssh_auth_sock_is_forwarded_to_child() {
    let (cfg, _) = make_test_config();
    let _restore = EnvRestore::capture("SSH_AUTH_SOCK");
    std::env::set_var("SSH_AUTH_SOCK", "/tmp/caller-agent.sock");
    let tools = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        tools.path(),
        "tools:\n  sh:\n    env:\n      SSH_AUTH_SOCK: /run/guard/broker-agent.sock\n",
    )
    .unwrap();
    *cfg.tool_registry.write().await =
        crate::tool_config::ToolRegistry::load(tools.path()).unwrap();

    let token = format!("trusted-ssh-auth-sock-{}", std::process::id());
    cfg.sessions.write().await.grant(
        token.clone(),
        SessionGrant {
            allow: vec!["sh *".into()],
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

    let mut req = basic_request(
        "sh",
        vec![
            "-c".to_string(),
            "printf '%s' \"$SSH_AUTH_SOCK\"".to_string(),
        ],
    );
    req.session_token = Some(token);

    let result = execute_command(req, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;
    match result.exec {
        ExecOutcome::Completed { stdout, .. } => {
            assert_eq!(stdout.as_deref(), Some("/run/guard/broker-agent.sock"));
        }
        other => panic!(
            "expected broker-owned SSH_AUTH_SOCK in child, got {:?}",
            other
        ),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn caller_env_cannot_override_guard_tool_env() {
    let (cfg, _) = make_test_config();
    let tools = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        tools.path(),
        "tools:\n  sh:\n    env:\n      BROKER_ENDPOINT: guard-owned\n",
    )
    .unwrap();
    *cfg.tool_registry.write().await =
        crate::tool_config::ToolRegistry::load(tools.path()).unwrap();

    let token = format!("tool-env-collision-{}", std::process::id());
    cfg.sessions.write().await.grant(
        token.clone(),
        SessionGrant {
            allow: vec!["sh *".into()],
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

    let mut req = basic_request(
        "sh",
        vec![
            "-c".to_string(),
            "printf '%s' \"$BROKER_ENDPOINT\"".to_string(),
        ],
    );
    req.session_token = Some(token);
    req.env
        .insert("BROKER_ENDPOINT".to_string(), "caller-owned".to_string());

    let result = execute_command(req, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;
    match result.exec {
        ExecOutcome::Failed { reason, started } => {
            assert!(!started);
            assert!(reason.contains(
                "injected environment variable 'BROKER_ENDPOINT' conflicts with Guard tool configuration"
            ));
        }
        other => panic!("expected collision to fail before exec, got {:?}", other),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn caller_secret_cannot_override_guard_tool_env() {
    let (cfg, _) = make_test_config();
    let tools = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        tools.path(),
        "tools:\n  sh:\n    env:\n      BROKER_TOKEN: guard-owned\n",
    )
    .unwrap();
    *cfg.tool_registry.write().await =
        crate::tool_config::ToolRegistry::load(tools.path()).unwrap();
    cfg.secrets
        .set(
            &PrincipalKey::from_uid(1000),
            "CALLER_TOKEN",
            "caller-owned",
        )
        .await
        .unwrap();

    let token = format!("tool-secret-collision-{}", std::process::id());
    cfg.sessions.write().await.grant(
        token.clone(),
        SessionGrant {
            allow: vec!["sh *".into()],
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

    let mut req = basic_request(
        "sh",
        vec![
            "-c".to_string(),
            "printf '%s' \"$BROKER_TOKEN\"".to_string(),
        ],
    );
    req.session_token = Some(token);
    req.secrets
        .insert("BROKER_TOKEN".to_string(), "CALLER_TOKEN".to_string());

    let result = execute_command(req, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;
    match result.exec {
        ExecOutcome::Failed { reason, started } => {
            assert!(!started);
            assert!(reason.contains(
                "injected environment variable 'BROKER_TOKEN' conflicts with Guard tool configuration"
            ));
        }
        other => panic!(
            "expected secret collision to fail before exec, got {:?}",
            other
        ),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn caller_env_cannot_override_daemon_child_env() {
    let (mut cfg, _) = make_test_config();
    let _restore = EnvRestore::capture("GUARD_CHILD_ENDPOINT");
    std::env::set_var("GUARD_CHILD_ENDPOINT", "daemon-owned");
    cfg.extra_child_env = vec!["GUARD_CHILD_ENDPOINT".to_string()];

    let token = format!("child-env-collision-{}", std::process::id());
    cfg.sessions.write().await.grant(
        token.clone(),
        SessionGrant {
            allow: vec!["sh *".into()],
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

    let mut req = basic_request(
        "sh",
        vec![
            "-c".to_string(),
            "printf '%s' \"$GUARD_CHILD_ENDPOINT\"".to_string(),
        ],
    );
    req.session_token = Some(token);
    req.env.insert(
        "GUARD_CHILD_ENDPOINT".to_string(),
        "caller-owned".to_string(),
    );

    let result = execute_command(req, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;
    match result.exec {
        ExecOutcome::Failed { reason, started } => {
            assert!(!started);
            assert!(reason.contains(
                "injected environment variable 'GUARD_CHILD_ENDPOINT' conflicts with Guard daemon child environment"
            ));
        }
        other => panic!(
            "expected daemon child env collision to fail before exec, got {:?}",
            other
        ),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn redaction_covers_effective_tool_child_and_request_env_values() {
    let (mut cfg, _) = make_test_config();
    cfg.redact = true;
    let _restore = EnvRestore::capture("GUARD_CHILD_SECRET");
    std::env::set_var("GUARD_CHILD_SECRET", "daemon-child-secret-value");
    cfg.extra_child_env = vec!["GUARD_CHILD_SECRET".to_string()];
    let tools = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        tools.path(),
        "tools:\n  sh:\n    env:\n      TOOL_SECRET: guard-tool-secret-value\n",
    )
    .unwrap();
    *cfg.tool_registry.write().await =
        crate::tool_config::ToolRegistry::load(tools.path()).unwrap();

    let token = format!("env-redaction-{}", std::process::id());
    cfg.sessions.write().await.grant(
        token.clone(),
        SessionGrant {
            allow: vec!["sh *".into()],
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

    let mut req = basic_request(
        "sh",
        vec![
            "-c".to_string(),
            "printf '%s %s %s' \"$TOOL_SECRET\" \"$GUARD_CHILD_SECRET\" \"$REQUEST_SECRET\""
                .to_string(),
        ],
    );
    req.session_token = Some(token);
    req.env.insert(
        "REQUEST_SECRET".to_string(),
        "request-secret-value".to_string(),
    );

    let result = execute_command(req, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;
    match result.exec {
        ExecOutcome::Completed { stdout, .. } => {
            let stdout = stdout.unwrap_or_default();
            assert!(
                !stdout.contains("guard-tool-secret-value"),
                "stdout={stdout}"
            );
            assert!(
                !stdout.contains("daemon-child-secret-value"),
                "stdout={stdout}"
            );
            assert!(!stdout.contains("request-secret-value"), "stdout={stdout}");
            assert!(stdout.contains("[REDACTED]"), "stdout={stdout}");
        }
        other => panic!("expected redacted env output, got {:?}", other),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn ansible_discovers_config_from_cwd_without_inherited_ansible_config() {
    let _env_guard = TEST_ENV_LOCK.lock().await;
    let (cfg, _) = make_test_config();
    let temp = tempfile::tempdir().unwrap();
    let bin_dir = temp.path().join("bin");
    let project = temp.path().join("project");
    std::fs::create_dir(&bin_dir).unwrap();
    std::fs::create_dir(&project).unwrap();
    std::fs::write(
        project.join("ansible.cfg"),
        "[defaults]\ninventory = inventory\n",
    )
    .unwrap();
    std::fs::write(project.join("inventory"), "all\n").unwrap();
    let ansible = bin_dir.join("ansible");
    std::fs::write(
        &ansible,
        "#!/bin/sh\n\
         test \"$*\" = '-m ping all' || exit 2\n\
         test -z \"${ANSIBLE_CONFIG:-}\" || exit 3\n\
         test -f ansible.cfg || exit 4\n\
         test -f inventory || exit 5\n\
         grep -q '^inventory *= *inventory$' ansible.cfg || exit 6\n\
         grep -q '^all$' inventory || exit 7\n\
         printf 'ansible-cwd-ok:%s' \"$(pwd)\"\n",
    )
    .unwrap();
    let mut perms = std::fs::metadata(&ansible).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o755);
    std::fs::set_permissions(&ansible, perms).unwrap();

    let _path_restore = EnvRestore::capture("PATH");
    let _ansible_config_restore = EnvRestore::capture("ANSIBLE_CONFIG");
    std::env::set_var("PATH", format!("{}:/usr/bin:/bin", bin_dir.display()));
    std::env::set_var("ANSIBLE_CONFIG", "/tmp/caller-ansible.cfg");

    let project_cwd = project.canonicalize().unwrap();
    let token = format!("ansible-cwd-{}", std::process::id());
    cfg.sessions.write().await.grant(
        token.clone(),
        SessionGrant {
            allow: Vec::new(),
            deny: Vec::new(),
            allow_exact: vec![SessionExactRule::with_cwd(
                "ansible",
                vec!["-m".into(), "ping".into(), "all".into()],
                project_cwd.clone(),
            )],
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

    let mut req = basic_request("ansible", vec!["-m".into(), "ping".into(), "all".into()]);
    req.session_token = Some(token);
    req.cwd = Some(project_cwd.clone());

    let result = execute_command(req, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;
    match result.exec {
        ExecOutcome::Completed { stdout, .. } => {
            let expected = format!("ansible-cwd-ok:{}", project_cwd.display());
            assert_eq!(stdout.as_deref(), Some(expected.as_str()));
        }
        other => panic!(
            "expected fake ansible to discover cwd config/inventory without ANSIBLE_CONFIG, got {:?}",
            other
        ),
    }
}

#[tokio::test]
async fn tcp_caller_cannot_assert_working_directory() {
    let (cfg, _) = make_test_config();
    let mut req = basic_request("echo", vec!["ok".to_string()]);
    req.cwd = Some(std::env::current_dir().unwrap());

    let result = execute_command(
        req,
        &cfg,
        &CallerIdentity::Tcp {
            token: "exec-token".into(),
        },
    )
    .await;

    assert!(!result.policy_allowed());
    assert!(result
        .policy_reason()
        .contains("authenticated local caller"));
}

#[cfg(unix)]
#[tokio::test]
async fn shim_dir_only_path_fails_without_recursing_into_primary_shim() {
    let _env_guard = TEST_ENV_LOCK.lock().await;
    let (mut cfg, _) = make_test_config();
    let shim_dir = tempfile::tempdir().unwrap();
    let shim_path = shim_dir.path().join("missing-tool");
    std::fs::write(&shim_path, "#!/bin/sh\nexit 99\n").unwrap();
    let mut perms = std::fs::metadata(&shim_path).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o755);
    std::fs::set_permissions(&shim_path, perms).unwrap();
    cfg.shim_dir = Some(shim_dir.path().to_path_buf());
    let _path_restore = EnvRestore::capture("PATH");
    let inherited_path = std::env::var_os("PATH").unwrap_or_default();
    let test_path = std::env::join_paths(
        std::iter::once(shim_dir.path().to_path_buf())
            .chain(std::env::split_paths(&inherited_path)),
    )
    .unwrap();
    std::env::set_var("PATH", test_path);

    let token = format!("shim-recursion-{}", std::process::id());
    cfg.sessions.write().await.grant(
        token.clone(),
        SessionGrant {
            allow: vec!["missing-tool".into()],
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

    let mut req = basic_request("missing-tool", Vec::new());
    req.session_token = Some(token);
    let result = execute_command(req, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;

    match result.exec {
        ExecOutcome::Failed { reason, started } => {
            assert!(!started);
            assert!(reason.contains("outside shim directory"), "got: {reason}");
        }
        other => panic!("expected pre-start exec failure, got {:?}", other),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn allowed_binary_floor_does_not_permit_shim_dir_recursion() {
    let _env_guard = TEST_ENV_LOCK.lock().await;
    let (mut cfg, _) = make_test_config();
    let shim_dir = tempfile::tempdir().unwrap();
    let shim_path = shim_dir.path().join("allowed-tool");
    std::fs::write(&shim_path, "#!/bin/sh\nexit 99\n").unwrap();
    let mut perms = std::fs::metadata(&shim_path).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o755);
    std::fs::set_permissions(&shim_path, perms).unwrap();
    cfg.shim_dir = Some(shim_dir.path().to_path_buf());
    cfg.allowed_binaries = Some(vec!["allowed-tool".to_string()]);
    let _path_restore = EnvRestore::capture("PATH");
    let inherited_path = std::env::var_os("PATH").unwrap_or_default();
    let test_path = std::env::join_paths(
        std::iter::once(shim_dir.path().to_path_buf())
            .chain(std::env::split_paths(&inherited_path)),
    )
    .unwrap();
    std::env::set_var("PATH", test_path);

    let token = format!("shim-allow-bin-{}", std::process::id());
    cfg.sessions.write().await.grant(
        token.clone(),
        SessionGrant {
            allow: vec!["allowed-tool".into()],
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

    let mut req = basic_request("allowed-tool", Vec::new());
    req.session_token = Some(token);
    let result = execute_command(req, &cfg, &CallerIdentity::Unix { uid: 1000 }).await;

    match result.exec {
        ExecOutcome::Failed { reason, started } => {
            assert!(!started);
            assert!(reason.contains("outside shim directory"), "got: {reason}");
        }
        other => panic!("expected pre-start exec failure, got {:?}", other),
    }
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
