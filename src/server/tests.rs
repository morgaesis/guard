use super::*;
use crate::evaluate::{EvalConfig, Evaluator};
use crate::secrets::{EnvBackend, SecretManager};
use crate::tool_config::ToolRegistry;
use std::io::Write;
use std::sync::{Arc, Mutex};
use tracing::subscriber::with_default;
use tracing_subscriber::fmt::MakeWriter;

/// `IncomingMessage` is untagged, so the grant wire shape must keep
/// resolving to the Grant variant (not fall through to Execute) and the
/// tagged `action` must select the right operation.
#[test]
fn grant_wire_shape_parses_to_grant_variant() {
    let msg: IncomingMessage = serde_json::from_str(
            r#"{"grant":{"action":"read","path":"/home/op/values.yaml","ttl_secs":600,"session_token":"tok"}}"#,
        )
        .expect("grant read parses");
    match msg {
        IncomingMessage::Grant {
            grant: GrantRequest::Read { path, ttl_secs, .. },
        } => {
            assert_eq!(path, "/home/op/values.yaml");
            assert_eq!(ttl_secs, 600);
        }
        other => panic!("expected Grant/Read, got {other:?}"),
    }

    let msg: IncomingMessage =
        serde_json::from_str(r#"{"grant":{"action":"revoke","path":"/home/op/values.yaml"}}"#)
            .expect("grant revoke parses");
    assert!(matches!(
        msg,
        IncomingMessage::Grant {
            grant: GrantRequest::Revoke { .. }
        }
    ));

    // An execute request must not be captured by the Grant arm.
    let msg: IncomingMessage =
        serde_json::from_str(r#"{"binary":"ls","args":["-l"]}"#).expect("execute parses");
    assert!(matches!(msg, IncomingMessage::Execute(_)));
}

// ---- Audit-line redaction helpers ---------------------------------------

/// Argv rendered into audit lines must have inline credentials masked:
/// the log records the command shape, never the secret values.
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
fn execute_result_denied_has_denied_policy_and_not_attempted_exec() {
    let r = ExecuteResult::denied("nope");
    assert!(!r.policy_allowed());
    assert_eq!(r.policy_reason(), "nope");
    assert!(matches!(r.exec, ExecOutcome::NotAttempted));
}

#[test]
fn execute_result_exec_failed_has_allowed_policy_and_failed_exec() {
    let r = ExecuteResult::exec_failed("looks fine", "no such file or directory");
    assert!(
        r.policy_allowed(),
        "exec_failed must still flag policy=allowed"
    );
    assert_eq!(r.policy_reason(), "looks fine");
    match &r.exec {
        ExecOutcome::Failed { reason, .. } => {
            assert!(reason.contains("no such file"));
        }
        other => panic!("expected Failed, got {:?}", other),
    }
}

#[test]
fn execute_result_completed_has_allowed_policy_and_completed_exec() {
    let r = ExecuteResult::completed(
        "static allow",
        Some(0),
        Some("out".into()),
        Some("err".into()),
    );
    assert!(r.policy_allowed());
    assert_eq!(r.policy_reason(), "static allow");
    match &r.exec {
        ExecOutcome::Completed {
            exit_code,
            stdout,
            stderr,
        } => {
            assert_eq!(*exit_code, Some(0));
            assert_eq!(stdout.as_deref(), Some("out"));
            assert_eq!(stderr.as_deref(), Some("err"));
        }
        other => panic!("expected Completed, got {:?}", other),
    }
}

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
fn parse_admin_response_line_accepts_admin_response() {
    let line = r#"{"result":"error","message":"admin denied"}"#;
    match parse_admin_response_line(line, "secret_set").unwrap() {
        AdminResponse::Error { message } => assert_eq!(message, "admin denied"),
        other => panic!("expected admin error, got {:?}", other),
    }
}

#[test]
fn parse_admin_response_line_maps_execute_invalid_request_to_actionable_error() {
    let line = r#"{"allowed":false,"reason":"invalid request: data did not match any variant of untagged enum IncomingMessage"}"#;
    match parse_admin_response_line(line, "secret_set").unwrap() {
        AdminResponse::Error { message } => {
            assert!(message.contains("secret_set"));
            assert!(message.contains("needs restart"));
        }
        other => panic!("expected admin error, got {:?}", other),
    }
}

#[test]
fn parse_admin_response_line_surfaces_malformed_admin_payloads_as_restart_errors() {
    let line = r#"{"result":"secret_list","items":[{"key":"alpha"}]}"#;
    match parse_admin_response_line(line, "secret_list").unwrap() {
        AdminResponse::Error { message } => {
            assert!(message.contains("secret_list"));
            assert!(message.contains("malformed admin response"));
            assert!(message.contains("Restart the daemon"));
        }
        other => panic!("expected admin error, got {:?}", other),
    }
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

#[test]
fn is_local_peer_excludes_tcp_and_unknown() {
    assert!(CallerIdentity::Unix { uid: 0 }.is_local_peer());
    assert!(!CallerIdentity::Tcp { token: "t".into() }.is_local_peer());
    assert!(!CallerIdentity::TcpAdmin { token: "t".into() }.is_local_peer());
    assert!(!CallerIdentity::Unknown.is_local_peer());
    #[cfg(windows)]
    assert!(CallerIdentity::Windows {
        sid: "S-1-5-18".into()
    }
    .is_local_peer());
}

#[test]
fn exec_failed_constructors_set_started_flag() {
    // Spawn/setup failure: the child never ran -> the containment envelope
    // drops the provisional (nothing to revert).
    let pre = ExecuteResult::exec_failed("allowed", "ENOENT");
    assert!(matches!(
        pre.exec,
        ExecOutcome::Failed { started: false, .. }
    ));
    // Failure after the child was launched (e.g. client stream dropped):
    // the mutation may have applied -> keep the auto-revert armed.
    let post = ExecuteResult::exec_failed_after_start("allowed", "client stream error");
    assert!(matches!(
        post.exec,
        ExecOutcome::Failed { started: true, .. }
    ));
}

#[cfg(windows)]
#[test]
fn reconstruct_caller_round_trips_windows_sid() {
    let sid = "S-1-5-21-1-2-3-1001";
    let rebuilt = reconstruct_caller(Some(PrincipalKey::from_sid(sid)), &CallerIdentity::Unknown);
    assert!(matches!(rebuilt, CallerIdentity::Windows { sid: s } if s == sid));
}

#[cfg(windows)]
#[test]
fn pipe_name_normalizes_bare_name() {
    assert_eq!(
        winplat::pipe_name(std::path::Path::new("guard")),
        r"\\.\pipe\guard"
    );
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

#[test]
fn into_response_for_denied_sets_allowed_false() {
    let resp = ExecuteResult::denied("blocked").into_response();
    assert!(!resp.allowed);
    assert_eq!(resp.reason, "blocked");
    assert!(resp.exit_code.is_none());
}

#[test]
fn into_response_for_exec_failed_sets_allowed_false_with_exec_error() {
    let resp = ExecuteResult::exec_failed("llm ok", "ENOENT").into_response();
    // Client-facing: the command did not run, so allowed=false is correct.
    // The audit log records POLICY=ALLOWED + EXEC_FAILED separately.
    assert!(!resp.allowed);
    assert!(resp.reason.contains("execution error"));
    assert!(resp.reason.contains("ENOENT"));
}

#[test]
fn into_response_for_dry_run_sets_allowed_true_without_child_output() {
    let resp = ExecuteResult::dry_run("llm ok").into_response();
    assert!(resp.allowed);
    assert_eq!(resp.reason, "llm ok");
    assert_eq!(resp.exit_code, Some(0));
    assert_eq!(
        resp.stdout.as_deref(),
        Some("[DRY-RUN] policy allowed; command was not executed\n")
    );
    assert!(resp.stderr.is_none());
}

#[test]
fn into_response_for_completed_carries_exit_and_streams() {
    let resp = ExecuteResult::completed("ok", Some(7), Some("hi".into()), None).into_response();
    assert!(resp.allowed);
    assert_eq!(resp.exit_code, Some(7));
    assert_eq!(resp.stdout.as_deref(), Some("hi"));
}

// ---- Audit emission end-to-end tests ------------------------------------

/// Shared-buffer writer for the tracing fmt subscriber. Lets us capture
/// emitted log lines and assert on their contents.
#[derive(Clone)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SharedBuf {
    type Writer = SharedBuf;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn make_test_config() -> (ServerConfig, SharedBuf) {
    // LLM disabled, no static policy → policy_allowed() never hits
    // this path; we manufacture results directly for audit tests.
    let eval_config = EvalConfig::default().llm_enabled(false);
    let evaluator = Evaluator::new(eval_config).expect("build evaluator");
    let secrets = SecretManager::with_backend(EnvBackend::default());
    let cfg = ServerConfig::new(
        None,
        None,
        evaluator,
        secrets,
        false,
        None,
        None,
        None,
        None,
        None,
        false,
        ToolRegistry::isolated_for_tests(),
        Vec::new(),
        false,
        SessionRegistry::new(),
        None,
        false,
        None,
    );
    let buf = SharedBuf(Arc::new(Mutex::new(Vec::new())));
    (cfg, buf)
}

fn paranoid_test_config() -> ServerConfig {
    let eval_config = EvalConfig::default()
        .llm_enabled(false)
        .mode(PolicyMode::Paranoid);
    let evaluator = Evaluator::new(eval_config).expect("build evaluator");
    let secrets = SecretManager::with_backend(EnvBackend::default());
    ServerConfig::new(
        None,
        None,
        evaluator,
        secrets,
        false,
        None,
        None,
        None,
        None,
        None,
        false,
        ToolRegistry::isolated_for_tests(),
        Vec::new(),
        false,
        SessionRegistry::new(),
        None,
        false,
        None,
    )
}

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
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

#[test]
fn safe_allow_accepts_fixed_ssh_diagnostic() {
    let (cfg, _buf) = make_test_config();
    let reason = deterministic_safe_allow_reason(&cfg, "ssh", &args(&["host01", "id"]));
    assert!(reason.is_some(), "fixed ssh diagnostic should be allowed");
}

fn ssh_request(mode: Option<SshHostKeyMode>, argv: &[&str]) -> ExecuteRequest {
    ExecuteRequest {
        binary: "ssh".to_string(),
        args: args(argv),
        auth_token: None,
        env: HashMap::new(),
        secrets: HashMap::new(),
        stream: false,
        session_token: None,
        revert: None,
        confirm_within_secs: None,
        require_approval: None,
        wait_approval_secs: None,
        verb: None,
        reevaluate: false,
        ssh_hostkey: mode,
    }
}

#[test]
fn apply_ssh_hostkey_injects_options_by_mode() {
    // OnlyExisting / absent: no change, ssh keeps its strict default.
    for mode in [None, Some(SshHostKeyMode::OnlyExisting)] {
        let mut req = ssh_request(mode, &["host01", "id"]);
        req.apply_ssh_hostkey_options();
        assert_eq!(req.args, args(&["host01", "id"]), "mode {mode:?}");
    }

    // AcceptNew prepends accept-new + UpdateHostKeys ahead of the host.
    let mut req = ssh_request(Some(SshHostKeyMode::AcceptNew), &["host01", "id"]);
    req.apply_ssh_hostkey_options();
    assert_eq!(
        req.args,
        args(&[
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "UpdateHostKeys=yes",
            "host01",
            "id",
        ])
    );

    // AcceptAll gives up host verification.
    let mut req = ssh_request(Some(SshHostKeyMode::AcceptAll), &["host01", "id"]);
    req.apply_ssh_hostkey_options();
    assert_eq!(
        req.args,
        args(&[
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "host01",
            "id",
        ])
    );
}

#[test]
fn apply_ssh_hostkey_is_noop_for_non_ssh() {
    let mut req = ssh_request(Some(SshHostKeyMode::AcceptAll), &["get", "pods"]);
    req.binary = "kubectl".to_string();
    req.apply_ssh_hostkey_options();
    assert_eq!(req.args, args(&["get", "pods"]));
}

#[test]
fn accept_new_hostkey_keeps_fixed_diagnostic_on_fast_path() {
    // The options accept-new injects are allow-listed, so a fixed
    // diagnostic still qualifies for the deterministic fast path.
    let (cfg, _buf) = make_test_config();
    let mut req = ssh_request(Some(SshHostKeyMode::AcceptNew), &["host01", "id"]);
    req.apply_ssh_hostkey_options();
    assert!(deterministic_safe_allow_reason(&cfg, "ssh", &req.args).is_some());
}

#[test]
fn accept_all_hostkey_forfeits_fast_path() {
    // accept-all injects StrictHostKeyChecking=no, which the option
    // allow-list rejects, so even a fixed diagnostic forfeits to the
    // evaluator rather than auto-allowing over an unauthenticated channel.
    let (cfg, _buf) = make_test_config();
    let mut req = ssh_request(Some(SshHostKeyMode::AcceptAll), &["host01", "id"]);
    req.apply_ssh_hostkey_options();
    assert!(deterministic_safe_allow_reason(&cfg, "ssh", &req.args).is_none());
}

#[test]
fn safe_allow_rejects_ssh_arbitrary_remote_command() {
    let (cfg, _buf) = make_test_config();
    assert!(
        deterministic_safe_allow_reason(&cfg, "ssh", &args(&["host01", "rm", "-rf", "/"]))
            .is_none()
    );
}

#[test]
fn safe_allow_rejects_ssh_chained_remote_command() {
    let (cfg, _buf) = make_test_config();
    assert!(
        deterministic_safe_allow_reason(&cfg, "ssh", &args(&["host01", "id; rm -rf /"])).is_none()
    );
}

#[test]
fn ssh_options_allow_list_permits_only_vetted_options() {
    // Options a read-only diagnostic may legitimately carry, in both the
    // separate-value and concatenated forms.
    for ok in [
        &["host01", "id"][..],
        &["-4", "host01", "id"][..],
        &["-6", "-C", "-q", "host01", "id"][..],
        &["-v", "host01", "id"][..],
        &["-vvv", "host01", "id"][..],
        &["-T", "-a", "-x", "-k", "host01", "id"][..],
        &["-p", "2222", "host01", "id"][..],
        &["-p2222", "host01", "id"][..],
        &["-l", "root", "host01", "id"][..],
        &["-lroot", "host01", "id"][..],
        &["-o", "ConnectTimeout=5", "host01", "id"][..],
        &["-o", "BatchMode=yes", "host01", "id"][..],
        &["-oConnectTimeout=5", "host01", "id"][..],
        // Host-key handling injected by the --hostkey mode must not
        // knock the diagnostic off the fast path.
        &[
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "UpdateHostKeys=yes",
            "host01",
            "id",
        ][..],
    ] {
        assert!(
            ssh_options_all_readonly_safe(&args(ok)),
            "options should be allow-listed: {ok:?}"
        );
    }

    // Every unvetted option forfeits the fast path. This covers the
    // classes an allow-list must reject: forwarding, proxy/jump, tunnel,
    // external config (-F) and PKCS#11 module (-I), identity/log/socket
    // files, and any -o directive outside the vetted keyword set.
    for bad in [
        &["-A", "host01", "id"][..],
        &["-X", "host01", "id"][..],
        &["-Y", "host01", "id"][..],
        &["-L", "8080:localhost:80", "host01", "id"][..],
        &["-R", "9000:localhost:22", "host01", "id"][..],
        &["-D", "1080", "host01", "id"][..],
        &["-W", "host:22", "host01", "id"][..],
        &["-J", "jump", "host01", "id"][..],
        &["-F", "/tmp/evil_ssh_config", "host01", "id"][..],
        &["-I", "/tmp/pkcs11.so", "host01", "id"][..],
        &["-E", "/tmp/log", "host01", "id"][..],
        &["-i", "/tmp/key", "host01", "id"][..],
        &["-S", "/tmp/ctl.sock", "host01", "id"][..],
        &["-o", "ProxyCommand=nc x 22", "host01", "id"][..],
        &["-oProxyJump=jump", "host01", "id"][..],
        &["-o", "LocalCommand=touch /tmp/x", "host01", "id"][..],
        &["-o", "RemoteCommand=cat /etc/shadow", "host01", "id"][..],
        &["-o", "PermitLocalCommand=yes", "host01", "id"][..],
        &["-o", "Include=/tmp/evil", "host01", "id"][..],
        // Combined short flags are not decomposed; forfeit conservatively.
        &["-Cq", "host01", "id"][..],
        // A value option with no following value is malformed; forfeit.
        &["-p"][..],
        &["host01", "-l"][..],
    ] {
        assert!(
            !ssh_options_all_readonly_safe(&args(bad)),
            "option should forfeit the fast path: {bad:?}"
        );
    }
}

#[test]
fn ssh_options_reject_dangerous_option_between_host_and_command() {
    // ssh honors options placed between the destination and the remote
    // command (confirmed against `ssh -G`), so the allow-list must scan
    // past the destination up to the command token. A proxy/forward/jump
    // in that position must forfeit the fast path.
    for bad in [
        &["host01", "-o", "ProxyCommand=nc x 22", "id"][..],
        &["host01", "-L", "8080:localhost:80", "id"][..],
        &["host01", "-J", "jump", "id"][..],
        &["host01", "-oProxyJump=jump", "id"][..],
        &["host01", "-F", "/tmp/evil_ssh_config", "id"][..],
    ] {
        assert!(
            !ssh_options_all_readonly_safe(&args(bad)),
            "option between host and command must forfeit: {bad:?}"
        );
    }
    // An option that appears *after* the command token is a command
    // argument, not an ssh option, and ssh does not re-parse it; it does
    // not affect the fast-path decision for the (fixed) command itself.
    assert!(ssh_options_all_readonly_safe(&args(&[
        "host01",
        "id",
        "-o",
        "ProxyCommand=nc x 22"
    ])));
}

#[test]
fn ssh_o_directive_rejects_newline_smuggled_second_directive() {
    // A single -o value carrying a second directive on a later line must
    // be rejected outright rather than inspected only up to its first
    // keyword.
    assert!(!ssh_o_directive_readonly_safe(
        "ConnectTimeout=5\nProxyCommand=nc attacker 22"
    ));
    assert!(!ssh_o_directive_readonly_safe(
        "BatchMode=yes\rLocalCommand=touch /tmp/x"
    ));
    assert!(!ssh_options_all_readonly_safe(&args(&[
        "-o",
        "ConnectTimeout=5\nProxyCommand=nc x 22",
        "host01",
        "id"
    ])));
    // The same keyword without a newline stays on the fast path.
    assert!(ssh_o_directive_readonly_safe("ConnectTimeout=5"));
}

#[test]
fn ssh_o_stricthostkeychecking_permits_only_secure_values() {
    // Security-preserving values keep the fast path (accept-new is what
    // the --hostkey mode injects).
    assert!(ssh_o_directive_readonly_safe("StrictHostKeyChecking=yes"));
    assert!(ssh_o_directive_readonly_safe(
        "StrictHostKeyChecking=accept-new"
    ));
    // Disabling or deferring host-key verification forfeits to the
    // evaluator rather than auto-allowing over an unauthenticated channel.
    for weak in [
        "StrictHostKeyChecking=no",
        "StrictHostKeyChecking=off",
        "StrictHostKeyChecking=ask",
        "stricthostkeychecking no",
    ] {
        assert!(
            !ssh_o_directive_readonly_safe(weak),
            "{weak} should forfeit the fast path"
        );
    }
    // And the whole invocation forfeits when the caller disables it.
    let (cfg, _buf) = make_test_config();
    assert!(deterministic_safe_allow_reason(
        &cfg,
        "ssh",
        &args(&["-o", "StrictHostKeyChecking=no", "host01", "id"])
    )
    .is_none());
}

#[test]
fn safe_allow_rejects_ssh_forwarding_and_proxy() {
    let (cfg, _buf) = make_test_config();
    for reject in [
        &["-L", "8080:localhost:80", "host01", "id"][..],
        &["-A", "host01", "id"][..],
        &["-o", "ProxyCommand=nc x 22", "host01", "id"][..],
        &["-oProxyJump=jump", "host01", "id"][..],
        &["-F", "/tmp/evil_ssh_config", "host01", "id"][..],
    ] {
        assert!(
            deterministic_safe_allow_reason(&cfg, "ssh", &args(reject)).is_none(),
            "ssh with {reject:?} must not take the fast path"
        );
    }
    // A benign, vetted option still allows the fixed diagnostic.
    assert!(deterministic_safe_allow_reason(
        &cfg,
        "ssh",
        &args(&["-o", "ConnectTimeout=5", "host01", "id"])
    )
    .is_some());
}

#[test]
fn is_fixed_readonly_diagnostic_is_narrow() {
    assert!(is_fixed_readonly_diagnostic("id"));
    assert!(is_fixed_readonly_diagnostic("uname -a"));
    assert!(is_fixed_readonly_diagnostic("df -h"));
    assert!(!is_fixed_readonly_diagnostic("id && rm -rf /"));
    assert!(!is_fixed_readonly_diagnostic("cat /etc/shadow"));
    assert!(!is_fixed_readonly_diagnostic("uname -a; whoami"));
    assert!(!is_fixed_readonly_diagnostic(""));
}

/// Trusted-verb + consequence-gate interaction: `trusted` only skips the
/// LLM evaluator (`bypass: false` in the `GateInputs` built for it,
/// see `execute_command_inner`); it must NOT also skip consequence
/// routing. An irreversible trusted verb must still be held for operator
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
}

/// `guard verb list` must not misrepresent a stale auto-promoted verb as
/// still trusted: its reported `trusted` field has to reflect the same
/// staleness check `execute_command_inner` applies, not the catalog's raw
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

fn capture<F: FnOnce()>(buf: &SharedBuf, f: F) -> String {
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .with_ansi(false)
        .without_time()
        .finish();
    with_default(subscriber, f);
    let bytes = buf.0.lock().unwrap().clone();
    String::from_utf8_lossy(&bytes).to_string()
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
        reg.check(&token, "kubectl", &["delete".into(), "pod".into()]),
        Some((SessionDecision::Deny, _))
    ));
    // ...its allow glob short-circuits to Allow...
    assert!(matches!(
        reg.check(&token, "kubectl", &["get".into(), "pods".into()]),
        Some((SessionDecision::Allow, _))
    ));
    // ...and a command matching neither falls through to normal evaluation.
    assert!(
        reg.check(&token, "helm", &["list".into()]).is_none(),
        "an unmatched command must fall through to the evaluator"
    );
}

// ---- Consequence-gating orchestration tests -----------------------------
//
// These drive the daemon orchestration in this file (arm_containment,
// hold_for_approval, handle_admin_request -> confirm/approve/deny/revert,
// and the sweeper's expire/auto-revert steps) directly in-process, so the
// invariants the Docker CTF (ctf/gating) checks end-to-end are also caught
// by `cargo test`. Tests that must spawn a real forward/revert child use
// POSIX `echo`/`true`/`false` and are `#[cfg(unix)]`; the authoritative
// cross-platform run is the Linux container. The pure registry/handler
// invariants (operator gating, TTL expiry, catalog voiding) run everywhere.

// The gating types (Approval, ApprovalSnapshot, ApprovalStatus, Provisional,
// ProvisionalStatus, Coverage, GateMode, Reversibility) and AsyncWrite are
// already in scope via `use super::*;`.
use std::collections::BTreeMap;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Build a containment-gating config: gate on, a distinct operator
/// principal, and the caller uid as the row owner. Returns
/// `(config, operator_caller, agent_caller)`.
fn gating_config(
    operator_uid: u32,
    agent_uid: u32,
) -> (ServerConfig, CallerIdentity, CallerIdentity) {
    let (mut cfg, _) = make_test_config();
    cfg.gate = GateMode::Consequence;
    cfg.daemon_uid = operator_uid;
    cfg.daemon_principal = PrincipalKey::from_uid(operator_uid);
    let operator = CallerIdentity::Unix { uid: operator_uid };
    let agent = CallerIdentity::Unix { uid: agent_uid };
    (cfg, operator, agent)
}

/// A request with a structured revert, used to drive `arm_containment`.
fn contain_request(binary: &str, args: &[&str], revert: RevertSpec) -> ExecuteRequest {
    ExecuteRequest {
        binary: binary.to_string(),
        args: args.iter().map(|s| s.to_string()).collect(),
        auth_token: None,
        env: HashMap::new(),
        secrets: HashMap::new(),
        stream: false,
        session_token: None,
        revert: Some(revert),
        confirm_within_secs: None,
        reevaluate: false,
        ssh_hostkey: None,
        require_approval: None,
        wait_approval_secs: None,
        verb: None,
    }
}

/// A `tokio::io::AsyncWrite` whose writes succeed `ok_writes` times and then
/// fail with `BrokenPipe`. With `ok_writes == 0` it fails on the very first
/// write, simulating a client stream that drops the instant the daemon
/// begins forwarding the child's output. The forward child still spawns and
/// runs (so the mutation may have applied); only streaming its output fails.
struct FlakyWriter {
    remaining_ok: usize,
}

impl FlakyWriter {
    fn failing_after(ok_writes: usize) -> Self {
        Self {
            remaining_ok: ok_writes,
        }
    }
}

impl AsyncWrite for FlakyWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.remaining_ok == 0 {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "client stream dropped",
            )));
        }
        self.remaining_ok -= 1;
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// CONTAINMENT-LEAK (regression for the just-landed disconnect fix): a
/// contained forward command that LAUNCHES and then fails because the client
/// stream drops mid-run must STAY ARMED — the provisional stays in the
/// registry with `forward_done` set so the auto-revert can still fire. A
/// leak here would let an unconfirmed mutation persist past its deadline.
#[cfg(unix)]
#[tokio::test]
async fn containment_stays_armed_when_client_stream_drops_after_launch() {
    let (cfg, _operator, agent) = gating_config(7001, 1000);
    let agent_principal = agent.principal();

    // Forward `echo` produces a line, so the daemon attempts to stream it;
    // our writer fails on that first write -> exec_failed_after_start.
    let request = contain_request(
        "echo",
        &["contained-change"],
        RevertSpec {
            binary: "true".to_string(),
            args: Vec::new(),
        },
    );
    let mut writer = FlakyWriter::failing_after(0);

    let result = arm_containment(
        request,
        &cfg,
        &agent,
        agent_principal,
        "recoverable change".to_string(),
        0,
        true, // stream_output: exercise the streaming failure path
        &mut writer,
    )
    .await;

    // The forward child launched then failed: started=true.
    match &result.exec {
        ExecOutcome::Failed { started, .. } => {
            assert!(*started, "client stream drop must report started=true");
        }
        other => panic!("expected Failed{{started:true}}, got {:?}", other),
    }

    // Invariant: the provisional is STILL ARMED with forward_done set, so the
    // sweeper's take_due can fire the auto-revert. It must NOT have been
    // dropped (that would leak the unconfirmed mutation).
    let reg = cfg.provisional.read().await;
    let rows = reg.list();
    assert_eq!(rows.len(), 1, "the armed provisional must be retained");
    let p = &rows[0];
    assert_eq!(p.status, ProvisionalStatus::Armed);
    assert!(
        p.forward_done,
        "forward_done must be set so the deadline is honored"
    );
    assert_eq!(reg.outstanding(), 1, "the armed row still occupies a slot");
}

/// Counterpart to the leak test: a contained forward command that FAILS TO
/// SPAWN (nonexistent binary, started=false) has no observable effect, so
/// the provisional is DROPPED — there is nothing to revert.
#[cfg(unix)]
#[tokio::test]
async fn containment_dropped_when_forward_fails_to_spawn() {
    let (cfg, _operator, agent) = gating_config(7002, 1000);
    let agent_principal = agent.principal();

    let request = contain_request(
        "guard-nonexistent-binary-xyz",
        &[],
        RevertSpec {
            binary: "true".to_string(),
            args: Vec::new(),
        },
    );
    let mut sink = tokio::io::sink();

    let result = arm_containment(
        request,
        &cfg,
        &agent,
        agent_principal,
        "recoverable change".to_string(),
        0,
        false,
        &mut sink,
    )
    .await;

    match &result.exec {
        ExecOutcome::Failed { started, .. } => {
            assert!(!*started, "spawn failure must report started=false");
        }
        other => panic!("expected Failed{{started:false}}, got {:?}", other),
    }

    // The provisional was dropped: nothing ran, so nothing to revert.
    let reg = cfg.provisional.read().await;
    assert!(
        reg.list().is_empty(),
        "a never-launched forward must drop its provisional"
    );
}

/// contain -> operator confirm keeps the change (no revert fires), and
/// confirm is daemon-principal-only: a non-operator caller is refused before
/// the registry is touched.
#[cfg(unix)]
#[tokio::test]
async fn contain_then_operator_confirm_keeps_change_nonoperator_refused() {
    let (cfg, operator, agent) = gating_config(7003, 1000);
    let agent_principal = agent.principal();

    let request = contain_request(
        "true",
        &[],
        RevertSpec {
            binary: "true".to_string(),
            args: Vec::new(),
        },
    );
    let mut sink = tokio::io::sink();
    let result = arm_containment(
        request,
        &cfg,
        &agent,
        agent_principal,
        "recoverable change".to_string(),
        0,
        false,
        &mut sink,
    )
    .await;
    let handle = match &result.exec {
        ExecOutcome::Provisional { handle, .. } => handle.clone(),
        other => panic!("expected Provisional, got {:?}", other),
    };

    // A non-operator (uid != daemon_principal) cannot confirm: validate_admin
    // refuses before handle_confirm runs, so the row is untouched.
    let refused = handle_admin_request(
        &cfg,
        &agent,
        AdminRequest::Confirm {
            handle: handle.clone(),
        },
    )
    .await;
    match refused {
        AdminResponse::Error { message } => {
            assert!(
                message.contains("not the daemon principal"),
                "got: {message}"
            );
        }
        other => panic!("non-operator confirm must be refused, got {:?}", other),
    }
    assert_eq!(
        cfg.provisional.read().await.get(&handle).unwrap().status,
        ProvisionalStatus::Armed,
        "a refused confirm must not change state"
    );

    // The operator confirms: the change is kept and the auto-revert is
    // cancelled.
    let ok = handle_admin_request(
        &cfg,
        &operator,
        AdminRequest::Confirm {
            handle: handle.clone(),
        },
    )
    .await;
    assert!(matches!(ok, AdminResponse::GateAction { .. }));
    assert_eq!(
        cfg.provisional.read().await.get(&handle).unwrap().status,
        ProvisionalStatus::Confirmed
    );

    // A confirmed provisional is never due, even far past any deadline: the
    // sweeper's take_due step yields nothing to revert.
    let due = cfg
        .provisional
        .write()
        .await
        .take_due(now_unix() + 10_000_000);
    assert!(due.is_empty(), "a confirmed change must never auto-revert");
}

/// contain -> deadline passes -> the sweeper's auto-revert path fires and
/// rolls the change back. Drives the sweeper's `take_due` + `finish_revert`
/// steps directly (the live `gating_sweeper` is an infinite loop with a
/// startup grace, so its time-driven body is exercised piecewise here).
#[cfg(unix)]
#[tokio::test]
async fn contain_then_deadline_triggers_sweeper_autorevert() {
    let (cfg, _operator, agent) = gating_config(7004, 1000);
    let agent_principal = agent.principal();

    // A 1s window: the smallest the clamp allows.
    let mut request = contain_request(
        "true",
        &[],
        RevertSpec {
            binary: "true".to_string(),
            args: Vec::new(),
        },
    );
    request.confirm_within_secs = Some(1);
    let mut sink = tokio::io::sink();
    let result = arm_containment(
        request,
        &cfg,
        &agent,
        agent_principal,
        "recoverable change".to_string(),
        0,
        false,
        &mut sink,
    )
    .await;
    let handle = match &result.exec {
        ExecOutcome::Provisional { handle, .. } => handle.clone(),
        other => panic!("expected Provisional, got {:?}", other),
    };

    // Sweeper step: claim every armed-and-due provisional (simulate the
    // deadline by passing a `now` well past it), then run each revert.
    let due = cfg
        .provisional
        .write()
        .await
        .take_due(now_unix() + 10_000_000);
    assert_eq!(
        due.len(),
        1,
        "the armed provisional is due past its deadline"
    );
    for p in &due {
        finish_revert(&cfg, p, &CallerIdentity::Unknown, "auto").await;
    }

    // The `true` revert exits 0 -> Reverted.
    assert_eq!(
        cfg.provisional.read().await.get(&handle).unwrap().status,
        ProvisionalStatus::Reverted,
        "auto-revert must roll the unconfirmed change back"
    );
}

/// A recoverable command whose free-form `--revert` cannot be affirmed is
/// HELD for operator review, not armed with an unverified rollback and not
/// silently denied. Here the rollback binary is structurally invalid, so
/// `assess_revert` returns `NeedsReview` before any evaluator call, keeping
/// the test deterministic and cross-platform (the hold path spawns no child).
#[tokio::test]
async fn recoverable_with_unaffirmable_revert_is_held_for_review() {
    let (cfg, _operator, agent) = gating_config(7011, 1000);

    let request = contain_request(
        "systemctl",
        &["restart", "app"],
        RevertSpec {
            binary: "../evil".to_string(), // `..` rejected by invalid_binary_reason
            args: Vec::new(),
        },
    );
    let inputs = GateInputs {
        reason: "recoverable restart".to_string(),
        risk: Some(2),
        reversibility: Some(Reversibility::Recoverable),
        revert_preauthorized: false,
        verb: None,
        bypass: false,
    };
    let mut sink = tokio::io::sink();
    let result = route_gated_allow(request, &cfg, &agent, inputs, 0, false, &mut sink).await;

    let handle = match &result.exec {
        ExecOutcome::Held { handle, .. } => handle.clone(),
        other => panic!("expected Held, got {:?}", other),
    };
    assert!(
        result.policy_reason().contains("held for operator review"),
        "reason should explain the escalation: {}",
        result.policy_reason()
    );
    assert_eq!(
        cfg.provisional.read().await.outstanding(),
        0,
        "an unaffirmable rollback must never arm a containment envelope"
    );
    assert_eq!(
        cfg.approvals.read().await.get(&handle).unwrap().status,
        ApprovalStatus::Pending,
        "the forward command must be queued for an operator decision"
    );
}

/// hold -> operator approve executes from the bound snapshot; a non-operator
/// caller cannot approve (validate_admin refuses before any state change).
#[cfg(unix)]
#[tokio::test]
async fn hold_then_operator_approve_executes_snapshot_nonoperator_refused() {
    let (cfg, operator, agent) = gating_config(7005, 1000);
    let agent_principal = agent.principal();

    // Hold a command. `true` is the bound binary; approval must run exactly
    // this snapshot.
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
    let mut sink = tokio::io::sink();
    let held = hold_for_approval(
        request,
        &cfg,
        &agent,
        agent_principal,
        "needs sign-off".to_string(),
        Some(9),
        Some(Reversibility::Irreversible),
        None,
        false,
        &mut sink,
    )
    .await;
    let handle = match &held.exec {
        ExecOutcome::Held { handle, .. } => handle.clone(),
        other => panic!("expected Held, got {:?}", other),
    };

    // Non-operator approve is refused; the hold stays pending.
    let refused = handle_admin_request(
        &cfg,
        &agent,
        AdminRequest::Approve {
            handle: handle.clone(),
        },
    )
    .await;
    match refused {
        AdminResponse::Error { message } => {
            assert!(
                message.contains("not the daemon principal"),
                "got: {message}"
            );
        }
        other => panic!("non-operator approve must be refused, got {:?}", other),
    }
    assert_eq!(
        cfg.approvals.read().await.get(&handle).unwrap().status,
        ApprovalStatus::Pending,
        "a refused approve must not change state"
    );

    // Operator approves: the snapshot executes (`true` -> exit 0) and the row
    // becomes Approved.
    let ok = handle_admin_request(
        &cfg,
        &operator,
        AdminRequest::Approve {
            handle: handle.clone(),
        },
    )
    .await;
    match ok {
        AdminResponse::GateAction { exit_code, .. } => {
            assert_eq!(exit_code, Some(0), "approved `true` exits 0");
        }
        other => panic!("operator approve should execute, got {:?}", other),
    }
    assert_eq!(
        cfg.approvals.read().await.get(&handle).unwrap().status,
        ApprovalStatus::Approved
    );
}

/// Wait (bounded) for a pending approval row to appear and return its handle.
async fn wait_for_pending_hold(cfg: &ServerConfig) -> String {
    for _ in 0..100 {
        let pending: Vec<String> = cfg
            .approvals
            .read()
            .await
            .list()
            .into_iter()
            .filter(|a| a.status == ApprovalStatus::Pending)
            .map(|a| a.handle)
            .collect();
        if let Some(h) = pending.into_iter().next() {
            return h;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("no pending hold appeared");
}

/// A kube-proxy `hold` parks the request in the approval queue: an operator
/// approve releases the waiter without spawning any process, an operator
/// deny fails it closed, and a waiter that vanishes undecided (client
/// disconnect) retires its row so the queue never offers a dead approval.
#[cfg(unix)]
#[tokio::test]
async fn kube_proxy_hold_routes_through_approval_queue() {
    let (cfg, operator, _agent) = gating_config(7013, 1000);
    let sink = Arc::new(DaemonGateSink {
        config: cfg.clone(),
        kubeconfig: PathBuf::from("unused-in-test"),
        snapshot_dir: std::env::temp_dir(),
        window_secs: 60,
    });

    // Approve: the waiter returns Approved with the queue handle; the row is
    // Approved and carries no exec result (nothing ran).
    let s = sink.clone();
    let waiter = tokio::spawn(async move {
        guard::proxy::GateSink::hold_request(&*s, "delete namespaces/prod", "namespace delete")
            .await
    });
    let handle = wait_for_pending_hold(&cfg).await;
    let resp = handle_admin_request(
        &cfg,
        &operator,
        AdminRequest::Approve {
            handle: handle.clone(),
        },
    )
    .await;
    match resp {
        AdminResponse::GateAction {
            message, exit_code, ..
        } => {
            assert!(message.contains("forwarding"), "got: {message}");
            assert_eq!(exit_code, None, "a released API hold executes nothing");
        }
        other => panic!("operator approve should release the hold, got {:?}", other),
    }
    match waiter.await.unwrap() {
        guard::proxy::HoldDecision::Approved { handle: h } => assert_eq!(h, handle),
        other => panic!("expected Approved, got {:?}", other),
    }
    assert_eq!(
        cfg.approvals.read().await.get(&handle).unwrap().status,
        ApprovalStatus::Approved
    );

    // Deny: the waiter fails closed with the operator's reason.
    let s = sink.clone();
    let waiter = tokio::spawn(async move {
        guard::proxy::GateSink::hold_request(&*s, "delete namespaces/prod", "namespace delete")
            .await
    });
    let handle = wait_for_pending_hold(&cfg).await;
    let resp = handle_admin_request(
        &cfg,
        &operator,
        AdminRequest::Deny {
            handle: handle.clone(),
        },
    )
    .await;
    assert!(
        !matches!(resp, AdminResponse::Error { .. }),
        "operator deny should succeed: {:?}",
        resp
    );
    match waiter.await.unwrap() {
        guard::proxy::HoldDecision::Denied { .. } => {}
        other => panic!("expected Denied, got {:?}", other),
    }
    assert_eq!(
        cfg.approvals.read().await.get(&handle).unwrap().status,
        ApprovalStatus::Denied
    );

    // Disconnect: dropping the waiter mid-hold retires the pending row.
    let s = sink.clone();
    let waiter = tokio::spawn(async move {
        guard::proxy::GateSink::hold_request(&*s, "delete namespaces/prod", "namespace delete")
            .await
    });
    let handle = wait_for_pending_hold(&cfg).await;
    waiter.abort();
    let mut retired = false;
    for _ in 0..100 {
        if cfg.approvals.read().await.get(&handle).unwrap().status == ApprovalStatus::ExecFailed {
            retired = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        retired,
        "an abandoned hold must be retired, not left pending"
    );
}

/// A non-streaming `--wait-approval` waiter must return as soon as the
/// operator decides, not park until its timeout: the waiter registers with
/// the notifier before checking status, so a decision landing in the gap
/// still completes the park immediately.
#[tokio::test]
async fn nonstreaming_wait_approval_returns_promptly_on_decision() {
    let (cfg, _operator, agent) = gating_config(7014, 1000);
    let agent_principal = agent.principal();

    let request = ExecuteRequest {
        binary: "rm".to_string(),
        args: vec!["-rf".to_string(), "/data".to_string()],
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
        wait_approval_secs: Some(30),
        verb: None,
    };
    let cfg2 = cfg.clone();
    let waiter = tokio::spawn(async move {
        let mut sink = tokio::io::sink();
        hold_for_approval(
            request,
            &cfg2,
            &agent,
            agent_principal,
            "destructive".to_string(),
            Some(10),
            Some(Reversibility::Irreversible),
            None,
            false,
            &mut sink,
        )
        .await
    });

    let handle = wait_for_pending_hold(&cfg).await;
    {
        let mut reg = cfg.approvals.write().await;
        reg.deny(&handle, now_unix(), "operator rejected".to_string())
            .unwrap();
    }

    // Well under the 30s wait: the deny must wake the waiter.
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
        .await
        .expect("waiter must wake on the decision, not sit out its timeout")
        .unwrap();
    assert!(!result.policy_allowed(), "denied decision is returned");
    assert!(
        result.policy_reason().contains("operator rejected"),
        "got: {}",
        result.policy_reason()
    );
}

/// hold -> TTL expiry -> the sweeper denies (fail-closed); the command never
/// executes. Cross-platform: no child is spawned on this path.
#[tokio::test]
async fn hold_then_ttl_expiry_denies_fail_closed() {
    let (cfg, _operator, agent) = gating_config(7006, 1000);
    let agent_principal = agent.principal();

    let request = ExecuteRequest {
        binary: "rm".to_string(),
        args: vec!["-rf".to_string(), "/data".to_string()],
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
    let mut sink = tokio::io::sink();
    let held = hold_for_approval(
        request,
        &cfg,
        &agent,
        agent_principal,
        "destructive".to_string(),
        Some(10),
        Some(Reversibility::Irreversible),
        None,
        false,
        &mut sink,
    )
    .await;
    let handle = match &held.exec {
        ExecOutcome::Held { handle, .. } => handle.clone(),
        other => panic!("expected Held, got {:?}", other),
    };

    // Sweeper step: expire every pending hold past its TTL. Pass a `now` far
    // beyond the TTL so the deadline has certainly passed.
    let expired = cfg
        .approvals
        .write()
        .await
        .expire_due(now_unix() + APPROVAL_TTL_SECS + 10_000);
    assert_eq!(expired, vec![handle.clone()]);

    let row = cfg.approvals.read().await.get(&handle).cloned().unwrap();
    assert_eq!(
        row.status,
        ApprovalStatus::Expired,
        "an unattended hold must fail closed (deny), not execute"
    );
    // The client-facing result is a denial, never an execution.
    let result = approval_to_result(&row);
    assert!(!result.policy_allowed());
    assert!(result.policy_reason().contains("expired"));
    assert!(matches!(result.exec, ExecOutcome::NotAttempted));
}

#[test]
fn hash_secret_value_is_salted_and_value_sensitive() {
    let a = hash_secret_value("salt1", "v1");
    // Deterministic for the same (salt, value).
    assert_eq!(a, hash_secret_value("salt1", "v1"));
    // Sensitive to the value.
    assert_ne!(a, hash_secret_value("salt1", "v2"));
    // Sensitive to the salt (so a persisted digest is not a plain value hash).
    assert_ne!(a, hash_secret_value("salt2", "v1"));
    // 32-byte SHA-256 -> 64 hex chars.
    assert_eq!(a.len(), 64);
}

/// A held command captures a salted hash of its mapped secret VALUES. If the
/// same-principal caller swaps a value between hold and approval, approval
/// fails closed before the command runs.
#[tokio::test]
async fn approve_rejected_when_bound_secret_value_changed() {
    let (cfg, _operator, agent) = gating_config(7201, 4201);
    let agent_principal = agent.principal();
    let p = agent_principal.clone().expect("agent principal");
    cfg.secrets.set(&p, "BIND_TEST_KEY", "v1").await.unwrap();

    let mut secrets = HashMap::new();
    secrets.insert("INJECTED".to_string(), "BIND_TEST_KEY".to_string());
    let request = ExecuteRequest {
        binary: "true".to_string(),
        args: Vec::new(),
        auth_token: None,
        env: HashMap::new(),
        secrets,
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
    let mut sink = tokio::io::sink();
    let held = hold_for_approval(
        request,
        &cfg,
        &agent,
        agent_principal.clone(),
        "needs review".to_string(),
        Some(8),
        Some(Reversibility::Irreversible),
        None,
        false,
        &mut sink,
    )
    .await;
    let handle = match &held.exec {
        ExecOutcome::Held { handle, .. } => handle.clone(),
        other => panic!("expected Held, got {:?}", other),
    };

    let snapshot = cfg
        .approvals
        .read()
        .await
        .get(&handle)
        .cloned()
        .unwrap()
        .snapshot;
    assert!(
        snapshot.secret_binding.is_some(),
        "a secret-value binding must be captured at hold time"
    );

    // The same principal swaps the value the operator was reviewing.
    cfg.secrets
        .set(&p, "BIND_TEST_KEY", "v2-tampered")
        .await
        .unwrap();

    let result = execute_snapshot(&cfg, &snapshot, "operator approved").await;
    match &result.exec {
        ExecOutcome::Failed { reason, started } => {
            assert!(!started, "the command must not have started");
            assert!(
                reason.contains("changed since the command was held"),
                "got: {}",
                reason
            );
        }
        other => panic!("expected a fail-closed rejection, got {:?}", other),
    }

    let _ = cfg.secrets.delete(&p, "BIND_TEST_KEY").await;
}

/// When the bound value is unchanged, the binding check passes (it does not
/// reject), so the approved command proceeds to execution.
#[tokio::test]
async fn approve_passes_binding_when_secret_value_unchanged() {
    let (cfg, _operator, agent) = gating_config(7202, 4202);
    let agent_principal = agent.principal();
    let p = agent_principal.clone().expect("agent principal");
    cfg.secrets.set(&p, "BIND_OK_KEY", "stable").await.unwrap();

    let mut secrets = HashMap::new();
    secrets.insert("INJECTED".to_string(), "BIND_OK_KEY".to_string());
    let request = ExecuteRequest {
        binary: "true".to_string(),
        args: Vec::new(),
        auth_token: None,
        env: HashMap::new(),
        secrets,
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
    let mut sink = tokio::io::sink();
    let held = hold_for_approval(
        request,
        &cfg,
        &agent,
        agent_principal.clone(),
        "needs review".to_string(),
        Some(8),
        Some(Reversibility::Irreversible),
        None,
        false,
        &mut sink,
    )
    .await;
    let handle = match &held.exec {
        ExecOutcome::Held { handle, .. } => handle.clone(),
        other => panic!("expected Held, got {:?}", other),
    };
    let snapshot = cfg
        .approvals
        .read()
        .await
        .get(&handle)
        .cloned()
        .unwrap()
        .snapshot;

    // Value unchanged -> the binding check must NOT reject. The subsequent
    // exec of `true` succeeds on Unix; on Windows there is no `true` binary,
    // so it may fail to spawn — either way it is not the binding rejection,
    // which is what this test asserts.
    let result = execute_snapshot(&cfg, &snapshot, "operator approved").await;
    if let ExecOutcome::Failed { reason, .. } = &result.exec {
        assert!(
            !reason.contains("changed since the command was held"),
            "binding check must not reject an unchanged value; got: {}",
            reason
        );
    }

    let _ = cfg.secrets.delete(&p, "BIND_OK_KEY").await;
}

/// The binding is mandatory: a secret that is UNRESOLVED at hold is bound by
/// a sentinel, so a same-principal caller cannot disable verification by
/// making a secret absent at hold and then creating it with a chosen value
/// before approval. Approval fails closed when the absent secret appears.
#[tokio::test]
async fn approve_rejected_when_unresolved_secret_appears_after_hold() {
    let (cfg, _operator, agent) = gating_config(7203, 4203);
    let agent_principal = agent.principal();
    let p = agent_principal.clone().expect("agent principal");
    // The secret does NOT exist at hold time.
    let _ = cfg.secrets.delete(&p, "BIND_LATE_KEY").await;

    let mut secrets = HashMap::new();
    secrets.insert("INJECTED".to_string(), "BIND_LATE_KEY".to_string());
    let request = ExecuteRequest {
        binary: "true".to_string(),
        args: Vec::new(),
        auth_token: None,
        env: HashMap::new(),
        secrets,
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
    let mut sink = tokio::io::sink();
    let held = hold_for_approval(
        request,
        &cfg,
        &agent,
        agent_principal.clone(),
        "needs review".to_string(),
        Some(8),
        Some(Reversibility::Irreversible),
        None,
        false,
        &mut sink,
    )
    .await;
    let handle = match &held.exec {
        ExecOutcome::Held { handle, .. } => handle.clone(),
        other => panic!("expected Held, got {:?}", other),
    };
    let snapshot = cfg
        .approvals
        .read()
        .await
        .get(&handle)
        .cloned()
        .unwrap()
        .snapshot;
    // A binding is captured even though the secret was unresolved at hold.
    assert!(
        snapshot.secret_binding.is_some(),
        "the binding must be mandatory, capturing a sentinel for the absent secret"
    );

    // The caller now creates the previously-absent secret with a chosen value.
    cfg.secrets
        .set(&p, "BIND_LATE_KEY", "sneaked-in")
        .await
        .unwrap();

    let result = execute_snapshot(&cfg, &snapshot, "operator approved").await;
    match &result.exec {
        ExecOutcome::Failed { reason, started } => {
            assert!(!started, "the command must not have started");
            assert!(
                reason.contains("changed since the command was held"),
                "got: {}",
                reason
            );
        }
        other => panic!("expected a fail-closed rejection, got {:?}", other),
    }

    let _ = cfg.secrets.delete(&p, "BIND_LATE_KEY").await;
}

/// The approval discussion thread accepts notes from the operator and from
/// the hold's original requester, refuses everyone else, and freezes once
/// the hold is decided.
#[tokio::test]
async fn approval_note_operator_and_owner_post_others_refused() {
    let (cfg, operator, agent) = gating_config(7301, 4301);
    let agent_principal = agent.principal();
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
    let mut sink = tokio::io::sink();
    let held = hold_for_approval(
        request,
        &cfg,
        &agent,
        agent_principal.clone(),
        "review".to_string(),
        Some(8),
        Some(Reversibility::Irreversible),
        None,
        false,
        &mut sink,
    )
    .await;
    let handle = match &held.exec {
        ExecOutcome::Held { handle, .. } => handle.clone(),
        other => panic!("expected Held, got {:?}", other),
    };

    // The requester (hold owner) can post.
    let r = handle_approval_note(&cfg, &agent, &handle, "why is this needed?").await;
    assert!(
        matches!(r, AdminResponse::ApprovalShow { .. }),
        "owner should post: {:?}",
        r
    );

    // The operator can post; the thread now has both turns, labeled.
    let r = handle_approval_note(&cfg, &operator, &handle, "ok, approving").await;
    match r {
        AdminResponse::ApprovalShow { item } => {
            assert_eq!(item.notes.len(), 2);
            assert_eq!(item.notes[0].author, "requester");
            assert_eq!(item.notes[1].author, "operator");
        }
        other => panic!("operator should post: {:?}", other),
    }

    // A different non-operator principal is refused (NotFound, no leak).
    let stranger = CallerIdentity::Unix { uid: 9999 };
    assert!(
        matches!(
            handle_approval_note(&cfg, &stranger, &handle, "let me in").await,
            AdminResponse::Error { .. }
        ),
        "a stranger must be refused"
    );

    // Empty text is rejected.
    assert!(matches!(
        handle_approval_note(&cfg, &operator, &handle, "   ").await,
        AdminResponse::Error { .. }
    ));

    // Once decided, the thread is frozen.
    cfg.approvals
        .write()
        .await
        .deny(&handle, now_unix(), "denied".to_string())
        .unwrap();
    assert!(
        matches!(
            handle_approval_note(&cfg, &operator, &handle, "too late").await,
            AdminResponse::Error { .. }
        ),
        "a decided hold's thread must be frozen"
    );
}

/// approve after the verb catalog version changed is voided: the approved
/// artifact may no longer mean what the operator reviewed, so the daemon
/// fails it closed rather than executing a stale rendering. Cross-platform:
/// the void check returns before any child is spawned.
#[tokio::test]
async fn approve_voided_when_verb_catalog_version_changed() {
    let (cfg, operator, agent) = gating_config(7007, 1000);

    // Enqueue a hold that originated from a verb, stamped with a catalog
    // version that differs from the live (empty) catalog's version. Use a
    // binary that would clearly execute if the void check were skipped, so a
    // false pass is detectable.
    let handle = new_handle();
    let snapshot = ApprovalSnapshot {
        binary: "true".to_string(),
        args: Vec::new(),
        env: BTreeMap::new(),
        secret_keys: BTreeMap::new(),
        verb_name: Some("restart-service".to_string()),
        verb_params: BTreeMap::new(),
        // Live catalog (VerbCatalog::empty()) has version 0; a stale stamp.
        catalog_version: Some(424_242),
        principal: agent.principal(),
        secret_binding: None,
    };
    let approval = Approval {
        handle: handle.clone(),
        snapshot,
        reason: "verb hold".to_string(),
        risk: Some(8),
        reversibility: Some(Reversibility::Irreversible),
        created_unix: now_unix(),
        ttl_secs: APPROVAL_TTL_SECS,
        status: ApprovalStatus::Pending,
        decided_unix: None,
        decided_reason: None,
        result_exit: None,
        result_stdout: None,
        result_stderr: None,
        notes: Vec::new(),
    };
    assert_ne!(
        approval.snapshot.catalog_version,
        Some(cfg.verbs.read().await.version()),
        "test precondition: the stamped version must differ from live"
    );
    cfg.approvals.write().await.enqueue(approval);

    let voided = handle_admin_request(
        &cfg,
        &operator,
        AdminRequest::Approve {
            handle: handle.clone(),
        },
    )
    .await;
    match voided {
        AdminResponse::Error { message } => {
            assert!(
                message.contains("catalog changed") && message.contains("voided"),
                "got: {message}"
            );
        }
        other => panic!("a stale-catalog approve must be voided, got {:?}", other),
    }

    // The hold is terminal (ExecFailed), not Approved: nothing executed.
    assert_eq!(
        cfg.approvals.read().await.get(&handle).unwrap().status,
        ApprovalStatus::ExecFailed
    );
}

/// Sanity: `Coverage::contain` is what a provisional carries, so the
/// client-facing result of a contained action advertises the residual risk
/// the operator owns (the gate did not verify the rollback inverts the
/// change). Guards against silently dropping coverage from the result.
#[test]
fn provisional_result_carries_contain_coverage() {
    let r = ExecuteResult::provisional(
        "recoverable".to_string(),
        "handle123".to_string(),
        Coverage::contain(),
        Some(0),
        None,
        None,
    );
    match &r.exec {
        ExecOutcome::Provisional {
            coverage, handle, ..
        } => {
            assert_eq!(handle, "handle123");
            assert!(coverage.not_checked.iter().any(|s| s.contains("invert")));
        }
        other => panic!("expected Provisional, got {:?}", other),
    }
}

// ---- Filesystem read-grant tests ----------------------------------------

#[test]
fn grant_envelope_routes_to_its_own_variant() {
    let grant_json = serde_json::to_string(&IncomingMessage::Grant {
        grant: GrantRequest::Read {
            path: "/home/op/values.yaml".to_string(),
            ttl_secs: 300,
            session_token: None,
            reevaluate: false,
        },
    })
    .unwrap();
    let parsed: IncomingMessage = serde_json::from_str(&grant_json).unwrap();
    assert!(matches!(parsed, IncomingMessage::Grant { .. }));

    // A bare execute request still routes to Execute, not Grant, under the
    // untagged enum.
    let exec: IncomingMessage = serde_json::from_str(r#"{"binary":"ls","args":[]}"#).unwrap();
    assert!(matches!(exec, IncomingMessage::Execute(_)));
}

#[cfg(windows)]
#[tokio::test]
async fn grant_read_is_denied_on_non_unix_platform() {
    let (cfg, _buf) = make_test_config();
    let caller = CallerIdentity::Unix { uid: 1000 };
    let result = handle_grant_request(
        &cfg,
        &caller,
        GrantRequest::Read {
            path: "/home/op/values.yaml".to_string(),
            ttl_secs: 300,
            session_token: None,
            reevaluate: false,
        },
    )
    .await;
    assert!(!result.policy_allowed());
    assert!(
        result
            .policy_reason()
            .contains("not supported on this platform"),
        "got: {}",
        result.policy_reason()
    );
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(unix)]
fn acl_tools_available() -> bool {
    let ok = |bin: &str| {
        std::process::Command::new(bin)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };
    ok("setfacl") && ok("getfacl")
}

#[cfg(unix)]
async fn getfacl_raw(path: &Path) -> String {
    let out = Command::new("getfacl")
        .arg("-n")
        .arg("--absolute-names")
        .arg("--")
        .arg(path)
        .output()
        .await
        .unwrap();
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// Whether a named `user:<uid>:` ACL entry exists on `path` (any perms).
#[cfg(unix)]
async fn getfacl_has_user(path: &Path, uid: u32) -> bool {
    let want = format!("user:{uid}:");
    getfacl_raw(path)
        .await
        .lines()
        .any(|l| l.trim().starts_with(&want))
}

#[cfg(unix)]
#[tokio::test]
async fn grant_read_deny_list_short_circuits_before_evaluator() {
    // The evaluator here is LLM-disabled with no policy, so a request that
    // reached it would be denied with "default-deny". A .vault_pass path is
    // instead denied with the deny-list reason, proving the static check
    // ran before any evaluator involvement.
    let (cfg, _buf) = make_test_config();
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join(".vault_pass");
    std::fs::write(&vault, "secret").unwrap();
    let caller = CallerIdentity::Unix {
        uid: unsafe { libc::geteuid() },
    };
    let result = handle_grant_request(
        &cfg,
        &caller,
        GrantRequest::Read {
            path: vault.display().to_string(),
            ttl_secs: 300,
            session_token: None,
            reevaluate: false,
        },
    )
    .await;
    assert!(!result.policy_allowed());
    assert!(
        result.policy_reason().contains("credential material"),
        "expected deny-list reason, got: {}",
        result.policy_reason()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn grant_read_denies_kubeconfig() {
    let (cfg, _buf) = make_test_config();
    let dir = tempfile::tempdir().unwrap();
    let kube = dir.path().join(".kube");
    std::fs::create_dir_all(&kube).unwrap();
    let config_file = kube.join("config");
    std::fs::write(&config_file, "apiVersion: v1").unwrap();
    let caller = CallerIdentity::Unix {
        uid: unsafe { libc::geteuid() },
    };
    let result = handle_grant_request(
        &cfg,
        &caller,
        GrantRequest::Read {
            path: config_file.display().to_string(),
            ttl_secs: 300,
            session_token: None,
            reevaluate: false,
        },
    )
    .await;
    assert!(!result.policy_allowed());
    assert!(
        result.policy_reason().contains("kube-proxy"),
        "got: {}",
        result.policy_reason()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn grant_revoke_is_not_scoped_to_the_requesting_caller() {
    // Revocation is intentionally an any-caller operation: a grant created
    // under session A can be revoked by a caller presenting session B's token
    // (or none at all), because revoking only ever removes access. This
    // proves that documented design (see the comment at handle_grant_revoke),
    // not an oversight in the unused `_session_token` parameter.
    let (cfg, _buf) = make_test_config();
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("values.yaml");
    std::fs::write(&target, "k: v").unwrap();
    let key = std::fs::canonicalize(&target)
        .unwrap()
        .display()
        .to_string();

    // Session A seeds an active grant. Empty ACL entries keep revocation free
    // of any real setfacl call (nothing to remove), so the test does not
    // depend on ACL tooling being installed.
    let now = now_unix();
    cfg.read_grants.write().await.insert(ReadGrant {
        handle: "hA".to_string(),
        principal: Some(PrincipalKey::from_uid(4242)),
        granting_session: Some("session-A".to_string()),
        target_path: key.clone(),
        grantee_uid: 4242,
        entries: Vec::new(),
        reason: "seeded by session A".to_string(),
        created_unix: now,
        expires_unix: now + 300,
        status: ReadGrantStatus::Active,
        revert_detail: None,
    });

    // Session B (a different token) revokes by path alone.
    let caller_b = CallerIdentity::Unix {
        uid: unsafe { libc::geteuid() },
    };
    let result = handle_grant_revoke(
        &cfg,
        &caller_b,
        target.display().to_string(),
        Some("session-B".to_string()),
    )
    .await;

    assert!(
        result.policy_allowed(),
        "any caller may revoke; got: {}",
        result.policy_reason()
    );
    assert_eq!(
        cfg.read_grants.read().await.get(&key).unwrap().status,
        ReadGrantStatus::Revoked,
        "the grant session A created must be revoked by session B"
    );
}

#[cfg(unix)]
#[test]
fn permission_denied_path_understands_common_error_shapes() {
    // coreutils
    assert_eq!(
        permission_denied_path("cat: /home/op/vars.yml: Permission denied").as_deref(),
        Some("/home/op/vars.yml")
    );
    // Python / ansible
    assert_eq!(
        permission_denied_path("[Errno 13] Permission denied: '/home/op/inventory.ini'").as_deref(),
        Some("/home/op/inventory.ini")
    );
    // Go tools (helm etc.)
    assert_eq!(
        permission_denied_path("Error: open /home/op/values.yaml: permission denied").as_deref(),
        Some("/home/op/values.yaml")
    );
    // A denied line with no path, and unrelated failures, yield nothing.
    assert_eq!(permission_denied_path("permission denied"), None);
    assert_eq!(
        permission_denied_path("error: /home/op/vars.yml: no such file"),
        None
    );
}

/// A permission failure naming a path the grant pipeline rejects (here:
/// unresolvable) must surface the command's own failure unchanged — no
/// retry loop, no grant row.
#[cfg(unix)]
#[tokio::test]
async fn read_grant_retry_returns_original_failure_when_grant_denied() {
    let (cfg, _buf) = make_test_config();
    let caller = CallerIdentity::Unix {
        uid: unsafe { libc::geteuid() },
    };
    let request = ExecuteRequest {
        binary: "sh".to_string(),
        args: vec![
            "-c".to_string(),
            "echo \"cat: /definitely/missing/vars.yml: Permission denied\" >&2; exit 1".to_string(),
        ],
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
    let mut sink = tokio::io::sink();
    let result = exec_with_read_grant_retry(
        request,
        &cfg,
        &caller,
        "test allow".to_string(),
        0,
        false,
        &mut sink,
    )
    .await;
    match &result.exec {
        ExecOutcome::Completed { exit_code, .. } => assert_eq!(*exit_code, Some(1)),
        other => panic!("expected the original failure, got {other:?}"),
    }
    assert!(
        cfg.read_grants.read().await.list().is_empty(),
        "a denied grant must leave no grant row"
    );
}

/// The full transparent path: a command fails naming a readable-policy
/// file, the read-grant pipeline (session-allowed here) applies a TTL ACL,
/// and the command is retried and succeeds. The agent never issued
/// `grant-read`.
#[cfg(unix)]
#[tokio::test]
async fn read_grant_retry_grants_and_reruns_after_permission_denied() {
    if !acl_tools_available() {
        eprintln!("skipping: setfacl/getfacl not available");
        return;
    }
    // The grant walks up to the file owner's home directory, so the target
    // must live under the real home.
    let Some(home) = dirs::home_dir() else {
        eprintln!("skipping: no home directory");
        return;
    };
    let Ok(dir) = tempfile::tempdir_in(&home) else {
        eprintln!("skipping: home directory not writable");
        return;
    };
    let target = dir.path().join("values.yaml");
    std::fs::write(&target, "k: v").unwrap();
    let canonical = std::fs::canonicalize(&target)
        .unwrap()
        .display()
        .to_string();
    let flag = dir.path().join("ran-once");

    let (mut cfg, _buf) = make_test_config();
    // The grantee must resolve to a real account for the ACL to apply.
    cfg.daemon_uid = unsafe { libc::geteuid() };
    // A session allow rule authorizes the grant deterministically, so the
    // test never reaches the (unconfigured) evaluator.
    cfg.sessions.write().await.grant(
        "sess-retry".to_string(),
        SessionGrant {
            allow: vec!["grant-read*".to_string()],
            deny: Vec::new(),
            allow_exact: Vec::new(),
            deny_exact: Vec::new(),
            expires_at: None,
            prompt_append: None,
            generated_notes: Vec::new(),
            granted_at: 0,
            static_only: false,
            auto_amend: false,
        },
    );

    let script = format!(
            "if [ -e '{}' ]; then exit 0; else echo \"cat: {}: Permission denied\" >&2; touch '{}'; exit 1; fi",
            flag.display(),
            canonical,
            flag.display()
        );
    let request = ExecuteRequest {
        binary: "sh".to_string(),
        args: vec!["-c".to_string(), script],
        auth_token: None,
        env: HashMap::new(),
        secrets: HashMap::new(),
        stream: false,
        session_token: Some("sess-retry".to_string()),
        revert: None,
        confirm_within_secs: None,
        reevaluate: false,
        ssh_hostkey: None,
        require_approval: None,
        wait_approval_secs: None,
        verb: None,
    };
    let caller = CallerIdentity::Unix {
        uid: unsafe { libc::geteuid() },
    };
    let mut sink = tokio::io::sink();
    let result = exec_with_read_grant_retry(
        request,
        &cfg,
        &caller,
        "test allow".to_string(),
        0,
        false,
        &mut sink,
    )
    .await;
    match &result.exec {
        ExecOutcome::Completed { exit_code, .. } => assert_eq!(
            *exit_code,
            Some(0),
            "the retried command must succeed after the grant"
        ),
        other => panic!("expected a completed retry, got {other:?}"),
    }
    let grant = cfg
        .read_grants
        .read()
        .await
        .get(&canonical)
        .cloned()
        .expect("the transparent grant must be recorded");
    assert_eq!(grant.status, ReadGrantStatus::Active);
    assert_eq!(grant.granting_session.as_deref(), Some("sess-retry"));

    // Cleanup: revoke so no ACL outlives the test.
    let _ = handle_grant_revoke(&cfg, &caller, canonical, None).await;
}

/// Build a home/pub_dir(0755)/priv_dir(0700)/values.yaml tree and return the
/// paths, so ACL tests can exercise "add traverse only where missing".
#[cfg(unix)]
fn build_grant_tree(home: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let pub_dir = home.join("pub_dir");
    std::fs::create_dir(&pub_dir).unwrap();
    set_mode(&pub_dir, 0o755);
    let priv_dir = pub_dir.join("priv_dir");
    std::fs::create_dir(&priv_dir).unwrap();
    set_mode(&priv_dir, 0o700);
    let target = priv_dir.join("values.yaml");
    std::fs::write(&target, "k: v").unwrap();
    set_mode(&target, 0o600);
    (pub_dir, priv_dir, target)
}

// A uid distinct from the test runner's own, so owner permission bits never
// grant it traverse and the "where missing" logic must add an entry.
#[cfg(unix)]
const TEST_GRANTEE_UID: u32 = 987654;
#[cfg(unix)]
const TEST_GRANTEE_GID: u32 = 987654;

#[cfg(unix)]
#[tokio::test]
async fn apply_read_grant_adds_traverse_only_where_missing_and_only_x() {
    if !acl_tools_available() {
        eprintln!("skipping: setfacl/getfacl not available");
        return;
    }
    let home = tempfile::tempdir().unwrap();
    set_mode(home.path(), 0o755); // world-traversable home: no traverse grant needed here
    let (pub_dir, priv_dir, target) = build_grant_tree(home.path());
    let pub_before = getfacl_raw(&pub_dir).await;

    let entries = apply_read_grant(&target, TEST_GRANTEE_UID, TEST_GRANTEE_GID, home.path())
        .await
        .expect("apply grant");

    // The private dir was 0700, so a traverse grant was added; the
    // world-traversable pub dir and home were skipped. The leaf got read.
    let priv_str = priv_dir.display().to_string();
    let target_str = target.display().to_string();
    let pub_str = pub_dir.display().to_string();
    let home_str = home.path().display().to_string();
    assert!(
        entries.iter().any(|e| e.path == priv_str && e.perms == "x"),
        "priv dir should get an x-only traverse grant: {entries:?}"
    );
    assert!(
        entries
            .iter()
            .any(|e| e.path == target_str && e.perms == "r"),
        "leaf should get an r grant: {entries:?}"
    );
    assert!(
        !entries.iter().any(|e| e.path == pub_str),
        "world-traversable pub dir must NOT get a grant: {entries:?}"
    );
    assert!(
        !entries.iter().any(|e| e.path == home_str),
        "world-traversable home must NOT get a grant: {entries:?}"
    );
    // Every ancestor grant is x-only (never r or w).
    for e in &entries {
        if e.path != target_str {
            assert_eq!(e.perms, "x", "ancestor grant must be x-only: {e:?}");
        }
    }
    // The untouched pub dir's ACL is byte-identical to before.
    assert_eq!(pub_before, getfacl_raw(&pub_dir).await);
    assert!(getfacl_user_has_traverse(&priv_dir, TEST_GRANTEE_UID).await);
}

/// The apply is pinned to the inodes vetted at plan time: swapping the
/// target for a different file between evaluation and apply must abort the
/// grant and roll back any ancestor entries already applied.
#[cfg(unix)]
#[tokio::test]
async fn read_grant_apply_aborts_when_target_swapped_after_plan() {
    if !acl_tools_available() {
        eprintln!("skipping: setfacl/getfacl not available");
        return;
    }
    let home = tempfile::tempdir().unwrap();
    set_mode(home.path(), 0o755);
    let (_pub_dir, priv_dir, target) = build_grant_tree(home.path());

    let planned = plan_read_grant(&target, TEST_GRANTEE_UID, TEST_GRANTEE_GID, home.path())
        .await
        .expect("plan grant");

    // Swap the vetted target for a symlink to a different file: the
    // original inode stays alive under another name so the filesystem
    // cannot recycle its number, and the path now resolves to the "secret".
    let secret = home.path().join("id_rsa");
    std::fs::write(&secret, "PRIVATE KEY").unwrap();
    std::fs::rename(&target, priv_dir.join("orig.yaml")).unwrap();
    std::os::unix::fs::symlink(&secret, &target).unwrap();

    let err = apply_read_grant_entries(TEST_GRANTEE_UID, &planned)
        .await
        .expect_err("apply must refuse the swapped inode");
    assert!(
        err.to_string()
            .contains("changed between policy evaluation"),
        "got: {err:#}"
    );
    assert!(
        !getfacl_user_has_traverse(&priv_dir, TEST_GRANTEE_UID).await,
        "the ancestor traverse entry applied before the abort must be rolled back"
    );
}

/// A multi-hardlink target is refused at plan time: the ACL binds to the
/// inode, which is reachable under every other link name.
#[cfg(unix)]
#[tokio::test]
async fn read_grant_denies_multi_hardlink_target() {
    let home = tempfile::tempdir().unwrap();
    set_mode(home.path(), 0o755);
    let (_pub_dir, priv_dir, target) = build_grant_tree(home.path());
    std::fs::hard_link(&target, priv_dir.join("alias.yaml")).unwrap();

    let err = plan_read_grant(&target, TEST_GRANTEE_UID, TEST_GRANTEE_GID, home.path())
        .await
        .expect_err("multi-hardlink target must be refused");
    assert!(err.to_string().contains("hard links"), "got: {err:#}");
}

#[cfg(unix)]
#[tokio::test]
async fn revoke_removes_exactly_added_entries_and_nothing_else() {
    if !acl_tools_available() {
        eprintln!("skipping: setfacl/getfacl not available");
        return;
    }
    let home = tempfile::tempdir().unwrap();
    set_mode(home.path(), 0o755);
    let (pub_dir, priv_dir, target) = build_grant_tree(home.path());

    // Seed an unrelated pre-existing ACL entry on the private dir; revocation
    // must leave it untouched (proving "removes exactly the added entries and
    // nothing else", which a blanket ACL wipe would violate).
    const OTHER_UID: u32 = 111222;
    let seed = Command::new("setfacl")
        .arg("-m")
        .arg(format!("u:{OTHER_UID}:rx"))
        .arg("--")
        .arg(&priv_dir)
        .output()
        .await
        .unwrap();
    assert!(seed.status.success());
    assert!(getfacl_has_user(&priv_dir, OTHER_UID).await);
    let pub_before = getfacl_raw(&pub_dir).await;

    let entries = apply_read_grant(&target, TEST_GRANTEE_UID, TEST_GRANTEE_GID, home.path())
        .await
        .expect("apply grant");
    assert!(getfacl_has_user(&priv_dir, TEST_GRANTEE_UID).await);

    let grant = ReadGrant {
        handle: "h".to_string(),
        principal: None,
        granting_session: None,
        target_path: target.display().to_string(),
        grantee_uid: TEST_GRANTEE_UID,
        entries,
        reason: "test".to_string(),
        created_unix: 0,
        expires_unix: 0,
        status: ReadGrantStatus::Reverting,
        revert_detail: None,
    };
    revoke_read_grant_acls(&grant).await.expect("revoke");

    // Exactly the granted entry is gone; the pre-existing unrelated entry
    // survives, and the never-touched pub dir is byte-identical.
    assert!(
        !getfacl_has_user(&priv_dir, TEST_GRANTEE_UID).await,
        "granted entry must be removed"
    );
    assert!(
        getfacl_has_user(&priv_dir, OTHER_UID).await,
        "pre-existing unrelated ACL entry must survive revocation"
    );
    assert!(!getfacl_has_user(&target, TEST_GRANTEE_UID).await);
    assert_eq!(pub_before, getfacl_raw(&pub_dir).await);
}

#[cfg(unix)]
#[tokio::test]
async fn expired_read_grant_is_auto_revoked() {
    if !acl_tools_available() {
        eprintln!("skipping: setfacl/getfacl not available");
        return;
    }
    let (cfg, _buf) = make_test_config();
    let home = tempfile::tempdir().unwrap();
    set_mode(home.path(), 0o755);
    let (_pub_dir, priv_dir, target) = build_grant_tree(home.path());

    let entries = apply_read_grant(&target, TEST_GRANTEE_UID, TEST_GRANTEE_GID, home.path())
        .await
        .expect("apply grant");
    assert!(getfacl_user_has_traverse(&priv_dir, TEST_GRANTEE_UID).await);

    let now = now_unix();
    let grant = ReadGrant {
        handle: "h".to_string(),
        principal: None,
        granting_session: None,
        target_path: target.display().to_string(),
        grantee_uid: TEST_GRANTEE_UID,
        entries,
        reason: "test".to_string(),
        created_unix: now,
        expires_unix: now.saturating_sub(1), // already past its TTL
        status: ReadGrantStatus::Active,
        revert_detail: None,
    };
    cfg.read_grants.write().await.insert(grant.clone());

    // The sweeper's due-claim drives the timer: an expired Active grant is
    // taken and then reverted.
    let due = cfg.read_grants.write().await.take_due(now_unix());
    assert_eq!(due.len(), 1);
    finish_read_grant_revert(&cfg, &due[0], "expiry").await;

    assert!(!getfacl_user_has_traverse(&priv_dir, TEST_GRANTEE_UID).await);
    assert_eq!(
        cfg.read_grants
            .read()
            .await
            .get(&grant.target_path)
            .unwrap()
            .status,
        ReadGrantStatus::Revoked
    );
}

/// The revert-availability fragment reaches the evaluator prompt only when a
/// rollback was supplied under the gate, composes with a session prompt, and
/// never turns a no-context call into a cache-bypassing one.
#[test]
fn revert_context_merges_only_when_supplied() {
    use super::execute::merge_revert_context;
    assert_eq!(merge_revert_context(None, false), None);
    let sp = merge_revert_context(Some("session ctx".to_string()), false);
    assert_eq!(sp.as_deref(), Some("session ctx"));
    let with = merge_revert_context(None, true).expect("fragment present");
    assert!(with.contains("REVERSIBILITY CONTEXT"));
    let both = merge_revert_context(Some("session ctx".to_string()), true).expect("merged");
    assert!(both.contains("REVERSIBILITY CONTEXT") && both.ends_with("session ctx"));
}
