use crate::server::admin::handle_admin_request_for_test;
use crate::server::execute::execute_command;
#[cfg(unix)]
use crate::server::execute::{observe_command_started_for_test, pause_command_initiation_for_test};
#[cfg(unix)]
use crate::server::gate_runtime::resume_approval;
use crate::server::wire::{
    AdminRequest, AdminResponse, CallerIdentity, ExecuteRequest, GateStatus, VerbInvocation,
};
use crate::server::ServerContext;
use crate::session::SessionGrant;
#[cfg(unix)]
use crate::session::{SessionDecisionSource, SessionExecStatus, SessionInteraction};
use guard::evaluate::{EvalConfig, Evaluator};
use guard::gating::approval::ApprovalStatus;
#[cfg(unix)]
use guard::gating::deny_shape::{canonical_argv, DenyLearningConfig, DenyShapeStore};
use guard::gating::verb::VerbCatalog;
use guard::gating::GateMode;
use guard::principal::PrincipalKey;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::make_test_config;
#[cfg(unix)]
use super::run_verb_synthesis_llm_with_preflight;
#[cfg(unix)]
use super::{trusted_artifact_tempdir, EnvRestore, TEST_ENV_LOCK};

fn generated_provider_credential() -> String {
    format!("fixture-{:032x}", rand::random::<u128>())
}

fn authority_tempdir() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("catalog test dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("harden catalog test dir");
    }
    directory
}

fn write_authority_file(path: &std::path::Path, content: impl AsRef<[u8]>) {
    std::fs::write(path, content).expect("write catalog test file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("harden catalog test file");
    }
}

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

#[cfg(unix)]
fn revision_bound_session() -> SessionGrant {
    let mut grant = SessionGrant {
        allow: Vec::new(),
        deny: Vec::new(),
        allow_exact: Vec::new(),
        deny_exact: Vec::new(),
        activated_verbs: Vec::new(),
        override_markers: Vec::new(),
        scope: Default::default(),
        expires_at: None,
        prompt_append: None,
        generated_notes: Vec::new(),
        static_only: false,
        auto_amend: false,
        granted_at: 0,
        owner: crate::session::SessionOwner::Principal(PrincipalKey::from_uid(1000)),
    };
    grant.scope.saved_grant = Some("scoped".to_string());
    grant.scope.secret_names = vec!["first-binding".to_string()];
    grant
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

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operator_artifact_mutation_before_process_start_denies_execution() {
    use std::os::unix::fs::PermissionsExt;

    let _environment_guard = TEST_ENV_LOCK.lock().await;
    let directory = trusted_artifact_tempdir();
    let private_key = directory.path().join("id_ed25519");
    write_authority_file(&private_key, "test key");
    let _path_restore = EnvRestore::capture("PATH");
    std::env::set_var("PATH", "/usr/bin:/bin");
    let yaml = format!(
        "verbs:\n  - name: pinned-artifact\n    binary: cat\n    args: [{}]\n    consequence: reversible\n    trusted: true\n",
        serde_json::to_string(&private_key).unwrap(),
    );
    let (mut server, _buffer) = make_test_config();
    server.config.gate = GateMode::Consequence;
    server.config.preflight = false;
    server.state.verbs = Arc::new(RwLock::new(VerbCatalog::from_yaml(yaml.as_str()).unwrap()));

    let (reached, release) = pause_command_initiation_for_test(&server);
    let executing_server = server.clone();
    let key_text = private_key.to_string_lossy().into_owned();
    let mut execution = tokio::spawn(async move {
        execute_command(
            raw_request("cat", &[&key_text], None),
            &executing_server,
            &CallerIdentity::Unix { uid: 1000 },
        )
        .await
        .into_response()
    });
    tokio::select! {
        permit = reached.acquire() => permit.unwrap().forget(),
        response = &mut execution => panic!(
            "command completed before the process-start mutation point: {:?}",
            response.unwrap()
        ),
        () = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
            panic!("command did not reach the process-start mutation point")
        }
    }
    std::fs::set_permissions(&private_key, std::fs::Permissions::from_mode(0o660)).unwrap();
    release.add_permits(1);

    let denied = tokio::time::timeout(std::time::Duration::from_secs(5), execution)
        .await
        .expect("command completes after releasing the process-start mutation point")
        .unwrap();
    assert!(!denied.allowed);
    assert!(
        denied.reason.contains("operator authority artifact"),
        "{denied:?}"
    );
    std::fs::set_permissions(&private_key, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ansible_password_helper_profile_is_denied_before_process_start() {
    use std::os::unix::fs::PermissionsExt;

    let _environment_guard = TEST_ENV_LOCK.lock().await;
    let directory = trusted_artifact_tempdir();
    let password_helper = directory.path().join("become-password-helper");
    write_authority_file(&password_helper, "#!/bin/sh\nprintf password\n");
    let ansible_config = directory.path().join("ansible.cfg");
    write_authority_file(
        &ansible_config,
        format!(
            "[defaults]\nbecome_password_file = {}\n",
            password_helper.display()
        ),
    );
    let playbook = directory.path().join("site.yml");
    write_authority_file(&playbook, "---\n- hosts: all\n  tasks: []\n");
    let executable = directory.path().join("ansible-playbook");
    write_authority_file(&executable, "#!/bin/sh\nexit 0\n");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let _path_restore = EnvRestore::capture("PATH");
    std::env::set_var(
        "PATH",
        format!("{}:/usr/bin:/bin", directory.path().display()),
    );
    let yaml = format!(
        "verbs:\n  - name: ansible-check\n    binary: ansible-playbook\n    args: [{}, \"--check\"]\n    consequence: reversible\n    trusted: true\n    coverage:\n      - name: check\n        action: preauthorized\n        required_args: [\"--check\"]\n",
        serde_json::to_string(&playbook).unwrap(),
    );
    let (mut server, _buffer) = make_test_config();
    server.config.gate = GateMode::Consequence;
    server.config.preflight = false;
    server.state.verbs = Arc::new(RwLock::new(VerbCatalog::from_yaml(&yaml).unwrap()));
    let tool_config = directory.path().join("tools.yaml");
    write_authority_file(
        &tool_config,
        format!(
            "tools:\n  ansible-playbook:\n    env:\n      ANSIBLE_CONFIG: {}\n",
            serde_json::to_string(&ansible_config).unwrap()
        ),
    );
    *server.state.tool_registry.write().await =
        crate::tool_config::ToolRegistry::load(&tool_config).unwrap();

    let playbook_text = playbook.to_string_lossy().into_owned();
    let denied = execute_command(
        raw_request(
            "ansible-playbook",
            &[playbook_text.as_str(), "--check"],
            None,
        ),
        &server,
        &CallerIdentity::Unix { uid: 1000 },
    )
    .await
    .into_response();
    assert!(!denied.allowed);
    assert!(
        denied.reason.contains("immutable profile snapshots"),
        "{denied:?}"
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn final_composed_match_rejects_nonprimary_amendment_and_new_deny() {
    const ORIGINAL: &str = r#"
verbs:
  - name: first-check
    binary: true
    args: ["--check"]
    consequence: reversible
    trusted: true
  - name: second-check
    binary: true
    args: ["--check"]
    consequence: reversible
    trusted: true
"#;
    let replacements = [
        ORIGINAL.replace(
            "name: second-check\n    binary: true",
            "name: second-check\n    binary: true\n    description: amended",
        ),
        format!(
            "{ORIGINAL}\n  - name: late-deny\n    binary: true\n    args: [\"--check\"]\n    consequence: reversible\n    coverage:\n      - name: deny-check\n        action: deny\n"
        ),
    ];

    for replacement in replacements {
        let (mut server, _buffer) = make_test_config();
        server.config.gate = GateMode::Consequence;
        server.state.verbs = Arc::new(RwLock::new(VerbCatalog::from_yaml(ORIGINAL).unwrap()));
        let (reached, release) = pause_command_initiation_for_test(&server);
        let executing_server = server.clone();
        let execution = tokio::spawn(async move {
            execute_command(
                raw_request("true", &["--check"], None),
                &executing_server,
                &CallerIdentity::Unix { uid: 1000 },
            )
            .await
            .into_response()
        });
        reached.acquire().await.unwrap().forget();
        *server.state.verbs.write().await = VerbCatalog::from_yaml(&replacement).unwrap();
        release.add_permits(1);

        let response = execution.await.unwrap();
        assert!(!response.allowed, "changed composed authority must deny");
        assert!(response.exit_code.is_none());
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verb_lease_ends_after_process_start_while_child_is_running() {
    use std::os::unix::fs::PermissionsExt;

    let _environment_guard = TEST_ENV_LOCK.lock().await;
    let _path_restore = EnvRestore::capture("PATH");
    let directory = tempfile::tempdir().unwrap();
    let executable_directory = trusted_artifact_tempdir();
    let authority_directory = authority_tempdir();
    let deny_config = DenyLearningConfig::new(authority_directory.path().join("deny.yaml"));
    let deny_store = DenyShapeStore::load(deny_config.clone()).unwrap();
    let release_child = directory.path().join("release");
    let script = format!(
        "while [ ! -e {} ]; do sleep 0.01; done",
        release_child.display()
    );
    let executable = executable_directory.path().join("printf");
    std::fs::write(&executable, format!("#!/bin/sh\n{script}\n")).unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::env::set_var(
        "PATH",
        format!("{}:/usr/bin:/bin", executable_directory.path().display()),
    );
    let yaml = "verbs:\n  - name: finite-start\n    binary: printf\n    consequence: reversible\n    trusted: true\n";
    let (mut server, _buffer) = make_test_config();
    server.config.gate = GateMode::Consequence;
    server.state.evaluator = Arc::new(
        Evaluator::new(EvalConfig::default().deny_shapes(Arc::new(RwLock::new(deny_store))))
            .unwrap(),
    );
    server.state.verbs = Arc::new(RwLock::new(VerbCatalog::from_yaml(yaml).unwrap()));
    let command_started = observe_command_started_for_test(&server);
    let executing_server = server.clone();
    let execution = tokio::spawn(async move {
        execute_command(
            raw_request("printf", &[], None),
            &executing_server,
            &CallerIdentity::Unix { uid: 1000 },
        )
        .await
        .into_response()
    });

    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        command_started.acquire(),
    )
    .await
    .expect("child process reaches the finite start boundary")
    .unwrap()
    .forget();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut catalog = server.state.verbs.write().await;
        *catalog = VerbCatalog::from_yaml("verbs: []").unwrap();
    })
    .await
    .expect("catalog mutation is not held for the child lifetime");
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::task::spawn_blocking(move || {
            let mut independent = DenyShapeStore::load(deny_config).unwrap();
            let evidence = canonical_argv(&[]);
            independent
                .promote_shape(
                    "fixture",
                    "printf",
                    &format!("^{}$", regex::escape(&evidence)),
                    &[evidence],
                    "blocked",
                    1,
                )
                .unwrap();
        }),
    )
    .await
    .expect("learned deny mutation is not held for the child lifetime")
    .unwrap();
    std::fs::write(&release_child, b"release").unwrap();
    assert!(execution.await.unwrap().allowed);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn learned_deny_committed_after_initial_allow_prevents_process_start() {
    let directory = authority_tempdir();
    let path = directory.path().join("deny.yaml");
    let deny_config = DenyLearningConfig::new(path.clone());
    let deny_store = DenyShapeStore::load(deny_config.clone()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let llm_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(run_verb_synthesis_llm_with_preflight(
        listener,
        |_| serde_json::json!({}),
        "APPROVE",
        "fixture evaluator allow",
    ));
    let evaluator = Evaluator::new(
        EvalConfig::default()
            .cache_enabled(false)
            .llm_api_key(generated_provider_credential())
            .llm_api_url(llm_url)
            .llm_retries(0)
            .gate_mode(GateMode::Consequence)
            .deny_shapes(Arc::new(RwLock::new(deny_store))),
    )
    .unwrap();
    let (mut server, _buffer) = make_test_config();
    server.config.gate = GateMode::Consequence;
    server.state.evaluator = Arc::new(evaluator);
    server.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            "verbs:\n  - name: checked\n    binary: true\n    args: [\"--check\"]\n    consequence: reversible\n    coverage:\n      - name: checked\n        action: evaluate\n        required_args: [\"--check\"]\n",
        )
        .unwrap(),
    ));
    let (reached, release) = pause_command_initiation_for_test(&server);
    let executing_server = server.clone();
    let execution = tokio::spawn(async move {
        execute_command(
            raw_request("true", &["--check"], None),
            &executing_server,
            &CallerIdentity::Unix { uid: 1000 },
        )
        .await
        .into_response()
    });
    tokio::time::timeout(std::time::Duration::from_secs(10), reached.acquire())
        .await
        .expect("command reaches the process-start authority boundary")
        .unwrap()
        .forget();
    let mut independent = DenyShapeStore::load(deny_config).unwrap();
    let evidence = canonical_argv(&["--check".to_string()]);
    independent
        .promote_shape(
            "fixture",
            "true",
            &format!("^{}$", regex::escape(&evidence)),
            &[evidence],
            "blocked",
            1,
        )
        .unwrap();
    release.add_permits(1);

    let response = execution.await.unwrap();
    assert!(!response.allowed);
    assert!(response.exit_code.is_none());
}

#[cfg(unix)]
#[tokio::test]
async fn exact_typed_verb_preempts_matching_learned_deny_at_process_start() {
    let directory = authority_tempdir();
    let deny_config = DenyLearningConfig::new(directory.path().join("deny.yaml"));
    let mut deny_store = DenyShapeStore::load(deny_config).unwrap();
    let evidence = canonical_argv(&["--check".to_string()]);
    deny_store
        .promote_shape(
            "fixture",
            "true",
            &format!("^{}$", regex::escape(&evidence)),
            &[evidence],
            "automatic heuristic",
            1,
        )
        .unwrap();

    let (mut server, _buffer) = make_test_config();
    server.config.gate = GateMode::Consequence;
    server.state.evaluator = Arc::new(
        Evaluator::new(
            EvalConfig::default()
                .llm_enabled(false)
                .deny_shapes(Arc::new(RwLock::new(deny_store))),
        )
        .unwrap(),
    );
    server.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            "verbs:\n  - name: typed-check\n    binary: true\n    args: [\"--check\"]\n    consequence: reversible\n    trusted: true\n",
        )
        .unwrap(),
    ));

    let response = execute_command(
        raw_request("true", &["--check"], None),
        &server,
        &CallerIdentity::Unix { uid: 1000 },
    )
    .await
    .into_response();

    assert!(
        response.allowed,
        "typed authority should preempt: {response:?}"
    );
    assert_eq!(response.exit_code, Some(0));
}

#[cfg(unix)]
#[tokio::test]
async fn trusted_verb_still_respects_explicit_static_deny_at_process_start() {
    let directory = authority_tempdir();
    let policy = directory.path().join("policy.yaml");
    std::fs::write(
        &policy,
        "policy:\n  commands:\n    deny:\n      - \"true --blocked\"\n",
    )
    .unwrap();
    let (mut server, _buffer) = make_test_config();
    server.config.gate = GateMode::Consequence;
    server.state.evaluator = Arc::new(
        Evaluator::new(EvalConfig::default().llm_enabled(false).policy_path(policy)).unwrap(),
    );
    server.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            "verbs:\n  - name: blocked\n    binary: true\n    args: [\"--blocked\"]\n    consequence: reversible\n    trusted: true\n",
        )
        .unwrap(),
    ));

    let response = execute_command(
        raw_request("true", &["--blocked"], None),
        &server,
        &CallerIdentity::Unix { uid: 1000 },
    )
    .await
    .into_response();

    assert!(!response.allowed);
    assert!(response.exit_code.is_none());
    assert!(response.reason.contains("static policy"), "{response:?}");
}

#[cfg(unix)]
#[tokio::test]
async fn trusted_verb_still_fails_closed_when_learned_deny_authority_is_unavailable() {
    let directory = authority_tempdir();
    let path = directory.path().join("deny.yaml");
    let deny_store = DenyShapeStore::load(DenyLearningConfig::new(path.clone())).unwrap();
    let (mut server, _buffer) = make_test_config();
    server.config.gate = GateMode::Consequence;
    server.state.evaluator = Arc::new(
        Evaluator::new(
            EvalConfig::default()
                .llm_enabled(false)
                .deny_shapes(Arc::new(RwLock::new(deny_store))),
        )
        .unwrap(),
    );
    server.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            "verbs:\n  - name: trusted-status\n    binary: true\n    consequence: reversible\n    trusted: true\n",
        )
        .unwrap(),
    ));
    std::fs::write(path, "invalid: [").unwrap();

    let response = execute_command(
        raw_request("true", &[], None),
        &server,
        &CallerIdentity::Unix { uid: 1000 },
    )
    .await
    .into_response();

    assert!(!response.allowed);
    assert!(response.exit_code.is_none());
    assert!(
        response
            .reason
            .contains("learned deny authority is unavailable"),
        "{response:?}"
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_entitlement_amendment_before_process_start_denies_execution() {
    let (mut server, _buffer) = make_test_config();
    server.config.gate = GateMode::Consequence;
    server.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            "verbs:\n  - name: session-check\n    binary: true\n    args: [\"--check\"]\n    consequence: reversible\n    trusted: true\n",
        )
        .unwrap(),
    ));
    let token = "revision-bound-command";
    assert!(server
        .state
        .sessions
        .write()
        .await
        .grant(token.to_string(), revision_bound_session()));
    let (reached, release) = pause_command_initiation_for_test(&server);
    let executing_server = server.clone();
    let execution = tokio::spawn(async move {
        execute_command(
            raw_request("true", &["--check"], Some(token)),
            &executing_server,
            &CallerIdentity::Unix { uid: 1000 },
        )
        .await
        .into_response()
    });
    reached.acquire().await.unwrap().forget();
    server.state.sessions.write().await.apply_delta(
        token,
        &crate::grant_profile::GrantRequestDelta {
            secret_names: vec!["second-binding".to_string()],
            ..Default::default()
        },
    );
    release.add_permits(1);

    let response = execution.await.unwrap();
    assert!(!response.allowed);
    assert!(response.exit_code.is_none());
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interaction_suspension_before_process_start_denies_execution() {
    let (mut server, _buffer) = make_test_config();
    server.config.gate = GateMode::Consequence;
    server.config.behavior_limits.max_denials = Some(1);
    server.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            "verbs:\n  - name: session-check\n    binary: true\n    args: [\"--check\"]\n    consequence: reversible\n    trusted: true\n",
        )
        .unwrap(),
    ));
    let token = "suspension-bound-command";
    assert!(server
        .state
        .sessions
        .write()
        .await
        .grant(token.to_string(), revision_bound_session()));
    let (reached, release) = pause_command_initiation_for_test(&server);
    let executing_server = server.clone();
    let execution = tokio::spawn(async move {
        execute_command(
            raw_request("true", &["--check"], Some(token)),
            &executing_server,
            &CallerIdentity::Unix { uid: 1000 },
        )
        .await
        .into_response()
    });
    reached.acquire().await.unwrap().forget();
    server.state.sessions.write().await.record_interaction(
        token,
        SessionInteraction {
            at_unix: guard::env::now_unix(),
            command: "denied command".to_string(),
            allowed: false,
            source: SessionDecisionSource::SessionDeny,
            reason: "denied".to_string(),
            risk: None,
            exec_status: SessionExecStatus::NotAttempted,
            exit_code: None,
            exposed_secret_refs: Vec::new(),
            decision_trace: None,
        },
    );
    release.add_permits(1);

    let response = execution.await.unwrap();
    assert!(!response.allowed);
    assert!(response.exit_code.is_none());
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn held_replay_rejects_session_revision_amendment_before_process_start() {
    let (mut server, _buffer) = make_test_config();
    server.config.gate = GateMode::Consequence;
    server.config.daemon_uid = 777;
    server.config.daemon_principal = PrincipalKey::from_uid(777);
    server.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            "verbs:\n  - name: held-session-check\n    binary: true\n    args: [\"--check\"]\n    consequence: irreversible\n    trusted: true\n",
        )
        .unwrap(),
    ));
    let token = "revision-bound-held-command";
    assert!(server
        .state
        .sessions
        .write()
        .await
        .grant(token.to_string(), revision_bound_session()));
    let mut request = raw_request("true", &["--check"], Some(token));
    request.require_approval = Some(true);
    let held = execute_command(request, &server, &CallerIdentity::Unix { uid: 1000 })
        .await
        .into_response();
    let handle = held.handle.expect("held command has an approval handle");
    assert!(matches!(
        handle_admin_request_for_test(
            &server,
            &CallerIdentity::UnixAdmin { uid: 777 },
            AdminRequest::Approve {
                handle: handle.clone(),
            },
        )
        .await,
        AdminResponse::GateAction { .. }
    ));
    let (reached, release) = pause_command_initiation_for_test(&server);
    let resuming = server.clone();
    let resuming_handle = handle.clone();
    let replay = tokio::spawn(async move {
        resume_approval(
            &resuming,
            &CallerIdentity::Unix { uid: 1000 },
            &resuming_handle,
        )
        .await
    });
    reached.acquire().await.unwrap().forget();
    server.state.sessions.write().await.apply_delta(
        token,
        &crate::grant_profile::GrantRequestDelta {
            secret_names: vec!["second-binding".to_string()],
            ..Default::default()
        },
    );
    release.add_permits(1);

    assert!(!matches!(
        replay.await.unwrap().exec,
        crate::server::wire::ExecOutcome::Completed { .. }
    ));
    assert_eq!(
        server
            .state
            .approvals
            .read()
            .await
            .get(&handle)
            .unwrap()
            .status,
        ApprovalStatus::ExecFailed
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn held_replay_rejects_interaction_suspension_before_process_start() {
    let (mut server, _buffer) = make_test_config();
    server.config.gate = GateMode::Consequence;
    server.config.behavior_limits.max_denials = Some(1);
    server.config.daemon_uid = 777;
    server.config.daemon_principal = PrincipalKey::from_uid(777);
    server.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            "verbs:\n  - name: held-session-check\n    binary: true\n    args: [\"--check\"]\n    consequence: irreversible\n    trusted: true\n",
        )
        .unwrap(),
    ));
    let token = "suspension-bound-held-command";
    assert!(server
        .state
        .sessions
        .write()
        .await
        .grant(token.to_string(), revision_bound_session()));
    let mut request = raw_request("true", &["--check"], Some(token));
    request.require_approval = Some(true);
    let held = execute_command(request, &server, &CallerIdentity::Unix { uid: 1000 })
        .await
        .into_response();
    let handle = held.handle.expect("held command has an approval handle");
    assert!(matches!(
        handle_admin_request_for_test(
            &server,
            &CallerIdentity::UnixAdmin { uid: 777 },
            AdminRequest::Approve {
                handle: handle.clone(),
            },
        )
        .await,
        AdminResponse::GateAction { .. }
    ));
    let (reached, release) = pause_command_initiation_for_test(&server);
    let resuming = server.clone();
    let resuming_handle = handle.clone();
    let replay = tokio::spawn(async move {
        resume_approval(
            &resuming,
            &CallerIdentity::Unix { uid: 1000 },
            &resuming_handle,
        )
        .await
    });
    reached.acquire().await.unwrap().forget();
    server.state.sessions.write().await.record_interaction(
        token,
        SessionInteraction {
            at_unix: guard::env::now_unix(),
            command: "denied command".to_string(),
            allowed: false,
            source: SessionDecisionSource::SessionDeny,
            reason: "denied".to_string(),
            risk: None,
            exec_status: SessionExecStatus::NotAttempted,
            exit_code: None,
            exposed_secret_refs: Vec::new(),
            decision_trace: None,
        },
    );
    release.add_permits(1);

    assert!(!matches!(
        replay.await.unwrap().exec,
        crate::server::wire::ExecOutcome::Completed { .. }
    ));
    assert_eq!(
        server
            .state
            .approvals
            .read()
            .await
            .get(&handle)
            .unwrap()
            .status,
        ApprovalStatus::ExecFailed
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn held_replay_revalidates_the_complete_composed_match_before_start() {
    const ORIGINAL: &str = r#"
verbs:
  - name: first-held-check
    binary: true
    args: ["--check"]
    consequence: irreversible
    trusted: true
  - name: second-held-check
    binary: true
    args: ["--check"]
    consequence: irreversible
    trusted: true
"#;
    let (mut server, _buffer) = make_test_config();
    server.config.gate = GateMode::Consequence;
    server.config.daemon_uid = 777;
    server.config.daemon_principal = PrincipalKey::from_uid(777);
    server.state.verbs = Arc::new(RwLock::new(VerbCatalog::from_yaml(ORIGINAL).unwrap()));
    let mut request = raw_request("true", &["--check"], None);
    request.require_approval = Some(true);
    let held = execute_command(request, &server, &CallerIdentity::Unix { uid: 1000 })
        .await
        .into_response();
    assert_eq!(held.status, Some(GateStatus::Held));
    let handle = held.handle.expect("held command has an approval handle");
    assert!(server
        .state
        .approvals
        .read()
        .await
        .get(&handle)
        .unwrap()
        .snapshot
        .verb_composition_digest
        .is_some());

    assert!(matches!(
        handle_admin_request_for_test(
            &server,
            &CallerIdentity::UnixAdmin { uid: 777 },
            AdminRequest::Approve {
                handle: handle.clone(),
            },
        )
        .await,
        AdminResponse::GateAction { .. }
    ));
    let (reached, release) = pause_command_initiation_for_test(&server);
    let resuming = server.clone();
    let resuming_handle = handle.clone();
    let replay = tokio::spawn(async move {
        resume_approval(
            &resuming,
            &CallerIdentity::Unix { uid: 1000 },
            &resuming_handle,
        )
        .await
    });
    reached.acquire().await.unwrap().forget();
    let amended = ORIGINAL.replace(
        "name: second-held-check\n    binary: true",
        "name: second-held-check\n    binary: true\n    description: amended",
    );
    *server.state.verbs.write().await = VerbCatalog::from_yaml(&amended).unwrap();
    release.add_permits(1);

    assert!(!matches!(
        replay.await.unwrap().exec,
        crate::server::wire::ExecOutcome::Completed { .. }
    ));
    assert_eq!(
        server
            .state
            .approvals
            .read()
            .await
            .get(&handle)
            .unwrap()
            .status,
        ApprovalStatus::ExecFailed
    );
}

#[cfg(unix)]
#[tokio::test]
async fn cwd_bound_coverage_resolves_after_canonicalization_and_rejects_changed_directory() {
    let (mut cfg, _buf) = make_test_config();
    cfg.config.gate = GateMode::Consequence;
    let root = trusted_artifact_tempdir();
    let root = root.path().canonicalize().unwrap();
    let root_yaml = serde_yaml_ng::to_string(&root).unwrap();
    let other = tempfile::tempdir().unwrap();
    cfg.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(&format!(
            r#"
verbs:
  - name: project-status
    binary: true
    consequence: reversible
    trusted: true
    coverage:
      - name: project-root
        action: preauthorized
        cwd: {}
"#,
            root_yaml.trim_end()
        ))
        .unwrap(),
    ));

    let mut approved = raw_request("true", &[], None);
    approved.cwd = Some(root);
    let approved = execute_command(approved, &cfg, &CallerIdentity::Unix { uid: 1000 })
        .await
        .into_response();
    assert!(approved.allowed, "{approved:?}");
    assert_eq!(approved.exit_code, Some(0));
    assert_eq!(approved.verb_matches[0].features, vec!["cwd:exact"]);

    let mut changed = raw_request("true", &[], None);
    changed.cwd = Some(other.path().to_path_buf());
    let changed = execute_command(changed, &cfg, &CallerIdentity::Unix { uid: 1000 })
        .await
        .into_response();
    assert!(!changed.allowed, "{changed:?}");
    assert!(changed.verb_matches.is_empty());
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

#[tokio::test]
async fn reversible_verb_with_hold_flag_routes_to_held() {
    let (mut cfg, _buf) = make_test_config();
    cfg.config.gate = GateMode::Consequence;
    cfg.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            "verbs:\n  - name: enumerate-accounts\n    binary: true\n    consequence: reversible\n    hold: true\n    trusted: true\n",
        )
        .unwrap(),
    ));
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
            name: "enumerate-accounts".to_string(),
            params: std::collections::BTreeMap::new(),
        }),
    };

    let response = execute_command(request, &cfg, &CallerIdentity::Unix { uid: 1000 })
        .await
        .into_response();
    assert!(response.allowed);
    assert_eq!(response.status, Some(GateStatus::Held));
    assert!(response.exit_code.is_none());
    assert!(response.handle.is_some());
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
    cfg.config.exec_as_caller = true;
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
async fn trusted_reverse_match_accepts_exact_typed_ansible_config_before_identity_floor() {
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
    assert!(
        !response.allowed,
        "fixed identity must reject: {response:?}"
    );
    assert!(response.reason.contains("shared child UID"));
    let trace = response.decision_trace.as_ref().expect("decision trace");
    assert_eq!(trace.version, guard::gating::DecisionTrace::VERSION);
    assert_eq!(trace.decision_source, response.decision_source);
    assert_eq!(trace.verb_matches.len(), 1);
    assert_eq!(trace.verb_matches[0].action, "preauthorized");
    assert_eq!(trace.failed_dimensions, vec!["validation"]);
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

    let response = handle_admin_request_for_test(
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
    binary: printf
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

    let response = handle_admin_request_for_test(
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
    assert_eq!(items[0].arg_template, vec!["show", "{target}"]);
    assert_eq!(items[0].params, vec!["target"]);
    assert_eq!(
        items[0].param_patterns.get("target").map(String::as_str),
        Some("^[a-z0-9-]+$")
    );
    let encoded = serde_json::to_string(&response).unwrap();
    for private in [
        "printf",
        "operator-only provenance",
        "trusted",
        "coverage",
        "credential_plan",
    ] {
        assert!(!encoded.contains(private), "leaked {private}: {encoded}");
    }

    assert!(!AdminRequest::VerbShow {
        name: "inspect-fixture".to_string()
    }
    .requires_admin_token());
    assert!(matches!(
        handle_admin_request_for_test(
            &cfg,
            &CallerIdentity::UnixAdmin { uid: 777 },
            AdminRequest::VerbList,
        )
        .await,
        AdminResponse::Verbs { .. }
    ));
}

/// A non-operator menu lists only verbs the caller can actually activate:
/// baseline verbs plus the caller's own session-activated scope. Foreign or
/// unactivated non-baseline verbs stay invisible, while operators keep the
/// complete catalog view.
#[tokio::test]
async fn non_operator_verb_menu_is_filtered_to_activatable_scope() {
    let (mut cfg, _buf) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            r#"
verbs:
  - name: open-fixture
    binary: printf
    consequence: reversible
  - name: session-only
    binary: printf
    baseline: false
    consequence: reversible
  - name: foreign-only
    binary: printf
    baseline: false
    consequence: reversible
"#,
        )
        .unwrap(),
    ));
    let mut grant = SessionGrant {
        allow: Vec::new(),
        deny: Vec::new(),
        allow_exact: Vec::new(),
        deny_exact: Vec::new(),
        activated_verbs: vec!["session-only".to_string()],
        override_markers: Vec::new(),
        scope: Default::default(),
        expires_at: None,
        prompt_append: None,
        generated_notes: Vec::new(),
        static_only: false,
        auto_amend: false,
        granted_at: 0,
        owner: crate::session::SessionOwner::Principal(PrincipalKey::from_uid(1001)),
    };
    grant.scope.access_managed = true;
    {
        let mut sessions = cfg.state.sessions.write().await;
        sessions.grant("menu-access".to_string(), grant);
        assert_eq!(
            sessions.install_access_grant(
                "menu-access",
                Some(2),
                "gr-menu".to_string(),
                vec!["session-only".to_string()],
            ),
            Some(true)
        );
    }

    let menu_names = |response: &AdminResponse| -> Vec<String> {
        let AdminResponse::VerbMenu { items } = response else {
            panic!("expected sanitized verb menu, got {response:?}");
        };
        items.iter().map(|item| item.name.clone()).collect()
    };

    let holder = handle_admin_request_for_test(
        &cfg,
        &CallerIdentity::Unix { uid: 1001 },
        AdminRequest::VerbList,
    )
    .await;
    assert_eq!(menu_names(&holder), vec!["open-fixture", "session-only"]);

    let stranger = handle_admin_request_for_test(
        &cfg,
        &CallerIdentity::Unix { uid: 2002 },
        AdminRequest::VerbList,
    )
    .await;
    assert_eq!(menu_names(&stranger), vec!["open-fixture"]);

    let operator = handle_admin_request_for_test(
        &cfg,
        &CallerIdentity::UnixAdmin { uid: 777 },
        AdminRequest::VerbList,
    )
    .await;
    let AdminResponse::Verbs { items } = operator else {
        panic!("operator must keep the complete catalog view");
    };
    assert_eq!(items.len(), 3);
}

/// Requester verb detail uses the same baseline and usable principal-bound
/// activated-verb visibility as the menu. It returns invocation-planning data
/// without executable or authority metadata, while an operator retains the
/// complete catalog definition. Missing and unavailable names share one
/// response so callers cannot enumerate the catalog through `verb show`.
#[tokio::test]
async fn requester_verb_show_matches_menu_visibility_without_leaking_catalog_detail() {
    let (mut cfg, _buf) = make_test_config();
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    cfg.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            r#"
verbs:
  - name: baseline-read
    description: Read a fixture
    binary: printf
    args: ["read", "{target}"]
    params:
      target: { pattern: "^[a-z0-9-]+$" }
    consequence: reversible
    evidence: private catalog evidence
  - name: requester-maintenance
    description: Maintain one fixture
    binary: printf
    args: ["maintain", "{target}"]
    baseline: false
    params:
      target: { pattern: "^[a-z0-9-]+$" }
    consequence: recoverable
    evidence: requester-only evidence
  - name: foreign-maintenance
    description: Maintain a foreign fixture
    binary: printf
    baseline: false
    consequence: recoverable
"#,
        )
        .unwrap(),
    ));
    let mut grant = SessionGrant {
        allow: Vec::new(),
        deny: Vec::new(),
        allow_exact: Vec::new(),
        deny_exact: Vec::new(),
        activated_verbs: vec!["requester-maintenance".to_string()],
        override_markers: Vec::new(),
        scope: Default::default(),
        expires_at: None,
        prompt_append: None,
        generated_notes: Vec::new(),
        static_only: false,
        auto_amend: false,
        granted_at: 0,
        owner: crate::session::SessionOwner::Principal(PrincipalKey::from_uid(1001)),
    };
    grant.scope.access_managed = true;
    {
        let mut sessions = cfg.state.sessions.write().await;
        sessions.grant("requester-show-token".to_string(), grant);
        assert_eq!(
            sessions.install_access_grant(
                "requester-show-token",
                Some(2),
                "gr-requester-show".to_string(),
                vec!["requester-maintenance".to_string()],
            ),
            Some(true)
        );
    }

    let requester = CallerIdentity::Unix { uid: 1001 };
    let stranger = CallerIdentity::Unix { uid: 2002 };
    let operator = CallerIdentity::UnixAdmin { uid: 777 };
    assert!(!AdminRequest::VerbShow {
        name: "baseline-read".to_string(),
    }
    .requires_admin_token());

    for name in ["baseline-read", "requester-maintenance"] {
        let response = handle_admin_request_for_test(
            &cfg,
            &requester,
            AdminRequest::VerbShow {
                name: name.to_string(),
            },
        )
        .await;
        let AdminResponse::VerbMenu { items } = response else {
            panic!("requester must receive a sanitized menu detail for {name}");
        };
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, name);
        if name != "foreign-maintenance" {
            assert_eq!(
                items[0].arg_template.last().map(String::as_str),
                Some("{target}")
            );
            assert_eq!(
                items[0].param_patterns.get("target").map(String::as_str),
                Some("^[a-z0-9-]+$")
            );
        }
        let encoded = serde_json::to_string(&items).unwrap();
        for private in [
            "printf",
            "private catalog evidence",
            "requester-only evidence",
        ] {
            assert!(
                !encoded.contains(private),
                "requester detail leaked {private}"
            );
        }
    }

    let unavailable = handle_admin_request_for_test(
        &cfg,
        &stranger,
        AdminRequest::VerbShow {
            name: "requester-maintenance".to_string(),
        },
    )
    .await;
    let unknown = handle_admin_request_for_test(
        &cfg,
        &stranger,
        AdminRequest::VerbShow {
            name: "not-a-verb".to_string(),
        },
    )
    .await;
    let error_message = |response: AdminResponse| match response {
        AdminResponse::Error { message } => message,
        other => panic!("expected non-leaking error, got {other:?}"),
    };
    assert_eq!(error_message(unavailable), error_message(unknown));

    let operator_detail = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::VerbShow {
            name: "foreign-maintenance".to_string(),
        },
    )
    .await;
    let AdminResponse::VerbCreated { verb, .. } = operator_detail else {
        panic!("operator must retain complete verb detail");
    };
    assert_eq!(verb.binary, "printf");
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

fn nonfinite_synthesis_arguments(_request: &str) -> serde_json::Value {
    serde_json::json!({
        "name": "inspect-fixture",
        "description": "Inspect one named fixture",
        "binary": "printf",
        "args": ["show", "{target}"],
        "params": {"target": {"pattern": "^[a-z0-9-]{1,63}$"}},
        "consequence": "reversible",
        "trusted": false,
        "evidence": "The command admits one bounded resource name."
    })
}

fn synthesis_arguments_with_sensitive_prose(_request: &str) -> serde_json::Value {
    let value = ["q", "7"].concat();
    serde_json::json!({
        "name": "check-compiler",
        "description": format!("password={value}"),
        "binary": "uptime",
        "args": ["--version"],
        "params": {},
        "consequence": "reversible",
        "trusted": false,
        "prompt_context": format!("password={value}"),
        "evidence": format!("password={value}")
    })
}

fn synthesis_arguments_with_sensitive_name(_request: &str) -> serde_json::Value {
    let value = ["q", "7"].concat();
    serde_json::json!({
        "name": format!("password={value}"),
        "description": "Inspect compiler version",
        "binary": "uptime",
        "args": ["--version"],
        "params": {},
        "consequence": "reversible",
        "trusted": false,
        "evidence": "The exact compiler version command is read only."
    })
}

fn relative_file_synthesis_arguments(_request: &str) -> serde_json::Value {
    serde_json::json!({
        "name": "apply-fixture",
        "description": "Apply one fixture manifest",
        "binary": "kubectl",
        "args": ["apply", "-f", "manifests/fixture.yaml"],
        "params": {},
        "consequence": "irreversible",
        "trusted": false,
        "evidence": "The manifest is fixed."
    })
}

fn file_backed_catalog() -> (tempfile::TempDir, VerbCatalog) {
    let dir = authority_tempdir();
    let path = dir.path().join("verbs.yaml");
    write_authority_file(&path, "verbs: []\n");
    let catalog = VerbCatalog::load(&path).expect("load empty catalog");
    (dir, catalog)
}

fn amend_test_catalog() -> (tempfile::TempDir, std::path::PathBuf, VerbCatalog) {
    let dir = authority_tempdir();
    let path = dir.path().join("verbs.yaml");
    write_authority_file(
        &path,
        r#"verbs:
  - name: inspect-fixture
    description: Inspect one fixture
    binary: printf
    args: [show, "{target}"]
    params:
      target: { pattern: "^[a-z0-9-]+$" }
    consequence: reversible
    trusted: true
  - name: untouched
    binary: true
    consequence: reversible
"#,
    );
    let catalog = VerbCatalog::load(&path).unwrap();
    (dir, path, catalog)
}

#[tokio::test]
async fn unavailable_catalog_disables_invocation_reverse_match_and_session_activation() {
    let (mut cfg, _buf) = make_test_config();
    cfg.config.gate = GateMode::Consequence;
    cfg.config.daemon_uid = 777;
    cfg.config.daemon_principal = PrincipalKey::from_uid(777);
    let directory = authority_tempdir();
    let path = directory.path().join("verbs.yaml");
    write_authority_file(
        &path,
        "verbs:\n  - name: session-safe\n    binary: true\n    baseline: false\n    consequence: reversible\n    trusted: true\n",
    );
    cfg.state.verbs = Arc::new(RwLock::new(VerbCatalog::load(&path).unwrap()));
    write_authority_file(&path, "verbs:\n  - malformed\n");

    let mut invocation = raw_request("", &[], None);
    invocation.verb = Some(VerbInvocation {
        name: "session-safe".to_string(),
        params: Default::default(),
    });
    let invoked = execute_command(invocation, &cfg, &CallerIdentity::Unix { uid: 1000 })
        .await
        .into_response();
    assert!(!invoked.allowed);
    assert!(invoked.reason.contains("catalog authority is unavailable"));

    let reversed = execute_command(
        raw_request("true", &[], None),
        &cfg,
        &CallerIdentity::Unix { uid: 1000 },
    )
    .await
    .into_response();
    assert!(!reversed.allowed);
    assert!(reversed.reason.contains("catalog authority is unavailable"));

    let session = handle_admin_request_for_test(
        &cfg,
        &CallerIdentity::UnixAdmin { uid: 777 },
        AdminRequest::SessionGrant {
            token: "catalog-unavailable".to_string(),
            allow: Vec::new(),
            deny: Vec::new(),
            activated_verbs: vec!["session-safe".to_string()],
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
        session,
        AdminResponse::Error { message } if message.contains("catalog authority is unavailable")
    ));
}

#[tokio::test]
async fn verb_amend_replaces_the_expected_definition_and_preserves_the_catalog() {
    let (mut cfg, _buf) = make_test_config();
    let (_dir, path, catalog) = amend_test_catalog();
    let current = catalog.get("inspect-fixture").unwrap().clone();
    let expected_digest = current.definition_digest();
    let mut replacement = current.clone();
    replacement.description = "Inspect one named fixture".to_string();
    let new_digest = replacement.definition_digest();
    cfg.state.verbs = Arc::new(RwLock::new(catalog));
    let operator = CallerIdentity::UnixAdmin { uid: 777 };

    let response = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::VerbAmend {
            name: "inspect-fixture".to_string(),
            expected_digest: expected_digest.clone(),
            replacement: Box::new(replacement.clone()),
        },
    )
    .await;
    let AdminResponse::VerbAmended {
        verb,
        previous_digest,
        digest,
    } = response
    else {
        panic!("expected successful amend, got {response:?}")
    };
    assert_eq!(verb.description, "Inspect one named fixture");
    assert_eq!(previous_digest, expected_digest);
    assert_eq!(digest, new_digest);

    let reloaded = VerbCatalog::load(&path).unwrap();
    assert_eq!(
        reloaded.get("inspect-fixture").unwrap().description,
        "Inspect one named fixture"
    );
    assert!(reloaded.get("untouched").is_some());
}

#[tokio::test]
async fn verb_add_persists_one_operator_definition_and_rejects_bad_writes_atomically() {
    let (mut cfg, _buf) = make_test_config();
    let (audit_directory, _audit) = super::attach_test_audit_log(&mut cfg);
    let (_dir, path, catalog) = amend_test_catalog();
    let mut added = catalog.get("inspect-fixture").unwrap().clone();
    added.name = "inspect-added-fixture".to_string();
    added.description = "Inspect one added fixture".to_string();
    added.coverage =
        serde_yaml_ng::from_str("- name: blocked\n  action: deny\n  required_args: [blocked]\n")
            .unwrap();
    let requested_digest = added.definition_digest();
    cfg.state.verbs = Arc::new(RwLock::new(catalog));
    let operator = CallerIdentity::UnixAdmin { uid: 777 };

    let response = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::VerbAdd {
            verb: Box::new(added.clone()),
        },
    )
    .await;
    let AdminResponse::VerbCreated {
        verb,
        persisted,
        preview_digest,
    } = response
    else {
        panic!("expected successful add, got {response:?}")
    };
    assert_ne!(verb.definition_digest(), requested_digest);
    let persisted_digest = verb.definition_digest();
    let persisted_audit_digest = format!("sha256:{persisted_digest}");
    let requested_audit_digest = format!("sha256:{requested_digest}");
    assert!(verb.coverage[0].sticky);
    assert!(persisted);
    assert!(preview_digest.is_none());
    let reloaded = VerbCatalog::load(&path).unwrap();
    let persisted_verb = reloaded.get("inspect-added-fixture").unwrap();
    assert_eq!(persisted_verb.description, "Inspect one added fixture");
    assert_eq!(persisted_verb.definition_digest(), persisted_digest);
    assert!(persisted_verb.coverage[0].sticky);
    assert!(reloaded.get("untouched").is_some());
    let records = guard::audit::tail_records(&audit_directory.path().join("audit.jsonl"), 10)
        .expect("read durable verb audit");
    let created = records
        .iter()
        .find(|record| record["kind"] == "VERB_CREATED")
        .expect("verb creation is audited");
    assert_eq!(
        created["caller"], "admin_uid=777",
        "durable audit must bind the authenticated operator identity"
    );
    let recorded_digest = created["fields"].as_array().and_then(|fields| {
        fields.iter().find_map(|field| {
            (field.get(0).and_then(serde_json::Value::as_str) == Some("definition_digest"))
                .then(|| field.get(1).and_then(serde_json::Value::as_str))
                .flatten()
        })
    });
    assert!(
        guard::redact::redact_output_text(&persisted_audit_digest) == persisted_audit_digest,
        "algorithm-qualified digest survives the audit redaction classifier"
    );
    assert!(
        guard::redact::redact_registered_exact_secrets(&persisted_audit_digest)
            == persisted_audit_digest,
        "algorithm-qualified digest is not registered as exact secret material"
    );
    assert_eq!(
        recorded_digest,
        Some(persisted_audit_digest.as_str()),
        "durable audit must bind the canonical persisted definition"
    );
    assert_ne!(recorded_digest, Some(requested_audit_digest.as_str()));
    let committed = std::fs::read(&path).unwrap();

    let duplicate = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::VerbAdd {
            verb: Box::new(added.clone()),
        },
    )
    .await;
    assert!(matches!(
        duplicate,
        AdminResponse::Error { message } if message.contains("already exists")
    ));
    assert_eq!(std::fs::read(&path).unwrap(), committed);

    let mut invalid = added;
    invalid.name = "invalid-added-fixture".to_string();
    invalid.params.get_mut("target").unwrap().pattern = "[a-z]+".to_string();
    let rejected = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::VerbAdd {
            verb: Box::new(invalid),
        },
    )
    .await;
    assert!(matches!(rejected, AdminResponse::Error { .. }));
    assert_eq!(std::fs::read(&path).unwrap(), committed);

    let mut generated = verb.clone();
    generated.name = "generated-added-fixture".to_string();
    generated.evidence = Some("model-authored evidence".to_string());
    let rejected = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::VerbAdd {
            verb: Box::new(generated),
        },
    )
    .await;
    assert!(matches!(
        rejected,
        AdminResponse::Error { message }
            if message.contains("operator-authored")
                && message.contains("evidence")
                && !message.contains("generated-added-fixture' cannot be added")
    ));
    assert_eq!(std::fs::read(&path).unwrap(), committed);
    assert!(AdminRequest::VerbAdd {
        verb: Box::new(verb),
    }
    .requires_admin_token());
}

#[tokio::test]
async fn verb_amend_rejects_a_stale_digest_without_writing() {
    let (mut cfg, _buf) = make_test_config();
    let (_dir, path, catalog) = amend_test_catalog();
    let original = std::fs::read(&path).unwrap();
    let mut replacement = catalog.get("inspect-fixture").unwrap().clone();
    replacement.description = "Stale replacement".to_string();
    cfg.state.verbs = Arc::new(RwLock::new(catalog));

    let response = handle_admin_request_for_test(
        &cfg,
        &CallerIdentity::UnixAdmin { uid: 777 },
        AdminRequest::VerbAmend {
            name: "inspect-fixture".to_string(),
            expected_digest: "0".repeat(64),
            replacement: Box::new(replacement),
        },
    )
    .await;
    let AdminResponse::Error { message } = response else {
        panic!("stale digest must fail")
    };
    assert!(message.contains("changed before amend"), "{message}");
    assert_eq!(std::fs::read(&path).unwrap(), original);
}

#[tokio::test]
async fn verb_amend_rejects_invalid_or_generated_candidates_without_writing() {
    let (mut cfg, _buf) = make_test_config();
    let (_dir, path, catalog) = amend_test_catalog();
    let original = std::fs::read(&path).unwrap();
    let current = catalog.get("inspect-fixture").unwrap().clone();
    let expected_digest = current.definition_digest();
    cfg.state.verbs = Arc::new(RwLock::new(catalog));
    let operator = CallerIdentity::UnixAdmin { uid: 777 };

    let mut invalid = current.clone();
    invalid.params.get_mut("target").unwrap().pattern = "[a-z]+".to_string();
    let response = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::VerbAmend {
            name: "inspect-fixture".to_string(),
            expected_digest: expected_digest.clone(),
            replacement: Box::new(invalid),
        },
    )
    .await;
    assert!(matches!(response, AdminResponse::Error { .. }));
    assert_eq!(std::fs::read(&path).unwrap(), original);

    let mut generated = current;
    generated.auto_promoted = true;
    let response = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::VerbAmend {
            name: "inspect-fixture".to_string(),
            expected_digest,
            replacement: Box::new(generated),
        },
    )
    .await;
    let AdminResponse::Error { message } = response else {
        panic!("generated candidate must fail")
    };
    assert!(message.contains("generated or reserved"), "{message}");
    assert_eq!(std::fs::read(&path).unwrap(), original);
    let replacement = cfg
        .state
        .verbs
        .read()
        .await
        .get("inspect-fixture")
        .unwrap()
        .clone();
    assert!(AdminRequest::VerbAmend {
        name: "inspect-fixture".to_string(),
        expected_digest: "0".repeat(64),
        replacement: Box::new(replacement),
    }
    .requires_admin_token());
}

fn synthesis_test_config(llm_url: String) -> (ServerContext, CallerIdentity) {
    let (mut cfg, _buf) = make_test_config();
    cfg.state.evaluator = Arc::new(
        Evaluator::new(
            EvalConfig::default()
                .llm_api_key(generated_provider_credential())
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

fn install_static_synthesis_policy(cfg: &mut ServerContext, decision: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("policy test dir");
    let path = dir.path().join("policy.yaml");
    std::fs::write(
        &path,
        format!("policy:\n  commands:\n    {decision}:\n      - \"uptime --version\"\n"),
    )
    .expect("write synthesis admission policy");
    cfg.state.evaluator = Arc::new(
        Evaluator::new(EvalConfig::default().llm_enabled(false).policy_path(path))
            .expect("build synthesis admission evaluator"),
    );
    dir
}

#[tokio::test]
async fn preview_digest_round_trip_installs_the_exact_reviewed_candidate() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(super::run_verb_synthesis_llm(listener));
    let (mut cfg, daemon) = synthesis_test_config(url);
    let (_dir, catalog) = file_backed_catalog();
    cfg.state.verbs = Arc::new(RwLock::new(catalog));

    let response = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::VerbCreate {
            prose: "Inspect compiler version.".to_string(),
            binary_hint: Some("uptime".to_string()),
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

    let _policy = install_static_synthesis_policy(&mut cfg, "allow");

    let response = handle_admin_request_for_test(
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
async fn successful_synthesis_sanitizes_preview_persistence_and_admin_projection() {
    let value = ["q", "7"].concat();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(super::run_verb_synthesis_llm_with(
        listener,
        synthesis_arguments_with_sensitive_prose,
    ));
    let (mut cfg, daemon) = synthesis_test_config(url);
    let (catalog_dir, catalog) = file_backed_catalog();
    cfg.state.verbs = Arc::new(RwLock::new(catalog));

    let response = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::VerbCreate {
            prose: format!("Inspect compiler version with password={value}."),
            binary_hint: Some("uptime".to_string()),
            preview: true,
            gate_feedback: Vec::new(),
        },
    )
    .await;
    let AdminResponse::VerbCreated {
        verb,
        preview_digest: Some(digest),
        ..
    } = response
    else {
        panic!("expected sanitized preview");
    };
    assert!(!serde_json::to_string(&verb).unwrap().contains(&value));
    assert_eq!(verb.definition_digest(), digest);

    let _policy = install_static_synthesis_policy(&mut cfg, "allow");
    let installed = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::VerbCreateFromPreview { digest },
    )
    .await;
    assert!(!serde_json::to_string(&installed).unwrap().contains(&value));
    let shown = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::VerbShow {
            name: "check-compiler".to_string(),
        },
    )
    .await;
    assert!(!serde_json::to_string(&shown).unwrap().contains(&value));
    let catalog_path = catalog_dir.path().join("verbs.yaml");
    assert!(!std::fs::read_to_string(catalog_path)
        .unwrap()
        .contains(&value));
}

#[tokio::test]
async fn sensitive_synthesized_name_never_reaches_preview_catalog_or_response() {
    let value = ["q", "7"].concat();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(super::run_verb_synthesis_llm_with(
        listener,
        synthesis_arguments_with_sensitive_name,
    ));
    let (mut cfg, daemon) = synthesis_test_config(url);
    let (catalog_dir, catalog) = file_backed_catalog();
    cfg.state.verbs = Arc::new(RwLock::new(catalog));

    let response = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::VerbCreate {
            prose: "Inspect compiler version.".to_string(),
            binary_hint: Some("uptime".to_string()),
            preview: true,
            gate_feedback: Vec::new(),
        },
    )
    .await;
    assert!(matches!(response, AdminResponse::Error { .. }));
    assert!(!serde_json::to_string(&response).unwrap().contains(&value));
    assert_eq!(
        std::fs::read_to_string(catalog_dir.path().join("verbs.yaml")).unwrap(),
        "verbs: []\n"
    );
    assert!(cfg.state.verb_previews.read().await.is_empty());
}

#[tokio::test]
async fn from_preview_rejects_unknown_and_malformed_digests() {
    let (mut cfg, _buf) = make_test_config();
    cfg.config.daemon_principal = PrincipalKey::from_uid(cfg.config.daemon_uid);
    let daemon = CallerIdentity::UnixAdmin {
        uid: cfg.config.daemon_uid,
    };

    let response = handle_admin_request_for_test(
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

    let response = handle_admin_request_for_test(
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
async fn evaluator_admission_denial_prevents_preview_installation() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(super::run_verb_synthesis_llm(listener));
    let (mut cfg, daemon) = synthesis_test_config(url);
    let (_dir, catalog) = file_backed_catalog();
    cfg.state.verbs = Arc::new(RwLock::new(catalog));

    let preview = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::VerbCreate {
            prose: "Inspect compiler version.".to_string(),
            binary_hint: Some("uptime".to_string()),
            preview: true,
            gate_feedback: Vec::new(),
        },
    )
    .await;
    let AdminResponse::VerbCreated {
        preview_digest: Some(digest),
        ..
    } = preview
    else {
        panic!("expected preview candidate, got {preview:?}");
    };

    let _policy = install_static_synthesis_policy(&mut cfg, "deny");
    let response = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::VerbCreateFromPreview { digest },
    )
    .await;
    let AdminResponse::Error { message } = response else {
        panic!("expected admission rejection, got {response:?}");
    };
    assert!(
        message.contains("rejected by admission preflight"),
        "{message}"
    );
    assert!(cfg.state.verbs.read().await.get("check-compiler").is_none());
}

#[tokio::test]
async fn nonfinite_synthesis_preflight_fails_explicitly_before_storage() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(super::run_verb_synthesis_llm_with(
        listener,
        nonfinite_synthesis_arguments,
    ));
    let (mut cfg, daemon) = synthesis_test_config(url);
    let (_dir, catalog) = file_backed_catalog();
    cfg.state.verbs = Arc::new(RwLock::new(catalog));

    let preview = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::VerbCreate {
            prose: "Inspect one named fixture.".to_string(),
            binary_hint: Some("printf".to_string()),
            preview: true,
            gate_feedback: Vec::new(),
        },
    )
    .await;
    let AdminResponse::VerbCreated {
        preview_digest: Some(digest),
        ..
    } = preview
    else {
        panic!("expected preview candidate, got {preview:?}");
    };
    let response = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::VerbCreateFromPreview { digest },
    )
    .await;
    let AdminResponse::Error { message } = response else {
        panic!("expected incomplete preflight, got {response:?}");
    };
    assert!(
        message.contains("admission preflight is incomplete"),
        "{message}"
    );
    assert!(
        message.contains("non-finite parameter pattern"),
        "{message}"
    );
    assert!(cfg
        .state
        .verbs
        .read()
        .await
        .get("inspect-fixture")
        .is_none());
}

#[tokio::test]
async fn rejected_direct_create_leaves_a_pending_hold_and_catalog_unchanged() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(super::run_verb_synthesis_llm_with(
        listener,
        relative_file_synthesis_arguments,
    ));
    let (mut cfg, daemon) = synthesis_test_config(url);
    cfg.config.gate = GateMode::Consequence;
    let dir = authority_tempdir();
    let path = dir.path().join("verbs.yaml");
    write_authority_file(
        &path,
        "verbs:\n  - name: held-fixture\n    binary: true\n    consequence: irreversible\n    trusted: true\n",
    );
    cfg.state.verbs = Arc::new(RwLock::new(VerbCatalog::load(&path).unwrap()));
    let original_version = cfg.state.verbs.read().await.version();

    let mut request = raw_request("", &[], None);
    request.verb = Some(VerbInvocation {
        name: "held-fixture".to_string(),
        params: Default::default(),
    });
    let held = execute_command(request, &cfg, &CallerIdentity::Unix { uid: 1001 })
        .await
        .into_response();
    let handle = held.handle.expect("irreversible verb creates a hold");
    assert_eq!(held.status, Some(GateStatus::Held));

    let response = handle_admin_request_for_test(
        &cfg,
        &daemon,
        AdminRequest::VerbCreate {
            prose: "Apply the fixed fixture manifest.".to_string(),
            binary_hint: Some("kubectl".to_string()),
            preview: false,
            gate_feedback: Vec::new(),
        },
    )
    .await;
    let AdminResponse::Error { message } = response else {
        panic!("expected relative-file rejection, got {response:?}");
    };
    assert!(message.contains("must be one absolute path"), "{message}");
    assert_eq!(cfg.state.verbs.read().await.version(), original_version);
    assert!(cfg.state.verbs.read().await.get("apply-fixture").is_none());
    assert_eq!(
        cfg.state
            .approvals
            .read()
            .await
            .get(&handle)
            .unwrap()
            .status,
        ApprovalStatus::Pending
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
    let response = handle_admin_request_for_test(
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
    let response = handle_admin_request_for_test(
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
