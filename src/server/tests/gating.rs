#[cfg(unix)]
use crate::server::admin::pause_access_approval_before_verb_lock_for_test;
use crate::server::admin::{
    handle_admin_request_for_test, handle_admin_request_owned, handle_approval_note,
};
use crate::server::execute::audit_session_fingerprint;
#[cfg(unix)]
use crate::server::execute::pause_command_initiation_for_test;
use crate::server::gate_runtime::{
    approval_to_result, execute_snapshot, hash_secret_value, hold_for_approval_with_authority,
    hold_for_approval_with_trace, merge_revert_assessment_prompt, new_handle, now_unix,
    route_gated_allow, GateInputs, SessionAuthoritySnapshot,
};
#[cfg(unix)]
use crate::server::gate_runtime::{
    arm_containment_with_access_use_for_test, arm_containment_with_authority,
    finish_due_provisional, finish_revert, resume_approval, run_provisional_check, DaemonGateSink,
};
use crate::server::gate_runtime::{observe_approval_lifecycle_for_test, ApprovalLifecycleTestHook};
#[cfg(unix)]
use crate::server::pause_verb_authority_lease_for_test;
use crate::server::wire::{
    approval_is_armed, AdminRequest, AdminResponse, CallerIdentity, ExecOutcome, ExecuteRequest,
    ExecuteResult, RevertSpec, CONSEQUENCE_ARM,
};
#[cfg(unix)]
use crate::server::wire::{
    ContainmentFailure, ContainmentFailureKind, ContainmentOutcome, GateStatus, VerbContext,
    CONSEQUENCE_RELEASE,
};
use crate::server::{RequestContext, ServerContext, APPROVAL_TTL_SECS};
use crate::session::SessionGrant;
#[cfg(unix)]
use crate::session::{AccessUseGrant, IssuedGrantScope, SessionOwner};
#[cfg(unix)]
use crate::session_store::SessionStore;
use guard::gating::approval::{Approval, ApprovalSnapshot, ApprovalStatus};
#[cfg(unix)]
use guard::gating::approval::{SecretBinding, ToolSecretBinding};
#[cfg(unix)]
use guard::gating::provisional::{ApiRevertPlan, Provisional, ProvisionalStatus};
use guard::gating::verb::VerbCatalog;
use guard::gating::{Coverage, GateMode, Reversibility};
use guard::principal::PrincipalKey;
use std::collections::HashMap;
#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use tokio::io::AsyncWrite;
#[cfg(unix)]
use tokio::sync::RwLock;

use super::make_test_config;

/// Capture the live session authority the way the daemon does before routing
/// (`route_gated_allow` receives it in `GateInputs::authority`).
async fn live_authority(cfg: &ServerContext, token: &str) -> Option<SessionAuthoritySnapshot> {
    cfg.state
        .sessions
        .read()
        .await
        .authority_snapshot(token)
        .map(SessionAuthoritySnapshot::from)
}

// ---- Consequence-gating orchestration tests -----------------------------
//
// These drive the daemon orchestration in this file (arm_containment_with_authority,
// hold_for_approval_with_authority, handle_admin_request_for_test -> confirm/approve/deny/revert,
// and the sweeper's expire/auto-revert steps) directly in-process, so the
// invariants the Docker CTF (ctf/gating) checks end-to-end are also caught
// by `cargo test`. Tests that must spawn a real forward/revert child use
// POSIX `echo`/`true`/`false` and are `#[cfg(unix)]`; the authoritative
// cross-platform run is the Linux container. The pure registry/handler
// invariants (operator gating, TTL expiry, catalog voiding) run everywhere.

#[test]
fn rollback_assessment_keeps_session_authority_context() {
    let merged = merge_revert_assessment_prompt(
        Some("operate only on the staging namespace"),
        "CONTAINMENT ENVELOPE ASSESSMENT",
    );
    assert!(merged.contains("operate only on the staging namespace"));
    assert!(merged.contains("CONTAINMENT ENVELOPE ASSESSMENT"));
}

// The gating types (Approval, ApprovalSnapshot, ApprovalStatus, Provisional,
// ProvisionalStatus, Coverage, GateMode, Reversibility) and AsyncWrite are
// already in scope via the imports at the top of this file.
use std::collections::BTreeMap;
#[cfg(unix)]
use std::pin::Pin;
#[cfg(unix)]
use std::task::{Context, Poll};

/// Build a containment-gating config: gate on, a distinct operator
/// principal, and the caller uid as the row owner. Returns
/// `(config, operator_caller, agent_caller)`.
fn gating_config(
    operator_uid: u32,
    agent_uid: u32,
) -> (ServerContext, CallerIdentity, CallerIdentity) {
    let (mut cfg, _) = make_test_config();
    cfg.config.gate = GateMode::Consequence;
    cfg.config.daemon_uid = operator_uid;
    cfg.config.daemon_principal = PrincipalKey::from_uid(operator_uid);
    let operator = CallerIdentity::UnixAdmin { uid: operator_uid };
    let agent = CallerIdentity::Unix { uid: agent_uid };
    (cfg, operator, agent)
}

/// A request with a structured revert, used to drive `arm_containment_with_authority`.
fn contain_request(binary: &str, args: &[&str], revert: RevertSpec) -> ExecuteRequest {
    ExecuteRequest {
        binary: binary.to_string(),
        args: args.iter().map(|s| s.to_string()).collect(),
        auth_token: None,
        env: HashMap::new(),
        secrets: HashMap::new(),
        secret_files: HashMap::new(),
        stream: false,
        session_token: None,
        revert: Some(revert),
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
fn held_request(
    binary: &str,
    args: Vec<String>,
    wait_approval_secs: Option<u64>,
) -> ExecuteRequest {
    ExecuteRequest {
        binary: binary.to_string(),
        args,
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
        wait_approval_secs,
        verb: None,
    }
}

fn active_session() -> SessionGrant {
    SessionGrant {
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
        owner: crate::session::SessionOwner::Principal(guard::principal::PrincipalKey::from_uid(
            1000,
        )),
    }
}

/// A `tokio::io::AsyncWrite` whose writes succeed `ok_writes` times and then
/// fail with `BrokenPipe`. With `ok_writes == 0` it fails on the very first
/// write, simulating a client stream that drops the instant the daemon
/// begins forwarding the child's output. The forward child still spawns and
/// runs (so the mutation may have applied); only streaming its output fails.
#[cfg(unix)]
struct FlakyWriter {
    remaining_ok: usize,
}

#[cfg(unix)]
impl FlakyWriter {
    fn failing_after(ok_writes: usize) -> Self {
        Self {
            remaining_ok: ok_writes,
        }
    }
}

#[cfg(unix)]
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

/// A contained forward command that launches and then loses its client stream
/// records an explicit interruption. No confirmation deadline is invented for
/// a child whose successful completion was never observed.
#[cfg(unix)]
#[tokio::test]
async fn containment_records_interruption_when_client_stream_drops_after_launch() {
    let temp = tempfile::tempdir().expect("tempdir");
    let child_pid_file = temp.path().join("background-child-pid");
    let child_pid_staging = temp.path().join("background-child-pid.staging");
    let store = SessionStore::open(temp.path().join("state.db"), 3_600)
        .await
        .expect("open store");
    let (mut cfg, _operator, agent) = gating_config(7001, 1000);
    cfg.state.session_store = Some(store.clone());
    let agent_principal = agent.principal();
    cfg.state
        .secrets
        .set(
            agent_principal.as_ref().unwrap(),
            "stream-file-secret",
            "stream-value",
        )
        .await
        .unwrap();

    // The shell produces a line and starts a same-group background child. The
    // The writer accepts one complete framed message and then fails. The shell
    // publishes the child PID before emitting its first line, so the failure
    // deterministically occurs after the background child has started.
    let mut request = contain_request(
        "sh",
        &[
            "-c",
            &format!(
                "sleep 30 & child=$!; printf '%s' \"$child\" > '{}'; mv '{}' '{}'; echo launched; wait",
                child_pid_staging.display(),
                child_pid_staging.display(),
                child_pid_file.display()
            ),
        ],
        RevertSpec::new("true", Vec::new()),
    );
    request.secret_files.insert(
        "STREAM_SECRET_FILE".to_string(),
        "stream-file-secret".to_string(),
    );
    let mut writer = FlakyWriter::failing_after(2);

    let result = arm_containment_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: true,
            stream_writer: // stream_output: exercise the streaming failure path
        &mut writer,
        },
        request,
        agent_principal,
        "recoverable change".to_string(),
        None,
    )
    .await;

    // The forward child launched then failed without a normal exit code.
    match &result.exec {
        ExecOutcome::ContainmentFailed {
            outcome: ContainmentOutcome::ForwardNoExitCode,
            handle: Some(_),
            ..
        } => {
            // The typed outcome prevents the CLI from treating this as a
            // numeric child exit or an armed timer.
        }
        other => panic!("expected typed containment failure, got {:?}", other),
    }

    // The provisional remains queryable, but its forward outcome is explicitly
    // interrupted and cannot race an automatic rollback timer.
    let reg = cfg.state.provisional.read().await;
    let rows = reg.list();
    assert_eq!(rows.len(), 1, "the armed provisional must be retained");
    let p = &rows[0];
    assert_eq!(p.status, ProvisionalStatus::NeedsOperatorDecision);
    assert!(!p.forward_done);
    assert_eq!(p.deadline_unix, 0);
    assert_eq!(p.forward_outcome(), "interrupted");
    assert!(p
        .revert_detail
        .as_deref()
        .is_some_and(|detail| detail.contains("interrupted after launch")));
    assert!(reg.due_handles(u64::MAX).is_empty());
    assert_eq!(reg.outstanding(), 1, "the armed row still occupies a slot");
    assert_eq!(
        p.secret_file_keys.get("STREAM_SECRET_FILE"),
        Some(&"stream-file-secret".to_string())
    );
    assert_eq!(
        std::fs::read_dir(cfg.config.secret_file_root.as_ref().unwrap())
            .unwrap()
            .count(),
        0,
        "stream disconnect must remove child-lifetime secret files"
    );
    let child_pid = std::fs::read_to_string(&child_pid_file)
        .expect("the shell records its background child before streaming")
        .parse::<i32>()
        .expect("valid child pid");
    let child_state = std::fs::read_to_string(format!("/proc/{child_pid}/stat"))
        .ok()
        .and_then(|stat| stat.rsplit_once(") ").map(|(_, tail)| tail.to_string()))
        .and_then(|tail| tail.chars().next());
    assert!(
        child_state.is_none() || child_state == Some('Z'),
        "same-group background child remained runnable after the stream disconnect"
    );
    drop(reg);

    let AdminResponse::Provisionals { items } =
        handle_admin_request_for_test(&cfg, &agent, AdminRequest::Provisionals).await
    else {
        panic!("requester should inspect its interrupted provisional");
    };
    assert_eq!(items[0].status, "interrupted");
    assert_eq!(items[0].forward_outcome, "interrupted");
}

#[cfg(unix)]
async fn interrupted_state_persistence_failure_fixture() -> (
    ServerContext,
    CallerIdentity,
    SessionStore,
    String,
    std::path::PathBuf,
    tempfile::TempDir,
) {
    let temp = tempfile::tempdir().expect("tempdir");
    let store = SessionStore::open(temp.path().join("state.db"), 3_600)
        .await
        .expect("open store");
    let (mut cfg, operator, agent) = gating_config(7_055, 1_000);
    cfg.state.session_store = Some(store.clone());
    let reverted = temp.path().join("reverted");
    let request = contain_request(
        "sh",
        &["-c", "sleep 0.2; printf interrupted; sleep 5"],
        RevertSpec::new(
            "touch",
            vec![reverted.to_str().expect("revert marker").to_string()],
        ),
    );
    let (initiation_reached, initiation_release) = pause_command_initiation_for_test(&cfg);
    let cfg_for_run = cfg.clone();
    let agent_for_run = agent.clone();
    let run = tokio::spawn(async move {
        let mut writer = FlakyWriter::failing_after(0);
        arm_containment_with_authority(
            &mut RequestContext {
                server: &cfg_for_run,
                caller: &agent_for_run,
                depth: 0,
                stream_output: true,
                stream_writer: &mut writer,
            },
            request,
            agent_for_run.principal(),
            "recoverable change".to_string(),
            None,
        )
        .await
    });

    initiation_reached.acquire().await.unwrap().forget();
    let handle = cfg
        .state
        .provisional
        .read()
        .await
        .list()
        .into_iter()
        .find(|row| row.forward_outcome() == "running")
        .expect("forward row is published before command initiation")
        .handle;
    store.fail_next_write_for_test();
    initiation_release.add_permits(1);

    let response = tokio::time::timeout(std::time::Duration::from_secs(4), run)
        .await
        .expect("interrupted forward should finish")
        .expect("forward task should not panic")
        .into_response();
    assert_eq!(response.handle.as_deref(), Some(handle.as_str()));
    assert_eq!(response.auto_revert_durable, Some(false));
    assert!(matches!(
        response.containment_failure,
        Some(ContainmentFailure {
            kind: ContainmentFailureKind::PersistenceFailure,
            command_may_have_run: true,
            forward_exit_code: None,
        })
    ));
    let live = cfg
        .state
        .provisional
        .read()
        .await
        .get(&handle)
        .cloned()
        .expect("live interrupted row");
    assert_eq!(live.status, ProvisionalStatus::NeedsOperatorDecision);
    assert!(live.forward_done);
    assert!(!live.forward_persistence_failed);
    assert_eq!(live.forward_outcome(), "completed");

    (cfg, operator, store, handle, reverted, temp)
}

#[cfg(unix)]
#[tokio::test]
async fn interrupted_state_persistence_failure_can_be_confirmed_without_restart() {
    let (cfg, operator, store, handle, _reverted, _temp) =
        interrupted_state_persistence_failure_fixture().await;

    let response = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::Confirm {
            handle: handle.clone(),
        },
    )
    .await;
    assert!(matches!(response, AdminResponse::GateAction { .. }));
    assert_eq!(
        cfg.state
            .provisional
            .read()
            .await
            .get(&handle)
            .expect("live confirmed row")
            .status,
        ProvisionalStatus::Confirmed
    );
    let durable = store.load_provisionals().await.expect("durable confirm");
    assert_eq!(durable[0].status, ProvisionalStatus::Confirmed);
    assert!(!durable[0].forward_persistence_failed);
}

#[cfg(unix)]
#[tokio::test]
async fn interrupted_state_persistence_failure_can_be_reverted_without_restart() {
    let (cfg, operator, store, handle, reverted, _temp) =
        interrupted_state_persistence_failure_fixture().await;

    let response = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::Revert {
            handle: handle.clone(),
        },
    )
    .await;
    assert!(matches!(response, AdminResponse::GateAction { .. }));
    assert!(reverted.exists());
    assert_eq!(
        cfg.state
            .provisional
            .read()
            .await
            .get(&handle)
            .expect("live reverted row")
            .status,
        ProvisionalStatus::Reverted
    );
    let durable = store.load_provisionals().await.expect("durable revert");
    assert_eq!(durable[0].status, ProvisionalStatus::Reverted);
    assert!(!durable[0].forward_persistence_failed);
}

#[cfg(unix)]
#[tokio::test]
async fn confirmation_deadline_starts_after_long_forward_and_survives_restart() {
    let (mut cfg, _operator, agent) = gating_config(7_041, 1_000);
    let state = tempfile::tempdir().unwrap();
    let store = SessionStore::open(state.path().join("state.db"), 3_600)
        .await
        .unwrap();
    cfg.state.session_store = Some(store.clone());
    let mut request = contain_request(
        "sh",
        &["-c", "sleep 2; printf completed"],
        RevertSpec::new("true", Vec::new()),
    );
    request.confirm_within_secs = Some(4);
    let (initiation_reached, initiation_release) = pause_command_initiation_for_test(&cfg);
    let cfg_for_run = cfg.clone();
    let agent_for_run = agent.clone();
    let run = tokio::spawn(async move {
        let mut sink = tokio::io::sink();
        arm_containment_with_authority(
            &mut RequestContext {
                server: &cfg_for_run,
                caller: &agent_for_run,
                depth: 0,
                stream_output: false,
                stream_writer: &mut sink,
            },
            request,
            agent_for_run.principal(),
            "long recoverable change".to_string(),
            None,
        )
        .await
    });

    initiation_reached.acquire().await.unwrap().forget();
    let row = cfg
        .state
        .provisional
        .read()
        .await
        .list()
        .into_iter()
        .next()
        .expect("forward row is published before command initiation");
    assert_eq!(row.forward_outcome(), "running");
    assert_eq!(row.deadline_unix, 0);
    assert!(cfg
        .state
        .provisional
        .read()
        .await
        .due_handles(u64::MAX)
        .is_empty());
    let handle = row.handle;
    initiation_release.add_permits(1);

    let result = tokio::time::timeout(std::time::Duration::from_secs(8), run)
        .await
        .expect("long forward should complete")
        .unwrap();
    assert!(matches!(
        result.exec,
        ExecOutcome::Provisional {
            exit_code: Some(0),
            ..
        }
    ));
    let observed_completion = now_unix();
    let completed = cfg
        .state
        .provisional
        .read()
        .await
        .get(&handle)
        .cloned()
        .unwrap();
    assert_eq!(completed.forward_outcome(), "completed");
    assert!(completed.forward_done);
    assert!(
        completed.deadline_unix >= completed.created_unix.saturating_add(5),
        "the four-second window must start after the two-second forward command"
    );
    assert!(completed.deadline_unix <= observed_completion.saturating_add(4));

    let durable = store.load_provisionals().await.unwrap();
    let (restarted, moved) = guard::gating::provisional::ProvisionalRegistry::from_rows(durable);
    assert!(moved.is_empty());
    let restored = restarted.get(&handle).unwrap();
    assert_eq!(restored.deadline_unix, completed.deadline_unix);
    assert!(restarted
        .due_handles(restored.deadline_unix.saturating_sub(1))
        .is_empty());
    assert_eq!(restarted.due_handles(restored.deadline_unix), vec![handle]);
}

/// Counterpart to the leak test: a contained forward command that FAILS TO
/// SPAWN (nonexistent binary, started=false) has no observable effect, so
/// the provisional is DROPPED - there is nothing to revert.
#[cfg(unix)]
#[tokio::test]
async fn containment_dropped_when_forward_fails_to_spawn() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store = SessionStore::open(temp.path().join("state.db"), 3_600)
        .await
        .expect("open store");
    let (mut cfg, _operator, agent) = gating_config(7002, 1000);
    cfg.state.session_store = Some(store);
    let agent_principal = agent.principal();

    let request = contain_request(
        "guard-nonexistent-binary-xyz",
        &[],
        RevertSpec::new("true", Vec::new()),
    );
    let mut sink = tokio::io::sink();

    let result = arm_containment_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        agent_principal,
        "recoverable change".to_string(),
        None,
    )
    .await;

    match &result.exec {
        ExecOutcome::Failed { started, .. } => {
            assert!(!*started, "spawn failure must report started=false");
        }
        other => panic!("expected Failed{{started:false}}, got {:?}", other),
    }

    // The provisional was dropped: nothing ran, so nothing to revert.
    let reg = cfg.state.provisional.read().await;
    assert!(
        reg.list().is_empty(),
        "a never-launched forward must drop its provisional"
    );
}

/// A failure to persist the completed forward outcome must not expose the
/// in-memory deadline as an armed auto-revert. The pre-forward row remains the
/// durable recovery authority, so a restarted daemon escalates it for an
/// operator decision.
#[cfg(unix)]
#[tokio::test]
async fn post_forward_persistence_failure_reports_no_durable_auto_revert_and_recovers_on_restart() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database = temp.path().join("state.db");
    let store = SessionStore::open(database.clone(), 3_600)
        .await
        .expect("open store");
    let (mut cfg, _operator, agent) = gating_config(7_042, 1_000);
    cfg.state.session_store = Some(store.clone());

    let mut request = contain_request(
        "sh",
        &["-c", "sleep 1"],
        RevertSpec::new("true", Vec::new()),
    );
    request.confirm_within_secs = Some(4);
    let (initiation_reached, initiation_release) = pause_command_initiation_for_test(&cfg);
    let cfg_for_run = cfg.clone();
    let agent_for_run = agent.clone();
    let run = tokio::spawn(async move {
        let mut sink = tokio::io::sink();
        arm_containment_with_authority(
            &mut RequestContext {
                server: &cfg_for_run,
                caller: &agent_for_run,
                depth: 0,
                stream_output: false,
                stream_writer: &mut sink,
            },
            request,
            agent_for_run.principal(),
            "recoverable change".to_string(),
            None,
        )
        .await
    });

    initiation_reached.acquire().await.unwrap().forget();
    let handle = cfg
        .state
        .provisional
        .read()
        .await
        .list()
        .into_iter()
        .find(|row| row.forward_outcome() == "running")
        .expect("forward row is durable before command initiation")
        .handle;
    store.fail_next_write_for_test();
    initiation_release.add_permits(1);

    let result = tokio::time::timeout(std::time::Duration::from_secs(4), run)
        .await
        .expect("forward execution should finish")
        .expect("forward task should not panic");
    let response = result.into_response();
    assert_eq!(response.handle.as_deref(), Some(handle.as_str()));
    assert_eq!(response.auto_revert_durable, Some(false));
    assert!(matches!(
        response.containment_failure,
        Some(ContainmentFailure {
            kind: ContainmentFailureKind::PersistenceFailure,
            command_may_have_run: true,
            forward_exit_code: Some(0),
        })
    ));
    assert!(response.confirm_deadline_unix.is_none());
    assert!(response.confirm_window_secs.is_none());
    assert!(response
        .reason
        .contains("durable auto-revert state could not be recorded"));

    let live = cfg
        .state
        .provisional
        .read()
        .await
        .get(&handle)
        .cloned()
        .expect("live provisional");
    assert_eq!(live.status, ProvisionalStatus::NeedsOperatorDecision);
    assert_eq!(live.forward_outcome(), "completed");
    assert!(!live.forward_persistence_failed);
    assert_eq!(live.deadline_unix, 0);
    assert_eq!(live.window_secs, 0);
    assert!(cfg
        .state
        .provisional
        .read()
        .await
        .due_handles(now_unix().saturating_add(10_000))
        .is_empty());

    let durable = store
        .load_provisionals()
        .await
        .expect("load fail-closed durable recovery row");
    assert_eq!(durable.len(), 1);
    assert_eq!(durable[0].status, ProvisionalStatus::NeedsOperatorDecision);
    assert!(durable[0].forward_done);
    assert_eq!(durable[0].deadline_unix, 0);

    let (mut restarted, moved) =
        guard::gating::provisional::ProvisionalRegistry::from_rows(durable);
    assert!(moved.is_empty());
    let recovered = restarted.list();
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        recovered[0].status,
        ProvisionalStatus::NeedsOperatorDecision
    );
    assert!(restarted
        .take_due(now_unix().saturating_add(10_000))
        .is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn signal_and_post_forward_persistence_failure_remain_distinct() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store = SessionStore::open(temp.path().join("state.db"), 3_600)
        .await
        .expect("open store");
    let (mut cfg, _operator, agent) = gating_config(7_049, 1_000);
    cfg.state.session_store = Some(store.clone());
    let request = contain_request(
        "sh",
        &["-c", "sleep 0.2; kill -TERM $$"],
        RevertSpec::new("true", Vec::new()),
    );
    let (initiation_reached, initiation_release) = pause_command_initiation_for_test(&cfg);
    let cfg_for_run = cfg.clone();
    let agent_for_run = agent.clone();
    let run = tokio::spawn(async move {
        let mut sink = tokio::io::sink();
        arm_containment_with_authority(
            &mut RequestContext {
                server: &cfg_for_run,
                caller: &agent_for_run,
                depth: 0,
                stream_output: false,
                stream_writer: &mut sink,
            },
            request,
            agent_for_run.principal(),
            "recoverable change".to_string(),
            None,
        )
        .await
    });

    initiation_reached.acquire().await.unwrap().forget();
    assert!(cfg
        .state
        .provisional
        .read()
        .await
        .list()
        .iter()
        .any(|row| row.forward_outcome() == "running"));
    store.fail_next_write_for_test();
    initiation_release.add_permits(1);

    let result = tokio::time::timeout(std::time::Duration::from_secs(4), run)
        .await
        .expect("forward command should finish")
        .expect("forward task should not panic");
    let response = result.into_response();
    assert!(matches!(
        response.containment_failure,
        Some(ContainmentFailure {
            kind: ContainmentFailureKind::PersistenceFailure,
            command_may_have_run: true,
            forward_exit_code: None,
        })
    ));
    assert!(response.reason.contains("without an exit code"));
    assert!(!response.reason.contains("code 0"));
    assert!(response.confirm_deadline_unix.is_none());
    assert!(response.confirm_window_secs.is_none());
}

#[cfg(unix)]
async fn post_forward_persistence_failure_fixture() -> (
    ServerContext,
    CallerIdentity,
    SessionStore,
    String,
    String,
    tempfile::TempDir,
) {
    let temp = tempfile::tempdir().expect("tempdir");
    let database = temp.path().join("state.db");
    let store = SessionStore::open(database.clone(), 3_600)
        .await
        .expect("open store");
    let (mut cfg, operator, agent) = gating_config(7_045, 1_000);
    cfg.state.session_store = Some(store.clone());

    let mut request = contain_request(
        "sh",
        &["-c", "sleep 1"],
        RevertSpec::new("true", Vec::new()),
    );
    request.confirm_within_secs = Some(4);
    let (initiation_reached, initiation_release) = pause_command_initiation_for_test(&cfg);
    let cfg_for_run = cfg.clone();
    let agent_for_run = agent.clone();
    let run = tokio::spawn(async move {
        let mut sink = tokio::io::sink();
        arm_containment_with_authority(
            &mut RequestContext {
                server: &cfg_for_run,
                caller: &agent_for_run,
                depth: 0,
                stream_output: false,
                stream_writer: &mut sink,
            },
            request,
            agent_for_run.principal(),
            "recoverable change".to_string(),
            None,
        )
        .await
    });

    initiation_reached.acquire().await.unwrap().forget();
    let handle = cfg
        .state
        .provisional
        .read()
        .await
        .list()
        .into_iter()
        .find(|row| row.forward_outcome() == "running")
        .expect("forward row is durable before command initiation")
        .handle;
    store.fail_next_write_for_test();
    initiation_release.add_permits(1);

    let result = tokio::time::timeout(std::time::Duration::from_secs(4), run)
        .await
        .expect("forward execution should finish")
        .expect("forward task should not panic");
    let response = result.into_response();
    assert_eq!(response.handle.as_deref(), Some(handle.as_str()));
    assert_eq!(response.auto_revert_durable, Some(false));
    assert!(matches!(
        response.containment_failure,
        Some(ContainmentFailure {
            kind: ContainmentFailureKind::PersistenceFailure,
            command_may_have_run: true,
            forward_exit_code: Some(0),
        })
    ));
    assert!(response.confirm_deadline_unix.is_none());
    assert!(response.confirm_window_secs.is_none());
    assert!(response
        .reason
        .contains("durable auto-revert state could not be recorded"));
    (
        cfg,
        operator,
        store,
        handle,
        database.display().to_string(),
        temp,
    )
}

#[cfg(unix)]
#[tokio::test]
async fn post_forward_persistence_failure_can_be_confirmed_and_converges_durably() {
    let (cfg, operator, store, handle, database_path, _temp) =
        post_forward_persistence_failure_fixture().await;

    // A transient failure leaves the live decision actionable and exposes only
    // a stable operator message. The detailed store error stays in diagnostics.
    store.fail_next_write_for_test();
    let failed = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::Confirm {
            handle: handle.clone(),
        },
    )
    .await;
    match failed {
        AdminResponse::Error { message } => {
            assert!(message.contains("durable state is unavailable"));
            assert!(!message.contains("simulated session-store write failure"));
            assert!(!message.contains(&database_path));
        }
        other => panic!("confirmation must fail closed on persistence loss: {other:?}"),
    }
    assert_eq!(
        cfg.state
            .provisional
            .read()
            .await
            .get(&handle)
            .unwrap()
            .status,
        ProvisionalStatus::NeedsOperatorDecision
    );

    let confirmed = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::Confirm {
            handle: handle.clone(),
        },
    )
    .await;
    assert!(matches!(confirmed, AdminResponse::GateAction { .. }));
    assert_eq!(
        cfg.state
            .provisional
            .read()
            .await
            .get(&handle)
            .unwrap()
            .status,
        ProvisionalStatus::Confirmed
    );
    let durable = store.load_provisionals().await.expect("durable confirm");
    assert_eq!(durable[0].status, ProvisionalStatus::Confirmed);
    assert!(!durable[0].forward_persistence_failed);
}

#[cfg(unix)]
#[tokio::test]
async fn post_forward_persistence_failure_can_be_reverted_and_converges_durably() {
    let (cfg, operator, store, handle, _database_path, _temp) =
        post_forward_persistence_failure_fixture().await;
    let reverted = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::Revert {
            handle: handle.clone(),
        },
    )
    .await;
    assert!(matches!(reverted, AdminResponse::GateAction { .. }));
    assert_eq!(
        cfg.state
            .provisional
            .read()
            .await
            .get(&handle)
            .unwrap()
            .status,
        ProvisionalStatus::Reverted
    );
    let durable = store.load_provisionals().await.expect("durable revert");
    assert_eq!(durable[0].status, ProvisionalStatus::Reverted);
    assert!(!durable[0].forward_persistence_failed);
}

#[cfg(unix)]
async fn running_containment_fixture() -> (
    Arc<ServerContext>,
    CallerIdentity,
    CallerIdentity,
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    String,
    tokio::task::JoinHandle<ExecuteResult>,
) {
    let temp = tempfile::tempdir().expect("tempdir");
    let store = SessionStore::open(temp.path().join("state.db"), 3_600)
        .await
        .expect("open store");
    let (mut cfg, operator, agent) = gating_config(7_052, 1_000);
    cfg.state.session_store = Some(store);
    let cfg = Arc::new(cfg);
    let release = temp.path().join("release-forward");
    let reverted = temp.path().join("reverted");
    let request = contain_request(
        "sh",
        &[
            "-c",
            "while [ ! -e \"$1\" ]; do sleep 0.01; done",
            "guard-test",
            release.to_str().expect("release path"),
        ],
        RevertSpec::new(
            "touch",
            vec![reverted.to_str().expect("revert path").to_string()],
        ),
    );
    let (initiation_reached, initiation_release) = pause_command_initiation_for_test(&cfg);
    let task_cfg = Arc::clone(&cfg);
    let task_agent = agent.clone();
    let task = tokio::spawn(async move {
        let mut sink = tokio::io::sink();
        arm_containment_with_authority(
            &mut RequestContext {
                server: &task_cfg,
                caller: &task_agent,
                depth: 0,
                stream_output: false,
                stream_writer: &mut sink,
            },
            request,
            task_agent.principal(),
            "recoverable change".to_string(),
            None,
        )
        .await
    });
    initiation_reached.acquire().await.unwrap().forget();
    let handle = cfg
        .state
        .provisional
        .read()
        .await
        .list()
        .into_iter()
        .find(|row| row.status == ProvisionalStatus::Armed && !row.forward_done)
        .expect("forward row is published before command initiation")
        .handle;
    initiation_release.add_permits(1);
    (cfg, operator, agent, temp, release, reverted, handle, task)
}

#[cfg(unix)]
#[tokio::test]
async fn confirm_is_blocked_until_the_forward_command_finishes() {
    let (cfg, operator, _agent, _temp, release, _reverted, handle, task) =
        running_containment_fixture().await;
    let blocked = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::Confirm {
            handle: handle.clone(),
        },
    )
    .await;
    assert!(matches!(
        blocked,
        AdminResponse::Error { ref message }
            if message.contains("forward command is still running")
    ));

    std::fs::write(release, b"release").expect("release forward");
    let response = task.await.expect("forward task").into_response();
    assert_eq!(response.status, Some(GateStatus::Provisional));
    let confirmed =
        handle_admin_request_for_test(&cfg, &operator, AdminRequest::Confirm { handle }).await;
    assert!(matches!(confirmed, AdminResponse::GateAction { .. }));
}

#[cfg(unix)]
#[tokio::test]
async fn revert_is_blocked_until_the_forward_command_finishes() {
    let (cfg, operator, _agent, _temp, release, reverted, handle, task) =
        running_containment_fixture().await;
    let blocked = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::Revert {
            handle: handle.clone(),
        },
    )
    .await;
    assert!(matches!(
        blocked,
        AdminResponse::Error { ref message }
            if message.contains("forward command is still running")
    ));
    assert!(!reverted.exists());

    std::fs::write(release, b"release").expect("release forward");
    let response = task.await.expect("forward task").into_response();
    assert_eq!(response.status, Some(GateStatus::Provisional));
    let reverted_response =
        handle_admin_request_for_test(&cfg, &operator, AdminRequest::Revert { handle }).await;
    assert!(matches!(
        reverted_response,
        AdminResponse::GateAction { .. }
    ));
    assert!(reverted.exists());
}

/// Containment without a state store cannot make a restart-safe rollback
/// promise, so the forward command is refused before it starts.
#[cfg(unix)]
#[tokio::test]
async fn containment_without_state_store_fails_closed_before_forward() {
    let (cfg, _operator, agent) = gating_config(7_046, 1_000);
    cfg.state.sessions.write().await.grant(
        "containment-access".to_string(),
        SessionGrant {
            activated_verbs: vec!["recoverable-fixture".to_string()],
            scope: IssuedGrantScope {
                label: Some("agent:1000".to_string()),
                access_managed: true,
                access_grants: vec![AccessUseGrant {
                    request: "containment-budget".to_string(),
                    verbs: vec!["recoverable-fixture".to_string()],
                    use_limit: Some(1),
                    remaining_uses: Some(1),
                    pending: false,
                }],
                ..IssuedGrantScope::default()
            },
            expires_at: Some(now_unix().saturating_add(60)),
            static_only: true,
            owner: SessionOwner::Principal(PrincipalKey::from_uid(1_000)),
            ..active_session()
        },
    );
    let temp = tempfile::tempdir().expect("tempdir");
    let marker = temp.path().join("forward-ran");
    let mut request = contain_request(
        "touch",
        &[marker.to_str().expect("marker path")],
        RevertSpec::new("true", Vec::new()),
    );
    request.session_token = Some("containment-access".to_string());
    let authority = live_authority(&cfg, "containment-access").await;
    let mut sink = tokio::io::sink();

    let result = arm_containment_with_access_use_for_test(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        agent.principal(),
        "recoverable change".to_string(),
        authority,
        vec!["recoverable-fixture".to_string()],
    )
    .await;

    let response = result.into_response();
    assert!(!response.allowed);
    assert!(matches!(
        response.containment_failure,
        Some(ContainmentFailure {
            kind: ContainmentFailureKind::PersistenceFailure,
            command_may_have_run: false,
            forward_exit_code: None,
        })
    ));
    assert_eq!(
        response.reason,
        "containment failed before forward execution: command was not run because durable rollback state is unavailable"
    );
    assert!(!marker.exists());
    assert!(cfg.state.provisional.read().await.list().is_empty());
    let uses = cfg
        .state
        .sessions
        .read()
        .await
        .access_grant_uses("containment-access", "containment-budget");
    assert_eq!(uses, Some((Some(1), Some(1))));
}

#[cfg(unix)]
#[tokio::test]
async fn admission_denial_with_cleanup_failure_retains_non_actionable_terminal_state() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store = SessionStore::open(temp.path().join("state.db"), 3_600)
        .await
        .expect("open store");
    let (mut cfg, operator, agent) = gating_config(7_053, 1_000);
    cfg.state.session_store = Some(store.clone());
    cfg.state.sessions.write().await.grant(
        "exhausted-containment".to_string(),
        SessionGrant {
            activated_verbs: vec!["recoverable-fixture".to_string()],
            scope: IssuedGrantScope {
                label: Some("bounded authority".to_string()),
                access_managed: true,
                access_grants: vec![AccessUseGrant {
                    request: "bounded-use".to_string(),
                    verbs: vec!["recoverable-fixture".to_string()],
                    use_limit: Some(1),
                    remaining_uses: Some(0),
                    pending: false,
                }],
                ..IssuedGrantScope::default()
            },
            expires_at: Some(now_unix().saturating_add(60)),
            static_only: true,
            owner: SessionOwner::Principal(PrincipalKey::from_uid(1_000)),
            ..active_session()
        },
    );
    let marker = temp.path().join("forward-ran");
    let mut request = contain_request(
        "touch",
        &[marker.to_str().expect("marker path")],
        RevertSpec::new("true", Vec::new()),
    );
    request.session_token = Some("exhausted-containment".to_string());
    let authority = live_authority(&cfg, "exhausted-containment").await;
    store.fail_next_provisional_delete_for_test();
    let mut sink = tokio::io::sink();
    let response = arm_containment_with_access_use_for_test(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        agent.principal(),
        "recoverable change".to_string(),
        authority,
        vec!["recoverable-fixture".to_string()],
    )
    .await
    .into_response();

    assert!(!response.allowed);
    assert!(!marker.exists());
    let rows = cfg.state.provisional.read().await.list();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, ProvisionalStatus::Reverted);
    assert!(!rows[0].forward_done);
    assert_eq!(rows[0].forward_outcome(), "not_executed");
    assert_eq!(cfg.state.provisional.read().await.outstanding(), 0);
    let handle = rows[0].handle.clone();
    for request in [
        AdminRequest::Confirm {
            handle: handle.clone(),
        },
        AdminRequest::Revert {
            handle: handle.clone(),
        },
    ] {
        assert!(matches!(
            handle_admin_request_for_test(&cfg, &operator, request).await,
            AdminResponse::Error { ref message }
                if message.contains("forward command did not execute")
        ));
    }
    let durable = store
        .load_provisionals()
        .await
        .expect("durable terminal row");
    assert_eq!(durable.len(), 1);
    assert_eq!(durable[0].status, ProvisionalStatus::Reverted);
    let (restarted, moved) = guard::gating::provisional::ProvisionalRegistry::from_rows(durable);
    assert!(moved.is_empty());
    assert_eq!(restarted.outstanding(), 0);
    assert_eq!(
        cfg.state
            .sessions
            .read()
            .await
            .access_grant_uses("exhausted-containment", "bounded-use"),
        Some((Some(1), Some(0)))
    );
}

#[cfg(unix)]
#[tokio::test]
async fn containment_persistence_error_is_sanitized_from_public_response() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database = temp.path().join("state.db");
    let store = SessionStore::open(database.clone(), 3_600)
        .await
        .expect("open store");
    let (mut cfg, _operator, agent) = gating_config(7_049, 1_000);
    cfg.state.session_store = Some(store.clone());
    store.fail_next_write_for_test();
    let request = contain_request("true", &[], RevertSpec::new("true", Vec::new()));
    let mut sink = tokio::io::sink();
    let result = arm_containment_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        agent.principal(),
        "recoverable change".to_string(),
        None,
    )
    .await;
    let ExecOutcome::ContainmentFailed {
        reason, outcome, ..
    } = result.exec
    else {
        panic!("expected failed containment arm");
    };
    assert!(matches!(
        outcome,
        ContainmentOutcome::PersistenceFailure {
            command_started: false,
            forward_exit_code: None,
        }
    ));
    assert_eq!(
        reason,
        "command was not run because durable rollback state is unavailable"
    );
    assert!(!reason.contains("simulated session-store write failure"));
    assert!(!reason.contains(database.to_str().expect("database path")));
}

#[cfg(unix)]
#[tokio::test]
async fn forward_nonzero_exit_is_durable_failure_without_auto_revert() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store = SessionStore::open(temp.path().join("state.db"), 3_600)
        .await
        .expect("open store");
    let (mut cfg, _operator, agent) = gating_config(7_047, 1_000);
    cfg.state.session_store = Some(store.clone());
    let request = contain_request(
        "sh",
        &["-c", "exit 17"],
        RevertSpec::new("true", Vec::new()),
    );
    let mut sink = tokio::io::sink();
    let result = arm_containment_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        agent.principal(),
        "recoverable change".to_string(),
        None,
    )
    .await;

    let response = result.into_response();
    assert_eq!(response.exit_code, Some(17));
    assert_eq!(response.auto_revert_durable, None);
    assert!(matches!(
        response.containment_failure,
        Some(ContainmentFailure {
            kind: ContainmentFailureKind::ForwardNonzeroExit,
            command_may_have_run: true,
            forward_exit_code: Some(17),
        })
    ));
    assert!(response.confirm_deadline_unix.is_none());
    assert!(response.reason.contains("forward command exited with code"));
    let live = cfg.state.provisional.read().await.list();
    assert_eq!(live[0].forward_outcome(), "failed");
    assert!(!live[0].forward_persistence_failed);
    let AdminResponse::Provisionals { items } =
        handle_admin_request_for_test(&cfg, &agent, AdminRequest::Provisionals).await
    else {
        panic!("requester should inspect failed provisional");
    };
    assert_eq!(items[0].status, "forward_failed");
    assert_eq!(items[0].forward_outcome, "failed");
    let durable = store
        .load_provisionals()
        .await
        .expect("durable forward failure");
    assert_eq!(durable[0].forward_exit, Some(17));
    assert!(!durable[0].forward_persistence_failed);
}

#[cfg(unix)]
#[tokio::test]
async fn signal_exit_is_a_typed_forward_failure_without_auto_revert() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store = SessionStore::open(temp.path().join("state.db"), 3_600)
        .await
        .expect("open store");
    let (mut cfg, _operator, agent) = gating_config(7_048, 1_000);
    cfg.state.session_store = Some(store);
    let request = contain_request(
        "sh",
        &["-c", "kill -TERM $$"],
        RevertSpec::new("true", Vec::new()),
    );
    let mut sink = tokio::io::sink();
    let result = arm_containment_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        agent.principal(),
        "recoverable change".to_string(),
        None,
    )
    .await;

    let response = result.into_response();
    assert_eq!(response.exit_code, None);
    assert_eq!(response.auto_revert_durable, None);
    assert!(matches!(
        response.containment_failure,
        Some(ContainmentFailure {
            kind: ContainmentFailureKind::ForwardNoExitCode,
            command_may_have_run: true,
            forward_exit_code: None,
        })
    ));
    assert!(response.reason.contains("without an exit code"));
    assert!(response.confirm_deadline_unix.is_none());
    let live = cfg.state.provisional.read().await.list();
    assert_eq!(live[0].status, ProvisionalStatus::NeedsOperatorDecision);
    assert_eq!(live[0].forward_exit, None);
    assert!(!live[0].forward_persistence_failed);
}

/// The rollback record is the containment envelope's crash-recovery authority.
/// If its initial write fails, the forward command must never start.
#[cfg(unix)]
#[tokio::test]
async fn containment_fails_closed_when_initial_provisional_persistence_fails() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database = temp.path().join("state.db");
    let marker = temp.path().join("forward-ran");
    let store = SessionStore::open(database.clone(), 3_600)
        .await
        .expect("open store");
    {
        let connection = rusqlite::Connection::open(&database).expect("open state database");
        connection
            .execute_batch(
                "CREATE TRIGGER fail_provisional_insert
                 BEFORE INSERT ON gating_provisional
                 BEGIN
                   SELECT RAISE(FAIL, 'simulated provisional insert failure');
                 END;",
            )
            .expect("install insert failure trigger");
    }
    let (mut cfg, _operator, agent) = gating_config(7_030, 1_000);
    cfg.state.session_store = Some(store.clone());
    let request = contain_request(
        "touch",
        &[marker.to_str().expect("marker path")],
        RevertSpec::new("true", Vec::new()),
    );
    let mut sink = tokio::io::sink();

    let result = arm_containment_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        agent.principal(),
        "recoverable change".to_string(),
        None,
    )
    .await;

    let response = result.into_response();
    assert!(!response.allowed);
    assert!(matches!(
        response.containment_failure,
        Some(ContainmentFailure {
            kind: ContainmentFailureKind::PersistenceFailure,
            command_may_have_run: false,
            forward_exit_code: None,
        })
    ));
    assert_eq!(
        response.reason,
        "containment failed before forward execution: command was not run because durable rollback state is unavailable"
    );
    assert!(!marker.exists(), "forward command must not run");
    assert!(cfg.state.provisional.read().await.list().is_empty());
    assert!(store
        .load_provisionals()
        .await
        .expect("load provisionals")
        .is_empty());
}

/// A failed cleanup delete must leave a durable terminal tombstone. Startup
/// recovery can then prove that no rollback is available for an unstarted
/// command instead of presenting an ambiguous rollback decision.
#[cfg(unix)]
#[tokio::test]
async fn spawn_failure_delete_error_persists_nonrollbackable_tombstone() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database = temp.path().join("state.db");
    let store = SessionStore::open(database.clone(), 3_600)
        .await
        .expect("open store");
    {
        let connection = rusqlite::Connection::open(&database).expect("open state database");
        connection
            .execute_batch(
                "CREATE TRIGGER fail_provisional_delete
                 BEFORE DELETE ON gating_provisional
                 BEGIN
                   SELECT RAISE(FAIL, 'simulated provisional delete failure');
                 END;",
            )
            .expect("install delete failure trigger");
    }
    let (mut cfg, _operator, agent) = gating_config(7_031, 1_000);
    cfg.state.session_store = Some(store.clone());
    let request = contain_request(
        "guard-nonexistent-binary-delete-failure",
        &[],
        RevertSpec::new("true", Vec::new()),
    );
    let mut sink = tokio::io::sink();

    let result = arm_containment_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        agent.principal(),
        "recoverable change".to_string(),
        None,
    )
    .await;

    assert!(matches!(
        result.exec,
        ExecOutcome::Failed { started: false, .. }
    ));
    let live = cfg.state.provisional.read().await.list();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].status, ProvisionalStatus::Reverted);
    assert!(!live[0].forward_done);
    assert!(live[0]
        .revert_detail
        .as_deref()
        .is_some_and(|detail| detail.contains("did not start")));

    let persisted = store
        .load_provisionals()
        .await
        .expect("load terminal tombstone");
    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0].status, ProvisionalStatus::Reverted);
    let (mut restarted, moved) =
        guard::gating::provisional::ProvisionalRegistry::from_rows(persisted);
    assert!(moved.is_empty());
    assert!(restarted.list()[0].status.is_terminal());
    assert!(restarted
        .take_due(now_unix().saturating_add(10_000))
        .is_empty());
}

/// contain -> operator confirm keeps the change (no revert fires), and
/// Confirm requires operator authority: a non-operator caller is refused before
/// the registry is touched.
#[cfg(unix)]
#[tokio::test]
async fn contain_then_operator_confirm_keeps_change_nonoperator_refused() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store = SessionStore::open(temp.path().join("state.db"), 3_600)
        .await
        .expect("open store");
    let (mut cfg, operator, agent) = gating_config(7003, 1000);
    cfg.state.session_store = Some(store.clone());
    let agent_principal = agent.principal();

    let request = contain_request("true", &[], RevertSpec::new("true", Vec::new()));
    let mut sink = tokio::io::sink();
    let result = arm_containment_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        agent_principal,
        "recoverable change".to_string(),
        None,
    )
    .await;
    let handle = match &result.exec {
        ExecOutcome::Provisional { handle, .. } => handle.clone(),
        other => panic!("expected Provisional, got {:?}", other),
    };

    // A non-operator (uid != daemon_principal) cannot confirm: validate_admin
    // refuses before handle_confirm runs, so the row is untouched.
    let refused = handle_admin_request_for_test(
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
                message.contains("lacks operator authority"),
                "got: {message}"
            );
        }
        other => panic!("non-operator confirm must be refused, got {:?}", other),
    }
    assert_eq!(
        cfg.state
            .provisional
            .read()
            .await
            .get(&handle)
            .unwrap()
            .status,
        ProvisionalStatus::Armed,
        "a refused confirm must not change state"
    );

    // The operator confirms: the change is kept and the auto-revert is
    // cancelled.
    let ok = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::Confirm {
            handle: handle.clone(),
        },
    )
    .await;
    assert!(matches!(ok, AdminResponse::GateAction { .. }));
    assert_eq!(
        cfg.state
            .provisional
            .read()
            .await
            .get(&handle)
            .unwrap()
            .status,
        ProvisionalStatus::Confirmed
    );

    // A confirmed provisional is never due, even far past any deadline: the
    // sweeper's take_due step yields nothing to revert.
    let due = cfg
        .state
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
    let temp = tempfile::tempdir().expect("tempdir");
    let store = SessionStore::open(temp.path().join("state.db"), 3_600)
        .await
        .expect("open store");
    let (mut cfg, _operator, agent) = gating_config(7004, 1000);
    cfg.state.session_store = Some(store.clone());
    let agent_principal = agent.principal();

    // A 1s window: the smallest the clamp allows.
    let mut request = contain_request("true", &[], RevertSpec::new("true", Vec::new()));
    request.confirm_within_secs = Some(1);
    let mut sink = tokio::io::sink();
    let result = arm_containment_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        agent_principal,
        "recoverable change".to_string(),
        None,
    )
    .await;
    let handle = match &result.exec {
        ExecOutcome::Provisional { handle, .. } => handle.clone(),
        other => panic!("expected Provisional, got {:?}", other),
    };

    // Sweeper step: claim every armed-and-due provisional (simulate the
    // deadline by passing a `now` well past it), then run each revert.
    let due = cfg
        .state
        .provisional
        .write()
        .await
        .take_due(now_unix() + 10_000_000);
    assert_eq!(
        due.len(),
        1,
        "the armed provisional is due past its deadline"
    );
    let durable = store.load_provisionals().await.unwrap();
    store
        .compare_and_swap_provisional(durable[0].clone(), due[0].clone())
        .await
        .unwrap();
    for p in &due {
        finish_revert(&cfg, p, &CallerIdentity::Unknown, "auto").await;
    }

    // The `true` revert exits 0 -> Reverted.
    assert_eq!(
        cfg.state
            .provisional
            .read()
            .await
            .get(&handle)
            .unwrap()
            .status,
        ProvisionalStatus::Reverted,
        "auto-revert must roll the unconfirmed change back"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn due_confirm_check_reuses_secret_bindings_and_keeps_the_change() {
    let temp = tempfile::tempdir().expect("tempdir");
    let revert_marker = temp.path().join("revert-ran");
    let store = SessionStore::open(temp.path().join("state.db"), 3_600)
        .await
        .expect("open store");
    let (mut cfg, _operator, agent) = gating_config(7_021, 1_000);
    cfg.state.session_store = Some(store.clone());
    let principal = agent.principal().expect("agent principal");
    cfg.state
        .sessions
        .write()
        .await
        .grant("check-session".to_string(), active_session());
    cfg.state
        .secrets
        .set(&principal, "check-token", "expected-check-secret")
        .await
        .expect("seed check secret");

    let mut revert = RevertSpec::new(
        "sh",
        vec!["-c".into(), format!("touch '{}'", revert_marker.display())],
    );
    revert.confirm_check = Some(crate::server::CommandSpec {
        binary: "sh".into(),
        args: vec!["-c".into(), "test -n \"$CHECK_TOKEN_FILE\"".into()],
    });
    revert.control_path = Some("local daemon identity and secret namespace".into());
    let mut request = contain_request("true", &[], revert);
    request.session_token = Some("check-session".into());
    request
        .secret_files
        .insert("CHECK_TOKEN_FILE".into(), "check-token".into());
    let mut sink = tokio::io::sink();
    let result = arm_containment_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        Some(principal),
        "verified change".into(),
        live_authority(&cfg, "check-session").await,
    )
    .await;
    let handle = match result.exec {
        ExecOutcome::Provisional { handle, .. } => handle,
        other => panic!("expected provisional, got {other:?}"),
    };
    let due = cfg
        .state
        .provisional
        .write()
        .await
        .take_due(now_unix() + 10_000_000);
    assert_eq!(due.len(), 1);
    let durable = store.load_provisionals().await.expect("durable armed row");
    store
        .compare_and_swap_provisional(durable[0].clone(), due[0].clone())
        .await
        .expect("durable revert claim");
    let checked = run_provisional_check(&cfg, &due[0]).await;
    assert!(
        matches!(
            checked.exec,
            ExecOutcome::Completed {
                exit_code: Some(0),
                ..
            }
        ),
        "confirmation check did not reuse the stored binding: {:?}",
        checked.exec
    );
    let outcome = finish_due_provisional(&cfg, &due[0]).await;

    assert_eq!(outcome.1, Some(0));
    let row = cfg
        .state
        .provisional
        .read()
        .await
        .get(&handle)
        .cloned()
        .unwrap();
    assert_eq!(row.status, ProvisionalStatus::Confirmed, "{}", outcome.0);
    assert_eq!(
        row.session_fingerprint.as_deref(),
        Some(audit_session_fingerprint(Some("check-session")).as_str())
    );
    assert!(
        !revert_marker.exists(),
        "successful check must not roll back"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn due_failed_confirm_check_runs_the_rollback() {
    let temp = tempfile::tempdir().expect("tempdir");
    let revert_marker = temp.path().join("revert-ran");
    let store = SessionStore::open(temp.path().join("state.db"), 3_600)
        .await
        .expect("open store");
    let (mut cfg, _operator, agent) = gating_config(7_022, 1_000);
    cfg.state.session_store = Some(store.clone());
    let mut revert = RevertSpec::new(
        "sh",
        vec!["-c".into(), format!("touch '{}'", revert_marker.display())],
    );
    revert.confirm_check = Some(crate::server::CommandSpec {
        binary: "false".into(),
        args: Vec::new(),
    });
    let request = contain_request("true", &[], revert);
    let mut sink = tokio::io::sink();
    let result = arm_containment_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        agent.principal(),
        "failed verification change".into(),
        None,
    )
    .await;
    let handle = match result.exec {
        ExecOutcome::Provisional { handle, .. } => handle,
        other => panic!("expected provisional, got {other:?}"),
    };
    let due = cfg
        .state
        .provisional
        .write()
        .await
        .take_due(now_unix() + 10_000_000);
    let durable = store.load_provisionals().await.unwrap();
    store
        .compare_and_swap_provisional(durable[0].clone(), due[0].clone())
        .await
        .unwrap();
    let outcome = finish_due_provisional(&cfg, &due[0]).await;

    assert_eq!(outcome.1, Some(0));
    assert_eq!(
        cfg.state
            .provisional
            .read()
            .await
            .get(&handle)
            .unwrap()
            .status,
        ProvisionalStatus::Reverted
    );
    assert!(revert_marker.exists(), "failed check must roll back");
}

#[cfg(unix)]
#[tokio::test]
async fn containment_check_cannot_bypass_the_server_binary_floor() {
    let temp = tempfile::tempdir().expect("tempdir");
    let forward_marker = temp.path().join("forward-ran");
    let (mut cfg, _operator, agent) = gating_config(7_023, 1_000);
    cfg.config.allowed_binaries = Some(vec!["sh".into(), "true".into()]);
    let mut revert = RevertSpec::new("true", Vec::new());
    revert.confirm_check = Some(crate::server::CommandSpec {
        binary: "false".into(),
        args: Vec::new(),
    });
    let request = contain_request(
        "sh",
        &["-c", &format!("touch '{}'", forward_marker.display())],
        revert,
    );
    let mut sink = tokio::io::sink();
    let result = arm_containment_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        agent.principal(),
        "binary floor test".into(),
        None,
    )
    .await;

    match result.exec {
        ExecOutcome::Failed {
            started: false,
            reason,
            ..
        } => assert!(reason.contains("outside the server allow-list"), "{reason}"),
        other => panic!("expected pre-exec failure, got {other:?}"),
    }
    assert!(!forward_marker.exists());
    assert!(cfg.state.provisional.read().await.list().is_empty());
}

/// A persisted provisional keeps only a secret-file reference. After a
/// simulated daemon restart, the operator-initiated revert resolves and
/// materializes that reference from the new daemon's live secret manager. A
/// temporarily missing secret defers the revert for an operator retry instead
/// of burning the rollback.
#[cfg(unix)]
#[tokio::test]
async fn provisional_revert_reresolves_secret_after_restart() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = SessionStore::open(tmp.path().join("state.db"), 24 * 60 * 60)
        .await
        .expect("open store");
    let output = tmp.path().join("revert-output");
    let agent_uid = 41_111;
    let agent_principal = PrincipalKey::from_uid(agent_uid);
    let secret_key = format!("REVERT_PARITY_{}", std::process::id());
    let initial_value = "forward-only-value";
    let restart_value = "resolved-after-restart";

    let (mut cfg, _operator, agent) = gating_config(7_016, agent_uid);
    cfg.state.session_store = Some(store.clone());
    cfg.state
        .secrets
        .set(&agent_principal, &secret_key, initial_value)
        .await
        .expect("seed forward secret");

    let mut request = contain_request(
        "true",
        &[],
        RevertSpec::new(
            "sh",
            vec![
                "-c".to_string(),
                "cat \"$REVERT_TOKEN_FILE\" > \"$1\"".to_string(),
                "sh".to_string(),
                output.display().to_string(),
            ],
        ),
    );
    request
        .secret_files
        .insert("REVERT_TOKEN_FILE".to_string(), secret_key.clone());

    let mut sink = tokio::io::sink();
    let result = arm_containment_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        Some(agent_principal.clone()),
        "recoverable change".to_string(),
        None,
    )
    .await;
    let handle = match result.exec {
        ExecOutcome::Provisional { handle, .. } => handle,
        other => panic!("expected Provisional, got {other:?}"),
    };

    let persisted = store
        .load_provisionals()
        .await
        .expect("load persisted provisional");
    assert_eq!(persisted.len(), 1);
    assert_eq!(
        persisted[0].secret_file_keys.get("REVERT_TOKEN_FILE"),
        Some(&secret_key)
    );
    let persisted_json = serde_json::to_string(&persisted[0]).expect("serialize persisted row");
    assert!(!persisted_json.contains(initial_value));
    assert!(!persisted_json.contains(restart_value));

    cfg.state
        .secrets
        .delete(&agent_principal, &secret_key)
        .await
        .expect("remove secret before restart");

    // Simulate registry restoration with a fresh secret-manager cache. A
    // completed forward remains armed; this test then models an immediate
    // operator revert while its named secret is unavailable.
    let (mut restarted, _operator, _agent) = gating_config(7_016, agent_uid);
    restarted.state.session_store = Some(store.clone());
    let (registry, moved) = guard::gating::provisional::ProvisionalRegistry::from_rows(persisted);
    assert!(moved.is_empty());
    *restarted.state.provisional.write().await = registry;

    let missing_claim = restarted
        .state
        .provisional
        .write()
        .await
        .begin_revert(&handle)
        .expect("claim recovered provisional");
    let (message, exit) = finish_revert(
        &restarted,
        &missing_claim,
        &CallerIdentity::Unknown,
        "operator",
    )
    .await;
    assert_eq!(exit, None);
    assert!(message.contains("deferred"), "got: {message}");
    assert_eq!(
        restarted
            .state
            .provisional
            .read()
            .await
            .get(&handle)
            .expect("deferred provisional")
            .status,
        ProvisionalStatus::NeedsOperatorDecision
    );
    assert!(!output.exists());

    restarted
        .state
        .secrets
        .set(&agent_principal, &secret_key, restart_value)
        .await
        .expect("restore live secret after deferred revert");
    let retry = restarted
        .state
        .provisional
        .write()
        .await
        .begin_revert(&handle)
        .expect("retry deferred provisional");
    let (_message, exit) =
        finish_revert(&restarted, &retry, &CallerIdentity::Unknown, "operator").await;
    assert_eq!(exit, Some(0));
    assert_eq!(
        std::fs::read_to_string(&output).expect("read revert output"),
        "resolved-after-restart"
    );

    restarted
        .state
        .secrets
        .delete(&agent_principal, &secret_key)
        .await
        .expect("clean test secret");
}

/// Plain env values have no live-store reference to resolve at revert time and
/// cannot be proven non-secret, so containment refuses all of them before
/// either persistence or the forward command. Callers must use `--secret`.
#[cfg(unix)]
#[tokio::test]
async fn containment_refuses_plain_env_before_forward_exec() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let marker = tmp.path().join("forward-ran");
    let store = SessionStore::open(tmp.path().join("state.db"), 24 * 60 * 60)
        .await
        .expect("open store");
    let (mut cfg, _operator, agent) = gating_config(7_017, 1_000);
    cfg.state.session_store = Some(store.clone());
    let mut request = contain_request(
        "sh",
        &["-c", &format!("touch '{}'", marker.display())],
        RevertSpec::new("true", Vec::new()),
    );
    request
        .env
        .insert("MODE".to_string(), "cleanup".to_string());

    let mut sink = tokio::io::sink();
    let result = arm_containment_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        agent.principal(),
        "recoverable change".to_string(),
        None,
    )
    .await;

    match result.exec {
        ExecOutcome::Failed {
            started, reason, ..
        } => {
            assert!(!started);
            assert!(reason.contains("pass them with --secret"), "got: {reason}");
        }
        other => panic!("expected pre-exec failure, got {other:?}"),
    }
    assert!(!marker.exists(), "forward command must not have run");
    assert!(
        cfg.state.provisional.read().await.list().is_empty(),
        "plain env must not reach the provisional registry"
    );
    assert!(
        store
            .load_provisionals()
            .await
            .expect("read persisted provisionals")
            .is_empty(),
        "plain env must not reach persisted provisional state"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn api_revert_without_running_proxy_defers_to_operator() {
    let (cfg, _operator, _agent) = gating_config(7014, 1000);
    let handle = "api-missing-proxy".to_string();
    let now = now_unix();
    let provisional = Provisional {
        handle: handle.clone(),
        principal: Some(cfg.config.daemon_principal.clone()),
        requester_principal: None,
        binary: "(api-proxy)".to_string(),
        args: vec!["delete labels/bug in o/r".to_string()],
        cwd: None,
        secret_keys: BTreeMap::new(),
        secret_file_keys: BTreeMap::new(),
        revert_binary: "(api-proxy)".to_string(),
        revert_args: vec![
            "github".to_string(),
            "POST".to_string(),
            "/repos/o/r/labels".to_string(),
        ],
        confirm_check_binary: None,
        confirm_check_args: Vec::new(),
        control_path: None,
        session_fingerprint: None,
        session_revision: None,
        secret_entitlements: None,
        api_revert: Some(ApiRevertPlan {
            endpoint: String::new(),
            protocol: "github".to_string(),
            upstream_target: String::new(),
            upstream_identity: String::new(),
            method: "POST".to_string(),
            path: "/repos/o/r/labels".to_string(),
            requires_uid_precondition: false,
            resource_uid: None,
            create_provenance: None,
            body_file: None,
        }),
        reason: "delete labels/bug in o/r".to_string(),
        decision_trace: None,
        created_unix: now,
        deadline_unix: now,
        window_secs: 0,
        auto_reverted_unix: None,
        forward_done: true,
        forward_exit: Some(0),
        forward_persistence_failed: false,
        status: ProvisionalStatus::Reverting,
        revert_exit: None,
        revert_detail: None,
    };
    cfg.state
        .provisional
        .write()
        .await
        .insert(provisional.clone());

    // A missing proxy is recoverable: the change is still live, so the revert
    // is deferred to the operator (NeedsOperatorDecision) rather than burned as
    // a terminal RevertFailed.
    let (message, exit) = finish_revert(&cfg, &provisional, &CallerIdentity::Unknown, "auto").await;
    assert!(message.contains("deferred"), "got: {message}");
    assert_eq!(exit, None);
    let row = cfg
        .state
        .provisional
        .read()
        .await
        .get(&handle)
        .cloned()
        .unwrap();
    assert_eq!(row.status, ProvisionalStatus::NeedsOperatorDecision);
    assert!(row
        .revert_detail
        .as_deref()
        .unwrap()
        .contains("no running api-proxy for protocol 'github'"));
}

/// A failed rollback is lifecycle-final but remains outstanding so an operator
/// can query and resolve the mutation. Its durable row, live registry, audit,
/// and notification must all record the same failed outcome.
#[cfg(unix)]
#[tokio::test]
async fn failed_revert_is_durable_queryable_and_notifies_operator() {
    let state = tempfile::tempdir().expect("state tempdir");
    let store = SessionStore::open(state.path().join("state.db"), 3_600)
        .await
        .expect("open store");
    let (mut cfg, _operator, agent) = gating_config(7_015, 1_000);
    cfg.state.session_store = Some(store.clone());
    let (audit_directory, _audit) = super::attach_test_audit_log(&mut cfg);
    let event_path = state.path().join("notify-event.json");
    cfg.state.notify_hook = crate::server::runtime::NotifyHook::new(
        vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("cat > '{}'", event_path.display()),
        ],
        5,
    );

    let mut sink = tokio::io::sink();
    let result = arm_containment_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        contain_request("true", &[], RevertSpec::new("false", Vec::new())),
        agent.principal(),
        "failed rollback fixture".to_string(),
        None,
    )
    .await;
    let handle = match result.exec {
        ExecOutcome::Provisional { handle, .. } => handle,
        other => panic!("expected provisional, got {other:?}"),
    };
    let claimed = cfg
        .state
        .provisional
        .write()
        .await
        .begin_revert(&handle)
        .expect("claim provisional for revert");
    let durable_armed = store
        .load_provisionals()
        .await
        .expect("load armed provisional")
        .into_iter()
        .find(|row| row.handle == handle)
        .expect("armed provisional row");
    store
        .compare_and_swap_provisional(durable_armed, claimed.clone())
        .await
        .expect("persist reverting claim");

    let (message, exit) = finish_revert(&cfg, &claimed, &CallerIdentity::Unknown, "auto").await;
    assert_eq!(exit, Some(1));
    assert!(message.contains("REVERT FAILED"), "got: {message}");

    let live = cfg
        .state
        .provisional
        .read()
        .await
        .get(&handle)
        .cloned()
        .expect("live failed revert");
    assert_eq!(live.status, ProvisionalStatus::RevertFailed);
    assert!(live.status.is_outstanding());
    assert!(!live.status.is_terminal());
    assert!(live.status.is_lifecycle_final());

    let durable = store
        .load_provisionals()
        .await
        .expect("load failed revert")
        .into_iter()
        .find(|row| row.handle == handle)
        .expect("durable failed revert");
    assert_eq!(durable.status, ProvisionalStatus::RevertFailed);
    assert_eq!(durable.revert_exit, Some(1));

    cfg.state.session_store = None;
    drop(store);
    let reopened = SessionStore::open(state.path().join("state.db"), 3_600)
        .await
        .expect("reopen store");
    let reloaded = reopened
        .load_provisionals()
        .await
        .expect("reload failed revert")
        .into_iter()
        .find(|row| row.handle == handle)
        .expect("reloaded failed revert");
    assert_eq!(reloaded.status, ProvisionalStatus::RevertFailed);

    let audit = std::fs::read_to_string(audit_directory.path().join("audit.jsonl"))
        .expect("read audit log");
    assert!(audit.contains("REVERT_FAILED"), "audit: {audit}");

    let event = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if event_path.exists() {
                break std::fs::read_to_string(&event_path).expect("read notification event");
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("revert notification event timed out");
    assert!(
        event.contains("\"event\":\"decision_made\""),
        "event: {event}"
    );
    assert!(
        event.contains("\"status\":\"revert_failed\""),
        "event: {event}"
    );
}

/// The sweeper executes a due API revert as an HTTP request through the
/// registered proxy's upstream, carrying the daemon's bearer credential and
/// the persisted body. This is the success half of the fail-loud test above.
#[cfg(unix)]
#[tokio::test]
async fn api_revert_executes_through_registered_proxy_upstream() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let state = tempfile::tempdir().expect("tempdir");
    let store = SessionStore::open(state.path().join("state.db"), 3_600)
        .await
        .expect("open store");

    // Minimal recording upstream: capture the one request, answer 200 JSON.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let captured: Arc<std::sync::Mutex<String>> = Arc::new(std::sync::Mutex::new(String::new()));
    let captured_in = captured.clone();
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            *captured_in.lock().unwrap() = String::from_utf8_lossy(&buf[..n]).to_string();
            let _ = stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}",
                )
                .await;
        }
    });

    let (mut cfg, _operator, _agent) = gating_config(7015, 1000);
    cfg.state.session_store = Some(store.clone());
    let upstream = guard::proxy::Upstream::from_base_url(
        &format!("http://{upstream_addr}"),
        guard::proxy::UpstreamAuth::Bearer("revert-token".to_string()),
    )
    .expect("upstream");
    let proxy = Arc::new(guard::proxy::ApiProxy::with_protocol(
        Arc::new(guard::proxy::GithubProtocol),
        "127.0.0.1:0".parse().unwrap(),
        guard::proxy::ProxyTls::generate().expect("tls"),
        upstream,
        guard::proxy::ApiPolicy::deny_all(),
        None,
    ));
    let upstream_target = proxy.upstream().base().to_string();
    let upstream_identity = proxy.upstream_identity_fingerprint();
    cfg.state
        .protocol_registry
        .write()
        .await
        .insert("github".to_string(), proxy);

    let body_file = std::env::temp_dir().join(format!("api-revert-body-{}", std::process::id()));
    std::fs::write(&body_file, br#"{"name":"bug","color":"d73a4a"}"#).unwrap();

    let handle = "api-live-proxy".to_string();
    let now = now_unix();
    let provisional = Provisional {
        handle: handle.clone(),
        principal: Some(cfg.config.daemon_principal.clone()),
        requester_principal: None,
        binary: "(api-proxy)".to_string(),
        args: vec!["delete labels/bug in o/r".to_string()],
        cwd: None,
        secret_keys: BTreeMap::new(),
        secret_file_keys: BTreeMap::new(),
        revert_binary: "(api-proxy)".to_string(),
        revert_args: vec![
            "github".to_string(),
            "POST".to_string(),
            "/repos/o/r/labels".to_string(),
        ],
        confirm_check_binary: None,
        confirm_check_args: Vec::new(),
        control_path: None,
        session_fingerprint: None,
        session_revision: None,
        secret_entitlements: None,
        api_revert: Some(ApiRevertPlan {
            endpoint: String::new(),
            protocol: "github".to_string(),
            upstream_target,
            upstream_identity,
            method: "POST".to_string(),
            path: "/repos/o/r/labels".to_string(),
            requires_uid_precondition: false,
            resource_uid: None,
            create_provenance: None,
            body_file: Some(body_file.clone()),
        }),
        reason: "delete labels/bug in o/r".to_string(),
        decision_trace: None,
        created_unix: now,
        deadline_unix: now,
        window_secs: 0,
        auto_reverted_unix: None,
        forward_done: true,
        forward_exit: Some(0),
        forward_persistence_failed: false,
        status: ProvisionalStatus::Reverting,
        revert_exit: None,
        revert_detail: None,
    };
    let mut durable = provisional.clone();
    durable.status = ProvisionalStatus::Armed;
    store
        .save_provisional(durable.clone())
        .await
        .expect("persist durable API provisional");
    store
        .compare_and_swap_provisional(durable, provisional.clone())
        .await
        .expect("persist API revert claim");
    cfg.state
        .provisional
        .write()
        .await
        .insert(provisional.clone());

    let (message, exit) = finish_revert(&cfg, &provisional, &CallerIdentity::Unknown, "auto").await;
    assert!(message.contains("reverted"), "got: {message}");
    assert_eq!(exit, Some(0));
    let row = cfg
        .state
        .provisional
        .read()
        .await
        .get(&handle)
        .cloned()
        .unwrap();
    assert_eq!(row.status, ProvisionalStatus::Reverted);

    let raw = captured.lock().unwrap().clone();
    assert!(raw.starts_with("POST /repos/o/r/labels HTTP/1.1"), "{raw}");
    assert!(
        raw.contains("authorization: Bearer revert-token")
            || raw.contains("Authorization: Bearer revert-token"),
        "daemon credential must ride the revert: {raw}"
    );
    assert!(raw.contains(r#"{"name":"bug","color":"d73a4a"}"#), "{raw}");
    // The secret-bearing snapshot body is removed once the revert is terminal.
    assert!(
        !body_file.exists(),
        "revert body file must be unlinked after a terminal revert"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn api_provisional_binds_session_and_upstream_identity() {
    let state = tempfile::tempdir().expect("tempdir");
    let store = SessionStore::open(state.path().join("state.db"), 3_600)
        .await
        .expect("open store");
    let (mut cfg, _operator, _agent) = gating_config(7016, 1000);
    cfg.state.session_store = Some(store);
    let sink = DaemonGateSink {
        server: cfg.clone(),
        endpoint: "cluster-a".to_string(),
        protocol: "kubernetes".to_string(),
        snapshot_dir: std::env::temp_dir(),
        snapshot_dir_safe: true,
        window_secs: 60,
    };
    let handle = guard::proxy::GateSink::arm_revert(
        &sink,
        guard::proxy::ApiMutation {
            label: "patch deployments/api".to_string(),
            revert: guard::proxy::HttpRevert {
                method: "PUT".to_string(),
                path: "/apis/apps/v1/namespaces/dev/deployments/api".to_string(),
                body: None,
            },
            revert_requires_uid_precondition: false,
            create_provenance: None,
            session_fingerprint: Some("session-fingerprint".to_string()),
            session_revision: Some("session-revision".to_string()),
            secret_entitlements: Some(vec!["cluster-a/token".to_string()]),
            upstream_target: "https://cluster-a.invalid".to_string(),
            upstream_identity: "identity-fingerprint".to_string(),
        },
    )
    .await
    .expect("provisional armed");

    let row = cfg
        .state
        .provisional
        .read()
        .await
        .get(&handle)
        .cloned()
        .unwrap();
    assert_eq!(
        row.session_fingerprint.as_deref(),
        Some("session-fingerprint")
    );
    assert_eq!(row.session_revision.as_deref(), Some("session-revision"));
    assert_eq!(
        row.secret_entitlements.as_deref(),
        Some(["cluster-a/token".to_string()].as_slice())
    );
    assert!(!row.forward_done);
    assert_eq!(row.deadline_unix, 0);
    assert_eq!(row.status, ProvisionalStatus::Staged);
    {
        let live = cfg.state.provisional.read().await;
        assert!(live.visible_list().is_empty());
        assert_eq!(live.visible_outstanding(), 0);
        assert_eq!(live.outstanding(), 1);
    }
    let mut inert = guard::gating::provisional::ProvisionalRegistry::new();
    inert.insert(row.clone());
    assert!(inert.begin_revert(&handle).is_err());
    assert!(inert.confirm(&handle).is_err());
    assert!(inert.due_handles(u64::MAX).is_empty());
    assert!(guard::proxy::GateSink::mark_revert_dispatching(&sink, &handle).await);
    assert!(guard::proxy::GateSink::mark_revert_forwarded(&sink, &handle, None).await);
    let live = cfg
        .state
        .provisional
        .read()
        .await
        .get(&handle)
        .cloned()
        .unwrap();
    assert!(live.forward_done);
    assert_eq!(live.forward_exit, Some(0));
    assert!(live.deadline_unix >= live.created_unix);
    let durable = cfg
        .state
        .session_store
        .as_ref()
        .unwrap()
        .load_provisionals()
        .await
        .unwrap()
        .into_iter()
        .find(|row| row.handle == handle)
        .unwrap();
    assert_eq!(durable.forward_done, live.forward_done);
    assert_eq!(durable.deadline_unix, live.deadline_unix);
    let api = row.api_revert.unwrap();
    assert_eq!(api.endpoint, "cluster-a");
    assert_eq!(api.upstream_target, "https://cluster-a.invalid");
    assert_eq!(api.upstream_identity, "identity-fingerprint");
}

#[cfg(unix)]
#[tokio::test]
async fn api_dispatch_state_blocks_operator_actions_until_the_handoff_is_uncertain() {
    let state = tempfile::tempdir().expect("tempdir");
    let store = SessionStore::open(state.path().join("state.db"), 3_600)
        .await
        .expect("open store");
    let (mut cfg, _operator, _agent) = gating_config(7017, 1000);
    cfg.state.session_store = Some(store.clone());
    let sink = DaemonGateSink {
        server: cfg.clone(),
        endpoint: "cluster-a".to_string(),
        protocol: "kubernetes".to_string(),
        snapshot_dir: state.path().to_path_buf(),
        snapshot_dir_safe: true,
        window_secs: 60,
    };
    let mutation = || guard::proxy::ApiMutation {
        label: "create pods/example".to_string(),
        revert: guard::proxy::HttpRevert {
            method: "DELETE".to_string(),
            path: "/api/v1/namespaces/dev/pods/example".to_string(),
            body: None,
        },
        revert_requires_uid_precondition: true,
        create_provenance: Some("provenance".to_string()),
        session_fingerprint: Some("session-fingerprint".to_string()),
        session_revision: Some("session-revision".to_string()),
        secret_entitlements: None,
        upstream_target: "https://cluster-a.invalid".to_string(),
        upstream_identity: "identity-fingerprint".to_string(),
    };

    let handle = guard::proxy::GateSink::arm_revert(&sink, mutation())
        .await
        .expect("stage rollback");
    let dispatching = cfg
        .state
        .provisional
        .read()
        .await
        .get(&handle)
        .cloned()
        .unwrap();
    let mut confirm_attempt = guard::gating::provisional::ProvisionalRegistry::new();
    confirm_attempt.insert(dispatching.clone());
    assert!(confirm_attempt.confirm(&handle).is_err());
    let mut revert_attempt = guard::gating::provisional::ProvisionalRegistry::new();
    revert_attempt.insert(dispatching);
    assert!(revert_attempt.begin_revert(&handle).is_err());

    assert!(guard::proxy::GateSink::mark_revert_dispatching(&sink, &handle).await);

    assert!(
        guard::proxy::GateSink::mark_revert_indeterminate(
            &sink,
            &handle,
            "upstream handoff timed out",
            Some("resource-uid"),
        )
        .await
    );
    let uncertain = cfg
        .state
        .provisional
        .read()
        .await
        .get(&handle)
        .cloned()
        .unwrap();
    let mut actionable = guard::gating::provisional::ProvisionalRegistry::new();
    actionable.insert(uncertain);
    assert!(actionable.begin_revert(&handle).is_ok());

    let rejected_handle = guard::proxy::GateSink::arm_revert(&sink, mutation())
        .await
        .expect("stage rejected rollback");
    assert!(guard::proxy::GateSink::cancel_staged_revert(&sink, &rejected_handle).await);
    assert!(cfg
        .state
        .provisional
        .read()
        .await
        .get(&rejected_handle)
        .is_none());
    assert!(store
        .load_provisionals()
        .await
        .unwrap()
        .iter()
        .all(|row| row.handle != rejected_handle));
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
        RevertSpec::new(
            "../evil", // `..` rejected by invalid_binary_reason
            Vec::new(),
        ),
    );
    let inputs = GateInputs {
        reason: "recoverable restart".to_string(),
        risk: Some(2),
        reversibility: Some(Reversibility::Recoverable),
        revert_preauthorized: false,
        verb: None,
        bypass: false,
        authority: None,
        consume_access_verbs: Vec::new(),
    };
    let mut sink = tokio::io::sink();
    let result = route_gated_allow(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        inputs,
        None,
    )
    .await;

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
        cfg.state.provisional.read().await.outstanding(),
        0,
        "an unaffirmable rollback must never arm a containment envelope"
    );
    assert_eq!(
        cfg.state
            .approvals
            .read()
            .await
            .get(&handle)
            .unwrap()
            .status,
        ApprovalStatus::Pending,
        "the forward command must be queued for an operator decision"
    );
}

#[tokio::test]
async fn post_evaluator_session_revoke_or_expiry_fails_before_arm_or_hold() {
    let (cfg, _operator, agent) = gating_config(7022, 1000);
    cfg.state
        .sessions
        .write()
        .await
        .grant("revoked-during-eval".to_string(), active_session());
    let revoked_authority = cfg
        .state
        .sessions
        .read()
        .await
        .authority_snapshot("revoked-during-eval")
        .unwrap()
        .into();
    assert!(cfg
        .state
        .sessions
        .write()
        .await
        .revoke("revoked-during-eval"));
    let mut contained = contain_request("true", &[], RevertSpec::new("true", Vec::new()));
    contained.session_token = Some("revoked-during-eval".to_string());
    let mut sink = tokio::io::sink();
    let denied = route_gated_allow(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        contained,
        GateInputs {
            reason: "evaluator approved before revoke".to_string(),
            risk: Some(2),
            reversibility: Some(Reversibility::Recoverable),
            revert_preauthorized: true,
            verb: None,
            bypass: false,
            authority: Some(revoked_authority),
            consume_access_verbs: Vec::new(),
        },
        None,
    )
    .await;
    assert!(!denied.policy_allowed());
    assert!(denied.policy_reason().contains("revoked"));
    assert_eq!(cfg.state.provisional.read().await.outstanding(), 0);

    cfg.state
        .sessions
        .write()
        .await
        .grant("expired-during-eval".to_string(), active_session());
    let expired_authority = cfg
        .state
        .sessions
        .read()
        .await
        .authority_snapshot("expired-during-eval")
        .unwrap()
        .into();
    let mut expired = active_session();
    expired.expires_at = Some(now_unix().saturating_sub(1));
    let mut sessions = cfg.state.sessions.write().await;
    let mut grants = sessions.grants_snapshot();
    grants.insert("expired-during-eval".to_string(), expired);
    *sessions = crate::session::SessionRegistry::from_parts(
        grants,
        sessions.history_snapshot(),
        sessions.interactions_snapshot(),
        3_600,
    );
    drop(sessions);
    let mut held = contain_request("true", &[], RevertSpec::new("true", Vec::new()));
    held.revert = None;
    held.session_token = Some("expired-during-eval".to_string());
    let denied = route_gated_allow(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        held,
        GateInputs {
            reason: "evaluator approved before expiry".to_string(),
            risk: Some(9),
            reversibility: Some(Reversibility::Irreversible),
            revert_preauthorized: false,
            verb: None,
            bypass: false,
            authority: Some(expired_authority),
            consume_access_verbs: Vec::new(),
        },
        None,
    )
    .await;
    assert!(!denied.policy_allowed());
    assert!(denied.policy_reason().contains("expired"));
    assert_eq!(cfg.state.approvals.read().await.outstanding(), 0);
}

#[cfg(unix)]
#[tokio::test]
async fn session_status_does_not_cross_expose_same_principal_provisionals() {
    let (cfg, _operator, agent) = gating_config(7024, 1000);
    for token in ["status-session-a", "status-session-b"] {
        cfg.state
            .sessions
            .write()
            .await
            .grant(token.to_string(), active_session());
        cfg.state.provisional.write().await.insert(Provisional {
            handle: format!("provisional-{token}"),
            principal: agent.principal(),
            requester_principal: None,
            binary: "true".to_string(),
            args: Vec::new(),
            cwd: None,
            secret_keys: BTreeMap::new(),
            secret_file_keys: BTreeMap::new(),
            revert_binary: "true".to_string(),
            revert_args: Vec::new(),
            confirm_check_binary: None,
            confirm_check_args: Vec::new(),
            control_path: Some("test".to_string()),
            session_fingerprint: Some(audit_session_fingerprint(Some(token))),
            session_revision: cfg
                .state
                .sessions
                .read()
                .await
                .effective_revision_key(token),
            secret_entitlements: None,
            api_revert: None,
            reason: "test".to_string(),
            decision_trace: None,
            created_unix: now_unix(),
            deadline_unix: now_unix().saturating_add(60),
            window_secs: 0,
            auto_reverted_unix: None,
            forward_done: true,
            forward_exit: Some(0),
            forward_persistence_failed: false,
            status: ProvisionalStatus::Armed,
            revert_exit: None,
            revert_detail: None,
        });
    }

    let response = handle_admin_request_for_test(
        &cfg,
        &agent,
        AdminRequest::SessionStatus {
            token: "status-session-a".to_string(),
            caller_token: Some("status-session-a".to_string()),
        },
    )
    .await;
    let AdminResponse::SessionStatus { provisionals, .. } = response else {
        panic!("expected session status, got {response:?}");
    };
    assert_eq!(provisionals.len(), 1);
    assert_eq!(provisionals[0].handle, "provisional-status-session-a");
}

#[cfg(unix)]
#[tokio::test]
async fn requester_can_list_own_api_provisional_without_decision_authority() {
    let (cfg, operator, requester) = gating_config(7_024, 1_000);
    let handle = "api-provisional-requester-visible";
    cfg.state.provisional.write().await.insert(Provisional {
        handle: handle.to_string(),
        principal: Some(cfg.config.daemon_principal.clone()),
        requester_principal: requester.principal(),
        binary: "(api-proxy)".to_string(),
        args: vec!["patch deployments/api in dev".to_string()],
        cwd: None,
        secret_keys: BTreeMap::new(),
        secret_file_keys: BTreeMap::new(),
        revert_binary: String::new(),
        revert_args: Vec::new(),
        confirm_check_binary: None,
        confirm_check_args: Vec::new(),
        control_path: Some("daemon API proxy for protocol kubernetes".to_string()),
        session_fingerprint: Some("sha256:requester-session".to_string()),
        session_revision: Some("requester-session-revision".to_string()),
        secret_entitlements: None,
        api_revert: Some(ApiRevertPlan {
            endpoint: "fixture".to_string(),
            protocol: "kubernetes".to_string(),
            upstream_target: "https://upstream.invalid".to_string(),
            upstream_identity: "fixture-identity".to_string(),
            method: "PUT".to_string(),
            path: "/apis/apps/v1/namespaces/dev/deployments/api".to_string(),
            requires_uid_precondition: false,
            resource_uid: None,
            create_provenance: None,
            body_file: None,
        }),
        reason: "patch deployments/api in dev".to_string(),
        decision_trace: None,
        created_unix: now_unix(),
        deadline_unix: now_unix().saturating_add(300),
        window_secs: 300,
        auto_reverted_unix: None,
        forward_done: true,
        forward_exit: Some(0),
        forward_persistence_failed: false,
        status: ProvisionalStatus::Armed,
        revert_exit: None,
        revert_detail: None,
    });

    let AdminResponse::Provisionals { items } =
        handle_admin_request_for_test(&cfg, &requester, AdminRequest::Provisionals).await
    else {
        panic!("requester should receive a provisional list");
    };
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].handle, handle);

    let AdminResponse::Provisionals { items } = handle_admin_request_for_test(
        &cfg,
        &CallerIdentity::Unix { uid: 1_001 },
        AdminRequest::Provisionals,
    )
    .await
    else {
        panic!("other requester should receive a provisional list");
    };
    assert!(items.is_empty());

    assert!(matches!(
        handle_admin_request_for_test(
            &cfg,
            &requester,
            AdminRequest::Confirm {
                handle: handle.to_string(),
            },
        )
        .await,
        AdminResponse::Error { message } if message.contains("operator authority")
    ));
    assert_eq!(
        cfg.state
            .provisional
            .read()
            .await
            .get(handle)
            .unwrap()
            .status,
        ProvisionalStatus::Armed
    );

    let AdminResponse::Provisionals { items } =
        handle_admin_request_for_test(&cfg, &operator, AdminRequest::Provisionals).await
    else {
        panic!("operator should receive a provisional list");
    };
    assert_eq!(items.len(), 1);
}

/// Approval arms the immutable snapshot without executing it. Only the
/// authenticated requester can claim the one-shot resume.
#[cfg(unix)]
#[tokio::test]
async fn approval_snapshot_omits_rendered_verb_parameter_values() {
    let (mut cfg, _, agent) = gating_config(7004, 1000);
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state.db");
    let store = SessionStore::open(path.clone(), 3600).await.unwrap();
    cfg.state.session_store = Some(store.clone());
    let value = ["q", "7"].concat();
    let mut sink = tokio::io::sink();
    let held = hold_for_approval_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        held_request("true", Vec::new(), None),
        agent.principal(),
        GateInputs {
            reason: "needs sign-off".to_string(),
            risk: Some(9),
            reversibility: Some(Reversibility::Irreversible),
            revert_preauthorized: false,
            verb: Some(VerbContext {
                name: "fixture-verb".to_string(),
                class: Reversibility::Irreversible,
                trusted: false,
                params: BTreeMap::from([("rollback_only".to_string(), value.clone())]),
                catalog_version: 1,
                verb_digest: None,
                composition_digest: None,
                access_evaluation_override_eligible: false,
            }),
            bypass: false,
            authority: None,
            consume_access_verbs: Vec::new(),
        },
    )
    .await;
    let ExecOutcome::Held { handle, .. } = held.exec else {
        panic!("expected held command")
    };
    let approval = cfg
        .state
        .approvals
        .read()
        .await
        .get(&handle)
        .unwrap()
        .clone();
    assert!(approval.snapshot.verb_params.is_empty());
    assert!(store.load_approvals().await.unwrap()[0]
        .snapshot
        .verb_params
        .is_empty());
    let durable = std::fs::read(path).unwrap();
    assert!(!durable
        .windows(value.len())
        .any(|window| window == value.as_bytes()));
}

#[cfg(unix)]
#[tokio::test]
async fn hold_approval_arms_then_requester_resumes_once_with_output() {
    let (cfg, operator, agent) = gating_config(7005, 1000);
    let agent_principal = agent.principal();
    let state = tempfile::tempdir().unwrap();
    let marker = state.path().join("resumed");

    // Hold a command with observable stdout, stderr, exit status, and side
    // effect so approval and execution cannot be confused.
    let request = ExecuteRequest {
        binary: "sh".to_string(),
        args: vec![
            "-c".to_string(),
            format!(
                "printf requester-stdout; printf requester-stderr >&2; printf resumed > '{}'; exit 7",
                marker.display()
            ),
        ],
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
    let mut sink = tokio::io::sink();
    let held = hold_for_approval_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        agent_principal,
        GateInputs {
            reason: "needs sign-off".to_string(),
            risk: Some(9),
            reversibility: Some(Reversibility::Irreversible),
            revert_preauthorized: false,
            verb: None,
            bypass: false,
            authority: None,
            consume_access_verbs: Vec::new(),
        },
    )
    .await;
    let handle = match &held.exec {
        ExecOutcome::Held { handle, .. } => handle.clone(),
        other => panic!("expected Held, got {:?}", other),
    };
    let held_response = held.into_response();
    let guidance = held_response.verb_guidance.as_deref().unwrap();
    assert_eq!(
        guidance,
        format!("ask your admin to approve request {handle} (see guard access show {handle})")
    );

    // Non-operator approve is refused; the hold stays pending.
    let refused = handle_admin_request_for_test(
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
                message.contains("lacks operator authority"),
                "got: {message}"
            );
        }
        other => panic!("non-operator approve must be refused, got {:?}", other),
    }
    assert_eq!(
        cfg.state
            .approvals
            .read()
            .await
            .get(&handle)
            .unwrap()
            .status,
        ApprovalStatus::Pending,
        "a refused approve must not change state"
    );

    // A budget other than one use is the only rejected form: the snapshot
    // cannot honour it. No use flag means the one legal thing.
    let response = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::AccessApprove {
            handles: vec![handle.clone()],
            uses: Some(3),
            wait_secs: None,
        },
    )
    .await;
    let AdminResponse::AccessDecisions { items, .. } = response else {
        panic!("expected held access decision")
    };
    assert!(!items[0].success);
    assert!(items[0].message.contains("approve them with --once"));
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

    // Operator approval arms the snapshot and returns without executing it.
    let ok = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::AccessApprove {
            handles: vec![handle.clone()],
            uses: Some(1),
            wait_secs: None,
        },
    )
    .await;
    match ok {
        AdminResponse::AccessDecisions { items, .. } => {
            assert!(items[0].success);
            assert_eq!(items[0].state, "armed");
            assert_eq!(items[0].remaining_uses, None);
            assert_eq!(items[0].use_policy, "unavailable");
            assert_eq!(items[0].target.as_deref(), Some("agent:1000"));
        }
        other => panic!("operator approval should arm, got {:?}", other),
    }
    assert!(
        !marker.exists(),
        "approval must not execute the held command"
    );
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
    let AdminResponse::Approvals { items } =
        handle_admin_request_for_test(&cfg, &agent, AdminRequest::ApprovalList).await
    else {
        panic!("requester should list its armed hold")
    };
    assert_eq!(items[0].status, "armed");

    let wrong_requester = CallerIdentity::Unix { uid: 1001 };
    let refused = handle_admin_request_for_test(
        &cfg,
        &wrong_requester,
        AdminRequest::Resume {
            handle: handle.clone(),
        },
    )
    .await;
    assert!(matches!(refused, AdminResponse::Error { .. }));
    assert!(!marker.exists());

    let resumed = handle_admin_request_for_test(
        &cfg,
        &agent,
        AdminRequest::Resume {
            handle: handle.clone(),
        },
    )
    .await;
    match resumed {
        AdminResponse::GateAction {
            exit_code,
            stdout,
            stderr,
            ..
        } => {
            assert_eq!(exit_code, Some(7));
            assert_eq!(stdout.as_deref(), Some("requester-stdout"));
            assert_eq!(stderr.as_deref(), Some("requester-stderr"));
        }
        other => panic!("requester resume should execute, got {other:?}"),
    }
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), "resumed");
    assert_eq!(
        cfg.state
            .approvals
            .read()
            .await
            .get(&handle)
            .unwrap()
            .status,
        ApprovalStatus::Approved
    );
    let replay = handle_admin_request_for_test(
        &cfg,
        &agent,
        AdminRequest::Resume {
            handle: handle.clone(),
        },
    )
    .await;
    assert!(matches!(replay, AdminResponse::Error { .. }));

    let AdminResponse::AccessItem { item } = handle_admin_request_for_test(
        &cfg,
        &agent,
        AdminRequest::AccessShow {
            reference: handle.clone(),
        },
    )
    .await
    else {
        panic!("requester should inspect its held access request")
    };
    assert_eq!(item.state, "approved");
    assert_eq!(item.target, "agent:1000");
    assert_eq!(item.remaining_uses, None);
    assert!(
        cfg.state
            .sessions
            .read()
            .await
            .access_token_for_principal(&PrincipalKey::from_uid(1000))
            .is_none(),
        "one-shot held execution must not leave session authority"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn armed_hold_survives_restart_and_persists_bounded_transcript() {
    let (mut cfg, operator, agent) = gating_config(7_042, 1_000);
    let state = tempfile::tempdir().unwrap();
    let store = SessionStore::open(state.path().join("state.db"), 3_600)
        .await
        .unwrap();
    cfg.state.session_store = Some(store.clone());
    let request = held_request(
        "sh",
        vec![
            "-c".to_string(),
            "yes x | head -c 300000; yes y | head -c 300000 >&2".to_string(),
        ],
        None,
    );
    let mut sink = tokio::io::sink();
    let held = hold_for_approval_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        agent.principal(),
        GateInputs {
            reason: "bounded transcript".to_string(),
            risk: Some(9),
            reversibility: Some(Reversibility::Irreversible),
            revert_preauthorized: false,
            verb: None,
            bypass: false,
            authority: None,
            consume_access_verbs: Vec::new(),
        },
    )
    .await;
    let ExecOutcome::Held { handle, .. } = held.exec else {
        panic!("expected held command")
    };
    let armed = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::AccessApprove {
            handles: vec![handle.clone()],
            uses: Some(1),
            wait_secs: None,
        },
    )
    .await;
    assert!(matches!(armed, AdminResponse::AccessDecisions { .. }));

    let rows = store.load_approvals().await.unwrap();
    let (registry, recovered) =
        guard::gating::approval::ApprovalRegistry::from_rows(rows, now_unix());
    assert!(recovered.is_empty());
    assert_eq!(
        crate::server::wire::ApprovalSummary::from_row(registry.get(&handle).unwrap()).status,
        "armed"
    );
    let (mut restarted, _operator, requester) = gating_config(7_042, 1_000);
    restarted.state.session_store = Some(store.clone());
    *restarted.state.approvals.write().await = registry;

    let resumed = handle_admin_request_for_test(
        &restarted,
        &requester,
        AdminRequest::Resume {
            handle: handle.clone(),
        },
    )
    .await;
    match resumed {
        AdminResponse::GateAction {
            exit_code,
            stdout,
            stderr,
            ..
        } => {
            assert_eq!(exit_code, Some(0));
            assert_eq!(stdout.as_deref().map(str::len), Some(300_000));
            assert_eq!(stderr.as_deref().map(str::len), Some(300_000));
        }
        other => panic!("restart resume failed: {other:?}"),
    }

    let durable = store.load_approvals().await.unwrap();
    let row = durable.iter().find(|row| row.handle == handle).unwrap();
    assert_eq!(row.status, ApprovalStatus::Approved);
    let stdout = row.result_stdout.as_deref().unwrap();
    let stderr = row.result_stderr.as_deref().unwrap();
    assert!(serde_json::to_vec(stdout).unwrap().len() <= 262_144);
    assert!(serde_json::to_vec(stderr).unwrap().len() <= 262_144);
    assert!(stdout.ends_with("[guard persisted transcript truncated]\n"));
    assert!(stderr.ends_with("[guard persisted transcript truncated]\n"));
    let summary = crate::server::wire::ApprovalSummary::from_row(row);
    assert!(summary.stdout_truncated);
    assert!(summary.stderr_truncated);
    assert!(
        serde_json::to_vec(summary.stdout.as_deref().unwrap())
            .unwrap()
            .len()
            <= 262_144
    );
    assert!(
        serde_json::to_vec(summary.stderr.as_deref().unwrap())
            .unwrap()
            .len()
            <= 262_144
    );
}

#[cfg(unix)]
#[tokio::test]
async fn armed_hold_expires_across_restart_without_execution() {
    let (mut cfg, operator, agent) = gating_config(7_043, 1_000);
    cfg.config.approval_ttl_secs = 0;
    let state = tempfile::tempdir().unwrap();
    let marker = state.path().join("must-not-run");
    let store = SessionStore::open(state.path().join("state.db"), 3_600)
        .await
        .unwrap();
    cfg.state.session_store = Some(store.clone());
    let request = held_request("touch", vec![marker.display().to_string()], None);
    let mut sink = tokio::io::sink();
    let held = hold_for_approval_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        agent.principal(),
        GateInputs {
            reason: "expiring hold".to_string(),
            risk: Some(9),
            reversibility: Some(Reversibility::Irreversible),
            revert_preauthorized: false,
            verb: None,
            bypass: false,
            authority: None,
            consume_access_verbs: Vec::new(),
        },
    )
    .await;
    let ExecOutcome::Held { handle, .. } = held.exec else {
        panic!("expected held command")
    };
    let _ = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::AccessApprove {
            handles: vec![handle.clone()],
            uses: Some(1),
            wait_secs: None,
        },
    )
    .await;
    let rows = store.load_approvals().await.unwrap();
    let (registry, recovered) =
        guard::gating::approval::ApprovalRegistry::from_rows(rows, now_unix());
    assert!(recovered.is_empty());
    let (mut restarted, _operator, requester) = gating_config(7_043, 1_000);
    restarted.state.session_store = Some(store.clone());
    *restarted.state.approvals.write().await = registry;
    let response = handle_admin_request_for_test(
        &restarted,
        &requester,
        AdminRequest::Resume {
            handle: handle.clone(),
        },
    )
    .await;
    assert!(matches!(response, AdminResponse::Error { .. }));
    assert!(!marker.exists());
    let durable = store.load_approvals().await.unwrap();
    assert_eq!(
        durable
            .iter()
            .find(|row| row.handle == handle)
            .unwrap()
            .status,
        ApprovalStatus::Expired
    );
}

#[tokio::test]
async fn access_projection_excludes_and_rejects_legacy_sessions() {
    let (cfg, operator, agent) = gating_config(7_005, 1_000);
    let mut legacy = active_session();
    legacy.scope.label = Some("legacy-access-projection".to_string());
    let mut managed = active_session();
    managed.scope.access_managed = true;
    managed.scope.label = Some("managed-access-projection".to_string());
    {
        let mut sessions = cfg.state.sessions.write().await;
        sessions.grant("legacy-access-projection".to_string(), legacy);
        sessions.grant("managed-access-projection".to_string(), managed);
    }

    let AdminResponse::AccessItems { items } =
        handle_admin_request_for_test(&cfg, &agent, AdminRequest::AccessList).await
    else {
        panic!("expected access list")
    };
    assert!(items.iter().any(
        |item| item.reference == crate::session::session_reference("managed-access-projection")
    ));
    assert!(!items.iter().any(
        |item| item.reference == crate::session::session_reference("legacy-access-projection")
    ));

    assert!(matches!(
        handle_admin_request_for_test(
            &cfg,
            &operator,
            AdminRequest::AccessShow {
                reference: crate::session::session_reference("legacy-access-projection"),
            },
        )
        .await,
        AdminResponse::Error { .. }
    ));
    let AdminResponse::AccessItem { item } = handle_admin_request_for_test(
        &cfg,
        &agent,
        AdminRequest::AccessShow {
            reference: crate::session::session_reference("managed-access-projection"),
        },
    )
    .await
    else {
        panic!("expected access-managed session")
    };
    assert_eq!(item.kind, "session");

    let AdminResponse::SessionStatus { report, .. } = handle_admin_request_for_test(
        &cfg,
        &agent,
        AdminRequest::AccessStatus {
            reference: crate::session::session_reference("managed-access-projection"),
        },
    )
    .await
    else {
        panic!("expected access-managed session status")
    };
    assert_eq!(
        report.active.as_ref().map(|active| active.token.as_str()),
        Some("(current)")
    );
    assert!(matches!(
        handle_admin_request_for_test(
            &cfg,
            &operator,
            AdminRequest::AccessStatus {
                reference: crate::session::session_reference("legacy-access-projection"),
            },
        )
        .await,
        AdminResponse::Error { .. }
    ));
}

#[tokio::test]
async fn held_access_projection_expires_before_the_sweeper_and_hides_approval_options() {
    let (cfg, _, agent) = gating_config(7_006, 1_001);
    let handle = "held-access-projection".to_string();
    let principal = PrincipalKey::from_uid(1_001);
    cfg.state.approvals.write().await.enqueue(Approval {
        handle: handle.clone(),
        snapshot: ApprovalSnapshot {
            binary: "true".to_string(),
            args: Vec::new(),
            cwd: None,
            env: BTreeMap::new(),
            secret_keys: BTreeMap::new(),
            session_fingerprint: None,
            session_revision: None,
            secret_entitlements: None,
            secret_file_keys: BTreeMap::new(),
            verb_name: None,
            verb_params: BTreeMap::new(),
            catalog_version: None,
            verb_digest: None,
            verb_composition_digest: None,
            access_verbs: Vec::new(),
            access_requests: Vec::new(),
            principal: Some(principal),
            secret_binding: None,
        },
        reason: "held access projection test".to_string(),
        risk: None,
        reversibility: None,
        decision_trace: None,
        created_unix: 0,
        ttl_secs: 0,
        status: ApprovalStatus::Pending,
        decided_unix: None,
        decided_reason: None,
        result_exit: None,
        result_stdout: None,
        result_stderr: None,
        notes: Vec::new(),
    });

    let AdminResponse::AccessItems { items } =
        handle_admin_request_for_test(&cfg, &agent, AdminRequest::AccessList).await
    else {
        panic!("expected access list")
    };
    let listed = items
        .iter()
        .find(|item| item.reference == handle)
        .expect("held access request remains visible before the sweeper");
    assert_eq!(listed.state, "expired");
    assert!(listed.approval_options.is_empty());
    // An expired hold has no active grant budget.
    assert_eq!(listed.use_policy, "unavailable");
    assert_eq!(listed.kind, "hold");
    assert_eq!(listed.consequence, CONSEQUENCE_ARM);

    let AdminResponse::AccessItem { item: shown } = handle_admin_request_for_test(
        &cfg,
        &agent,
        AdminRequest::AccessShow {
            reference: handle.clone(),
        },
    )
    .await
    else {
        panic!("expected held access show")
    };
    assert_eq!(shown.state, "expired");
    assert!(shown.approval_options.is_empty());
    assert_eq!(
        cfg.state
            .approvals
            .read()
            .await
            .get(&handle)
            .unwrap()
            .status,
        ApprovalStatus::Pending,
        "projection must not mutate the held row before the sweeper"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn held_snapshot_consumes_its_originating_once_authority() {
    let (cfg, operator, agent) = gating_config(7_025, 1_000);
    cfg.state.sessions.write().await.grant(
        "access-token".to_string(),
        SessionGrant {
            allow: Vec::new(),
            deny: Vec::new(),
            allow_exact: Vec::new(),
            deny_exact: Vec::new(),
            activated_verbs: vec!["inspect-fixture".to_string()],
            override_markers: Vec::new(),
            scope: IssuedGrantScope {
                label: Some("agent:1000".to_string()),
                access_managed: true,
                access_grants: vec![AccessUseGrant {
                    request: "gr-origin".to_string(),
                    verbs: vec!["inspect-fixture".to_string()],
                    use_limit: Some(1),
                    remaining_uses: Some(1),
                    pending: false,
                }],
                ..IssuedGrantScope::default()
            },
            expires_at: Some(now_unix().saturating_add(60)),
            prompt_append: None,
            generated_notes: Vec::new(),
            static_only: true,
            auto_amend: false,
            granted_at: now_unix(),
            owner: SessionOwner::Principal(PrincipalKey::from_uid(1_000)),
        },
    );
    let authority = live_authority(&cfg, "access-token").await;
    let request = ExecuteRequest {
        binary: "true".to_string(),
        args: Vec::new(),
        auth_token: None,
        env: HashMap::new(),
        secrets: HashMap::new(),
        secret_files: HashMap::new(),
        stream: false,
        session_token: Some("access-token".to_string()),
        revert: None,
        confirm_within_secs: None,
        reevaluate: false,
        ssh_hostkey: None,
        cwd: None,
        require_approval: None,
        wait_approval_secs: None,
        verb: None,
    };
    let mut sink = tokio::io::sink();
    let held = hold_for_approval_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        agent.principal(),
        GateInputs {
            reason: "operator review required".to_string(),
            risk: Some(8),
            reversibility: Some(Reversibility::Irreversible),
            revert_preauthorized: false,
            verb: None,
            bypass: false,
            authority,
            consume_access_verbs: vec!["inspect-fixture".to_string()],
        },
    )
    .await;
    let handle = match held.exec {
        ExecOutcome::Held { handle, .. } => handle,
        other => panic!("expected Held, got {other:?}"),
    };
    assert_eq!(
        cfg.state
            .approvals
            .read()
            .await
            .get(&handle)
            .expect("held request remains registered")
            .snapshot
            .access_verbs,
        vec!["inspect-fixture".to_string()]
    );
    assert_eq!(
        cfg.state
            .approvals
            .read()
            .await
            .get(&handle)
            .expect("held request remains registered")
            .snapshot
            .access_requests,
        vec!["gr-origin".to_string()]
    );

    let AdminResponse::AccessDecisions { items, .. } = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::AccessApprove {
            handles: vec![handle.clone()],
            uses: Some(1),
            wait_secs: None,
        },
    )
    .await
    else {
        panic!("expected held access decision")
    };
    assert!(items[0].success, "approval failed: {:?}", items[0]);
    assert_eq!(items[0].state, "armed");
    assert_eq!(items[0].remaining_uses, Some(1));
    let resumed = resume_approval(&cfg, &agent, &handle).await;
    assert!(matches!(resumed.exec, ExecOutcome::Completed { .. }));
    let AdminResponse::AccessDecisions { items: replay, .. } = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::AccessApprove {
            handles: vec![handle.clone()],
            uses: Some(1),
            wait_secs: None,
        },
    )
    .await
    else {
        panic!("expected terminal held replay decision")
    };
    assert!(!replay[0].success);
    assert_eq!(replay[0].state, "approved");
    assert!(replay[0].message.contains("already approved"));
    assert_eq!(
        cfg.state
            .sessions
            .read()
            .await
            .access_grant_uses("access-token", "gr-origin"),
        Some((Some(1), Some(0)))
    );
    assert_eq!(
        cfg.state.sessions.write().await.consume_access_use(
            "access-token",
            &["inspect-fixture".to_string()],
            None
        ),
        Err("access use limit is exhausted".to_string())
    );
}

#[cfg(unix)]
#[tokio::test]
async fn held_snapshot_does_not_fall_through_to_overlapping_authority() {
    let (cfg, operator, agent) = gating_config(7_026, 1_000);
    cfg.state.sessions.write().await.grant(
        "access-token".to_string(),
        SessionGrant {
            allow: Vec::new(),
            deny: Vec::new(),
            allow_exact: Vec::new(),
            deny_exact: Vec::new(),
            activated_verbs: vec!["inspect-fixture".to_string(), "operate-fixture".to_string()],
            override_markers: Vec::new(),
            scope: IssuedGrantScope {
                label: Some("agent:1000".to_string()),
                access_managed: true,
                access_grants: vec![
                    AccessUseGrant {
                        request: "a-origin".to_string(),
                        verbs: vec!["inspect-fixture".to_string(), "operate-fixture".to_string()],
                        use_limit: Some(1),
                        remaining_uses: Some(1),
                        pending: false,
                    },
                    AccessUseGrant {
                        request: "b-overlap-unbounded".to_string(),
                        verbs: vec!["inspect-fixture".to_string()],
                        use_limit: None,
                        remaining_uses: None,
                        pending: false,
                    },
                    AccessUseGrant {
                        request: "c-overlap-bounded".to_string(),
                        verbs: vec!["operate-fixture".to_string()],
                        use_limit: Some(1),
                        remaining_uses: Some(1),
                        pending: false,
                    },
                ],
                ..IssuedGrantScope::default()
            },
            expires_at: Some(now_unix().saturating_add(60)),
            prompt_append: None,
            generated_notes: Vec::new(),
            static_only: true,
            auto_amend: false,
            granted_at: now_unix(),
            owner: SessionOwner::Principal(PrincipalKey::from_uid(1_000)),
        },
    );
    let selected_verbs = vec!["inspect-fixture".to_string(), "operate-fixture".to_string()];
    let request = ExecuteRequest {
        binary: "true".to_string(),
        args: Vec::new(),
        auth_token: None,
        env: HashMap::new(),
        secrets: HashMap::new(),
        secret_files: HashMap::new(),
        stream: false,
        session_token: Some("access-token".to_string()),
        revert: None,
        confirm_within_secs: None,
        reevaluate: false,
        ssh_hostkey: None,
        cwd: None,
        require_approval: None,
        wait_approval_secs: None,
        verb: None,
    };
    let mut sink = tokio::io::sink();
    let held = hold_for_approval_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        agent.principal(),
        GateInputs {
            reason: "operator review required".to_string(),
            risk: Some(8),
            reversibility: Some(Reversibility::Irreversible),
            revert_preauthorized: false,
            verb: None,
            bypass: false,
            authority: live_authority(&cfg, "access-token").await,
            consume_access_verbs: selected_verbs.clone(),
        },
    )
    .await;
    let handle = match held.exec {
        ExecOutcome::Held { handle, .. } => handle,
        other => panic!("expected Held, got {other:?}"),
    };
    assert_eq!(
        cfg.state
            .approvals
            .read()
            .await
            .get(&handle)
            .expect("held request")
            .snapshot
            .access_requests,
        vec!["a-origin".to_string()]
    );

    let origin = vec!["a-origin".to_string()];
    cfg.state
        .sessions
        .write()
        .await
        .consume_access_use("access-token", &selected_verbs, Some(&origin))
        .expect("consume the bound origin before approval");
    let AdminResponse::AccessDecisions { items, .. } = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::AccessApprove {
            handles: vec![handle.clone()],
            uses: Some(1),
            wait_secs: None,
        },
    )
    .await
    else {
        panic!("expected held access decision")
    };
    assert!(items[0].success);
    assert_eq!(items[0].state, "armed");
    let resumed = resume_approval(&cfg, &agent, &handle).await;
    assert!(matches!(
        resumed.exec,
        ExecOutcome::Failed { ref reason, .. }
            if reason.contains("access use limit is exhausted")
    ));
    assert_eq!(
        cfg.state
            .sessions
            .read()
            .await
            .access_grant_uses("access-token", "c-overlap-bounded"),
        Some((Some(1), Some(1)))
    );
}

#[cfg(unix)]
#[tokio::test]
async fn held_snapshot_binds_and_consumes_multiple_originating_requests() {
    let (cfg, operator, agent) = gating_config(7_027, 1_000);
    cfg.state.sessions.write().await.grant(
        "access-token".to_string(),
        SessionGrant {
            allow: Vec::new(),
            deny: Vec::new(),
            allow_exact: Vec::new(),
            deny_exact: Vec::new(),
            activated_verbs: vec!["inspect-fixture".to_string(), "operate-fixture".to_string()],
            override_markers: Vec::new(),
            scope: IssuedGrantScope {
                label: Some("agent:1000".to_string()),
                access_managed: true,
                access_grants: vec![
                    AccessUseGrant {
                        request: "request-a".to_string(),
                        verbs: vec!["inspect-fixture".to_string()],
                        use_limit: Some(1),
                        remaining_uses: Some(1),
                        pending: false,
                    },
                    AccessUseGrant {
                        request: "request-b".to_string(),
                        verbs: vec!["operate-fixture".to_string()],
                        use_limit: Some(1),
                        remaining_uses: Some(1),
                        pending: false,
                    },
                ],
                ..IssuedGrantScope::default()
            },
            expires_at: Some(now_unix().saturating_add(60)),
            prompt_append: None,
            generated_notes: Vec::new(),
            static_only: true,
            auto_amend: false,
            granted_at: now_unix(),
            owner: SessionOwner::Principal(PrincipalKey::from_uid(1_000)),
        },
    );
    let selected_verbs = vec!["inspect-fixture".to_string(), "operate-fixture".to_string()];
    let request = ExecuteRequest {
        binary: "true".to_string(),
        args: Vec::new(),
        auth_token: None,
        env: HashMap::new(),
        secrets: HashMap::new(),
        secret_files: HashMap::new(),
        stream: false,
        session_token: Some("access-token".to_string()),
        revert: None,
        confirm_within_secs: None,
        reevaluate: false,
        ssh_hostkey: None,
        cwd: None,
        require_approval: None,
        wait_approval_secs: None,
        verb: None,
    };
    let mut sink = tokio::io::sink();
    let held = hold_for_approval_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        agent.principal(),
        GateInputs {
            reason: "operator review required".to_string(),
            risk: Some(8),
            reversibility: Some(Reversibility::Irreversible),
            revert_preauthorized: false,
            verb: None,
            bypass: false,
            authority: live_authority(&cfg, "access-token").await,
            consume_access_verbs: selected_verbs,
        },
    )
    .await;
    let handle = match held.exec {
        ExecOutcome::Held { handle, .. } => handle,
        other => panic!("expected Held, got {other:?}"),
    };
    assert_eq!(
        cfg.state
            .approvals
            .read()
            .await
            .get(&handle)
            .expect("held request")
            .snapshot
            .access_requests,
        vec!["request-a".to_string(), "request-b".to_string()]
    );

    let AdminResponse::AccessDecisions { items, .. } = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::AccessApprove {
            handles: vec![handle.clone()],
            uses: Some(1),
            wait_secs: None,
        },
    )
    .await
    else {
        panic!("expected held access decision")
    };
    assert!(items[0].success, "approval failed: {:?}", items[0]);
    assert_eq!(items[0].state, "armed");
    let resumed = resume_approval(&cfg, &agent, &handle).await;
    assert!(matches!(resumed.exec, ExecOutcome::Completed { .. }));
    assert_eq!(
        cfg.state
            .sessions
            .read()
            .await
            .access_grant_uses("access-token", "request-a"),
        Some((Some(1), Some(0)))
    );
    assert_eq!(
        cfg.state
            .sessions
            .read()
            .await
            .access_grant_uses("access-token", "request-b"),
        Some((Some(1), Some(0)))
    );
}

#[cfg(unix)]
#[tokio::test]
async fn exhausted_multi_verb_hold_requests_every_required_scope() {
    let (mut cfg, _operator, agent) = gating_config(7_028, 1_000);
    cfg.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            "verbs:\n  - name: inspect-fixture\n    description: Inspect fixture\n    binary: true\n    args: []\n    baseline: false\n    consequence: irreversible\n    trusted: true\n  - name: operate-fixture\n    description: Operate fixture\n    binary: true\n    args: []\n    baseline: false\n    consequence: irreversible\n    trusted: true\n",
        )
        .expect("load fixture verbs"),
    ));
    cfg.state.sessions.write().await.grant(
        "access-token".to_string(),
        SessionGrant {
            allow: Vec::new(),
            deny: Vec::new(),
            allow_exact: Vec::new(),
            deny_exact: Vec::new(),
            activated_verbs: vec!["inspect-fixture".to_string(), "operate-fixture".to_string()],
            override_markers: Vec::new(),
            scope: IssuedGrantScope {
                label: Some("agent:1000".to_string()),
                access_managed: true,
                access_grants: vec![
                    AccessUseGrant {
                        request: "exhausted-inspect".to_string(),
                        verbs: vec!["inspect-fixture".to_string()],
                        use_limit: Some(1),
                        remaining_uses: Some(0),
                        pending: false,
                    },
                    AccessUseGrant {
                        request: "exhausted-operate".to_string(),
                        verbs: vec!["operate-fixture".to_string()],
                        use_limit: Some(1),
                        remaining_uses: Some(0),
                        pending: false,
                    },
                ],
                ..IssuedGrantScope::default()
            },
            expires_at: Some(now_unix().saturating_add(60)),
            prompt_append: None,
            generated_notes: Vec::new(),
            static_only: true,
            auto_amend: false,
            granted_at: now_unix(),
            owner: SessionOwner::Principal(PrincipalKey::from_uid(1_000)),
        },
    );
    let request = ExecuteRequest {
        binary: "true".to_string(),
        args: Vec::new(),
        auth_token: None,
        env: HashMap::new(),
        secrets: HashMap::new(),
        secret_files: HashMap::new(),
        stream: false,
        session_token: Some("access-token".to_string()),
        revert: None,
        confirm_within_secs: None,
        reevaluate: false,
        ssh_hostkey: None,
        cwd: None,
        require_approval: None,
        wait_approval_secs: None,
        verb: None,
    };
    let selected_verbs = vec!["inspect-fixture".to_string(), "operate-fixture".to_string()];
    let mut sink = tokio::io::sink();
    let result = hold_for_approval_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        agent.principal(),
        GateInputs {
            reason: "operator review required".to_string(),
            risk: Some(8),
            reversibility: Some(Reversibility::Irreversible),
            revert_preauthorized: false,
            verb: None,
            bypass: false,
            authority: live_authority(&cfg, "access-token").await,
            consume_access_verbs: selected_verbs.clone(),
        },
    )
    .await;

    assert!(matches!(&result.exec, ExecOutcome::NotAttempted));
    let mut requests = cfg
        .state
        .grant_requests
        .read()
        .await
        .values()
        .map(|request| {
            (
                request.handle.clone(),
                request.delta.activated_verbs.clone(),
            )
        })
        .collect::<Vec<_>>();
    requests.sort_by(|left, right| left.0.cmp(&right.0));
    assert_eq!(requests.len(), 2);
    let mut requested_verbs = requests
        .iter()
        .flat_map(|(_, verbs)| verbs.iter().cloned())
        .collect::<Vec<_>>();
    requested_verbs.sort();
    assert_eq!(requested_verbs, selected_verbs);
    let handles = requests
        .iter()
        .map(|(handle, _)| handle.clone())
        .collect::<Vec<_>>();
    let response = result.into_response();
    let guidance = response
        .verb_guidance
        .expect("requester-safe approval guidance");
    for handle in &handles {
        assert!(guidance.contains(&format!(
            "ask your admin to approve request {handle} (see guard access show {handle})"
        )));
    }
    assert!(!guidance.contains("guard access approve"));
    assert!(response.handle.is_none());
    assert!(response.approval_options.is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn held_access_replay_fails_if_staged_session_was_revoked() {
    let (cfg, _operator, agent) = gating_config(7006, 1000);
    let snapshot = ApprovalSnapshot {
        binary: "true".to_string(),
        args: Vec::new(),
        cwd: None,
        env: std::collections::BTreeMap::new(),
        secret_keys: std::collections::BTreeMap::new(),
        secret_file_keys: std::collections::BTreeMap::new(),
        secret_binding: None,
        principal: agent.principal(),
        session_fingerprint: None,
        session_revision: None,
        secret_entitlements: Some(Vec::new()),
        verb_name: None,
        verb_params: std::collections::BTreeMap::new(),
        catalog_version: None,
        verb_digest: None,
        verb_composition_digest: None,
        access_verbs: Vec::new(),
        access_requests: Vec::new(),
    };
    let access_requests = vec!["held-request".to_string()];
    let result = super::super::gate_runtime::execute_snapshot_with_access_request(
        &cfg,
        &snapshot,
        "operator approved",
        Some(&access_requests),
    )
    .await;
    assert!(matches!(
        result.exec,
        ExecOutcome::Failed {
            started: false,
            ref reason
        } if reason.contains("expired or was revoked")
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn approval_rejects_tool_secret_rotated_after_hold() {
    let (cfg, operator, agent) = gating_config(7023, 1000);
    let principal = agent.principal().unwrap();
    cfg.state
        .secrets
        .set(&principal, "broker/token", "held-value")
        .await
        .unwrap();
    let tools = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        tools.path(),
        "tools:\n  true:\n    secrets:\n      BROKER_TOKEN: broker/token\n",
    )
    .unwrap();
    *cfg.state.tool_registry.write().await =
        crate::tool_config::ToolRegistry::load(tools.path()).unwrap();
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
    let mut sink = tokio::io::sink();
    let held = hold_for_approval_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        Some(principal.clone()),
        GateInputs {
            reason: "tool secret hold".to_string(),
            risk: Some(9),
            reversibility: Some(Reversibility::Irreversible),
            revert_preauthorized: false,
            verb: None,
            bypass: false,
            authority: None,
            consume_access_verbs: Vec::new(),
        },
    )
    .await;
    let ExecOutcome::Held { handle, .. } = held.exec else {
        panic!("expected held command")
    };
    let snapshot = cfg
        .state
        .approvals
        .read()
        .await
        .get(&handle)
        .unwrap()
        .snapshot
        .clone();
    let binding = snapshot.secret_binding.as_ref().unwrap();
    let tool_binding = binding
        .tool_hashes
        .as_ref()
        .unwrap()
        .get("BROKER_TOKEN")
        .unwrap();
    assert_eq!(tool_binding.secret_name, "broker/token");

    let mut legacy_snapshot = snapshot.clone();
    legacy_snapshot.secret_binding = None;
    let legacy_result = execute_snapshot(&cfg, &legacy_snapshot, "operator approved").await;
    assert!(matches!(
        legacy_result.exec,
        ExecOutcome::Failed { started: false, ref reason }
            if reason.contains("secrets were not bound")
    ));

    std::fs::write(
        tools.path(),
        "tools:\n  true:\n    secrets:\n      RENAMED_TOKEN: broker/token\n",
    )
    .unwrap();
    *cfg.state.tool_registry.write().await =
        crate::tool_config::ToolRegistry::load(tools.path()).unwrap();
    let remapped_result = execute_snapshot(&cfg, &snapshot, "operator approved").await;
    assert!(matches!(
        remapped_result.exec,
        ExecOutcome::Failed { started: false, ref reason }
            if reason.contains("tool secret mappings changed")
    ));

    std::fs::write(
        tools.path(),
        "tools:\n  true:\n    secrets:\n      BROKER_TOKEN: broker/token\n",
    )
    .unwrap();
    *cfg.state.tool_registry.write().await =
        crate::tool_config::ToolRegistry::load(tools.path()).unwrap();
    cfg.state
        .secrets
        .set(&principal, "broker/token", "rotated-value")
        .await
        .unwrap();
    let response = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::AccessApprove {
            handles: vec![handle.clone()],
            uses: Some(1),
            wait_secs: None,
        },
    )
    .await;
    let AdminResponse::AccessDecisions { items, .. } = response else {
        panic!("expected access decision result")
    };
    assert!(items[0].success);
    assert_eq!(items[0].state, "armed");
    let resumed = resume_approval(&cfg, &agent, &handle).await;
    assert!(matches!(
        resumed.exec,
        ExecOutcome::Failed { ref reason, .. }
            if reason.contains("tool-configured secret value changed")
    ));
    let approval = cfg
        .state
        .approvals
        .read()
        .await
        .get(&handle)
        .cloned()
        .unwrap();
    assert_eq!(approval.status, ApprovalStatus::ExecFailed);
    assert!(approval
        .decided_reason
        .as_deref()
        .unwrap_or_default()
        .contains("tool-configured secret value changed"));
    assert!(
        cfg.state
            .sessions
            .read()
            .await
            .access_token_for_principal(&principal)
            .is_none(),
        "a pre-admission rejection must not leave an access session"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn hold_is_not_returned_until_its_pending_state_is_durable() {
    let (mut cfg, _operator, agent) = gating_config(7006, 1000);
    let state = tempfile::tempdir().unwrap();
    cfg.state.session_store = Some(
        crate::session_store::SessionStore::open(state.path().join("state.db"), 3600)
            .await
            .unwrap(),
    );
    cfg.state
        .session_store
        .as_ref()
        .unwrap()
        .fail_next_write_for_test();
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
    let mut sink = tokio::io::sink();
    let result = hold_for_approval_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        agent.principal(),
        GateInputs {
            reason: "needs sign-off".to_string(),
            risk: Some(9),
            reversibility: Some(Reversibility::Irreversible),
            revert_preauthorized: false,
            verb: None,
            bypass: false,
            authority: None,
            consume_access_verbs: Vec::new(),
        },
    )
    .await;
    assert!(matches!(
        result.exec,
        ExecOutcome::Failed {
            started: false,
            ref reason
        } if reason.contains("failed to persist approval")
    ));
    assert!(cfg.state.approvals.read().await.list().is_empty());
    assert!(cfg
        .state
        .session_store
        .as_ref()
        .unwrap()
        .load_approvals()
        .await
        .unwrap()
        .is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn approval_state_must_be_durable_before_a_held_snapshot_executes() {
    let (mut cfg, operator, agent) = gating_config(7006, 1000);
    let state = tempfile::tempdir().unwrap();
    cfg.state.session_store = Some(
        crate::session_store::SessionStore::open(state.path().join("state.db"), 3600)
            .await
            .unwrap(),
    );
    let output = state.path().join("must-not-exist");
    let request = ExecuteRequest {
        binary: "touch".to_string(),
        args: vec![output.display().to_string()],
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
    let mut sink = tokio::io::sink();
    let held = hold_for_approval_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        agent.principal(),
        GateInputs {
            reason: "needs sign-off".to_string(),
            risk: Some(9),
            reversibility: Some(Reversibility::Irreversible),
            revert_preauthorized: false,
            verb: None,
            bypass: false,
            authority: None,
            consume_access_verbs: Vec::new(),
        },
    )
    .await;
    let ExecOutcome::Held { handle, .. } = held.exec else {
        panic!("expected held command")
    };
    cfg.state
        .session_store
        .as_ref()
        .unwrap()
        .fail_next_write_for_test();
    let AdminResponse::AccessDecisions { items, .. } = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::AccessApprove {
            handles: vec![handle.clone()],
            uses: Some(1),
            wait_secs: None,
        },
    )
    .await
    else {
        panic!("expected access decision")
    };
    assert!(!items[0].success);
    assert!(items[0]
        .message
        .contains("failed to persist terminal approval"));
    assert!(
        !output.exists(),
        "the held snapshot executed without durable admission"
    );
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
    let durable = cfg
        .state
        .session_store
        .as_ref()
        .unwrap()
        .load_approvals()
        .await
        .unwrap();
    assert_eq!(durable[0].status, ApprovalStatus::Pending);
}

async fn pending_hold_after(cfg: &ServerContext, lifecycle: &ApprovalLifecycleTestHook) -> String {
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        lifecycle.enqueued.acquire(),
    )
    .await
    .expect("hold publication completes")
    .unwrap()
    .forget();
    cfg.state
        .approvals
        .read()
        .await
        .list()
        .into_iter()
        .find(|approval| approval.status == ApprovalStatus::Pending)
        .expect("pending hold was published")
        .handle
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
        server: cfg.clone(),
        endpoint: "default".to_string(),
        protocol: "kubernetes".to_string(),
        snapshot_dir: std::env::temp_dir(),
        snapshot_dir_safe: true,
        window_secs: 60,
    });

    // Approve: the waiter returns Approved with the queue handle; the row is
    // Approved and carries no exec result (nothing ran).
    let lifecycle = observe_approval_lifecycle_for_test(&cfg);
    let s = sink.clone();
    let waiter = tokio::spawn(async move {
        let context = guard::proxy::ApiSessionContext {
            fingerprint: "session-fingerprint".to_string(),
            revision: "session-revision".to_string(),
            secret_entitlements: Some(vec!["cluster/token".to_string()]),
            intent: Some("inspect the cluster".to_string()),
            evaluation_mode: guard::proxy::ApiEvaluationMode::Evaluator,
            can_evaluate_api_override: true,
        };
        let snapshot = guard::proxy::ApiHoldSnapshot {
            label: "delete namespaces/prod".to_string(),
            body_sha256: "body-digest".to_string(),
            redacted_body_shape: "(no body)".to_string(),
            redacted_query: String::new(),
            authority_selectors: Default::default(),
        };
        guard::proxy::GateSink::hold_request(&*s, &snapshot, "namespace delete", Some(&context))
            .await
    });
    lifecycle.enqueued.acquire().await.unwrap().forget();
    let handle = cfg
        .state
        .approvals
        .read()
        .await
        .list()
        .into_iter()
        .find(|approval| approval.status == ApprovalStatus::Pending)
        .expect("pending hold was published")
        .handle;
    assert_eq!(
        cfg.state
            .approvals
            .read()
            .await
            .get(&handle)
            .unwrap()
            .snapshot
            .session_fingerprint
            .as_deref(),
        Some("session-fingerprint")
    );
    assert_eq!(
        cfg.state
            .approvals
            .read()
            .await
            .get(&handle)
            .unwrap()
            .snapshot
            .session_revision
            .as_deref(),
        Some("session-revision")
    );
    let resp = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::AccessApprove {
            handles: vec![handle.clone()],
            uses: Some(1),
            wait_secs: None,
        },
    )
    .await;
    match resp {
        AdminResponse::AccessDecisions { items, .. } => {
            assert!(items[0].success, "got: {:?}", items[0]);
            assert!(items[0].message.contains("forwarding"));
            assert_eq!(items[0].remaining_uses, None);
        }
        other => panic!("operator approve should release the hold, got {:?}", other),
    }
    match waiter.await.unwrap() {
        guard::proxy::HoldDecision::Approved { handle: h } => assert_eq!(h, handle),
        other => panic!("expected Approved, got {:?}", other),
    }
    assert_eq!(
        cfg.state
            .approvals
            .read()
            .await
            .get(&handle)
            .unwrap()
            .status,
        ApprovalStatus::Approved
    );
    assert!(
        cfg.state
            .sessions
            .read()
            .await
            .access_token_for_principal(&cfg.config.daemon_principal)
            .is_none(),
        "approving an API hold must not create reusable daemon-principal authority"
    );

    // Deny: the waiter fails closed with the operator's reason.
    let lifecycle = observe_approval_lifecycle_for_test(&cfg);
    let s = sink.clone();
    let waiter = tokio::spawn(async move {
        let snapshot = guard::proxy::ApiHoldSnapshot {
            label: "delete namespaces/prod".to_string(),
            body_sha256: "body-digest".to_string(),
            redacted_body_shape: "(no body)".to_string(),
            redacted_query: String::new(),
            authority_selectors: Default::default(),
        };
        guard::proxy::GateSink::hold_request(&*s, &snapshot, "namespace delete", None).await
    });
    lifecycle.enqueued.acquire().await.unwrap().forget();
    let handle = cfg
        .state
        .approvals
        .read()
        .await
        .list()
        .into_iter()
        .find(|approval| approval.status == ApprovalStatus::Pending)
        .expect("pending hold was published")
        .handle;
    let resp = handle_admin_request_for_test(
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
        cfg.state
            .approvals
            .read()
            .await
            .get(&handle)
            .unwrap()
            .status,
        ApprovalStatus::Denied
    );

    // Disconnect: dropping the waiter mid-hold retires the pending row.
    let lifecycle = observe_approval_lifecycle_for_test(&cfg);
    let s = sink.clone();
    let waiter = tokio::spawn(async move {
        let snapshot = guard::proxy::ApiHoldSnapshot {
            label: "delete namespaces/prod".to_string(),
            body_sha256: "body-digest".to_string(),
            redacted_body_shape: "(no body)".to_string(),
            redacted_query: String::new(),
            authority_selectors: Default::default(),
        };
        guard::proxy::GateSink::hold_request(&*s, &snapshot, "namespace delete", None).await
    });
    lifecycle.enqueued.acquire().await.unwrap().forget();
    let handle = cfg
        .state
        .approvals
        .read()
        .await
        .list()
        .into_iter()
        .find(|approval| approval.status == ApprovalStatus::Pending)
        .expect("pending hold was published")
        .handle;
    waiter.abort();
    lifecycle.retired.acquire().await.unwrap().forget();
    assert_eq!(
        cfg.state
            .approvals
            .read()
            .await
            .get(&handle)
            .unwrap()
            .status,
        ApprovalStatus::ExecFailed
    );
}

/// A non-streaming `--wait-approval` waiter must return as soon as the
/// operator decides, not park until its timeout: the waiter registers with
/// the notifier before checking status, so a decision landing in the gap
/// still completes the park immediately.
#[tokio::test]
async fn nonstreaming_wait_approval_returns_promptly_on_decision() {
    let (mut cfg, _operator, agent) = gating_config(7014, 1000);
    let state = tempfile::tempdir().unwrap();
    let store = crate::session_store::SessionStore::open(state.path().join("state.db"), 3_600)
        .await
        .unwrap();
    cfg.state.session_store = Some(store.clone());
    let agent_principal = agent.principal();

    let request = ExecuteRequest {
        binary: "rm".to_string(),
        args: vec!["-rf".to_string(), "/data".to_string()],
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
        wait_approval_secs: Some(30),
        verb: None,
    };
    let lifecycle = observe_approval_lifecycle_for_test(&cfg);
    let cfg2 = cfg.clone();
    let waiter = tokio::spawn(async move {
        let mut sink = tokio::io::sink();
        hold_for_approval_with_trace(
            &mut RequestContext {
                server: &cfg2,
                caller: &agent,
                depth: 0,
                stream_output: false,
                stream_writer: &mut sink,
            },
            request,
            agent_principal,
            GateInputs {
                reason: "destructive".to_string(),
                risk: Some(10),
                reversibility: Some(Reversibility::Irreversible),
                revert_preauthorized: false,
                verb: None,
                bypass: false,
                authority: None,
                consume_access_verbs: Vec::new(),
            },
            Some(guard::gating::DecisionTrace::source("static_policy")),
        )
        .await
    });

    let handle = pending_hold_after(&cfg, &lifecycle).await;
    let denied = {
        let mut reg = cfg.state.approvals.write().await;
        reg.deny(&handle, now_unix(), "operator rejected".to_string())
            .unwrap();
        reg.get(&handle).cloned().unwrap()
    };
    store.save_approval(denied).await.unwrap();

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
    let durable = store.load_approvals().await.unwrap();
    assert_eq!(durable[0].status, ApprovalStatus::Denied);
    assert_eq!(
        durable[0]
            .decision_trace
            .as_ref()
            .map(|trace| trace.decision_source.as_str()),
        Some("static_policy")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn waiting_requester_resumes_armed_hold_and_receives_terminal_output() {
    let (mut cfg, operator, agent) = gating_config(7_044, 1_000);
    let state = tempfile::tempdir().unwrap();
    let store = SessionStore::open(state.path().join("state.db"), 3_600)
        .await
        .unwrap();
    cfg.state.session_store = Some(store.clone());
    let request = held_request(
        "sh",
        vec![
            "-c".to_string(),
            "printf waiting-stdout; printf waiting-stderr >&2; exit 9".to_string(),
        ],
        Some(30),
    );
    let lifecycle = observe_approval_lifecycle_for_test(&cfg);
    let cfg_for_waiter = cfg.clone();
    let waiter = tokio::spawn(async move {
        let mut sink = tokio::io::sink();
        hold_for_approval_with_trace(
            &mut RequestContext {
                server: &cfg_for_waiter,
                caller: &agent,
                depth: 0,
                stream_output: false,
                stream_writer: &mut sink,
            },
            request,
            agent.principal(),
            GateInputs {
                reason: "wait for requester resume".to_string(),
                risk: Some(9),
                reversibility: Some(Reversibility::Irreversible),
                revert_preauthorized: false,
                verb: None,
                bypass: false,
                authority: None,
                consume_access_verbs: Vec::new(),
            },
            None,
        )
        .await
    });
    let handle = pending_hold_after(&cfg, &lifecycle).await;
    let approval = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::AccessApprove {
            handles: vec![handle.clone()],
            uses: Some(1),
            wait_secs: None,
        },
    )
    .await;
    let AdminResponse::AccessDecisions { items, .. } = approval else {
        panic!("operator approval should return an access decision")
    };
    assert_eq!(items[0].state, "armed");

    let result = tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
        .await
        .expect("waiting requester should claim the arm promptly")
        .unwrap();
    match result.exec {
        ExecOutcome::Completed {
            exit_code,
            stdout,
            stderr,
        } => {
            assert_eq!(exit_code, Some(9));
            assert_eq!(stdout.as_deref(), Some("waiting-stdout"));
            assert_eq!(stderr.as_deref(), Some("waiting-stderr"));
        }
        other => panic!("expected resumed completion, got {other:?}"),
    }
    let durable = store.load_approvals().await.unwrap();
    assert_eq!(
        durable
            .iter()
            .find(|row| row.handle == handle)
            .unwrap()
            .status,
        ApprovalStatus::Approved
    );
}

/// hold -> TTL expiry -> the sweeper denies (fail-closed); the command never
/// executes. Cross-platform: no child is spawned on this path.
#[tokio::test]
async fn hold_then_ttl_expiry_denies_fail_closed() {
    let (cfg, _operator, agent) = gating_config(7006, 1000);
    let agent_principal = agent.principal();
    let session_token = new_handle();
    cfg.state
        .sessions
        .write()
        .await
        .grant(session_token.clone(), active_session());

    let request = ExecuteRequest {
        binary: "rm".to_string(),
        args: vec!["-rf".to_string(), "/data".to_string()],
        auth_token: None,
        env: HashMap::new(),
        secrets: HashMap::new(),
        secret_files: HashMap::new(),
        stream: false,
        session_token: Some(session_token.clone()),
        revert: None,
        confirm_within_secs: None,
        reevaluate: false,
        ssh_hostkey: None,
        cwd: None,
        require_approval: None,
        wait_approval_secs: None,
        verb: None,
    };
    let mut sink = tokio::io::sink();
    let held = hold_for_approval_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        agent_principal,
        GateInputs {
            reason: "destructive".to_string(),
            risk: Some(10),
            reversibility: Some(Reversibility::Irreversible),
            revert_preauthorized: false,
            verb: None,
            bypass: false,
            authority: live_authority(&cfg, &session_token).await,
            consume_access_verbs: Vec::new(),
        },
    )
    .await;
    let handle = match &held.exec {
        ExecOutcome::Held { handle, .. } => handle.clone(),
        other => panic!("expected Held, got {:?}", other),
    };

    // Sweeper step: expire every pending hold past its TTL. Pass a `now` far
    // beyond the TTL so the deadline has certainly passed.
    let expired = cfg
        .state
        .approvals
        .write()
        .await
        .expire_due(now_unix() + APPROVAL_TTL_SECS + 10_000);
    assert_eq!(expired, vec![handle.clone()]);

    let row = cfg
        .state
        .approvals
        .read()
        .await
        .get(&handle)
        .cloned()
        .unwrap();
    let expected_session_fingerprint = audit_session_fingerprint(Some(&session_token));
    assert_eq!(
        row.snapshot.session_fingerprint.as_deref(),
        Some(expected_session_fingerprint.as_str())
    );
    assert!(!serde_json::to_string(&row.snapshot)
        .unwrap()
        .contains(&session_token));
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

/// File-backed secret references use the same held-value binding as env
/// secrets. Persisted snapshots contain names and hashes, never values.
#[tokio::test]
async fn approve_rejected_when_bound_secret_value_changed() {
    let (cfg, _operator, agent) = gating_config(7201, 4201);
    let agent_principal = agent.principal();
    let p = agent_principal.clone().expect("agent principal");
    cfg.state
        .secrets
        .set(&p, "BIND_TEST_KEY", "v1")
        .await
        .unwrap();

    let mut secret_files = HashMap::new();
    secret_files.insert("INJECTED_FILE".to_string(), "BIND_TEST_KEY".to_string());
    let request = ExecuteRequest {
        binary: "true".to_string(),
        args: Vec::new(),
        auth_token: None,
        env: HashMap::new(),
        secrets: HashMap::new(),
        secret_files,
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
    let mut sink = tokio::io::sink();
    let held = hold_for_approval_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        agent_principal.clone(),
        GateInputs {
            reason: "needs review".to_string(),
            risk: Some(8),
            reversibility: Some(Reversibility::Irreversible),
            revert_preauthorized: false,
            verb: None,
            bypass: false,
            authority: None,
            consume_access_verbs: Vec::new(),
        },
    )
    .await;
    let handle = match &held.exec {
        ExecOutcome::Held { handle, .. } => handle.clone(),
        other => panic!("expected Held, got {:?}", other),
    };

    let snapshot = cfg
        .state
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
    assert_eq!(
        snapshot.secret_file_keys.get("INJECTED_FILE"),
        Some(&"BIND_TEST_KEY".to_string())
    );
    let persisted = serde_json::to_string(&snapshot).unwrap();
    assert!(!persisted.contains("v1"));

    // The same principal swaps the value the operator was reviewing.
    cfg.state
        .secrets
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

    let _ = cfg.state.secrets.delete(&p, "BIND_TEST_KEY").await;
}

/// When the bound value is unchanged, the binding check passes (it does not
/// reject), so the approved command proceeds to execution.
#[tokio::test]
async fn approve_passes_binding_when_secret_value_unchanged() {
    let (cfg, _operator, agent) = gating_config(7202, 4202);
    let agent_principal = agent.principal();
    let p = agent_principal.clone().expect("agent principal");
    cfg.state
        .secrets
        .set(&p, "BIND_OK_KEY", "stable")
        .await
        .unwrap();

    let mut secret_files = HashMap::new();
    secret_files.insert("INJECTED_FILE".to_string(), "BIND_OK_KEY".to_string());
    let request = ExecuteRequest {
        binary: "true".to_string(),
        args: Vec::new(),
        auth_token: None,
        env: HashMap::new(),
        secrets: HashMap::new(),
        secret_files,
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
    let mut sink = tokio::io::sink();
    let held = hold_for_approval_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        agent_principal.clone(),
        GateInputs {
            reason: "needs review".to_string(),
            risk: Some(8),
            reversibility: Some(Reversibility::Irreversible),
            revert_preauthorized: false,
            verb: None,
            bypass: false,
            authority: None,
            consume_access_verbs: Vec::new(),
        },
    )
    .await;
    let handle = match &held.exec {
        ExecOutcome::Held { handle, .. } => handle.clone(),
        other => panic!("expected Held, got {:?}", other),
    };
    let snapshot = cfg
        .state
        .approvals
        .read()
        .await
        .get(&handle)
        .cloned()
        .unwrap()
        .snapshot;

    // Value unchanged -> the binding check must NOT reject. The subsequent
    // exec of `true` succeeds on Unix; on Windows there is no `true` binary,
    // so it may fail to spawn - either way it is not the binding rejection,
    // which is what this test asserts.
    let result = execute_snapshot(&cfg, &snapshot, "operator approved").await;
    if let ExecOutcome::Failed { reason, .. } = &result.exec {
        assert!(
            !reason.contains("changed since the command was held"),
            "binding check must not reject an unchanged value; got: {}",
            reason
        );
    }
    assert_eq!(
        std::fs::read_dir(cfg.config.secret_file_root.as_ref().unwrap())
            .unwrap()
            .count(),
        0,
        "held approval execution must clean its secret-file lease"
    );

    let _ = cfg.state.secrets.delete(&p, "BIND_OK_KEY").await;
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
    let _ = cfg.state.secrets.delete(&p, "BIND_LATE_KEY").await;

    let mut secrets = HashMap::new();
    secrets.insert("INJECTED".to_string(), "BIND_LATE_KEY".to_string());
    let request = ExecuteRequest {
        binary: "true".to_string(),
        args: Vec::new(),
        auth_token: None,
        env: HashMap::new(),
        secrets,
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
    let mut sink = tokio::io::sink();
    let held = hold_for_approval_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        agent_principal.clone(),
        GateInputs {
            reason: "needs review".to_string(),
            risk: Some(8),
            reversibility: Some(Reversibility::Irreversible),
            revert_preauthorized: false,
            verb: None,
            bypass: false,
            authority: None,
            consume_access_verbs: Vec::new(),
        },
    )
    .await;
    let handle = match &held.exec {
        ExecOutcome::Held { handle, .. } => handle.clone(),
        other => panic!("expected Held, got {:?}", other),
    };
    let snapshot = cfg
        .state
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
    cfg.state
        .secrets
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

    let _ = cfg.state.secrets.delete(&p, "BIND_LATE_KEY").await;
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
    let mut sink = tokio::io::sink();
    let held = hold_for_approval_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        request,
        agent_principal.clone(),
        GateInputs {
            reason: "review".to_string(),
            risk: Some(8),
            reversibility: Some(Reversibility::Irreversible),
            revert_preauthorized: false,
            verb: None,
            bypass: false,
            authority: None,
            consume_access_verbs: Vec::new(),
        },
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

    // Only the requester can withdraw its hold. Withdrawal is a terminal
    // denial, so execution never becomes claimable and the thread freezes.
    assert!(matches!(
        handle_admin_request_for_test(
            &cfg,
            &stranger,
            AdminRequest::ApprovalWithdraw {
                handle: handle.clone(),
            },
        )
        .await,
        AdminResponse::Error { .. }
    ));
    assert!(matches!(
        handle_admin_request_for_test(
            &cfg,
            &agent,
            AdminRequest::ApprovalWithdraw {
                handle: handle.clone(),
            },
        )
        .await,
        AdminResponse::GateAction { message, .. }
            if message == "requester withdrew held command"
    ));
    assert!(
        matches!(
            handle_approval_note(&cfg, &operator, &handle, "too late").await,
            AdminResponse::Error { .. }
        ),
        "a decided hold's thread must be frozen"
    );
}

/// Minimal catalog for verb-hold staleness tests: one matched verb plus
/// optional extra content so the whole-catalog version can change without
/// touching the matched verb's definition.
const HELD_VERB_YAML: &str = r#"
verbs:
  - name: restart-service
    binary: true
    args: ["{unit}"]
    params:
      unit: { pattern: "^[a-zA-Z0-9@._-]+$", required: true }
    consequence: irreversible
"#;

/// One pending hold bound to `restart-service` with a harmless executable
/// rendering so successful replay is observable.
fn held_verb_approval(
    handle: &str,
    catalog_version: Option<u64>,
    verb_digest: Option<String>,
    principal: Option<PrincipalKey>,
) -> Approval {
    Approval {
        handle: handle.to_string(),
        snapshot: ApprovalSnapshot {
            binary: "true".to_string(),
            args: vec!["fixture".to_string()],
            cwd: None,
            env: BTreeMap::new(),
            secret_keys: BTreeMap::new(),
            session_fingerprint: None,
            session_revision: None,
            secret_entitlements: None,
            secret_file_keys: BTreeMap::new(),
            verb_name: Some("restart-service".to_string()),
            verb_params: BTreeMap::new(),
            catalog_version,
            verb_digest,
            verb_composition_digest: None,
            access_verbs: Vec::new(),
            access_requests: Vec::new(),
            principal,
            secret_binding: None,
        },
        reason: "verb hold".to_string(),
        risk: Some(8),
        reversibility: Some(Reversibility::Irreversible),
        decision_trace: None,
        created_unix: now_unix(),
        ttl_secs: APPROVAL_TTL_SECS,
        status: ApprovalStatus::Pending,
        decided_unix: None,
        decided_reason: None,
        result_exit: None,
        result_stdout: None,
        result_stderr: None,
        notes: Vec::new(),
    }
}

#[tokio::test]
async fn one_rpc_approval_wait_returns_owned_armed_outcome() {
    let (cfg, operator, agent) = gating_config(7007, 1000);
    let catalog = VerbCatalog::from_yaml(HELD_VERB_YAML).unwrap();
    let catalog_version = catalog.version();
    *cfg.state.verbs.write().await = catalog;
    let handle = "one-rpc-arm";
    cfg.state
        .approvals
        .write()
        .await
        .enqueue(held_verb_approval(
            handle,
            Some(catalog_version),
            None,
            agent.principal(),
        ));

    let owned = handle_admin_request_owned(
        &cfg,
        &operator,
        AdminRequest::AccessApprove {
            handles: vec![handle.to_string()],
            uses: Some(1),
            wait_secs: Some(30),
        },
    )
    .await;
    let AdminResponse::AccessDecisions {
        items,
        wait: Some(wait),
    } = &owned.response
    else {
        panic!("expected one access decision with wait outcome");
    };
    assert!(items[0].success);
    assert_eq!(items[0].consequence, CONSEQUENCE_ARM);
    assert_eq!(wait.outcome, "armed");
    assert_eq!(wait.item.status, "armed");
    assert!(owned.waiter_lease.is_some());
    assert_eq!(cfg.state.approvals.read().await.active_waiters(handle), 1);
    serde_json::to_vec(&owned.response).expect("owned response serializes");
    drop(owned);
    assert_eq!(cfg.state.approvals.read().await.active_waiters(handle), 0);
}

#[tokio::test]
async fn one_rpc_approval_wait_returns_failed_terminal_and_timeout_outcomes() {
    for (status, expected) in [
        (ApprovalStatus::Denied, "denied"),
        (ApprovalStatus::Expired, "expired"),
        (ApprovalStatus::ExecFailed, "exec_failed"),
    ] {
        let (cfg, operator, agent) = gating_config(7007, 1000);
        let handle = format!("one-rpc-{expected}");
        let mut approval = held_verb_approval(&handle, None, None, agent.principal());
        approval.status = status;
        approval.decided_unix = Some(now_unix());
        approval.decided_reason = Some(expected.to_string());
        cfg.state.approvals.write().await.enqueue(approval);

        let owned = handle_admin_request_owned(
            &cfg,
            &operator,
            AdminRequest::AccessApprove {
                handles: vec![handle],
                uses: Some(1),
                wait_secs: Some(1),
            },
        )
        .await;
        let AdminResponse::AccessDecisions {
            items,
            wait: Some(wait),
        } = &owned.response
        else {
            panic!("expected failed decision with an observed terminal row")
        };
        assert!(!items[0].success);
        assert_eq!(wait.outcome, expected);
        assert_eq!(wait.item.status, expected);
    }

    for (status, uses) in [
        (ApprovalStatus::Pending, Some(2)),
        (ApprovalStatus::Approving, Some(1)),
    ] {
        let (cfg, operator, agent) = gating_config(7007, 1000);
        let handle = format!("one-rpc-timeout-{}", status.as_str());
        let mut approval = held_verb_approval(&handle, None, None, agent.principal());
        approval.status = status;
        cfg.state.approvals.write().await.enqueue(approval);

        let owned = handle_admin_request_owned(
            &cfg,
            &operator,
            AdminRequest::AccessApprove {
                handles: vec![handle],
                uses,
                wait_secs: Some(1),
            },
        )
        .await;
        let AdminResponse::AccessDecisions {
            items,
            wait: Some(wait),
        } = &owned.response
        else {
            panic!("expected failed decision with a timeout observation")
        };
        assert!(!items[0].success);
        assert_eq!(wait.outcome, "timed_out");
        assert_eq!(wait.item.status, status.as_str());
    }
}

#[tokio::test]
async fn access_audience_controls_hold_visibility_and_next_action() {
    let (cfg, operator, owner) = gating_config(7007, 1000);
    let unrelated = CallerIdentity::Unix { uid: 1001 };
    let handle = "audience-hold";
    cfg.state
        .approvals
        .write()
        .await
        .enqueue(held_verb_approval(handle, None, None, owner.principal()));

    let AdminResponse::AccessItem { item: owner_item } = handle_admin_request_for_test(
        &cfg,
        &owner,
        AdminRequest::AccessShow {
            reference: handle.to_string(),
        },
    )
    .await
    else {
        panic!("owner must see its hold")
    };
    assert_eq!(
        owner_item.next_action,
        format!("guard approval show {handle} --wait")
    );
    assert_eq!(
        owner_item.approval_options,
        vec![format!(
            "ask your admin to approve request {handle} (see guard access show {handle})"
        )]
    );

    let AdminResponse::AccessItem {
        item: operator_item,
    } = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::AccessShow {
            reference: handle.to_string(),
        },
    )
    .await
    else {
        panic!("operator must see the hold")
    };
    assert_eq!(
        operator_item.next_action,
        format!("guard access approve {handle} --once")
    );
    assert_eq!(
        operator_item.approval_options,
        vec![format!("guard access approve {handle} --once")]
    );

    assert!(matches!(
        handle_admin_request_for_test(
            &cfg,
            &unrelated,
            AdminRequest::AccessShow {
                reference: handle.to_string()
            }
        )
        .await,
        AdminResponse::Error { .. }
    ));
    let AdminResponse::AccessItems { items } =
        handle_admin_request_for_test(&cfg, &unrelated, AdminRequest::AccessList).await
    else {
        panic!("unrelated caller receives a scoped list")
    };
    assert!(items.iter().all(|item| item.reference != handle));
}

#[test]
fn execution_approval_guidance_respects_authenticated_audience() {
    let (cfg, operator, requester) = gating_config(7007, 1000);
    let handle = "audience-request";

    assert_eq!(
        super::super::admin::approval_guidance(&cfg, &operator, handle, false),
        format!(
            "approve: guard access approve {handle}\nonce: guard access approve {handle} --once\nbounded: guard access approve {handle} --uses 3"
        )
    );
    assert_eq!(
        super::super::admin::approval_guidance(&cfg, &requester, handle, false),
        format!("ask your admin to approve request {handle} (see guard access show {handle})")
    );
}

#[tokio::test]
async fn lost_one_rpc_response_leaves_one_durable_mutation() {
    let (cfg, operator, agent) = gating_config(7007, 1000);
    let catalog = VerbCatalog::from_yaml(HELD_VERB_YAML).unwrap();
    let catalog_version = catalog.version();
    *cfg.state.verbs.write().await = catalog;
    let handle = "lost-one-rpc-response";
    cfg.state
        .approvals
        .write()
        .await
        .enqueue(held_verb_approval(
            handle,
            Some(catalog_version),
            None,
            agent.principal(),
        ));

    let owned = handle_admin_request_owned(
        &cfg,
        &operator,
        AdminRequest::AccessApprove {
            handles: vec![handle.to_string()],
            uses: Some(1),
            wait_secs: Some(1),
        },
    )
    .await;
    let AdminResponse::AccessDecisions {
        items,
        wait: Some(wait),
    } = &owned.response
    else {
        panic!("lost response simulation requires the one-RPC wait envelope");
    };
    assert!(items[0].success);
    assert_eq!(wait.outcome, "armed");
    assert_eq!(wait.item.status, "armed");
    drop(owned);
    assert!(approval_is_armed(
        cfg.state.approvals.read().await.get(handle).unwrap()
    ));

    let AdminResponse::AccessDecisions { items, .. } = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::AccessApprove {
            handles: vec![handle.to_string()],
            uses: Some(1),
            wait_secs: None,
        },
    )
    .await
    else {
        panic!("repeat observation returns a decision row")
    };
    assert!(!items[0].success);
    assert_eq!(items[0].state, "armed");
}

#[cfg(unix)]
#[tokio::test]
async fn one_rpc_release_wait_returns_approved_outcome() {
    let (cfg, operator, _agent) = gating_config(7013, 1000);
    let sink = Arc::new(DaemonGateSink {
        server: cfg.clone(),
        endpoint: "default".to_string(),
        protocol: "kubernetes".to_string(),
        snapshot_dir: std::env::temp_dir(),
        snapshot_dir_safe: true,
        window_secs: 60,
    });
    let lifecycle = observe_approval_lifecycle_for_test(&cfg);
    let waiter = tokio::spawn(async move {
        let snapshot = guard::proxy::ApiHoldSnapshot {
            label: "release operation".to_string(),
            body_sha256: "body-digest".to_string(),
            redacted_body_shape: "(no body)".to_string(),
            redacted_query: String::new(),
            authority_selectors: Default::default(),
        };
        guard::proxy::GateSink::hold_request(&*sink, &snapshot, "release review", None).await
    });
    let handle = pending_hold_after(&cfg, &lifecycle).await;
    let owned = handle_admin_request_owned(
        &cfg,
        &operator,
        AdminRequest::AccessApprove {
            handles: vec![handle.clone()],
            uses: Some(1),
            wait_secs: Some(30),
        },
    )
    .await;
    let AdminResponse::AccessDecisions {
        items,
        wait: Some(wait),
    } = &owned.response
    else {
        panic!("expected release decision and outcome")
    };
    assert!(items[0].success);
    assert_eq!(items[0].consequence, CONSEQUENCE_RELEASE);
    assert_eq!(wait.outcome, "approved");
    assert_eq!(wait.item.status, "approved");
    assert!(matches!(
        waiter.await.unwrap(),
        guard::proxy::HoldDecision::Approved { .. }
    ));
}

/// approve of a legacy row (no stored verb digest) after the verb catalog
/// version changed is voided: without a digest the whole-catalog version is
/// the only binding, so the approved artifact may no longer mean what the
/// operator reviewed. Cross-platform: the void check returns before any
/// child is spawned.
#[tokio::test]
async fn approve_voided_when_verb_catalog_version_changed() {
    let (cfg, operator, agent) = gating_config(7007, 1000);
    *cfg.state.verbs.write().await = VerbCatalog::from_yaml(HELD_VERB_YAML).unwrap();

    // Enqueue a hold that originated from a verb, stamped with a catalog
    // version that differs from the live catalog's version and written
    // before per-verb digests existed.
    let handle = new_handle();
    let approval = held_verb_approval(&handle, Some(424_242), None, agent.principal());
    assert_ne!(
        approval.snapshot.catalog_version,
        Some(cfg.state.verbs.read().await.version()),
        "test precondition: the stamped version must differ from live"
    );
    cfg.state.approvals.write().await.enqueue(approval);

    let voided = handle_admin_request_for_test(
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
        cfg.state
            .approvals
            .read()
            .await
            .get(&handle)
            .unwrap()
            .status,
        ApprovalStatus::ExecFailed
    );
}

/// A pending hold bound to its verb's definition digest survives an
/// unrelated verb being appended to the catalog: the whole-catalog version
/// changes but the matched verb's definition does not, so approve proceeds
/// instead of voiding.
#[tokio::test]
async fn approve_survives_unrelated_verb_append() {
    let (cfg, operator, agent) = gating_config(7047, 1000);
    let held_catalog = VerbCatalog::from_yaml(HELD_VERB_YAML).unwrap();
    let held_version = held_catalog.version();
    let held_digest = held_catalog
        .verb_definition_digest("restart-service")
        .unwrap();
    *cfg.state.verbs.write().await = held_catalog;

    let handle = new_handle();
    cfg.state
        .approvals
        .write()
        .await
        .enqueue(held_verb_approval(
            &handle,
            Some(held_version),
            Some(held_digest.clone()),
            agent.principal(),
        ));

    // Append an unrelated verb: the catalog version changes, the matched
    // verb's definition does not.
    let appended = VerbCatalog::from_yaml(&format!(
        "{HELD_VERB_YAML}  - name: unrelated-uptime\n    binary: uptime\n    consequence: reversible\n"
    ))
    .unwrap();
    assert_ne!(appended.version(), held_version);
    assert_eq!(
        appended.verb_definition_digest("restart-service").unwrap(),
        held_digest
    );
    *cfg.state.verbs.write().await = appended;

    let response = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::Approve {
            handle: handle.clone(),
        },
    )
    .await;
    if let AdminResponse::Error { message } = &response {
        assert!(
            !message.contains("was held"),
            "an unrelated catalog append must not void the hold, got: {message}"
        );
    }
    let approval = cfg
        .state
        .approvals
        .read()
        .await
        .get(&handle)
        .unwrap()
        .clone();
    assert!(approval_is_armed(&approval));
    assert!(
        approval
            .decided_reason
            .as_deref()
            .is_none_or(|reason| !reason.contains("was held")),
        "got: {:?}",
        approval.decided_reason
    );
    #[cfg(unix)]
    {
        let resumed = resume_approval(&cfg, &agent, &handle).await;
        assert!(matches!(resumed.exec, ExecOutcome::Completed { .. }));
        assert_eq!(
            cfg.state
                .approvals
                .read()
                .await
                .get(&handle)
                .unwrap()
                .status,
            ApprovalStatus::Approved
        );
    }
}

/// A pending hold is voided when the matched verb's own definition changes,
/// even though the verb still exists under the same name: the operator would
/// otherwise approve a rendering the current definition no longer produces.
/// Cross-platform: the void check returns before any child is spawned.
#[tokio::test]
async fn approve_voided_when_matched_verb_definition_changed() {
    let (cfg, operator, agent) = gating_config(7048, 1000);
    let held_catalog = VerbCatalog::from_yaml(HELD_VERB_YAML).unwrap();
    let held_version = held_catalog.version();
    let held_digest = held_catalog
        .verb_definition_digest("restart-service")
        .unwrap();
    *cfg.state.verbs.write().await = held_catalog;

    let handle = new_handle();
    cfg.state
        .approvals
        .write()
        .await
        .enqueue(held_verb_approval(
            &handle,
            Some(held_version),
            Some(held_digest.clone()),
            agent.principal(),
        ));

    // Change the matched verb's own definition (narrow its unit pattern).
    let changed =
        VerbCatalog::from_yaml(&HELD_VERB_YAML.replace("^[a-zA-Z0-9@._-]+$", "^(nginx|sshd)$"))
            .unwrap();
    assert_ne!(
        changed.verb_definition_digest("restart-service").unwrap(),
        held_digest
    );
    *cfg.state.verbs.write().await = changed;

    let voided = handle_admin_request_for_test(
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
                message.contains("'restart-service' changed since it was held")
                    && message.contains("voided"),
                "got: {message}"
            );
        }
        other => panic!("a changed-verb approve must be voided, got {:?}", other),
    }
    assert_eq!(
        cfg.state
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
async fn held_approval_catalog_race_is_linearized(replacement: VerbCatalog) {
    let (cfg, operator, agent) = gating_config(7088, 1000);
    let held_catalog = VerbCatalog::from_yaml(HELD_VERB_YAML).unwrap();
    let held_version = held_catalog.version();
    let held_digest = held_catalog
        .verb_definition_digest("restart-service")
        .unwrap();
    *cfg.state.verbs.write().await = held_catalog;
    let handle = new_handle();
    cfg.state
        .approvals
        .write()
        .await
        .enqueue(held_verb_approval(
            &handle,
            Some(held_version),
            Some(held_digest),
            agent.principal(),
        ));

    let (acquired, release) = pause_verb_authority_lease_for_test(&cfg, "held command arming");
    let approving = cfg.clone();
    let approving_operator = operator.clone();
    let approving_handle = handle.clone();
    let approval = tokio::spawn(async move {
        handle_admin_request_for_test(
            &approving,
            &approving_operator,
            AdminRequest::Approve {
                handle: approving_handle,
            },
        )
        .await
    });
    acquired.acquire().await.unwrap().forget();

    // The immutable lease is generation-bound and does not retain a global
    // catalog lock while the replacement and downstream work proceed.
    let changing = cfg.clone();
    let mutation = tokio::spawn(async move {
        *changing.state.verbs.write().await = replacement;
    });
    release.add_permits(1);

    assert!(matches!(
        approval.await.unwrap(),
        AdminResponse::GateAction { .. }
    ));
    mutation.await.unwrap();
    let resumed = resume_approval(&cfg, &agent, &handle).await;
    assert!(!matches!(resumed.exec, ExecOutcome::Completed { .. }));
    assert_eq!(
        cfg.state
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
async fn held_approval_lease_linearizes_against_deletion_and_amendment() {
    held_approval_catalog_race_is_linearized(VerbCatalog::from_yaml("verbs: []").unwrap()).await;
    let replacement = VerbCatalog::from_yaml(
        &HELD_VERB_YAML.replace("^[a-zA-Z0-9@._-]+$", "^(fixture|alternate)$"),
    )
    .unwrap();
    held_approval_catalog_race_is_linearized(replacement).await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verb_execution_lease_linearizes_against_concurrent_amendment() {
    let (cfg, _operator, agent) = gating_config(7089, 1000);
    const EXECUTION_VERB: &str =
        "verbs:\n  - name: runtime-command\n    binary: true\n    consequence: reversible\n    trusted: true\n";
    let catalog = VerbCatalog::from_yaml(EXECUTION_VERB).unwrap();
    let digest = catalog.verb_definition_digest("runtime-command").unwrap();
    let version = catalog.version();
    *cfg.state.verbs.write().await = catalog;
    let (acquired, release) = pause_verb_authority_lease_for_test(&cfg, "command process start");

    let execution = cfg.clone();
    let execution_agent = agent.clone();
    let routed = tokio::spawn(async move {
        let mut sink = tokio::io::sink();
        route_gated_allow(
            &mut RequestContext {
                server: &execution,
                caller: &execution_agent,
                depth: 0,
                stream_output: false,
                stream_writer: &mut sink,
            },
            held_request("true", Vec::new(), None),
            GateInputs {
                reason: "operator verb".to_string(),
                risk: Some(1),
                reversibility: Some(Reversibility::Reversible),
                revert_preauthorized: false,
                verb: Some(VerbContext {
                    name: "runtime-command".to_string(),
                    class: Reversibility::Reversible,
                    trusted: true,
                    params: BTreeMap::new(),
                    catalog_version: version,
                    verb_digest: Some(digest),
                    composition_digest: None,
                    access_evaluation_override_eligible: false,
                }),
                bypass: true,
                authority: None,
                consume_access_verbs: Vec::new(),
            },
            None,
        )
        .await
    });
    acquired.acquire().await.unwrap().forget();

    // The immutable lease is generation-bound and does not retain a global
    // catalog lock while the amendment and downstream work proceed.
    let changing = cfg.clone();
    let mutation = tokio::spawn(async move {
        let replacement = VerbCatalog::from_yaml(
            &EXECUTION_VERB.replace("binary: true", "binary: true\n    description: amended"),
        )
        .unwrap();
        *changing.state.verbs.write().await = replacement;
    });
    release.add_permits(1);

    assert!(matches!(
        routed.await.unwrap().exec,
        ExecOutcome::Completed { .. }
    ));
    mutation.await.unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn access_approval_and_command_start_follow_one_lock_order() {
    let (cfg, operator, agent) = gating_config(7090, 1000);
    let catalog = VerbCatalog::from_yaml(
        r#"
verbs:
  - name: runtime-command
    binary: true
    baseline: false
    consequence: reversible
    trusted: true
  - name: approval-scope
    binary: echo
    args: ["scope"]
    baseline: false
    consequence: reversible
    trusted: true
"#,
    )
    .unwrap();
    let version = catalog.version();
    let digest = catalog.verb_definition_digest("runtime-command").unwrap();
    *cfg.state.verbs.write().await = catalog;
    let mut command_session = active_session();
    command_session.activated_verbs = vec!["runtime-command".to_string()];
    cfg.state
        .sessions
        .write()
        .await
        .grant("lock-order-session".to_string(), command_session);

    let mut pending = crate::grant_profile::GrantRequest::new_access(
        agent.principal().unwrap(),
        None,
        "agent-fixture".to_string(),
        crate::grant_profile::GrantRequestDelta {
            activated_verbs: vec!["approval-scope".to_string()],
            ..Default::default()
        },
        "bounded scope".to_string(),
    )
    .unwrap();
    pending.authority_verbs = vec!["approval-scope".to_string()];
    pending.request_key = pending.canonical_access_key().unwrap();
    let pending_handle = pending.handle.clone();
    cfg.state
        .grant_requests
        .write()
        .await
        .insert(pending.handle.clone(), pending);

    let (command_acquired, release_command) =
        pause_verb_authority_lease_for_test(&cfg, "command process start");
    let mut request = held_request("true", Vec::new(), None);
    request.session_token = Some("lock-order-session".to_string());
    let session_authority = live_authority(&cfg, "lock-order-session").await;
    let executing = cfg.clone();
    let executing_agent = agent.clone();
    let command = tokio::spawn(async move {
        let mut sink = tokio::io::sink();
        route_gated_allow(
            &mut RequestContext {
                server: &executing,
                caller: &executing_agent,
                depth: 0,
                stream_output: false,
                stream_writer: &mut sink,
            },
            request,
            GateInputs {
                reason: "operator verb".to_string(),
                risk: Some(1),
                reversibility: Some(Reversibility::Reversible),
                revert_preauthorized: false,
                verb: Some(VerbContext {
                    name: "runtime-command".to_string(),
                    class: Reversibility::Reversible,
                    trusted: true,
                    params: BTreeMap::new(),
                    catalog_version: version,
                    verb_digest: Some(digest),
                    composition_digest: None,
                    access_evaluation_override_eligible: false,
                }),
                bypass: true,
                authority: session_authority,
                consume_access_verbs: Vec::new(),
            },
            None,
        )
        .await
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        command_acquired.acquire(),
    )
    .await
    .expect("command reaches the verb initiation lease")
    .unwrap()
    .forget();

    let (approval_reached, release_approval) =
        pause_access_approval_before_verb_lock_for_test(&cfg);
    let approving = cfg.clone();
    let approval = tokio::spawn(async move {
        handle_admin_request_for_test(
            &approving,
            &operator,
            AdminRequest::AccessApprove {
                handles: vec![pending_handle],
                uses: Some(1),
                wait_secs: None,
            },
        )
        .await
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        approval_reached.acquire(),
    )
    .await
    .expect("approval reaches verb coordination before session coordination")
    .unwrap()
    .forget();
    release_approval.add_permits(1);
    // Both flows are synchronized at explicit lease boundaries. No global
    // catalog lock spans the finite process-start or approval work.

    release_command.add_permits(1);
    let (command_result, approval_result) =
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(command, approval)
        })
        .await
        .expect("opposing flows do not form a lock cycle");
    let command_result = command_result.unwrap();
    let command_response = command_result.into_response();
    assert!(
        command_response.allowed && command_response.exit_code == Some(0),
        "command start failed: {}",
        command_response.reason
    );
    let AdminResponse::AccessDecisions { items, .. } = approval_result.unwrap() else {
        panic!("expected access decision")
    };
    assert!(items[0].success, "access approval failed: {:?}", items[0]);
}

#[tokio::test]
async fn approved_snapshot_rechecks_binary_floor_before_exec() {
    let (mut cfg, _, agent) = gating_config(7015, 1000);
    cfg.config.allowed_binaries = Some(vec!["echo".to_string()]);
    let snapshot = ApprovalSnapshot {
        binary: "sh".to_string(),
        args: vec!["-c".to_string(), "true".to_string()],
        cwd: None,
        env: BTreeMap::new(),
        secret_keys: BTreeMap::new(),
        session_fingerprint: None,
        session_revision: None,
        secret_entitlements: None,
        secret_file_keys: BTreeMap::new(),
        verb_name: None,
        verb_params: BTreeMap::new(),
        catalog_version: None,
        verb_digest: None,
        verb_composition_digest: None,
        access_verbs: Vec::new(),
        access_requests: Vec::new(),
        principal: agent.principal(),
        secret_binding: None,
    };

    let result = execute_snapshot(&cfg, &snapshot, "operator approved").await;

    assert!(matches!(
        result.exec,
        ExecOutcome::Failed { started: false, .. }
    ));
    assert_eq!(result.policy_reason(), "operator approved");
    if let ExecOutcome::Failed { reason, .. } = result.exec {
        assert!(reason.contains("not in the server allow-list"));
    }
}

#[cfg(unix)]
#[tokio::test]
async fn sensitive_hold_and_containment_snapshots_fail_before_persistence() {
    let (mut cfg, _operator, agent) = gating_config(7_050, 1_000);
    let (audit_directory, _audit) = super::attach_test_audit_log(&mut cfg);
    let state = tempfile::tempdir().unwrap();
    let store = SessionStore::open(state.path().join("state.db"), 3_600)
        .await
        .unwrap();
    cfg.state.session_store = Some(store.clone());
    let sensitive = ["q", "7"].concat();
    let mut sink = tokio::io::sink();

    let held = hold_for_approval_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        held_request("curl.EXE", vec![format!("-u{sensitive}")], None),
        agent.principal(),
        GateInputs {
            reason: "requires approval".to_string(),
            risk: Some(9),
            reversibility: Some(Reversibility::Irreversible),
            revert_preauthorized: false,
            verb: None,
            bypass: false,
            authority: None,
            consume_access_verbs: Vec::new(),
        },
    )
    .await;
    assert!(matches!(&held.exec, ExecOutcome::NotAttempted));

    let contained = arm_containment_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        contain_request(
            "true",
            &[],
            RevertSpec::new("curl", vec!["-u".to_string(), sensitive.clone()]),
        ),
        agent.principal(),
        "recoverable change".to_string(),
        None,
    )
    .await;
    assert!(matches!(&contained.exec, ExecOutcome::NotAttempted));
    assert!(cfg.state.approvals.read().await.list().is_empty());
    assert!(cfg.state.provisional.read().await.list().is_empty());
    assert!(store.load_approvals().await.unwrap().is_empty());
    assert!(store.load_provisionals().await.unwrap().is_empty());
    assert!(!serde_json::to_string(&held.into_response())
        .unwrap()
        .contains(&sensitive));
    assert!(!serde_json::to_string(&contained.into_response())
        .unwrap()
        .contains(&sensitive));
    let audit = std::fs::read_to_string(audit_directory.path().join("audit.jsonl")).unwrap();
    assert!(!audit.contains(&sensitive));
}

#[cfg(unix)]
#[tokio::test]
async fn sensitive_armed_approval_is_redacted_and_cannot_resume() {
    let (mut cfg, operator, agent) = gating_config(7_051, 1_000);
    let (audit_directory, _audit) = super::attach_test_audit_log(&mut cfg);
    let mut sink = tokio::io::sink();
    let held = hold_for_approval_with_authority(
        &mut RequestContext {
            server: &cfg,
            caller: &agent,
            depth: 0,
            stream_output: false,
            stream_writer: &mut sink,
        },
        held_request("true", Vec::new(), None),
        agent.principal(),
        GateInputs {
            reason: "requires approval".to_string(),
            risk: Some(9),
            reversibility: Some(Reversibility::Irreversible),
            revert_preauthorized: false,
            verb: None,
            bypass: false,
            authority: None,
            consume_access_verbs: Vec::new(),
        },
    )
    .await;
    let ExecOutcome::Held { handle, .. } = held.exec else {
        panic!("expected held command")
    };
    let armed = handle_admin_request_for_test(
        &cfg,
        &operator,
        AdminRequest::AccessApprove {
            handles: vec![handle.clone()],
            uses: Some(1),
            wait_secs: None,
        },
    )
    .await;
    assert!(matches!(armed, AdminResponse::AccessDecisions { .. }));

    let sensitive = ["q", "7"].concat();
    {
        let mut approvals = cfg.state.approvals.write().await;
        let mut rows = approvals.list();
        let row = rows.iter_mut().find(|row| row.handle == handle).unwrap();
        row.snapshot.binary = "docker.CMD".to_string();
        row.snapshot.args = vec!["login".to_string(), format!("-p:{sensitive}")];
        row.reason = format!("password={sensitive}");
        row.notes.push(guard::gating::approval::ApprovalNote {
            at_unix: now_unix(),
            author: "operator".to_string(),
            text: format!("password={sensitive}"),
        });
        row.decision_trace = Some(guard::gating::DecisionTrace {
            guidance: Some(format!("password={sensitive}")),
            ..guard::gating::DecisionTrace::source("fixture")
        });
        let (registry, recovered) =
            guard::gating::approval::ApprovalRegistry::from_rows(rows, now_unix());
        assert!(recovered.is_empty());
        *approvals = registry;
    }
    let listed = handle_admin_request_for_test(&cfg, &agent, AdminRequest::ApprovalList).await;
    assert!(!serde_json::to_string(&listed).unwrap().contains(&sensitive));
    let operator_listed =
        handle_admin_request_for_test(&cfg, &operator, AdminRequest::ApprovalList).await;
    assert!(!serde_json::to_string(&operator_listed)
        .unwrap()
        .contains(&sensitive));
    let resumed = handle_admin_request_for_test(
        &cfg,
        &agent,
        AdminRequest::Resume {
            handle: handle.clone(),
        },
    )
    .await;
    assert!(!serde_json::to_string(&resumed)
        .unwrap()
        .contains(&sensitive));
    assert_eq!(
        cfg.state
            .approvals
            .read()
            .await
            .get(&handle)
            .unwrap()
            .status,
        ApprovalStatus::ExecFailed
    );
    let audit = std::fs::read_to_string(audit_directory.path().join("audit.jsonl")).unwrap();
    assert!(!audit.contains(&sensitive));
}

#[cfg(unix)]
#[tokio::test]
async fn sensitive_provisional_snapshots_are_redacted_and_cannot_replay() {
    let (mut cfg, _operator, agent) = gating_config(7_052, 1_000);
    let (audit_directory, _audit) = super::attach_test_audit_log(&mut cfg);
    let sensitive = ["q", "7"].concat();
    let provisional = Provisional {
        handle: "sensitive-provisional-replay".to_string(),
        principal: agent.principal(),
        requester_principal: None,
        binary: "curl.EXE".to_string(),
        args: vec![format!("-u{sensitive}")],
        cwd: None,
        secret_keys: BTreeMap::new(),
        secret_file_keys: BTreeMap::new(),
        revert_binary: "docker.CMD".to_string(),
        revert_args: vec!["login".to_string(), format!("-p={sensitive}")],
        confirm_check_binary: Some("redis-cli.COM".to_string()),
        confirm_check_args: vec![format!("-a:{sensitive}")],
        control_path: Some("fixture".to_string()),
        session_fingerprint: None,
        session_revision: None,
        secret_entitlements: None,
        api_revert: None,
        reason: format!("password={sensitive}"),
        decision_trace: Some(guard::gating::DecisionTrace {
            guidance: Some(format!("password={sensitive}")),
            ..guard::gating::DecisionTrace::source("fixture")
        }),
        created_unix: now_unix(),
        deadline_unix: now_unix(),
        window_secs: 0,
        auto_reverted_unix: None,
        forward_done: true,
        forward_exit: Some(0),
        forward_persistence_failed: false,
        status: ProvisionalStatus::Reverting,
        revert_exit: None,
        revert_detail: None,
    };
    let summary = crate::server::wire::ProvisionalSummary::from_row(&provisional);
    assert!(!serde_json::to_string(&summary)
        .unwrap()
        .contains(&sensitive));
    let checked = run_provisional_check(&cfg, &provisional).await;
    assert!(matches!(
        &checked.exec,
        ExecOutcome::Failed { started: false, .. }
    ));
    assert!(!serde_json::to_string(&checked.into_response())
        .unwrap()
        .contains(&sensitive));

    cfg.state
        .provisional
        .write()
        .await
        .insert(provisional.clone());
    let (message, exit) = finish_revert(&cfg, &provisional, &agent, "operator retry").await;
    assert_eq!(exit, None);
    assert!(!message.contains(&sensitive));
    let audit = std::fs::read_to_string(audit_directory.path().join("audit.jsonl")).unwrap();
    assert!(!audit.contains(&sensitive));
}

#[cfg(unix)]
#[tokio::test]
async fn stored_entitlements_cover_tool_secrets_for_approval_check_and_revert() {
    let (mut cfg, _, agent) = gating_config(7020, 1000);
    let state = tempfile::tempdir().unwrap();
    let store = SessionStore::open(state.path().join("state.db"), 3_600)
        .await
        .unwrap();
    cfg.state.session_store = Some(store.clone());
    let principal = agent.principal().unwrap();
    cfg.state
        .secrets
        .set(&principal, "broker/token", "never-printed")
        .await
        .unwrap();
    let tools = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        tools.path(),
        "tools:\n  true:\n    secrets:\n      BROKER_TOKEN: broker/token\n",
    )
    .unwrap();
    *cfg.state.tool_registry.write().await =
        crate::tool_config::ToolRegistry::load(tools.path()).unwrap();

    let snapshot = ApprovalSnapshot {
        binary: "true".to_string(),
        args: Vec::new(),
        cwd: None,
        env: BTreeMap::new(),
        secret_keys: BTreeMap::new(),
        session_fingerprint: None,
        session_revision: None,
        secret_entitlements: Some(Vec::new()),
        secret_file_keys: BTreeMap::new(),
        verb_name: None,
        verb_params: BTreeMap::new(),
        catalog_version: None,
        verb_digest: None,
        verb_composition_digest: None,
        access_verbs: Vec::new(),
        access_requests: Vec::new(),
        principal: Some(principal.clone()),
        secret_binding: Some(SecretBinding {
            salt: "test-salt".to_string(),
            hashes: BTreeMap::new(),
            tool_hashes: Some(BTreeMap::from([(
                "BROKER_TOKEN".to_string(),
                ToolSecretBinding {
                    secret_name: "broker/token".to_string(),
                    hash: hash_secret_value("test-salt", "never-printed"),
                },
            )])),
        }),
    };
    let approved = execute_snapshot(&cfg, &snapshot, "operator approved").await;
    assert!(matches!(
        approved.exec,
        ExecOutcome::Failed { started: false, ref reason }
            if reason.contains("does not entitle secret 'broker/token'")
    ));

    let provisional = Provisional {
        handle: "entitled-control-path".to_string(),
        principal: Some(principal),
        requester_principal: None,
        binary: "true".to_string(),
        args: Vec::new(),
        cwd: None,
        secret_keys: BTreeMap::new(),
        secret_file_keys: BTreeMap::new(),
        revert_binary: "true".to_string(),
        revert_args: Vec::new(),
        confirm_check_binary: Some("true".to_string()),
        confirm_check_args: Vec::new(),
        control_path: Some("test".to_string()),
        session_fingerprint: None,
        session_revision: Some("revoked-session-revision".to_string()),
        secret_entitlements: Some(Vec::new()),
        api_revert: None,
        reason: "test".to_string(),
        decision_trace: None,
        created_unix: now_unix(),
        deadline_unix: now_unix(),
        window_secs: 0,
        auto_reverted_unix: None,
        forward_done: true,
        forward_exit: Some(0),
        forward_persistence_failed: false,
        status: ProvisionalStatus::Reverting,
        revert_exit: None,
        revert_detail: None,
    };
    let checked = run_provisional_check(&cfg, &provisional).await;
    assert!(matches!(
        checked.exec,
        ExecOutcome::Failed { started: false, ref reason }
            if reason.contains("does not entitle secret 'broker/token'")
    ));
    let mut viable = provisional;
    viable.handle = "revoked-session-rollback".to_string();
    viable.secret_entitlements = Some(vec!["broker/token".to_string()]);
    viable.status = ProvisionalStatus::Reverting;
    viable.revert_exit = None;
    viable.revert_detail = None;
    let checked = run_provisional_check(&cfg, &viable).await;
    assert!(matches!(
        checked.exec,
        ExecOutcome::Completed {
            exit_code: Some(0),
            ..
        }
    ));
    let mut durable = viable.clone();
    durable.status = ProvisionalStatus::Armed;
    store.save_provisional(durable.clone()).await.unwrap();
    store
        .compare_and_swap_provisional(durable, viable.clone())
        .await
        .unwrap();
    cfg.state.provisional.write().await.insert(viable.clone());
    let (_, exit) = finish_revert(&cfg, &viable, &agent, "test").await;
    assert_eq!(exit, Some(0));
    assert_eq!(
        cfg.state
            .provisional
            .read()
            .await
            .get(&viable.handle)
            .unwrap()
            .status,
        ProvisionalStatus::Reverted
    );
}

#[cfg(unix)]
#[tokio::test]
async fn approved_snapshot_rejects_changed_session_revision() {
    let (cfg, _, agent) = gating_config(7021, 1000);
    let token = "held-session-revision";
    cfg.state.sessions.write().await.grant(
        token.to_string(),
        SessionGrant {
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
            owner: crate::session::SessionOwner::Principal(
                guard::principal::PrincipalKey::from_uid(1000),
            ),
        },
    );
    let revision = cfg
        .state
        .sessions
        .read()
        .await
        .effective_revision_key(token)
        .unwrap();
    let snapshot = ApprovalSnapshot {
        binary: "true".to_string(),
        args: Vec::new(),
        cwd: None,
        env: BTreeMap::new(),
        secret_keys: BTreeMap::new(),
        session_fingerprint: Some(audit_session_fingerprint(Some(token))),
        session_revision: Some(revision),
        secret_entitlements: None,
        secret_file_keys: BTreeMap::new(),
        verb_name: None,
        verb_params: BTreeMap::new(),
        catalog_version: None,
        verb_digest: None,
        verb_composition_digest: None,
        access_verbs: Vec::new(),
        access_requests: Vec::new(),
        principal: agent.principal(),
        secret_binding: None,
    };
    assert!(cfg.state.sessions.write().await.revoke(token));
    let result = execute_snapshot(&cfg, &snapshot, "operator approved").await;
    assert!(matches!(
        result.exec,
        ExecOutcome::Failed { started: false, ref reason }
            if reason.contains("session changed or was revoked")
    ));
}

#[tokio::test]
async fn approved_snapshot_rejects_dangerous_request_env_before_exec() {
    let (cfg, _, agent) = gating_config(7018, 1000);
    let snapshot = ApprovalSnapshot {
        binary: "sh".to_string(),
        args: vec!["-c".to_string(), "printf should-not-run".to_string()],
        cwd: None,
        env: BTreeMap::from([(
            "SSH_AUTH_SOCK".to_string(),
            "/tmp/caller-agent.sock".to_string(),
        )]),
        secret_keys: BTreeMap::new(),
        session_fingerprint: None,
        session_revision: None,
        secret_entitlements: None,
        secret_file_keys: BTreeMap::new(),
        verb_name: None,
        verb_params: BTreeMap::new(),
        catalog_version: None,
        verb_digest: None,
        verb_composition_digest: None,
        access_verbs: Vec::new(),
        access_requests: Vec::new(),
        principal: agent.principal(),
        secret_binding: None,
    };

    let result = execute_snapshot(&cfg, &snapshot, "operator approved").await;

    assert!(matches!(
        result.exec,
        ExecOutcome::Failed { started: false, .. }
    ));
    assert_eq!(result.policy_reason(), "operator approved");
    if let ExecOutcome::Failed { reason, .. } = result.exec {
        assert!(reason.contains("dangerous injected environment variable name: 'SSH_AUTH_SOCK'"));
    }
}

#[cfg(unix)]
#[tokio::test]
async fn approved_snapshot_executes_in_snapshotted_cwd() {
    let (cfg, _, agent) = gating_config(7016, 1000);
    let temp = tempfile::tempdir().unwrap();
    let snapshot = ApprovalSnapshot {
        binary: "sh".to_string(),
        args: vec![
            "-c".to_string(),
            "printf approved > approval-cwd.txt".to_string(),
        ],
        cwd: Some(temp.path().to_path_buf()),
        env: BTreeMap::new(),
        secret_keys: BTreeMap::new(),
        session_fingerprint: None,
        session_revision: None,
        secret_entitlements: None,
        secret_file_keys: BTreeMap::new(),
        verb_name: None,
        verb_params: BTreeMap::new(),
        catalog_version: None,
        verb_digest: None,
        verb_composition_digest: None,
        access_verbs: Vec::new(),
        access_requests: Vec::new(),
        principal: agent.principal(),
        secret_binding: None,
    };

    let result = execute_snapshot(&cfg, &snapshot, "operator approved").await;

    assert!(matches!(
        result.exec,
        ExecOutcome::Completed {
            exit_code: Some(0),
            ..
        }
    ));
    assert_eq!(
        std::fs::read_to_string(temp.path().join("approval-cwd.txt")).unwrap(),
        "approved"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn approved_snapshot_rejects_missing_snapshotted_cwd_before_exec() {
    let (cfg, _, agent) = gating_config(7017, 1000);
    let temp = tempfile::tempdir().unwrap();
    let cwd = temp.path().to_path_buf();
    let snapshot = ApprovalSnapshot {
        binary: "sh".to_string(),
        args: vec!["-c".to_string(), "printf approved".to_string()],
        cwd: Some(cwd.clone()),
        env: BTreeMap::new(),
        secret_keys: BTreeMap::new(),
        session_fingerprint: None,
        session_revision: None,
        secret_entitlements: None,
        secret_file_keys: BTreeMap::new(),
        verb_name: None,
        verb_params: BTreeMap::new(),
        catalog_version: None,
        verb_digest: None,
        verb_composition_digest: None,
        access_verbs: Vec::new(),
        access_requests: Vec::new(),
        principal: agent.principal(),
        secret_binding: None,
    };
    drop(temp);

    let result = execute_snapshot(&cfg, &snapshot, "operator approved").await;

    match result.exec {
        ExecOutcome::Failed {
            started, reason, ..
        } => {
            assert!(!started);
            assert!(
                reason.contains("working directory")
                    && reason.contains("changed before exec")
                    && reason.contains(cwd.to_str().unwrap()),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected stale cwd rejection, got {other:?}"),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn approved_snapshot_rejects_retargeted_snapshotted_cwd_before_exec() {
    let (cfg, _, agent) = gating_config(7018, 1000);
    let parent = tempfile::tempdir().unwrap();
    let approved = parent.path().join("approved");
    let retargeted = parent.path().join("retargeted");
    std::fs::create_dir(&approved).unwrap();
    std::fs::create_dir(&retargeted).unwrap();
    let cwd = approved.canonicalize().unwrap();
    let snapshot = ApprovalSnapshot {
        binary: "sh".to_string(),
        args: vec!["-c".to_string(), "printf approved".to_string()],
        cwd: Some(cwd.clone()),
        env: BTreeMap::new(),
        secret_keys: BTreeMap::new(),
        session_fingerprint: None,
        session_revision: None,
        secret_entitlements: None,
        secret_file_keys: BTreeMap::new(),
        verb_name: None,
        verb_params: BTreeMap::new(),
        catalog_version: None,
        verb_digest: None,
        verb_composition_digest: None,
        access_verbs: Vec::new(),
        access_requests: Vec::new(),
        principal: agent.principal(),
        secret_binding: None,
    };

    std::fs::remove_dir(&approved).unwrap();
    std::os::unix::fs::symlink(&retargeted, &approved).unwrap();

    let result = execute_snapshot(&cfg, &snapshot, "operator approved").await;

    match result.exec {
        ExecOutcome::Failed {
            started, reason, ..
        } => {
            assert!(!started);
            assert!(
                reason.contains("working directory")
                    && reason.contains("changed before exec")
                    && reason.contains(cwd.to_str().unwrap()),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected retargeted cwd rejection, got {other:?}"),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn provisional_revert_executes_in_snapshotted_cwd() {
    let (cfg, _operator, agent) = gating_config(7017, 1000);
    let temp = tempfile::tempdir().unwrap();
    let provisional = Provisional {
        handle: "cwd-revert".to_string(),
        principal: agent.principal(),
        requester_principal: None,
        binary: "true".to_string(),
        args: Vec::new(),
        cwd: Some(temp.path().to_path_buf()),
        secret_keys: BTreeMap::new(),
        secret_file_keys: BTreeMap::new(),
        revert_binary: "sh".to_string(),
        revert_args: vec![
            "-c".to_string(),
            "printf reverted > provisional-cwd.txt".to_string(),
        ],
        confirm_check_binary: None,
        confirm_check_args: Vec::new(),
        control_path: None,
        session_fingerprint: None,
        session_revision: None,
        secret_entitlements: None,
        api_revert: None,
        reason: "cwd revert".to_string(),
        decision_trace: None,
        created_unix: now_unix(),
        deadline_unix: now_unix(),
        window_secs: 0,
        auto_reverted_unix: None,
        forward_done: true,
        forward_exit: Some(0),
        forward_persistence_failed: false,
        status: ProvisionalStatus::Reverting,
        revert_exit: None,
        revert_detail: None,
    };
    cfg.state
        .provisional
        .write()
        .await
        .insert(provisional.clone());

    let (_message, exit) = finish_revert(&cfg, &provisional, &agent, "test").await;

    assert_eq!(exit, Some(0));
    assert_eq!(
        std::fs::read_to_string(temp.path().join("provisional-cwd.txt")).unwrap(),
        "reverted"
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
        1_700_000_300,
        300,
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
    let response = r.into_response();
    assert_eq!(response.auto_revert_durable, Some(true));
    assert_eq!(response.confirm_deadline_unix, Some(1_700_000_300));
    assert_eq!(response.confirm_window_secs, Some(300));
}
