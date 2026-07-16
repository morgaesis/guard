#[cfg(windows)]
use crate::server::gate_runtime::reconstruct_caller;
#[cfg(windows)]
use crate::server::transport::winplat;
use crate::server::wire::{CallerIdentity, ExecOutcome, ExecuteResult, IncomingMessage};
#[cfg(windows)]
use guard::principal::PrincipalKey;

/// `IncomingMessage` is untagged, and a bare execute request must resolve to
/// the Execute variant.
#[test]
fn execute_wire_shape_parses_to_execute_variant() {
    let msg: IncomingMessage =
        serde_json::from_str(r#"{"binary":"ls","args":["-l"]}"#).expect("execute parses");
    assert!(matches!(msg, IncomingMessage::Execute(_)));
}

#[test]
fn session_scoped_public_rpcs_carry_distinct_owner_bearers() {
    let batch = crate::server::wire::AdminRequest::EvaluateBatch {
        session_token: Some("target".to_string()),
        caller_token: Some("owner".to_string()),
        commands: vec![guard::wire::BatchCommand {
            binary: "true".to_string(),
            args: Vec::new(),
            env: std::collections::HashMap::new(),
            secrets: std::collections::HashMap::new(),
            secret_files: std::collections::HashMap::new(),
            cwd: None,
        }],
    };
    assert!(!batch.requires_daemon_uid());
    let json = serde_json::to_value(&batch).unwrap();
    assert_eq!(json["session_token"], "target");
    assert_eq!(json["caller_token"], "owner");

    let submit = crate::server::wire::AdminRequest::GrantRequestSubmit {
        session_token: "target".to_string(),
        caller_token: Some("owner".to_string()),
        saved_grant: None,
        prompt: "request".to_string(),
        delta: Default::default(),
    };
    assert!(!submit.requires_daemon_uid());

    let list = crate::server::wire::AdminRequest::GrantRequestList {
        session_token: Some("target".to_string()),
        caller_token: Some("owner".to_string()),
    };
    assert!(!list.requires_daemon_uid());
    let json = serde_json::to_value(&list).unwrap();
    assert_eq!(json["session_token"], "target");
    assert_eq!(json["caller_token"], "owner");
}

// ---- Audit-line redaction helpers ---------------------------------------

/// Argv rendered into audit lines must have inline credentials masked:
/// the log records the command shape, never the secret values.
#[test]
fn execute_result_denied_has_denied_policy_and_not_attempted_exec() {
    let r = ExecuteResult::denied("nope");
    assert!(!r.policy_allowed());
    assert_eq!(r.policy_reason(), "nope");
    assert!(matches!(r.exec, ExecOutcome::NotAttempted));
}

#[test]
fn execute_response_carries_stable_decision_source_and_trace() {
    let response = ExecuteResult::denied("invalid")
        .with_decision_source(crate::session::SessionDecisionSource::Validation)
        .into_response();
    assert_eq!(response.decision_source, "validation");
    assert_eq!(
        response.decision_trace.as_ref().map(|trace| trace.version),
        Some(guard::gating::DecisionTrace::VERSION)
    );
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
