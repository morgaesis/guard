#[cfg(windows)]
use crate::server::gate_runtime::reconstruct_caller;
#[cfg(windows)]
use crate::server::transport::winplat;
use crate::server::wire::{
    authorize_session_use, CallerIdentity, ContainmentFailureKind, ContainmentOutcome, ExecOutcome,
    ExecuteResult, ExecuteStreamMessage, IncomingMessage, SessionAuthz, EXECUTE_FEATURE_LOCAL_CWD,
    EXECUTE_PROTOCOL_VERSION,
};
use crate::session::SessionOwner;
use guard::principal::PrincipalKey;

/// `IncomingMessage` is untagged, and a versioned execute envelope resolves to
/// the Execute variant.
#[test]
fn execute_wire_shape_parses_to_execute_variant() {
    let msg: IncomingMessage = serde_json::from_value(serde_json::json!({
        "protocol_version": EXECUTE_PROTOCOL_VERSION,
        "features": [EXECUTE_FEATURE_LOCAL_CWD],
        "execute": {
            "binary": "ls",
            "args": ["-l"],
            "cwd": "/fixture"
        }
    }))
    .expect("execute parses");
    assert!(matches!(msg, IncomingMessage::Execute { .. }));
}

#[test]
fn remaining_session_scoped_batch_read_carries_distinct_owner_bearers() {
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
    assert!(!batch.requires_admin_token());
    let json = serde_json::to_value(&batch).unwrap();
    assert_eq!(json["session_token"], "target");
    assert_eq!(json["caller_token"], "owner");
}

#[test]
fn legacy_authority_operations_are_not_wire_protocol_variants() {
    for json in [
        r#"{"op":"session_grant","token":"chosen"}"#,
        r#"{"op":"session_extend","token":"chosen","ttl_secs":3600}"#,
        r#"{"op":"grant_request_submit","session_token":"chosen","prompt":"hidden","delta":{"secret_names":["credential"]}}"#,
        r#"{"op":"grant_request_list","session_token":"chosen","caller_token":"owner"}"#,
        r#"{"op":"grant_request_show","handle":"gr-example","session_token":"chosen"}"#,
        r#"{"op":"saved_grant_edit","name":"hidden"}"#,
    ] {
        assert!(
            serde_json::from_str::<crate::server::wire::AdminRequest>(json).is_err(),
            "legacy authority mutation unexpectedly parsed: {json}"
        );
    }
}

#[test]
fn access_wire_shapes_are_stable_and_requester_is_not_caller_selected() {
    let request = crate::server::wire::AdminRequest::AccessRequest {
        intent: "Inspect fixture".to_string(),
    };
    assert!(!request.requires_admin_token());
    let json = serde_json::to_value(&request).unwrap();
    assert_eq!(json["intent"], "Inspect fixture");
    assert!(json.get("requester").is_none());
    assert!(json.get("owner").is_none());

    let item = crate::server::wire::AccessItem {
        reference: "gr-example".to_string(),
        kind: "request".to_string(),
        requester: "1001".to_string(),
        target: "agent:1001".to_string(),
        effective_scope: vec!["inspect".to_string()],
        expires_unix: Some(123),
        remaining_uses: Some(1),
        use_policy: "not-yet-granted".to_string(),
        consequence: crate::server::wire::CONSEQUENCE_GRANT.to_string(),
        default_use_policy: Some("unlimited".to_string()),
        default_uses: None,
        state: "pending".to_string(),
        next_action: "guard access approve gr-example".to_string(),
        approval_options: Vec::new(),
        intent: Some("Inspect fixture".to_string()),
        capabilities: Vec::new(),
        decided_reason: None,
    };
    let json = serde_json::to_value(item).unwrap();
    assert_eq!(json["reference"], "gr-example");
    assert_eq!(json["requester"], "1001");
    assert_eq!(json["remaining_uses"], 1);
    assert!(json.get("session_token").is_none());
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
fn structured_guidance_preserves_access_commands_and_coverage_detail() {
    let response = ExecuteResult::denied("missing authority")
        .with_verb_resolution(
            Vec::new(),
            Some("approve: guard access approve gr-example --once".to_string()),
        )
        .with_verb_resolution(Vec::new(), Some("coverage conflict".to_string()))
        .with_access_request(Some("gr-example".to_string()))
        .into_response();
    assert_eq!(
        response.verb_guidance.as_deref(),
        Some("approve: guard access approve gr-example --once\ncoverage conflict")
    );
    assert_eq!(response.handle.as_deref(), Some("gr-example"));
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
fn windows_system_operator_check_never_elevates_unix_or_tcp_callers() {
    assert!(!CallerIdentity::Unix { uid: 0 }.is_windows_system_operator());
    assert!(!CallerIdentity::Tcp {
        token: "S-1-5-18".into()
    }
    .is_windows_system_operator());
    assert!(!CallerIdentity::TcpAdmin {
        token: "S-1-5-18".into()
    }
    .is_windows_system_operator());
}

#[test]
fn daemon_principal_is_not_implicit_cross_session_authority() {
    let owner = SessionOwner::Principal(PrincipalKey::from_raw("principal:owner"));
    assert!(matches!(
        authorize_session_use(&owner, &CallerIdentity::Unix { uid: 777 }, false),
        SessionAuthz::Mismatch
    ));
    assert!(matches!(
        authorize_session_use(&owner, &CallerIdentity::UnixAdmin { uid: 777 }, false),
        SessionAuthz::Allowed
    ));
}

#[cfg(windows)]
#[test]
fn windows_system_sid_is_the_only_named_pipe_system_operator() {
    assert!(CallerIdentity::Windows {
        sid: "s-1-5-18".into()
    }
    .is_windows_system_operator());
    assert!(!CallerIdentity::Windows {
        sid: "S-1-5-19".into()
    }
    .is_windows_system_operator());

    let owner = SessionOwner::Principal(PrincipalKey::from_raw("principal:owner"));
    let system = CallerIdentity::Windows {
        sid: "S-1-5-18".into(),
    };
    assert!(matches!(
        authorize_session_use(&owner, &system, false),
        SessionAuthz::Mismatch
    ));
    assert!(matches!(
        authorize_session_use(&owner, &system, true),
        SessionAuthz::Allowed
    ));
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

#[test]
fn containment_failure_is_parseable_by_origin_main_clients_in_both_response_shapes() {
    let response = ExecuteResult::completed("approved", Some(0), None, None)
        .containment_failed(
            "command executed, but durable containment state was unavailable",
            Some("containment-handle".to_string()),
            guard::gating::Coverage::contain(),
            ContainmentOutcome::PersistenceFailure {
                command_started: true,
                forward_exit_code: Some(0),
            },
            Some(0),
            None,
            None,
        )
        .into_response();

    assert!(!response.allowed);
    assert_eq!(response.status, None);
    assert_eq!(response.auto_revert_durable, Some(false));
    let failure = response
        .containment_failure
        .as_ref()
        .expect("typed failure detail");
    assert_eq!(failure.kind, ContainmentFailureKind::PersistenceFailure);
    assert!(failure.command_may_have_run);
    assert_eq!(failure.forward_exit_code, Some(0));

    #[allow(dead_code)]
    #[derive(Debug, serde::Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum LegacyGateStatus {
        Executed,
        Provisional,
        Held,
        Reverted,
        DryRun,
    }

    #[allow(dead_code)]
    #[derive(Debug, serde::Deserialize)]
    struct LegacyResponse {
        allowed: bool,
        reason: String,
        exit_code: Option<i32>,
        status: Option<LegacyGateStatus>,
        handle: Option<String>,
    }

    #[allow(dead_code)]
    #[derive(Debug, serde::Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    enum LegacyStreamMessage {
        Stdout { data: String },
        Stderr { data: String },
        PolicyDecision { allowed: bool, reason: String },
        Keepalive,
        Result { response: LegacyResponse },
    }

    let json = serde_json::to_value(&response).expect("response serializes");
    assert_eq!(json["containment_failure"]["kind"], "persistence_failure");
    let legacy: LegacyResponse = serde_json::from_value(json).expect("origin/main response parses");
    assert!(!legacy.allowed);
    assert!(legacy.status.is_none());
    assert_eq!(legacy.handle.as_deref(), Some("containment-handle"));

    let stream = ExecuteStreamMessage::Result { response };
    let legacy_stream: LegacyStreamMessage =
        serde_json::from_value(serde_json::to_value(stream).expect("stream response serializes"))
            .expect("origin/main streaming response parses");
    let LegacyStreamMessage::Result { response } = legacy_stream else {
        panic!("expected streaming result");
    };
    assert!(!response.allowed);
    assert!(response.status.is_none());
    assert_eq!(response.handle.as_deref(), Some("containment-handle"));
}

// ---- Audit emission end-to-end tests ------------------------------------
