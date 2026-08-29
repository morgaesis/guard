use super::*;
use crate::MainArgs;
use clap::Parser;

fn config_with(socket: Option<&str>, port: Option<u16>) -> client_config::ClientConfig {
    client_config::ClientConfig {
        server_socket: socket.map(str::to_string),
        server_tcp_port: port,
        ..Default::default()
    }
}

fn parsed_run_socket(args: &[&str]) -> Option<String> {
    match MainArgs::try_parse_from(args).expect("parse guard run") {
        MainArgs::Run { socket, .. } => socket,
        _ => panic!("expected run command"),
    }
}

#[test]
fn run_parses_explicit_socket_override() {
    assert_eq!(
        parsed_run_socket(&[
            "guard",
            "run",
            "--socket",
            "/run/guard/alternate.sock",
            "echo",
            "ok",
        ]),
        Some("/run/guard/alternate.sock".to_string())
    );
}

#[test]
fn mcp_resolves_only_the_execution_token() {
    let config = client_config::ClientConfig {
        auth_token: Some("configured-exec".to_string()),
        admin_token: Some("configured-admin".to_string()),
        ..Default::default()
    };
    let auth_token = resolve_mcp_daemon_token(&config);
    assert_eq!(auth_token.as_deref(), Some("configured-exec"));
}

#[test]
fn verb_mutation_client_carries_the_configured_admin_bearer() {
    let config = client_config::ClientConfig {
        admin_token: Some("configured-admin".to_string()),
        ..Default::default()
    };
    let client = admin_client(None, Some(7331), &config);
    assert!(client.has_admin_token());
}

#[test]
fn requester_verb_show_has_stable_human_and_json_menu_projections() {
    let item = server::VerbMenuItem {
        name: "inspect-fixture".to_string(),
        description: "Inspect one fixture".to_string(),
        params: vec!["target".to_string()],
        consequence: "reversible".to_string(),
        hold: false,
        has_revert: false,
    };
    assert_eq!(
        verb_menu_human_lines(&item),
        vec![
            "inspect-fixture [reversible] - Inspect one fixture".to_string(),
            "    --param target=<value>".to_string(),
        ]
    );
    let document = verb_show_menu_json(&item);
    assert_eq!(document["schema_version"], JSON_SCHEMA_VERSION);
    assert_eq!(document["type"], "verb_show");
    assert_eq!(document["projection"], "agent_menu");
    assert_eq!(document["item"]["name"], "inspect-fixture");
    assert!(document["item"].get("binary").is_none());
}

#[test]
fn requester_verb_show_negotiates_old_daemons_without_operator_authority() {
    let requester = daemon_client::Client::new(None, Some(7331));
    assert!(requester_verb_show_requires_capability(&requester));
    let error = validate_daemon_capability(
        "0.8.0",
        &[],
        "guard verb show",
        server::CAPABILITY_REQUESTER_VERB_SHOW_V1,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("unavailable on Guard daemon 0.8.0"));
    assert!(error.contains("upgrade and restart the daemon"));

    let operator = requester.with_admin_token("configured-admin".to_string());
    assert!(!requester_verb_show_requires_capability(&operator));
}

#[test]
fn unix_operator_guidance_uses_the_packaged_wrapper() {
    #[cfg(unix)]
    {
        assert_eq!(
            operator_confirm_command("pv-1"),
            "sudo guard-operator confirm pv-1"
        );
        assert_eq!(
            operator_revert_command("pv-1"),
            "sudo guard-operator revert pv-1"
        );
    }
}

#[test]
fn access_whoami_negotiates_an_explicit_daemon_capability() {
    assert!(validate_daemon_capability(
        "compatible-version",
        &[server::CAPABILITY_ACCESS_WHOAMI_V1.to_string()],
        "guard access whoami",
        server::CAPABILITY_ACCESS_WHOAMI_V1,
    )
    .is_ok());
    let error = validate_daemon_capability(
        "0.8.0",
        &[],
        "guard access whoami",
        server::CAPABILITY_ACCESS_WHOAMI_V1,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("unavailable on Guard daemon 0.8.0"));
    assert!(error.contains("upgrade and restart the daemon"));
}

#[test]
fn resume_json_shape_contains_the_execution_result() {
    let document = resume_json_response(
        "hold-1",
        "resumed",
        Some(7),
        Some("saved stdout"),
        Some("saved stderr"),
    );
    assert_eq!(document["schema_version"], JSON_SCHEMA_VERSION);
    assert_eq!(document["type"], "resume_result");
    assert_eq!(document["handle"], "hold-1");
    assert_eq!(document["exit_code"], 7);
    assert_eq!(document["stdout"], "saved stdout");
    assert_eq!(document["stderr"], "saved stderr");
}

#[test]
fn client_config_errors_use_one_versioned_shape() {
    let document = client_config_error("malformed client configuration");
    assert_eq!(document["schema_version"], JSON_SCHEMA_VERSION);
    assert_eq!(document["type"], "client_config_error");
    assert_eq!(document["error"]["code"], "invalid_client_config");
    assert_eq!(
        document["error"]["message"],
        "malformed client configuration"
    );
    assert_eq!(document.as_object().map(serde_json::Map::len), Some(3));
}

#[test]
fn audit_tail_json_keeps_historical_secret_detail_redacted() {
    let marker = "synthetic-historical-secret-tail-marker";
    let historical = serde_json::json!({
        "v": 1,
        "seq": 23,
        "ts": 1_700_000_123,
        "prev_hash": "synthetic-previous-hash",
        "kind": "SECRET_EXPOSED",
        "handle": "synthetic-handle",
        "cmd": marker,
        "reason": marker,
        "fields": [["synthetic-secret-key", marker]],
    });

    let items = vec![historical]
        .into_iter()
        .map(guard::audit::redacted_read_projection)
        .collect::<Vec<_>>();
    let document = audit_tail_json_response("synthetic-audit-path", &items);
    let encoded = serde_json::to_string(&document).unwrap();

    assert!(!encoded.contains(marker));
    assert_eq!(document["items"][0]["seq"], 23);
    assert_eq!(document["items"][0]["ts"], 1_700_000_123);
    assert_eq!(document["items"][0]["kind"], "SECRET_EXPOSED");
    assert_eq!(document["items"][0]["prev_hash"], "synthetic-previous-hash");
    assert_eq!(document["items"][0]["fields"][0][0], "synthetic-secret-key");
    assert_eq!(
        document["items"][0]["read_projection"],
        "secret_exposure_detail_redacted"
    );
}

#[test]
fn denied_guidance_lists_every_durable_request_exactly() {
    let response = server::ExecuteResponse {
        allowed: false,
        reason: "access required".to_string(),
        exit_code: None,
        stdout: None,
        stderr: None,
        status: None,
        handle: Some("legacy-handle".to_string()),
        approval_options: vec!["legacy approval".to_string()],
        access_requests: vec![
            server::AccessRequestGuidance {
                reference: "gr-11111111111111111111111111111111".to_string(),
                approval_options: vec![
                    "guard access approve gr-11111111111111111111111111111111".to_string(),
                    "guard access approve gr-11111111111111111111111111111111 --once".to_string(),
                ],
            },
            server::AccessRequestGuidance {
                reference: "gr-22222222222222222222222222222222".to_string(),
                approval_options: vec![
                    "guard access approve gr-22222222222222222222222222222222 --uses 3".to_string(),
                ],
            },
        ],
        coverage: None,
        verb_matches: Vec::new(),
        verb_guidance: Some("request access".to_string()),
        confirm_deadline_unix: None,
        confirm_window_secs: None,
        auto_revert_durable: None,
        containment_failure: None,
        decision_source: "access_gate".to_string(),
        decision_trace: None,
    };

    assert_eq!(
        access_request_guidance_lines(&response),
        vec![
            "request: gr-11111111111111111111111111111111",
            "approve: guard access approve gr-11111111111111111111111111111111",
            "approve: guard access approve gr-11111111111111111111111111111111 --once",
            "inspect: guard access show gr-11111111111111111111111111111111",
            "request: gr-22222222222222222222222222222222",
            "approve: guard access approve gr-22222222222222222222222222222222 --uses 3",
            "inspect: guard access show gr-22222222222222222222222222222222",
        ]
    );
}

#[test]
fn requester_guidance_does_not_label_admin_handoff_as_an_approve_command() {
    let mut response = provisional_response(None, None);
    response.allowed = false;
    response.status = None;
    response.handle = Some("gr-requester".to_string());
    response.approval_options = vec![
        "ask your admin to approve request gr-requester (see guard access show gr-requester)"
            .to_string(),
    ];

    let lines = access_request_guidance_lines(&response);
    assert!(lines.contains(
        &"ask your admin to approve request gr-requester (see guard access show gr-requester)"
            .to_string()
    ));
    assert!(lines
        .iter()
        .all(|line| !line.contains("guard access approve")));
}

fn provisional_response(
    confirm_deadline_unix: Option<u64>,
    confirm_window_secs: Option<u64>,
) -> server::ExecuteResponse {
    server::ExecuteResponse {
        allowed: true,
        reason: "recoverable change".to_string(),
        exit_code: Some(0),
        stdout: None,
        stderr: None,
        status: Some(server::GateStatus::Provisional),
        handle: Some("pv-1".to_string()),
        approval_options: Vec::new(),
        access_requests: Vec::new(),
        coverage: None,
        verb_matches: Vec::new(),
        verb_guidance: None,
        confirm_deadline_unix,
        confirm_window_secs,
        auto_revert_durable: None,
        containment_failure: None,
        decision_source: "llm".to_string(),
        decision_trace: None,
    }
}

#[test]
fn the_provisional_banner_states_the_armed_deadline_and_how_to_change_it() {
    let lines = provisional_window_lines(&provisional_response(Some(1_700_000_300), Some(300)));
    assert_eq!(
        lines,
        vec![
            "result:  executed, auto-reverts in 300s (at 2023-11-14T22:18:20Z (1700000300)) \
                 unless confirmed"
                .to_string(),
            "window:  set with --confirm-within SECONDS".to_string(),
        ]
    );
}

#[test]
fn a_daemon_that_reports_no_deadline_keeps_the_deadline_free_wording() {
    for response in [
        provisional_response(None, None),
        provisional_response(Some(1_700_000_300), None),
        provisional_response(None, Some(300)),
    ] {
        let lines = provisional_window_lines(&response);
        assert_eq!(
            lines,
            vec!["result:  executed, auto-reverts unless confirmed".to_string()]
        );
    }
}

#[test]
fn held_banner_names_containment_only_when_the_server_reports_a_route() {
    let mut response = provisional_response(None, None);
    response.status = Some(server::GateStatus::Held);
    response.verb_guidance = Some(
            "ask your admin to approve request hold-1\ncontain: re-run with --revert '<cmd>' --confirm-within 300 to execute under auto-revert"
                .to_string(),
        );
    assert_eq!(
            held_discovery_lines(&response),
            vec![
                "contain: re-run with --revert '<cmd>' --confirm-within 300 to execute under auto-revert"
                    .to_string(),
                "inspect: guard provisionals".to_string(),
            ]
        );

    response.verb_guidance = Some("ask your admin to approve request hold-1".to_string());
    assert_eq!(
        held_discovery_lines(&response),
        vec!["inspect: guard provisionals".to_string()]
    );
}

#[test]
fn access_status_human_fields_render_entitlements_and_decision_trace() {
    assert_eq!(
        secret_entitlements_line(
            &["service/read".to_string(), "service/write".to_string()],
            "  "
        ),
        Some("  secret_names: service/read,service/write".to_string())
    );

    let trace = guard::gating::DecisionTrace {
        version: guard::gating::DecisionTrace::VERSION,
        decision_source: "session_allow".to_string(),
        verb_matches: vec![guard::gating::DecisionVerbMatch {
            verb: "restart-service".to_string(),
            cell: "restart".to_string(),
            scope: "session".to_string(),
            action: "evaluate".to_string(),
            features: Vec::new(),
            selected: true,
            overridden: true,
        }],
        failed_dimensions: Vec::new(),
        conflict: None,
        guidance: None,
        suggested_grant_delta: Some("grant restart-service".to_string()),
    };

    assert_eq!(
        decision_trace_human_lines(Some(&trace), "    "),
        vec![
            "    verb_matches: restart-service/restart (session/evaluate, selected, overridden)"
                .to_string(),
            "    suggested_grant_delta: grant restart-service".to_string(),
        ]
    );
}

#[test]
fn provisional_human_output_includes_secret_names_when_present() {
    let provisional = server::ProvisionalSummary {
        handle: "pv-1".to_string(),
        status: "armed".to_string(),
        forward_outcome: "completed".to_string(),
        command: "servicectl restart app".to_string(),
        revert_command: "servicectl rollback app".to_string(),
        confirm_check: None,
        control_path: None,
        session_fingerprint: None,
        reason: "recoverable change".to_string(),
        created_unix: 1_700_000_000,
        deadline_unix: 1_700_000_300,
        forward_done: true,
        cwd: None,
        secret_names: vec!["service/read".to_string(), "service/write".to_string()],
        principal: None,
        revert_exit: None,
        revert_detail: None,
        decision_trace: None,
    };

    let line = provisional_human_line(&provisional, false);
    assert!(
        line.contains("secret_names: service/read,service/write"),
        "{line}"
    );
}

#[test]
fn an_ambiguous_legacy_durability_flag_never_claims_an_armed_timer() {
    let mut response = provisional_response(None, None);
    response.auto_revert_durable = Some(false);
    assert_eq!(
        provisional_window_lines(&response),
        vec![
            "result:  containment outcome is not durably armed; operator decision required"
                .to_string()
        ]
    );
}

#[test]
fn a_forward_nonzero_exit_has_failure_wording_separate_from_persistence_loss() {
    let mut response = provisional_response(None, None);
    response.exit_code = Some(17);
    response.status = None;
    response.containment_failure = Some(server::ContainmentFailure {
        kind: server::ContainmentFailureKind::ForwardNonzeroExit,
        command_may_have_run: true,
        forward_exit_code: Some(17),
    });
    assert_eq!(
            provisional_window_lines(&response),
            vec![
                "result:  forward command failed with exit code 17; auto-revert was not armed; operator decision required"
                    .to_string()
            ]
        );
}

#[test]
fn a_signal_forward_failure_has_no_exit_code_wording() {
    let mut response = provisional_response(None, None);
    response.exit_code = None;
    response.status = None;
    response.containment_failure = Some(server::ContainmentFailure {
        kind: server::ContainmentFailureKind::ForwardNoExitCode,
        command_may_have_run: true,
        forward_exit_code: None,
    });
    assert_eq!(
            provisional_window_lines(&response),
            vec![
                "result:  forward command ended without an exit code; auto-revert was not armed; operator decision required"
                    .to_string()
            ]
        );
}

#[test]
fn a_durability_failure_reports_whether_forward_started() {
    let mut response = provisional_response(None, None);
    response.status = None;
    response.containment_failure = Some(server::ContainmentFailure {
        kind: server::ContainmentFailureKind::PersistenceFailure,
        command_may_have_run: false,
        forward_exit_code: None,
    });
    assert_eq!(
            provisional_window_lines(&response),
            vec![
                "result:  containment failed before forward execution because durable rollback state was unavailable"
                    .to_string()
            ]
        );
}

#[test]
fn a_signal_plus_durability_failure_preserves_both_facts() {
    let mut response = provisional_response(None, None);
    response.exit_code = None;
    response.status = None;
    response.containment_failure = Some(server::ContainmentFailure {
        kind: server::ContainmentFailureKind::PersistenceFailure,
        command_may_have_run: true,
        forward_exit_code: None,
    });
    assert_eq!(
            provisional_window_lines(&response),
            vec![
                "result:  forward command ended without an exit code, and its durable outcome could not be recorded; auto-revert was not armed; operator decision required"
                    .to_string()
            ]
        );
}

fn denied_response(decision_source: &str) -> server::ExecuteResponse {
    server::ExecuteResponse {
        allowed: false,
        reason: "rejected".to_string(),
        exit_code: None,
        stdout: None,
        stderr: None,
        status: None,
        handle: None,
        approval_options: Vec::new(),
        access_requests: Vec::new(),
        coverage: None,
        verb_matches: Vec::new(),
        verb_guidance: None,
        confirm_deadline_unix: None,
        confirm_window_secs: None,
        auto_revert_durable: None,
        containment_failure: None,
        decision_source: decision_source.to_string(),
        decision_trace: None,
    }
}

#[test]
fn every_deny_source_renders_a_distinct_tag_and_appeal_route() {
    let rendered = [
        ("static_policy", "matched deny pattern: rm*"),
        ("static_policy", guard::policy::DEFAULT_DENY_REASON),
        ("learned_deny", "repeatedly denied shape"),
        ("llm", "destroys unbacked state"),
        ("cache", "destroys unbacked state"),
        ("session_deny", "outside the session boundary"),
        ("evaluator_error", "evaluation error: upstream timeout"),
        ("validation", "cwd must be an absolute path"),
    ]
    .map(|(source, reason)| {
        let mut response = denied_response(source);
        response.reason = reason.to_string();
        deny_source_lines(&response).join("\n")
    });

    for (index, text) in rendered.iter().enumerate() {
        assert_eq!(text.lines().count(), 2, "{text}");
        for other in rendered.iter().skip(index + 1) {
            assert_ne!(text, other);
        }
    }

    let static_policy = &rendered[0];
    assert!(
        static_policy.contains("source:  static-policy"),
        "{static_policy}"
    );
    assert!(static_policy.contains("absolute"), "{static_policy}");

    let default_deny = &rendered[1];
    assert!(
        default_deny.contains("source:  static-default-deny"),
        "{default_deny}"
    );
    assert!(
        default_deny.contains("guard access request"),
        "{default_deny}"
    );

    let learned = &rendered[2];
    assert!(learned.contains("source:  learned-deny"), "{learned}");
    assert!(learned.contains("--reevaluate"), "{learned}");

    let evaluator = &rendered[3];
    assert!(evaluator.contains("source:  evaluator"), "{evaluator}");
    assert!(evaluator.contains("guard access request"), "{evaluator}");
}

#[test]
fn similar_denial_count_does_not_masquerade_as_a_learned_deny_match() {
    let mut response = denied_response("llm");
    response.reason = "destructive request\nthis denial came from evaluator judgment; no learned deny shape decided this command. Guard has recorded 2 similar echo denials".to_string();

    let text = deny_source_lines(&response).join("\n");
    assert!(text.contains("source:  evaluator"), "{text}");
    assert!(!text.contains("source:  learned-deny"), "{text}");
    assert!(text.contains("evaluator judgment"), "{text}");
}

#[test]
fn only_a_matched_policy_deny_rule_is_described_as_absolute() {
    let appealable = [
        ("static_policy", guard::policy::DEFAULT_DENY_REASON),
        (
            "static_policy",
            guard::policy::NO_DECIDER_DEFAULT_DENY_REASON,
        ),
        ("learned_deny", "repeatedly denied shape"),
        ("llm", "destroys unbacked state"),
        ("cache", "destroys unbacked state"),
        ("session_deny", "outside the session boundary"),
        ("session_static_only", "outside the session boundary"),
        ("evaluator_error", "evaluation error: upstream timeout"),
        ("validation", "cwd must be an absolute path"),
        ("api_proxy", "protocol hard-deny"),
    ];
    for (source, reason) in appealable {
        let mut response = denied_response(source);
        response.reason = reason.to_string();
        let text = deny_source_lines(&response).join("\n");
        assert!(!text.contains("absolute"), "{source}: {text}");
        assert!(!text.contains("unappealable"), "{source}: {text}");
    }
}

#[test]
fn a_default_deny_keeps_its_tag_once_the_daemon_appends_request_context() {
    let mut response = denied_response("static_policy");
    let request_reference = ["gr", "fixture"].join("-");
    response.reason = format!(
        "{}; access_request={request_reference}",
        guard::policy::DEFAULT_DENY_REASON
    );
    assert_eq!(
        deny_source_lines(&response)[0],
        "source:  static-default-deny"
    );
}

#[test]
fn an_unknown_deny_source_still_reports_its_tag() {
    let lines = deny_source_lines(&denied_response("api_proxy"));
    assert_eq!(lines, vec!["source:  api-proxy".to_string()]);
}
#[test]
fn access_json_errors_use_one_versioned_shape() {
    for message in [
        "daemon unavailable",
        "invalid daemon response",
        "request rejected",
        "unexpected access response",
    ] {
        let document = access_json_error(message);
        assert_eq!(document["schema_version"], JSON_SCHEMA_VERSION);
        assert_eq!(document["type"], "access_error");
        assert_eq!(document["error"], message);
        assert_eq!(document.as_object().map(serde_json::Map::len), Some(3));
    }
}

#[test]
fn access_json_response_rejects_daemon_errors_and_unexpected_variants() {
    let error = access_json_response(&server::AdminResponse::Error {
        message: "denied by daemon".to_string(),
    })
    .unwrap_err();
    assert_eq!(error, "denied by daemon");

    let error = access_json_response(&server::AdminResponse::Ok).unwrap_err();
    assert!(error.starts_with("unexpected access response:"));
}

#[test]
fn access_json_batch_is_one_document_and_any_failed_item_sets_exit_status() {
    let response = server::AdminResponse::AccessDecisions {
        items: vec![
            server::AccessDecisionResult {
                request: "request-ok".to_string(),
                success: true,
                state: "approved".to_string(),
                target: Some("session:one".to_string()),
                remaining_uses: Some(1),
                use_policy: "bounded".to_string(),
                consequence: server::CONSEQUENCE_GRANT.to_string(),
                message: "approved".to_string(),
            },
            server::AccessDecisionResult {
                request: "hold-failed".to_string(),
                success: false,
                state: "failed".to_string(),
                target: None,
                remaining_uses: None,
                use_policy: "unavailable".to_string(),
                consequence: String::new(),
                message: "not found".to_string(),
            },
        ],
        wait: None,
    };
    let document = access_json_response(&response).unwrap();
    assert_eq!(document["schema_version"], JSON_SCHEMA_VERSION);
    assert_eq!(document["type"], "access_decisions");
    assert_eq!(
        document["response"]["items"].as_array().map(Vec::len),
        Some(2)
    );
    assert_eq!(document["response"]["items"][1]["consequence"], "arm");
    assert_eq!(
        document["response"]["items"][1]["consequence_source"],
        LEGACY_CONSEQUENCE_SOURCE
    );
    assert!(access_decision_failed(&response));

    let all_failed = server::AdminResponse::AccessDecisions {
        items: vec![server::AccessDecisionResult {
            request: "request-failed".to_string(),
            success: false,
            state: "failed".to_string(),
            target: None,
            remaining_uses: None,
            use_policy: "unavailable".to_string(),
            consequence: String::new(),
            message: "not found".to_string(),
        }],
        wait: None,
    };
    assert!(access_decision_failed(&all_failed));

    let all_succeeded = server::AdminResponse::AccessDecisions {
        items: vec![server::AccessDecisionResult {
            request: "request-ok".to_string(),
            success: true,
            state: "approved".to_string(),
            target: Some("session:one".to_string()),
            remaining_uses: None,
            use_policy: "unlimited".to_string(),
            consequence: server::CONSEQUENCE_GRANT.to_string(),
            message: "approved".to_string(),
        }],
        wait: None,
    };
    assert!(!access_decision_failed(&all_succeeded));
}

#[test]
fn legacy_consequence_fallback_never_infers_release() {
    for (reference, expected) in [("gr-legacy", "grant"), ("hold-legacy", "arm")] {
        let mut value = serde_json::json!({
            "reference": reference,
            "consequence": ""
        });
        normalize_legacy_consequence_json(&mut value);
        assert_eq!(value["consequence"], expected);
        assert_eq!(value["consequence_source"], LEGACY_CONSEQUENCE_SOURCE);
        assert_ne!(value["consequence"], "release");
    }

    let mut explicit = serde_json::json!({
        "reference": "hold-explicit",
        "consequence": "release"
    });
    normalize_legacy_consequence_json(&mut explicit);
    assert_eq!(explicit["consequence"], "release");
    assert!(explicit.get("consequence_source").is_none());
}

#[test]
fn verb_create_rejection_extracts_only_gate_complaints() {
    assert_eq!(
        verb_create_rejection(
            "synthesized verb rejected by the safety gate: parameter 'x' is too permissive"
        ),
        Some("parameter 'x' is too permissive")
    );
    assert_eq!(
            verb_create_rejection(
                "synthesized verb rejected by validation: verb 'x' declares parameter 'op' but no template references {op}"
            ),
            Some("verb 'x' declares parameter 'op' but no template references {op}")
        );
    assert_eq!(
        verb_create_rejection("previewed verb rejected by the safety gate: shape changed"),
        Some("shape changed")
    );
    // Operational failures never trigger a re-synthesis.
    assert_eq!(verb_create_rejection("verb synthesis failed: no key"), None);
    assert_eq!(
        verb_create_rejection("verb create requires non-empty --prompt prose"),
        None
    );
}

#[test]
fn verb_create_choice_accepts_create_and_quit_spellings() {
    for input in ["c", "C", "create", "y", "yes", " c \n"] {
        assert_eq!(
            parse_verb_create_choice(input),
            Some(true),
            "input {input:?}"
        );
    }
    for input in ["q", "quit", "n", "no"] {
        assert_eq!(
            parse_verb_create_choice(input),
            Some(false),
            "input {input:?}"
        );
    }
    for input in ["", "maybe", "cq"] {
        assert_eq!(parse_verb_create_choice(input), None, "input {input:?}");
    }
}

#[test]
fn access_review_choice_accepts_short_long_and_yes_no_spellings() {
    for input in ["a", "A", "approve", "y", "yes", " a \n"] {
        assert_eq!(
            parse_access_review_choice(input),
            Some(AccessReviewChoice::Approve),
            "input {input:?}"
        );
    }
    for input in ["d", "deny", "n", "no"] {
        assert_eq!(
            parse_access_review_choice(input),
            Some(AccessReviewChoice::Deny),
            "input {input:?}"
        );
    }
    assert_eq!(
        parse_access_review_choice("s"),
        Some(AccessReviewChoice::Skip)
    );
    assert_eq!(
        parse_access_review_choice("quit"),
        Some(AccessReviewChoice::Quit)
    );
    for input in ["", "maybe", "ad", "--once"] {
        assert_eq!(parse_access_review_choice(input), None, "input {input:?}");
    }
}

fn helm_upgrade_capability() -> server::AccessCapability {
    server::AccessCapability {
        verb: "helm-upgrade".to_string(),
        description: "Upgrades one Helm release in the monitoring namespace.".to_string(),
        matcher: serde_json::json!({
            "binary": "helm",
            "args": [
                "upgrade",
                "{release}",
                "monitoring/{chart}",
                "--namespace",
                "monitoring"
            ],
            "params": {
                "release": {"pattern": "^(netdata|loki)$"},
                "chart": {"pattern": "^netdata$"}
            },
            "coverage": [{"name": "upgrade", "action": "evaluate"}]
        }),
        matcher_digest: "digest".to_string(),
        consequence: "recoverable".to_string(),
        credential_plan: None,
        baseline: false,
        trusted: false,
        has_revert: true,
        evidence: Some("rollback validated".to_string()),
    }
}

fn pending_access_item(capabilities: Vec<server::AccessCapability>) -> server::AccessItem {
    server::AccessItem {
        reference: "gr-11111111111111111111111111111111".to_string(),
        kind: "request".to_string(),
        requester: "uid:1004".to_string(),
        target: "agent:1004".to_string(),
        effective_scope: vec!["helm-upgrade".to_string()],
        expires_unix: Some(1_753_000_000),
        remaining_uses: None,
        use_policy: "unselected".to_string(),
        consequence: server::CONSEQUENCE_GRANT.to_string(),
        default_use_policy: Some("unlimited".to_string()),
        default_uses: None,
        state: "pending".to_string(),
        next_action: "approve or deny".to_string(),
        approval_options: vec![
            "guard access approve gr-11111111111111111111111111111111".to_string()
        ],
        intent: Some("upgrade the netdata release".to_string()),
        capabilities,
        decided_reason: None,
    }
}

#[test]
fn access_item_card_renders_the_matcher_as_the_command_line_it_admits() {
    let item = pending_access_item(vec![helm_upgrade_capability()]);
    let card = access_item_card(&item, false).join("\n");
    assert!(!card.contains('\u{1b}'), "colors off must emit no ANSI");
    for fact in [
        "access request gr-11111111111111111111111111111111",
        "state:     pending",
        "requester: uid:1004",
        "intent:    upgrade the netdata release",
        "uses:      unlimited (default; --once or --uses N to bound the approval)",
        "recoverable helm-upgrade trusted=false revert=available",
        "description: Upgrades one Helm release in the monitoring namespace.",
        "command: helm upgrade <release> monitoring/<chart> --namespace monitoring",
        "param chart: ^netdata$ -> fixed value \"netdata\"",
        "param release: ^(netdata|loki)$ -> one of \"netdata\", \"loki\"",
        "coverage: upgrade (evaluate)",
        "matcher_digest: digest",
        "evidence: rollback validated",
        "next:      approve or deny",
        "approval:  guard access approve gr-11111111111111111111111111111111",
    ] {
        assert!(card.contains(fact), "card is missing {fact:?}:\n{card}");
    }
    assert!(
        !card.contains("matcher: {"),
        "the approval card must not fall back to raw matcher JSON:\n{card}"
    );
    let colored = access_item_card(&item, true).join("\n");
    assert!(colored.contains('\u{1b}'), "colors on must emit ANSI");
}

#[test]
fn access_show_keeps_raw_matcher_json_behind_the_flag() {
    let item = pending_access_item(vec![helm_upgrade_capability()]);
    let readable = access_item_human(&item, false);
    assert!(
        !readable.contains("matcher: {"),
        "the default rendering must not print the matcher blob:\n{readable}"
    );
    assert!(
        readable.contains("command: helm upgrade <release> monitoring/<chart>"),
        "the default rendering must show the admitted command:\n{readable}"
    );
    let raw = access_item_human(&item, true);
    assert!(
        raw.contains("matcher: {\"args\":[\"upgrade\",\"{release}\""),
        "--raw must add the exact reviewed matcher:\n{raw}"
    );
    assert!(
        raw.contains("command: helm upgrade <release> monitoring/<chart>"),
        "--raw must keep the readable rendering:\n{raw}"
    );
}

#[test]
fn matcher_without_a_command_template_falls_back_to_the_raw_document() {
    assert_eq!(
        matcher_detail_lines(&serde_json::json!({"coverage": []}), "  "),
        None
    );
    let capability = server::AccessCapability {
        matcher: serde_json::json!({"coverage": []}),
        ..helm_upgrade_capability()
    };
    let lines = capability_detail_lines(&capability, "  ", false).join("\n");
    assert!(
        lines.contains("matcher: {\"coverage\":[]}"),
        "an unreadable matcher must still reach the operator verbatim:\n{lines}"
    );
    assert!(
        !lines.contains("command:"),
        "no command line can be claimed for a document that has none:\n{lines}"
    );
}

#[test]
fn pending_use_display_names_the_budget_a_bare_approve_grants() {
    let mut item = pending_access_item(Vec::new());
    assert_eq!(
        pending_use_display(&item),
        "unlimited (default; --once or --uses N to bound the approval)"
    );
    item.default_use_policy = Some("bounded".to_string());
    item.default_uses = Some(3);
    assert_eq!(
        pending_use_display(&item),
        "3 (default; --once or --uses N to change)"
    );
    item.default_uses = Some(1);
    assert_eq!(
        pending_use_display(&item),
        "1 (default; the only budget this request accepts)"
    );
    item.default_use_policy = None;
    item.default_uses = None;
    assert_eq!(pending_use_display(&item), "not selected until approval");
    item.use_policy = "bounded".to_string();
    item.remaining_uses = Some(2);
    assert_eq!(
        pending_use_display(&item),
        "2",
        "a decided item still reports its remaining budget verbatim"
    );
}

#[test]
fn pattern_readings_cover_literals_and_enumerations_only() {
    assert_eq!(
        describe_pattern("^monitoring$").as_deref(),
        Some("fixed value \"monitoring\"")
    );
    assert_eq!(
        describe_pattern("^(?:get|list)$").as_deref(),
        Some("one of \"get\", \"list\"")
    );
    assert_eq!(
        describe_pattern("^(single)$").as_deref(),
        Some("fixed value \"single\"")
    );
    // An unbounded or otherwise structured pattern gets no summary: a wrong
    // reading of what a grant admits is worse than the pattern itself.
    for pattern in ["^[a-z][a-z0-9-]{0,40}$", "^(deploy/[a-z-]+)$", "[a-z]+"] {
        assert_eq!(describe_pattern(pattern), None, "pattern {pattern:?}");
    }
}

#[test]
fn parameter_lines_carry_pattern_shape_and_admission_notes() {
    let spec: guard::gating::verb::ParamSpec = serde_json::from_value(serde_json::json!({
        "pattern": "^-o$",
        "required": false,
        "allow_dash": true,
        "value_type": "single_argv",
        "max_length": 64
    }))
    .unwrap();
    assert_eq!(
            param_display("flag", &spec),
            "flag: ^-o$ -> fixed value \"-o\" [optional; may begin with a dash; one argv element, up to 64 characters]"
        );
}

/// Baseline coverage applies without a session and carries no reviewed
/// matcher, so it names what it does and stops there. Rendering a matcher
/// for it would put a decision in front of an operator that no approval
/// ever asks for.
#[test]
fn baseline_capabilities_render_no_matcher_detail() {
    let capability = server::AccessCapability {
        baseline: true,
        ..helm_upgrade_capability()
    };
    for raw in [false, true] {
        let lines = capability_detail_lines(&capability, "  ", raw).join("\n");
        assert!(
            lines.contains("description: Upgrades one Helm release"),
            "baseline coverage still says what it does (raw={raw}):\n{lines}"
        );
        for absent in [
            "command:",
            "param ",
            "coverage:",
            "matcher:",
            "matcher_digest:",
        ] {
            assert!(
                !lines.contains(absent),
                "baseline coverage must not render {absent:?} (raw={raw}):\n{lines}"
            );
        }
    }
}

#[test]
fn placeholders_render_as_the_values_the_caller_supplies() {
    assert_eq!(
        placeholder_display("monitoring/{chart}"),
        "monitoring/<chart>"
    );
    assert_eq!(placeholder_display("--namespace"), "--namespace");
    assert_eq!(placeholder_display("{a}-{b}"), "<a>-<b>");
    assert_eq!(placeholder_display("{}"), "{}");
    assert_eq!(placeholder_display("{unclosed"), "{unclosed");
}

#[test]
fn access_item_card_escapes_control_characters_in_server_text() {
    let item = server::AccessItem {
        reference: "gr-22222222222222222222222222222222".to_string(),
        kind: "request".to_string(),
        requester: "uid:1004".to_string(),
        target: "agent:1004".to_string(),
        effective_scope: Vec::new(),
        expires_unix: None,
        remaining_uses: None,
        use_policy: "unselected".to_string(),
        consequence: server::CONSEQUENCE_GRANT.to_string(),
        default_use_policy: None,
        default_uses: None,
        state: "pending".to_string(),
        next_action: "approve or deny".to_string(),
        approval_options: vec!["\u{1b}[1A\u{1b}[2Kguard access approve x".to_string()],
        intent: Some("\u{1b}[2J\u{1b}[H\nintent:    read one log file".to_string()),
        capabilities: vec![server::AccessCapability {
            verb: "log-read".to_string(),
            description: "\u{1b}[2Kdescription: reads one file".to_string(),
            matcher: serde_json::json!({
                "binary": "cat",
                "args": ["{path}"],
                "params": {"path": {"pattern": "^\u{1b}[2K/var/log/syslog$"}}
            }),
            matcher_digest: "\u{1b}[2Kdigest".to_string(),
            consequence: "reversible".to_string(),
            credential_plan: None,
            baseline: false,
            trusted: false,
            has_revert: false,
            evidence: None,
        }],
        decided_reason: None,
    };
    let card = access_item_card(&item, false).join("\n");
    assert!(
        !card.contains('\u{1b}') && !card.contains('\r'),
        "control characters must not survive into the card:\n{card}"
    );
    assert!(
        card.contains("\\u{1b}[2J") && card.contains("\\nintent:"),
        "escaped forms must stay visible:\n{card}"
    );
    let human = access_item_human(&item, true);
    assert!(
        !human.contains('\u{1b}'),
        "guard access show must escape the same fields:\n{human}"
    );
}

#[test]
fn access_review_enabled_requires_every_interactive_stream() {
    assert!(access_review_enabled(true, true, true));
    for (stdin_tty, stdout_tty, stderr_tty) in [
        (false, true, true),
        (true, false, true),
        (true, true, false),
        (false, false, false),
    ] {
        assert!(
            !access_review_enabled(stdin_tty, stdout_tty, stderr_tty),
            "stdin={stdin_tty} stdout={stdout_tty} stderr={stderr_tty}"
        );
    }
}

#[test]
fn access_colors_map_states_and_consequences() {
    for state in ["pending", "approving"] {
        assert!(matches!(access_state_color(state), AnsiColor::Yellow));
    }
    for state in ["approved", "active"] {
        assert!(matches!(access_state_color(state), AnsiColor::Green));
    }
    for state in [
        "denied",
        "withdrawn",
        "revoked",
        "expired",
        "exhausted",
        "exec_failed",
    ] {
        assert!(matches!(access_state_color(state), AnsiColor::Red));
    }
    assert!(matches!(access_state_color("held"), AnsiColor::Cyan));
    assert!(matches!(consequence_color("irreversible"), AnsiColor::Red));
    assert!(matches!(
        consequence_color("recoverable"),
        AnsiColor::Yellow
    ));
    assert!(matches!(consequence_color("reversible"), AnsiColor::Green));
}

#[test]
fn run_socket_flag_is_honored() {
    let socket = parsed_run_socket(&["guard", "run", "--socket", "/tmp/run.sock", "true"]);
    let (socket, port, source) = resolve_endpoint(
        socket,
        Some("9999".to_string()),
        Some("/tmp/env.sock".to_string()),
        &config_with(Some("/tmp/config.sock"), Some(1234)),
        true,
    );

    assert_eq!(socket, Some(PathBuf::from("/tmp/run.sock")));
    assert_eq!(port, None);
    assert_eq!(source, EndpointSource::Flag);
}

#[test]
fn run_without_socket_uses_environment_then_config() {
    let socket = parsed_run_socket(&["guard", "run", "true"]);
    assert_eq!(socket, None);

    let (env_socket, env_port, env_source) = resolve_endpoint(
        socket.clone(),
        None,
        Some("/tmp/env.sock".to_string()),
        &config_with(Some("/tmp/config.sock"), None),
        true,
    );
    assert_eq!(env_socket, Some(PathBuf::from("/tmp/env.sock")));
    assert_eq!(env_port, None);
    assert_eq!(env_source, EndpointSource::Env);

    let (config_socket, config_port, config_source) = resolve_endpoint(
        socket,
        None,
        None,
        &config_with(Some("/tmp/config.sock"), None),
        true,
    );
    assert_eq!(config_socket, Some(PathBuf::from("/tmp/config.sock")));
    assert_eq!(config_port, None);
    assert_eq!(config_source, EndpointSource::Config);
}

#[test]
fn endpoint_flag_override_beats_env_config_and_default() {
    let (socket, port, source) = resolve_endpoint(
        Some("/tmp/flag.sock".to_string()),
        Some("9999".to_string()),
        Some("/tmp/env.sock".to_string()),
        &config_with(Some("/tmp/cfg.sock"), Some(1234)),
        true,
    );
    assert_eq!(socket, Some(PathBuf::from("/tmp/flag.sock")));
    assert_eq!(port, None);
    assert_eq!(source, EndpointSource::Flag);
}

#[test]
fn endpoint_env_tcp_port_beats_env_socket_and_config() {
    let (socket, port, source) = resolve_endpoint(
        None,
        Some("9999".to_string()),
        Some("/tmp/env.sock".to_string()),
        &config_with(Some("/tmp/cfg.sock"), None),
        true,
    );
    assert_eq!(socket, None);
    assert_eq!(port, Some(9999));
    assert_eq!(source, EndpointSource::Env);
}

#[test]
fn endpoint_unparsable_env_tcp_port_falls_through_to_env_socket() {
    let (socket, port, source) = resolve_endpoint(
        None,
        Some("not-a-port".to_string()),
        Some("/tmp/env.sock".to_string()),
        &config_with(None, None),
        true,
    );
    assert_eq!(socket, Some(PathBuf::from("/tmp/env.sock")));
    assert_eq!(port, None);
    assert_eq!(source, EndpointSource::Env);
}

#[test]
fn endpoint_empty_env_socket_falls_through_to_config() {
    let (socket, port, source) = resolve_endpoint(
        None,
        None,
        Some(String::new()),
        &config_with(Some("/tmp/cfg.sock"), None),
        true,
    );
    assert_eq!(socket, Some(PathBuf::from("/tmp/cfg.sock")));
    assert_eq!(port, None);
    assert_eq!(source, EndpointSource::Config);
}

#[test]
fn endpoint_config_port_beats_config_socket() {
    let (socket, port, source) = resolve_endpoint(
        None,
        None,
        None,
        &config_with(Some("/tmp/cfg.sock"), Some(1234)),
        true,
    );
    assert_eq!(socket, None);
    assert_eq!(port, Some(1234));
    assert_eq!(source, EndpointSource::Config);
}

#[cfg(unix)]
#[test]
fn endpoint_default_prefers_system_socket_when_present() {
    let (socket, port, source) = resolve_endpoint(None, None, None, &config_with(None, None), true);
    assert_eq!(socket, Some(PathBuf::from(defaults::SYSTEM_SOCKET)));
    assert_eq!(port, None);
    assert_eq!(source, EndpointSource::Default);
}

#[cfg(unix)]
#[test]
fn endpoint_default_falls_back_to_home_socket_when_system_socket_missing() {
    let (socket, port, source) =
        resolve_endpoint(None, None, None, &config_with(None, None), false);
    let expected = dirs::home_dir()
        .map(|h| h.join(".guard").join("guard.sock"))
        .unwrap_or_else(|| PathBuf::from(defaults::SYSTEM_SOCKET));
    assert_eq!(socket, Some(expected));
    assert_eq!(port, None);
    assert_eq!(source, EndpointSource::Default);
}

#[cfg(windows)]
#[test]
fn endpoint_default_is_loopback_tcp_on_windows() {
    let (socket, port, source) =
        resolve_endpoint(None, None, None, &config_with(None, None), false);
    assert_eq!(socket, None);
    assert_eq!(port, Some(defaults::DEFAULT_TCP_PORT));
    assert_eq!(source, EndpointSource::Default);
}

#[test]
fn set_server_passes_tcp_endpoint_through() {
    assert_eq!(
        normalize_server_socket_value("127.0.0.1:8123".to_string()),
        "127.0.0.1:8123"
    );
    assert_eq!(
        normalize_server_socket_value("localhost:9000".to_string()),
        "localhost:9000"
    );
}

#[cfg(unix)]
#[test]
fn set_server_absolutizes_relative_socket_path() {
    let normalized = normalize_server_socket_value("relative/guard.sock".to_string());
    assert!(std::path::Path::new(&normalized).is_absolute());
    assert!(normalized.ends_with("relative/guard.sock"));
}

#[cfg(unix)]
#[test]
fn set_server_keeps_absolute_socket_path() {
    assert_eq!(
        normalize_server_socket_value("/run/guard/guard.sock".to_string()),
        "/run/guard/guard.sock"
    );
}

#[test]
fn execute_json_envelope_keeps_decision_output_and_child_status() {
    let response = server::ExecuteResponse {
        allowed: true,
        reason: "trusted verb".to_string(),
        exit_code: Some(75),
        stdout: Some("out".to_string()),
        stderr: Some("err".to_string()),
        status: Some(server::GateStatus::Executed),
        handle: None,
        approval_options: Vec::new(),
        access_requests: Vec::new(),
        coverage: None,
        verb_matches: Vec::new(),
        verb_guidance: None,
        confirm_deadline_unix: None,
        confirm_window_secs: None,
        auto_revert_durable: None,
        containment_failure: None,
        decision_source: "static_policy".to_string(),
        decision_trace: Some(guard::gating::DecisionTrace::source("static_policy")),
    };
    let envelope = execute_response_envelope(
        "run_result",
        "sh",
        &["-c".to_string(), "exit 75".to_string()],
        &response,
    );

    assert_eq!(envelope["schema_version"], JSON_SCHEMA_VERSION);
    assert_eq!(envelope["type"], "run_result");
    assert_eq!(envelope["command"]["binary"], "sh");
    assert_eq!(envelope["response"]["allowed"], true);
    assert_eq!(envelope["response"]["exit_code"], 75);
    assert_eq!(envelope["response"]["stdout"], "out");
    assert_eq!(envelope["response"]["stderr"], "err");
}
