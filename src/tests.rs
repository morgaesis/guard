use super::*;

#[test]
fn bounded_durations_reject_zero() {
    assert!(parse_unbounded_secs("0").is_err());
    assert_eq!(parse_unbounded_secs("1").unwrap(), 1);
    assert_eq!(parse_unbounded_secs("unbounded").unwrap(), u64::MAX);
}

fn parse_start(args: &[&str]) -> ServerCommands {
    match MainArgs::parse_from(args) {
        MainArgs::Server(ServerCommands::Start {
            socket,
            tcp_port,
            auth_token,
            admin_token,
            admin_token_stdin,
            socket_group,
            users,
            policy,
            shim_dir,
            llm_api_key,
            llm_api_url,
            llm_model,
            llm_timeout,
            llm_retries,
            llm_models,
            llm_reasoning_effort,
            llm,
            no_llm,
            no_redact,
            preflight,
            no_cache,
            cache_capacity,
            cache_ttl,
            learn_rules,
            learned_rules,
            learn_min_approvals,
            learn_max_risk,
            learn_shims,
            learn_deny,
            no_learn_deny,
            deny_shapes,
            learn_deny_min_denials,
            learn_allow,
            no_learn_allow,
            learn_allow_state,
            learn_allow_min_approvals,
            dry_run,
            state_db,
            audit_log,
            metrics_addr,
            history_retention,
            exec_as_caller,
            exec_timeout_secs,
            system_prompt,
            system_prompt_append,
            gate,
            approval_ttl,
            verbs,
            grants,
            allow_bin,
            child_env,
            api_proxy,
            api_endpoints,
            api_protocol,
            api_upstream,
            api_token_env,
            api_token_file,
            api_ca_out,
            kube_proxy,
            kubeconfig,
            kube_context,
            api_policy,
            brokered_kubeconfig_out,
            api_rarity_escalation,
            api_promotion,
            no_api_promotion,
            api_promotion_state,
            api_promotion_min_approvals,
            api_promotion_min_denials,
            notify_cmd,
            notify_timeout,
            session_behavior_window,
            session_max_denials,
            session_max_holds,
            session_max_deny_ratio,
            session_deny_ratio_min_commands,
            api_judge_max_concurrency,
            api_judge_rate_per_minute,
            api_judge_burst,
            api_judge_error_threshold,
            api_judge_circuit_cooldown,
            command_max_concurrency,
            command_principal_concurrency,
            command_evaluator_max_concurrency,
            command_evaluator_principal_concurrency,
            command_evaluator_rate_per_minute,
            command_evaluator_burst,
            command_evaluator_error_threshold,
            command_evaluator_circuit_cooldown,
            service,
        }) => ServerCommands::Start {
            socket,
            tcp_port,
            auth_token,
            admin_token,
            admin_token_stdin,
            socket_group,
            users,
            policy,
            shim_dir,
            llm_api_key,
            llm_api_url,
            llm_model,
            llm_timeout,
            llm_retries,
            llm_models,
            llm_reasoning_effort,
            llm,
            no_llm,
            no_redact,
            preflight,
            no_cache,
            cache_capacity,
            cache_ttl,
            learn_rules,
            learned_rules,
            learn_min_approvals,
            learn_max_risk,
            learn_shims,
            learn_deny,
            no_learn_deny,
            deny_shapes,
            learn_deny_min_denials,
            learn_allow,
            no_learn_allow,
            learn_allow_state,
            learn_allow_min_approvals,
            dry_run,
            state_db,
            audit_log,
            metrics_addr,
            history_retention,
            exec_as_caller,
            exec_timeout_secs,
            system_prompt,
            system_prompt_append,
            gate,
            approval_ttl,
            verbs,
            grants,
            allow_bin,
            child_env,
            api_proxy,
            api_endpoints,
            api_protocol,
            api_upstream,
            api_token_env,
            api_token_file,
            api_ca_out,
            kube_proxy,
            kubeconfig,
            kube_context,
            api_policy,
            brokered_kubeconfig_out,
            api_rarity_escalation,
            api_promotion,
            no_api_promotion,
            api_promotion_state,
            api_promotion_min_approvals,
            api_promotion_min_denials,
            notify_cmd,
            notify_timeout,
            session_behavior_window,
            session_max_denials,
            session_max_holds,
            session_max_deny_ratio,
            session_deny_ratio_min_commands,
            api_judge_max_concurrency,
            api_judge_rate_per_minute,
            api_judge_burst,
            api_judge_error_threshold,
            api_judge_circuit_cooldown,
            command_max_concurrency,
            command_principal_concurrency,
            command_evaluator_max_concurrency,
            command_evaluator_principal_concurrency,
            command_evaluator_rate_per_minute,
            command_evaluator_burst,
            command_evaluator_error_threshold,
            command_evaluator_circuit_cooldown,
            service,
        },
        _ => panic!("expected server start args"),
    }
}

#[test]
fn parses_exec_timeout_secs() {
    let ServerCommands::Start {
        exec_timeout_secs, ..
    } = parse_start(&["guard", "server", "start", "--exec-timeout-secs", "42"])
    else {
        panic!("expected server start");
    };
    assert_eq!(exec_timeout_secs, Some(42));
}

#[test]
fn parses_named_api_endpoints_and_spend_controls() {
    let command = parse_start(&[
        "guard",
        "server",
        "start",
        "--api-endpoints",
        "/tmp/endpoints.yaml",
        "--api-judge-max-concurrency",
        "2",
        "--api-judge-rate-per-minute",
        "30",
        "--api-judge-burst",
        "4",
        "--api-judge-error-threshold",
        "3",
        "--api-judge-circuit-cooldown",
        "90",
    ]);
    let ServerCommands::Start {
        api_endpoints,
        api_judge_max_concurrency,
        api_judge_rate_per_minute,
        api_judge_burst,
        api_judge_error_threshold,
        api_judge_circuit_cooldown,
        ..
    } = command
    else {
        panic!("expected server start");
    };
    assert_eq!(api_endpoints, Some(PathBuf::from("/tmp/endpoints.yaml")));
    assert_eq!(api_judge_max_concurrency, Some(2));
    assert_eq!(api_judge_rate_per_minute, Some(30));
    assert_eq!(api_judge_burst, Some(4));
    assert_eq!(api_judge_error_threshold, Some(3));
    assert_eq!(api_judge_circuit_cooldown, Some(90));
}

fn resolved_llm(args: &[&str]) -> bool {
    let ServerCommands::Start { llm, no_llm, .. } = parse_start(args) else {
        panic!("expected start");
    };

    resolve_bool_flag(llm, no_llm, true)
}

#[test]
fn test_server_start_llm_defaults_true() {
    assert!(resolved_llm(&["guard", "server", "start"]));
}

#[test]
fn test_server_start_llm_positive_forms() {
    assert!(resolved_llm(&["guard", "server", "start", "--llm"]));
    assert!(resolved_llm(&["guard", "server", "start", "--llm=true"]));
    assert!(resolved_llm(&["guard", "server", "start", "--llm", "true"]));
}

#[test]
fn test_server_start_llm_negative_forms() {
    assert!(!resolved_llm(&["guard", "server", "start", "--no-llm"]));
    assert!(!resolved_llm(&["guard", "server", "start", "--llm=false"]));
    assert!(!resolved_llm(&[
        "guard", "server", "start", "--llm", "false"
    ]));
}

#[test]
fn test_server_start_llm_retries_flag() {
    let ServerCommands::Start { llm_retries, .. } =
        parse_start(&["guard", "server", "start", "--llm-retries", "1"])
    else {
        panic!("expected start");
    };
    assert_eq!(llm_retries, Some(1));
}

#[test]
fn test_server_start_parses_notification_and_behavior_limits() {
    let ServerCommands::Start {
        notify_cmd,
        notify_timeout,
        session_behavior_window,
        session_max_denials,
        session_max_holds,
        session_max_deny_ratio,
        session_deny_ratio_min_commands,
        ..
    } = parse_start(&[
        "guard",
        "server",
        "start",
        "--notify-cmd",
        "notify-guard --channel sre",
        "--notify-timeout",
        "9",
        "--session-behavior-window",
        "120",
        "--session-max-denials",
        "4",
        "--session-max-holds",
        "2",
        "--session-max-deny-ratio",
        "35",
        "--session-deny-ratio-min-commands",
        "8",
    ])
    else {
        panic!("expected start");
    };
    assert_eq!(notify_cmd.as_deref(), Some("notify-guard --channel sre"));
    assert_eq!(notify_timeout, Some(9));
    assert_eq!(session_behavior_window, Some(120));
    assert_eq!(session_max_denials, Some(4));
    assert_eq!(session_max_holds, Some(2));
    assert_eq!(session_max_deny_ratio, Some(35));
    assert_eq!(session_deny_ratio_min_commands, Some(8));
}

#[test]
fn test_history_retention_flag_and_environment_resolution() {
    let ServerCommands::Start {
        history_retention, ..
    } = parse_start(&["guard", "server", "start", "--history-retention", "7200"])
    else {
        panic!("expected start");
    };
    assert_eq!(history_retention, Some(7200));
    assert_eq!(
        cli_server::resolve_history_retention(None, Some("3600".into())).unwrap(),
        3600
    );
    assert!(cli_server::resolve_history_retention(None, Some("0".into())).is_err());
    assert!(cli_server::resolve_history_retention(None, Some("bad".into())).is_err());
}

fn resolved_learn_deny(args: &[&str]) -> bool {
    let ServerCommands::Start {
        learn_deny,
        no_learn_deny,
        ..
    } = parse_start(args)
    else {
        panic!("expected start");
    };
    resolve_bool_flag(learn_deny, no_learn_deny, true)
}

#[test]
fn test_server_start_learn_deny_defaults_true() {
    assert!(resolved_learn_deny(&["guard", "server", "start"]));
}

#[test]
fn test_server_start_learn_deny_can_be_disabled() {
    assert!(!resolved_learn_deny(&[
        "guard",
        "server",
        "start",
        "--no-learn-deny"
    ]));
    assert!(!resolved_learn_deny(&[
        "guard",
        "server",
        "start",
        "--learn-deny=false"
    ]));
}

#[test]
fn test_server_start_learn_deny_min_denials_flag() {
    let ServerCommands::Start {
        learn_deny_min_denials,
        ..
    } = parse_start(&["guard", "server", "start", "--learn-deny-min-denials", "5"])
    else {
        panic!("expected start");
    };
    assert_eq!(learn_deny_min_denials, Some(5));
}

fn resolved_learn_allow(args: &[&str]) -> bool {
    let ServerCommands::Start {
        learn_allow,
        no_learn_allow,
        ..
    } = parse_start(args)
    else {
        panic!("expected start");
    };
    resolve_bool_flag(learn_allow, no_learn_allow, true)
}

#[test]
fn test_server_start_learn_allow_defaults_true() {
    assert!(resolved_learn_allow(&["guard", "server", "start"]));
}

#[test]
fn test_server_start_learn_allow_can_be_disabled() {
    assert!(!resolved_learn_allow(&[
        "guard",
        "server",
        "start",
        "--no-learn-allow"
    ]));
    assert!(!resolved_learn_allow(&[
        "guard",
        "server",
        "start",
        "--learn-allow=false"
    ]));
}

#[test]
fn test_server_start_learn_allow_min_approvals_flag() {
    let ServerCommands::Start {
        learn_allow_min_approvals,
        ..
    } = parse_start(&[
        "guard",
        "server",
        "start",
        "--learn-allow-min-approvals",
        "7",
    ])
    else {
        panic!("expected start");
    };
    assert_eq!(learn_allow_min_approvals, Some(7));
}

#[test]
fn test_server_start_learn_allow_state_flag() {
    let ServerCommands::Start {
        learn_allow_state, ..
    } = parse_start(&[
        "guard",
        "server",
        "start",
        "--learn-allow-state",
        "/tmp/allow.yaml",
    ])
    else {
        panic!("expected start");
    };
    assert_eq!(learn_allow_state, Some(PathBuf::from("/tmp/allow.yaml")));
}

fn resolved_api_promotion(args: &[&str]) -> bool {
    let ServerCommands::Start {
        api_promotion,
        no_api_promotion,
        ..
    } = parse_start(args)
    else {
        panic!("expected start");
    };
    resolve_bool_flag(api_promotion, no_api_promotion, true)
}

#[test]
fn test_server_start_api_promotion_defaults_true() {
    assert!(resolved_api_promotion(&["guard", "server", "start"]));
}

#[test]
fn test_server_start_api_promotion_can_be_disabled() {
    assert!(!resolved_api_promotion(&[
        "guard",
        "server",
        "start",
        "--no-api-promotion"
    ]));
    assert!(!resolved_api_promotion(&[
        "guard",
        "server",
        "start",
        "--api-promotion=false"
    ]));
}

#[test]
fn test_server_start_api_promotion_threshold_flags() {
    let ServerCommands::Start {
        api_promotion_min_approvals,
        api_promotion_min_denials,
        ..
    } = parse_start(&[
        "guard",
        "server",
        "start",
        "--api-promotion-min-approvals",
        "7",
        "--api-promotion-min-denials",
        "4",
    ])
    else {
        panic!("expected start");
    };
    assert_eq!(api_promotion_min_approvals, Some(7));
    assert_eq!(api_promotion_min_denials, Some(4));
}

#[test]
fn test_server_start_api_promotion_state_flag() {
    let ServerCommands::Start {
        api_promotion_state,
        ..
    } = parse_start(&[
        "guard",
        "server",
        "start",
        "--api-promotion-state",
        "/tmp/api.yaml",
    ])
    else {
        panic!("expected start");
    };
    assert_eq!(api_promotion_state, Some(PathBuf::from("/tmp/api.yaml")));
}

#[test]
fn test_run_reevaluate_flag() {
    match MainArgs::try_parse_from(["guard", "run", "--reevaluate", "kubectl", "get", "pods"]) {
        Ok(MainArgs::Run { reevaluate, .. }) => assert!(reevaluate),
        Ok(_) => panic!("expected Run variant"),
        Err(e) => panic!("parser rejected --reevaluate: {}", e),
    }
    match MainArgs::try_parse_from(["guard", "run", "kubectl", "get", "pods"]) {
        Ok(MainArgs::Run { reevaluate, .. }) => assert!(!reevaluate),
        Ok(_) => panic!("expected Run variant"),
        Err(e) => panic!("parser rejected plain run: {}", e),
    }
}

#[test]
fn test_run_confirm_check_requires_and_composes_with_revert() {
    match MainArgs::try_parse_from([
        "guard",
        "run",
        "--revert",
        "ssh firewall-a rollback",
        "--confirm-check",
        "ssh firewall-a verify",
        "--revert-control-path",
        "brokered SSH to firewall-a",
        "--confirm-within",
        "45",
        "ssh",
        "firewall-a",
        "apply",
    ]) {
        Ok(MainArgs::Run {
            revert,
            confirm_check,
            revert_control_path,
            confirm_within,
            ..
        }) => {
            assert_eq!(revert.as_deref(), Some("ssh firewall-a rollback"));
            assert_eq!(confirm_check.as_deref(), Some("ssh firewall-a verify"));
            assert_eq!(
                revert_control_path.as_deref(),
                Some("brokered SSH to firewall-a")
            );
            assert_eq!(confirm_within, Some(45));
        }
        Ok(_) => panic!("expected Run variant"),
        Err(error) => panic!("parser rejected containment envelope: {error}"),
    }
    assert!(MainArgs::try_parse_from(["guard", "run", "--confirm-check", "true", "true"]).is_err());
}

#[test]
fn test_server_start_exec_as_caller_flag() {
    let ServerCommands::Start { exec_as_caller, .. } =
        parse_start(&["guard", "server", "start", "--exec-as-caller"])
    else {
        panic!("expected start");
    };
    assert!(exec_as_caller);
}

#[test]
fn test_server_start_state_db_flag() {
    let ServerCommands::Start { state_db, .. } = parse_start(&[
        "guard",
        "server",
        "start",
        "--state-db",
        "/var/lib/guard/state.db",
    ]) else {
        panic!("expected start");
    };
    assert_eq!(state_db, Some(PathBuf::from("/var/lib/guard/state.db")));
}

#[test]
fn server_secret_values_are_rejected_in_argv() {
    for flag in ["--auth-token", "--admin-token", "--llm-api-key"] {
        assert!(
            MainArgs::try_parse_from(["guard", "server", "start", flag, "secret-value"]).is_err(),
            "{flag} must not accept a secret through argv"
        );
    }
}

#[test]
fn secret_setters_reject_values_in_argv() {
    assert!(MainArgs::try_parse_from(["guard", "config", "set-token", "secret-value"]).is_err());
    assert!(
        MainArgs::try_parse_from(["guard", "config", "set-admin-token", "secret-value"]).is_err()
    );
    assert!(
        MainArgs::try_parse_from(["guard", "secrets", "add", "fixture-key", "secret-value"])
            .is_err()
    );

    assert!(matches!(
        MainArgs::try_parse_from(["guard", "config", "set-token"]),
        Ok(MainArgs::Config(ConfigCommands::SetToken))
    ));
    assert!(matches!(
        MainArgs::try_parse_from(["guard", "secrets", "add", "fixture-key"]),
        Ok(MainArgs::Secrets(SecretCommands::Add { value: None, .. }))
    ));
}

#[test]
fn bare_guard_is_non_mutating_access_help() {
    let error = match MainArgs::try_parse_from(["guard"]) {
        Err(error) => error,
        Ok(_) => panic!("bare guard unexpectedly parsed"),
    };
    assert_eq!(
        error.kind(),
        clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
    );
    let rendered = error.to_string();
    assert!(rendered.contains("guard access request \"<intent>\""));
    assert!(rendered.contains("guard access approve <request>..."));
    assert!(rendered.contains("guard access list"));
}

#[test]
fn bare_access_is_non_mutating_help() {
    let error = match MainArgs::try_parse_from(["guard", "access"]) {
        Err(error) => error,
        Ok(_) => panic!("bare access unexpectedly parsed"),
    };
    assert_eq!(
        error.kind(),
        clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
    );
    let rendered = error.to_string();
    for command in [
        "request", "approve", "deny", "revoke", "extend", "list", "show",
    ] {
        assert!(rendered.contains(command), "missing {command}: {rendered}");
    }
    assert!(rendered.contains("guard access approve <request> --once"));
    assert!(rendered.contains("one or more decisions in the access batch failed"));
}

#[test]
fn access_command_family_parses_bounded_and_batch_forms() {
    assert!(matches!(
        MainArgs::try_parse_from(["guard", "access", "request", "restart one service"]),
        Ok(MainArgs::Access(AccessCommands::Request { .. }))
    ));
    match MainArgs::try_parse_from([
        "guard", "access", "approve", "gr-one", "gr-two", "--uses", "3", "--json",
    ]) {
        Ok(MainArgs::Access(AccessCommands::Approve {
            requests,
            yes,
            once,
            uses,
            json,
            ..
        })) => {
            assert_eq!(requests, ["gr-one", "gr-two"]);
            assert!(!yes);
            assert!(!once);
            assert_eq!(uses, Some(3));
            assert!(json);
        }
        Ok(_) => panic!("unexpected access command"),
        Err(error) => panic!("access approve did not parse: {error}"),
    }
    assert!(MainArgs::try_parse_from([
        "guard", "access", "approve", "gr-one", "--once", "--uses", "2"
    ])
    .is_err());
    assert!(matches!(
        MainArgs::try_parse_from(["guard", "access", "approve", "gr-one", "--yes", "--once"]),
        Ok(MainArgs::Access(AccessCommands::Approve {
            yes: true,
            once: true,
            ..
        }))
    ));
    assert!(MainArgs::try_parse_from(["guard", "access", "approve"]).is_err());
    assert!(matches!(
        MainArgs::try_parse_from([
            "guard",
            "access",
            "extend",
            "session:0011",
            "inspect fixture",
            "--once"
        ]),
        Ok(MainArgs::Access(AccessCommands::Extend { once: true, .. }))
    ));
    assert!(matches!(
        MainArgs::try_parse_from(["guard", "access", "revoke", "session:0011", "--json"]),
        Ok(MainArgs::Access(AccessCommands::Revoke { json: true, .. }))
    ));
}

#[test]
fn resume_and_verb_amend_parse_their_requester_and_cas_inputs() {
    match MainArgs::try_parse_from([
        "guard",
        "resume",
        "0123456789abcdef",
        "--socket",
        "/run/guard.sock",
        "--json",
    ]) {
        Ok(MainArgs::Resume {
            handle,
            socket,
            json,
            ..
        }) => {
            assert_eq!(handle, "0123456789abcdef");
            assert_eq!(socket.as_deref(), Some("/run/guard.sock"));
            assert!(json);
        }
        Ok(_) => panic!("unexpected resume command"),
        Err(error) => panic!("resume did not parse: {error}"),
    }

    match MainArgs::try_parse_from([
        "guard",
        "verb",
        "amend",
        "inspect-fixture",
        "--file",
        "replacement.yaml",
        "--socket",
        "/run/guard.sock",
        "--json",
    ]) {
        Ok(MainArgs::Verb(VerbCommands::Amend {
            name,
            file,
            socket,
            json,
        })) => {
            assert_eq!(name, "inspect-fixture");
            assert_eq!(file, PathBuf::from("replacement.yaml"));
            assert_eq!(socket.as_deref(), Some("/run/guard.sock"));
            assert!(json);
        }
        Ok(_) => panic!("unexpected verb amend command"),
        Err(error) => panic!("verb amend did not parse: {error}"),
    }
    assert!(MainArgs::try_parse_from(["guard", "verb", "amend", "inspect-fixture"]).is_err());

    let help = match MainArgs::try_parse_from(["guard", "verb", "--help"]) {
        Err(error) => error.to_string(),
        Ok(_) => panic!("verb help unexpectedly parsed"),
    };
    assert!(help.contains("amend"));
}

#[test]
fn verb_lint_parses_optional_file_and_explicit_fix() {
    match MainArgs::try_parse_from(["guard", "verb", "lint", "--file", "candidate.yaml", "--fix"]) {
        Ok(MainArgs::Verb(VerbCommands::Lint { file, fix })) => {
            assert_eq!(file, Some(PathBuf::from("candidate.yaml")));
            assert!(fix);
        }
        Ok(_) => panic!("unexpected verb command"),
        Err(error) => panic!("verb lint did not parse: {error}"),
    }
    assert!(matches!(
        MainArgs::try_parse_from(["guard", "verb", "lint"]),
        Ok(MainArgs::Verb(VerbCommands::Lint {
            file: None,
            fix: false
        }))
    ));
}

#[test]
fn access_extend_help_explains_target_and_bounded_use_defaults() {
    let error = match MainArgs::try_parse_from(["guard", "access", "extend", "--help"]) {
        Err(error) => error,
        Ok(_) => panic!("access extend help unexpectedly parsed"),
    };
    let rendered = error.to_string();
    assert!(rendered.contains("session reference or agent label"));
    assert!(rendered.contains("Unlimited by default"));
    assert!(rendered.contains("Equivalent to --uses 1"));
    assert!(rendered.contains("Omit both use flags for unlimited authority"));
}

#[test]
fn historical_authority_aliases_and_argv_http_bearer_are_rejected() {
    for args in [
        vec!["guard", "approve", "0123456789abcdef0123456789abcdef"],
        vec!["guard", "deny", "0123456789abcdef0123456789abcdef"],
        vec!["guard", "approvals"],
        vec![
            "guard",
            "mcp",
            "serve",
            "--http",
            "127.0.0.1:7333",
            "--http-token",
            "fixture",
        ],
        vec![
            "guard",
            "mcp",
            "serve",
            "--tcp-port",
            "7332",
            "--token",
            "fixture",
        ],
    ] {
        assert!(MainArgs::try_parse_from(args).is_err());
    }

    assert!(matches!(
        MainArgs::try_parse_from(["guard", "session", "new", "--profile", "fixture"]),
        Ok(MainArgs::Session { .. })
    ));
    assert!(matches!(
        MainArgs::try_parse_from(["guard", "grant", "issue", "fixture"]),
        Ok(MainArgs::Grant { .. })
    ));
    assert!(matches!(
        MainArgs::try_parse_from(["guard", "appeal", "fixture", "status"]),
        Ok(MainArgs::Appeal { .. })
    ));
    for (command, replacement) in [
        ("session", "guard access"),
        ("grant", "guard access"),
        ("appeal", "guard access request <intent>"),
    ] {
        let error = legacy_authority_error(command, replacement).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("has been removed"));
        assert!(message.contains(replacement));
    }
}

#[test]
fn verb_help_lists_show_and_delete() {
    let error = match MainArgs::try_parse_from(["guard", "verb", "--help"]) {
        Err(error) => error,
        Ok(_) => panic!("verb help unexpectedly parsed"),
    };
    let rendered = error.to_string();
    assert!(rendered.contains("list"));
    assert!(rendered.contains("run"));
    assert!(rendered.contains("show"));
    assert!(rendered.contains("delete"));
}

#[test]
fn guard_mode_env_resolution() {
    use guard::policy::PolicyMode;

    assert_eq!(
        cli_server::resolve_policy_mode(None).unwrap(),
        PolicyMode::Readonly
    );
    assert_eq!(
        cli_server::resolve_policy_mode(Some(String::new())).unwrap(),
        PolicyMode::Readonly
    );
    assert_eq!(
        cli_server::resolve_policy_mode(Some("paranoid".to_string())).unwrap(),
        PolicyMode::Paranoid
    );

    let err = cli_server::resolve_policy_mode(Some("bogus".to_string())).unwrap_err();
    let message = err.to_string();
    assert!(message.contains("bogus"), "message: {message}");
    assert!(message.contains("readonly"), "message: {message}");
    assert!(message.contains("paranoid"), "message: {message}");
    assert!(message.contains("safe"), "message: {message}");
}

/// Shared guard for tests that mutate `GUARD_LLM_MODEL*` environment
/// variables. Rust's test runner executes tests in parallel by default, and
/// `std::env::{set,remove}_var` mutates shared process state, so concurrent
/// readers/writers must be serialized with a mutex.
static MODEL_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Mirror of the resolution logic in `run_server` so we can exercise the
/// precedence ladder without spinning up an actual server. Uses the same
/// `guard_env` helper as `run_server`, so it honors the canonical `GUARD_`
/// prefix. Must stay in sync with the block under the "Model resolution
/// precedence" comment in `run_server`.
fn resolve_single_model_for_test(cli_flag: Option<String>) -> Option<String> {
    cli_flag
        .filter(|value| !value.is_empty())
        .or_else(|| guard::env::guard_env("LLM_MODEL").filter(|v| !v.is_empty()))
}

fn resolve_chain_for_test(cli_flag: Option<Vec<String>>) -> Vec<String> {
    let models_chain: Vec<String> = cli_flag
        .unwrap_or_default()
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    if models_chain.is_empty() {
        guard::env::guard_env("LLM_MODELS")
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    } else {
        models_chain
    }
}

/// Regression guard for silent-ignore of `GUARD_LLM_MODEL`. Exercises the
/// full precedence ladder:
///
///   1. `--llm-model` CLI flag
///   2. `GUARD_LLM_MODEL` env var (singular)
///   3. default (`None` here; EvalConfig falls back to `DEFAULT_MODEL`)
///
/// and verifies that `GUARD_LLM_MODELS` (plural, chain) still parses
/// correctly alongside the singular. The test is sequential within a single
/// function body because splitting into multiple `#[test]` functions would
/// allow parallel process-env races even with a mutex (one test could
/// observe another test's cleared state).
#[test]
fn test_llm_model_env_resolution_chain() {
    // SAFETY: serialize all process-env mutations in this test suite.
    let _guard = MODEL_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    // Snapshot existing values (both prefixes) so we restore the shell's
    // environment on exit even if the harness inherited one of these vars.
    let prev = ["GUARD_LLM_MODEL", "GUARD_LLM_MODELS"].map(|k| (k, std::env::var(k).ok()));

    // Env mutations are serialized across tests via MODEL_ENV_LOCK above.
    for (k, _) in &prev {
        std::env::remove_var(k);
    }

    // 1. Clean slate: no flag, no env -> None (caller falls back to
    //    evaluate::DEFAULT_MODEL which is "openai/gpt-5.4-mini").
    assert_eq!(
        resolve_single_model_for_test(None),
        None,
        "with no flag and no env, single-model resolution must be None so \
             EvalConfig picks DEFAULT_MODEL"
    );
    assert_eq!(resolve_chain_for_test(None), Vec::<String>::new());

    // 2. GUARD_LLM_MODEL set -> picked up as primary.
    std::env::set_var("GUARD_LLM_MODEL", "alt/model-x");
    assert_eq!(
        resolve_single_model_for_test(None),
        Some("alt/model-x".to_string()),
        "GUARD_LLM_MODEL must be honored when no CLI flag is supplied"
    );

    // 3. CLI flag wins over the singular env var.
    assert_eq!(
        resolve_single_model_for_test(Some("flag/model-y".to_string())),
        Some("flag/model-y".to_string()),
        "--llm-model must take precedence over GUARD_LLM_MODEL"
    );

    // 4. Empty CLI flag falls through to env var.
    assert_eq!(
        resolve_single_model_for_test(Some(String::new())),
        Some("alt/model-x".to_string()),
        "empty --llm-model value must fall through to the env var"
    );

    // 5. Chain env var still parses independently of the singular var.
    std::env::set_var("GUARD_LLM_MODELS", "a,b,c");
    let chain = resolve_chain_for_test(None);
    assert_eq!(
        chain,
        vec!["a".to_string(), "b".to_string(), "c".to_string()],
        "GUARD_LLM_MODELS must parse into an ordered chain"
    );
    // The singular resolver is orthogonal and still returns the singular
    // value; the call site in run_server applies the precedence rule
    // ("chain wins when non-empty") when wiring EvalConfig.
    assert_eq!(
        resolve_single_model_for_test(None),
        Some("alt/model-x".to_string())
    );

    // Cleanup: restore prior values so other tests see the original env.
    for (k, v) in &prev {
        match v {
            Some(val) => std::env::set_var(k, val),
            None => std::env::remove_var(k),
        }
    }
}

#[test]
fn test_server_start_llm_models_flag() {
    let ServerCommands::Start { llm_models, .. } = parse_start(&[
        "guard",
        "server",
        "start",
        "--llm-models",
        "openai/gpt-5.4-mini,meta-llama/llama-4-maverick",
    ]) else {
        panic!("expected start");
    };
    assert_eq!(
        llm_models,
        Some(vec![
            "openai/gpt-5.4-mini".to_string(),
            "meta-llama/llama-4-maverick".to_string()
        ])
    );
}

#[test]
fn test_resolve_bool_flag() {
    assert!(resolve_bool_flag(None, false, true));
    assert!(!resolve_bool_flag(None, true, true));
    assert!(resolve_bool_flag(Some(true), false, false));
    assert!(!resolve_bool_flag(Some(false), false, true));
}

/// `guard run df -h` must forward `-h` to df. Earlier a pre-clap argv
/// scan consumed `-h` before clap could see that it was a positional
/// arg to the subcommand. We verify at the parser level: clap must
/// parse `run echo -h` into the `Run` variant with `-h` in args.
#[test]
fn run_forwards_short_help_flag_to_child() {
    match MainArgs::try_parse_from(["guard", "run", "echo", "-h"]) {
        Ok(MainArgs::Run { binary, args, .. }) => {
            assert_eq!(binary, "echo");
            assert_eq!(args, vec!["-h".to_string()]);
        }
        Ok(other) => panic!(
            "expected Run variant, got {:?}",
            std::mem::discriminant(&other)
        ),
        Err(e) => panic!("parser must not intercept -h: {}", e),
    }
}

/// Same story for `--help` - must be forwarded, not caught by clap's
/// subcommand help handler.
#[test]
fn run_forwards_long_help_flag_to_child() {
    match MainArgs::try_parse_from(["guard", "run", "df", "--help"]) {
        Ok(MainArgs::Run { binary, args, .. }) => {
            assert_eq!(binary, "df");
            assert_eq!(args, vec!["--help".to_string()]);
        }
        Ok(_) => panic!("expected Run variant"),
        Err(e) => panic!("parser must not intercept --help: {}", e),
    }
}

/// Mixed flags after the binary should all be forwarded intact.
#[test]
fn run_forwards_multiple_trailing_flags() {
    match MainArgs::try_parse_from(["guard", "run", "df", "-h", "/"]) {
        Ok(MainArgs::Run { binary, args, .. }) => {
            assert_eq!(binary, "df");
            assert_eq!(args, vec!["-h".to_string(), "/".to_string()]);
        }
        Ok(_) => panic!("expected Run variant"),
        Err(e) => panic!("parser rejected valid run args: {}", e),
    }
}

#[test]
fn run_accepts_transient_secret_injection() {
    match MainArgs::try_parse_from([
        "guard",
        "run",
        "--secret",
        "OPNSENSE_API_KEY",
        "--secret",
        "OPNSENSE_API_SECRET=atlas/opnsense-api-secret",
        "ssh",
        "fw",
        "configctl",
        "system",
        "status",
    ]) {
        Ok(MainArgs::Run {
            secret_vars,
            binary,
            args,
            ..
        }) => {
            assert_eq!(binary, "ssh");
            assert_eq!(
                secret_vars,
                vec![
                    (
                        "OPNSENSE_API_KEY".to_string(),
                        "OPNSENSE_API_KEY".to_string()
                    ),
                    (
                        "OPNSENSE_API_SECRET".to_string(),
                        "atlas/opnsense-api-secret".to_string()
                    )
                ]
            );
            assert_eq!(
                args,
                vec![
                    "fw".to_string(),
                    "configctl".to_string(),
                    "system".to_string(),
                    "status".to_string()
                ]
            );
        }
        Ok(_) => panic!("expected Run variant"),
        Err(e) => panic!("parser rejected valid run secret injection: {}", e),
    }
}

#[test]
fn run_accepts_comma_separated_bare_secret_names() {
    match MainArgs::try_parse_from(["guard", "run", "--secret", "foo,bar", "sh", "-c", "true"]) {
        Ok(MainArgs::Run {
            secret_vars,
            binary,
            args,
            ..
        }) => {
            assert_eq!(binary, "sh");
            assert_eq!(args, vec!["-c".to_string(), "true".to_string()]);
            assert_eq!(
                secret_vars,
                vec![
                    ("FOO".to_string(), "foo".to_string()),
                    ("BAR".to_string(), "bar".to_string())
                ]
            );
        }
        Ok(_) => panic!("expected Run variant"),
        Err(e) => panic!("parser rejected comma-separated bare secrets: {}", e),
    }
}

#[test]
fn bare_secret_name_derives_shell_safe_env_name() {
    let parsed = parse_secret_mapping("opnsense-apikey-secret").unwrap();
    assert_eq!(
        parsed,
        (
            "OPNSENSE_APIKEY_SECRET".to_string(),
            "opnsense-apikey-secret".to_string()
        )
    );
}

#[test]
fn secret_mapping_rejects_invalid_env_name() {
    let err = parse_secret_mapping("bad-name=secret").expect_err("must reject invalid env");
    assert!(err.contains("invalid environment variable name"));
}

#[test]
fn passthrough_help_requested_only_for_bare_command_help() {
    assert_eq!(
        passthrough_command_help_requested(&["run".to_string(), "--help".to_string()]),
        Some((vec!["run"], "guard run"))
    );
    assert_eq!(
        passthrough_command_help_requested(&["exec".to_string(), "-h".to_string()]),
        Some((vec!["run"], "guard run"))
    );
    assert_eq!(
        passthrough_command_help_requested(&[
            "run".to_string(),
            "df".to_string(),
            "--help".to_string()
        ]),
        None
    );
}

#[test]
fn server_connect_accepts_command_args_without_separator() {
    match MainArgs::try_parse_from([
        "guard",
        "server",
        "connect",
        "--socket",
        ".cache/guard.sock",
        "cp",
        "README.md",
        ".cache/copy",
    ]) {
        Ok(MainArgs::Server(ServerCommands::Connect {
            socket,
            binary,
            args,
            ..
        })) => {
            assert_eq!(socket, Some(".cache/guard.sock".to_string()));
            assert_eq!(binary, "cp");
            assert_eq!(
                args,
                vec!["README.md".to_string(), ".cache/copy".to_string()]
            );
        }
        Ok(_) => panic!("expected server connect variant"),
        Err(e) => panic!("parser rejected valid server connect args: {}", e),
    }
}

#[test]
fn server_connect_forwards_hyphen_args_without_separator() {
    match MainArgs::try_parse_from([
        "guard",
        "server",
        "connect",
        "--socket",
        ".cache/guard.sock",
        "bash",
        "-lc",
        "id",
    ]) {
        Ok(MainArgs::Server(ServerCommands::Connect { binary, args, .. })) => {
            assert_eq!(binary, "bash");
            assert_eq!(args, vec!["-lc".to_string(), "id".to_string()]);
        }
        Ok(_) => panic!("expected server connect variant"),
        Err(e) => panic!("parser rejected valid server connect args: {}", e),
    }
}

/// Top-level `--help` must still work (clap handles it natively after
/// we removed the argv pre-scan).
#[test]
fn top_level_help_still_triggers_clap_display_help() {
    match MainArgs::try_parse_from(["guard", "--help"]) {
        Ok(_) => panic!("expected clap to return DisplayHelp error"),
        Err(e) => assert_eq!(e.kind(), clap::error::ErrorKind::DisplayHelp),
    }
}

/// `guard help run` should show the subcommand help via clap. Note:
/// because `Run` disables its own help flag, `guard run --help` would
/// forward `--help` to the child instead - users get run help via
/// `guard help run`. The instructions explicitly permit this tradeoff.
#[test]
fn help_run_shows_subcommand_help() {
    match MainArgs::try_parse_from(["guard", "help", "run"]) {
        Ok(_) => panic!("expected clap to return DisplayHelp for `help run`"),
        Err(e) => assert_eq!(e.kind(), clap::error::ErrorKind::DisplayHelp),
    }
}

#[test]
fn top_level_version_requested_matches_first_arg_only() {
    assert!(top_level_version_requested(&["--version".to_string()]));
    assert!(top_level_version_requested(&["-V".to_string()]));
    assert!(!top_level_version_requested(&[
        "run".to_string(),
        "-V".to_string()
    ]));
    assert!(!top_level_version_requested(&[]));
}

#[test]
fn cli_command_path_avoids_unknown_positional_values() {
    assert_eq!(
        cli_command_path(&["ssh".to_string(), "prod-host".to_string()]),
        "ssh"
    );
    assert_eq!(
        cli_command_path(&["profile".to_string(), "seccomp".to_string()]),
        "profile"
    );
    assert_eq!(
        cli_command_path(&[
            "session".to_string(),
            "show".to_string(),
            "token".to_string()
        ]),
        "session"
    );
    assert_eq!(
        cli_command_path(&[
            "config".to_string(),
            "set-token".to_string(),
            "secret".to_string()
        ]),
        "config set-token"
    );
}

#[test]
fn cli_command_path_normalizes_aliases() {
    assert_eq!(
        cli_command_path(&["secret".to_string(), "add".to_string(), "KEY".to_string()]),
        "secrets add"
    );
    assert_eq!(
        cli_command_path(&["exec".to_string(), "git".to_string(), "status".to_string()]),
        "run"
    );
}

/// Anti-drift guard: every leaf command in the clap tree must resolve to its
/// full path through `cli_command_path`, so the audit command path can never
/// silently lag a newly added subcommand.
#[test]
fn cli_command_path_covers_every_clap_leaf_command() {
    fn walk(command: &clap::Command, path: &mut Vec<String>, failures: &mut Vec<String>) {
        let mut subcommands = command
            .get_subcommands()
            .filter(|sub| sub.get_name() != "help")
            .peekable();
        if subcommands.peek().is_none() {
            let expected = path.join(" ");
            let resolved = cli_command_path(path);
            if resolved != expected {
                failures.push(format!("`{expected}` resolved to `{resolved}`"));
            }
            return;
        }
        for sub in subcommands {
            path.push(sub.get_name().to_string());
            walk(sub, path, failures);
            path.pop();
        }
    }

    let root = MainArgs::command();
    assert!(
        root.get_subcommands().next().is_some(),
        "clap tree walk found no commands"
    );
    let mut failures = Vec::new();
    for sub in root
        .get_subcommands()
        .filter(|sub| sub.get_name() != "help")
    {
        let mut path = vec![sub.get_name().to_string()];
        walk(sub, &mut path, &mut failures);
    }
    assert!(
        failures.is_empty(),
        "cli_command_path lags the clap command tree:\n{}",
        failures.join("\n")
    );
}

#[test]
fn env_pairs_to_map_rejects_conflicting_duplicate_values() {
    let err = env_pairs_to_map(vec![
        ("FOO".to_string(), "one".to_string()),
        ("FOO".to_string(), "two".to_string()),
    ])
    .unwrap_err();
    assert!(err.contains("conflicting duplicate environment variable injection"));
}

#[test]
fn secret_pairs_to_map_allows_idempotent_repeats() {
    let map = secret_pairs_to_map(vec![
        ("AWS_TOKEN".to_string(), "aws/token".to_string()),
        ("AWS_TOKEN".to_string(), "aws/token".to_string()),
    ])
    .unwrap();
    assert_eq!(map.get("AWS_TOKEN").map(String::as_str), Some("aws/token"));
}

#[test]
fn singular_secret_alias_parses_as_secrets_subcommand() {
    let args = MainArgs::try_parse_from(["guard", "secret", "list"]).unwrap();
    assert!(matches!(
        args,
        MainArgs::Secrets(SecretCommands::List {
            detailed: false,
            json: false,
        })
    ));
}

#[test]
fn machine_readable_flags_cover_read_and_execution_commands() {
    assert!(matches!(
        MainArgs::try_parse_from(["guard", "run", "--json", "echo", "ok"]),
        Ok(MainArgs::Run { json: true, .. })
    ));
    assert!(matches!(
        MainArgs::try_parse_from(["guard", "status", "--json"]),
        Ok(MainArgs::Status { json: true, .. })
    ));
    assert!(matches!(
        MainArgs::try_parse_from(["guard", "server", "status", "--json"]),
        Ok(MainArgs::Server(ServerCommands::Status { json: true, .. }))
    ));
    assert!(matches!(
        MainArgs::try_parse_from(["guard", "provisionals", "--json"]),
        Ok(MainArgs::Provisionals { json: true, .. })
    ));
    assert!(matches!(
        MainArgs::try_parse_from(["guard", "resume", "hold-1", "--json"]),
        Ok(MainArgs::Resume { json: true, .. })
    ));
    assert!(matches!(
        MainArgs::try_parse_from(["guard", "approval", "show", "hold-1", "--json"]),
        Ok(MainArgs::Approval(ApprovalCommands::Show {
            json: true,
            ..
        }))
    ));
    assert!(matches!(
        MainArgs::try_parse_from(["guard", "approval", "withdraw", "hold-1"]),
        Ok(MainArgs::Approval(ApprovalCommands::Withdraw { .. }))
    ));
    assert!(matches!(
        MainArgs::try_parse_from(["guard", "access", "list", "--json"]),
        Ok(MainArgs::Access(AccessCommands::List { json: true, .. }))
    ));
    assert!(matches!(
        MainArgs::try_parse_from(["guard", "access", "status", "session:example", "--json"]),
        Ok(MainArgs::Access(AccessCommands::Status { json: true, .. }))
    ));
    assert!(matches!(
        MainArgs::try_parse_from(["guard", "verb", "list", "--json"]),
        Ok(MainArgs::Verb(VerbCommands::List { json: true, .. }))
    ));
    assert!(matches!(
        MainArgs::try_parse_from(["guard", "verb", "run", "uptime", "--json"]),
        Ok(MainArgs::Verb(VerbCommands::Run { json: true, .. }))
    ));
    assert!(matches!(
        MainArgs::try_parse_from(["guard", "verb", "coverage", "list", "--json"]),
        Ok(MainArgs::Verb(VerbCommands::Coverage {
            command: VerbCoverageCommands::List { json: true, .. }
        }))
    ));
    assert!(matches!(
        MainArgs::try_parse_from(["guard", "secret", "list", "--json"]),
        Ok(MainArgs::Secrets(SecretCommands::List { json: true, .. }))
    ));
    assert!(matches!(
        MainArgs::try_parse_from(["guard", "config", "show", "--json"]),
        Ok(MainArgs::Config(ConfigCommands::Show { json: true }))
    ));
    assert!(matches!(
        MainArgs::try_parse_from(["guard", "shim", "--json"]),
        Ok(MainArgs::Shim { json: true, .. })
    ));
}

#[test]
fn guard_exit_codes_do_not_collide_with_common_child_failures() {
    let guard_codes = [EXIT_GUARD_ERROR, EXIT_GUARD_DENIED, EXIT_GUARD_HELD];
    assert_eq!(guard_codes, [125, 126, 127]);
    assert!(!guard_codes.contains(&1));
    assert!(!guard_codes.contains(&75));
}

#[test]
fn unknown_top_level_command_does_not_execute_implicitly() {
    let err = MainArgs::try_parse_from(["guard", "ssh", "host"])
        .err()
        .unwrap();
    assert_eq!(err.kind(), clap::error::ErrorKind::InvalidSubcommand);
}

#[test]
fn wait_approval_accepts_explicit_and_bare_unbounded() {
    for args in [
        vec!["guard", "run", "--wait-approval=unbounded", "true"],
        vec!["guard", "run", "--wait-approval", "--", "true"],
    ] {
        assert!(matches!(
            MainArgs::try_parse_from(args),
            Ok(MainArgs::Run {
                wait_approval: Some(u64::MAX),
                ..
            })
        ));
    }
    assert!(MainArgs::try_parse_from(["guard", "run", "--wait-approval=0", "true"]).is_err());
}

/// Anti-drift guard: the help tree is generated from the clap model, so every
/// printed command path must resolve in that model as a visible command, and
/// every visible command must appear in the tree exactly once, in walk order.
#[test]
fn help_tree_matches_clap_model() {
    let root = MainArgs::command();
    let mut entries = Vec::new();
    help_tree_entries(&root, &[], &mut entries);
    assert!(!entries.is_empty(), "help tree walk found no commands");

    for (path, _display, _about) in &entries {
        let mut current = &root;
        for name in path {
            current = find_subcommand(current, name).unwrap_or_else(|| {
                panic!(
                    "help tree prints `{}`, which is not in the clap model",
                    path.join(" ")
                )
            });
        }
        assert!(
            !current.is_hide_set(),
            "help tree prints hidden command `{}`",
            path.join(" ")
        );
    }

    fn visible_paths(command: &clap::Command, path: &[String], paths: &mut Vec<Vec<String>>) {
        for sub in command.get_subcommands() {
            if sub.is_hide_set() || sub.get_name() == "help" {
                continue;
            }
            let mut sub_path = path.to_vec();
            sub_path.push(sub.get_name().to_string());
            paths.push(sub_path.clone());
            visible_paths(sub, &sub_path, paths);
        }
    }
    let mut expected = Vec::new();
    visible_paths(&root, &[], &mut expected);
    let printed: Vec<Vec<String>> = entries.iter().map(|(path, _, _)| path.clone()).collect();
    assert_eq!(printed, expected, "help tree lags the clap command tree");
}

#[test]
fn provisionals_show_parses_handle_and_flags() {
    match MainArgs::try_parse_from(["guard", "provisionals", "show", "prov-1", "--json"]).unwrap() {
        MainArgs::Provisionals {
            command:
                Some(ProvisionalCommands::Show {
                    handle,
                    socket,
                    json,
                }),
            ..
        } => {
            assert_eq!(handle, "prov-1");
            assert!(socket.is_none());
            assert!(json);
        }
        _ => panic!("expected provisionals show"),
    }
    assert!(matches!(
        MainArgs::try_parse_from(["guard", "provisionals"]),
        Ok(MainArgs::Provisionals { command: None, .. })
    ));
}

#[test]
fn provisional_detail_includes_fields_the_list_line_elides() {
    let item = server::ProvisionalSummary {
        handle: "prov-1".to_string(),
        status: "pending".to_string(),
        forward_outcome: "running".to_string(),
        command: "systemctl restart nginx".to_string(),
        revert_command: "systemctl stop nginx".to_string(),
        confirm_check: Some("curl -fsS localhost".to_string()),
        control_path: Some("local systemd".to_string()),
        session_fingerprint: Some("ses-9".to_string()),
        reason: "recoverable service restart".to_string(),
        created_unix: 1000,
        deadline_unix: 1600,
        forward_done: true,
        cwd: Some("/srv/app".to_string()),
        secret_names: vec!["deploy-token".to_string()],
        principal: Some("agent:alice".to_string()),
        revert_exit: None,
        revert_detail: None,
        decision_trace: None,
    };
    let detail = cli_client::provisional_detail_human(&item);
    for expected in [
        "provisional prov-1",
        "status: pending",
        "forward_outcome: running",
        "forward_done: true",
        "command: systemctl restart nginx",
        "revert: systemctl stop nginx",
        "check: curl -fsS localhost",
        "control_path: local systemd",
        "cwd: /srv/app",
        "session: ses-9",
        "principal: agent:alice",
        "secrets: deploy-token",
        "reason: recoverable service restart",
    ] {
        assert!(
            detail.contains(expected),
            "detail missing `{expected}`:\n{detail}"
        );
    }
}

#[test]
fn access_list_parses_state_and_agent_filters() {
    match MainArgs::try_parse_from([
        "guard",
        "access",
        "list",
        "--state",
        "pending",
        "--agent",
        "agent:alice",
    ])
    .unwrap()
    {
        MainArgs::Access(AccessCommands::List { state, agent, .. }) => {
            assert_eq!(state.as_deref(), Some("pending"));
            assert_eq!(agent.as_deref(), Some("agent:alice"));
        }
        _ => panic!("expected access list"),
    }
}

fn access_item_fixture(reference: &str, state: &str, requester: &str) -> server::AccessItem {
    server::AccessItem {
        reference: reference.to_string(),
        kind: "request".to_string(),
        requester: requester.to_string(),
        target: "unassigned".to_string(),
        effective_scope: Vec::new(),
        expires_unix: None,
        remaining_uses: None,
        use_policy: "unselected".to_string(),
        consequence: String::new(),
        default_use_policy: None,
        default_uses: None,
        state: state.to_string(),
        next_action: String::new(),
        approval_options: Vec::new(),
        intent: None,
        capabilities: Vec::new(),
        decided_reason: None,
    }
}

#[test]
fn access_list_filters_narrow_by_state_and_agent() {
    let items = || {
        vec![
            access_item_fixture("req-1", "pending", "agent:alice"),
            access_item_fixture("req-2", "expired", "agent:alice"),
            access_item_fixture("ses-3", "active", "agent:bob"),
        ]
    };
    let references = |items: &[server::AccessItem]| {
        items
            .iter()
            .map(|i| i.reference.clone())
            .collect::<Vec<_>>()
    };

    let mut by_state = items();
    cli_client::filter_access_items(&mut by_state, Some("pending"), None);
    assert_eq!(references(&by_state), ["req-1"]);

    let mut by_agent = items();
    cli_client::filter_access_items(&mut by_agent, None, Some("agent:alice"));
    assert_eq!(references(&by_agent), ["req-1", "req-2"]);

    let mut by_both = items();
    cli_client::filter_access_items(&mut by_both, Some("expired"), Some("agent:alice"));
    assert_eq!(references(&by_both), ["req-2"]);

    let mut unfiltered = items();
    cli_client::filter_access_items(&mut unfiltered, None, None);
    assert_eq!(unfiltered.len(), 3);
}

#[test]
fn verb_show_and_delete_are_visible_commands() {
    let root = MainArgs::command();
    let verb = find_subcommand(&root, "verb").expect("verb command exists");
    for name in ["show", "delete"] {
        let sub = find_subcommand(verb, name)
            .unwrap_or_else(|| panic!("verb {name} is in the clap model"));
        assert!(!sub.is_hide_set(), "verb {name} must be visible");
    }
}
