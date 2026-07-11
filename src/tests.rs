use super::*;

fn parse_start(args: &[&str]) -> ServerCommands {
    match MainArgs::parse_from(args) {
        MainArgs::Server(ServerCommands::Start {
            socket,
            tcp_port,
            auth_token,
            admin_token,
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
            exec_as_caller,
            system_prompt,
            system_prompt_append,
            gate,
            verbs,
            profiles,
            allow_bin,
            child_env,
            api_proxy,
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
            service,
        }) => ServerCommands::Start {
            socket,
            tcp_port,
            auth_token,
            admin_token,
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
            exec_as_caller,
            system_prompt,
            system_prompt_append,
            gate,
            verbs,
            profiles,
            allow_bin,
            child_env,
            api_proxy,
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
            service,
        },
        _ => panic!("expected server start args"),
    }
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
fn test_server_start_admin_token_flag() {
    let ServerCommands::Start { admin_token, .. } =
        parse_start(&["guard", "server", "start", "--admin-token", "adm"])
    else {
        panic!("expected start");
    };
    assert_eq!(admin_token.as_deref(), Some("adm"));
}

#[test]
fn top_level_grant_parses_prose_and_static_only() {
    match MainArgs::try_parse_from([
        "guard",
        "grant",
        "tok",
        "--static-only",
        "readonly grafana kube access",
    ]) {
        Ok(MainArgs::Grant {
            token,
            prose,
            static_only,
            ..
        }) => {
            assert_eq!(token.as_deref(), Some("tok"));
            assert_eq!(prose.as_deref(), Some("readonly grafana kube access"));
            assert!(static_only);
        }
        Ok(_) => panic!("expected top-level grant"),
        Err(err) => panic!("expected grant parse, got {err}"),
    }
}

#[test]
fn top_level_grant_bare_prose_mints_session() {
    let command = top_level_grant_to_session_command(
        Some("readonly grafana kube access".to_string()),
        None,
        Vec::new(),
        Vec::new(),
        Some(120),
        None,
        None,
        true,
        false,
        false,
        None,
    );

    match command {
        SessionCommands::New {
            prose,
            ttl,
            static_only,
            ..
        } => {
            assert_eq!(prose.as_deref(), Some("readonly grafana kube access"));
            assert_eq!(ttl, Some(120));
            assert!(static_only);
        }
        _ => panic!("expected top-level prose grant to mint a session"),
    }
}

#[test]
fn top_level_grant_token_shaped_word_keeps_token_path() {
    let command = top_level_grant_to_session_command(
        Some("0123456789abcdef0123456789abcdef".to_string()),
        None,
        vec!["whoami".to_string()],
        Vec::new(),
        None,
        None,
        None,
        false,
        false,
        false,
        None,
    );

    match command {
        SessionCommands::Grant { token, allow, .. } => {
            assert_eq!(token, "0123456789abcdef0123456789abcdef");
            assert_eq!(allow, vec!["whoami"]);
        }
        _ => panic!("expected token-shaped top-level grant to update a session"),
    }
}

#[test]
fn top_level_grant_plain_word_is_prose_not_token() {
    // `guard grant readonly` must not target a session literally named
    // "readonly"; a single word that is not 32 lowercase hex chars is prose.
    let command = top_level_grant_to_session_command(
        Some("readonly".to_string()),
        None,
        Vec::new(),
        Vec::new(),
        None,
        None,
        None,
        false,
        false,
        false,
        None,
    );

    match command {
        SessionCommands::New { prose, .. } => {
            assert_eq!(prose.as_deref(), Some("readonly"));
        }
        _ => panic!("expected non-token single word to mint a session with prose"),
    }
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

#[test]
fn session_grant_parses_prose_and_static_only_alias() {
    match MainArgs::try_parse_from([
        "guard",
        "session",
        "grant",
        "tok",
        "--no-llm-fallback",
        "readonly grafana kube access",
    ]) {
        Ok(MainArgs::Session(SessionCommands::Grant {
            token,
            prose,
            static_only,
            ..
        })) => {
            assert_eq!(token, "tok");
            assert_eq!(prose.as_deref(), Some("readonly grafana kube access"));
            assert!(static_only);
        }
        Ok(_) => panic!("expected session grant"),
        Err(err) => panic!("expected session grant parse, got {err}"),
    }
}

#[test]
fn session_grant_parses_auto_amend_flags() {
    match MainArgs::try_parse_from([
        "guard",
        "session",
        "grant",
        "tok",
        "--auto-amend",
        "--no-auto-amend",
        "readonly grafana kube access",
    ]) {
        Ok(MainArgs::Session(SessionCommands::Grant {
            auto_amend,
            no_auto_amend,
            ..
        })) => {
            assert!(auto_amend);
            assert!(no_auto_amend);
        }
        Ok(_) => panic!("expected session grant"),
        Err(err) => panic!("expected session grant parse, got {err}"),
    }
}

#[test]
fn session_appeal_forwards_hyphen_args() {
    match MainArgs::try_parse_from(["guard", "session", "appeal", "tok", "df", "-h", "--output"]) {
        Ok(MainArgs::Session(SessionCommands::Appeal {
            token,
            binary,
            args,
            ..
        })) => {
            assert_eq!(token, "tok");
            assert_eq!(binary, "df");
            assert_eq!(args, vec!["-h", "--output"]);
        }
        Ok(_) => panic!("expected session appeal"),
        Err(err) => panic!("expected session appeal parse, got {err}"),
    }
}

#[test]
fn top_level_appeal_parses_session_and_command() {
    match MainArgs::try_parse_from([
        "guard",
        "appeal",
        "--session",
        "tok",
        "kubectl",
        "get",
        "pods",
        "-n",
        "grafana",
    ]) {
        Ok(MainArgs::Appeal {
            session,
            binary,
            args,
            ..
        }) => {
            assert_eq!(session.as_deref(), Some("tok"));
            assert_eq!(binary, "kubectl");
            assert_eq!(args, vec!["get", "pods", "-n", "grafana"]);
        }
        Ok(_) => panic!("expected top-level appeal"),
        Err(err) => panic!("expected top-level appeal parse, got {err}"),
    }
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
        passthrough_command_help_requested(&["appeal".to_string(), "--help".to_string()]),
        Some((vec!["appeal"], "guard appeal"))
    );
    // Help after guard's own options (but before the binary) is still guard's.
    assert_eq!(
        passthrough_command_help_requested(&[
            "appeal".to_string(),
            "--session".to_string(),
            "tok".to_string(),
            "--help".to_string()
        ]),
        Some((vec!["appeal"], "guard appeal"))
    );
    assert_eq!(
        passthrough_command_help_requested(&[
            "session".to_string(),
            "appeal".to_string(),
            "-h".to_string()
        ]),
        Some((vec!["session", "appeal"], "guard session appeal"))
    );
    // Token given, binary not yet: help is still for guard.
    assert_eq!(
        passthrough_command_help_requested(&[
            "session".to_string(),
            "appeal".to_string(),
            "tok".to_string(),
            "--help".to_string()
        ]),
        Some((vec!["session", "appeal"], "guard session appeal"))
    );
    assert_eq!(
        passthrough_command_help_requested(&[
            "run".to_string(),
            "df".to_string(),
            "--help".to_string()
        ]),
        None
    );
    // Once the binary is named, `--help`/`-h` belong to the appealed command.
    assert_eq!(
        passthrough_command_help_requested(&[
            "appeal".to_string(),
            "kubectl".to_string(),
            "--help".to_string()
        ]),
        None
    );
    assert_eq!(
        passthrough_command_help_requested(&[
            "session".to_string(),
            "appeal".to_string(),
            "tok".to_string(),
            "df".to_string(),
            "-h".to_string()
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
        "session show"
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
        MainArgs::Secrets(SecretCommands::List { detailed: false })
    ));
}

#[test]
fn unknown_top_level_command_does_not_execute_implicitly() {
    let err = MainArgs::try_parse_from(["guard", "ssh", "host"])
        .err()
        .unwrap();
    assert_eq!(err.kind(), clap::error::ErrorKind::InvalidSubcommand);
}
