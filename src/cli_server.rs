use super::*;

#[cfg(unix)]
fn current_uid() -> u32 {
    unsafe { libc::geteuid() as u32 }
}

fn default_state_db_path() -> Option<PathBuf> {
    default_guard_state_dir().map(|dir| dir.join("state.db"))
}

pub(crate) fn resolve_history_retention(
    configured: Option<u64>,
    environment: Option<String>,
) -> Result<u64> {
    let value = match configured {
        Some(value) => value,
        None => match environment {
            Some(value) => value
                .parse::<u64>()
                .context("GUARD_HISTORY_RETENTION_SECS must be a positive integer")?,
            None => session::DEFAULT_HISTORY_RETENTION_SECS,
        },
    };
    if value == 0 {
        anyhow::bail!("history retention must be greater than zero");
    }
    Ok(value)
}

/// Resolve the GUARD_MODE env value: unset or blank defaults to readonly,
/// and a present-but-invalid value fails startup loudly (like --gate)
/// instead of silently falling back to readonly.
pub(crate) fn resolve_policy_mode(value: Option<String>) -> Result<PolicyMode> {
    match value.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        Some(value) => PolicyMode::parse(value).ok_or_else(|| {
            anyhow::anyhow!(
                "invalid GUARD_MODE value '{}' (expected 'readonly', 'paranoid', or 'safe')",
                value
            )
        }),
        None => Ok(PolicyMode::Readonly),
    }
}

fn default_learned_rules_path() -> Option<PathBuf> {
    default_guard_state_dir().map(|dir| dir.join("learned-rules.yaml"))
}

fn default_deny_shapes_path() -> Option<PathBuf> {
    default_guard_state_dir().map(|dir| dir.join("learned-deny.yaml"))
}

fn default_allow_promotion_state_path() -> Option<PathBuf> {
    default_guard_state_dir().map(|dir| dir.join("learned-allow.yaml"))
}

fn default_api_promotion_state_path() -> Option<PathBuf> {
    default_guard_state_dir().map(|dir| dir.join("learned-api.yaml"))
}

/// Default verb catalog path used only when `--verbs` was not given but
/// auto-promotion is enabled and needs somewhere to persist a promoted verb.
/// Unlike `--verbs`, a missing file at this path is not an error (see the
/// call site): auto-promotion should work out of the box on a fresh host,
/// the same way `--learn-deny` and `--learn-rules` do not require the
/// operator to hand-create a state file first.
fn default_verbs_path() -> Option<PathBuf> {
    default_guard_state_dir().map(|dir| dir.join("verbs.yaml"))
}

fn default_guard_state_dir() -> Option<PathBuf> {
    if let Some(dir) = dirs::state_dir() {
        return Some(dir.join("guard"));
    }
    if let Some(dir) = dirs::data_local_dir() {
        return Some(dir.join("guard"));
    }
    dirs::home_dir().map(|dir| dir.join(".guard"))
}

pub(crate) async fn run_server(cmd: ServerCommands) -> Result<()> {
    match cmd {
        ServerCommands::Start {
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
            history_retention,
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
            // Consumed in `main` (Windows SCM dispatch); irrelevant to the
            // server run itself, which is identical in service and foreground.
            service: _,
        } => {
            tracing::info!("Starting guard server...");

            // Resolve consequence-gating mode: flag > GUARD_GATE env > off.
            let gate_mode: guard::gating::GateMode = gate
                .or_else(|| guard_env("GATE").filter(|v| !v.is_empty()))
                .map(|v| v.parse())
                .transpose()
                .map_err(anyhow::Error::msg)
                .context("invalid --gate value (expected 'off' or 'consequence')")?
                .unwrap_or_default();
            if gate_mode.is_on() {
                tracing::info!("Consequence gating enabled (mode: {})", gate_mode);
            }

            // --users is a Unix-uid allow-list enforced via SO_PEERCRED. The
            // Windows named-pipe transport authenticates peers by SID, so the
            // flag has no effect there; fail fast rather than silently ignore a
            // security control.
            #[cfg(windows)]
            if users.as_deref().is_some_and(|s| !s.trim().is_empty()) {
                anyhow::bail!(
                    "--users is not supported on Windows (the named-pipe transport authenticates peers by SID, not Unix uid); restrict access via the pipe ACL instead"
                );
            }

            let configured_socket = socket.map(PathBuf::from).or_else(|| {
                let config = client_config::ClientConfig::load().ok()?;
                config.server_socket.map(PathBuf::from)
            });
            // Local transport: a Unix-domain socket on Unix, a named pipe on
            // Windows (winplat::pipe_name maps `--socket <name>` to
            // \\.\pipe\<name>). On Unix it also falls back to a home-dir default.
            #[cfg(unix)]
            let socket_path = configured_socket.or_else(defaults::home_socket);
            #[cfg(windows)]
            let socket_path = configured_socket;

            // TCP loopback is the Windows no-flag default, but only when no named
            // pipe was selected; an explicit --socket chooses the pipe instead.
            let tcp_port = tcp_port
                .or_else(|| guard_env("TCP_PORT").and_then(|v| v.parse::<u16>().ok()))
                .or({
                    #[cfg(windows)]
                    {
                        if socket_path.is_none() {
                            Some(defaults::DEFAULT_TCP_PORT)
                        } else {
                            None
                        }
                    }
                    #[cfg(not(windows))]
                    {
                        None
                    }
                });

            // Consequence gating is principal-scoped: only a kernel-verified
            // local peer (a Unix-socket uid or a Windows named-pipe SID) can be
            // the operator. A TCP listener carries only a bearer token, so it
            // both cannot reach the operator gate and needlessly widens the exec
            // surface. Enforce on the FINAL resolved transport - after --tcp-port,
            // GUARD_TCP_PORT, and the platform default - so an env-set TCP
            // port cannot slip a listener in beside the gate.
            if gate_mode.is_on() {
                if tcp_port.is_some() {
                    anyhow::bail!(
                        "--gate consequence is incompatible with a TCP listener (--tcp-port or GUARD_TCP_PORT); the operator approval gate is principal-scoped and unreachable over TCP. Use a local socket via --socket."
                    );
                }
                if socket_path.is_none() {
                    anyhow::bail!(
                        "--gate consequence requires a local listener: pass --socket (a Unix-domain socket on Unix, a named pipe on Windows). TCP carries no peer identity and cannot reach the operator approval gate."
                    );
                }
            }

            if let Some(ref path) = socket_path {
                tracing::info!("Socket: {}", path.display());
            }
            if let Some(port) = tcp_port {
                tracing::info!("TCP: 127.0.0.1:{}", port);
            }
            let auth_token = auth_token
                .filter(|token| !token.is_empty())
                .or_else(|| guard_env("AUTH_TOKEN").filter(|token| !token.is_empty()));
            if tcp_port.is_some() && auth_token.is_none() {
                anyhow::bail!(
                    "TCP server requires --auth-token or GUARD_AUTH_TOKEN; configure clients with `guard config set-token`"
                );
            }
            let admin_token = admin_token
                .filter(|token| !token.is_empty())
                .or_else(|| guard_env("ADMIN_TOKEN").filter(|token| !token.is_empty()));
            if tcp_port.is_some() && admin_token.is_none() {
                tracing::warn!(
                    "TCP admin RPCs other than ping are disabled; set --admin-token or GUARD_ADMIN_TOKEN to use guard grant/status over TCP"
                );
            }

            let shim_dir =
                shim_dir.or_else(|| dirs::home_dir().map(|h| h.join(".guard").join("shims")));

            if let Some(ref dir) = shim_dir {
                tracing::info!("Shim dir (nested evaluation): {}", dir.display());
            }

            let allowed_uids: Option<Vec<u32>> =
                users.map(|s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect());
            tracing::info!("Allowed UIDs: {:?}", allowed_uids);

            let dry_run = dry_run
                || guard_env("DRY_RUN")
                    .as_deref()
                    .map(parse_env_bool)
                    .unwrap_or(false);
            if dry_run {
                tracing::warn!("Dry-run mode enabled: approved commands will not be executed");
            }

            let state_db_path = state_db
                .or_else(|| {
                    guard_env("STATE_DB")
                        .filter(|value| !value.is_empty())
                        .map(PathBuf::from)
                })
                .or_else(default_state_db_path);
            if let Some(ref path) = state_db_path {
                tracing::info!("State DB: {}", path.display());
            }

            let exec_as_caller = exec_as_caller
                || guard_env("EXEC_AS_CALLER")
                    .as_deref()
                    .map(parse_env_bool)
                    .unwrap_or(false);
            if exec_as_caller {
                #[cfg(windows)]
                anyhow::bail!(
                    "--exec-as-caller is not supported on Windows; the daemon executes approved commands as its own service account"
                );
                #[cfg(unix)]
                {
                    let daemon_uid = current_uid();
                    if daemon_uid != 0 {
                        anyhow::bail!("--exec-as-caller requires the daemon to start as root");
                    }
                    if tcp_port.is_some() {
                        anyhow::bail!(
                            "--exec-as-caller requires a unix socket only; TCP callers do not carry a trusted local UID"
                        );
                    }
                    tracing::info!("Approved commands will execute as the connecting unix uid");
                }
            }

            let llm_enabled = resolve_bool_flag(llm, no_llm, true);
            if !llm_enabled {
                tracing::info!("LLM evaluation disabled (static policy only)");
            }

            let api_key = llm_api_key
                .or_else(|| guard_env("LLM_API_KEY"))
                .or_else(|| std::env::var("OPENROUTER_API_KEY").ok());

            if llm_enabled && api_key.is_none() {
                tracing::warn!("No LLM API key provided (set GUARD_LLM_API_KEY, OPENROUTER_API_KEY, or --llm-api-key)");
            }

            let resolved_timeout = llm_timeout
                .or_else(|| guard_env("LLM_TIMEOUT").and_then(|v| v.parse::<u64>().ok()))
                .unwrap_or(30);
            let mut eval_config = evaluate::EvalConfig::default()
                .llm_enabled(llm_enabled)
                .gate_mode(gate_mode)
                .llm_timeout_secs(resolved_timeout);

            if let Some(api_key) = api_key.filter(|value| !value.is_empty()) {
                eval_config = eval_config.llm_api_key(api_key);
            }

            let resolved_api_url = llm_api_url
                .filter(|value| !value.is_empty())
                .or_else(|| guard_env("LLM_API_URL").filter(|value| !value.is_empty()));
            if let Some(api_url) = resolved_api_url {
                eval_config = eval_config.llm_api_url(api_url);
            }

            // Model resolution precedence (single primary model):
            //   1. --llm-model CLI flag
            //   2. GUARD_LLM_MODEL env var (singular - primary model)
            //   3. evaluate::EvalConfig default (DEFAULT_MODEL in evaluate.rs)
            //
            // The fallback chain (GUARD_LLM_MODELS / --llm-models) is
            // resolved separately below and, when set, takes precedence over
            // the single-model value above because a chain is an explicit
            // opt-in to multi-model evaluation.
            let resolved_single_model = llm_model
                .filter(|value| !value.is_empty())
                .or_else(|| guard_env("LLM_MODEL").filter(|v| !v.is_empty()));
            if let Some(model) = resolved_single_model {
                eval_config = eval_config.llm_model(model);
            }

            // Retries: flag > env var > default.
            let retries = llm_retries
                .or_else(|| guard_env("LLM_RETRIES").and_then(|v| v.parse::<u32>().ok()))
                .unwrap_or(2);
            eval_config = eval_config.llm_retries(retries);
            tracing::info!("LLM retries per model: {}", retries);

            // Fallback chain: flag > env var > empty (no chain, single model).
            // When non-empty this supersedes the single-model value above.
            let models_chain: Vec<String> = llm_models
                .unwrap_or_default()
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>();
            let models_chain = if models_chain.is_empty() {
                guard_env("LLM_MODELS")
                    .map(|v| {
                        v.split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            } else {
                models_chain
            };
            if !models_chain.is_empty() {
                tracing::info!("LLM model fallback chain: {:?}", models_chain);
                eval_config = eval_config.llm_models(models_chain);
            }

            let mode = resolve_policy_mode(guard_env("MODE"))?;

            tracing::info!("Using built-in {} policy mode", mode.as_str());
            eval_config = eval_config.mode(mode);

            if let Some(ref policy_path) = policy {
                tracing::info!("Loading static policy from: {}", policy_path);
                eval_config = eval_config.policy_path(PathBuf::from(policy_path));
            }

            if let Some(ref prompt_path) = system_prompt {
                tracing::info!("Loading system prompt from: {}", prompt_path.display());
                eval_config = eval_config.system_prompt_path(prompt_path.clone());
            }

            // Cache: flag disable wins, else env GUARD_CACHE=false disables.
            // Capacity and TTL: flag > env > default.
            let cache_env_enabled = guard_env("CACHE")
                .as_deref()
                .map(parse_env_bool)
                .unwrap_or(true);
            let cache_enabled = !no_cache && cache_env_enabled;
            let cache_capacity = cache_capacity
                .or_else(|| guard_env("CACHE_CAPACITY").and_then(|v| v.parse::<usize>().ok()))
                .unwrap_or(evaluate::DEFAULT_CACHE_CAPACITY);
            let cache_ttl_secs = cache_ttl
                .or_else(|| guard_env("CACHE_TTL").and_then(|v| v.parse::<u64>().ok()))
                .unwrap_or(evaluate::DEFAULT_CACHE_TTL_SECS);
            eval_config = eval_config
                .cache_enabled(cache_enabled)
                .cache_capacity(cache_capacity)
                .cache_ttl(std::time::Duration::from_secs(cache_ttl_secs));
            if !cache_enabled {
                tracing::info!("LLM decision cache disabled");
            }

            let learning_enabled = learn_rules
                || guard_env("LEARN_RULES")
                    .as_deref()
                    .map(parse_env_bool)
                    .unwrap_or(false);
            if learning_enabled {
                let learned_rules_path = learned_rules
                    .or_else(|| {
                        guard_env("LEARNED_RULES")
                            .filter(|value| !value.is_empty())
                            .map(PathBuf::from)
                    })
                    .or_else(default_learned_rules_path)
                    .ok_or_else(|| anyhow::anyhow!("could not determine learned rules path"))?;
                let mut learning_config = LearningConfig::new(learned_rules_path.clone());
                learning_config.min_approvals = learn_min_approvals
                    .or_else(|| {
                        guard_env("LEARN_MIN_APPROVALS").and_then(|v| v.parse::<u32>().ok())
                    })
                    .unwrap_or(learning_config.min_approvals)
                    .max(1);
                learning_config.max_risk = learn_max_risk
                    .or_else(|| guard_env("LEARN_MAX_RISK").and_then(|v| v.parse::<i32>().ok()))
                    .unwrap_or(learning_config.max_risk)
                    .clamp(0, 10);
                let shim_mode = learn_shims
                    .or_else(|| guard_env("LEARN_SHIMS"))
                    .and_then(|value| AutoShimMode::parse(&value))
                    .unwrap_or(learning_config.auto_shim);
                learning_config.auto_shim = shim_mode;
                let store = LearnedRuleStore::load(learning_config).with_context(|| {
                    format!(
                        "failed to load learned rules from {}",
                        learned_rules_path.display()
                    )
                })?;
                tracing::info!(
                    "Learned-rule candidate detection enabled: path={} min_approvals={} max_risk={} shims={}",
                    store.path().display(),
                    store.min_approvals(),
                    store.max_risk(),
                    store.auto_shim().as_str()
                );
                eval_config = eval_config.learned_rules(Arc::new(RwLock::new(store)));
            }

            let deny_learning_enabled = if no_learn_deny {
                false
            } else {
                learn_deny
                    .or_else(|| guard_env("LEARN_DENY").map(|v| parse_env_bool(&v)))
                    .unwrap_or(true)
            };
            if deny_learning_enabled {
                let deny_shapes_path = deny_shapes
                    .or_else(|| {
                        guard_env("DENY_SHAPES")
                            .filter(|value| !value.is_empty())
                            .map(PathBuf::from)
                    })
                    .or_else(default_deny_shapes_path)
                    .ok_or_else(|| anyhow::anyhow!("could not determine deny-shapes path"))?;
                let mut deny_config =
                    guard::gating::deny_shape::DenyLearningConfig::new(deny_shapes_path.clone());
                deny_config.min_denials = learn_deny_min_denials
                    .or_else(|| {
                        guard_env("LEARN_DENY_MIN_DENIALS").and_then(|v| v.parse::<u32>().ok())
                    })
                    .unwrap_or(deny_config.min_denials)
                    .max(1);
                let store = guard::gating::deny_shape::DenyShapeStore::load(deny_config)
                    .with_context(|| {
                        format!(
                            "failed to load deny shapes from {}",
                            deny_shapes_path.display()
                        )
                    })?;
                tracing::info!(
                    "Auto-learned deny shapes enabled: path={} min_denials={}",
                    store.path().display(),
                    store.min_denials()
                );
                eval_config = eval_config.deny_shapes(Arc::new(RwLock::new(store)));
            }

            let allow_promotion_enabled = if no_learn_allow {
                false
            } else {
                learn_allow
                    .or_else(|| guard_env("LEARN_ALLOW").map(|v| parse_env_bool(&v)))
                    .unwrap_or(true)
            };
            if allow_promotion_enabled {
                let learn_allow_state_path = learn_allow_state
                    .or_else(|| {
                        guard_env("LEARN_ALLOW_STATE")
                            .filter(|value| !value.is_empty())
                            .map(PathBuf::from)
                    })
                    .or_else(default_allow_promotion_state_path)
                    .ok_or_else(|| {
                        anyhow::anyhow!("could not determine allow-promotion state path")
                    })?;
                let mut allow_config = guard::gating::allow_promotion::AllowPromotionConfig::new(
                    learn_allow_state_path.clone(),
                );
                allow_config.min_approvals = learn_allow_min_approvals
                    .or_else(|| {
                        guard_env("LEARN_ALLOW_MIN_APPROVALS").and_then(|v| v.parse::<u32>().ok())
                    })
                    .unwrap_or(allow_config.min_approvals)
                    .max(2);
                let store = guard::gating::allow_promotion::AllowPromotionStore::load(allow_config)
                    .with_context(|| {
                        format!(
                            "failed to load allow-promotion state from {}",
                            learn_allow_state_path.display()
                        )
                    })?;
                tracing::info!(
                    "Auto-verb-promotion enabled: path={} min_approvals={}",
                    store.path().display(),
                    store.min_approvals()
                );
                eval_config = eval_config.allow_promotion(Arc::new(RwLock::new(store)));
            }

            let api_promotion_enabled = if no_api_promotion {
                false
            } else {
                api_promotion
                    .or_else(|| guard_env("API_PROMOTION").map(|v| parse_env_bool(&v)))
                    .unwrap_or(true)
            };
            let api_promotion_store = if api_promotion_enabled {
                let api_promotion_state_path = api_promotion_state
                    .or_else(|| {
                        guard_env("API_PROMOTION_STATE")
                            .filter(|value| !value.is_empty())
                            .map(PathBuf::from)
                    })
                    .or_else(default_api_promotion_state_path)
                    .ok_or_else(|| {
                        anyhow::anyhow!("could not determine API promotion state path")
                    })?;
                let mut api_config = guard::gating::api_promotion::ApiPromotionConfig::new(
                    api_promotion_state_path.clone(),
                );
                api_config.min_approvals = api_promotion_min_approvals
                    .or_else(|| {
                        guard_env("API_PROMOTION_MIN_APPROVALS").and_then(|v| v.parse::<u32>().ok())
                    })
                    .unwrap_or(api_config.min_approvals)
                    .max(2);
                api_config.min_denials = api_promotion_min_denials
                    .or_else(|| {
                        guard_env("API_PROMOTION_MIN_DENIALS").and_then(|v| v.parse::<u32>().ok())
                    })
                    .unwrap_or(api_config.min_denials)
                    .max(1);
                let store = guard::gating::api_promotion::ApiPromotionStore::load(api_config)
                    .with_context(|| {
                        format!(
                            "failed to load API promotion state from {}",
                            api_promotion_state_path.display()
                        )
                    })?;
                tracing::info!(
                    "API request-shape learning enabled: path={} min_approvals={} min_denials={}",
                    store.path().display(),
                    store.min_approvals(),
                    store.min_denials()
                );
                Some(Arc::new(RwLock::new(store)))
            } else {
                None
            };

            // Additive prompt: append to base prompt without replacing it.
            // Priority: --system-prompt-append flag > GUARD_PROMPT_APPEND env var
            let append_path = system_prompt_append.or_else(|| {
                guard_env("PROMPT_APPEND")
                    .filter(|v| !v.is_empty())
                    .map(PathBuf::from)
            });
            if let Some(ref path) = append_path {
                tracing::info!("Appending additive prompt from: {}", path.display());
                eval_config = eval_config.system_prompt_append_path(path.clone());
            }

            // Secret backend is built BEFORE the evaluator so the daemon can
            // source its own LLM key from the backend when none was supplied by
            // flag or env (see the unified-startup-secret block below).
            tracing::info!("Initializing secret backend...");
            let backend_type = match guard_env("BACKEND") {
                Some(value) => value
                    .parse::<secrets::BackendType>()
                    .map_err(anyhow::Error::msg)
                    .context("invalid secret backend")?,
                None => secrets::detect_backend(),
            };
            tracing::info!("Using {} secret backend", backend_type.as_str());
            if guard_env("BACKEND").is_none() && backend_type == secrets::BackendType::Env {
                tracing::warn!(
                    "auto-selected env secret backend; secrets are process-local and will disappear on daemon restart"
                );
            }
            let backend = backend_type
                .build()
                .context("Failed to create secret backend")?;
            let secrets = secrets::SecretManager::new(backend);
            tracing::info!("Secret backend ready");

            // Unify the daemon's own startup secret onto the secret backend: when
            // no LLM key was supplied via --llm-api-key or env, read it from the
            // backend as a secret owned by the server principal (GUARD_SERVER_UID,
            // else the daemon's own principal). This reuses the same fetch / cache
            // / redaction path as any brokered secret, so the daemon can source
            // its key from pass/vault/infisical without an external `vault agent`
            // or `infisical run` wrapper around `guard server start`.
            if llm_enabled
                && eval_config
                    .llm
                    .api_key
                    .as_ref()
                    .map(|k| k.is_empty())
                    .unwrap_or(true)
            {
                let server_principal = match guard_env("SERVER_UID") {
                    Some(uid_str) => match uid_str.trim().parse::<u32>() {
                        Ok(uid) => guard::principal::PrincipalKey::from_uid(uid),
                        Err(_) => {
                            tracing::warn!(
                                "GUARD_SERVER_UID is not a valid uid; using the daemon principal"
                            );
                            server::resolve_daemon_principal()
                        }
                    },
                    None => server::resolve_daemon_principal(),
                };
                match secrets.get(&server_principal, "LLM_API_KEY").await {
                    Ok(Some(key)) if !key.is_empty() => {
                        tracing::info!(
                            "Loaded LLM API key from the {} secret backend (owner {})",
                            secrets.backend_name(),
                            server_principal.as_str()
                        );
                        eval_config = eval_config.llm_api_key(key);
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!("Could not read LLM API key from the secret backend: {}", e)
                    }
                }
            }

            // Collect known secret values for exact-match output redaction BEFORE
            // moving eval_config into the evaluator. This includes a backend-
            // sourced daemon key resolved just above.
            let mut redact_secrets: Vec<String> = Vec::new();
            if let Some(ref key) = eval_config.llm.api_key {
                if !key.is_empty() {
                    redact_secrets.push(key.clone());
                }
            }

            let api_judge_llm = eval_config.llm.clone();
            let api_judge_cache_enabled = cache_enabled;
            let api_judge_cache_capacity = cache_capacity;
            let api_judge_cache_ttl = std::time::Duration::from_secs(cache_ttl_secs);

            tracing::info!("Creating evaluator...");
            let evaluator =
                evaluate::Evaluator::new(eval_config).context("Failed to create evaluator")?;
            tracing::info!("Evaluator created successfully");

            // Redaction is server-side only, controlled by CLI flag.
            // NOT readable from child env (prevents GUARD_REDACT=false bypass).
            let redact = !no_redact;

            let preflight = preflight
                || guard_env("PREFLIGHT")
                    .as_deref()
                    .map(parse_env_bool)
                    .unwrap_or(false);
            if preflight {
                tracing::info!(
                    "Preflight checks enabled (executable validation, credential pattern deny)"
                );
            }

            tracing::info!("Admin RPCs restricted to daemon UID");

            let tool_registry = tool_config::ToolRegistry::load_default().unwrap_or_else(|e| {
                tracing::warn!("Could not load tool config: {}", e);
                tool_config::ToolRegistry::empty()
            });
            let tool_count = tool_registry.list().count();
            if tool_count > 0 {
                tracing::info!("Loaded {} tool config(s)", tool_count);
            }
            if let Some(ref token) = auth_token {
                redact_secrets.push(token.clone());
            }

            let history_retention_secs =
                resolve_history_retention(history_retention, guard_env("HISTORY_RETENTION_SECS"))?;

            let (sessions, session_store) = if let Some(ref path) = state_db_path {
                let store = session_store::SessionStore::open(path.clone(), history_retention_secs)
                    .await
                    .with_context(|| format!("failed to open state db {}", path.display()))?;
                let sessions = store
                    .load_registry()
                    .await
                    .with_context(|| format!("failed to load state db {}", path.display()))?;
                (sessions, Some(store))
            } else {
                (session::SessionRegistry::new(), None)
            };

            let socket_announcement = socket_path
                .as_ref()
                .map(|path| format!("guard server listening on socket {}", path.display()));

            tracing::info!("Creating server instance...");
            let mut srv = server::Server::new(
                socket_path,
                tcp_port,
                evaluator,
                secrets,
                redact,
                auth_token,
                admin_token,
                socket_group,
                allowed_uids,
                shim_dir,
                dry_run,
                tool_registry,
                redact_secrets,
                preflight,
                sessions,
                session_store,
                exec_as_caller,
                state_db_path,
            );
            srv.set_gate(gate_mode);

            let explicit_verbs_path = verbs.or_else(|| {
                guard_env("VERBS")
                    .filter(|v| !v.is_empty())
                    .map(PathBuf::from)
            });
            // An explicitly-given --verbs/GUARD_VERBS path must already exist:
            // an operator naming a path is trusted to have created it, and a
            // typo should fail loudly rather than silently start with zero
            // verbs. Auto-promotion falling back to its own default path is
            // different -- it should work out of the box on a fresh host, the
            // same way --learn-deny does not require a pre-created state
            // file, so that path is created empty if missing. Gated on
            // `gate_mode.is_on()` too (not just `allow_promotion_enabled`,
            // which defaults to true independent of gating): promotion is
            // inert without consequence gating (see `AllowPromotionStore::
            // record_approval`), so there is no reason to create a live,
            // trust-bearing catalog file a daemon running without --gate
            // could never populate.
            let verbs_path = match explicit_verbs_path {
                Some(path) => Some(path),
                None if allow_promotion_enabled && gate_mode.is_on() => {
                    let path = default_verbs_path()
                        .ok_or_else(|| anyhow::anyhow!("could not determine default verbs path"))?;
                    if !path.exists() {
                        if let Some(parent) = path.parent() {
                            std::fs::create_dir_all(parent).with_context(|| {
                                format!("failed to create {}", parent.display())
                            })?;
                        }
                        std::fs::write(&path, "verbs: []\n")
                            .with_context(|| format!("failed to create {}", path.display()))?;
                        // This file grants real, permanent LLM-bypassing
                        // trust once auto-promotion populates it -- harden
                        // its permissions explicitly rather than relying on
                        // process umask, since this path is created
                        // automatically rather than only when an operator
                        // deliberately opted in via --verbs.
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            if let Err(e) = std::fs::set_permissions(
                                &path,
                                std::fs::Permissions::from_mode(0o600),
                            ) {
                                tracing::warn!(
                                    "failed to set restrictive permissions on {}: {}",
                                    path.display(),
                                    e
                                );
                            }
                        }
                        tracing::info!(
                            "Created empty verb catalog at {} for auto-verb-promotion",
                            path.display()
                        );
                    }
                    Some(path)
                }
                None => None,
            };
            if let Some(path) = verbs_path {
                let catalog = guard::gating::verb::VerbCatalog::load(&path)
                    .with_context(|| format!("failed to load verb catalog {}", path.display()))?;
                tracing::info!(
                    "Loaded verb catalog from {} ({} verb(s), version {})",
                    path.display(),
                    catalog.names().len(),
                    catalog.version()
                );
                srv.set_verbs(catalog);
            }

            // Session-grant profiles: flag wins, else GUARD_PROFILES. An
            // explicitly-named path must exist -- a typo should fail loudly, the
            // same as --verbs, rather than silently starting with no profiles.
            let profiles_path = profiles.or_else(|| {
                guard_env("PROFILES")
                    .filter(|v| !v.is_empty())
                    .map(PathBuf::from)
            });
            if let Some(path) = profiles_path {
                let catalog = grant_profile::ProfileCatalog::load(&path).with_context(|| {
                    format!("failed to load session profile catalog {}", path.display())
                })?;
                tracing::info!(
                    "Loaded session profile catalog from {} ({} profile(s))",
                    path.display(),
                    catalog.names().len()
                );
                srv.set_profiles(catalog);
            }

            // Binary allow-list: flag wins, else GUARD_ALLOW_BIN (comma-separated).
            // Entries are trimmed; an all-empty value is treated as no restriction.
            let allowed_binaries = allow_bin
                .or_else(|| {
                    guard_env("ALLOW_BIN").map(|v| {
                        v.split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect::<Vec<_>>()
                    })
                })
                .map(|list| {
                    list.into_iter()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                })
                .filter(|list| !list.is_empty());
            if let Some(ref list) = allowed_binaries {
                tracing::info!("Binary allow-list active: {:?}", list);
                srv.set_allowed_binaries(Some(list.clone()));
            }

            // Extra child-env passthrough: flag wins, else GUARD_CHILD_ENV
            // (comma-separated). Forwards named daemon env vars to children.
            let child_env_vars = child_env
                .or_else(|| {
                    guard_env("CHILD_ENV").map(|v| {
                        v.split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect::<Vec<_>>()
                    })
                })
                .map(|list| {
                    list.into_iter()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if !child_env_vars.is_empty() {
                tracing::info!("Child-env passthrough: {:?}", child_env_vars);
                srv.set_extra_child_env(child_env_vars);
            }

            let env_api_proxy = guard_env("API_PROXY");
            let env_kube_proxy = guard_env("KUBE_PROXY");
            let env_api_protocol = guard_env("API_PROTOCOL");
            let env_api_upstream = guard_env("API_UPSTREAM");
            let env_api_token_env = guard_env("API_TOKEN_ENV");
            let env_api_token_file = guard_env("API_TOKEN_FILE").map(PathBuf::from);
            let env_api_ca_out = guard_env("API_CA_OUT").map(PathBuf::from);
            let env_api_policy = guard_env("API_POLICY").map(PathBuf::from);
            let env_api_rarity_escalation = guard_env("API_RARITY_ESCALATION");

            let api_proxy_flag_set = api_proxy.is_some();
            let kube_proxy_flag_set = kube_proxy.is_some();
            let api_companion_configured = api_protocol.is_some()
                || api_upstream.is_some()
                || api_token_env.is_some()
                || api_token_file.is_some()
                || api_ca_out.is_some()
                || env_api_protocol.is_some()
                || env_api_upstream.is_some()
                || env_api_token_env.is_some()
                || env_api_token_file.is_some()
                || env_api_ca_out.is_some();

            let generic_api_proxy_addr = if api_proxy_flag_set {
                api_proxy
            } else if kube_proxy_flag_set {
                None
            } else {
                env_api_proxy
            };
            let kube_proxy_addr = if kube_proxy_flag_set {
                kube_proxy
            } else if api_proxy_flag_set {
                None
            } else {
                env_kube_proxy
            };
            if generic_api_proxy_addr.is_some() && kube_proxy_addr.is_some() {
                anyhow::bail!("--api-proxy and --kube-proxy cannot both be set");
            }
            if generic_api_proxy_addr.is_none()
                && kube_proxy_addr.is_none()
                && api_companion_configured
            {
                anyhow::bail!("API proxy companion options require --api-proxy or --kube-proxy");
            }
            let using_kube_sugar = kube_proxy_addr.is_some();
            let api_policy_path = api_policy.or(env_api_policy);

            if let Some(addr_str) = generic_api_proxy_addr.or(kube_proxy_addr) {
                if exec_as_caller {
                    anyhow::bail!(
                        "--api-proxy is incompatible with --exec-as-caller: a child running as the caller could read caller-owned credentials and reach the upstream around the proxy"
                    );
                }
                let listen: std::net::SocketAddr = addr_str
                    .parse()
                    .with_context(|| format!("invalid API proxy address '{addr_str}'"))?;
                if !listen.ip().is_loopback() {
                    anyhow::bail!(
                        "--api-proxy must bind a loopback address (got {listen}): the proxy \
                         authenticates nothing itself, so a non-loopback bind would offer the \
                         daemon's upstream credential to anything that can reach the port"
                    );
                }

                let protocol_name = api_protocol
                    .or(env_api_protocol)
                    .unwrap_or_else(|| "kubernetes".to_string())
                    .to_ascii_lowercase();
                if using_kube_sugar && !matches!(protocol_name.as_str(), "kubernetes" | "k8s") {
                    anyhow::bail!("--kube-proxy is sugar for --api-protocol kubernetes");
                }
                let resolved_api_upstream = api_upstream.or(env_api_upstream);
                let resolved_token_env = api_token_env.or(env_api_token_env);
                let resolved_token_file = api_token_file.or(env_api_token_file);
                let is_kubernetes = matches!(protocol_name.as_str(), "kubernetes" | "k8s");

                let protocol: Arc<dyn guard::proxy::ProtocolConfig> = match protocol_name.as_str()
                {
                    "kubernetes" | "k8s" => Arc::new(guard::proxy::KubernetesProtocol),
                    "github" => Arc::new(guard::proxy::GithubProtocol),
                    "vercel" => Arc::new(guard::proxy::VercelProtocol),
                    other => anyhow::bail!(
                        "unsupported --api-protocol '{other}' (expected kubernetes, github, or vercel)"
                    ),
                };
                let upstream = if is_kubernetes {
                    if resolved_api_upstream.is_some()
                        || resolved_token_env.is_some()
                        || resolved_token_file.is_some()
                    {
                        anyhow::bail!(
                            "--api-protocol kubernetes rejects --api-upstream and --api-token-*; use --kubeconfig"
                        );
                    }
                    let kubeconfig_path = kubeconfig
                        .or_else(|| guard_env("KUBE_PROXY_KUBECONFIG").map(PathBuf::from))
                        .context(
                            "--api-protocol kubernetes requires --kubeconfig (the operator's real kubeconfig)",
                        )?;
                    let context = kube_context.or_else(|| guard_env("KUBE_CONTEXT"));
                    guard::proxy::Upstream::from_kubeconfig_file(
                        &kubeconfig_path,
                        context.as_deref(),
                    )
                    .context("load upstream kubeconfig for API proxy")?
                } else {
                    let upstream_url = resolved_api_upstream.context(
                        "--api-proxy with a non-kubernetes protocol requires --api-upstream",
                    )?;
                    let token = match (resolved_token_env, resolved_token_file) {
                        (Some(var), None) => {
                            if !is_valid_env_name(&var) {
                                anyhow::bail!("--api-token-env must be a valid environment variable name");
                            }
                            std::env::var(&var).with_context(|| {
                                format!("read upstream bearer token from ${var}")
                            })?
                        }
                        (None, Some(path)) => std::fs::read_to_string(&path)
                            .with_context(|| {
                                format!("read upstream bearer token file {}", path.display())
                            })?
                            .trim()
                            .to_string(),
                        (Some(_), Some(_)) => {
                            anyhow::bail!("--api-token-env and --api-token-file cannot both be set")
                        }
                        (None, None) => anyhow::bail!(
                            "--api-proxy with a non-kubernetes protocol requires --api-token-env or --api-token-file"
                        ),
                    };
                    if token.is_empty() {
                        anyhow::bail!("upstream bearer token is empty");
                    }
                    guard::proxy::Upstream::from_base_url(
                        &upstream_url,
                        guard::proxy::UpstreamAuth::Bearer(token),
                    )
                    .context("build generic API upstream")?
                };
                let tls =
                    guard::proxy::ProxyTls::generate().context("generate proxy TLS material")?;
                let policy = match &api_policy_path {
                    Some(p) => guard::proxy::ApiPolicy::load_file(p)
                        .with_context(|| format!("load --api-policy {}", p.display()))?,
                    None => {
                        tracing::warn!(
                            "--api-proxy started without --api-policy: default-deny (no API requests pass)"
                        );
                        guard::proxy::ApiPolicy::deny_all()
                    }
                };
                let policy_contains_evaluate = policy.contains_evaluate();
                let policy_intent = policy.intent.clone();
                let rarity_threshold = api_rarity_escalation
                    .map(Ok)
                    .or_else(|| {
                        env_api_rarity_escalation.map(|v| {
                            v.parse::<u64>()
                                .context("parse GUARD_API_RARITY_ESCALATION")
                        })
                    })
                    .transpose()?
                    .unwrap_or(0);
                let ca_pem = tls.ca_pem().to_string();
                let mut proxy = guard::proxy::ApiProxy::with_protocol(
                    protocol,
                    listen,
                    tls,
                    upstream,
                    policy,
                    api_policy_path,
                );
                if rarity_threshold > 0 {
                    proxy = proxy.with_rarity_escalation(rarity_threshold);
                    tracing::info!(
                        "api-proxy rarity escalation on: shapes seen < {} times this run are held for review",
                        rarity_threshold
                    );
                }
                let proxy = Arc::new(proxy);
                let mut api_judge_attached = false;
                if api_judge_llm.enabled
                    && api_judge_llm
                        .api_key
                        .as_ref()
                        .is_some_and(|key| !key.is_empty())
                {
                    let llm = api_judge_llm.clone();
                    let api_promotion_store = api_promotion_store.clone();
                    let builder =
                        Arc::new(
                            move |intent: Option<String>| match server::DaemonApiJudge::build(
                                llm.clone(),
                                api_judge_cache_enabled,
                                api_judge_cache_capacity,
                                api_judge_cache_ttl,
                                intent,
                                api_promotion_store.clone(),
                            ) {
                                Ok(judge) => Some(judge),
                                Err(e) => {
                                    tracing::error!("failed to build API evaluator judge: {e:#}");
                                    None
                                }
                            },
                        );
                    proxy.attach_judge_builder(builder.clone());
                    if let Some(judge) = builder(policy_intent) {
                        proxy.attach_judge(judge);
                        api_judge_attached = true;
                        tracing::info!(
                            "API proxy evaluator attached for {}",
                            proxy.protocol_name()
                        );
                    }
                }
                if policy_contains_evaluate && !api_judge_attached {
                    tracing::warn!(
                        "API policy contains evaluate actions but no API evaluator judge is attached; those requests will hold, and deny without an approval queue"
                    );
                }
                if let Some(out) = api_ca_out.or(env_api_ca_out) {
                    std::fs::write(&out, ca_pem)
                        .with_context(|| format!("write API proxy CA to {}", out.display()))?;
                    tracing::info!("Wrote API proxy CA to {}", out.display());
                }
                if let Some(out) = brokered_kubeconfig_out
                    .or_else(|| guard_env("BROKERED_KUBECONFIG_OUT").map(PathBuf::from))
                {
                    if !is_kubernetes {
                        anyhow::bail!(
                            "--brokered-kubeconfig-out is only valid for the Kubernetes API proxy"
                        );
                    }
                    let yaml = proxy.brokered_kubeconfig();
                    // The generator is credential-free by construction; assert it
                    // before handing the file to an agent.
                    guard::proxy::validate_brokered_kubeconfig(&yaml).map_err(|e| {
                        anyhow::anyhow!("generated brokered kubeconfig is not credential-free: {e}")
                    })?;
                    std::fs::write(&out, yaml).with_context(|| {
                        format!("write brokered kubeconfig to {}", out.display())
                    })?;
                    tracing::info!("Wrote brokered kubeconfig to {}", out.display());
                }
                tracing::info!(
                    "API proxy enabled for {} on {}",
                    proxy.protocol_name(),
                    proxy.listen()
                );
                srv.register_api_proxy(proxy).await;
            }

            // Plain stdout, not tracing: the default log filter is "warn", so
            // info-level lines are invisible on a plain foreground start and the
            // operator would otherwise get no confirmation of where the daemon
            // listens. Printed after all startup validation so a refused start
            // never claims a listener.
            if let Some(line) = socket_announcement {
                println!("{line}");
            }
            if let Some(port) = tcp_port {
                println!("guard server listening on tcp 127.0.0.1:{}", port);
            }

            srv.run().await
        }
        ServerCommands::Connect {
            socket,
            tcp_port,
            token,
            env_vars,
            secret_vars,
            binary,
            args,
        } => {
            let env_vars = env_pairs_to_map(env_vars).map_err(anyhow::Error::msg)?;
            let secret_vars = secret_pairs_to_map(secret_vars).map_err(anyhow::Error::msg)?;
            let socket_path = socket.map(PathBuf::from);
            let mut client = daemon_client::Client::new(socket_path, tcp_port);
            if let Some(token) = token {
                client = client.with_auth(token);
            }
            if let Ok(session) = std::env::var("GUARD_SESSION") {
                if !session.is_empty() {
                    client = client.with_session(session);
                }
            }

            tracing::info!(
                binary = %binary,
                endpoint = %client.endpoint_for_log(),
                "REQUEST"
            );
            let mut streamed_output = false;
            let resp = client
                .execute_streaming_with_injections(
                    &binary,
                    &args,
                    env_vars,
                    secret_vars,
                    |stream, data| {
                        streamed_output = true;
                        match stream {
                            server::OutputStream::Stdout => {
                                print!("{}", data);
                                let _ = std::io::stdout().flush();
                            }
                            server::OutputStream::Stderr => {
                                eprint!("{}", data);
                                let _ = std::io::stderr().flush();
                            }
                        }
                    },
                )
                .await?;

            if resp.allowed {
                if !streamed_output {
                    if let Some(stdout) = &resp.stdout {
                        print!("{}", stdout);
                    }
                    if let Some(stderr) = &resp.stderr {
                        eprint!("{}", stderr);
                    }
                }
                if let Some(code) = resp.exit_code {
                    std::process::exit(code);
                }
                Ok(())
            } else {
                let color = color_enabled_for_stderr();
                eprintln!(
                    "{}: {}",
                    paint("DENIED", AnsiColor::Red, color),
                    resp.reason
                );
                std::process::exit(1);
            }
        }
        ServerCommands::Status { socket, json } => handle_status(socket, json).await,
    }
}
