//! guard - LLM-evaluated command gate for AI agents
//!
#![allow(unused)]

mod client_config;
mod grant_rules;
mod injection;
mod mcp;
mod redact;
mod secrets;
mod server;
mod session;
mod session_store;
mod shim;
mod ssh;
mod tool_config;

use guard::evaluate;
use guard::learned_rules::{AutoShimMode, LearnedRuleStore, LearningConfig};

use anyhow::{Context, Result};
use clap::{ArgAction, CommandFactory, Parser, Subcommand};
use guard::policy::PolicyMode;
use injection::{collect_unique_pairs, derive_env_name, is_valid_env_name};
use std::collections::HashMap;
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser)]
#[allow(clippy::large_enum_variant)]
enum MainArgs {
    /// Execute a command through the guard server
    // `disable_help_flag` is critical: without it clap would intercept
    // `guard run df -h` and print the subcommand's own help instead of
    // forwarding `-h` to `df`. Users can still see the help for the `run`
    // subcommand via `guard help run`.
    #[clap(
        alias = "exec",
        disable_help_flag = true,
        after_help = "Use `guard run <binary> --help` to pass --help to the child command."
    )]
    Run {
        /// Inject an environment variable (KEY=VALUE, repeatable)
        #[arg(long = "env", value_name = "KEY=VALUE", value_parser = parse_env_assignment)]
        env_vars: Vec<(String, String)>,
        /// Inject a stored secret. Bare SECRET derives an env var; ENV_VAR=SECRET sets one.
        /// Repeat the flag or pass a comma-separated list for multiple secrets.
        #[arg(long = "secret", value_name = "SECRET[,SECRET]", value_parser = parse_secret_mapping, value_delimiter = ',')]
        secret_vars: Vec<(String, String)>,
        /// Binary to execute
        binary: String,
        /// Arguments to pass to the binary
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Server management
    #[clap(subcommand)]
    Server(ServerCommands),
    /// Manage secrets
    #[clap(subcommand, alias = "secret")]
    Secrets(SecretCommands),
    /// Install shim scripts for command interposition
    Shim {
        /// Comma-separated list of tools to shim (e.g. ssh,kubectl,helm)
        #[arg(value_delimiter = ',')]
        tools: Option<Vec<String>>,
        /// List installed shims
        #[arg(long)]
        list: bool,
        /// Remove shims (all or specified tools)
        #[arg(long)]
        remove: bool,
        /// Custom shim directory
        #[arg(long, value_name = "PATH")]
        path: Option<PathBuf>,
        /// Inject an environment variable (KEY=VALUE, repeatable)
        #[arg(long = "env", value_name = "KEY=VALUE", value_parser = parse_env_assignment)]
        env_vars: Vec<(String, String)>,
        /// Inject a secret as an env var (ENV_VAR=secret-name). Repeat or comma-separate.
        #[arg(long = "secret", value_name = "ENV_VAR=SECRET[,ENV_VAR=SECRET]", value_parser = parse_env_assignment, value_delimiter = ',')]
        secret_vars: Vec<(String, String)>,
        /// Apply env/secret config to a specific user (UID or token name)
        #[arg(long)]
        user: Option<String>,
    },
    /// Manage client configuration
    #[clap(subcommand)]
    Config(ConfigCommands),
    /// Expose guard as an MCP server over stdio
    #[clap(subcommand)]
    Mcp(McpCommands),
    /// Manage session grants (extra allow/deny for a specific session token)
    #[clap(subcommand)]
    Session(SessionCommands),
    /// Shorthand for `guard session new <prose>` or `guard session grant <token> ...`
    Grant {
        /// Opaque session token to update, or quoted prose to create a fresh session.
        token: Option<String>,
        /// Prose describing the intended access. Known domains are compiled to
        /// static session rules; misses fall through to the LLM unless
        /// --static-only is set.
        #[arg(value_name = "PROSE")]
        prose: Option<String>,
        /// Glob pattern to allow in this session (repeatable)
        #[arg(long = "allow", value_name = "GLOB")]
        allow: Vec<String>,
        /// Glob pattern to deny in this session (repeatable, beats allow)
        #[arg(long = "deny", value_name = "GLOB")]
        deny: Vec<String>,
        /// Time-to-live in seconds; omit for no expiry
        #[arg(long, value_name = "SECONDS")]
        ttl: Option<u64>,
        /// Free-form context appended to the LLM system prompt for evaluator
        /// calls made under this session token.
        #[arg(long, value_name = "TEXT")]
        prompt: Option<String>,
        /// Read prompt from a file (alternative to --prompt).
        #[arg(long, value_name = "PATH")]
        prompt_file: Option<PathBuf>,
        /// Deny session-rule misses instead of falling through to the LLM.
        #[arg(long = "static-only", alias = "no-llm-fallback", action = ArgAction::SetTrue)]
        static_only: bool,
        /// Let fresh low-risk LLM fallback decisions add exact session rules.
        #[arg(long = "auto-amend", action = ArgAction::SetTrue)]
        auto_amend: bool,
        /// Disable automatic exact-rule amendment for this grant.
        #[arg(long = "no-auto-amend", action = ArgAction::SetTrue)]
        no_auto_amend: bool,
        /// Server socket path (defaults to configured)
        #[arg(long, value_name = "PATH")]
        socket: Option<String>,
    },
    /// Ask the evaluator to amend or deny a session grant without executing the command
    #[clap(
        disable_help_flag = true,
        after_help = "Use `guard appeal --session <token> <binary> --help` to pass --help to the appealed command."
    )]
    Appeal {
        /// Session token. Defaults to GUARD_SESSION.
        #[arg(long, value_name = "TOKEN")]
        session: Option<String>,
        /// Server socket path (defaults to configured)
        #[arg(long, value_name = "PATH")]
        socket: Option<String>,
        /// Binary to evaluate for session amendment
        binary: String,
        /// Arguments to pass to the binary
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Show daemon status. Always prints client + server version,
    /// uptime, evaluation mode, and dry-run state. The full config
    /// snapshot is restricted to the daemon UID.
    Status {
        #[arg(long)]
        socket: Option<String>,
    },
}

#[derive(Subcommand)]
enum SessionCommands {
    /// Mint a fresh session token (UUID-shaped). With any of --prompt /
    /// --allow / --deny / --ttl, also installs the grant in one round
    /// trip. Prints `export GUARD_SESSION=<token>` on stdout so you can
    /// `eval $(guard session new ...)` to set it for the current shell.
    New {
        /// Prose describing the intended access. Known domains are compiled to
        /// static session rules; misses fall through to the LLM unless
        /// --static-only is set.
        #[arg(value_name = "PROSE")]
        prose: Option<String>,
        /// Glob pattern to allow in this session (repeatable)
        #[arg(long = "allow", value_name = "GLOB")]
        allow: Vec<String>,
        /// Glob pattern to deny in this session (repeatable, beats allow)
        #[arg(long = "deny", value_name = "GLOB")]
        deny: Vec<String>,
        /// Time-to-live in seconds; omit for no expiry (cleared on daemon restart)
        #[arg(long, value_name = "SECONDS")]
        ttl: Option<u64>,
        /// Free-form context appended to the LLM system prompt for this session.
        #[arg(long, value_name = "TEXT")]
        prompt: Option<String>,
        /// Read session context from a file.
        #[arg(long, value_name = "PATH")]
        prompt_file: Option<PathBuf>,
        /// Deny session-rule misses instead of falling through to the LLM.
        #[arg(long = "static-only", alias = "no-llm-fallback", action = ArgAction::SetTrue)]
        static_only: bool,
        /// Let fresh low-risk LLM fallback decisions add exact session rules.
        #[arg(long = "auto-amend", action = ArgAction::SetTrue)]
        auto_amend: bool,
        /// Disable automatic exact-rule amendment for this grant.
        #[arg(long = "no-auto-amend", action = ArgAction::SetTrue)]
        no_auto_amend: bool,
        /// Server socket path (defaults to configured)
        #[arg(long, value_name = "PATH")]
        socket: Option<String>,
    },
    /// Grant a session token extra allow/deny patterns
    Grant {
        /// Opaque session token; the agent passes this as GUARD_SESSION or --session
        token: String,
        /// Prose describing the intended access. Known domains are compiled to
        /// static session rules; misses fall through to the LLM unless
        /// --static-only is set.
        #[arg(value_name = "PROSE")]
        prose: Option<String>,
        /// Glob pattern to allow in this session (repeatable)
        #[arg(long = "allow", value_name = "GLOB")]
        allow: Vec<String>,
        /// Glob pattern to deny in this session (repeatable, beats allow)
        #[arg(long = "deny", value_name = "GLOB")]
        deny: Vec<String>,
        /// Time-to-live in seconds; omit for no expiry (cleared on daemon restart)
        #[arg(long, value_name = "SECONDS")]
        ttl: Option<u64>,
        /// Free-form context appended to the LLM system prompt for evaluator
        /// calls made under this session token. Use to give the model context
        /// the static glob patterns cannot express.
        #[arg(long, value_name = "TEXT")]
        prompt: Option<String>,
        /// Read prompt from a file (alternative to --prompt). Mutually
        /// exclusive with --prompt; --prompt-file wins if both are given.
        #[arg(long, value_name = "PATH")]
        prompt_file: Option<PathBuf>,
        /// Deny session-rule misses instead of falling through to the LLM.
        #[arg(long = "static-only", alias = "no-llm-fallback", action = ArgAction::SetTrue)]
        static_only: bool,
        /// Let fresh low-risk LLM fallback decisions add exact session rules.
        #[arg(long = "auto-amend", action = ArgAction::SetTrue)]
        auto_amend: bool,
        /// Disable automatic exact-rule amendment for this grant.
        #[arg(long = "no-auto-amend", action = ArgAction::SetTrue)]
        no_auto_amend: bool,
        /// Server socket path (defaults to configured)
        #[arg(long, value_name = "PATH")]
        socket: Option<String>,
    },
    /// Ask the evaluator to amend or deny a session grant without executing the command.
    #[clap(
        disable_help_flag = true,
        after_help = "Use `guard session appeal <token> <binary> --help` to pass --help to the appealed command."
    )]
    Appeal {
        /// Session token to appeal against.
        token: String,
        /// Server socket path (defaults to configured)
        #[arg(long, value_name = "PATH")]
        socket: Option<String>,
        /// Binary to evaluate for session amendment.
        binary: String,
        /// Arguments to pass to the binary.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Revoke a session grant
    Revoke {
        /// Session token to revoke.
        token: String,
        /// Server socket path (defaults to configured)
        #[arg(long, value_name = "PATH")]
        socket: Option<String>,
    },
    /// Show one session in detail, including prompt, aggregate stats, and recent interactions.
    Show {
        /// Session token to inspect.
        token: String,
        /// Number of recent interactions to print.
        #[arg(long, value_name = "N", default_value_t = 20)]
        limit: usize,
        /// Server socket path (defaults to configured)
        #[arg(long, value_name = "PATH")]
        socket: Option<String>,
    },
    /// List active session grants
    List {
        /// Include past (revoked/expired) grants. Daemon retains
        /// history for a bounded window (default 24h).
        #[arg(long = "history", action = ArgAction::SetTrue)]
        history: bool,
        /// Filter history to entries that ended within the last duration.
        /// Accepts plain seconds (e.g. `3600`) or simple suffixes:
        /// `30m`, `2h`, `1d`. Implies --history when set.
        #[arg(long, value_name = "DURATION")]
        since: Option<String>,
        /// Print untruncated session prompts (daemon UID only; other users
        /// still see "(hidden)").
        #[arg(long = "full", action = ArgAction::SetTrue)]
        full: bool,
        /// Server socket path (defaults to configured)
        #[arg(long, value_name = "PATH")]
        socket: Option<String>,
    },
}

fn parse_key_value(s: &str) -> Result<(String, String), String> {
    let pos = s
        .find('=')
        .ok_or_else(|| format!("expected KEY=VALUE, got '{s}'"))?;
    Ok((s[..pos].to_string(), s[pos + 1..].to_string()))
}

fn parse_env_assignment(s: &str) -> Result<(String, String), String> {
    let (key, value) = parse_key_value(s)?;
    if !is_valid_env_name(&key) {
        return Err(format!("invalid environment variable name '{key}'"));
    }
    Ok((key, value))
}

fn parse_secret_mapping(s: &str) -> Result<(String, String), String> {
    let (env_name, secret_name) = match s.find('=') {
        Some(pos) => (s[..pos].to_string(), s[pos + 1..].to_string()),
        None => (derive_env_name(s)?, s.to_string()),
    };
    if !is_valid_env_name(&env_name) {
        return Err(format!("invalid environment variable name '{env_name}'"));
    }
    if secret_name.trim().is_empty() {
        return Err("secret name must not be empty".to_string());
    }
    Ok((env_name, secret_name))
}

fn env_pairs_to_map(pairs: Vec<(String, String)>) -> Result<HashMap<String, String>, String> {
    collect_unique_pairs(pairs, "environment variable injection", "value")
}

fn secret_pairs_to_map(pairs: Vec<(String, String)>) -> Result<HashMap<String, String>, String> {
    collect_unique_pairs(pairs, "secret injection", "secret")
}

fn resolve_bool_flag(value: Option<bool>, negated: bool, default: bool) -> bool {
    if negated {
        false
    } else {
        value.unwrap_or(default)
    }
}

fn parse_env_bool(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum ServerCommands {
    /// Start the guard server (privileged daemon)
    Start {
        /// UNIX socket path to listen on.
        #[arg(long, value_name = "PATH")]
        socket: Option<String>,

        /// TCP port on 127.0.0.1 to listen on.
        #[arg(long, value_name = "PORT")]
        tcp_port: Option<u16>,

        /// Shared token required for TCP clients.
        /// Env: SSH_GUARD_AUTH_TOKEN.
        #[arg(long, value_name = "TOKEN")]
        auth_token: Option<String>,

        /// Separate token required for non-Ping TCP admin RPCs.
        /// Env: SSH_GUARD_ADMIN_TOKEN.
        #[arg(long, value_name = "TOKEN")]
        admin_token: Option<String>,

        /// Group owning the UNIX socket.
        #[arg(long, value_name = "GROUP")]
        socket_group: Option<String>,

        /// Comma-separated list of local UIDs allowed to execute commands.
        #[arg(long, value_name = "UID[,UID]")]
        users: Option<String>,

        /// Path to a static allow/deny policy YAML file.
        #[arg(long, value_name = "PATH")]
        policy: Option<String>,

        /// Shim directory for nested command evaluation
        #[arg(long, value_name = "PATH")]
        shim_dir: Option<PathBuf>,

        /// LLM provider API key. Prefer the GUARD_LLM_API_KEY env var.
        #[arg(long, value_name = "KEY")]
        llm_api_key: Option<String>,

        /// OpenAI-compatible chat completions endpoint.
        #[arg(long, value_name = "URL")]
        llm_api_url: Option<String>,

        /// Primary LLM model slug.
        #[arg(long, value_name = "MODEL")]
        llm_model: Option<String>,

        /// LLM request timeout in seconds.
        #[arg(long, value_name = "SECONDS")]
        llm_timeout: Option<u64>,

        /// Retries per model on transient failures (default 2, capped at 2).
        /// Env: SSH_GUARD_LLM_RETRIES.
        #[arg(long, value_name = "N")]
        llm_retries: Option<u32>,

        /// Ordered fallback chain of model slugs. If more than one is supplied,
        /// the evaluator tries them in order, each with its own retry budget.
        /// Overrides --llm-model when non-empty.
        /// Env: SSH_GUARD_LLM_MODELS (comma-separated).
        #[arg(long, value_name = "MODEL[,MODEL]", value_delimiter = ',')]
        llm_models: Option<Vec<String>>,

        /// Enable or disable LLM evaluation.
        #[arg(
            long,
            action = ArgAction::Set,
            num_args = 0..=1,
            default_missing_value = "true",
            value_name = "BOOL",
            overrides_with = "no_llm"
        )]
        llm: Option<bool>,

        /// Disable LLM evaluation; static policy must allow commands.
        #[arg(long = "no-llm", action = ArgAction::SetTrue, overrides_with = "llm")]
        no_llm: bool,

        /// Disable output redaction (default: redaction enabled)
        #[arg(long = "no-redact", action = ArgAction::SetTrue)]
        no_redact: bool,

        /// Enable deterministic pre-LLM checks: executable-exists on PATH
        /// and credential-disclosure pattern deny. Default off. Env:
        /// SSH_GUARD_PREFLIGHT.
        #[arg(long = "preflight", action = ArgAction::SetTrue)]
        preflight: bool,

        /// Disable in-memory caching of LLM decisions. Env: SSH_GUARD_CACHE.
        #[arg(long = "no-cache", action = ArgAction::SetTrue)]
        no_cache: bool,

        /// Maximum number of cached decisions. Env: SSH_GUARD_CACHE_CAPACITY.
        #[arg(long, value_name = "N")]
        cache_capacity: Option<usize>,

        /// Cache entry TTL in seconds. Env: SSH_GUARD_CACHE_TTL.
        #[arg(long, value_name = "SECONDS")]
        cache_ttl: Option<u64>,

        /// Learn static allow rules from repeated low-risk LLM approvals.
        /// Env: SSH_GUARD_LEARN_RULES.
        #[arg(long = "learn-rules", action = ArgAction::SetTrue)]
        learn_rules: bool,

        /// Path to learned static rules YAML.
        /// Env: SSH_GUARD_LEARNED_RULES.
        #[arg(long, value_name = "PATH")]
        learned_rules: Option<PathBuf>,

        /// LLM approvals required before a learned allow rule is promoted.
        /// Env: SSH_GUARD_LEARN_MIN_APPROVALS.
        #[arg(long, value_name = "N")]
        learn_min_approvals: Option<u32>,

        /// Maximum risk score eligible for learned static allow promotion.
        /// Env: SSH_GUARD_LEARN_MAX_RISK.
        #[arg(long, value_name = "0-10")]
        learn_max_risk: Option<i32>,

        /// Service-shim behavior for learned rules: off, suggest, or create.
        /// Env: SSH_GUARD_LEARN_SHIMS.
        #[arg(long, value_name = "MODE")]
        learn_shims: Option<String>,

        /// Evaluate policy but do not execute approved commands.
        /// Env: SSH_GUARD_DRY_RUN.
        #[arg(long = "dry-run", action = ArgAction::SetTrue)]
        dry_run: bool,

        /// SQLite state database path for persistent sessions and session history.
        /// Env: SSH_GUARD_STATE_DB.
        #[arg(long, value_name = "PATH")]
        state_db: Option<PathBuf>,

        /// Execute approved Unix-socket requests as the connecting UID instead of the daemon UID.
        /// Requires a root daemon and no TCP listener.
        #[arg(long = "exec-as-caller", action = ArgAction::SetTrue)]
        exec_as_caller: bool,

        /// Path to custom system prompt file for the LLM evaluator
        #[arg(long, value_name = "PATH")]
        system_prompt: Option<PathBuf>,

        /// Path to additive prompt file (appended to base prompt)
        #[arg(long, value_name = "PATH")]
        system_prompt_append: Option<PathBuf>,
    },
    /// Connect to guard server and execute a command
    Connect {
        /// UNIX socket path to connect to.
        #[arg(long, value_name = "PATH")]
        socket: Option<String>,

        /// TCP port on 127.0.0.1 to connect to.
        #[arg(long, value_name = "PORT")]
        tcp_port: Option<u16>,

        /// Shared token for TCP connections.
        #[arg(long, value_name = "TOKEN")]
        token: Option<String>,

        /// Inject an environment variable (KEY=VALUE, repeatable)
        #[arg(long = "env", value_name = "KEY=VALUE", value_parser = parse_env_assignment)]
        env_vars: Vec<(String, String)>,

        /// Inject a stored secret. Bare SECRET derives an env var; ENV_VAR=SECRET sets one.
        /// Repeat the flag or pass a comma-separated list for multiple secrets.
        #[arg(long = "secret", value_name = "SECRET[,SECRET]", value_parser = parse_secret_mapping, value_delimiter = ',')]
        secret_vars: Vec<(String, String)>,

        /// Binary to execute
        binary: String,

        /// Arguments to pass to the binary
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Show server status (alias for top-level `guard status`)
    Status {
        #[arg(long)]
        socket: Option<String>,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Show current configuration
    Show,
    /// Set server socket path
    SetServer {
        /// UNIX socket path for guard clients.
        socket: String,
    },
    /// Set TCP port
    SetPort {
        /// TCP port on 127.0.0.1 for guard clients.
        port: u16,
    },
    /// Set auth token
    SetToken {
        /// Shared token for TCP connections.
        token: String,
    },
    /// Set admin token
    SetAdminToken {
        /// Separate token for TCP admin RPCs.
        token: String,
    },
    /// Set default user
    SetUser {
        /// Default user label for client configuration.
        user: String,
    },
    /// Clear configuration
    Clear,
}

#[derive(Subcommand)]
enum McpCommands {
    /// Start a stdio MCP server backed by the configured guard daemon
    Serve {
        /// UNIX socket path to connect to.
        #[arg(long, value_name = "PATH")]
        socket: Option<String>,

        /// TCP port on 127.0.0.1 to connect to.
        #[arg(long, value_name = "PORT")]
        tcp_port: Option<u16>,

        /// Shared token for TCP connections.
        #[arg(long, value_name = "TOKEN")]
        token: Option<String>,

        /// MCP tool name exposed to clients.
        #[arg(long, default_value = "guard_run")]
        tool_name: String,
    },
}

#[derive(Subcommand)]
enum SecretCommands {
    /// Store a secret in guard's configured backend.
    Add {
        /// Secret key used by --secret and tool configs.
        key: String,
        /// Secret value. Omit to read piped stdin or prompt interactively.
        value: Option<String>,
    },
    /// List stored secret keys.
    List {
        /// Include daemon-only ownership/origin detail for migration work.
        #[arg(long, action = ArgAction::SetTrue)]
        detailed: bool,
    },
    /// Remove a stored secret.
    Remove {
        /// Secret key to remove.
        key: String,
    },
}

/// Try GUARD_ prefix, then SSH_GUARD_ prefix for a given env var suffix.
fn guard_env(suffix: &str) -> Option<String> {
    std::env::var(format!("GUARD_{}", suffix))
        .ok()
        .or_else(|| std::env::var(format!("SSH_GUARD_{}", suffix)).ok())
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();

    // Log level: RUST_LOG > GUARD_LOG_LEVEL > SSH_GUARD_LOG_LEVEL > "info"
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        let level = guard_env("LOG_LEVEL").unwrap_or_else(|| "warn".to_string());
        EnvFilter::new(level)
    });
    fmt().with_env_filter(filter).with_target(true).init();

    let args: Vec<String> = std::env::args().skip(1).collect();

    // Top-level --version / -V sniff. We cannot scan for --help / -h here
    // because `guard run df -h` must pass `-h` through to `df`. clap handles
    // `--help` natively on the top-level parser and every subcommand, so we
    // let it do its job for help output. We only keep the version sniff so
    // that `guard --version` stays concise and does not require parsing
    // subcommands.
    if top_level_version_requested(&args) {
        println!("guard v{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if run_help_requested(&args) {
        return print_run_help();
    }

    let result = MainArgs::try_parse_from(std::env::args());

    match result {
        Ok(MainArgs::Run {
            env_vars,
            secret_vars,
            binary,
            args,
        }) => {
            let env_vars = env_pairs_to_map(env_vars).map_err(anyhow::Error::msg)?;
            let secret_vars = secret_pairs_to_map(secret_vars).map_err(anyhow::Error::msg)?;
            run_exec(binary, args, env_vars, secret_vars).await
        }
        Ok(MainArgs::Server(cmd)) => run_server(cmd).await,
        Ok(MainArgs::Secrets(subcommand)) => handle_secrets(subcommand).await,
        Ok(MainArgs::Shim {
            tools,
            list,
            remove,
            path,
            env_vars,
            secret_vars,
            user,
        }) => handle_shim(tools, list, remove, path, env_vars, secret_vars, user).await,
        Ok(MainArgs::Config(subcommand)) => handle_config(subcommand).await,
        Ok(MainArgs::Mcp(subcommand)) => run_mcp(subcommand).await,
        Ok(MainArgs::Session(subcommand)) => handle_session(subcommand).await,
        Ok(MainArgs::Grant {
            token,
            prose,
            allow,
            deny,
            ttl,
            prompt,
            prompt_file,
            static_only,
            auto_amend,
            no_auto_amend,
            socket,
        }) => {
            handle_session(top_level_grant_to_session_command(
                token,
                prose,
                allow,
                deny,
                ttl,
                prompt,
                prompt_file,
                static_only,
                auto_amend,
                no_auto_amend,
                socket,
            ))
            .await
        }
        Ok(MainArgs::Appeal {
            session,
            socket,
            binary,
            args,
        }) => {
            let token = session
                .or_else(|| std::env::var("GUARD_SESSION").ok())
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!("guard appeal requires --session or GUARD_SESSION")
                })?;
            handle_session(SessionCommands::Appeal {
                token,
                socket,
                binary,
                args,
            })
            .await
        }
        Ok(MainArgs::Status { socket }) => handle_status(socket).await,
        Err(ref e)
            if e.kind() == clap::error::ErrorKind::DisplayHelp
                || e.kind() == clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
                || e.kind() == clap::error::ErrorKind::DisplayVersion =>
        {
            // Let clap render help/version to stdout and exit 0.
            e.exit();
        }
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}

/// Returns true if the user asked for `--version` / `-V` at the top level,
/// before any subcommand. We scan only the very first positional token so
/// that `guard run foo -V` does not trigger a top-level version print.
fn top_level_version_requested(args: &[String]) -> bool {
    match args.first() {
        Some(first) => first == "--version" || first == "-V",
        None => false,
    }
}

fn run_help_requested(args: &[String]) -> bool {
    matches!(args.first().map(String::as_str), Some("run" | "exec"))
        && matches!(args.get(1).map(String::as_str), Some("--help" | "-h"))
        && args.len() == 2
}

fn print_run_help() -> Result<()> {
    let command = MainArgs::command();
    let mut run = command
        .find_subcommand("run")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("internal error: run help is unavailable"))?;
    run = run.bin_name("guard run");
    run.print_help()?;
    println!();
    Ok(())
}

fn current_uid() -> u32 {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() as u32 }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

fn default_state_db_path() -> Option<PathBuf> {
    default_guard_state_dir().map(|dir| dir.join("state.db"))
}

fn default_learned_rules_path() -> Option<PathBuf> {
    default_guard_state_dir().map(|dir| dir.join("learned-rules.yaml"))
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

async fn run_server(cmd: ServerCommands) -> Result<()> {
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
            dry_run,
            state_db,
            exec_as_caller,
            system_prompt,
            system_prompt_append,
        } => {
            tracing::info!("Starting guard server...");

            #[cfg(not(unix))]
            if socket.is_some() {
                anyhow::bail!("--socket is not supported on this platform; use --tcp-port");
            }

            let configured_socket = socket.map(PathBuf::from).or_else(|| {
                let config = client_config::ClientConfig::load().ok()?;
                config.server_socket.map(PathBuf::from)
            });
            #[cfg(unix)]
            let socket_path = configured_socket
                .or_else(|| dirs::home_dir().map(|h| h.join(".guard").join("guard.sock")));
            #[cfg(not(unix))]
            let socket_path: Option<PathBuf> = None;

            let tcp_port = tcp_port
                .or_else(|| guard_env("TCP_PORT").and_then(|v| v.parse::<u16>().ok()))
                .or_else(|| {
                    #[cfg(windows)]
                    {
                        Some(8123)
                    }
                    #[cfg(not(windows))]
                    {
                        None
                    }
                });

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
                    "TCP server requires --auth-token or SSH_GUARD_AUTH_TOKEN; configure clients with `guard config set-token`"
                );
            }
            let admin_token = admin_token
                .filter(|token| !token.is_empty())
                .or_else(|| guard_env("ADMIN_TOKEN").filter(|token| !token.is_empty()));
            if tcp_port.is_some() && admin_token.is_none() {
                tracing::warn!(
                    "TCP admin RPCs other than ping are disabled; set --admin-token or SSH_GUARD_ADMIN_TOKEN to use guard grant/status over TCP"
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

            let llm_enabled = resolve_bool_flag(llm, no_llm, true);
            if !llm_enabled {
                tracing::info!("LLM evaluation disabled (static policy only)");
            }

            let api_key = llm_api_key
                .or_else(|| guard_env("LLM_API_KEY"))
                .or_else(|| std::env::var("OPENROUTER_API_KEY").ok())
                .or_else(|| guard_env("API_KEY")); // deprecated fallback

            if llm_enabled && api_key.is_none() {
                tracing::warn!("No LLM API key provided (set GUARD_LLM_API_KEY, OPENROUTER_API_KEY, or --llm-api-key)");
            }

            let resolved_timeout = llm_timeout
                .or_else(|| guard_env("LLM_TIMEOUT").and_then(|v| v.parse::<u64>().ok()))
                .or_else(|| guard_env("TIMEOUT").and_then(|v| v.parse::<u64>().ok()))
                .unwrap_or(30);
            let mut eval_config = evaluate::EvalConfig::default()
                .llm_enabled(llm_enabled)
                .llm_timeout_secs(resolved_timeout);

            if let Some(api_key) = api_key.filter(|value| !value.is_empty()) {
                eval_config = eval_config.llm_api_key(api_key);
            }

            let resolved_api_url = llm_api_url
                .filter(|value| !value.is_empty())
                .or_else(|| guard_env("LLM_API_URL").filter(|value| !value.is_empty()))
                .or_else(|| guard_env("API_URL").filter(|value| !value.is_empty()));
            if let Some(api_url) = resolved_api_url {
                eval_config = eval_config.llm_api_url(api_url);
            }

            // Model resolution precedence (single primary model):
            //   1. --llm-model CLI flag
            //   2. SSH_GUARD_LLM_MODEL env var (singular — primary model)
            //   3. evaluate::EvalConfig default (DEFAULT_MODEL in evaluate.rs)
            //
            // The fallback chain (SSH_GUARD_LLM_MODELS / --llm-models) is
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

            let mode = guard_env("MODE")
                .and_then(|value| PolicyMode::parse(&value))
                .unwrap_or(PolicyMode::Readonly);

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

            // Cache: flag disable wins, else env SSH_GUARD_CACHE=false disables.
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
                    "Learned static rules enabled: path={} min_approvals={} max_risk={} shims={}",
                    store.path().display(),
                    store.min_approvals(),
                    store.max_risk(),
                    store.auto_shim().as_str()
                );
                eval_config = eval_config.learned_rules(Arc::new(RwLock::new(store)));
            }

            // Additive prompt: append to base prompt without replacing it.
            // Priority: --system-prompt-append flag > SSH_GUARD_PROMPT_APPEND env var
            let append_path = system_prompt_append.or_else(|| {
                guard_env("PROMPT_APPEND")
                    .filter(|v| !v.is_empty())
                    .map(PathBuf::from)
            });
            if let Some(ref path) = append_path {
                tracing::info!("Appending additive prompt from: {}", path.display());
                eval_config = eval_config.system_prompt_append_path(path.clone());
            }

            // Collect known secret values for exact-match output redaction BEFORE
            // moving eval_config into the evaluator.
            let mut redact_secrets: Vec<String> = Vec::new();
            if let Some(ref key) = eval_config.llm.api_key {
                if !key.is_empty() {
                    redact_secrets.push(key.clone());
                }
            }

            tracing::info!("Creating evaluator...");
            let evaluator =
                evaluate::Evaluator::new(eval_config).context("Failed to create evaluator")?;
            tracing::info!("Evaluator created successfully");

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

            // Redaction is server-side only, controlled by CLI flag.
            // NOT readable from child env (prevents SSH_GUARD_REDACT=false bypass).
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

            let (sessions, session_store) = if let Some(ref path) = state_db_path {
                let store = session_store::SessionStore::open(
                    path.clone(),
                    session::DEFAULT_HISTORY_RETENTION_SECS,
                )
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

            tracing::info!("Creating server instance...");
            let srv = server::Server::new(
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
            let mut client = server::Client::new(socket_path, tcp_port);
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
                eprintln!("DENIED: {}", resp.reason);
                std::process::exit(1);
            }
        }
        ServerCommands::Status { socket } => handle_status(socket).await,
    }
}

async fn run_exec(
    binary: String,
    args: Vec<String>,
    env_vars: HashMap<String, String>,
    secret_vars: HashMap<String, String>,
) -> Result<()> {
    let config = client_config::ClientConfig::load().ok().unwrap_or_default();

    let (socket_path, tcp_port) = resolve_client_endpoint(None, &config);

    let mut client = server::Client::new(socket_path, tcp_port);
    if let Some(token) = config.auth_token {
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
        .execute_streaming_with_injections(&binary, &args, env_vars, secret_vars, |stream, data| {
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
        })
        .await?;

    if resp.allowed {
        tracing::info!(
            binary = %binary,
            reason = %resp.reason,
            "ALLOWED"
        );
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
        tracing::warn!(
            binary = %binary,
            reason = %resp.reason,
            "DENIED"
        );
        eprintln!("DENIED: {}", resp.reason);
        std::process::exit(1);
    }
}

async fn run_mcp(subcommand: McpCommands) -> Result<()> {
    match subcommand {
        McpCommands::Serve {
            socket,
            tcp_port,
            token,
            tool_name,
        } => {
            let config = client_config::ClientConfig::load().ok().unwrap_or_default();
            let (mut socket_path, mut resolved_tcp_port) = resolve_client_endpoint(socket, &config);
            if let Some(port) = tcp_port {
                socket_path = None;
                resolved_tcp_port = Some(port);
            }
            let auth_token = token.or(config.auth_token);

            let mcp_config = mcp::McpConfig {
                socket_path,
                tcp_port: resolved_tcp_port,
                auth_token,
                tool_name,
            };

            mcp::serve(mcp_config).await
        }
    }
}

/// Well-known default socket path. Used when nothing more specific is
/// configured (no --socket flag, no GUARD_SOCKET env, no client.yaml).
/// Matches the systemd RuntimeDirectory layout in deployment/systemd/.
#[cfg(unix)]
const DEFAULT_CLIENT_SOCKET: &str = "/run/guard/guard.sock";
const DEFAULT_CLIENT_TCP_PORT: u16 = 8123;

/// Resolve the client endpoint from explicit override > env var > client
/// config > well-known default. Returns (socket, tcp_port). At most one
/// of the two will be Some.
fn resolve_client_endpoint(
    socket_override: Option<String>,
    config: &client_config::ClientConfig,
) -> (Option<PathBuf>, Option<u16>) {
    if let Some(s) = socket_override {
        return (Some(PathBuf::from(s)), None);
    }
    if let Ok(port) =
        std::env::var("GUARD_TCP_PORT").or_else(|_| std::env::var("SSH_GUARD_TCP_PORT"))
    {
        if let Ok(port) = port.parse::<u16>() {
            return (None, Some(port));
        }
    }
    if let Ok(s) = std::env::var("GUARD_SOCKET") {
        if !s.is_empty() {
            #[cfg(not(unix))]
            {
                return (
                    None,
                    Some(config.server_tcp_port.unwrap_or(DEFAULT_CLIENT_TCP_PORT)),
                );
            }
            #[cfg(unix)]
            return (Some(PathBuf::from(s)), None);
        }
    }
    if let Some(port) = config.server_tcp_port {
        return (None, Some(port));
    }
    #[cfg(unix)]
    if let Some(ref s) = config.server_socket {
        return (Some(PathBuf::from(s)), None);
    }
    #[cfg(windows)]
    {
        return (None, Some(DEFAULT_CLIENT_TCP_PORT));
    }
    // Fall back to the well-known default. If it doesn't exist the
    // connect will fail with a clear "failed to connect" error, which
    // is more useful than the previous "No server configured" since
    // most local installs use the default anyway.
    #[cfg(unix)]
    {
        (Some(PathBuf::from(DEFAULT_CLIENT_SOCKET)), None)
    }
    #[cfg(not(any(unix, windows)))]
    {
        (None, Some(DEFAULT_CLIENT_TCP_PORT))
    }
}

fn admin_client(
    socket_path: Option<PathBuf>,
    tcp_port: Option<u16>,
    config: &client_config::ClientConfig,
) -> server::Client {
    let client = server::Client::new(socket_path, tcp_port);
    if let Some(token) = config.admin_token.clone() {
        client.with_admin_token(token)
    } else {
        client
    }
}

async fn handle_status(socket: Option<String>) -> Result<()> {
    let config = client_config::ClientConfig::load().ok().unwrap_or_default();
    let (socket_path, tcp_port) = resolve_client_endpoint(socket, &config);
    let client = admin_client(socket_path.clone(), tcp_port, &config);

    // Client info first — useful even when the daemon is unreachable.
    println!("Client:");
    println!("  version        {}", env!("CARGO_PKG_VERSION"));
    println!("  endpoint       {}", client.endpoint_for_log());
    println!();

    // Ping is the public liveness probe. Always permitted to any
    // exec-allowed UID; reveals only version/uptime/mode/dry_run.
    let ping = match client.send_admin(server::AdminRequest::Ping).await {
        Ok(server::AdminResponse::Ping {
            version,
            uptime_secs,
            mode,
            dry_run,
        }) => (version, uptime_secs, mode, dry_run),
        Ok(server::AdminResponse::Error { message }) => {
            eprintln!("Server: ping refused — {}", message);
            std::process::exit(1);
        }
        Ok(other) => {
            eprintln!("Server: unexpected ping response: {:?}", other);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Server: unreachable — {}", e);
            std::process::exit(1);
        }
    };

    let (version, uptime, mode, dry_run) = ping;
    println!("Server:");
    println!("  version        {}", version);
    println!("  uptime         {}s", uptime);
    println!("  mode           {}", mode);
    println!("  dry_run        {}", dry_run);

    // Try the full Status RPC. Succeeds for daemon-UID Unix callers or
    // TCP callers with the configured admin token.
    match client.send_admin(server::AdminRequest::Status).await {
        Ok(server::AdminResponse::Status { status }) => {
            if let Some(ref s) = status.socket_path {
                println!("  socket         {}", s);
            }
            if let Some(p) = status.tcp_port {
                println!("  tcp_port       {}", p);
            }
            println!("  llm_enabled    {}", status.llm_enabled);
            if status.llm_enabled {
                println!("  llm_models     {:?}", status.llm_model_chain);
            }
            println!("  static_policy  {}", status.static_policy);
            println!("  preflight      {}", status.preflight);
            println!("  redact         {}", status.redact);
            if !status.secret_backend.is_empty() {
                println!("  secret_backend {}", status.secret_backend);
            }
            println!(
                "  cache          enabled={} size={}",
                status.cache_enabled, status.cache_size
            );
            println!(
                "  learning       enabled={} rules={}",
                status.learning_enabled, status.learned_rule_count
            );
            println!("  sessions       {}", status.session_count);
            println!("  daemon_uid     {}", status.daemon_uid);
            println!("  exec_identity  {}", status.exec_identity);
            if let Some(ref path) = status.state_db_path {
                println!("  state_db       {}", path);
            }
            Ok(())
        }
        Ok(server::AdminResponse::Error { .. }) => {
            // Expected when caller is not the daemon UID. Hide the rest.
            println!();
            println!("(full server config is restricted to the daemon UID)");
            Ok(())
        }
        Ok(other) => {
            eprintln!("Server: unexpected status response: {:?}", other);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Server: status RPC failed: {}", e);
            std::process::exit(1);
        }
    }
}

/// Format a session prompt for `guard session list` output. Without
/// `full`, prompts longer than 60 chars are ellipsized so the listing
/// stays terminal-readable; `--full` prints the entire prompt.
fn format_prompt(prompt: Option<&str>, full: bool) -> String {
    match prompt {
        None => "(none)".to_string(),
        Some(s) if full => format!("\"{}\"", s),
        Some(s) => {
            let preview: String = s.chars().take(60).collect();
            if s.chars().count() > 60 {
                format!("\"{}…\"", preview)
            } else {
                format!("\"{}\"", preview)
            }
        }
    }
}

fn read_grant_prompt(
    prompt: Option<String>,
    prompt_file: Option<&PathBuf>,
) -> Result<Option<String>> {
    match prompt_file {
        Some(path) => Ok(Some(std::fs::read_to_string(path).with_context(|| {
            format!("failed to read --prompt-file {}", path.display())
        })?)),
        None => Ok(prompt),
    }
}

/// Parse a `--since` value into an absolute unix-seconds threshold.
/// Accepts plain integer seconds or simple suffixes: `s`, `m`, `h`, `d`.
fn parse_since_to_unix(value: &str) -> Result<u64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        anyhow::bail!("--since must not be empty");
    }
    let (num_part, multiplier) = if let Some(stripped) = trimmed.strip_suffix('s') {
        (stripped, 1u64)
    } else if let Some(stripped) = trimmed.strip_suffix('m') {
        (stripped, 60u64)
    } else if let Some(stripped) = trimmed.strip_suffix('h') {
        (stripped, 3600u64)
    } else if let Some(stripped) = trimmed.strip_suffix('d') {
        (stripped, 86400u64)
    } else {
        (trimmed, 1u64)
    };
    let n: u64 = num_part
        .parse()
        .with_context(|| format!("invalid --since value: '{}'", value))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Ok(now.saturating_sub(n.saturating_mul(multiplier)))
}

/// Mint a 128-bit hex session token. Uniqueness collision is the only
/// failure mode and is statistically irrelevant for in-memory grants
/// that clear on daemon restart.
fn generate_session_token() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[allow(clippy::too_many_arguments)]
fn top_level_grant_to_session_command(
    token_or_prose: Option<String>,
    prose: Option<String>,
    allow: Vec<String>,
    deny: Vec<String>,
    ttl: Option<u64>,
    prompt: Option<String>,
    prompt_file: Option<PathBuf>,
    static_only: bool,
    auto_amend: bool,
    no_auto_amend: bool,
    socket: Option<String>,
) -> SessionCommands {
    let single_positional_prose = prose.is_none()
        && token_or_prose
            .as_deref()
            .is_some_and(looks_like_quoted_grant_prose);

    if token_or_prose.is_none() || single_positional_prose {
        let prose = prose.or(token_or_prose);
        SessionCommands::New {
            prose,
            allow,
            deny,
            ttl,
            prompt,
            prompt_file,
            static_only,
            auto_amend,
            no_auto_amend,
            socket,
        }
    } else {
        SessionCommands::Grant {
            token: token_or_prose.expect("checked Some above"),
            prose,
            allow,
            deny,
            ttl,
            prompt,
            prompt_file,
            static_only,
            auto_amend,
            no_auto_amend,
            socket,
        }
    }
}

fn resolve_session_auto_amend(
    prose: Option<&str>,
    auto_amend: bool,
    no_auto_amend: bool,
    static_only: bool,
) -> bool {
    if static_only || no_auto_amend {
        false
    } else {
        auto_amend || prose.map(|value| !value.trim().is_empty()).unwrap_or(false)
    }
}

fn looks_like_quoted_grant_prose(value: &str) -> bool {
    value.split_whitespace().nth(1).is_some()
}

async fn handle_session(subcommand: SessionCommands) -> Result<()> {
    let config = client_config::ClientConfig::load().ok().unwrap_or_default();

    // `session new` is special: it mints a token before deciding what to
    // send. If no grant flags are present we just print and exit; otherwise
    // we send a SessionGrant for the freshly-minted token.
    if let SessionCommands::New {
        prose,
        allow,
        deny,
        ttl,
        prompt,
        prompt_file,
        static_only,
        auto_amend,
        no_auto_amend,
        socket,
    } = &subcommand
    {
        let token = generate_session_token();
        let has_grant = prose.is_some()
            || !allow.is_empty()
            || !deny.is_empty()
            || ttl.is_some()
            || prompt.is_some()
            || prompt_file.is_some()
            || *static_only;

        if has_grant {
            let prompt_append = read_grant_prompt(prompt.clone(), prompt_file.as_ref())?;
            let auto_amend = resolve_session_auto_amend(
                prose.as_deref(),
                *auto_amend,
                *no_auto_amend,
                *static_only,
            );

            let (socket_path, tcp_port) = resolve_client_endpoint(socket.clone(), &config);
            let client = admin_client(socket_path, tcp_port, &config);
            let request = server::AdminRequest::SessionGrant {
                token: token.clone(),
                allow: allow.clone(),
                deny: deny.clone(),
                ttl_secs: *ttl,
                prompt_append,
                prose: prose.clone(),
                static_only: *static_only,
                auto_amend,
            };
            match client.send_admin(request).await? {
                server::AdminResponse::Ok => {}
                server::AdminResponse::Error { message } => {
                    eprintln!("error: {}", message);
                    std::process::exit(1);
                }
                other => {
                    eprintln!("unexpected admin response: {:?}", other);
                    std::process::exit(1);
                }
            }
        }

        // Eval-friendly export line on stdout; status on stderr so it does
        // not pollute the captured value.
        println!("export GUARD_SESSION={}", token);
        if has_grant {
            eprintln!("granted session {}", token);
        } else {
            eprintln!(
                "minted session {} (no grant installed; run `guard session grant {} ...` to attach rules)",
                token, token
            );
        }
        return Ok(());
    }

    let mut print_full_prompt = false;

    let (socket_override, request) = match subcommand {
        SessionCommands::New { .. } => unreachable!("handled above"),
        SessionCommands::Grant {
            token,
            prose,
            allow,
            deny,
            ttl,
            prompt,
            prompt_file,
            static_only,
            auto_amend,
            no_auto_amend,
            socket,
        } => {
            let prompt_append = read_grant_prompt(prompt, prompt_file.as_ref())?;
            let auto_amend = resolve_session_auto_amend(
                prose.as_deref(),
                auto_amend,
                no_auto_amend,
                static_only,
            );
            (
                socket,
                server::AdminRequest::SessionGrant {
                    token,
                    allow,
                    deny,
                    ttl_secs: ttl,
                    prompt_append,
                    prose,
                    static_only,
                    auto_amend,
                },
            )
        }
        SessionCommands::Appeal {
            token,
            socket,
            binary,
            args,
        } => (
            socket,
            server::AdminRequest::SessionAppeal {
                token,
                binary,
                args,
            },
        ),
        SessionCommands::Revoke { token, socket } => {
            (socket, server::AdminRequest::SessionRevoke { token })
        }
        SessionCommands::Show {
            token,
            limit,
            socket,
        } => (
            socket,
            server::AdminRequest::SessionShow {
                token,
                limit: Some(limit),
            },
        ),
        SessionCommands::List {
            history,
            since,
            full,
            socket,
        } => {
            let since_unix = match since.as_deref() {
                Some(s) => Some(parse_since_to_unix(s)?),
                None => None,
            };
            // --since implies --history; pure --history with no
            // since shows the entire retention window.
            let include_history = history || since_unix.is_some();
            print_full_prompt = full;
            (
                socket,
                server::AdminRequest::SessionList {
                    include_history,
                    since_unix,
                },
            )
        }
    };

    let (socket_path, tcp_port) = resolve_client_endpoint(socket_override, &config);
    let client = admin_client(socket_path, tcp_port, &config);

    match client.send_admin(request).await? {
        server::AdminResponse::Ok => {
            println!("ok");
        }
        server::AdminResponse::Error { message } => {
            eprintln!("error: {}", message);
            std::process::exit(1);
        }
        server::AdminResponse::SessionList { grants, history } => {
            if grants.is_empty() && history.is_empty() {
                println!("(no session grants)");
            } else {
                for g in &grants {
                    println!(
                        "[active]  token={} allow={:?} deny={:?} allow_exact={:?} deny_exact={:?} static_only={} auto_amend={} granted_at={} expires_at={} prompt={}",
                        g.token,
                        g.allow,
                        g.deny,
                        g.allow_exact,
                        g.deny_exact,
                        g.static_only,
                        g.auto_amend,
                        g.granted_at,
                        g.expires_at
                            .map(|t| t.to_string())
                            .unwrap_or_else(|| "(never)".to_string()),
                        format_prompt(g.prompt_append.as_deref(), print_full_prompt),
                    );
                }
                for h in &history {
                    let label = match h.status {
                        server::HistoricalStatus::Revoked => "[revoked]",
                        server::HistoricalStatus::Expired => "[expired]",
                    };
                    println!(
                        "{} token={} allow={:?} deny={:?} allow_exact={:?} deny_exact={:?} static_only={} auto_amend={} granted_at={} ended_at={} prompt={}",
                        label,
                        h.token,
                        h.allow,
                        h.deny,
                        h.allow_exact,
                        h.deny_exact,
                        h.static_only,
                        h.auto_amend,
                        h.granted_at,
                        h.ended_at,
                        format_prompt(h.prompt_append.as_deref(), print_full_prompt),
                    );
                }
            }
        }
        server::AdminResponse::SessionShow { report } => {
            if let Some(active) = report.active {
                println!(
                    "token={} status=active static_only={} auto_amend={} granted_at={} expires_at={} allow={:?} deny={:?} allow_exact={:?} deny_exact={:?}",
                    active.token,
                    active.static_only,
                    active.auto_amend,
                    active.granted_at,
                    active
                        .expires_at
                        .map(|t| t.to_string())
                        .unwrap_or_else(|| "(never)".to_string()),
                    active.allow,
                    active.deny,
                    active.allow_exact,
                    active.deny_exact,
                );
                println!(
                    "prompt={}",
                    format_prompt(active.prompt_append.as_deref(), true)
                );
            } else {
                println!("status=inactive");
            }

            for entry in &report.history {
                let label = match entry.status {
                    server::HistoricalStatus::Revoked => "revoked",
                    server::HistoricalStatus::Expired => "expired",
                };
                println!(
                    "history status={} static_only={} auto_amend={} granted_at={} ended_at={} expires_at={} allow={:?} deny={:?} allow_exact={:?} deny_exact={:?} prompt={}",
                    label,
                    entry.static_only,
                    entry.auto_amend,
                    entry.granted_at,
                    entry.ended_at,
                    entry
                        .expires_at
                        .map(|t| t.to_string())
                        .unwrap_or_else(|| "(never)".to_string()),
                    entry.allow,
                    entry.deny,
                    entry.allow_exact,
                    entry.deny_exact,
                    format_prompt(entry.prompt_append.as_deref(), true),
                );
            }

            println!(
                "stats total={} allowed={} denied={} completed={} exec_failed={} dry_run={} not_attempted={}",
                report.stats.total,
                report.stats.allowed,
                report.stats.denied,
                report.stats.completed,
                report.stats.exec_failed,
                report.stats.dry_run,
                report.stats.not_attempted,
            );
            if !report.stats.source_counts.is_empty() {
                let sources = report
                    .stats
                    .source_counts
                    .iter()
                    .map(|(source, count)| format!("{source}={count}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                println!("sources {}", sources);
            }
            let histogram = report
                .stats
                .risk_histogram
                .iter()
                .enumerate()
                .filter(|(_, count)| **count > 0)
                .map(|(risk, count)| format!("{risk}={count}"))
                .collect::<Vec<_>>()
                .join(" ");
            println!(
                "risk_histogram {}",
                if histogram.is_empty() {
                    "(none)".to_string()
                } else {
                    histogram
                }
            );
            if report.recent.is_empty() {
                println!("recent (none)");
            } else {
                for interaction in &report.recent {
                    let exec = match interaction.exec_status {
                        session::SessionExecStatus::NotAttempted => "not_attempted",
                        session::SessionExecStatus::Completed => "completed",
                        session::SessionExecStatus::Failed => "failed",
                        session::SessionExecStatus::DryRun => "dry_run",
                    };
                    println!(
                        "recent at={} allowed={} source={:?} risk={} exec={} cmd={:?} reason={:?}",
                        interaction.at_unix,
                        interaction.allowed,
                        interaction.source,
                        interaction
                            .risk
                            .map(|risk| risk.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                        exec,
                        interaction.command,
                        interaction.reason,
                    );
                }
            }
        }
        server::AdminResponse::SessionAppeal {
            allowed,
            amended,
            pattern,
            reason,
            risk,
        } => {
            println!(
                "allowed={} amended={} risk={} pattern={} reason={}",
                allowed,
                amended,
                risk.map(|value| value.to_string())
                    .unwrap_or_else(|| "(none)".to_string()),
                pattern.unwrap_or_else(|| "(none)".to_string()),
                reason
            );
            if !allowed {
                std::process::exit(1);
            }
        }
        server::AdminResponse::Status { .. }
        | server::AdminResponse::Ping { .. }
        | server::AdminResponse::SecretExists { .. }
        | server::AdminResponse::SecretList { .. }
        | server::AdminResponse::SecretListDetailed { .. } => {
            // session subcommands never request these response variants.
            eprintln!("unexpected response from session admin call");
            std::process::exit(1);
        }
    }

    Ok(())
}

async fn handle_config(subcommand: ConfigCommands) -> Result<()> {
    // Surface load errors loudly for every subcommand — this catches the
    // relative-XDG_CONFIG_HOME case that previously fell through silently
    // and risked writing to the default path instead of the intended one.
    match subcommand {
        ConfigCommands::Show => {
            let config =
                client_config::ClientConfig::load().context("failed to load client config")?;
            println!("socket: {:?}", config.server_socket.unwrap_or_default());
            println!(
                "port: {:?}",
                config
                    .server_tcp_port
                    .map(|p| p.to_string())
                    .unwrap_or_default()
            );
            println!("user: {:?}", config.default_user.unwrap_or_default());
            println!(
                "token: {}",
                if config.auth_token.is_some() {
                    "***"
                } else {
                    "(none)"
                }
            );
            println!(
                "admin_token: {}",
                if config.admin_token.is_some() {
                    "***"
                } else {
                    "(none)"
                }
            );
        }
        ConfigCommands::SetServer { socket } => {
            let mut config =
                client_config::ClientConfig::load().context("failed to load client config")?;
            config.server_socket = Some(socket);
            config.server_tcp_port = None;
            config.save()?;
            println!("Server socket set");
        }
        ConfigCommands::SetPort { port } => {
            let mut config =
                client_config::ClientConfig::load().context("failed to load client config")?;
            config.server_tcp_port = Some(port);
            config.server_socket = None;
            config.save()?;
            println!("Server port set");
        }
        ConfigCommands::SetToken { token } => {
            let mut config =
                client_config::ClientConfig::load().context("failed to load client config")?;
            config.auth_token = Some(token);
            config.save()?;
            println!("Token set");
        }
        ConfigCommands::SetAdminToken { token } => {
            let mut config =
                client_config::ClientConfig::load().context("failed to load client config")?;
            config.admin_token = Some(token);
            config.save()?;
            println!("Admin token set");
        }
        ConfigCommands::SetUser { user } => {
            let mut config =
                client_config::ClientConfig::load().context("failed to load client config")?;
            config.default_user = Some(user);
            config.save()?;
            println!("Default user set");
        }
        ConfigCommands::Clear => {
            let config = client_config::ClientConfig::default();
            config.save()?;
            println!("Configuration cleared");
        }
    }
    Ok(())
}

async fn handle_secrets(subcommand: SecretCommands) -> Result<()> {
    let config = client_config::ClientConfig::load().ok().unwrap_or_default();
    let (socket_path, tcp_port) = resolve_client_endpoint(None, &config);
    let client = admin_client(socket_path, tcp_port, &config);

    match subcommand {
        SecretCommands::Add { key, value } => {
            let existed = match client
                .send_admin(server::AdminRequest::SecretExists { key: key.clone() })
                .await
            {
                Ok(server::AdminResponse::SecretExists { exists }) => exists,
                Ok(server::AdminResponse::Error { .. }) | Err(_) => {
                    match client.send_admin(server::AdminRequest::SecretList).await? {
                        server::AdminResponse::SecretList { keys } => {
                            keys.iter().any(|k| k == &key)
                        }
                        server::AdminResponse::Error { message } => anyhow::bail!("{}", message),
                        other => anyhow::bail!("unexpected admin response: {:?}", other),
                    }
                }
                Ok(other) => anyhow::bail!("unexpected admin response: {:?}", other),
            };
            let secret_value = if let Some(v) = value {
                v
            } else if !std::io::stdin().is_terminal() {
                let mut value = String::new();
                std::io::stdin()
                    .read_to_string(&mut value)
                    .context("failed to read secret value from stdin")?;
                if value.ends_with('\n') {
                    value.pop();
                    if value.ends_with('\r') {
                        value.pop();
                    }
                }
                value
            } else {
                rpassword::prompt_password("Secret value: ")?
            };
            match client
                .send_admin(server::AdminRequest::SecretSet {
                    key: key.clone(),
                    value: secret_value,
                })
                .await?
            {
                server::AdminResponse::Ok => {
                    if existed {
                        eprintln!(
                            "warning: secret '{}' already existed and was overwritten",
                            key
                        );
                    }
                    println!("Secret '{}' stored", key);
                    Ok(())
                }
                server::AdminResponse::Error { message } => {
                    anyhow::bail!("{}", message);
                }
                other => anyhow::bail!("unexpected admin response: {:?}", other),
            }
        }
        SecretCommands::List { detailed } => {
            let request = if detailed {
                server::AdminRequest::SecretListDetailed
            } else {
                server::AdminRequest::SecretList
            };
            match client.send_admin(request).await? {
                server::AdminResponse::SecretList { keys } => {
                    if keys.is_empty() {
                        println!("No secrets stored");
                    } else {
                        for key in keys {
                            println!("  - {}", key);
                        }
                    }
                    Ok(())
                }
                server::AdminResponse::SecretListDetailed { items } => {
                    if items.is_empty() {
                        println!("No secrets stored");
                    } else {
                        for item in items {
                            if item.legacy {
                                println!("  - {}  origin=legacy", item.key);
                            } else if let Some(uid) = item.uid {
                                println!("  - {}  uid={}", item.key, uid);
                            } else {
                                println!("  - {}", item.key);
                            }
                        }
                    }
                    Ok(())
                }
                server::AdminResponse::Error { message } => {
                    anyhow::bail!("{}", message);
                }
                other => anyhow::bail!("unexpected admin response: {:?}", other),
            }
        }
        SecretCommands::Remove { key } => {
            match client
                .send_admin(server::AdminRequest::SecretDelete { key: key.clone() })
                .await?
            {
                server::AdminResponse::Ok => {
                    println!("Secret '{}' removed", key);
                    Ok(())
                }
                server::AdminResponse::Error { message } => {
                    anyhow::bail!("{}", message);
                }
                server::AdminResponse::SecretExists { .. } => {
                    anyhow::bail!("unexpected admin response: secret_exists")
                }
                other => anyhow::bail!("unexpected admin response: {:?}", other),
            }
        }
    }
}

async fn handle_shim(
    tools: Option<Vec<String>>,
    list: bool,
    remove: bool,
    path: Option<PathBuf>,
    env_vars: Vec<(String, String)>,
    secret_vars: Vec<(String, String)>,
    user: Option<String>,
) -> Result<()> {
    let env_vars = env_pairs_to_map(env_vars).map_err(anyhow::Error::msg)?;
    let secret_vars = env_pairs_to_map(secret_vars).map_err(anyhow::Error::msg)?;
    let shim_dir = path.unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".guard/shims")
    });

    if list {
        let generator = shim::ShimGenerator::new(std::env::current_exe()?, shim_dir);
        let installed = generator.list_installed()?;
        if installed.is_empty() {
            println!("No shims installed");
        } else {
            let registry = tool_config::ToolRegistry::load_default()
                .unwrap_or_else(|_| tool_config::ToolRegistry::empty());
            for s in installed {
                print!("  - {}", s);
                if let Some(tc) = registry.get(&s) {
                    let parts: Vec<String> = tc
                        .env
                        .iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .chain(tc.secrets.iter().map(|(k, v)| format!("{k}=<secret:{v}>")))
                        .collect();
                    if !parts.is_empty() {
                        print!("  [{}]", parts.join(", "));
                    }
                    for (uid, user_override) in &tc.users {
                        let user_parts: Vec<String> = user_override
                            .env
                            .iter()
                            .map(|(k, v)| format!("{k}={v}"))
                            .chain(
                                user_override
                                    .secrets
                                    .iter()
                                    .map(|(k, v)| format!("{k}=<secret:{v}>")),
                            )
                            .collect();
                        if !user_parts.is_empty() {
                            print!("  user({uid}): [{}]", user_parts.join(", "));
                        }
                    }
                }
                println!();
            }
        }
        return Ok(());
    }

    if remove {
        let generator = shim::ShimGenerator::new(std::env::current_exe()?, shim_dir);
        if let Some(tools) = tools {
            let tools_refs: Vec<&str> = tools.iter().map(|s| s.as_str()).collect();
            generator.remove(&tools_refs)?;
            // Also remove tool configs
            if let Ok(mut registry) = tool_config::ToolRegistry::load_default() {
                for t in &tools_refs {
                    let _ = registry.remove(t);
                }
            }
        } else {
            generator.remove_all()?;
        }
        println!("Removed shims");
        return Ok(());
    }

    // Default: install shims
    let tools_to_install = tools.unwrap_or_else(|| vec!["ssh".to_string(), "scp".to_string()]);
    let generator = shim::ShimGenerator::new(std::env::current_exe()?, shim_dir.clone());
    let tools_refs: Vec<&str> = tools_to_install.iter().map(|s| s.as_str()).collect();
    generator.generate(&tools_refs)?;
    println!("Installed shims to: {}", shim_dir.display());

    // Register tool configs if env/secret flags were provided
    if !env_vars.is_empty() || !secret_vars.is_empty() {
        let mut registry = tool_config::ToolRegistry::load_default()
            .unwrap_or_else(|_| tool_config::ToolRegistry::empty());

        for tool_name in &tools_to_install {
            let mut existing = registry.get(tool_name).cloned().unwrap_or_default();

            if let Some(ref user_key) = user {
                // Per-user override: store under users.<user_key>
                let user_override = existing.users.entry(user_key.clone()).or_default();

                for (k, v) in &env_vars {
                    user_override.env.insert(k.clone(), v.clone());
                }
                for (k, v) in &secret_vars {
                    user_override.secrets.insert(k.clone(), v.clone());
                }
                println!(
                    "Registered per-user ({}) config for: {}",
                    user_key, tool_name
                );
            } else {
                // Base tool config
                for (k, v) in &env_vars {
                    existing.env.insert(k.clone(), v.clone());
                }
                for (k, v) in &secret_vars {
                    existing.secrets.insert(k.clone(), v.clone());
                }
                println!("Registered tool config for: {}", tool_name);
            }

            registry.set(tool_name, existing)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
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
                dry_run,
                state_db,
                exec_as_caller,
                system_prompt,
                system_prompt_append,
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
                dry_run,
                state_db,
                exec_as_caller,
                system_prompt,
                system_prompt_append,
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
            "readonly nextcloud kube access",
        ]) {
            Ok(MainArgs::Grant {
                token,
                prose,
                static_only,
                ..
            }) => {
                assert_eq!(token.as_deref(), Some("tok"));
                assert_eq!(prose.as_deref(), Some("readonly nextcloud kube access"));
                assert!(static_only);
            }
            Ok(_) => panic!("expected top-level grant"),
            Err(err) => panic!("expected grant parse, got {err}"),
        }
    }

    #[test]
    fn top_level_grant_bare_prose_mints_session() {
        let command = top_level_grant_to_session_command(
            Some("readonly nextcloud kube access".to_string()),
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
                assert_eq!(prose.as_deref(), Some("readonly nextcloud kube access"));
                assert_eq!(ttl, Some(120));
                assert!(static_only);
            }
            _ => panic!("expected top-level prose grant to mint a session"),
        }
    }

    #[test]
    fn top_level_grant_single_word_keeps_token_path() {
        let command = top_level_grant_to_session_command(
            Some("tok".to_string()),
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
                assert_eq!(token, "tok");
                assert_eq!(allow, vec!["whoami"]);
            }
            _ => panic!("expected single-word top-level grant to update a session"),
        }
    }

    #[test]
    fn session_grant_parses_prose_and_static_only_alias() {
        match MainArgs::try_parse_from([
            "guard",
            "session",
            "grant",
            "tok",
            "--no-llm-fallback",
            "readonly nextcloud kube access",
        ]) {
            Ok(MainArgs::Session(SessionCommands::Grant {
                token,
                prose,
                static_only,
                ..
            })) => {
                assert_eq!(token, "tok");
                assert_eq!(prose.as_deref(), Some("readonly nextcloud kube access"));
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
            "readonly nextcloud kube access",
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
        match MainArgs::try_parse_from([
            "guard", "session", "appeal", "tok", "df", "-h", "--output",
        ]) {
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
            "nextcloud",
        ]) {
            Ok(MainArgs::Appeal {
                session,
                binary,
                args,
                ..
            }) => {
                assert_eq!(session.as_deref(), Some("tok"));
                assert_eq!(binary, "kubectl");
                assert_eq!(args, vec!["get", "pods", "-n", "nextcloud"]);
            }
            Ok(_) => panic!("expected top-level appeal"),
            Err(err) => panic!("expected top-level appeal parse, got {err}"),
        }
    }

    /// Shared guard for tests that mutate `SSH_GUARD_LLM_MODEL*` environment
    /// variables. Rust's test runner executes tests in parallel by default,
    /// and `std::env::{set,remove}_var` mutates shared process state, so
    /// concurrent readers/writers must be serialized with a mutex.
    static MODEL_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Mirror of the resolution logic in `run_server` so we can exercise the
    /// precedence ladder without spinning up an actual server. Must stay in
    /// sync with the block under the "Model resolution precedence" comment
    /// in `run_server`.
    fn resolve_single_model_for_test(cli_flag: Option<String>) -> Option<String> {
        cli_flag.filter(|value| !value.is_empty()).or_else(|| {
            std::env::var("SSH_GUARD_LLM_MODEL")
                .ok()
                .filter(|v| !v.is_empty())
        })
    }

    fn resolve_chain_for_test(cli_flag: Option<Vec<String>>) -> Vec<String> {
        let models_chain: Vec<String> = cli_flag
            .unwrap_or_default()
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        if models_chain.is_empty() {
            std::env::var("SSH_GUARD_LLM_MODELS")
                .ok()
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

    /// Regression guard for silent-ignore of `SSH_GUARD_LLM_MODEL`. Exercises
    /// the full precedence ladder:
    ///
    ///   1. `--llm-model` CLI flag
    ///   2. `SSH_GUARD_LLM_MODEL` env var (singular)
    ///   3. default (`None` here; EvalConfig falls back to `DEFAULT_MODEL`)
    ///
    /// and verifies that `SSH_GUARD_LLM_MODELS` (plural, chain) still parses
    /// correctly alongside the singular. The test is sequential within a
    /// single function body because splitting into multiple `#[test]`
    /// functions would allow parallel process-env races even with a mutex
    /// (one test could observe another test's cleared state).
    #[test]
    fn test_llm_model_env_resolution_chain() {
        // SAFETY: serialize all process-env mutations in this test suite.
        let _guard = MODEL_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Snapshot existing values so we restore the shell's environment on
        // exit even if the harness inherited one of these vars.
        let prev_single = std::env::var("SSH_GUARD_LLM_MODEL").ok();
        let prev_chain = std::env::var("SSH_GUARD_LLM_MODELS").ok();

        // Env mutations are serialized across tests via MODEL_ENV_LOCK above.
        std::env::remove_var("SSH_GUARD_LLM_MODEL");
        std::env::remove_var("SSH_GUARD_LLM_MODELS");

        // 1. Clean slate: no flag, no env -> None (caller falls back to
        //    evaluate::DEFAULT_MODEL which is "openai/gpt-5.4-nano").
        assert_eq!(
            resolve_single_model_for_test(None),
            None,
            "with no flag and no env, single-model resolution must be None so \
             EvalConfig picks DEFAULT_MODEL"
        );
        assert_eq!(resolve_chain_for_test(None), Vec::<String>::new());

        // 2. SSH_GUARD_LLM_MODEL set -> picked up as primary.
        std::env::set_var("SSH_GUARD_LLM_MODEL", "alt/model-x");
        assert_eq!(
            resolve_single_model_for_test(None),
            Some("alt/model-x".to_string()),
            "SSH_GUARD_LLM_MODEL must be honored when no CLI flag is supplied"
        );

        // 3. CLI flag wins over the singular env var.
        assert_eq!(
            resolve_single_model_for_test(Some("flag/model-y".to_string())),
            Some("flag/model-y".to_string()),
            "--llm-model must take precedence over SSH_GUARD_LLM_MODEL"
        );

        // 4. Empty CLI flag falls through to env var.
        assert_eq!(
            resolve_single_model_for_test(Some(String::new())),
            Some("alt/model-x".to_string()),
            "empty --llm-model value must fall through to the env var"
        );

        // 5. Chain env var still parses independently of the singular var.
        std::env::set_var("SSH_GUARD_LLM_MODELS", "a,b,c");
        let chain = resolve_chain_for_test(None);
        assert_eq!(
            chain,
            vec!["a".to_string(), "b".to_string(), "c".to_string()],
            "SSH_GUARD_LLM_MODELS must parse into an ordered chain"
        );
        // The singular resolver is orthogonal and still returns the singular
        // value; the call site in run_server applies the precedence rule
        // ("chain wins when non-empty") when wiring EvalConfig.
        assert_eq!(
            resolve_single_model_for_test(None),
            Some("alt/model-x".to_string())
        );

        // Cleanup: restore prior values so other tests see the original env.
        match prev_single {
            Some(v) => std::env::set_var("SSH_GUARD_LLM_MODEL", v),
            None => std::env::remove_var("SSH_GUARD_LLM_MODEL"),
        }
        match prev_chain {
            Some(v) => std::env::set_var("SSH_GUARD_LLM_MODELS", v),
            None => std::env::remove_var("SSH_GUARD_LLM_MODELS"),
        }
    }

    #[test]
    fn test_server_start_llm_models_flag() {
        let ServerCommands::Start { llm_models, .. } = parse_start(&[
            "guard",
            "server",
            "start",
            "--llm-models",
            "openai/gpt-5.4-nano,meta-llama/llama-4-maverick",
        ]) else {
            panic!("expected start");
        };
        assert_eq!(
            llm_models,
            Some(vec![
                "openai/gpt-5.4-nano".to_string(),
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

    /// Same story for `--help` — must be forwarded, not caught by clap's
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
        match MainArgs::try_parse_from(["guard", "run", "--secret", "foo,bar", "sh", "-c", "true"])
        {
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
    fn run_help_requested_only_when_help_is_the_run_command() {
        assert!(run_help_requested(&[
            "run".to_string(),
            "--help".to_string()
        ]));
        assert!(run_help_requested(&["exec".to_string(), "-h".to_string()]));
        assert!(!run_help_requested(&[
            "run".to_string(),
            "df".to_string(),
            "--help".to_string()
        ]));
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
    /// forward `--help` to the child instead — users get run help via
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
}
