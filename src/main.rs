//! guard - LLM-evaluated command gate for AI agents
//!

mod cli_client;
mod cli_secrets;
mod cli_server;
mod cli_shim;
mod client_config;
mod daemon_client;
mod defaults;
mod grant_profile;
mod grant_rules;
mod injection;
mod mcp;
mod secrets;
mod server;
mod session;
mod session_store;
mod shim;
mod ssh;
mod tool_config;
#[cfg(windows)]
mod winsvc;

use guard::evaluate;
use guard::learned_rules::{AutoShimMode, LearnedRuleStore, LearningConfig};
use guard::redact;

use anyhow::{Context, Result};
use clap::{ArgAction, CommandFactory, Parser, Subcommand};
use guard::policy::PolicyMode;
use injection::{collect_unique_pairs, derive_env_name, is_valid_env_name};
use std::collections::HashMap;
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::{fmt as tracing_fmt, EnvFilter};

use cli_client::{
    handle_approval_note_cmd, handle_approvals, handle_config, handle_gate_action,
    handle_grant_read, handle_grant_revoke, handle_provisionals, handle_session, handle_status,
    handle_verb, run_exec, run_mcp, top_level_grant_to_session_command, GatingOptions,
    SshHostKeyCliMode,
};
use cli_secrets::handle_secrets;
use cli_server::run_server;
use cli_shim::handle_shim;

#[derive(Parser)]
#[command(
    name = "guard",
    about = "LLM-evaluated command gate for AI agents",
    after_help = "Access model:\n  Non-admin local callers can run commands, manage their own secret namespace, read liveness status, list sessions with redaction, show a known session token, list/run verbs, inspect their own held approvals/provisionals, and manage local client setup.\n  Daemon-principal callers or TCP admin-token callers can grant/revoke/appeal sessions, approve/deny/confirm/revert gates, create verbs, read full daemon status, and inspect detailed secret ownership.\n\nUse `guard help-tree` for a categorized access summary."
)]
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
        /// Rollback command for a recoverable action under consequence gating,
        /// as a single string (e.g. --revert "systemctl stop nginx"). It is
        /// itself policy-evaluated; if denied, the whole request is denied.
        #[arg(long = "revert", value_name = "COMMAND")]
        revert: Option<String>,
        /// Auto-revert window in seconds for the containment envelope.
        #[arg(long = "confirm-within", value_name = "SECONDS")]
        confirm_within: Option<u64>,
        /// Force the command onto the operator-approval (hold) path.
        #[arg(long = "require-approval", action = ArgAction::SetTrue)]
        require_approval: bool,
        /// Block up to SECONDS for an operator decision on a held command and
        /// return the real result inline. Bare flag waits the full approval TTL.
        #[arg(long = "wait-approval", value_name = "SECONDS", num_args = 0..=1, default_missing_value = "3600")]
        wait_approval: Option<u64>,
        /// Skip the daemon's auto-learned deny-shape fast path and force a
        /// fresh LLM look at this command. Never skips an operator-authored
        /// policy deny rule -- those stay absolute either way. Use this if
        /// you believe an auto-learned shape over-blocked something that
        /// should be allowed.
        #[arg(long = "reevaluate", action = ArgAction::SetTrue)]
        reevaluate: bool,
        /// SSH host-key policy for a guarded `ssh` command. `only-existing`
        /// (default) keeps ssh's strict checking; `accept-new` trusts a new
        /// host on first contact but still rejects a changed key; `accept-all`
        /// gives up host verification and never rides the deterministic fast
        /// path. Only affects `ssh`.
        #[arg(long = "hostkey", value_enum, default_value = "only-existing")]
        hostkey: SshHostKeyCliMode,
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
    /// Manage shim scripts for command interposition. Naming tools installs
    /// their shims; bare `guard shim` lists what is installed.
    Shim {
        /// Comma-separated list of tools to shim (e.g. ssh,kubectl,helm);
        /// required to install, omit to list installed shims
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
    /// Shorthand for `guard session new <prose>` or `guard session grant <token> ...`.
    /// Daemon-principal or TCP admin-token only when it installs or updates a grant.
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
    /// Ask the evaluator to amend or deny a session grant without executing the command.
    /// Daemon-principal or TCP admin-token only.
    //
    // `disable_help_flag` so `guard appeal <binary> -h` forwards `-h` to the
    // appealed command rather than printing this subcommand's help. Bare help
    // (before a binary is named) is recovered by `passthrough_command_help_requested`.
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
    /// Print a categorized command tree with access markers.
    #[clap(name = "help-tree")]
    HelpTree {
        /// Include daemon-principal/admin-token commands.
        #[arg(long, action = ArgAction::SetTrue)]
        admin: bool,
    },
    /// List provisional (containment-envelope) executions awaiting confirmation.
    Provisionals {
        #[arg(long)]
        socket: Option<String>,
    },
    /// Confirm a provisional: keep the change and cancel its auto-revert.
    /// Daemon-UID only.
    Confirm {
        handle: String,
        #[arg(long)]
        socket: Option<String>,
    },
    /// Revert a provisional immediately (manual rollback). Daemon-UID only.
    Revert {
        handle: String,
        #[arg(long)]
        socket: Option<String>,
    },
    /// List held / decided operator approvals, or show one with a handle.
    Approvals {
        /// Optional handle to show a single approval's status and result.
        handle: Option<String>,
        #[arg(long)]
        socket: Option<String>,
    },
    /// Approve a held command: execute it from its bound snapshot. Daemon-UID only.
    Approve {
        handle: String,
        #[arg(long)]
        socket: Option<String>,
    },
    /// Deny a held command. Daemon-UID only.
    Deny {
        handle: String,
        #[arg(long)]
        socket: Option<String>,
    },
    /// Post a note to a held command's approval thread, then show the thread.
    /// The operator may note any hold; the requester may note its own.
    #[clap(name = "approval-note")]
    ApprovalNote {
        /// Held-command handle.
        handle: String,
        /// Note text.
        text: String,
        #[arg(long)]
        socket: Option<String>,
    },
    /// Run or list operator-defined verbs (the typed, least-expressive interface).
    #[clap(subcommand)]
    Verb(VerbCommands),
    /// Grant guard's brokering identity a time-boxed POSIX ACL read grant on a
    /// specific operator-owned file (Unix only), so a brokered ansible/helm
    /// command can read a config/vars/values file guard's service account
    /// otherwise cannot. Evaluated through the same policy pipeline as any
    /// brokered command (credential deny-list, session globs, LLM evaluator),
    /// and auto-revoked when the TTL expires.
    #[clap(name = "grant-read")]
    GrantRead {
        /// Path to the single file to grant read access on.
        path: String,
        /// Time-to-live in seconds (required; bounded to 24h). No unbounded grant.
        #[arg(long, value_name = "SECONDS")]
        ttl: u64,
        /// Skip the auto-learned deny-shape fast path and force a fresh LLM look.
        #[arg(long = "reevaluate", action = ArgAction::SetTrue)]
        reevaluate: bool,
        /// Server socket path (defaults to configured)
        #[arg(long, value_name = "PATH")]
        socket: Option<String>,
    },
    /// Revoke an active read grant early (Unix only). De-escalation; not
    /// re-evaluated by the LLM, but audited.
    #[clap(name = "grant-revoke")]
    GrantRevoke {
        /// Path the grant was issued on.
        path: String,
        /// Server socket path (defaults to configured)
        #[arg(long, value_name = "PATH")]
        socket: Option<String>,
    },
}

#[derive(Subcommand)]
enum VerbCommands {
    /// List available verbs with their parameters and consequence class.
    List {
        #[arg(long)]
        socket: Option<String>,
    },
    /// Run a verb with validated parameters: --param key=value (repeatable).
    Run {
        /// Verb name from the catalog.
        name: String,
        /// Parameter assignments (key=value), repeatable.
        #[arg(long = "param", value_name = "KEY=VALUE", value_parser = parse_env_assignment)]
        params: Vec<(String, String)>,
        /// Auto-revert window in seconds for a recoverable verb.
        #[arg(long = "confirm-within", value_name = "SECONDS")]
        confirm_within: Option<u64>,
        /// Block up to SECONDS for an operator decision if the verb is held.
        #[arg(long = "wait-approval", value_name = "SECONDS", num_args = 0..=1, default_missing_value = "3600")]
        wait_approval: Option<u64>,
        #[arg(long)]
        socket: Option<String>,
    },
    /// Create a verb from plain-language prose (LLM-synthesized, validated, and
    /// stored with the prose + evidence). Operator-only.
    Create {
        /// Plain-language description of the operation to expose as a verb.
        #[arg(long)]
        prompt: String,
        /// Optional hint: the target binary (e.g. cmk, kubectl).
        #[arg(long)]
        binary: Option<String>,
        /// Synthesize and show the verb but do not write it to the catalog.
        #[arg(long)]
        preview: bool,
        #[arg(long)]
        socket: Option<String>,
    },
}

#[derive(Subcommand)]
enum SessionCommands {
    /// Mint a fresh session token (32 lowercase hex chars). With grant prose or any
    /// grant flags, also installs the grant in one round trip and requires
    /// the daemon principal or TCP admin token. Prints `export
    /// GUARD_SESSION=<token>` on stdout so you can `eval $(guard session
    /// new ...)` to set it for the current shell.
    New {
        /// Prose describing the intended access. Known domains are compiled to
        /// static session rules; misses fall through to the LLM unless
        /// --static-only is set.
        #[arg(value_name = "PROSE")]
        prose: Option<String>,
        /// Mint this grant from an operator-defined profile (see --profiles on
        /// `guard server start`): a named {ttl, allow, deny, prompt} bundle.
        /// Works standalone; an unknown name is rejected by the daemon.
        #[arg(long, value_name = "NAME")]
        profile: Option<String>,
        /// Glob pattern to allow in this session (repeatable)
        #[arg(long = "allow", value_name = "GLOB")]
        allow: Vec<String>,
        /// Glob pattern to deny in this session (repeatable, beats allow)
        #[arg(long = "deny", value_name = "GLOB")]
        deny: Vec<String>,
        /// Time-to-live in seconds; omit for no expiry (grants persist in the
        /// state DB and are reloaded on daemon restart)
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
    /// Grant a session token extra allow/deny patterns.
    /// Daemon-principal or TCP admin-token only.
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
        /// Time-to-live in seconds; omit for no expiry (grants persist in the
        /// state DB and are reloaded on daemon restart)
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
    /// Daemon-principal or TCP admin-token only.
    //
    // `disable_help_flag`: same rationale as the top-level `Appeal` variant --
    // `-h`/`--help` after the binary must reach the appealed command. Bare help is
    // recovered by `passthrough_command_help_requested`.
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
    /// Revoke a session grant. Daemon-principal or TCP admin-token only.
    Revoke {
        /// Session token to revoke.
        token: String,
        /// Server socket path (defaults to configured)
        #[arg(long, value_name = "PATH")]
        socket: Option<String>,
    },
    /// Show one session in detail, including prompt, aggregate stats, and recent
    /// interactions. With no token, defaults to the caller's own `$GUARD_SESSION`.
    /// A non-daemon caller may only inspect the grant on its own token.
    Show {
        /// Session token to inspect. Defaults to $GUARD_SESSION when omitted.
        token: Option<String>,
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
        /// Env: GUARD_AUTH_TOKEN.
        #[arg(long, value_name = "TOKEN")]
        auth_token: Option<String>,

        /// Separate token required for non-Ping TCP admin RPCs.
        /// Env: GUARD_ADMIN_TOKEN.
        #[arg(long, value_name = "TOKEN")]
        admin_token: Option<String>,

        /// Group owning the UNIX socket.
        #[arg(long, value_name = "GROUP")]
        socket_group: Option<String>,

        /// Comma-separated list of local UIDs allowed to execute commands.
        #[arg(long, value_name = "UID[,UID]")]
        users: Option<String>,

        /// Path to a static policy YAML file: a pre-LLM deny fast path. `deny`
        /// patterns fast-reject before the LLM is called; `allow` patterns are
        /// parsed for the --no-llm fallback and backward compatibility but do
        /// not skip the LLM while it is enabled -- use `guard verb` for that.
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
        /// Env: GUARD_LLM_RETRIES.
        #[arg(long, value_name = "N")]
        llm_retries: Option<u32>,

        /// Ordered fallback chain of model slugs. If more than one is supplied,
        /// the evaluator tries them in order, each with its own retry budget.
        /// Overrides --llm-model when non-empty.
        /// Env: GUARD_LLM_MODELS (comma-separated).
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
        /// GUARD_PREFLIGHT.
        #[arg(long = "preflight", action = ArgAction::SetTrue)]
        preflight: bool,

        /// Disable in-memory caching of LLM decisions. Env: GUARD_CACHE.
        #[arg(long = "no-cache", action = ArgAction::SetTrue)]
        no_cache: bool,

        /// Maximum number of cached decisions. Env: GUARD_CACHE_CAPACITY.
        #[arg(long, value_name = "N")]
        cache_capacity: Option<usize>,

        /// Cache entry TTL in seconds. Env: GUARD_CACHE_TTL.
        #[arg(long, value_name = "SECONDS")]
        cache_ttl: Option<u64>,

        /// Detect repeated low-risk LLM approvals and surface them as verb
        /// candidates in the policy reason text (with a ready-to-run `guard
        /// verb create --prompt` suggestion). Never grants a bypass itself --
        /// only an operator running that command can. Env: GUARD_LEARN_RULES.
        #[arg(long = "learn-rules", action = ArgAction::SetTrue)]
        learn_rules: bool,

        /// Path to the learned-rule candidate state YAML.
        /// Env: GUARD_LEARNED_RULES.
        #[arg(long, value_name = "PATH")]
        learned_rules: Option<PathBuf>,

        /// LLM approvals required before a command becomes a learned-rule
        /// candidate. Env: GUARD_LEARN_MIN_APPROVALS.
        #[arg(long, value_name = "N")]
        learn_min_approvals: Option<u32>,

        /// Maximum risk score eligible for learned-rule candidacy.
        /// Env: GUARD_LEARN_MAX_RISK.
        #[arg(long, value_name = "0-10")]
        learn_max_risk: Option<i32>,

        /// Service-shim behavior for learned-rule candidates: off, suggest, or
        /// create. A shim is a command alias, not a bypass -- the aliased
        /// command still runs through normal evaluation. Env: GUARD_LEARN_SHIMS.
        #[arg(long, value_name = "MODE")]
        learn_shims: Option<String>,

        /// Auto-learn deny shapes from repeated LLM denials and fast-reject
        /// matching commands without another LLM call. On by default: unlike
        /// learned-rule allow candidates, this never grants anything -- it can
        /// only accelerate a "no" the LLM already gave, so it needs no
        /// operator promotion step. A client can force a fresh LLM look past
        /// it with `--reevaluate` on `guard run`. Env: GUARD_LEARN_DENY.
        #[arg(
            long,
            action = ArgAction::Set,
            num_args = 0..=1,
            default_missing_value = "true",
            value_name = "BOOL",
            overrides_with = "no_learn_deny"
        )]
        learn_deny: Option<bool>,

        /// Disable auto-learned deny shapes.
        #[arg(long = "no-learn-deny", action = ArgAction::SetTrue, overrides_with = "learn_deny")]
        no_learn_deny: bool,

        /// Path to the auto-learned deny-shape state YAML.
        /// Env: GUARD_DENY_SHAPES.
        #[arg(long, value_name = "PATH")]
        deny_shapes: Option<PathBuf>,

        /// LLM denials of the same shape required before attempting to
        /// synthesize an auto-learned deny fast path. Env: GUARD_LEARN_DENY_MIN_DENIALS.
        #[arg(long, value_name = "N")]
        learn_deny_min_denials: Option<u32>,

        /// Auto-promote trusted verbs from repeated low-risk LLM approvals
        /// (requires --gate consequence: promotion is keyed on the
        /// reversibility class the gate produces). On by default. Unlike
        /// --learn-rules, this needs no operator step: a qualifying shape is
        /// appended straight to the verb catalog as `trusted`, restricted to
        /// reversible/recoverable-with-a-validated-revert shapes -- an
        /// irreversible command is never eligible, since it always holds for
        /// operator approval regardless of `trusted`. See
        /// `gating::allow_promotion` for the full safety rationale.
        /// Env: GUARD_LEARN_ALLOW.
        #[arg(
            long,
            action = ArgAction::Set,
            num_args = 0..=1,
            default_missing_value = "true",
            value_name = "BOOL",
            overrides_with = "no_learn_allow"
        )]
        learn_allow: Option<bool>,

        /// Disable auto-promotion of trusted verbs.
        #[arg(long = "no-learn-allow", action = ArgAction::SetTrue, overrides_with = "learn_allow")]
        no_learn_allow: bool,

        /// Path to the auto-verb-promotion observation state YAML (bookkeeping
        /// only; promoted verbs themselves land in --verbs). Env: GUARD_LEARN_ALLOW_STATE.
        #[arg(long, value_name = "PATH")]
        learn_allow_state: Option<PathBuf>,

        /// LLM approvals of the same shape required before attempting to
        /// promote a trusted verb. Env: GUARD_LEARN_ALLOW_MIN_APPROVALS.
        #[arg(long, value_name = "N")]
        learn_allow_min_approvals: Option<u32>,

        /// Evaluate policy but do not execute approved commands.
        /// Env: GUARD_DRY_RUN.
        #[arg(long = "dry-run", action = ArgAction::SetTrue)]
        dry_run: bool,

        /// SQLite state database path for persistent sessions and session history.
        /// Env: GUARD_STATE_DB.
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

        /// Consequence gating: `off` (default) or `consequence`. When enabled,
        /// LLM-approved commands are routed by reversibility - reversible runs
        /// immediately, recoverable runs behind an auto-revert envelope, and
        /// irreversible is held for operator approval. Requires a Unix-socket
        /// listener (incompatible with --tcp-port). Env: GUARD_GATE.
        #[arg(long, value_name = "MODE")]
        gate: Option<String>,

        /// Path to the verb catalog YAML (the operator-defined, typed interface
        /// agents call via `guard verb`). Hot-reloaded on change.
        /// Env: GUARD_VERBS.
        #[arg(long, value_name = "PATH")]
        verbs: Option<PathBuf>,

        /// Path to the session-grant profile catalog YAML: operator-authored,
        /// named {ttl, allow, deny, prompt} bundles that `guard session new
        /// --profile <name>` mints a grant from. Read once at startup.
        /// Env: GUARD_PROFILES.
        #[arg(long, value_name = "PATH")]
        profiles: Option<PathBuf>,

        /// Restrict which binaries the server may execute, regardless of the LLM
        /// decision. Repeat or comma-separate (e.g. `--allow-bin kubectl,git`).
        /// Bare names match by command name via the daemon PATH; path-qualified
        /// entries must match exactly. Empty/unset means no restriction.
        /// Env: GUARD_ALLOW_BIN (comma-separated).
        #[arg(long = "allow-bin", value_name = "BIN[,BIN]", value_delimiter = ',')]
        allow_bin: Option<Vec<String>>,

        /// Extra environment variables the daemon forwards from its own
        /// environment to executed children (beyond the built-in platform
        /// allowlist). The generic way to broker a tool's credential config
        /// without per-tool code, e.g. `--child-env KUBECONFIG` so brokered
        /// kubectl/helm read a config the agent cannot see. Repeat or
        /// comma-separate. Env: GUARD_CHILD_ENV (comma-separated).
        #[arg(long = "child-env", value_name = "VAR[,VAR]", value_delimiter = ',')]
        child_env: Option<Vec<String>>,

        /// Front the Kubernetes apiserver with a TLS-terminating proxy on ADDR
        /// (e.g. 127.0.0.1:8443). Each API request from a brokered client (helm,
        /// kubectl, terraform, k9s, client libraries) is gated against
        /// --api-policy and re-originated to the real apiserver with the
        /// credentials only the daemon holds. Requires --kubeconfig; incompatible
        /// with --exec-as-caller. Env: GUARD_KUBE_PROXY.
        #[arg(long = "kube-proxy", value_name = "ADDR")]
        kube_proxy: Option<String>,

        /// The operator's real kubeconfig the proxy uses upstream. The daemon
        /// holds these credentials; the brokered config it emits carries none.
        /// Env: GUARD_KUBE_PROXY_KUBECONFIG.
        #[arg(long = "kubeconfig", value_name = "PATH")]
        kubeconfig: Option<PathBuf>,

        /// kubeconfig context to use upstream (default: its current-context).
        /// Env: GUARD_KUBE_CONTEXT.
        #[arg(long = "kube-context", value_name = "NAME")]
        kube_context: Option<String>,

        /// Operator API policy for the proxy (see examples/api-policy.yaml).
        /// Hot-reloaded on change. Absent means default-deny. Env: GUARD_API_POLICY.
        #[arg(long = "api-policy", value_name = "PATH")]
        api_policy: Option<PathBuf>,

        /// Write the agent-facing brokered kubeconfig here at startup. It points
        /// at the proxy and carries no credential; agents set KUBECONFIG to it.
        /// Env: GUARD_BROKERED_KUBECONFIG_OUT.
        #[arg(long = "brokered-kubeconfig-out", value_name = "PATH")]
        brokered_kubeconfig_out: Option<PathBuf>,

        /// Escalate a policy-allowed proxy request to the operator hold queue
        /// when its shape (verb x resource x namespace, object name excluded)
        /// has been seen fewer than N times this run, so a broad allow rule
        /// fails toward review on a rare or first-seen shape. Requires
        /// --gate consequence (the hold queue). 0 (default) disables it.
        /// Env: GUARD_API_RARITY_ESCALATION.
        #[arg(long = "api-rarity-escalation", value_name = "N")]
        api_rarity_escalation: Option<u64>,

        /// Internal marker: launched under the Windows Service Control Manager.
        /// The Windows installer sets this in the service binPath so startup
        /// answers the SCM start/stop handshake instead of running in the
        /// foreground. Hidden; it has no effect when not run as a Windows
        /// service, and the daemon configuration is otherwise identical.
        #[arg(long = "service", hide = true, action = ArgAction::SetTrue)]
        service: bool,
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
    /// Start an MCP server backed by the configured guard daemon. Defaults to
    /// stdio; pass --http to serve over a local HTTP endpoint instead.
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

        /// Serve MCP over Streamable-HTTP on this address (e.g. 127.0.0.1:7333)
        /// instead of stdio. Requires a bearer token (--http-token or
        /// GUARD_MCP_TOKEN). Intended for localhost / trusted networks.
        #[arg(long, value_name = "ADDR")]
        http: Option<String>,

        /// Bearer token required on every HTTP request (overrides
        /// GUARD_MCP_TOKEN). Only used with --http; never logged.
        #[arg(long, value_name = "TOKEN")]
        http_token: Option<String>,
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

/// Resolve a `GUARD_<suffix>` configuration variable. Thin wrapper over
/// [`guard::env::guard_env`] so the binary and the library resolve
/// configuration identically.
fn guard_env(suffix: &str) -> Option<String> {
    guard::env::guard_env(suffix)
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();

    // Windows service entry. The installer registers the daemon with
    // `server start ... --service`; when the Service Control Manager launches
    // that command we must answer its start/stop handshake from a dispatcher
    // thread rather than run in the foreground. Detect it from argv before any
    // logging or arg parsing, and hand the process to the dispatcher (on a
    // blocking thread so it owns its own runtime). An interactive run never
    // sets `--service`, so the foreground path below is unaffected.
    #[cfg(windows)]
    {
        let argv: Vec<String> = std::env::args().skip(1).collect();
        if winsvc::is_service_invocation(&argv) {
            return tokio::task::spawn_blocking(winsvc::run)
                .await
                .context("the service dispatcher thread panicked")?;
        }
    }

    // Log level: RUST_LOG > GUARD_LOG_LEVEL > "warn"
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        let level = guard_env("LOG_LEVEL").unwrap_or_else(|| "warn".to_string());
        EnvFilter::new(level)
    });
    tracing_fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_timer(UtcTimestamp)
        .with_ansi(color_enabled_for_stderr())
        .with_writer(std::io::stderr)
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();

    // Top-level --version / -V sniff. We cannot scan for --help / -h here
    // because `guard run df -h` must pass `-h` through to `df`. clap handles
    // `--help` natively on the top-level parser and every subcommand, so we
    // let it do its job for help output. We only keep the version sniff so
    // that `guard --version` stays concise and does not require parsing
    // subcommands.
    if top_level_version_requested(&args) {
        println!(
            "guard v{} ({})",
            env!("CARGO_PKG_VERSION"),
            env!("GUARD_GIT_COMMIT")
        );
        return Ok(());
    }
    if let Some((path, bin_name)) = passthrough_command_help_requested(&args) {
        return print_nested_help(&path, bin_name);
    }

    let result = MainArgs::try_parse_from(std::env::args());

    match result {
        Ok(MainArgs::Run {
            env_vars,
            secret_vars,
            revert,
            confirm_within,
            require_approval,
            wait_approval,
            reevaluate,
            hostkey,
            binary,
            args,
        }) => {
            let env_vars = env_pairs_to_map(env_vars).map_err(anyhow::Error::msg)?;
            let secret_vars = secret_pairs_to_map(secret_vars).map_err(anyhow::Error::msg)?;
            let gating = GatingOptions {
                revert,
                confirm_within,
                require_approval,
                wait_approval,
                reevaluate,
            };
            run_exec(binary, args, env_vars, secret_vars, gating, hostkey.into()).await
        }
        Ok(MainArgs::Server(cmd)) => run_server(cmd).await,
        Ok(MainArgs::Provisionals { socket }) => handle_provisionals(socket).await,
        Ok(MainArgs::Confirm { handle, socket }) => {
            handle_gate_action(socket, "confirm", handle).await
        }
        Ok(MainArgs::Revert { handle, socket }) => {
            handle_gate_action(socket, "revert", handle).await
        }
        Ok(MainArgs::Approve { handle, socket }) => {
            handle_gate_action(socket, "approve", handle).await
        }
        Ok(MainArgs::Deny { handle, socket }) => handle_gate_action(socket, "deny", handle).await,
        Ok(MainArgs::Approvals { handle, socket }) => handle_approvals(socket, handle).await,
        Ok(MainArgs::ApprovalNote {
            handle,
            text,
            socket,
        }) => handle_approval_note_cmd(socket, handle, text).await,
        Ok(MainArgs::Verb(subcommand)) => handle_verb(subcommand).await,
        Ok(MainArgs::GrantRead {
            path,
            ttl,
            reevaluate,
            socket,
        }) => handle_grant_read(path, ttl, reevaluate, socket).await,
        Ok(MainArgs::GrantRevoke { path, socket }) => handle_grant_revoke(path, socket).await,
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
        Ok(MainArgs::HelpTree { admin }) => {
            print_help_tree(admin);
            Ok(())
        }
        Err(ref e)
            if e.kind() == clap::error::ErrorKind::DisplayHelp
                || e.kind() == clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
                || e.kind() == clap::error::ErrorKind::DisplayVersion =>
        {
            // Let clap render help/version to stdout and exit 0.
            e.exit();
        }
        Err(e) => {
            log_cli_usage_error(&args, &e);
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

// The `run`/`exec` and `appeal` commands disable clap's help flag so that
// `-h`/`--help` after the target binary forward to that binary instead of
// printing guard's own help. The cost is that a help flag meant for guard
// (before any binary is named) would otherwise error, so it is recovered here
// and redirected to the subcommand's own help.
fn passthrough_command_help_requested(
    args: &[String],
) -> Option<(Vec<&'static str>, &'static str)> {
    let is_help = |idx| matches!(args.get(idx).map(String::as_str), Some("--help" | "-h"));
    match args.first().map(String::as_str) {
        Some("run" | "exec") if is_help(1) && args.len() == 2 => Some((vec!["run"], "guard run")),
        // `guard appeal [--session T] [--socket P] <binary> ...`: the binary is
        // the first positional. Help before it is guard's; after it forwards.
        Some("appeal") if appeal_self_help_requested(&args[1..], &["--session", "--socket"], 0) => {
            Some((vec!["appeal"], "guard appeal"))
        }
        // `guard session appeal [--socket P] <token> <binary> ...`: the binary is
        // the second positional (token is the first).
        Some("session")
            if matches!(args.get(1).map(String::as_str), Some("appeal"))
                && appeal_self_help_requested(&args[2..], &["--socket"], 1) =>
        {
            Some((vec!["session", "appeal"], "guard session appeal"))
        }
        _ => None,
    }
}

/// True if `-h`/`--help` in an appeal invocation is meant for guard rather than
/// the appealed command: it appears before the `<binary>` positional has been
/// consumed. `value_flags` are the guard options that take a separate value (so
/// their value is not miscounted as a positional); `leading_positionals` is how
/// many positionals precede `<binary>` (0 for top-level appeal, 1 for `session
/// appeal`, whose first positional is the token).
fn appeal_self_help_requested(
    args: &[String],
    value_flags: &[&str],
    leading_positionals: usize,
) -> bool {
    let mut positionals = 0usize;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "--help" || arg == "-h" {
            // `<binary>` is the positional at index `leading_positionals`; it is
            // consumed once `positionals` exceeds that count.
            return positionals <= leading_positionals;
        }
        if arg.starts_with('-') && arg != "-" {
            if value_flags.contains(&arg) && !arg.contains('=') {
                i += 2;
            } else {
                i += 1;
            }
        } else {
            positionals += 1;
            if positionals > leading_positionals {
                // The binary has been named; everything after belongs to it.
                return false;
            }
            i += 1;
        }
    }
    false
}

fn print_nested_help(path: &[&str], bin_name: &str) -> Result<()> {
    let mut command = MainArgs::command();
    for name in path {
        command = command.find_subcommand(name).cloned().ok_or_else(|| {
            anyhow::anyhow!("internal error: help for `{}` is unavailable", bin_name)
        })?;
    }
    command = command.bin_name(bin_name);
    command.print_help()?;
    println!();
    Ok(())
}

#[derive(Clone, Copy)]
enum AnsiColor {
    Red,
    Green,
    Yellow,
    Cyan,
    Bold,
}

fn color_enabled_for_stdout() -> bool {
    color_enabled(std::io::stdout().is_terminal())
}

fn color_enabled_for_stderr() -> bool {
    color_enabled(std::io::stderr().is_terminal())
}

fn color_enabled(is_terminal: bool) -> bool {
    is_terminal
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var("TERM")
            .map(|term| term != "dumb")
            .unwrap_or(true)
}

fn paint(text: impl AsRef<str>, color: AnsiColor, enabled: bool) -> String {
    if !enabled {
        return text.as_ref().to_string();
    }
    let code = match color {
        AnsiColor::Red => "31",
        AnsiColor::Green => "32",
        AnsiColor::Yellow => "33",
        AnsiColor::Cyan => "36",
        AnsiColor::Bold => "1",
    };
    format!("\x1b[{code}m{}\x1b[0m", text.as_ref())
}

struct UtcTimestamp;

impl FormatTime for UtcTimestamp {
    fn format_time(&self, writer: &mut Writer<'_>) -> std::fmt::Result {
        let now = guard::env::now_unix();
        write!(writer, "{}", unix_seconds_to_utc(now))
    }
}

fn unix_seconds_to_utc(ts: u64) -> String {
    let days = (ts / 86_400) as i64;
    let seconds = ts % 86_400;
    let hour = seconds / 3_600;
    let minute = (seconds % 3_600) / 60;
    let second = seconds % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days_since_epoch: i64) -> (i64, u64, u64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    (year, month as u64, day as u64)
}

fn format_timestamp(ts: u64) -> String {
    format!("{} ({ts})", unix_seconds_to_utc(ts))
}

fn format_optional_timestamp(ts: Option<u64>) -> String {
    ts.map(format_timestamp)
        .unwrap_or_else(|| "(never)".to_string())
}

fn log_cli_usage_error(args: &[String], error: &clap::Error) {
    let command_path = cli_command_path(args);
    tracing::warn!(
        "[AUDIT] CLI_USAGE_ERROR command={} kind={:?} argc={}",
        command_path,
        error.kind(),
        args.len()
    );
}

fn cli_command_path(args: &[String]) -> String {
    let mut parts = args
        .iter()
        .filter(|arg| !arg.starts_with('-'))
        .map(String::as_str);
    let Some(first) = parts.next() else {
        return "(top-level)".to_string();
    };
    let Some(second) = parts.next() else {
        return first.to_string();
    };
    let allowed_second = match first {
        "server" => matches!(second, "start" | "connect" | "status"),
        "secrets" | "secret" => matches!(second, "add" | "list" | "remove"),
        "config" => matches!(
            second,
            "show"
                | "set-server"
                | "set-port"
                | "set-token"
                | "set-admin-token"
                | "set-user"
                | "clear"
        ),
        "mcp" => matches!(second, "serve"),
        "session" => matches!(
            second,
            "new" | "grant" | "appeal" | "revoke" | "show" | "list"
        ),
        "verb" => matches!(second, "list" | "run" | "create"),
        _ => false,
    };
    if allowed_second {
        format!("{first} {second}")
    } else {
        first.to_string()
    }
}

fn print_help_tree(admin: bool) {
    let color = color_enabled_for_stdout();
    println!("{}", paint("guard access summary", AnsiColor::Bold, color));
    println!("  user");
    println!("    run|exec <binary> [args...]");
    println!("    server connect <binary> [args...]");
    println!("    status");
    println!("    server status");
    println!("    secrets|secret add|remove|list");
    println!("    verb list");
    println!("    verb run <name> --param key=value");
    println!("    grant-read <path> --ttl <secs>");
    println!("    grant-revoke <path>");
    println!("    session list [--history] [--since duration] [--full]");
    println!("    session show [token]  (defaults to $GUARD_SESSION)");
    println!("    session new");
    println!("    provisionals");
    println!("    approvals [handle]");
    println!("    approval-note <handle> <text>");
    println!("    mcp serve");
    println!();
    println!("  local setup");
    println!("    shim [tools] [--list|--remove]");
    println!("    config show|set-server|set-port|set-token|set-admin-token|set-user|clear");
    if admin {
        println!();
        println!("{}", paint("  admin", AnsiColor::Yellow, color));
        println!("    server start");
        println!("    session new [prose] [--allow glob] [--deny glob]");
        println!("    session grant <token> [prose] [--allow glob] [--deny glob]");
        println!("    session appeal <token> <binary> [args...]");
        println!("    session revoke <token>");
        println!("    grant [token] [prose]");
        println!("    appeal --session <token> <binary> [args...]");
        println!("    secrets list --detailed");
        println!("    approve|deny <handle>");
        println!("    confirm|revert <handle>");
        println!("    verb create --prompt <text>");
    } else {
        println!();
        println!(
            "{}",
            paint(
                "Run `guard help-tree --admin` to include daemon-principal/admin-token commands.",
                AnsiColor::Cyan,
                color,
            )
        );
    }
    println!();
    println!("Access markers:");
    println!("  user commands are available to allowed local callers.");
    println!("  local setup commands edit client-side files for the invoking account.");
    println!("  session show reveals a full grant only to the daemon or the token's own holder; list hides raw tokens for non-admin callers.");
    println!("  admin commands require the daemon principal or the TCP admin token.");
}
#[cfg(test)]
mod tests;
