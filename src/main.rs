//! guard - evaluator-gated command execution for AI agents
//!

mod cli_client;
mod cli_secrets;
mod cli_server;
mod cli_shim;
mod client_config;
mod daemon_client;
mod defaults;
mod grant_profile;
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

#[cfg(windows)]
use anyhow::Context;
use anyhow::Result;
use clap::{ArgAction, CommandFactory, Parser, Subcommand};
use injection::{collect_unique_pairs, derive_env_name, is_valid_env_name};
use std::collections::HashMap;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use tracing_subscriber::filter::{filter_fn, FilterExt};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt as tracing_fmt, EnvFilter, Layer};

const EXIT_GUARD_ERROR: i32 = 125;
const EXIT_GUARD_DENIED: i32 = 126;
const EXIT_GUARD_HELD: i32 = 127;
/// One or more decisions in a completed access batch failed. This is a result
/// status, not a guard operational failure.
const EXIT_GUARD_ACCESS_DECISION_FAILED: i32 = 1;
const JSON_SCHEMA_VERSION: u32 = 1;

fn parse_unbounded_secs(value: &str) -> Result<u64, String> {
    if value.eq_ignore_ascii_case("unbounded") {
        return Ok(u64::MAX);
    }
    let seconds = value
        .parse::<u64>()
        .map_err(|_| "expected positive seconds or 'unbounded'".to_string())?;
    if seconds == 0 {
        return Err("duration must be greater than zero or 'unbounded'".to_string());
    }
    Ok(seconds)
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<()> {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer_pretty(&mut lock, value)?;
    writeln!(lock)?;
    Ok(())
}

use cli_client::{
    handle_access, handle_api, handle_audit_tail, handle_audit_verify, handle_config,
    handle_gate_action, handle_provisionals, handle_resume, handle_status, handle_verb, run_exec,
    run_mcp, GatingOptions, RunInjections, SshHostKeyCliMode,
};
use cli_secrets::handle_secrets;
use cli_server::run_server;
use cli_shim::{handle_shim, ShimOptions};

#[derive(Parser)]
#[command(
    name = "guard",
    about = "Evaluator-gated command execution for AI agents",
    after_help = "Access workflow:\n  Agents run ordinary commands and use `guard access request \"<intent>\"` when authority is missing.\n  Operators use `guard access approve <request>...`, optionally with `--once` or `--uses N`; on a terminal it reviews each request first, and `--yes` skips the review.\n  `guard access list` and `show` inspect principal-bound requests, holds, and sessions without bearer tokens.\n  Operators use `guard access revoke <session-or-agent>` to remove active access authority.\n\nUse `guard access --help` for representative examples or `guard help-tree` for the full command map."
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
        after_help = "Use `guard run <binary> --help` to pass --help to the child command.\n\n\
            Exit codes:\n  \
            125    guard operational error (daemon unreachable, protocol failure)\n  \
            126    denied by policy\n  \
            127    held for operator approval\n  \
            2      invalid guard CLI usage\n  \
            other  the child's own exit status, propagated untranslated\n\n\
            A child can itself exit 125-127 (`sh -c` exits 127 for a missing command;\n\
            `git bisect skip` uses 125), so the exit code alone cannot prove a\n\
            guard-origin outcome. Use --json and read `allowed`/`status` for certainty."
    )]
    Run {
        /// Emit one machine-readable result object instead of streaming child output.
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
        /// Explain the selected verb coverage and decision source on stderr.
        #[arg(long, action = ArgAction::SetTrue)]
        explain: bool,
        /// Inject an environment variable (KEY=VALUE, repeatable)
        #[arg(long = "env", value_name = "KEY=VALUE", value_parser = parse_env_assignment)]
        env_vars: Vec<(String, String)>,
        /// Inject a stored secret. Bare SECRET derives an env var; ENV_VAR=SECRET sets one.
        /// Repeat the flag or pass a comma-separated list for multiple secrets.
        #[arg(long = "secret", value_name = "SECRET[,SECRET]", value_parser = parse_secret_mapping, value_delimiter = ',')]
        secret_vars: Vec<(String, String)>,
        /// Inject a stored secret through a private file path in ENV_VAR.
        #[arg(long = "secret-file", value_name = "ENV_VAR=SECRET", value_parser = parse_env_assignment, value_delimiter = ',')]
        secret_file_vars: Vec<(String, String)>,
        /// Rollback command for a recoverable action under consequence gating,
        /// as a single string (e.g. --revert "systemctl stop nginx"). It is
        /// assessed with the full envelope; an uncertain chain is held.
        #[arg(long = "revert", value_name = "COMMAND")]
        revert: Option<String>,
        /// Independent command run at the deadline. Exit zero confirms the
        /// change; any other result runs the rollback.
        #[arg(long = "confirm-check", value_name = "COMMAND", requires = "revert")]
        confirm_check: Option<String>,
        /// Authority and transport required to run the confirmation check and
        /// rollback, such as "brokered SSH to firewall-a".
        #[arg(
            long = "revert-control-path",
            value_name = "DESCRIPTION",
            requires = "revert"
        )]
        revert_control_path: Option<String>,
        /// Auto-revert window in seconds for the containment envelope.
        #[arg(long = "confirm-within", value_name = "SECONDS")]
        confirm_within: Option<u64>,
        /// Force the command onto the operator-approval (hold) path.
        #[arg(long = "require-approval", action = ArgAction::SetTrue)]
        require_approval: bool,
        /// Block for SECONDS or `unbounded` for an operator decision. A bare
        /// flag is unbounded and remains cancellable by disconnecting.
        #[arg(long = "wait-approval", value_name = "SECONDS|unbounded", num_args = 0..=1, default_missing_value = "unbounded", value_parser = parse_unbounded_secs)]
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
        /// Emit machine-readable output when listing shims.
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
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
    /// Removed caller-scoped API credential export.
    #[clap(subcommand, hide = true)]
    Api(ApiCommands),
    /// Expose guard as an MCP server over stdio
    #[clap(subcommand)]
    Mcp(McpCommands),
    /// Request, approve, inspect, and extend principal-bound access.
    #[clap(
        subcommand,
        after_help = "Common workflow:\n  guard access request \"restart the fixture service\"\n  guard access approve <request>\n  guard access approve <request> --once\n  guard access approve <request> --uses 3\n  guard access approve <request> --yes\n  guard access list\n  guard access show <request-or-session>\n  guard access revoke <session-or-agent>\n\nOn a terminal, approve reviews each request before deciding; --yes skips the review.\nRequests left undecided by skip or quit stay pending and do not fail the batch.\n\nExit status:\n  1      one or more decisions in the access batch failed"
    )]
    Access(AccessCommands),
    /// Removed legacy authority command. Use `guard access`.
    #[clap(hide = true, disable_help_flag = true)]
    Session {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        legacy_args: Vec<String>,
    },
    /// Removed legacy authority command. Use `guard access`.
    #[clap(hide = true, disable_help_flag = true)]
    Grant {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        legacy_args: Vec<String>,
    },
    /// Removed legacy authority command. Use `guard access request`.
    #[clap(hide = true, disable_help_flag = true)]
    Appeal {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        legacy_args: Vec<String>,
    },
    /// Show daemon status. Always prints client + server version,
    /// uptime, evaluation mode, and dry-run state. The full config
    /// snapshot is restricted to the daemon UID.
    Status {
        #[arg(long)]
        socket: Option<String>,
        /// Emit machine-readable status.
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
    },
    /// Print a categorized command tree with access markers.
    #[clap(name = "help-tree")]
    HelpTree {
        /// Include daemon-principal/admin-token commands.
        #[arg(long, action = ArgAction::SetTrue)]
        admin: bool,
    },
    /// Generate shell completion definitions.
    Completions {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// List provisional (containment-envelope) executions awaiting confirmation.
    Provisionals {
        #[arg(long)]
        socket: Option<String>,
        /// Emit machine-readable provisional records.
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
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
    /// Execute one operator-approved hold as its original requester.
    Resume {
        handle: String,
        #[arg(long)]
        socket: Option<String>,
        /// Emit the persisted execution result as one JSON document.
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
    },
    /// Run or list operator-defined verbs (the typed, least-expressive interface).
    #[clap(subcommand)]
    Verb(VerbCommands),
    /// Inspect the daemon's hash-chained audit log. Daemon-principal only.
    #[clap(subcommand)]
    Audit(AuditCommands),
}

#[derive(Subcommand)]
enum AuditCommands {
    /// Walk the audit chain from genesis and report intact or the first
    /// broken sequence (any truncation, edit, or reorder breaks the chain).
    Verify {
        #[arg(long)]
        socket: Option<String>,
        /// Emit the machine-readable verification result.
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
    },
    /// Print the most recent audit records.
    Tail {
        /// Number of records to print (default 20).
        #[arg(short = 'n', long = "lines", value_name = "N")]
        n: Option<usize>,
        #[arg(long)]
        socket: Option<String>,
        /// Emit machine-readable audit records.
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum AccessCommands {
    /// Submit prose for the authenticated local principal.
    Request {
        intent: String,
        #[arg(long)]
        socket: Option<String>,
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
    },
    /// Approve each request independently with unlimited authority by default.
    /// On a terminal this reviews each request interactively; --yes skips the review.
    Approve {
        #[arg(required = true)]
        requests: Vec<String>,
        /// Decide without the interactive review.
        #[arg(long, action = ArgAction::SetTrue)]
        yes: bool,
        /// Grant one use. Equivalent to --uses 1.
        #[arg(long, conflicts_with = "uses", action = ArgAction::SetTrue)]
        once: bool,
        /// Grant exactly N uses. A batch exits 1 if any request fails.
        #[arg(long, value_name = "N", value_parser = clap::value_parser!(u64).range(1..))]
        uses: Option<u64>,
        #[arg(long)]
        socket: Option<String>,
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
    },
    /// Deny one or more requests independently.
    Deny {
        #[arg(required = true)]
        requests: Vec<String>,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        socket: Option<String>,
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
    },
    /// Revoke one active access-managed session.
    Revoke {
        target: String,
        #[arg(long)]
        socket: Option<String>,
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
    },
    /// Add prose-derived authority to one session reference or agent label. Unlimited by default.
    Extend {
        /// Stable session reference or agent label that receives the authority.
        target: String,
        /// Plain-language description of the authority to add.
        intent: String,
        /// Grant one use. Equivalent to --uses 1.
        #[arg(long, conflicts_with = "uses", action = ArgAction::SetTrue)]
        once: bool,
        /// Grant exactly N uses. Omit both use flags for unlimited authority.
        #[arg(long, value_name = "N", value_parser = clap::value_parser!(u64).range(1..))]
        uses: Option<u64>,
        #[arg(long)]
        socket: Option<String>,
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
    },
    /// List compact request and session state.
    List {
        #[arg(long)]
        socket: Option<String>,
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
    },
    /// Show detailed request or session coverage and evidence.
    Show {
        reference: String,
        #[arg(long)]
        socket: Option<String>,
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum VerbCommands {
    /// List available verbs with their parameters and consequence class.
    List {
        #[arg(long)]
        socket: Option<String>,
        /// Emit machine-readable verb records.
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
    },
    /// Show one verb, including typed coverage and generation evidence.
    #[clap(hide = true)]
    Show {
        name: String,
        #[arg(long)]
        socket: Option<String>,
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
    },
    /// Delete one operator-authored verb.
    #[clap(hide = true)]
    Delete {
        name: String,
        #[arg(long)]
        socket: Option<String>,
    },
    /// Replace one operator-authored verb without clobbering concurrent edits.
    Amend {
        name: String,
        /// YAML file containing exactly one verb definition.
        #[arg(long, value_name = "PATH")]
        file: PathBuf,
        #[arg(long)]
        socket: Option<String>,
        /// Emit a machine-readable amendment result.
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
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
        /// Block for SECONDS or `unbounded` for an operator decision. A bare
        /// flag is unbounded and remains cancellable by disconnecting.
        #[arg(long = "wait-approval", value_name = "SECONDS|unbounded", num_args = 0..=1, default_missing_value = "unbounded", value_parser = parse_unbounded_secs)]
        wait_approval: Option<u64>,
        #[arg(long)]
        socket: Option<String>,
        /// Emit one machine-readable result object instead of streaming child output.
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
        /// Explain the selected verb coverage and decision source on stderr.
        #[arg(long, action = ArgAction::SetTrue)]
        explain: bool,
    },
    /// Create a verb from plain-language prose (LLM-synthesized, validated, and
    /// stored with the prose + evidence). Operator-only.
    #[clap(hide = true)]
    Create {
        /// Plain-language description of the operation to expose as a verb.
        #[arg(
            long,
            required_unless_present = "from_preview",
            conflicts_with = "from_preview"
        )]
        prompt: Option<String>,
        /// Optional hint: the target binary (e.g. cmk, kubectl).
        #[arg(long, conflicts_with = "from_preview")]
        binary: Option<String>,
        /// Synthesize and show the verb but do not write it to the catalog.
        #[arg(long, conflicts_with = "from_preview")]
        preview: bool,
        /// Install a previewed candidate exactly as reviewed, by its digest or
        /// an unambiguous prefix. No LLM call.
        #[arg(long, value_name = "DIGEST")]
        from_preview: Option<String>,
        /// Automatic re-synthesis attempts after a safety-gate rejection
        /// (0 disables). Defaults to the client config or 4.
        #[arg(long, value_name = "N", conflicts_with = "from_preview")]
        retries: Option<u32>,
        /// Skip the interactive create-now prompt after a terminal preview.
        #[arg(long, action = ArgAction::SetTrue)]
        yes: bool,
        #[arg(long)]
        socket: Option<String>,
        /// Emit the synthesized verb as machine-readable JSON.
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
    },
    /// Inspect or clear evaluator-generated API verb coverage.
    Coverage {
        #[command(subcommand)]
        command: VerbCoverageCommands,
    },
}

#[derive(Subcommand)]
enum VerbCoverageCommands {
    /// List active and expired generated API coverage cells.
    List {
        #[arg(long)]
        socket: Option<String>,
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
    },
    /// Clear evaluator-generated API coverage and its evidence.
    Clear {
        #[arg(long)]
        socket: Option<String>,
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
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

fn legacy_authority_error(command: &str, replacement: &str) -> Result<()> {
    anyhow::bail!(
        "`guard {command}` has been removed because it bypasses the principal-bound access workflow; use `{replacement}`"
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

        /// Shared token required for TCP clients. Read from GUARD_AUTH_TOKEN.
        #[arg(skip)]
        auth_token: Option<String>,

        /// Separate token required for non-Ping admin RPCs on every listener.
        /// Read from GUARD_ADMIN_TOKEN (development only: a brokered child
        /// can read the daemon's /proc/<pid>/environ).
        #[arg(skip)]
        admin_token: Option<String>,

        /// Read the admin token's first line from stdin at startup. This is
        /// the production channel: the operator's service manager opens the
        /// root-held token file (e.g. systemd StandardInput=file:) so the
        /// value never enters the daemon's environment, argv, or a file its
        /// brokered children can read. Env: GUARD_ADMIN_TOKEN_STDIN.
        #[arg(long = "admin-token-stdin", action = ArgAction::SetTrue)]
        admin_token_stdin: bool,

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

        /// LLM provider API key. Read from GUARD_LLM_API_KEY or
        /// OPENROUTER_API_KEY.
        #[arg(skip)]
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
            long = "evaluator",
            alias = "llm",
            action = ArgAction::Set,
            num_args = 0..=1,
            default_missing_value = "true",
            value_name = "BOOL",
            overrides_with = "no_llm"
        )]
        llm: Option<bool>,

        /// Disable LLM evaluation; static policy must allow commands.
        #[arg(long = "no-evaluator", alias = "no-llm", action = ArgAction::SetTrue, overrides_with = "llm")]
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
        #[arg(long = "learn-rules", hide = true, action = ArgAction::SetTrue)]
        learn_rules: bool,

        /// Path to the learned-rule candidate state YAML.
        /// Env: GUARD_LEARNED_RULES.
        #[arg(long, value_name = "PATH", hide = true)]
        learned_rules: Option<PathBuf>,

        /// LLM approvals required before a command becomes a learned-rule
        /// candidate. Env: GUARD_LEARN_MIN_APPROVALS.
        #[arg(long, value_name = "N", hide = true)]
        learn_min_approvals: Option<u32>,

        /// Maximum risk score eligible for learned-rule candidacy.
        /// Env: GUARD_LEARN_MAX_RISK.
        #[arg(long, value_name = "0-10", hide = true)]
        learn_max_risk: Option<i32>,

        /// Service-shim behavior for learned-rule candidates: off, suggest, or
        /// create. A shim is a command alias, not a bypass -- the aliased
        /// command still runs through normal evaluation. Env: GUARD_LEARN_SHIMS.
        #[arg(long, value_name = "MODE", hide = true)]
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

        /// Append-only hash-chained JSONL audit log path. Defaults to
        /// audit.jsonl in the state directory. Env: GUARD_AUDIT_LOG.
        #[arg(long = "audit-log", value_name = "PATH")]
        audit_log: Option<PathBuf>,

        /// Serve a read-only metrics/health surface on ADDR (GET /healthz,
        /// /metrics Prometheus text, /metrics.json). Off unless set. A bare
        /// port binds 127.0.0.1. Unauthenticated and free of any command,
        /// argument, secret, or reason text - coarse counters only. The daemon
        /// refuses to start if the bind fails. Env: GUARD_METRICS_ADDR.
        #[arg(long = "metrics-addr", value_name = "ADDR")]
        metrics_addr: Option<String>,

        /// Retain ended session grants and command interactions for this many
        /// seconds. Env: GUARD_HISTORY_RETENTION_SECS. Default: 86400.
        #[arg(long = "history-retention", value_name = "SECONDS")]
        history_retention: Option<u64>,

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

        /// Held-command lifetime in seconds, or `unbounded`.
        /// Env: GUARD_APPROVAL_TTL.
        #[arg(long, value_name = "SECONDS|unbounded")]
        approval_ttl: Option<String>,

        /// Path to the verb catalog YAML (the operator-defined, typed interface
        /// agents call via `guard verb`). Hot-reloaded on change.
        /// Env: GUARD_VERBS.
        #[arg(long, value_name = "PATH")]
        verbs: Option<PathBuf>,

        /// YAML catalog of reusable saved grants.
        /// Env: GUARD_GRANTS.
        #[arg(long, alias = "profiles", value_name = "PATH")]
        grants: Option<PathBuf>,

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

        /// Front an HTTP API with a TLS-terminating, protocol-aware proxy on
        /// ADDR (loopback only). --api-protocol selects the protocol (default
        /// kubernetes, which takes its upstream and credentials from
        /// --kubeconfig); github and vercel require --api-upstream and a bearer
        /// token via --api-token-env or --api-token-file. Env: GUARD_API_PROXY.
        #[arg(long = "api-proxy", value_name = "ADDR")]
        api_proxy: Option<String>,

        /// YAML file containing reusable named API endpoints. Each endpoint
        /// owns its listener, protocol, upstream credential reference, policy,
        /// and optional brokered client output. Env: GUARD_API_ENDPOINTS.
        #[arg(long = "api-endpoints", value_name = "PATH")]
        api_endpoints: Option<PathBuf>,

        /// Protocol parser for --api-proxy: kubernetes, github, or vercel. Env:
        /// GUARD_API_PROTOCOL.
        #[arg(long = "api-protocol", value_name = "NAME")]
        api_protocol: Option<String>,

        /// Base upstream URL for --api-proxy. Env: GUARD_API_UPSTREAM.
        #[arg(long = "api-upstream", value_name = "URL")]
        api_upstream: Option<String>,

        /// Environment variable containing the upstream bearer token. Env:
        /// GUARD_API_TOKEN_ENV.
        #[arg(long = "api-token-env", value_name = "VAR")]
        api_token_env: Option<String>,

        /// File containing the upstream bearer token. Env:
        /// GUARD_API_TOKEN_FILE.
        #[arg(long = "api-token-file", value_name = "PATH")]
        api_token_file: Option<PathBuf>,

        /// Write the proxy CA certificate PEM here for generic API clients.
        /// Env: GUARD_API_CA_OUT.
        #[arg(long = "api-ca-out", value_name = "PATH")]
        api_ca_out: Option<PathBuf>,

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

        /// Generate exact API verb coverage from repeated evaluator verdicts.
        /// Generated allows retain the consequence floor. Env:
        /// GUARD_API_VERB_COVERAGE.
        #[arg(
            long = "api-verb-coverage",
            alias = "api-promotion",
            action = ArgAction::Set,
            num_args = 0..=1,
            default_missing_value = "true",
            value_name = "BOOL",
            overrides_with = "no_api_promotion"
        )]
        api_promotion: Option<bool>,

        /// Disable generated API verb coverage.
        #[arg(long = "no-api-verb-coverage", alias = "no-api-promotion", action = ArgAction::SetTrue, overrides_with = "api_promotion")]
        no_api_promotion: bool,

        /// Path to generated API verb coverage state YAML.
        /// Env: GUARD_API_VERB_COVERAGE_STATE.
        #[arg(
            long = "api-verb-coverage-state",
            alias = "api-promotion-state",
            value_name = "PATH"
        )]
        api_promotion_state: Option<PathBuf>,

        /// Evaluator approvals required before generated allow coverage is active.
        /// Env: GUARD_API_VERB_COVERAGE_MIN_APPROVALS.
        #[arg(
            long = "api-verb-coverage-min-approvals",
            alias = "api-promotion-min-approvals",
            value_name = "N"
        )]
        api_promotion_min_approvals: Option<u32>,

        /// Evaluator denials required before generated deny coverage is active.
        /// Env: GUARD_API_VERB_COVERAGE_MIN_DENIALS.
        #[arg(
            long = "api-verb-coverage-min-denials",
            alias = "api-promotion-min-denials",
            value_name = "N"
        )]
        api_promotion_min_denials: Option<u32>,

        /// Fire an operator command for gate lifecycle events. The command is
        /// parsed into argv, receives one JSON event on stdin, and is killed at
        /// the bounded timeout. Off by default. Env: GUARD_NOTIFY_CMD.
        #[arg(long = "notify-cmd", value_name = "COMMAND")]
        notify_cmd: Option<String>,

        /// Notify command timeout in seconds (1-60). Env:
        /// GUARD_NOTIFY_TIMEOUT_SECS.
        #[arg(long = "notify-timeout", value_name = "SECONDS")]
        notify_timeout: Option<u64>,

        /// Rolling window for session behavioral circuit breakers. Env:
        /// GUARD_SESSION_BEHAVIOR_WINDOW_SECS.
        #[arg(long = "session-behavior-window", value_name = "SECONDS")]
        session_behavior_window: Option<u64>,

        /// Suspend a session after this many denials in the rolling window.
        /// Env: GUARD_SESSION_MAX_DENIALS.
        #[arg(long = "session-max-denials", value_name = "N")]
        session_max_denials: Option<u64>,

        /// Suspend a session after this many holds in the rolling window. Env:
        /// GUARD_SESSION_MAX_HOLDS.
        #[arg(long = "session-max-holds", value_name = "N")]
        session_max_holds: Option<u64>,

        /// Suspend when the rolling denial ratio reaches this percentage. Env:
        /// GUARD_SESSION_MAX_DENY_RATIO.
        #[arg(long = "session-max-deny-ratio", value_name = "1-100")]
        session_max_deny_ratio: Option<u8>,

        /// Minimum rolling command count before applying the denial ratio. Env:
        /// GUARD_SESSION_DENY_RATIO_MIN_COMMANDS.
        #[arg(long = "session-deny-ratio-min-commands", value_name = "N")]
        session_deny_ratio_min_commands: Option<u64>,

        /// Maximum simultaneous evaluator calls across API proxy traffic.
        /// Env: GUARD_API_JUDGE_MAX_CONCURRENCY.
        #[arg(long, value_name = "N")]
        api_judge_max_concurrency: Option<usize>,

        /// Evaluator calls admitted per minute across API proxy traffic.
        /// Env: GUARD_API_JUDGE_RATE_PER_MINUTE.
        #[arg(long, value_name = "N")]
        api_judge_rate_per_minute: Option<u32>,

        /// Token-bucket burst capacity for API evaluator calls.
        /// Env: GUARD_API_JUDGE_BURST.
        #[arg(long, value_name = "N")]
        api_judge_burst: Option<u32>,

        /// Consecutive evaluator errors that open the API judge circuit.
        /// Env: GUARD_API_JUDGE_ERROR_THRESHOLD.
        #[arg(long, value_name = "N")]
        api_judge_error_threshold: Option<u32>,

        /// Seconds an API judge circuit remains open after repeated errors.
        /// Env: GUARD_API_JUDGE_CIRCUIT_COOLDOWN.
        #[arg(long, value_name = "SECONDS")]
        api_judge_circuit_cooldown: Option<u64>,

        /// Maximum simultaneous command handlers. Env: GUARD_COMMAND_MAX_CONCURRENCY.
        #[arg(long, value_name = "N")]
        command_max_concurrency: Option<usize>,
        /// Maximum simultaneous commands for one authenticated principal. Env:
        /// GUARD_COMMAND_PRINCIPAL_CONCURRENCY.
        #[arg(long, value_name = "N")]
        command_principal_concurrency: Option<usize>,
        /// Maximum simultaneous command evaluator calls. Env:
        /// GUARD_COMMAND_EVALUATOR_MAX_CONCURRENCY.
        #[arg(long, value_name = "N")]
        command_evaluator_max_concurrency: Option<usize>,
        /// Maximum simultaneous evaluator calls for one principal. Env:
        /// GUARD_COMMAND_EVALUATOR_PRINCIPAL_CONCURRENCY.
        #[arg(long, value_name = "N")]
        command_evaluator_principal_concurrency: Option<usize>,
        /// Evaluator admissions per minute for each command principal. Env:
        /// GUARD_COMMAND_EVALUATOR_RATE_PER_MINUTE.
        #[arg(long, value_name = "N")]
        command_evaluator_rate_per_minute: Option<u32>,
        /// Per-principal command evaluator burst capacity. Env:
        /// GUARD_COMMAND_EVALUATOR_BURST.
        #[arg(long, value_name = "N")]
        command_evaluator_burst: Option<u32>,
        /// Consecutive command evaluator errors that open the circuit. Env:
        /// GUARD_COMMAND_EVALUATOR_ERROR_THRESHOLD.
        #[arg(long, value_name = "N")]
        command_evaluator_error_threshold: Option<u32>,
        /// Command evaluator circuit cooldown in seconds. Env:
        /// GUARD_COMMAND_EVALUATOR_CIRCUIT_COOLDOWN.
        #[arg(long, value_name = "SECONDS")]
        command_evaluator_circuit_cooldown: Option<u64>,
        /// Internal marker: launched under the Windows Service Control Manager.
        /// The Windows installer sets this in the service binPath so startup
        /// answers the SCM start/stop handshake instead of running in the
        /// foreground. Hidden; it has no effect when not run as a Windows
        /// service, and the daemon configuration is otherwise identical.
        #[arg(long = "service", hide = true, action = ArgAction::SetTrue)]
        service: bool,
    },
    /// Connect to guard server and execute a command
    #[clap(
        after_help = "Guard parses its own flags anywhere on the line, so a child argument that\n\
            matches one (--socket, --env, -h, ...) is consumed by guard instead of the\n\
            child. Pass `--` after guard's options to forward everything that follows\n\
            verbatim, e.g. `guard server connect -- df -h`."
    )]
    Connect {
        /// UNIX socket path to connect to.
        #[arg(long, value_name = "PATH")]
        socket: Option<String>,

        /// TCP port on 127.0.0.1 to connect to.
        #[arg(long, value_name = "PORT")]
        tcp_port: Option<u16>,

        /// Inject an environment variable (KEY=VALUE, repeatable)
        #[arg(long = "env", value_name = "KEY=VALUE", value_parser = parse_env_assignment)]
        env_vars: Vec<(String, String)>,

        /// Inject a stored secret. Bare SECRET derives an env var; ENV_VAR=SECRET sets one.
        /// Repeat the flag or pass a comma-separated list for multiple secrets.
        #[arg(long = "secret", value_name = "SECRET[,SECRET]", value_parser = parse_secret_mapping, value_delimiter = ',')]
        secret_vars: Vec<(String, String)>,
        /// Inject a stored secret through a private file path in ENV_VAR.
        #[arg(long = "secret-file", value_name = "ENV_VAR=SECRET", value_parser = parse_env_assignment, value_delimiter = ',')]
        secret_file_vars: Vec<(String, String)>,

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
        /// Emit machine-readable status.
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Show current configuration
    Show {
        /// Emit machine-readable configuration with credentials masked.
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
    },
    /// Set server socket path
    SetServer {
        /// Socket path for guard clients: a UNIX domain socket path on Unix,
        /// or a named pipe path on Windows.
        socket: String,
    },
    /// Set TCP port
    SetPort {
        /// TCP port on 127.0.0.1 for guard clients.
        port: u16,
    },
    /// Set the TCP execution token from piped stdin or a hidden prompt.
    SetToken,
    /// Set the TCP admin token from piped stdin or a hidden prompt.
    SetAdminToken,
    /// Set default user
    SetUser {
        /// Default user label for client configuration.
        user: String,
    },
    /// Clear configuration
    Clear,
}

#[derive(Subcommand)]
enum ApiCommands {
    /// Removed because access-managed authority is command-only.
    #[clap(hide = true)]
    Kubeconfig {
        /// Named Kubernetes endpoint configured on the daemon.
        #[arg(long, default_value = "default")]
        endpoint: String,
        /// Write a private 0600 file instead of YAML on standard output.
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// Server socket path (defaults to configured).
        #[arg(long, value_name = "PATH")]
        socket: Option<String>,
    },
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

        /// MCP tool name exposed to clients.
        #[arg(long, default_value = "guard_run")]
        tool_name: String,

        /// Serve MCP over Streamable HTTP on a loopback address (for example,
        /// 127.0.0.1:7333) instead of stdio. Requires GUARD_MCP_TOKEN.
        #[arg(long, value_name = "ADDR")]
        http: Option<String>,
    },
}

#[derive(Subcommand)]
enum SecretCommands {
    /// Store a secret in guard's configured backend.
    Add {
        /// Secret key used by --secret and tool configs.
        key: String,
        /// Secret value, read from piped stdin or a hidden prompt.
        #[arg(skip)]
        value: Option<String>,
    },
    /// List stored secret keys.
    List {
        /// Include daemon-only ownership/origin detail for migration work.
        #[arg(long, action = ArgAction::SetTrue)]
        detailed: bool,
        /// Emit machine-readable secret metadata. Values are never included.
        #[arg(long, action = ArgAction::SetTrue)]
        json: bool,
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
async fn main() {
    if let Err(error) = run_main().await {
        eprintln!("guard: {error:#}");
        std::process::exit(EXIT_GUARD_ERROR);
    }
}

async fn run_main() -> Result<()> {
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
    let non_audit = filter_fn(|metadata| metadata.target() != "guard::audit").and(filter);
    let audit = filter_fn(|metadata| metadata.target() == "guard::audit");
    let ansi = color_enabled_for_stderr();
    tracing_subscriber::registry()
        .with(
            tracing_fmt::layer()
                .with_target(true)
                .with_timer(UtcTimestamp)
                .with_ansi(ansi)
                .with_writer(std::io::stderr)
                .with_filter(non_audit),
        )
        .with(
            tracing_fmt::layer()
                .with_target(true)
                .with_timer(UtcTimestamp)
                .with_ansi(ansi)
                .with_writer(std::io::stderr)
                .with_filter(audit),
        )
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
    if args.is_empty() {
        return print_nested_help(&[], "guard");
    }
    if args.len() == 1 && args[0] == "access" {
        return print_nested_help(&["access"], "guard access");
    }
    if let Some((path, bin_name)) = passthrough_command_help_requested(&args) {
        return print_nested_help(&path, bin_name);
    }

    let result = MainArgs::try_parse();

    match result {
        Ok(MainArgs::Run {
            json,
            explain,
            env_vars,
            secret_vars,
            secret_file_vars,
            revert,
            confirm_check,
            revert_control_path,
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
            let secret_file_vars =
                collect_unique_pairs(secret_file_vars, "secret-file injection", "secret")
                    .map_err(anyhow::Error::msg)?;
            let gating = GatingOptions {
                revert,
                confirm_check,
                revert_control_path,
                confirm_within,
                require_approval,
                wait_approval,
                reevaluate,
            };
            run_exec(
                binary,
                args,
                RunInjections {
                    env: env_vars,
                    secrets: secret_vars,
                    secret_files: secret_file_vars,
                },
                gating,
                hostkey.into(),
                json,
                explain,
            )
            .await
        }
        Ok(MainArgs::Server(cmd)) => run_server(cmd).await,
        Ok(MainArgs::Provisionals { socket, json }) => handle_provisionals(socket, json).await,
        Ok(MainArgs::Confirm { handle, socket }) => {
            handle_gate_action(socket, "confirm", handle).await
        }
        Ok(MainArgs::Revert { handle, socket }) => {
            handle_gate_action(socket, "revert", handle).await
        }
        Ok(MainArgs::Resume {
            handle,
            socket,
            json,
        }) => handle_resume(socket, handle, json).await,
        Ok(MainArgs::Verb(subcommand)) => handle_verb(subcommand).await,
        Ok(MainArgs::Audit(subcommand)) => match subcommand {
            AuditCommands::Verify { socket, json } => handle_audit_verify(socket, json).await,
            AuditCommands::Tail { n, socket, json } => handle_audit_tail(socket, n, json).await,
        },
        Ok(MainArgs::Secrets(subcommand)) => handle_secrets(subcommand).await,
        Ok(MainArgs::Shim {
            json,
            tools,
            list,
            remove,
            path,
            env_vars,
            secret_vars,
            user,
        }) => {
            handle_shim(ShimOptions {
                tools,
                list,
                remove,
                path,
                env_vars,
                secret_vars,
                user,
                json,
            })
            .await
        }
        Ok(MainArgs::Config(subcommand)) => handle_config(subcommand).await,
        Ok(MainArgs::Api(subcommand)) => handle_api(subcommand).await,
        Ok(MainArgs::Mcp(subcommand)) => run_mcp(subcommand).await,
        Ok(MainArgs::Access(subcommand)) => handle_access(subcommand).await,
        Ok(MainArgs::Session { .. }) => legacy_authority_error("session", "guard access"),
        Ok(MainArgs::Grant { .. }) => legacy_authority_error("grant", "guard access"),
        Ok(MainArgs::Appeal { .. }) => {
            legacy_authority_error("appeal", "guard access request <intent>")
        }
        Ok(MainArgs::Status { socket, json }) => handle_status(socket, json).await,
        Ok(MainArgs::HelpTree { admin }) => {
            print_help_tree(admin);
            Ok(())
        }
        Ok(MainArgs::Completions { shell }) => {
            let mut command = MainArgs::command();
            clap_complete::generate(shell, &mut command, "guard", &mut std::io::stdout());
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
            std::process::exit(2);
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

// The `run`/`exec` commands disable clap's help flag so that
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
        _ => None,
    }
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

fn log_cli_usage_error(args: &[String], error: &clap::Error) {
    let command_path = cli_command_path(args);
    // Client-side event: no durable sink is installed in the CLI process, so
    // this reaches the stderr projection only.
    let _ = guard::audit::emit_global(
        &guard::audit::AuditEvent::new(guard::audit::AuditKind::CliUsageError)
            .field("command", command_path)
            .field("kind", format!("{:?}", error.kind()))
            .field("argc", args.len()),
    );
}

/// Resolve the command path for audit logging without echoing arbitrary
/// user-controlled argument values. The path is derived from the clap command
/// tree itself, so new subcommands are covered automatically (see the
/// `cli_command_path_covers_every_clap_leaf_command` test). A positional token
/// that does not name a subcommand of the current level stops the walk; only
/// the first token is reported verbatim so a mistyped top-level command stays
/// visible in the audit record.
fn cli_command_path(args: &[String]) -> String {
    let mut positionals = args.iter().filter(|arg| !arg.starts_with('-'));
    let Some(first) = positionals.next() else {
        return "(top-level)".to_string();
    };
    let root = MainArgs::command();
    let Some(mut current) = find_subcommand(&root, first) else {
        return first.to_string();
    };
    let mut path = vec![current.get_name().to_string()];
    for token in positionals {
        match find_subcommand(current, token) {
            Some(sub) => {
                path.push(sub.get_name().to_string());
                current = sub;
            }
            None => break,
        }
    }
    path.join(" ")
}

/// Match a token against a command's subcommands by canonical name or alias,
/// returning the canonical subcommand so aliases normalize in audit output.
fn find_subcommand<'cmd>(parent: &'cmd clap::Command, token: &str) -> Option<&'cmd clap::Command> {
    parent
        .get_subcommands()
        .find(|sub| sub.get_name() == token || sub.get_all_aliases().any(|alias| alias == token))
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
    println!("    access request \"<intent>\"");
    println!("    access list");
    println!("    access show <request-or-session>");
    println!("    provisionals");
    println!("    resume <handle>");
    println!("    mcp serve");
    println!();
    println!("  local setup");
    println!("    shim [tools] [--list|--remove]");
    println!("    config show|set-server|set-port|set-token|set-admin-token|set-user|clear");
    if admin {
        println!();
        println!("{}", paint("  admin", AnsiColor::Yellow, color));
        println!("    server start");
        println!("    verb show <name>");
        println!("    access approve <request>... [--once|--uses N|--yes]");
        println!("    access revoke <session-or-agent>");
        println!("    access deny <request>... [--reason text]");
        println!("    access extend <session-or-agent> \"<intent>\" [--once|--uses N]");
        println!("    secrets list --detailed");
        println!("    confirm|revert <handle>");
        println!("    audit verify|tail [-n N]");
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
    println!("  access list and show expose stable references and scoped authority, never raw session tokens.");
    println!("  admin commands require the daemon principal or the TCP admin token.");
}
#[cfg(test)]
mod tests;
